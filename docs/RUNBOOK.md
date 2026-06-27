# Production runbook

Operating the Secure Device Relay in production: deploying the full stack on a
single VPS with automatic HTTPS, building images off-box, wiring up Stripe,
day-to-day operations, troubleshooting, and the complete environment-variable
reference. For a local dry-run see the
[quick start](../README.md#quick-start-local-stack-with-docker); for development
builds see the [build book](./BUILD.md); for component internals see the
[architecture reference](./ARCHITECTURE.md).

## Topology

```
clients ──wss/https──▶ TLS termination ──▶ relay (:8443)  ┐
                       (Caddy in prod,     auth  (:8080)  ├─▶ Redis (slots/routing/revocation)
                        none for dry-run)                 └─▶ Postgres (auth state)
```

The relay holds **no secrets** and verifies tokens via the auth service's JWKS;
the auth service holds the JWT signing key and Stripe secrets. Keep secrets in env
/ mounted files — **never in an image**. For multi-node/scale-out, Kubernetes
manifests live in [`deploy/k8s/`](../deploy/k8s)
([`deploy/README.md`](../deploy/README.md)).

## Production (VPS)

A single 2 vCPU / 4 GB Linux VPS (the PRD §10.1 reference instance) runs the whole
stack behind **Caddy**, which obtains and renews Let's Encrypt certificates
automatically, terminates TLS, forwards WebSocket upgrades, and sets
`X-Forwarded-For` so per-IP rate limiting sees the real client. The bundle lives
in [`deploy/compose/`](../deploy/compose): `docker-compose.prod.yml`, `Caddyfile`,
and `.env.example`.

**1. DNS** — point three A records at the VPS public IP:
`relay.example.com`, `auth.example.com`, and `models.example.com` (the AI model
download host). All three terminate at the same Caddy edge.

**2. VPS prep** — install Docker Engine + the compose plugin, then apply the host
kernel/ulimit tuning so the box can hold many connections (full rationale and
values in [`docs/tuning.md`](./tuning.md)):

```sh
### docker prep ###
sudo apt update
sudo apt -y install ca-certificates curl gnupg

# GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Repo — arch auto-detected, codename from os-release (no lsb_release dependency)
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt -y install docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
newgrp docker
docker run hello-world

### system tuning ###
sudo tee /etc/sysctl.d/90-relay.conf >/dev/null <<'EOF'
fs.file-max = 2097152
net.core.somaxconn = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
vm.overcommit_memory = 1   # silences the Redis startup warning (host-level only)
EOF
sudo sysctl --system
```

**Open inbound 80 + 443 — at *both* the cloud firewall and the host firewall.**
Caddy needs them reachable from the public internet to get TLS certificates:

| Port | Proto | Why |
|------|-------|-----|
| 80   | TCP   | **Required** for the ACME HTTP-01 challenge — the CA fetches `http://<host>/.well-known/acme-challenge/…` over plain HTTP. Caddy redirects 80→443 for real traffic *after* a cert is issued, but issuance fails without it. |
| 443  | TCP   | HTTPS (the actual relay/auth traffic). |
| 443  | UDP   | HTTP/3 (the `443:443/udp` mapping). Optional for issuance; matches the compose. |

```sh
# Host firewall (skip rules that already exist):
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw allow 443/udp

# On a cloud VM (AWS EC2 / GCP / Azure) you ALSO must open these in the provider's
# security group / firewall — the host firewall alone is not enough. AWS example:
aws ec2 authorize-security-group-ingress --group-id sg-XXXX --ip-permissions \
  IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges='[{CidrIp=0.0.0.0/0}]' \
  IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=0.0.0.0/0}]' \
  IpProtocol=udp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=0.0.0.0/0}]'
```

Verify from a machine **outside** the VPS before launching — `nc -zv <public-ip> 80`
should connect, not time out. A `Timeout during connect (likely firewall problem)`
in the Caddy ACME logs means port 80 is still blocked upstream (usually the cloud
security group). Note Let's Encrypt rate-limits failed attempts (~5/hour per
hostname), so fix the firewall before retrying. Open **only** 80/443 — Redis and
Postgres stay on the internal Docker network and must never be exposed.

**3. Secrets & signing key** — from the repo on the VPS:

```sh
cd deploy/compose
cp .env.example .env          # set RELAY_HOST/AUTH_HOST/MODELS_HOST/ACME_EMAIL/JWT_ISSUER
                              # and real POSTGRES_PASSWORD, REDIS_PASSWORD, Stripe secrets, admin key
mkdir -p keys
go run ../../cmd/devtoken -gen-keys -out-dir ./keys -alg ES256   # writes keys/relay.key.json

# The auth container runs as uid 65532 (distroless nonroot). Give that uid read
# access WITHOUT making the signing key world-readable:
sudo chown -R 65532:65532 keys && sudo chmod 0750 keys && sudo chmod 0640 keys/relay.key.json
```

`.env` and `keys/` are gitignored — keep them on the host only. Back up
`keys/relay.key.json`: losing it invalidates every issued token (rotate it via the
JWKS to roll keys, ≤ 90 days per PRD §10.2).

**3b. Model artifacts** — the `models` service serves files from `deploy/compose/models/`
(a read-only bind mount). Provision them on the host out-of-band; unlike `keys/`
these are **not** secret and only need to be world-readable:

```sh
mkdir -p models
rsync -P model.gguf user@vps:~/secure-gateway/models/   # or scp/aws s3 cp …
chmod 0644 models/*                                      # readable by the container uid 65532
```

The blobs are gitignored (only `models/.gitkeep` is tracked). `static-web-server`
serves them with HTTP byte-range support, so large downloads resume. Anyone with
the URL can fetch them — gate the host (Caddy `forward_auth` / signed URLs) before
publishing private models.

**4. Launch** (run from `deploy/compose/` so the build context and volumes resolve):

```sh
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f caddy   # watch the cert issuance
```

**5. Verify over HTTPS** (certs may take ~30s on first boot):

```sh
curl -fsS https://auth.example.com/healthz && echo
curl -fsS https://relay.example.com/healthz && echo
curl -fsS https://auth.example.com/.well-known/jwks.json | head -c 80; echo

# Model download host — headers should show Accept-Ranges: bytes, and a ranged
# request should return 206 Partial Content (resumable downloads):
curl -fsSI https://models.example.com/model.gguf | grep -i accept-ranges
curl -fsS -r 0-1023 -o /dev/null -w '%{http_code}\n' https://models.example.com/model.gguf
```

**6. Stripe** — in the Stripe dashboard (**Live mode** — production uses live
keys/secrets), under *Developers → Webhooks → Add endpoint*, set the URL to
`https://auth.example.com/v1/webhooks/stripe` and subscribe to **exactly these six
events** (the only ones the handler acts on; any others are logged no-ops):

```
checkout.session.completed     # link customer↔account, provision licenses, ready the claim token
customer.subscription.created  # sync subscription state + provisioning
customer.subscription.updated  # same upsert path
customer.subscription.deleted  # mark canceled, revoke all licenses
invoice.payment_failed         # enter grace period (past_due + grace deadline)
invoice.paid                   # clear grace, reactivate suspended licenses
```

Reveal the endpoint's signing secret and put it in `.env` as
`AUTH_STRIPE_WEBHOOK_SECRET=whsec_…` (every webhook is signature-verified; a
missing/test-mode secret yields `400 bad_signature`). Also set
`AUTH_STRIPE_SECRET_KEY=sk_live_…` so the nightly reconciliation can heal any
missed or out-of-order webhooks by re-reading subscriptions from Stripe, and
`AUTH_STRIPE_PRICE_ID=price_…` for the desktop plan — these three are an
all-or-none unit (see
[Billing modes](./ARCHITECTURE.md#billing-modes-stripe-enabled-vs-disabled); to
run without Stripe, set none of them and `AUTH_BILLING_DISABLED=true`). All three
(endpoint, `whsec_`, `sk_`) must be from the **same mode** — live for prod. Then
`docker compose -f docker-compose.prod.yml up -d auth` to apply, and use the
dashboard's *Send test event* to confirm a `200`.

Licenses are provisioned **only** by signed webhooks (plus reconciliation
healing), not the admin endpoint. The handler is idempotent (duplicate
redeliveries return `200 {"duplicate":true}`) and never wedges Stripe's retries
(processing failures still return `200 {"queued":true}` and retry internally), so
no extra Stripe-side retry config is needed.

**7. Provision an account** — once Stripe drives subscriptions this is automatic;
to create an account credential manually use the admin key:

```sh
curl -fsS -X POST https://auth.example.com/v1/accounts \
  -H "Authorization: Bearer $AUTH_ADMIN_KEY" \
  -d '{"account_id":"acct_123"}'
```

### Build off-box (recommended for production)

Steps 4–5 above build the relay/auth images **on the VPS** (`up -d --build`). That
is the simplest path, but it drags the Go toolchain, the full repo source, and
build caches onto the production box, and a build competes with live traffic for
the 2 vCPU / 4 GB. For a hardened deployment, build the images on a separate
**secure builder**, push a versioned, digest-pinned artifact, and have the VPS
only ever pull and run it. Use
[`docker-compose.prod-image.yml`](../deploy/compose/docker-compose.prod-image.yml),
which is identical to `docker-compose.prod.yml` except `relay`/`auth` reference
`image:` instead of `build:`.

The signing key story is **unchanged**: `keys/relay.key.json` is a runtime secret
mounted as a read-only volume (`./keys:/keys:ro`) — it is never `COPY`'d into a
Dockerfile, so the registry images carry no secret and the key never reaches the
builder. The only *new* secrets are the registry credentials (give the builder
**push**, the VPS **read-only** — not the same credential).

**1. Build & push** (on the secure builder, which has the toolchain + source).
The `push` Make target builds both registry-tagged images and pushes them (here
`VERSION` is the image tag, i.e. `IMAGE_TAG` in `.env`):

```sh
docker login ghcr.io                                       # push credential (a PAT with write:packages)
make push VERSION=1.0.0                                     # defaults to IMAGE_REGISTRY=ghcr.io/lley154/secure-gateway
```

It refuses the `dev`/`latest` tags so prod always gets a real, immutable
artifact. Override `IMAGE_REGISTRY=…` for a different registry. Equivalent to the
raw commands:

```sh
export IMAGE_REGISTRY=ghcr.io/lley154/secure-gateway IMAGE_TAG=1.0.0
docker build -f Dockerfile      --build-arg VERSION=$IMAGE_TAG -t $IMAGE_REGISTRY/relay:$IMAGE_TAG .
docker build -f Dockerfile.auth --build-arg VERSION=$IMAGE_TAG -t $IMAGE_REGISTRY/auth:$IMAGE_TAG  .
docker push $IMAGE_REGISTRY/relay:$IMAGE_TAG
docker push $IMAGE_REGISTRY/auth:$IMAGE_TAG
```

If the builder and VPS differ in CPU architecture, build for the VPS's arch with
`docker buildx build --platform linux/amd64 ...`. Optionally `cosign sign` the
images here and `cosign verify` on the VPS so it only runs artifacts you built
(the cosign private key stays on the builder; only its public key goes to the VPS).

> **GHCR auth & visibility.** `docker login ghcr.io` uses your GitHub username
> and a **Personal Access Token (classic)** as the password — `write:packages`
> on the builder, `read:packages` on the VPS — *not* your GitHub password.
> First push creates the `relay`/`auth` packages **private** and initially
> unlinked from the repo. In each package's GitHub settings: link it to the
> `secure-gateway` repo (so repo collaborators inherit access), and under
> *Manage Actions access / Package settings* add the VPS's pull identity. Keep
> them **private** — these images aren't sensitive (the signing key is never
> baked in), but there's no reason to publish them. If you make a package
> public, `read:packages` is no longer needed to pull it (anonymous pull works),
> but the VPS still needs login to pull a private one.

*No registry?* Ship a tarball over SSH instead of pushing/pulling:
`docker save $IMAGE_REGISTRY/relay:$IMAGE_TAG $IMAGE_REGISTRY/auth:$IMAGE_TAG | gzip | ssh deploy@vps 'gunzip | docker load'` — then skip the `login`/`pull` below and go straight to `up -d`.

**2. Get the signing key onto the VPS** (generate on the builder, copy over SSH —
this avoids needing the Go toolchain on the VPS just to run `devtoken`):

```sh
# on the builder (one time)
go run ./cmd/devtoken -gen-keys -out-dir ./keys -alg ES256
ssh ubuntu@vps 'mkdir -p ~/secure-gateway/keys'
scp keys/relay.key.json ubuntu@vps:~/secure-gateway/keys/
# on the VPS — lock it down to the distroless uid 65532
ssh ubuntu@vps 'cd ~/secure-gateway && sudo chown -R 65532:65532 keys && sudo chmod 0750 keys && sudo chmod 0640 keys/relay.key.json'
```

Back the key up off-box (encrypted): losing it invalidates every issued token;
rotate via JWKS ≤ 90 days (PRD §10.2).

**3. Deploy** (on the VPS — no toolchain, no repo source, no `--build`). The VPS
needs **only these four files**, all in one directory, because the compose file
mounts the rest by *relative* path (`env_file: .env`, `./Caddyfile`, `./keys`):

```
~/secure-gateway/
├── docker-compose.prod-image.yml   # the compose file
├── Caddyfile                       # reverse-proxy / TLS config
├── .env                            # secrets + IMAGE_REGISTRY / IMAGE_TAG (gitignored; you create it)
└── keys/
    └── relay.key.json              # JWT signing key (from step 2)
```

Nothing else from the repo belongs on the VPS — not the source, the Dockerfiles,
the Makefile, nor the other compose files. The `pgdata`/`caddy_data`/`caddy_config`
volumes are Docker-managed (created automatically), not host files. Copy just the
two config files from the repo (the key is already there from step 2):

```sh
# from the repo on your builder/laptop — copy ONLY these two
scp deploy/compose/docker-compose.prod-image.yml deploy/compose/Caddyfile \
    ubuntu@vps:~/secure-gateway/

# then on the VPS, in that directory
cd ~/secure-gateway
# create .env from the template (deploy/compose/.env.example) and fill in real
# values incl. IMAGE_REGISTRY / IMAGE_TAG — the file itself is all you need, not a repo:
nano .env
ls Caddyfile keys/relay.key.json   # confirm the mounted paths exist as FILES before up
docker login ghcr.io                                       # registry READ credential (a PAT with read:packages)
docker compose -f docker-compose.prod-image.yml pull
docker compose -f docker-compose.prod-image.yml up -d
docker compose -f docker-compose.prod-image.yml ps
```

> Run `up` only from the directory holding those files. If a mounted path is
> missing, Docker silently creates it as an empty **directory** and the container
> then dies with `not a directory: Are you trying to mount a directory onto a
> file`. Fix: `down`, `rmdir` the stray directory, put the real file there, `up -d`.

Upgrades and rollbacks are then a one-line image swap: bump `IMAGE_TAG` in `.env`,
`pull`, and `up -d` (or set it back to the previous tag to roll back). Verify over
HTTPS and configure Stripe exactly as in steps 5–7 above.

### TLS without a reverse proxy (alternative)

To terminate TLS directly at the relay/auth instead of Caddy, mount certificates
and set `RELAY_TLS_CERT_FILE`/`RELAY_TLS_KEY_FILE` (and the `AUTH_*` equivalents),
publish `:8443`/`:8080`, and set `RELAY_TRUST_PROXY=false` / `AUTH_TRUST_PROXY=false`
(the client IP is then the real socket peer). The relay already enforces TLS 1.2+,
a modern cipher allow-list, and HSTS; `relay_tls_cert_expiry_seconds` then reports
days-to-expiry for alerting.

## Operations

- **Zero-downtime deploys**: rebuild and `up -d`; on `SIGTERM` each service sends
  `sys{shutdown}` and drains for up to `*_SHUTDOWN_DRAIN` (30s) while clients
  reconnect with jittered backoff.
- **Backups**: snapshot the `pgdata` volume (auth/license state). Redis holds only
  ephemeral slots and may be wiped safely (new claims just re-establish).
- **Monitoring**: scrape `/metrics` on both services with Prometheus, load
  [`deploy/prometheus/alerts.yml`](../deploy/prometheus/alerts.yml) into
  `rule_files`, and import
  [`deploy/grafana/relay-dashboard.json`](../deploy/grafana/relay-dashboard.json).
  Key alerts: auth-failure spike, fd saturation, `*_backplane_up == 0`, webhook
  lag, and cert expiry.
- **Capacity**: this single instance targets ≥ 50k connections; see
  [`docs/capacity.md`](./capacity.md) for the load-test procedure. When one
  VPS is not enough, scale to multiple relay instances behind an L4/L7 load
  balancer with shared (managed) Redis + Postgres — the Kubernetes manifests in
  [`deploy/k8s/`](../deploy/k8s) do exactly this.

## Verifying a running stack

Beyond the health checks, these confirm the M5 hardening is live against any
running deployment (adjust host/port for prod vs. the local dry-run):

```sh
# M5 observability gauges are live (collectors run in the binaries)
curl -s localhost:8443/metrics | grep -E 'relay_backplane_up|relay_fd_used|relay_fd_limit'
curl -s localhost:8080/metrics | grep -E 'auth_backplane_up|auth_webhooks_pending'

# Rate limiting (default per-IP burst 60): a burst of unauthenticated upgrades
# returns 401 within the burst, then HTTP 429 + Retry-After
for i in $(seq 1 90); do curl -s -o /dev/null -w '%{http_code} ' localhost:8443/v1/connect; done; echo
curl -s -D - -o /dev/null localhost:8443/v1/connect | grep -i retry-after

# Fail-closed on backplane loss (PRD §10.3): stop Redis and watch the gauge flip
docker compose stop redis
sleep 18 && curl -s localhost:8443/metrics | grep relay_backplane_up   # -> 0
docker compose start redis
```

## Troubleshooting

- **`redis ... setpriv: setresuid failed: Operation not permitted` / `dependency
  redis failed to start`** — the Redis image's root entrypoint tries to drop to
  the `redis` user with `setpriv`, which needs `CAP_SETUID`; our `cap_drop:[ALL]`
  removes it. The compose files pin `user: redis` on the service so it starts
  unprivileged and skips the drop. If you hit this, you're on an older copy of
  the compose file — pull the latest, or add `user: redis` to the `redis`
  service yourself. **Postgres** is hardened the same way (`cap_drop:[ALL]`) but
  keeps a minimal `cap_add` — `CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID` — so its
  alpine entrypoint can still chown the data volume and `su-exec` down to the
  unprivileged `postgres` user (SG-20). If Postgres fails to start after an upgrade
  with a permissions error, confirm those caps are present on the service.
- **`error mounting ".../Caddyfile" ... not a directory: Are you trying to mount
  a directory onto a file`** — the host path the compose file mounts (`./Caddyfile`,
  and likewise `./keys`/`.env`) didn't exist when you ran `up`, so Docker created
  it as an empty directory and then couldn't mount it onto the image's file. You
  ran from a directory missing the config bundle. Fix:
  ```sh
  docker compose -f docker-compose.prod-image.yml down
  sudo rmdir Caddyfile           # remove the stray empty directory
  # put the real Caddyfile (and .env, keys/) next to the compose file — see step 3
  docker compose -f docker-compose.prod-image.yml up -d
  ```
- **Caddy ACME `Timeout during connect (likely firewall problem)` / no
  certificate** — DNS resolves to your box, but the CA can't reach port 80 for
  the HTTP-01 challenge. Open inbound 80/443 at **both** the host firewall and
  the cloud security group (see VPS prep step 2); on EC2 it's almost always the
  security group. Verify with `nc -zv <public-ip> 80` from outside the VPS. Fix
  the firewall before retrying — Let's Encrypt rate-limits failed attempts.
- **`permission denied` on `/keys/relay.key.json`** — `make keys` writes the key
  `0600` owned by your host user, but the container runs as uid 65532. `chown` it
  to the container uid (`sudo chown 65532:65532 keys/relay.key.json`) for prod, or
  for a throwaway dev key `chmod 0644 keys/relay.key.json`.

## Configuration reference

### Relay (`RELAY_` prefix)

| Var | Default | Purpose |
|---|---|---|
| `RELAY_LISTEN_ADDR` | `:8443` | bind address |
| `RELAY_METRICS_ADDR` | — | private `/metrics` + `/healthz` listener (e.g. `:9090`); empty ⇒ served on the main listener. When set it is validated at boot: must parse as `host:port` and differ from `RELAY_LISTEN_ADDR`, so a typo fails startup instead of silently serving metrics nowhere (SG-18) |
| `RELAY_TLS_CERT_FILE` / `RELAY_TLS_KEY_FILE` | — | enable `wss`; empty ⇒ plain HTTP behind a TLS proxy |
| `RELAY_TLS_MIN_VERSION` | `1.2` | `1.2` or `1.3` |
| `RELAY_JWT_ISSUER` | — | expected `iss` (required) |
| `RELAY_JWT_AUDIENCE` | `relay` | expected `aud` |
| `RELAY_JWT_ALGS` | `ES256,EdDSA` | allowed algorithms (asymmetric only) |
| `RELAY_JWKS_URL` | — | JWKS endpoint (prod); mutually exclusive with the file |
| `RELAY_JWT_PUBLIC_KEY_FILE` | — | PEM public key (dev/test with `devtoken`) |
| `RELAY_JWT_LEEWAY` | `30s` | clock-skew tolerance |
| `RELAY_MAX_MESSAGE_BYTES` | `262144` | 256 KB per-frame cap |
| `RELAY_PING_INTERVAL` | `25s` | heartbeat ping interval |
| `RELAY_PONG_TIMEOUT` | `25s` | per-ping pong wait (2 misses ⇒ close) |
| `RELAY_OUT_QUEUE_SIZE` | `64` | per-session write buffer depth |
| `RELAY_SLOT_TTL` | `60s` | backplane slot TTL (> 2× ping) |
| `RELAY_BACKPLANE` | `memory` | `memory` or `redis` |
| `RELAY_REDIS_ADDR` / `RELAY_REDIS_PASSWORD` / `RELAY_REDIS_DB` | — | go-redis connection |
| `RELAY_SHUTDOWN_DRAIN` | `30s` | graceful drain budget |
| `RELAY_TRUST_PROXY` | `false` | use `X-Forwarded-For` for client IP — set **only** behind a proxy that sets/replaces it (else clients can spoof) |
| `RELAY_RATELIMIT_ENABLED` | `true` | master switch for per-IP limiting + bans |
| `RELAY_RATELIMIT_IP_PER_MIN` | `120` | per-IP connection attempts/min |
| `RELAY_RATELIMIT_IP_BURST` | `60` | per-IP burst allowance |
| `RELAY_ABUSE_STRIKE_THRESHOLD` | `10` | `4005` strikes before a temporary ban (0 disables) |
| `RELAY_ABUSE_STRIKE_WINDOW` | `1m` | window strikes accumulate in |
| `RELAY_ABUSE_BAN_WINDOW` | `15m` | how long a banned IP stays banned |
| `RELAY_LOG_LEVEL` / `RELAY_LOG_FORMAT` | `info` / `json` | logging |
| `RELAY_INSTANCE_ID` | auto | overrideable instance identity |

### Auth (`AUTH_` prefix)

| Var | Default | Purpose |
|---|---|---|
| `AUTH_LISTEN_ADDR` | `:8080` | bind address |
| `AUTH_METRICS_ADDR` | — | private `/metrics` + `/healthz` listener (e.g. `:9090`); empty ⇒ served on the main listener. Validated at boot: must parse as `host:port` and differ from `AUTH_LISTEN_ADDR`, so a typo fails startup instead of silently serving metrics nowhere (SG-18) |
| `AUTH_TLS_CERT_FILE` / `AUTH_TLS_KEY_FILE` | — | enable TLS; empty ⇒ plain HTTP behind a proxy |
| `AUTH_TLS_MIN_VERSION` | `1.2` | `1.2` or `1.3` |
| `AUTH_STORE` | `memory` | `memory` or `postgres` |
| `AUTH_DB_DSN` | — | Postgres DSN (required for `postgres`) |
| `AUTH_BACKPLANE` | `memory` | `memory` or `redis` (revocation publish) |
| `AUTH_REDIS_ADDR` / `AUTH_REDIS_PASSWORD` / `AUTH_REDIS_DB` | — | go-redis connection |
| `AUTH_JWT_ISSUER` | — | token `iss` (required; must match the relay's) |
| `AUTH_JWT_AUDIENCE` | `relay` | token `aud` |
| `AUTH_JWT_ALG` | `ES256` | `ES256` or `EdDSA` |
| `AUTH_JWT_KID` | `auth-1` | key id (when loading a raw PEM key) |
| `AUTH_JWT_SIGNING_KEY_FILE` | — | signing key (required); `devtoken` JSON keyfile or PKCS#8 PEM |
| `AUTH_TOKEN_TTL` | `10m` | connection JWT lifetime |
| `AUTH_REFRESH_TTL` | `720h` | refresh token lifetime |
| `AUTH_GRACE_PERIOD` | `168h` | `past_due` grace window (PRD default 7 days) |
| `AUTH_STRIPE_WEBHOOK_SECRET` | — | webhook signature secret; part of the all-or-none Stripe trio (see below) |
| `AUTH_STRIPE_SECRET_KEY` | — | Stripe API key (nightly reconciliation + desktop checkout); part of the trio |
| `AUTH_STRIPE_PRICE_ID` | — | subscription plan price; enables `POST /v1/checkout/start`; part of the trio |
| `AUTH_BILLING_DISABLED` | `false` | explicit acknowledgement required to boot with no Stripe config; runs ungated (see below) |
| `AUTH_PUBLIC_URL` | — | this service's public base URL; the checkout `success_url`/`return` base (required when Stripe enabled) |
| `AUTH_CLAIM_TTL` | `30m` | one-time checkout-claim lifetime (desktop onboarding) |
| `AUTH_RECONCILE_INTERVAL` | `24h` | reconciliation cadence |
| `AUTH_ADMIN_KEY` | — | gates `POST /v1/accounts`; empty ⇒ disabled |
| `AUTH_SHUTDOWN_DRAIN` | `30s` | graceful shutdown budget |
| `AUTH_TRUST_PROXY` | `false` | use `X-Forwarded-For` for client IP — set **only** behind a trusted proxy |
| `AUTH_RATELIMIT_ENABLED` | `true` | master switch for per-IP + per-account limiting |
| `AUTH_RATELIMIT_IP_PER_MIN` / `AUTH_RATELIMIT_IP_BURST` | `60` / `20` | per-IP limit on sensitive endpoints |
| `AUTH_RATELIMIT_ACCOUNT_PER_MIN` / `AUTH_RATELIMIT_ACCOUNT_BURST` | `30` / `10` | per-account auth-attempt limit |
| `AUTH_LOG_LEVEL` / `AUTH_LOG_FORMAT` | `info` / `json` | logging |
| `AUTH_INSTANCE_ID` | auto | overrideable instance identity |

The `AUTH_STRIPE_*` trio and `AUTH_BILLING_DISABLED` interact at startup — see
[Billing modes](./ARCHITECTURE.md#billing-modes-stripe-enabled-vs-disabled).
