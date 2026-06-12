# secure-gateway

Secure Device Relay — a subscription-gated WebSocket relay that lets a mobile
app reach its paired desktop app from anywhere, even behind NAT/firewalls. Both
ends dial *out* to the relay over `wss://`; the relay pairs them and forwards
**end-to-end-encrypted** frames it cannot read. See
[`prd-secure-mobile-desktop-relay.md`](./prd-secure-mobile-desktop-relay.md).

## Status: M1 — Relay core, M2 — Auth & licensing, M3 — Pairing & E2EE, M4 — Client SDKs, M5 — Hardening & scale

**M1**, the Go relay server:

- `wss` WebSocket endpoint (`/v1/connect`) with asymmetric JWT auth verified
  **before** the upgrade (ES256/EdDSA, JWKS-ready), claims-only routing.
- Per-pair slot enforcement (one mobile + one desktop), newest-wins eviction
  (`4001`), heartbeat (ping/pong), live-socket token refresh, token-expiry
  close (`4003`), revocation (`4004`), oversize/protocol close (`4005`).
- Opaque, end-to-end-encrypted payloads — the relay reads only `v`/`type`/`id`
  and **never logs payloads** (enforced by test).
- A backplane interface with two implementations: in-memory (single instance)
  and Redis (multi-instance routing, revocation, eviction).
- Graceful drain on `SIGTERM`, Prometheus metrics (`/metrics`), structured logs.
- Distroless, static, non-root container.

**M2**, the Auth & License Service (`cmd/auth`):

- Stripe-driven licensing: signed-webhook ingestion (idempotent, durable, with a
  dead-letter retry queue) mirrors subscription state; license behavior is
  derived per PRD §6.3 (valid / grace / revoked / suspended). Nightly
  reconciliation heals the mirror against missed webhooks.
- Connection-token issue/refresh (ES256/EdDSA JWTs) **only** for valid licenses,
  with re-validation on refresh; opaque rotating refresh tokens.
- License-key provisioning per `max_pairs`, device registration, and a minimal
  pairing API (the QR/E2EE flow lands in M3).
- Immediate cutoff: revocations published to the shared Redis channel close live
  relay sessions (`4004`) within ≤ 2 s.
- A `Store` interface with in-memory (tests) and Postgres (prod) implementations,
  a `/.well-known/jwks.json` endpoint the relay verifies against, and the same
  distroless/static/non-root container hardening as the relay.

**M3**, QR pairing and end-to-end encryption:

- Versioned QR pairing flow (FR-2): the desktop requests a one-time pairing token
  and renders a QR (`{v, pairing_token, desktop_pubkey, desktop_device_id,
  endpoints}`); the mobile scans it and completes pairing over HTTPS, exchanging
  X25519 public keys. New endpoints: `POST /v1/pairing-tokens`,
  `POST /v1/pairing-tokens/poll`, `POST /v1/pairings/unpair`.
- The `internal/e2ee` reference crypto (FR-5): X25519 ECDH → HKDF-SHA256
  directional keys → **XChaCha20-Poly1305** (24-byte nonce), with the envelope
  `id`/`ts` bound as AEAD associated data. The committed interop vectors
  (`internal/e2ee/testdata/vectors.json`) are the cross-platform contract; the
  relay still only ever sees ciphertext.

**M4**, the client SDKs (`sdk/`) — Android (Kotlin), desktop (Java), iOS (Swift) —
with one common API (`connect`, `send(bytes)->ack`, `onMessage`, `onStateChange`,
`pair(qr)` / `generatePairingQr()`). Each implements FR-1 reconnect/heartbeat, FR-3
token refresh, and FR-5 crypto internally, so host apps deal only in plaintext
messages and connection state. All three reproduce `vectors.json` byte-for-byte; a
cross-platform E2E (Kotlin mobile ↔ Java desktop) runs against the real relay +
auth binaries. See [`sdk/README.md`](./sdk/README.md). `cmd/devtoken` still mints
tokens for relay-only dev/tests.

## Layout

```
cmd/relay        relay server entrypoint
cmd/auth         Auth & License Service entrypoint (M2)
cmd/devtoken     dev CLI: generate keys and mint test connection tokens
internal/config  RELAY_* env configuration
internal/token   JWT claims + asymmetric verification (static-PEM / JWKS)
internal/signer  JWT minting + JWKS (auth service signs; relay never links it)
internal/backplane          slot/routing/revocation interface
internal/backplane/memory   in-memory single-instance backplane
internal/backplane/redis    go-redis backplane (Lua claims + pub/sub)
internal/relay/protocol     wire envelope, message types, close codes
internal/relay/session      connection lifecycle (read/write/monitor pumps)
internal/relay/hub          per-instance registry, routing, presence
internal/relay/server       HTTP surface, /v1/connect, TLS, drain
internal/metrics, logging   Prometheus collectors, structured logging
-- Auth & License Service (M2) --
internal/authconfig         AUTH_* env configuration
internal/authmetrics        auth_* Prometheus collectors
internal/authstore          Store interface + domain types
internal/authstore/memory   in-memory store (tests, hermetic E2E)
internal/authstore/postgres pgx store + embedded SQL migrations (prod)
internal/authstore/storetest shared store conformance suite
internal/license            entitlement rules (§6.3) + license-key generation
internal/billing            Stripe webhook verify/dispatch, reconcile, revocation
internal/billing/fake       hermetic Stripe test double (API + signed webhooks)
internal/authservice        HTTP handlers, token/pairing issue/refresh, JWKS, account auth
internal/e2ee               reference E2EE (X25519/HKDF/XChaCha20) + interop vectors (M3)
-- Client SDKs (M4) --
sdk/core         shared JVM contract logic (crypto, protocol, pairing/token client, state machine)
sdk/java         desktop SDK (java.net.http.WebSocket) + cross-platform e2eTest
sdk/android      mobile SDK in Kotlin/OkHttp (built as a JVM lib here)
sdk/ios          iOS SDK in Swift (URLSessionWebSocketTask) — source-only on Linux
test/testclient  reusable Go relay client
test/integration end-to-end tests (echo, lifecycle, slots, revocation, drain,
                 observability, cross-instance over Redis, auth subscription
                 lifecycle, rate limiting)
test/soak        build-tagged idle-connection leak soak
test/bench       build-tagged §10.1 capacity checks (latency, verify, revoke, storm)
-- Hardening & scale (M5) --
internal/ratelimit   per-IP/account token-bucket limiter + strike/ban tracker
internal/httpsec     shared HSTS + modern cipher allow-list + TLS config + client IP
internal/obs         fd-usage and TLS cert-expiry sampling helpers
deploy/k8s           Kubernetes manifests (Deployments, Services, ConfigMap, PDB, HPA)
deploy/prometheus    alert rules; deploy/grafana dashboard JSON
docs/                capacity.md, tuning.md, threat-model.md
```

## Build & test

```sh
make build         # bin/relay, bin/auth, bin/devtoken (static, stripped)
make test          # unit + integration tests
make race          # tests under the race detector
make vet
make docker        # distroless image secure-gateway/relay:dev
make docker-auth   # distroless image secure-gateway/auth:dev
```

### Capacity checks (M5 / §10.1)

CI-sized assertions for forward latency, token-verify, revocation propagation, and a
reconnect storm; scale up with env overrides (see [`docs/capacity.md`](./docs/capacity.md)):

```sh
make bench                                  # CI-sized assertions
make bench LAT_FRAMES=20000 STORM_CONNS=20000
```

### Soak (M1 exit criterion)

CI-sized by default; override for the full 10k / 24h run:

```sh
make soak                                  # 1000 conns, 5s
make soak SOAK_CONNS=10000 SOAK_DURATION=24h
```

It samples goroutine, heap, and FD counts and fails on unbounded growth.

## Run locally

```sh
make keys                                   # writes ./keys/relay.{pub.pem,jwks.json,key.json}
RELAY_JWT_ISSUER=https://auth.example.com \
RELAY_JWT_PUBLIC_KEY_FILE=./keys/relay.pub.pem \
RELAY_BACKPLANE=memory \
RELAY_LISTEN_ADDR=127.0.0.1:8443 \
  ./bin/relay
```

Mint a token and connect with the `Authorization: Bearer <jwt>` header:

```sh
./bin/devtoken -key ./keys/relay.key.json -role mobile  -pair p1 -device m1
./bin/devtoken -key ./keys/relay.key.json -role desktop -pair p1 -device d1
```

Or bring up relay + Redis together (build the image, generate keys first):

```sh
make keys
docker compose up --build
```

## Configuration (env, `RELAY_` prefix)

| Var | Default | Purpose |
|---|---|---|
| `RELAY_LISTEN_ADDR` | `:8443` | bind address |
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

## Auth & License Service (M2)

HTTP/JSON API (TLS in prod, or plain HTTP behind a proxy):

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /v1/webhooks/stripe` | Stripe signature | Ingest subscription events (idempotent, durable) |
| `POST /v1/accounts` | admin key | Provision an account credential (seam for the account backend) |
| `POST /v1/checkout/start` | — (IP-limited) | Desktop: create a Stripe Checkout Session + record a pending claim (desktop onboarding) |
| `GET /v1/checkout/return` | — (browser) | Stripe `success_url`; 302 to the desktop's loopback callback with a one-time `claim_code` |
| `POST /v1/accounts/claim` | — (IP-limited) | Desktop: exchange the one-time `claim_code` (or `nonce`) for `{account_id, account_secret, license_id, subscription_id}`, once |
| `GET /v1/subscription` | account secret | Desktop: launch-time status (`status`, `current_period_end`, `max_pairs`) |
| `POST /v1/billing-portal` | account secret | Desktop: mint a Stripe Customer Portal URL ("Subscription Settings"); requires the portal enabled in the Stripe dashboard |
| `POST /v1/devices` | account secret | Register a mobile/desktop device |
| `POST /v1/pairing-tokens` | account secret | Desktop: mint a one-time pairing token + QR payload (M3) |
| `POST /v1/pairing-tokens/poll` | account secret | Desktop: learn `pair_id` + mobile pubkey once paired (M3) |
| `POST /v1/pairings` | pairing token | Mobile: complete pairing with its X25519 pubkey → `pair_id` (M3) |
| `POST /v1/pairings/unpair` | account secret | Revoke a pairing and free the license slot (M3) |
| `POST /v1/token` | account secret | Issue a connection JWT + refresh token (valid licenses only) |
| `POST /v1/token/refresh` | refresh token | Rotate; re-checks license validity |
| `GET /.well-known/jwks.json` | — | Public keys the relay verifies against |
| `GET /healthz`, `GET /metrics` | — | Health + Prometheus |

### Run the auth service locally

```sh
make keys                                    # writes ./keys/relay.key.json (signing key)
AUTH_JWT_ISSUER=https://auth.example.com \
AUTH_JWT_SIGNING_KEY_FILE=./keys/relay.key.json \
AUTH_STORE=memory \
AUTH_BACKPLANE=memory \
AUTH_STRIPE_WEBHOOK_SECRET=whsec_test \
AUTH_ADMIN_KEY=dev_admin_key \
AUTH_LISTEN_ADDR=127.0.0.1:8080 \
  ./bin/auth
```

Point the relay at its JWKS with `RELAY_JWKS_URL=http://127.0.0.1:8080/.well-known/jwks.json`
(use the shared Redis backplane on both so revocations propagate). `docker
compose up` brings up the full stack (auth + relay + Redis + Postgres).

### Desktop subscription onboarding (claim-token flow)

`POST /v1/accounts` is admin-gated and returns the account secret once, so a
freshly-paid desktop has no way to authenticate. The claim-token flow closes that
gap end to end (used by mobile-agent's "anywhere access" upgrade):

1. **Desktop → `POST /v1/checkout/start`** with a client-generated `nonce` and its
   loopback `redirect_uri` (`http://127.0.0.1:<port>/subscribe/callback`). The
   service creates a Stripe Checkout Session (subscription mode) carrying
   `metadata.nonce`, records a **pending** claim, and returns `checkout_url`. The
   desktop opens it in the browser.
2. **Stripe webhook `checkout.session.completed`** provisions the account +
   license (as before) and, when `metadata.nonce` is present, marks the claim
   **ready** (idempotent under retries). If a `customer.subscription.created`
   event arrived **first** (Stripe may deliver it before
   `checkout.session.completed`), that handler already created+provisioned an
   account for the customer, so checkout-completion **reuses the customer's
   existing account** (`resolveAccount`) instead of minting a second one —
   otherwise the claim binds to an account whose `license_id` belongs to the
   other, and pairing later fails `404 license_not_found`.
3. **Stripe `success_url` → `GET /v1/checkout/return`** mints a one-time
   `claim_code`, then 302s the browser to the desktop's loopback callback with it.
   While the webhook is still pending it serves a self-refreshing interstitial.
4. **Desktop → `POST /v1/accounts/claim`** exchanges the `claim_code` (or the held
   `nonce`) for `{account_id, account_secret, license_id, subscription_id}`,
   **exactly once**. The account secret is **minted at claim time and only its hash
   is stored** — never persisted in plaintext, never returned twice.
5. **Every desktop launch → `GET /v1/subscription`** (account-secret auth)
   re-validates; the relay's revocation channel is still the authoritative cutoff.

The desktop may also claim by polling `POST /v1/accounts/claim` with the held
`nonce` (fallback for when the browser redirect doesn't reach the loopback
callback). When that poll wins the race it consumes the single-use claim, so
`GET /v1/checkout/return` then finds the claim **consumed** and shows the success
page (the desktop already has its credential) — it is not treated as expired.

**"Subscription Settings"** opens the **Stripe Customer Portal** via `POST
/v1/billing-portal` (mints a portal session for the account's customer). Enable
the portal once in the Stripe dashboard (test: Settings → Billing → Customer
portal), or the call returns `502 stripe_error`.

Requires `AUTH_STRIPE_PRICE_ID` (the plan's price), `AUTH_STRIPE_SECRET_KEY`, and
`AUTH_PUBLIC_URL` (the `success_url` base); without `AUTH_STRIPE_PRICE_ID`,
`/v1/checkout/start` returns `503 checkout_unavailable`. Security: the redirect is
validated **loopback-only** so a `claim_code` can never be delivered to a remote
host; the claim is single-use with a short TTL (`AUTH_CLAIM_TTL`, default 30m);
the `nonce` binds start→webhook→return and `/return` checks `session_id`.

### Subscription lifecycle (M2 exit criterion)

The hermetic end-to-end test drives **purchase → use → fail payment → grace →
cancel → cutoff** with a fake Stripe (real signature scheme) and a shared
backplane, asserting the relay closes sessions `4004` on cancellation:

```sh
go test ./test/integration/ -run TestSubscriptionLifecycleE2E -v
```

The Postgres store is covered by the same conformance suite the memory store
passes; run it against a disposable database:

```sh
AUTH_TEST_DB_DSN='postgres://user:pass@localhost:5432/auth_test?sslmode=disable' \
  go test ./internal/authstore/postgres/
```

## Configuration (auth, env, `AUTH_` prefix)

| Var | Default | Purpose |
|---|---|---|
| `AUTH_LISTEN_ADDR` | `:8080` | bind address |
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
| `AUTH_STRIPE_WEBHOOK_SECRET` | — | webhook signature secret (required) |
| `AUTH_STRIPE_SECRET_KEY` | — | Stripe API key; enables nightly reconciliation + desktop checkout |
| `AUTH_STRIPE_PRICE_ID` | — | subscription plan price; enables `POST /v1/checkout/start` (requires `AUTH_PUBLIC_URL` + `AUTH_STRIPE_SECRET_KEY`) |
| `AUTH_PUBLIC_URL` | — | this service's public base URL; the checkout `success_url`/`return` base |
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

## Client SDKs (M4)

Thin Relay Client SDKs live under [`sdk/`](./sdk) (a Gradle 8.7 / JDK 17 multi-module
build plus a Swift package). `sdk/core` holds all contract logic once — FR-5 crypto,
the wire protocol codec, the pairing/token HTTP client, the per-session handshake, and
the reconnect/state machine — and the per-platform modules add transport, key storage,
and an idiomatic facade. See [`sdk/README.md`](./sdk/README.md) for details and
[`sdk/ios/vectors-spec.md`](./sdk/ios/vectors-spec.md) for the E2EE interop contract.

Build and test (from `sdk/`):

```sh
./gradlew build                                  # compile all modules + unit tests
./gradlew :core:test :java:test :android:test    # incl. vectors conformance (Java + Kotlin)
./gradlew :java:e2eTest                           # cross-platform E2E vs the real relay + auth
```

`:java:e2eTest` is the **M4 exit criterion**: it builds and boots the real `cmd/relay` +
`cmd/auth` binaries (memory backplane/store, no Redis/Stripe), generates an ES256 key
with `cmd/devtoken`, seeds a license via `AUTH_DEV_SEED`, and runs the full **Kotlin
mobile ↔ Java desktop** flow — pair (QR) → token → `wss` connect → handshake →
bidirectional encrypted send/ack — asserting the relay only ever sees ciphertext. It
uses the project's Go toolchain at `~/.local/go-sdk/go/bin/go` (override the repo root
with `-Dsdk.repoRoot=...` if needed).

> `AUTH_DEV_SEED="<account>,<license>,<subscription>"` is a **dev-only** seam on
> `cmd/auth` (memory store only) that provisions a deterministic active license, since
> licenses are otherwise minted only via signed Stripe webhooks with no read-back path.

The Android module is built as a plain Kotlin/JVM library so it compiles, unit-tests, and
runs the E2E on Linux (no Android SDK required here); a real Android build re-targets it
with `com.android.library` + `lazysodium-android`. The iOS Swift package needs Xcode —
run its vectors-conformance test on macOS with `cd sdk/ios && swift test` (see
[`sdk/ios/README.md`](./sdk/ios/README.md)).

## Hardening & scale (M5)

Production hardening on top of M1–M4 — **additive only**, no client-visible contract
changed (wire envelope, close codes, JWT claims, e2ee vectors, and the SDK API are
frozen):

- **Rate limiting & abuse control** (`internal/ratelimit`): per-IP connection-attempt
  limiting and a temporary ban for repeat protocol-error/oversize (`4005`) offenders at
  the relay, plus per-IP + per-account limiting on the auth token/pairing endpoints. All
  reject **before** the WebSocket upgrade with `HTTP 429 + Retry-After`. On by default;
  see the `RELAY_RATELIMIT_*` / `RELAY_ABUSE_*` / `AUTH_RATELIMIT_*` knobs.
- **Capacity validation** (`test/bench`, `make bench`): CI-asserted §10.1 targets —
  forward-latency p99 ≤ 50 ms, token-verify p99 ≤ 1 ms, revocation ≤ 2 s, and a scaled
  reconnect-storm — plus the full 50k-connection procedure in [`docs/capacity.md`](./docs/capacity.md).
- **Observability**: fd-saturation, backplane-health (`*_backplane_up`), webhook
  queue/lag, and TLS cert-expiry metrics, with committed Prometheus alert rules
  ([`deploy/prometheus/alerts.yml`](./deploy/prometheus/alerts.yml)) and a Grafana
  dashboard ([`deploy/grafana/relay-dashboard.json`](./deploy/grafana/relay-dashboard.json)).
- **Deployment hardening**: digest-pinned base images, HSTS + an explicit modern cipher
  allow-list (`internal/httpsec`), kernel/TCP tuning ([`docs/tuning.md`](./docs/tuning.md)),
  and Kubernetes manifests ([`deploy/k8s/`](./deploy/k8s)).
- **Threat model**: [`docs/threat-model.md`](./docs/threat-model.md). FR-3.7
  sender-constrained tokens are deferred to Phase 2 (would change the frozen handshake).

See **[Deployment](#deployment)** below for local dry-run and production VPS instructions.

### Manual end-to-end verification

Drive the whole stack by hand — relay + auth + both SDKs — with no Redis or Stripe. This
uses the in-memory stores and the dev license seed; all commands run from the repo root
unless noted. You'll use **three terminals**.

**1. Build the binaries and a signing key** (one time):

```sh
export PATH="$PATH:$HOME/.local/go-sdk/go/bin"
make build          # bin/relay, bin/auth, bin/devtoken
make keys           # ./keys/relay.{key.json,pub.pem,jwks.json}
```

**2. Terminal 1 — start the auth service** (seeds a deterministic account license):

```sh
AUTH_LISTEN_ADDR=127.0.0.1:8080 \
AUTH_STORE=memory AUTH_BACKPLANE=memory \
AUTH_JWT_ISSUER=https://auth.example.com \
AUTH_JWT_SIGNING_KEY_FILE=./keys/relay.key.json \
AUTH_STRIPE_WEBHOOK_SECRET=whsec_dev \
AUTH_ADMIN_KEY=admin-e2e-key \
AUTH_DEV_SEED=acct_e2e,lic_e2e,sub_e2e \
AUTH_RELAY_URL=ws://127.0.0.1:8443/v1/connect \
AUTH_PUBLIC_URL=http://127.0.0.1:8080 \
  ./bin/auth
```

The log line `DEV SEED active — provisioned test license` confirms the seed. The
`AUTH_ADMIN_KEY`, `AUTH_DEV_SEED` account, and `AUTH_RELAY_URL` here must match the values
the driver expects (they do, by default).

**3. Terminal 2 — start the relay** (verifies tokens via the auth JWKS):

```sh
RELAY_LISTEN_ADDR=127.0.0.1:8443 \
RELAY_BACKPLANE=memory \
RELAY_JWT_ISSUER=https://auth.example.com \
RELAY_JWKS_URL=http://127.0.0.1:8080/.well-known/jwks.json \
RELAY_JWT_ALGS=ES256 \
  ./bin/relay
```

Both `RELAY_JWT_ISSUER` and `AUTH_JWT_ISSUER` must match. Sanity-check health:

```sh
curl -fsS http://127.0.0.1:8080/healthz && echo      # auth -> {"status":"ok"}
curl -fsS http://127.0.0.1:8443/healthz && echo      # relay -> ok
```

**4. Terminal 3 — run the SDK driver** (Kotlin mobile ↔ Java desktop, through the live relay):

```sh
cd sdk
./gradlew :java:manualE2E            # add -DauthUrl=… -DwsUrl=… to override the defaults
```

It creates the account, generates the pairing QR, pairs, connects both ends, and exchanges
one encrypted message each way. Expected output:

```
[manual-e2e] desktop QR payload: {"v":1,"pairing_token":"pt_…","desktop_pubkey":"…",…}
[manual-e2e] paired: pair_id = pair_…
[manual-e2e] both ends connected
[manual-e2e] desktop received: "hello desktop, from the mobile SDK"
[manual-e2e] mobile received:  "reply from the desktop SDK"
[manual-e2e] OK — bidirectional encrypted exchange succeeded (the relay only saw ciphertext)
```

**5. Confirm the relay never saw plaintext** — the relay's own log must contain only
ciphertext and routing metadata (FR-5.4). With the relay log captured to a file, e.g.
`./bin/relay … | tee /tmp/relay.log`:

```sh
grep -c "hello desktop, from the mobile" /tmp/relay.log    # -> 0
```

To inspect the auth/pairing HTTP contract by hand instead, the same flow is exposed over
JSON (`POST /v1/accounts` → `/v1/devices` → `/v1/pairing-tokens` → `/v1/pairings` →
`/v1/token`); the QR payload returned by `/v1/pairing-tokens` is what step 4 carries. (Driving
the *encrypted* exchange by hand isn't practical — the SDK driver above does the X25519/HKDF/
XChaCha20 handshake for you.) Press Ctrl-C in terminals 1 and 2 to stop.

## Deployment

Two paths are documented here: a **local dry-run** of the full stack on your
machine (Docker), and a **production deployment on a single VPS** with automatic
HTTPS. For multi-node/scale-out, Kubernetes manifests live in
[`deploy/k8s/`](./deploy/k8s) ([`deploy/README.md`](./deploy/README.md)).

Topology in both cases:

```
clients ──wss/https──▶ TLS termination ──▶ relay (:8443)  ┐
                       (Caddy in prod,     auth  (:8080)  ├─▶ Redis (slots/routing/revocation)
                        none for dry-run)                 └─▶ Postgres (auth state)
```

The relay holds **no secrets** and verifies tokens via the auth service's JWKS;
the auth service holds the JWT signing key and Stripe secrets. Keep secrets in env
/ mounted files — **never in an image**.

### Local dry-run (docker compose)

The repo-root [`docker-compose.yml`](./docker-compose.yml) builds both images and
runs the full stack (Redis + Postgres + auth + relay) with the production
container hardening (distroless/non-root, read-only rootfs, `cap_drop: ALL`,
`no-new-privileges`, `nofile` ulimit, and the relay TCP sysctls). It serves plain
HTTP (no TLS) — intended for a TLS-terminating proxy in prod, and fine for a local
dry-run.

```sh
make keys                 # ./keys/relay.key.json (the auth signing key, mounted ro)
# The auth container runs as the distroless nonroot user (uid 65532), so the
# bind-mounted key must be readable by it. For this throwaway dev key:
chmod 0755 keys && chmod 0644 keys/relay.key.json
docker compose up --build # redis, postgres, auth (:8080), relay (:8443)
```

> **`permission denied` on `/keys/relay.key.json`?** `make keys` writes the key
> `0600` owned by your host user, but the container runs as uid 65532 — run the
> `chmod` above (dev), or `chown` it to the container uid (prod, see below).
>
> **Redis `Memory overcommit must be enabled` warning?** Harmless here — our Redis
> runs with persistence disabled, so it never forks for a background save. It is a
> host kernel setting (`vm.overcommit_memory`) that cannot be set per-container; to
> silence it run `sudo sysctl vm.overcommit_memory=1` on the host.

Verify the stack (in another terminal):

```sh
# Health
curl -fsS localhost:8080/healthz && echo      # auth  -> {"status":"ok"}
curl -fsS localhost:8443/healthz && echo      # relay -> ok

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

#### Drive the full SDK flow against the stack (no Stripe)

A real token → pair → connect → encrypted-send flow needs an **account** and a
valid **license**. Without Stripe there is no license, so layer the dev-seed
override: it switches auth to the in-memory store and seeds a deterministic active
license matching the constants the `:java:manualE2E` driver expects (admin key
`admin-e2e-key`, account `acct_e2e`, license `lic_e2e`).

```sh
docker compose -f docker-compose.yml \
               -f deploy/compose/docker-compose.dev-seed.yml up --build
# then, from sdk/:
./gradlew :java:manualE2E
```

It creates the account, pairs the Kotlin (mobile) and Java (desktop) SDKs, and
exchanges an encrypted message each way. (Without the override you'll get
`403 forbidden` on account creation — the base compose uses a different admin key
and the Postgres store, where `AUTH_DEV_SEED` is disabled.) Alternatively, hand-run
the binaries per [Manual end-to-end verification](#manual-end-to-end-verification).
Tear down with `docker compose down -v`.

> **No Stripe but want the Postgres store?** Licenses are otherwise minted only by
> signed Stripe webhooks. Either send a signed test webhook to
> `POST /v1/webhooks/stripe` (PRD §6.4), or insert a `subscription` + `license`
> row directly — the dev-seed override above is the simpler path for local testing.

### Production (VPS)

A single 2 vCPU / 4 GB Linux VPS (the PRD §10.1 reference instance) runs the whole
stack behind **Caddy**, which obtains and renews Let's Encrypt certificates
automatically, terminates TLS, forwards WebSocket upgrades, and sets
`X-Forwarded-For` so per-IP rate limiting sees the real client. The bundle lives
in [`deploy/compose/`](./deploy/compose): `docker-compose.prod.yml`, `Caddyfile`,
and `.env.example`.

**1. DNS** — point two A records at the VPS public IP:
`relay.example.com` and `auth.example.com`.

**2. VPS prep** — install Docker Engine + the compose plugin, then apply the host
kernel/ulimit tuning so the box can hold many connections (full rationale and
values in [`docs/tuning.md`](./docs/tuning.md)):

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

Open only **80/443** at the firewall; Redis and Postgres stay on the internal
Docker network and must not be exposed.

**3. Secrets & signing key** — from the repo on the VPS:

```sh
cd deploy/compose
cp .env.example .env          # set RELAY_HOST/AUTH_HOST/ACME_EMAIL/JWT_ISSUER and
                              # real POSTGRES_PASSWORD, REDIS_PASSWORD, Stripe secrets, admin key
mkdir -p keys
go run ../../cmd/devtoken -gen-keys -out-dir ./keys -alg ES256   # writes keys/relay.key.json

# The auth container runs as uid 65532 (distroless nonroot). Give that uid read
# access WITHOUT making the signing key world-readable:
sudo chown -R 65532:65532 keys && sudo chmod 0750 keys && sudo chmod 0640 keys/relay.key.json
```

`.env` and `keys/` are gitignored — keep them on the host only. Back up
`keys/relay.key.json`: losing it invalidates every issued token (rotate it via the
JWKS to roll keys, ≤ 90 days per PRD §10.2).

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
```

**6. Stripe** — in the Stripe dashboard add a webhook endpoint
`https://auth.example.com/v1/webhooks/stripe` for the subscription/invoice events
(PRD §6.4), copy its signing secret into `.env` as `AUTH_STRIPE_WEBHOOK_SECRET`,
and `docker compose -f docker-compose.prod.yml up -d auth` to apply. Licenses are
provisioned only by signed webhooks; the nightly reconciliation (needs
`AUTH_STRIPE_SECRET_KEY`) heals any missed ones.

**7. Provision an account** — once Stripe drives subscriptions this is automatic;
to create an account credential manually use the admin key:

```sh
curl -fsS -X POST https://auth.example.com/v1/accounts \
  -H "Authorization: Bearer $AUTH_ADMIN_KEY" \
  -d '{"account_id":"acct_123"}'
```

#### Build off-box (recommended for production)

Steps 4–5 above build the relay/auth images **on the VPS** (`up -d --build`). That
is the simplest path, but it drags the Go toolchain, the full repo source, and
build caches onto the production box, and a build competes with live traffic for
the 2 vCPU / 4 GB. For a hardened deployment, build the images on a separate
**secure builder**, push a versioned, digest-pinned artifact, and have the VPS
only ever pull and run it. Use
[`docker-compose.prod-image.yml`](./deploy/compose/docker-compose.prod-image.yml),
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

*No registry?* Ship a tarball over SSH instead of pushing/pulling:
`docker save $IMAGE_REGISTRY/relay:$IMAGE_TAG $IMAGE_REGISTRY/auth:$IMAGE_TAG | gzip | ssh deploy@vps 'gunzip | docker load'` — then skip the `login`/`pull` below and go straight to `up -d`.

**2. Get the signing key onto the VPS** (generate on the builder, copy over SSH —
this avoids needing the Go toolchain on the VPS just to run `devtoken`):

```sh
# on the builder (one time)
go run ./cmd/devtoken -gen-keys -out-dir ./keys -alg ES256
scp keys/relay.key.json deploy@vps:/srv/secure-gateway/deploy/compose/keys/
# on the VPS — lock it down to the distroless uid 65532 (see step 3 above)
sudo chown -R 65532:65532 keys && sudo chmod 0750 keys && sudo chmod 0640 keys/relay.key.json
```

Back the key up off-box (encrypted): losing it invalidates every issued token;
rotate via JWKS ≤ 90 days (PRD §10.2).

**3. Deploy** (on the VPS — no toolchain, no repo build, no `--build`):

```sh
cd deploy/compose
cp .env.example .env          # fill in real values, incl. IMAGE_REGISTRY / IMAGE_TAG
docker login ghcr.io                                       # registry READ credential (a PAT with read:packages)
docker compose -f docker-compose.prod-image.yml pull
docker compose -f docker-compose.prod-image.yml up -d
docker compose -f docker-compose.prod-image.yml ps
```

Upgrades and rollbacks are then a one-line image swap: bump `IMAGE_TAG` in `.env`,
`pull`, and `up -d` (or set it back to the previous tag to roll back). Verify over
HTTPS and configure Stripe exactly as in steps 5–7 above.

#### TLS without a reverse proxy (alternative)

To terminate TLS directly at the relay/auth instead of Caddy, mount certificates
and set `RELAY_TLS_CERT_FILE`/`RELAY_TLS_KEY_FILE` (and the `AUTH_*` equivalents),
publish `:8443`/`:8080`, and set `RELAY_TRUST_PROXY=false` / `AUTH_TRUST_PROXY=false`
(the client IP is then the real socket peer). The relay already enforces TLS 1.2+,
a modern cipher allow-list, and HSTS; `relay_tls_cert_expiry_seconds` then reports
days-to-expiry for alerting.

#### Operations

- **Zero-downtime deploys**: rebuild and `up -d`; on `SIGTERM` each service sends
  `sys{shutdown}` and drains for up to `*_SHUTDOWN_DRAIN` (30s) while clients
  reconnect with jittered backoff.
- **Backups**: snapshot the `pgdata` volume (auth/license state). Redis holds only
  ephemeral slots and may be wiped safely (new claims just re-establish).
- **Monitoring**: scrape `/metrics` on both services with Prometheus, load
  [`deploy/prometheus/alerts.yml`](./deploy/prometheus/alerts.yml) into
  `rule_files`, and import
  [`deploy/grafana/relay-dashboard.json`](./deploy/grafana/relay-dashboard.json).
  Key alerts: auth-failure spike, fd saturation, `*_backplane_up == 0`, webhook
  lag, and cert expiry.
- **Capacity**: this single instance targets ≥ 50k connections; see
  [`docs/capacity.md`](./docs/capacity.md) for the load-test procedure. When one
  VPS is not enough, scale to multiple relay instances behind an L4/L7 load
  balancer with shared (managed) Redis + Postgres — the Kubernetes manifests in
  [`deploy/k8s/`](./deploy/k8s) do exactly this.

## Close codes (Appendix B)

| Code | Meaning | Client behavior |
|---|---|---|
| 1000/1001 | normal / going away (deploy drain) | reconnect with jitter |
| 4001 | superseded (slot evicted) | do not auto-reconnect; "connected elsewhere" |
| 4003 | token_expired | refresh token, reconnect |
| 4004 | revoked (license/pairing) | do not reconnect; surface licensing state |
| 4005 | protocol_error / oversize | log, limited retries |
