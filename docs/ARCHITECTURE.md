# Architecture

Component-level reference for the Secure Device Relay: what each service does,
the code layout, the HTTP APIs, billing modes, the desktop onboarding flow, and
the WebSocket close codes. For the high-level overview and quick start see the
[README](../README.md); the full requirements live in the
[PRD](./prd-secure-mobile-desktop-relay.md).

## Milestones

The system was built in five milestones (M1–M5). Each is additive; from M5 on
the client-visible contract (wire envelope, close codes, JWT claims, E2EE
vectors, SDK API) is frozen.

### M1 — Relay core (`cmd/relay`)

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

### M2 — Auth & License Service (`cmd/auth`)

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

### M3 — QR pairing & end-to-end encryption

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

### M4 — Client SDKs (`sdk/`)

Android (Kotlin), desktop (Java), iOS (Swift) — with one common API (`connect`,
`send(bytes)->ack`, `onMessage`, `onStateChange`, `pair(qr)` /
`generatePairingQr()`). Each implements FR-1 reconnect/heartbeat, FR-3 token
refresh, and FR-5 crypto internally, so host apps deal only in plaintext messages
and connection state. All three reproduce `vectors.json` byte-for-byte; a
cross-platform E2E (Kotlin mobile ↔ Java desktop) runs against the real relay +
auth binaries. See [`sdk/README.md`](../sdk/README.md). `cmd/devtoken` still mints
tokens for relay-only dev/tests.

### M5 — Hardening & scale

Production hardening on top of M1–M4 — **additive only**, no client-visible
contract changed (wire envelope, close codes, JWT claims, e2ee vectors, and the
SDK API are frozen):

- **Rate limiting & abuse control** (`internal/ratelimit`): per-IP
  connection-attempt limiting and a temporary ban for repeat
  protocol-error/oversize (`4005`) offenders at the relay, plus per-IP +
  per-account limiting on the auth token/pairing endpoints. All reject **before**
  the WebSocket upgrade with `HTTP 429 + Retry-After`. On by default; see the
  `RELAY_RATELIMIT_*` / `RELAY_ABUSE_*` / `AUTH_RATELIMIT_*` knobs in the
  [runbook](./RUNBOOK.md#configuration-reference).
- **Capacity validation** (`test/bench`, `make bench`): CI-asserted §10.1 targets
  — forward-latency p99 ≤ 50 ms, token-verify p99 ≤ 1 ms, revocation ≤ 2 s, and a
  scaled reconnect-storm — plus the full 50k-connection procedure in
  [`docs/capacity.md`](./capacity.md).
- **Observability**: fd-saturation, backplane-health (`*_backplane_up`), webhook
  queue/lag, and TLS cert-expiry metrics, with committed Prometheus alert rules
  ([`deploy/prometheus/alerts.yml`](../deploy/prometheus/alerts.yml)) and a Grafana
  dashboard ([`deploy/grafana/relay-dashboard.json`](../deploy/grafana/relay-dashboard.json)).
- **Deployment hardening**: digest-pinned base images, HSTS + an explicit modern
  cipher allow-list (`internal/httpsec`), kernel/TCP tuning
  ([`docs/tuning.md`](./tuning.md)), and Kubernetes manifests
  ([`deploy/k8s/`](../deploy/k8s)).
- **Threat model**: [`docs/threat-model.md`](./threat-model.md). FR-3.7
  sender-constrained tokens are deferred to Phase 2 (would change the frozen
  handshake).

## Code layout

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

## Auth & License Service API

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

## Billing modes (Stripe enabled vs. disabled)

The three `AUTH_STRIPE_*` credentials are an **all-or-none** unit, validated at
startup so an accidental omission can never silently leave secure links ungated:

| `AUTH_STRIPE_WEBHOOK_SECRET` / `_SECRET_KEY` / `_PRICE_ID` | `AUTH_BILLING_DISABLED` | Result |
|---|---|---|
| all three set | (ignored) | **Stripe enabled** — secure links gated on a valid subscription (also requires `AUTH_PUBLIC_URL`) |
| none set | `true` | **Stripe disabled** — secure links ungated; an open license is auto-provisioned. A loud warning is logged at startup |
| none set | unset/`false` | **startup error** — refuses to boot |
| some set, some missing | (any) | **startup error** — names the missing var(s) |

In disabled mode the desktop "upgrade" flow still works unchanged: `POST
/v1/checkout/start` auto-provisions an account + open license and returns a
`checkout_url` carrying a one-time `claim_code` (instead of a Stripe URL), which
the desktop redeems via `POST /v1/accounts/claim` exactly as in the paid flow —
so the client never needs to know whether Stripe is on or off. An open license is
also provisioned directly on `POST /v1/accounts` (returns `license_id`). Only
`POST /v1/webhooks/stripe` returns `503`.

## Desktop subscription onboarding (claim-token flow)

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

The paid path requires Stripe to be enabled — the `AUTH_STRIPE_*` trio plus
`AUTH_PUBLIC_URL` (the `success_url` base); see [Billing modes](#billing-modes-stripe-enabled-vs-disabled).
When Stripe is disabled, `/v1/checkout/start` skips Stripe entirely: it
auto-provisions the account + open license and returns a `checkout_url` carrying
the `claim_code` directly, so the same desktop flow completes without payment.
Security: the redirect is validated **loopback-only** so a `claim_code` can never
be delivered to a remote host; the claim is single-use with a short TTL
(`AUTH_CLAIM_TTL`, default 30m); the `nonce` binds start→webhook→return and
`/return` checks `session_id`.

## Close codes (Appendix B)

| Code | Meaning | Client behavior |
|---|---|---|
| 1000/1001 | normal / going away (deploy drain) | reconnect with jitter |
| 4001 | superseded (slot evicted) | do not auto-reconnect; "connected elsewhere" |
| 4003 | token_expired | refresh token, reconnect |
| 4004 | revoked (license/pairing) | do not reconnect; surface licensing state |
| 4005 | protocol_error / oversize | log, limited retries |
