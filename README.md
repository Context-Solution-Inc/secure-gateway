# secure-gateway

Secure Device Relay — a subscription-gated WebSocket relay that lets a mobile
app reach its paired desktop app from anywhere, even behind NAT/firewalls. Both
ends dial *out* to the relay over `wss://`; the relay pairs them and forwards
**end-to-end-encrypted** frames it cannot read. See
[`prd-secure-mobile-desktop-relay.md`](./prd-secure-mobile-desktop-relay.md).

## Status: M1 — Relay core, M2 — Auth & licensing, M3 — Pairing & E2EE, M4 — Client SDKs

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
                 lifecycle)
test/soak        build-tagged idle-connection leak soak
```

## Build & test

```sh
make build      # bin/relay and bin/devtoken (static, stripped)
make test       # unit + integration tests
make race       # tests under the race detector
make vet
make docker     # distroless image secure-gateway/relay:dev
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
| `RELAY_LOG_LEVEL` / `RELAY_LOG_FORMAT` | `info` / `json` | logging |
| `RELAY_INSTANCE_ID` | auto | overrideable instance identity |

## Auth & License Service (M2)

HTTP/JSON API (TLS in prod, or plain HTTP behind a proxy):

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /v1/webhooks/stripe` | Stripe signature | Ingest subscription events (idempotent, durable) |
| `POST /v1/accounts` | admin key | Provision an account credential (seam for the account backend) |
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
| `AUTH_STRIPE_SECRET_KEY` | — | Stripe API key; enables nightly reconciliation |
| `AUTH_RECONCILE_INTERVAL` | `24h` | reconciliation cadence |
| `AUTH_ADMIN_KEY` | — | gates `POST /v1/accounts`; empty ⇒ disabled |
| `AUTH_SHUTDOWN_DRAIN` | `30s` | graceful shutdown budget |
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

## Close codes (Appendix B)

| Code | Meaning | Client behavior |
|---|---|---|
| 1000/1001 | normal / going away (deploy drain) | reconnect with jitter |
| 4001 | superseded (slot evicted) | do not auto-reconnect; "connected elsewhere" |
| 4003 | token_expired | refresh token, reconnect |
| 4004 | revoked (license/pairing) | do not reconnect; surface licensing state |
| 4005 | protocol_error / oversize | log, limited retries |
