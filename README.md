# secure-gateway

Secure Device Relay — a subscription-gated WebSocket relay that lets a mobile
app reach its paired desktop app from anywhere, even behind NAT/firewalls. Both
ends dial *out* to the relay over `wss://`; the relay pairs them and forwards
**end-to-end-encrypted** frames it cannot read. See
[`prd-secure-mobile-desktop-relay.md`](./prd-secure-mobile-desktop-relay.md).

## Status: M1 — Relay core

This repository currently implements **M1**, the Go relay server:

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

The Auth & License Service (accounts, Stripe, pairing) and the client SDKs are
**not** in this milestone; `cmd/auth` is a reserved placeholder. Tokens for
development/tests are minted by `cmd/devtoken`, standing in for that service.

## Layout

```
cmd/relay        relay server entrypoint
cmd/auth         placeholder for the M2 Auth & License Service
cmd/devtoken     dev CLI: generate keys and mint test connection tokens
internal/config  RELAY_* env configuration
internal/token   JWT claims + asymmetric verification (static-PEM / JWKS)
internal/backplane          slot/routing/revocation interface
internal/backplane/memory   in-memory single-instance backplane
internal/backplane/redis    go-redis backplane (Lua claims + pub/sub)
internal/relay/protocol     wire envelope, message types, close codes
internal/relay/session      connection lifecycle (read/write/monitor pumps)
internal/relay/hub          per-instance registry, routing, presence
internal/relay/server       HTTP surface, /v1/connect, TLS, drain
internal/metrics, logging   Prometheus collectors, structured logging
test/testclient  reusable Go relay client
test/integration end-to-end tests (echo, lifecycle, slots, revocation, drain,
                 observability, cross-instance over Redis)
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

## Close codes (Appendix B)

| Code | Meaning | Client behavior |
|---|---|---|
| 1000/1001 | normal / going away (deploy drain) | reconnect with jitter |
| 4001 | superseded (slot evicted) | do not auto-reconnect; "connected elsewhere" |
| 4003 | token_expired | refresh token, reconnect |
| 4004 | revoked (license/pairing) | do not reconnect; surface licensing state |
| 4005 | protocol_error / oversize | log, limited retries |
