# secure-gateway

**Secure Device Relay** — a subscription-gated WebSocket relay that lets a mobile
app reach its paired desktop app from anywhere, even behind NAT or a firewall.
Both ends dial *out* to the relay over `wss://`; the relay pairs them and forwards
**end-to-end-encrypted** frames it cannot read.

## The problem

A desktop app behind home or corporate NAT has no reachable address, so a phone
can't connect to it directly. The usual fixes — port forwarding, a VPN, or
punching holes in a firewall — are fragile and expose the desktop to the internet.
And a naïve relay in the middle can read everything that passes through it.

Secure Device Relay solves this with a rendezvous service that **both devices dial
out to** (so neither needs an inbound route), pairs them, and forwards traffic
that is **end-to-end encrypted between the two devices** — the relay only ever
sees ciphertext and routing metadata. Access is **gated on an active
subscription**, with revocation that cuts off live sessions within seconds.

## How it works

```
clients ──wss/https──▶ TLS termination ──▶ relay (:8443)  ┐
                       (Caddy in prod,     auth  (:8080)  ├─▶ Redis (slots/routing/revocation)
                        none for dry-run)                 └─▶ Postgres (auth state)
```

- **Relay** (`cmd/relay`) — verifies a connection JWT **before** the WebSocket
  upgrade, enforces one mobile + one desktop slot per pair, and forwards opaque
  E2EE frames. It holds no secrets and **never logs payloads**.
- **Auth & License Service** (`cmd/auth`) — mirrors Stripe subscription state,
  issues short-lived connection JWTs **only** for valid licenses, drives QR
  pairing, and publishes revocations. It holds the JWT signing key; the relay
  verifies tokens against its published JWKS.
- **End-to-end encryption** — X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305.
  Pairing private keys never leave the device; only public keys are exchanged.
- **Backplane** — in-memory for a single instance, or Redis for multi-instance
  routing, slot enforcement, and revocation fan-out.
- **Client SDKs** (`sdk/`) — Android (Kotlin), desktop (Java), iOS (Swift) hide
  the reconnect, token-refresh, and crypto so host apps deal only in plaintext
  messages and connection state.

The system was built across five milestones (M1 relay core → M5 hardening &
scale); the [architecture reference](./docs/ARCHITECTURE.md) breaks each down,
along with the HTTP APIs, billing modes, and close codes.

## Quick start (local stack with Docker)

The repo-root [`docker-compose.yml`](./docker-compose.yml) builds both images and
runs the full stack (Redis + Postgres + auth + relay) with production container
hardening (distroless/non-root, read-only rootfs, dropped capabilities). It serves
plain HTTP — intended for a TLS-terminating proxy in prod, and fine for a local
dry-run. You need only Docker (with the compose plugin) and the Go toolchain to
generate a signing key.

```sh
make keys                 # ./keys/relay.key.json (the auth signing key, mounted ro)
# The auth container runs as the distroless nonroot user (uid 65532), so the
# bind-mounted key must be readable by it. For this throwaway dev key:
chmod 0755 keys && chmod 0644 keys/relay.key.json
docker compose up --build # redis, postgres, auth (:8080), relay (:8443)
```

Verify the stack (in another terminal):

```sh
curl -fsS localhost:8080/healthz && echo      # auth  -> {"status":"ok"}
curl -fsS localhost:8443/healthz && echo      # relay -> ok
```

> **`permission denied` on `/keys/relay.key.json`?** `make keys` writes the key
> `0600` owned by your host user, but the container runs as uid 65532 — run the
> `chmod` above (dev), or `chown` it to the container uid (prod).
>
> **Redis `Memory overcommit must be enabled` warning?** Harmless — our Redis runs
> with persistence disabled, so it never forks for a background save. To silence
> it, `sudo sysctl vm.overcommit_memory=1` on the host.

To drive a full **token → pair → connect → encrypted-send** flow through the
SDKs (with a dev license seed, no Stripe), and for running the binaries without
Docker, see the [build book](./docs/BUILD.md). Tear down with
`docker compose down -v`.

## Documentation

| Document | What's in it |
|---|---|
| [Architecture](./docs/ARCHITECTURE.md) | Component breakdown (M1–M5), code layout, relay + auth HTTP APIs, billing modes, onboarding flow, close codes |
| [Build book](./docs/BUILD.md) | Toolchain, `make` targets, running services for dev, SDK build/test, benchmarks, manual end-to-end verification |
| [Production runbook](./docs/RUNBOOK.md) | VPS deploy with automatic HTTPS, off-box image builds, Stripe setup, operations, troubleshooting, full env-var reference |
| [Security policy](./SECURITY.md) | Vulnerability reporting, security model overview |
| [Threat model](./docs/threat-model.md) | Assets, trust boundaries, and enforcement points |
| [Contributing](./CONTRIBUTING.md) | Development workflow and pre-push checks |
| [Capacity](./docs/capacity.md) / [Tuning](./docs/tuning.md) | §10.1 targets + load-test procedure; host kernel/TCP tuning |
| [SDK guide](./sdk/README.md) | Client SDK internals and per-platform notes |
| [PRD](./docs/prd-secure-mobile-desktop-relay.md) | Full product requirements |

## License

[MIT](./LICENSE) © Context Solutions Inc.
