# Build book

How to build, test, and run the Secure Device Relay from source for development.
The [quick start](../README.md#quick-start-local-stack-with-docker) covers the
self-contained Docker stack; this document covers building the binaries directly,
the SDKs, the benchmark/soak suites, and a manual end-to-end run of the whole
system without Docker. For production deployment see the
[runbook](./RUNBOOK.md); for the full env-var reference see its
[configuration reference](./RUNBOOK.md#configuration-reference).

## Toolchain

- **Go** — this repo's toolchain lives at `~/.local/go-sdk/go/bin` (not on
  `PATH` by default). Export it before running `make` or `go`:

  ```sh
  export PATH="$PATH:$HOME/.local/go-sdk/go/bin"
  ```

- **SDKs** — the JVM SDK build needs **JDK 17** and uses the bundled Gradle 8.7
  wrapper (`sdk/gradlew`). The iOS Swift package needs Xcode (macOS only).

## Build & test

```sh
make build         # bin/relay, bin/auth, bin/devtoken (static, stripped)
make test          # unit + integration tests
make race          # tests under the race detector
make vet
make docker        # distroless image secure-gateway/relay:dev
make docker-auth   # distroless image secure-gateway/auth:dev
```

## Run the relay locally

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

## Run the auth service locally

```sh
make keys                                    # writes ./keys/relay.key.json (signing key)
AUTH_JWT_ISSUER=https://auth.example.com \
AUTH_JWT_SIGNING_KEY_FILE=./keys/relay.key.json \
AUTH_STORE=memory \
AUTH_BACKPLANE=memory \
AUTH_BILLING_DISABLED=true \
AUTH_ADMIN_KEY=dev_admin_key \
AUTH_LISTEN_ADDR=127.0.0.1:8080 \
  ./bin/auth
```

The example above runs **without Stripe** (`AUTH_BILLING_DISABLED=true`): secure
links are ungated and `POST /v1/accounts` returns an auto-provisioned `license_id`.
To exercise the real billing path instead, drop that flag and set all three
`AUTH_STRIPE_*` vars plus `AUTH_PUBLIC_URL` (see
[Billing modes](./ARCHITECTURE.md#billing-modes-stripe-enabled-vs-disabled)).

Point the relay at its JWKS with `RELAY_JWKS_URL=http://127.0.0.1:8080/.well-known/jwks.json`
(use the shared Redis backplane on both so revocations propagate). `docker
compose up` brings up the full stack (auth + relay + Redis + Postgres).

## Capacity checks (§10.1)

CI-sized assertions for forward latency, token-verify, revocation propagation, and
a reconnect storm; scale up with env overrides (see
[`docs/capacity.md`](./capacity.md)):

```sh
make bench                                  # CI-sized assertions
make bench LAT_FRAMES=20000 STORM_CONNS=20000
```

## Soak (M1 exit criterion)

CI-sized by default; override for the full 10k / 24h run:

```sh
make soak                                  # 1000 conns, 5s
make soak SOAK_CONNS=10000 SOAK_DURATION=24h
```

It samples goroutine, heap, and FD counts and fails on unbounded growth.

## Subscription lifecycle (M2 exit criterion)

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

## Client SDKs

Thin Relay Client SDKs live under [`sdk/`](../sdk) (a Gradle 8.7 / JDK 17
multi-module build plus a Swift package). `sdk/core` holds all contract logic once
— FR-5 crypto, the wire protocol codec, the pairing/token HTTP client, the
per-session handshake, and the reconnect/state machine — and the per-platform
modules add transport, key storage, and an idiomatic facade. See
[`sdk/README.md`](../sdk/README.md) for details and
[`sdk/ios/vectors-spec.md`](../sdk/ios/vectors-spec.md) for the E2EE interop
contract.

Build and test (from `sdk/`):

```sh
./gradlew build                                  # compile all modules + unit tests
./gradlew :core:test :java:test :android:test    # incl. vectors conformance (Java + Kotlin)
./gradlew :java:e2eTest                           # cross-platform E2E vs the real relay + auth
```

`:java:e2eTest` is the **M4 exit criterion**: it builds and boots the real
`cmd/relay` + `cmd/auth` binaries (memory backplane/store, no Redis/Stripe),
generates an ES256 key with `cmd/devtoken`, seeds a license via `AUTH_DEV_SEED`,
and runs the full **Kotlin mobile ↔ Java desktop** flow — pair (QR) → token →
`wss` connect → handshake → bidirectional encrypted send/ack — asserting the relay
only ever sees ciphertext. It uses the project's Go toolchain at
`~/.local/go-sdk/go/bin/go` (override the repo root with `-Dsdk.repoRoot=...` if
needed).

> `AUTH_DEV_SEED="<account>,<license>,<subscription>"` is a **dev-only** seam on
> `cmd/auth` (memory store only) that provisions a deterministic active license,
> since licenses are otherwise minted only via signed Stripe webhooks with no
> read-back path.

The Android module is built as a plain Kotlin/JVM library so it compiles,
unit-tests, and runs the E2E on Linux (no Android SDK required here); a real
Android build re-targets it with `com.android.library` + `lazysodium-android`. The
iOS Swift package needs Xcode — run its vectors-conformance test on macOS with
`cd sdk/ios && swift test` (see [`sdk/ios/README.md`](../sdk/ios/README.md)).

## Manual end-to-end verification

Drive the whole stack by hand — relay + auth + both SDKs — with no Redis or
Stripe. This uses the in-memory stores and the dev license seed; all commands run
from the repo root unless noted. You'll use **three terminals**.

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
AUTH_BILLING_DISABLED=true \
AUTH_ADMIN_KEY=admin-e2e-key \
AUTH_DEV_SEED=acct_e2e,lic_e2e,sub_e2e \
AUTH_RELAY_URL=ws://127.0.0.1:8443/v1/connect \
AUTH_PUBLIC_URL=http://127.0.0.1:8080 \
  ./bin/auth
```

The log line `DEV SEED active — provisioned test license` confirms the seed. The
`AUTH_ADMIN_KEY`, `AUTH_DEV_SEED` account, and `AUTH_RELAY_URL` here must match the
values the driver expects (they do, by default).

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

It creates the account, generates the pairing QR, pairs, connects both ends, and
exchanges one encrypted message each way. Expected output:

```
[manual-e2e] desktop QR payload: {"v":1,"pairing_token":"pt_…","desktop_pubkey":"…",…}
[manual-e2e] paired: pair_id = pair_…
[manual-e2e] both ends connected
[manual-e2e] desktop received: "hello desktop, from the mobile SDK"
[manual-e2e] mobile received:  "reply from the desktop SDK"
[manual-e2e] OK — bidirectional encrypted exchange succeeded (the relay only saw ciphertext)
```

**5. Confirm the relay never saw plaintext** — the relay's own log must contain
only ciphertext and routing metadata (FR-5.4). With the relay log captured to a
file, e.g. `./bin/relay … | tee /tmp/relay.log`:

```sh
grep -c "hello desktop, from the mobile" /tmp/relay.log    # -> 0
```

To inspect the auth/pairing HTTP contract by hand instead, the same flow is
exposed over JSON (`POST /v1/accounts` → `/v1/devices` → `/v1/pairing-tokens` →
`/v1/pairings` → `/v1/token`); the QR payload returned by `/v1/pairing-tokens` is
what step 4 carries. (Driving the *encrypted* exchange by hand isn't practical —
the SDK driver above does the X25519/HKDF/XChaCha20 handshake for you.) Press
Ctrl-C in terminals 1 and 2 to stop.
