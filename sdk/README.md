# Secure Gateway — Client SDKs (M4)

Thin Relay Client SDKs for the three platforms (PRD §8), with one common conceptual API so
host apps deal only in plaintext app messages and connection state:

```
connect(credentials) · send(bytes) -> ack · onMessage · onStateChange · pair(qr) / generatePairingQr() · unpair()
```

Each SDK implements FR-1 (reconnect with exponential backoff + full jitter, base 1s/cap 60s;
25s heartbeat), FR-3 (connection token in the `Authorization: Bearer` header on the wss
upgrade; `auth_refresh` over the live socket), and FR-5 crypto internally.

## Layout

| Module | Language | Transport | Crypto |
|---|---|---|---|
| `core/` | Java (JVM) | — (transport injected) | X25519 + XChaCha20-Poly1305 via **lazysodium**; HKDF-SHA256 via `javax.crypto.Mac` (RFC 5869) |
| `java/` | Java (desktop) | `java.net.http.WebSocket` | (via `core`) |
| `android/` | Kotlin (built as JVM lib here) | **OkHttp** | (via `core`) |
| `ios/` | Swift (source-only on Linux) | `URLSessionWebSocketTask` | CryptoKit (X25519/HKDF) + **swift-sodium** (XChaCha) |

`core` holds all contract logic (crypto, protocol codec, pairing/token HTTP client, handshake,
reconnect/state machine) once; the platform modules add transport, key storage, and an
idiomatic facade. This single-sources the byte-for-byte interop contract, which is the point of
M4.

> The Android module is built as a plain Kotlin/JVM library so it compiles, unit-tests, and runs
> the cross-platform E2E on Linux (no Android SDK here). The Android Keystore and FCM seams are
> stubbed behind `core` interfaces; a real Android build re-targets these with
> `com.android.library` + `lazysodium-android`. iOS likewise requires a Mac — see `ios/README.md`.

## Crypto parity — the gate

The first deliverable per platform is a crypto layer that reproduces
`internal/e2ee/testdata/vectors.json` byte-for-byte. The JVM modules copy that file from the Go
reference at build time (with a SHA-256 guard) so the SDK and the relay can never drift. See
`ios/vectors-spec.md` for the full scheme.

## Build & test (from `sdk/`)

```sh
./gradlew build                                  # compile all modules + unit tests
./gradlew :core:test :java:test :android:test    # incl. vectors conformance (Java + Kotlin)
./gradlew :java:e2eTest                           # cross-platform E2E vs the real Go relay+auth
```

`e2eTest` boots the real `cmd/relay` + `cmd/auth` Go binaries (memory backplane/store, no
Redis/Stripe), generates an ES256 key with `cmd/devtoken`, seeds a license via `AUTH_DEV_SEED`,
and runs the full **Kotlin mobile ↔ Java desktop** flow — pair (QR) → token → wss connect →
handshake → bidirectional encrypted send/ack — asserting the relay only ever sees ciphertext.
It locates the repo's Go toolchain at `~/.local/go-sdk/go/bin/go`.

`./gradlew :java:manualE2E` runs the same Kotlin↔Java flow against an **already-running**
relay + auth instead of booting its own. The driver expects admin key `admin-e2e-key`,
account `acct_e2e`, and a seeded license `lic_e2e`, so the backend must be configured to
match. The easiest no-Stripe backend is the docker compose stack with the dev-seed override:

```sh
# from the repo root:
docker compose -f docker-compose.yml -f deploy/compose/docker-compose.dev-seed.yml up --build
# then, from sdk/:
./gradlew :java:manualE2E            # add -DauthUrl=… -DwsUrl=… to override the defaults
```

A `403 forbidden` on account creation means the backend's `AUTH_ADMIN_KEY` doesn't match the
driver (and/or the license isn't seeded) — use the override above. See the repo README's
"Local dry-run" section for details.

iOS (macOS only): `cd ios && swift test`.

## Publishing (M4)

The SDK publishes `com.securegateway:{core,java,android}` two ways:

```sh
./gradlew publishToMavenLocal     # local dev — mobile-agent consumes from ~/.m2 (keyless)
./gradlew publish                 # push GPG-signed artifacts to GitHub Packages
```

`publish` targets this repo's **GitHub Packages** Maven registry
(`https://maven.pkg.github.com/Context-Solution-Inc/secure-gateway`). Credentials come from
gradle props `gpr.user`/`gpr.key` or env `GITHUB_ACTOR`/`GITHUB_TOKEN` (a PAT / the Actions
token with `read:packages` to consume, `write:packages` to publish).

**Signing** is in-memory GPG: set `signingKey` (ASCII-armored private key) + `signingPassword`
gradle props, or env `SIGNING_KEY`/`SIGNING_PASSWORD`. With no key the build publishes
**unsigned** (fine for `publishToMavenLocal`); a release SHOULD sign so the consumer can pin the
signature via Gradle dependency verification. CI does this on a published GitHub Release via
[`.github/workflows/publish-sdk.yml`](../.github/workflows/publish-sdk.yml) using the
`SDK_SIGNING_KEY` / `SDK_SIGNING_PASSWORD` secrets.

The published `version` is `allprojects { version }` in `build.gradle.kts` — bump it in
lockstep with the consumer's `libs.versions.toml` + `verification-metadata.xml` regen so a stale
mavenLocal jar can't shadow the signed remote.

## Host-app integration seam (feature flag)

Each platform exposes one entry point the host toggles behind its relay feature flag:

- Desktop: `SecureGateway.desktop(DesktopConfig)` → `DesktopClient` (+ `generatePairingQr()`).
- Mobile (Kotlin): `SecureGateway.mobile(MobileConfig)` → `MobileClient` (+ `pair(qr)`).
- iOS (Swift): `MobileClient(authURL:accountSecret:…)`.

When the flag is off, the app keeps its legacy local QR-sync path. The QR payload is versioned
(`v:1`), so a legacy QR (no `v`) routes to the old behavior (FR-2 backward compatibility). Key
storage (`KeyStore`) and push-to-wake (`PushWaker`) are injected, so the host supplies the
platform implementations (Android Keystore/FCM, iOS Keychain/APNs, desktop OS keystore).

**Endpoint security (0.2.2+).** The relay/auth endpoints read from the (untrusted) QR are
validated before use (`EndpointValidator`, mirrored in JVM + Swift): the relay endpoint must be
`wss://` and the auth endpoint `https://`, so a malicious QR cannot downgrade the connection JWT
(carried as `Authorization: Bearer`) to cleartext. Plaintext `ws://`/`http://` is allowed **only**
for loopback or RFC1918 private hosts (LAN development). An insecure or malformed endpoint throws
(`IllegalArgumentException` on the JVM, `EndpointError` on iOS — replacing the old force-unwrap).

## Lifecycle: pairing, reconnect, unpair

The QR's **pairing token is single-use** — it authorizes exactly one `completePairing`. A host
that re-runs `pair()` / `generatePairingQr()` on every reconnect (toggle off/on, app relaunch)
replays the spent token and the gateway returns `401 pairing_token_invalid`. So the SDK lets the
host **pair once and reconnect many**:

- **Mobile** (`MobileClient`): after `pair(qr)`, persist `deviceId()` + `pairId()` +
  `desktopPublicKeyB64()`. On a later launch, feed them back via `MobileConfig.deviceId` /
  `pairId` / `desktopPublicKeyB64` and call `connect()` directly — `isPaired()` returns true and
  no token is replayed. The X25519 identity itself persists via the injected `KeyStore`.
- **Desktop** (`DesktopClient`): persist `deviceId()` after the first `generatePairingQr()` and
  restore it via `DesktopConfig.deviceId` next launch. The gateway keys "re-pair" on the desktop
  **device id**, so reusing it makes a re-mint **reuse the account's `max_pairs` slot + the same
  `pair_id`** (FR-2.2/2.4) instead of registering a new device and failing `capacity_exceeded`
  while the prior pairing still holds the slot. Without this the desktop silently can't re-mint a
  QR after a restart.
- **`unpair()`** (both): revoke the pairing at the gateway (`POST /v1/pairings/unpair`) — cuts the
  peer's live session and frees the slot so a new device can pair. No-op before pairing completes;
  blocking HTTP, so call off the UI thread, then `close()`.

The pairing/token HTTP client (`core` `AuthClient`) uses **`java.net.HttpURLConnection`**, not
`java.net.http.HttpClient` — the latter is absent on Android (`NoClassDefFoundError` on-device).
`ConnectionManager.close()` is crash-safe: transport callbacks and `send()` no longer call
`exec.execute()` after `exec.shutdown()` (which threw `RejectedExecutionException` uncaught on the
OkHttp thread and crashed the host).
