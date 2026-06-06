# Secure Gateway — Client SDKs (M4)

Thin Relay Client SDKs for the three platforms (PRD §8), with one common conceptual API so
host apps deal only in plaintext app messages and connection state:

```
connect(credentials) · send(bytes) -> ack · onMessage · onStateChange · pair(qr) / generatePairingQr()
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

iOS (macOS only): `cd ios && swift test`.

## Host-app integration seam (feature flag)

Each platform exposes one entry point the host toggles behind its relay feature flag:

- Desktop: `SecureGateway.desktop(DesktopConfig)` → `DesktopClient` (+ `generatePairingQr()`).
- Mobile (Kotlin): `SecureGateway.mobile(MobileConfig)` → `MobileClient` (+ `pair(qr)`).
- iOS (Swift): `MobileClient(authURL:accountSecret:…)`.

When the flag is off, the app keeps its legacy local QR-sync path. The QR payload is versioned
(`v:1`), so a legacy QR (no `v`) routes to the old behavior (FR-2 backward compatibility). Key
storage (`KeyStore`) and push-to-wake (`PushWaker`) are injected, so the host supplies the
platform implementations (Android Keystore/FCM, iOS Keychain/APNs, desktop OS keystore).
