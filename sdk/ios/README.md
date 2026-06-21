# SecureGatewaySDK (iOS)

The iOS Relay Client SDK (PRD §8.2). Same conceptual API as the Android (Kotlin) and desktop
(Java) SDKs: `pair(qr)`, `connect()`, `send(bytes)`, `onMessage`, `onStateChange`.

> **Build/test on macOS only.** This package uses CryptoKit and swift-sodium and cannot be
> compiled on Linux (no Xcode/Swift-Apple toolchain). The repo's Linux CI ships it as
> reviewed source; the vectors-conformance test is the contract gate, run on a Mac.

## Crypto (the contract)

Matches the Go reference (`internal/e2ee/e2ee.go`) and the JVM SDKs byte-for-byte:

- **X25519 ECDH** — CryptoKit `Curve25519.KeyAgreement` (raw shared secret). Long-term identity
  keys plus a per-session ephemeral keypair; the four-DH `ikm = ss||ee||md||dm` (Noise-KK style)
  gives **forward secrecy** (see `vectors-spec.md`).
- **HKDF-SHA256** — CryptoKit `HKDF<SHA256>` (RFC 5869); `salt = mobileEphemeralPub||desktopEphemeralPub`,
  `info = "secure-gateway/e2ee/v2|"+dir`, `dir ∈ {m2d,d2m}`, 32-byte output.
- **XChaCha20-Poly1305 (24-byte nonce)** — libsodium via **swift-sodium**
  (`aead.xchacha20poly1305ietf`). CryptoKit's `ChaChaPoly` is the **12-byte IETF** variant and
  will **not** match — do not use it for payloads.
- Wire = `nonce(24) || ciphertext+tag(16)`; AAD = `utf8(id) || bigEndianUint64(ts)`.

See [`vectors-spec.md`](vectors-spec.md) for the full scheme.

## Running the conformance test (macOS)

```sh
cd sdk/ios
swift test            # resolves swift-sodium, runs VectorsConformanceTests
# or: xcodebuild test -scheme SecureGatewaySDK -destination 'platform=iOS Simulator,name=iPhone 15'
```

`Tests/.../Resources/vectors.json` is a copy of the canonical
`internal/e2ee/testdata/vectors.json`; keep it in sync (the JVM SDKs copy it at build time).

## Usage sketch

```swift
let mobile = try MobileClient(authURL: "https://auth.example.com", accountSecret: secret,
                              keyStore: KeychainKeyStore(), pushWaker: NoopPushWaker())
mobile.onMessage = { data in /* plaintext app message */ }
mobile.onStateChange = { state in /* connected | reconnecting | peerOffline | revoked | superseded */ }

try await mobile.pair(scannedQR)   // QrPayload from the desktop's QR
try await mobile.connect()         // wss + handshake
try await mobile.send(Data("hello".utf8))
```

## Platform seams (host-app responsibilities)

- **Keychain / Secure Enclave** (`KeychainKeyStore`): the Secure Enclave can't hold X25519
  keys directly; production should wrap the X25519 private key with a Secure-Enclave key and
  store the wrapped blob (TODO marked in source).
- **APNs push-to-wake** (`PushWaker`): a silent `content-available` push wakes a backgrounded
  app to reconnect when the desktop's message returns `peer_offline`. Wire to your APNs
  delegate.
