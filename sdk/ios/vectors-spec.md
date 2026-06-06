# E2EE interop contract (cross-platform)

The authoritative scheme is the Go reference `internal/e2ee/e2ee.go`; the canonical test
vectors are `internal/e2ee/testdata/vectors.json`. Every SDK (Go, Java, Kotlin, Swift) must
reproduce each vector **byte-for-byte** and decrypt it. This document restates the contract so
an implementer needs no Go.

## Primitives

| Step | Algorithm | Notes |
|---|---|---|
| Key agreement | X25519 (Curve25519) | 32-byte keys; raw scalar-mult shared secret; reject all-zero (low-order) output |
| KDF | HKDF-SHA256 (RFC 5869) | NOT libsodium's `crypto_kdf` (BLAKE2b) — use HMAC-SHA256 HKDF |
| AEAD | XChaCha20-Poly1305 | **24-byte nonce** (libsodium `..._xchacha20poly1305_ietf_*`); NOT the 12-byte IETF ChaCha |

## Directional session keys

Each side contributes a fresh 32-byte handshake nonce, exchanged in the first frame of the
session. Two directional keys are derived:

```
salt = mobile_handshake_nonce (32) || desktop_handshake_nonce (32)      # mobile first, fixed by ROLE
info = "secure-gateway/e2ee/v1|" + dir       # dir = "m2d" or "d2m"
K_dir = HKDF-SHA256(ikm = X25519(myPriv, peerPub), salt = salt, info = info, L = 32)
```

- **mobile** seals with `K_m2d`, opens with `K_d2m`.
- **desktop** seals with `K_d2m`, opens with `K_m2d`.

Salt ordering is fixed by role (mobile nonce first), **not** by who initiated. Re-deriving per
session gives session-granularity forward secrecy.

## Per-message AEAD

```
nonce   = 24 random bytes (one per message)
aad     = utf8(envelope.id) || big-endian uint64(envelope.ts)
cipher  = XChaCha20Poly1305_seal(key = K_send, nonce, plaintext, aad)   # ciphertext + 16-byte tag
wire    = nonce (24) || cipher
```

Open reverses it: split the 24-byte nonce prefix, then
`XChaCha20Poly1305_open(K_recv, nonce, cipher, aad)`. The `id` and `ts` used as AAD **must** be
the same values carried on the relay envelope (the sender must seal with the exact `ts` it puts
on the envelope — a mismatch fails authentication).

## Vector fields (`vectors.json`)

`{ scheme, vectors[] }`. Each vector (all byte fields lowercase hex):

`name`, `sender` (`mobile`/`desktop`), `mobile_private/public`, `desktop_private/public`,
`mobile_handshake_nonce`, `desktop_handshake_nonce`, `key_m2d`, `key_d2m`, `message_nonce` (24),
`id` (string), `ts` (int64), `plaintext` (hex, may be empty), `wire_ciphertext` (hex).

**Conformance:** derive public keys (assert == committed), derive `K_m2d`/`K_d2m` (assert ==),
re-seal `plaintext` with the fixed `message_nonce` (assert == `wire_ciphertext`), and open
`wire_ciphertext` back to `plaintext`. There are 4 vectors: basic m→d, basic d→m, empty
plaintext, and binary (non-UTF8) plaintext with a max-int `ts`.

## SDK framing note

The relay payload is opaque, so the SDKs carry a 1-byte tag inside it to distinguish the
cleartext handshake nonce (`0x01`) from an encrypted application frame (`0x02`). This framing is
an SDK detail above the crypto contract above; the vectors test only covers the crypto layer.
