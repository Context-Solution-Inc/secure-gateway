# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in the Secure Device Relay,
**please report it privately** — do not open a public issue or pull request.

Email **security@contextsolutions.ca** with:

- a description of the issue and its impact,
- steps to reproduce (or a proof of concept), and
- any affected versions / components.

We aim to acknowledge reports within a few business days and will keep you updated
as we investigate and remediate. Please give us a reasonable window to ship a fix
before any public disclosure.

## Security model in brief

The relay is designed so that **our infrastructure cannot read user traffic**:

- **End-to-end encryption (E2EE).** Messages are sealed on the sending device and
  opened only on the paired device — X25519 ECDH → HKDF-SHA256 directional keys →
  XChaCha20-Poly1305, with the envelope `id`/`ts` bound as AEAD associated data and
  a per-session receive-side anti-replay window. The relay forwards opaque
  ciphertext frames it cannot decrypt and **never logs payloads** (enforced by test).
- **Forward secrecy.** Each session mixes a fresh ephemeral X25519 exchange into the
  key derivation, so compromise of a device's long-term identity key does not expose
  previously recorded session traffic.
- **Pairing private keys never leave the device.** Only X25519 public keys are
  exchanged during QR pairing.
- **Asymmetric auth.** The relay verifies connection JWTs (ES256/EdDSA) against the
  auth service's published JWKS **before** the WebSocket upgrade; the JWT signing
  private key lives only in the auth service and is mounted as a runtime secret,
  never baked into an image.
- **Subscription-gated access** with immediate cutoff: revocations propagate over
  the shared backplane and close live sessions within ≤ 2 s (`4004`).
- **Hardened transport & runtime:** TLS 1.2+, a modern cipher allow-list, HSTS,
  per-IP / per-account rate limiting with abuse bans, and distroless, non-root,
  read-only-rootfs containers with all capabilities dropped.

For the full asset/threat enumeration, trust boundaries, and enforcement points,
see the [threat model](./docs/threat-model.md). The component-level security
design is described in the [architecture reference](./docs/ARCHITECTURE.md).

## Operational security

When deploying, follow the [production runbook](./docs/RUNBOOK.md):

- Keep `.env` and `keys/` on the host only (both are gitignored); never commit
  secrets or bake them into images.
- Back up the JWT signing key off-box (encrypted) and rotate it via the JWKS at
  least every 90 days (PRD §10.2) — losing it invalidates every issued token.
- Expose only ports 80/443; keep Redis and Postgres on the internal network.
