# Threat model — Secure Device Relay

Status: M5 (Hardening & Scale). Maintained alongside
[`prd-secure-mobile-desktop-relay.md`](./prd-secure-mobile-desktop-relay.md)
(PRD §10.2). This document is the standalone form of the threat model that the
PRD references inline; update it when the architecture or enforcement points
change.

## 1. Assets

| Asset | Why it matters |
|---|---|
| User message content | Private user data. Must never be readable by our infrastructure. |
| Device identity private keys (X25519) | Used to authenticate the peer and pair. Compromise lets an attacker impersonate that device in future sessions, but per-session ephemeral keys give forward secrecy, so it does **not** expose previously recorded session traffic. Never leave the device. |
| JWT signing private key (ES256/EdDSA) | Can mint connection tokens for any pair. Lives only in the auth service. |
| Stripe webhook secret / API key | Forging webhooks could grant/deny licenses; API key can read billing data. |
| Account credentials / refresh tokens | Grant token issuance for an account's pairs. |
| Connection tokens (JWT, 10-min TTL) | Bearer access to a pair's relay slot until expiry. |
| License + subscription state | Determines who may use the service. |

## 2. Trust boundaries

```
 Untrusted clients (mobile/desktop)
        │  wss (TLS 1.2+), Bearer JWT
        ▼
 ┌──────────────┐   Redis (slots/routing/revocation) ── trusted internal net
 │    Relay     │◄───────────────────────────────────►┌──────────────┐
 │ (no secrets, │                                      │ Auth & License│── signing key, DB
 │  no decrypt) │  verifies JWT via JWKS (public key)  │   Service     │── Stripe webhooks/API
 └──────────────┘                                      └──────────────┘
```

- **Clients are untrusted.** All authz decisions are server-side (PRD §10.2);
  routing is derived only from validated token claims, never client input
  (FR-3.3).
- **The relay is minimally trusted.** It cannot mint tokens and cannot decrypt
  payloads (no-mint, E2EE). A relay compromise exposes ciphertext + routing
  metadata only.
- **The auth service is the crown jewel.** It holds the signing key and Stripe
  secrets. Compromise is catastrophic — keep its attack surface small.
- **Redis and Postgres** sit on a trusted internal network; they are not
  internet-exposed.

## 3. Key threats & mitigations

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T1 | **Token theft** (stolen JWT replayed by an attacker) | Short 10-min TTL; tokens only in the `Authorization` header, never URLs (FR-1.2); audience/issuer/expiry checked on every connect. Residual window ≤ TTL. | Mitigated; further hardening = T11 (FR-3.7), deferred. |
| T2 | **Relay compromise** (attacker controls a relay instance) | E2EE (XChaCha20-Poly1305) means payloads are ciphertext; relay holds only the JWKS public key and cannot mint tokens. No payload is logged or stored (FR-5.4, verified by `TestNoPayloadInLogs`). | Mitigated by design. |
| T3 | **Credential / seat sharing** (one license used by many) | Per-pair slot enforcement: exactly one mobile + one desktop slot, atomic claim in Redis; newest wins, older evicted (4001). | Mitigated. |
| T4 | **Subscription lapse / fraud** | License derived from Stripe state; token refresh re-checks license; immediate revocation channel closes live sessions ≤ 2s (4004). | Mitigated (≤15m graceful / ≤2s immediate). |
| T5 | **Forged Stripe webhooks** | Mandatory signature verification; idempotent, durable handlers; nightly reconciliation heals missed/forged events. | Mitigated. |
| T6 | **Connection-flood / DoS at the relay** | Per-IP connection-attempt rate limiting (pre-upgrade 429 + Retry-After). | Mitigated per-instance (see §4). |
| T7 | **Auth-endpoint abuse** (credential stuffing, token-mint flood, device-row amplification, slow-body/slow-read) | Per-IP + per-account rate limiting on token/pairing **and device-registration** endpoints (429 + Retry-After); `POST /v1/devices` is capped per account with idempotent re-registration of the same role+key (SG-10); full HTTP timeouts (`Read`/`Write`/`Idle`, not just header) bound slow-loris connections on both auth listeners (SG-08). | Mitigated per-instance. |
| T8 | **Protocol abuse / oversize frames** | Oversize/garbage frames closed with 4005; repeat offenders earn a temporary IP ban. | Mitigated per-instance. |
| T9 | **Signing-key compromise** | Key only in the auth service (HSM/KMS where available); rotated ≤90 days via JWKS; relay holds public key only. | Process control (key custody). |
| T10 | **MITM / downgrade** | TLS 1.2+ only, explicit modern ECDHE/AEAD cipher allow-list, HSTS on the HTTP surfaces. Client SDKs additionally reject a non-`wss://` relay (or non-`https://` auth) endpoint read from the **untrusted QR**, so a malicious QR cannot downgrade the connection JWT to cleartext — except for loopback/RFC1918 hosts (LAN-dev carve-out) (SG-14/SG-19). | Mitigated. |
| T11 | **Stolen-token-alone use** (bearer not bound to device) | **FR-3.7 sender-constrained tokens — deferred to Phase 2** (see §5). | Accepted residual (bounded by T1's short TTL). |

## 4. New M5 controls and their limitations

M5 adds in-process rate limiting and abuse banning (`internal/ratelimit`):

- **Per-instance, not global.** Limits and bans are tracked in each
  relay/auth process. Behind N instances an attacker gets up to N× the per-instance
  budget, and a ban on one instance does not propagate to others. This is an
  accepted v1 tradeoff: it keeps the hot connect path free of a Redis round-trip
  and avoids coupling rate-limiting to backplane availability. If global limits
  become necessary, move the ban/limit state to Redis (the backplane already
  exists) — designed for but not implemented in M5.
- **Client IP trust.** Per-IP limits key on `X-Forwarded-For` only when
  `RELAY_TRUST_PROXY` / `AUTH_TRUST_PROXY` is set; otherwise the socket peer
  address. Set the trust flag **only** behind a proxy that strips inbound XFF,
  or an attacker can spoof the header to evade/poison limits.
- **NAT considerations.** Per-IP limits can affect many users behind one NAT;
  defaults are generous and tunable. Per-account limits are the precise control.

## 4a. Desktop subscription onboarding (checkout claim-token flow)

The desktop "anywhere access" upgrade (`POST /v1/checkout/start` →
`checkout.session.completed` webhook → `GET /v1/checkout/return` →
`POST /v1/accounts/claim`) hands a freshly-paid desktop its account credential.
`/checkout/start` and `/accounts/claim` are **unauthenticated** (the desktop has
no account yet), so the controls are:

- **Loopback-only redirect.** `validateLoopbackRedirect` requires the desktop's
  `redirect_uri` to be `http` to a loopback host (no userinfo). The one-time
  `claim_code` is delivered only by 302 to that address, so a paid account's
  credential can never be redirected to an attacker-controlled host (open-redirect
  / code-exfiltration defense).
- **Single-use + short TTL.** The claim is consumed atomically
  (`ConsumeCheckoutClaim`, `UPDATE … WHERE status='ready'`), so a `claim_code`
  yields the credential at most once; it expires after `AUTH_CLAIM_TTL` (default
  30m) and is GC'd. Both unauthenticated endpoints are rate-limited per-IP.
- **Secret never persisted in plaintext / never reissued.** The account secret is
  minted at claim time and only its SHA-256 hash is stored on the account; the
  plaintext is returned exactly once in the claim response.
- **Nonce binding.** A desktop-generated nonce (≥128-bit) ties
  start→metadata→webhook→return together, and `/checkout/return` checks the
  Stripe `session_id` against the one recorded at start, so a forged success URL
  cannot drive a redirect for someone else's session.
- **`POST /v1/billing-portal`** ("Subscription Settings") is account-secret-authed
  and only ever mints a Stripe Customer Portal session for that account's own
  customer id (looked up server-side, never client-supplied).

Residual: an unclaimed account whose secret was never minted simply can't
authenticate (the subscription/licenses exist but are inert) and the claim
GC-expires; operator recovery is the admin `POST /v1/accounts` path.

## 5. FR-3.7 (sender-constrained tokens) — deferred

The PRD lists FR-3.7 (a connect-handshake nonce signed by the device's pairing
private key, binding the bearer token to the device keypair) as **Phase 2,
recommended**. It is **explicitly out of scope for M5**:

- It would change the **connect handshake** — a client-visible contract frozen by
  M1–M4. M5 is hardening-only and must not alter the wire envelope, close codes,
  JWT claims, or SDK API.
- The threat it closes (T11, stolen-token-alone) is already bounded by the short
  10-minute TTL (T1) and TLS transport.

Revisit in Phase 2 alongside an SDK/protocol version bump. When implemented it
should be additive (a new handshake message/field gated by negotiated version) so
older clients continue to work.

## 6. Residual risks (accepted for v1)

- Per-instance rate limiting (§4) — global enforcement deferred.
- Stolen-token-alone within the TTL window (T11/FR-3.7) — deferred.
- TLS-inspecting corporate proxies may break `wss` (documented limitation, PRD
  §13); an HTTP long-poll fallback is post-v1.
- Metadata retention: connection metadata (account/pair/jti, never payload) is
  retained ≤30 days for ops/debugging (PRD §10.2 privacy).

## 7. Verification

- E2EE / no-plaintext: `internal/e2ee` vectors; `TestNoPayloadInLogs` (FR-5.4).
- Rate limiting / bans: `internal/ratelimit` unit tests; relay + auth 429 and ban
  integration tests.
- Revocation timing: `test/bench` `TestRevocationPropagation` (≤2s).
- Desktop onboarding: `TestDesktopCheckoutClaimFlow` (single-use claim, success/409/410)
  + `TestCheckoutStartRejectsNonLoopbackRedirect` (loopback-only) in
  `test/integration`; `TestVerifyAcceptsMismatchedAPIVersion` in `internal/billing`.
- TLS hardening: `internal/httpsec` tests (HSTS, cipher allow-list).
- SDK transport security: `EndpointValidator` tests (JVM + Swift) — `wss`/`https` required,
  loopback/RFC1918 carve-out, malformed-URL rejection (SG-14/SG-19).
- Capacity / abuse bounds: `TestPairingCapacityNotExceededUnderConcurrency` (SG-16 atomic
  `max_pairs`), `TestDeviceRegistrationCap` / `…Idempotent` (SG-10), and refresh reuse detection
  `TestRefreshTokenReuseRevokesChain` (SG-17) in `test/integration`.
- Config fail-closed: metrics-addr validation tests in `internal/config` / `internal/authconfig`
  (SG-18); superseded-slot self-close `TestRenewSelfClosesOnSlotLoss` in `internal/relay/session`
  (SG-05).
- Run `/security-review` and `/code-review` (high) over the relay connect path,
  pairing flow, and `internal/ratelimit` before each release; resolve highs.
