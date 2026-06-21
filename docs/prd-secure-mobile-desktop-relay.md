# PRD: Secure Mobile ↔ Desktop WebSocket Relay Service

| | |
|---|---|
| **Document status** | Draft v1.0 |
| **Date** | June 5, 2026 |
| **Component name** | Secure Device Relay ("the Relay") |
| **Server platform** | Go service, deployed on Linux (hardened container) |
| **Clients** | Android, iOS (mobile); Java desktop app on Linux, Windows, macOS |
| **Licensing authority** | Stripe (paid subscription → device/desktop license keys) |

---

## 1. Summary

This document specifies a secure, subscription-gated communication channel that lets the existing mobile application (Android, iOS) communicate with the existing Java desktop application from anywhere on the internet, even when the desktop sits behind a firewall or NAT that blocks inbound connections.

The solution is a **WebSocket relay**: both the mobile and desktop clients open *outbound* TLS WebSocket (`wss://`) connections to a relay server we operate. The relay authenticates each connection, pairs the two ends of a licensed device pair, and forwards messages between them. Message payloads are **end-to-end encrypted** between mobile and desktop using keys established during the product's existing QR-code sync flow, so the relay (and our infrastructure generally) can never read user content.

Access is governed by **Stripe subscriptions**. An active paid subscription entitles the user to one or more *device pairs* (one mobile + one desktop). License validity is always derived from current Stripe subscription state, synchronized via webhooks. When a subscription lapses, the corresponding connections are refused and/or terminated.

## 2. Background and problem statement

The product today synchronizes a mobile app and a desktop app using QR codes, which requires the devices to be near each other (and typically on the same network). Users need the mobile app to reach their desktop application from anywhere — but the desktop typically runs behind a home or corporate firewall/NAT (often carrier-grade NAT) where no inbound port can be opened, and the desktop's network location changes.

Direct connection is therefore not viable as a general solution. A relay that both endpoints dial *out* to solves reachability universally, requires zero network configuration by the user, and gives us a natural enforcement point for subscription licensing.

## 3. Goals

1. A mobile device can exchange messages with its paired desktop application from any network, with no router/firewall configuration by the user.
2. Access requires an active paid Stripe subscription; lapsed subscriptions lose access within a bounded, configurable window (default ≤ 15 minutes, immediate on demand).
3. Message content is end-to-end encrypted; the relay and all server-side infrastructure handle only ciphertext and routing metadata.
4. Reuse the existing QR-code sync flow as the device pairing and key-exchange mechanism, minimizing new UX.
5. Provide client SDKs / integration layers with a consistent API surface for Android (Kotlin), iOS (Swift), and desktop Java, so the existing applications integrate with minimal platform-specific code.
6. The relay runs as a single static Go binary in a minimal hardened Linux container, horizontally scalable.

## 4. Non-goals

- Peer-to-peer / NAT hole-punched direct connections (WebRTC). May be a future latency optimization; out of scope here.
- Offline message queuing / store-and-forward beyond a short in-flight buffer. v1 requires both endpoints online; a bounded queue is listed as a stretch item.
- Multi-desktop fan-out (one mobile broadcasting to N desktops). v1 supports 1:1 pairs only; the data model must not preclude it later.
- Payment UI. Checkout, plan selection, and billing management use Stripe Checkout and the Stripe Customer Portal; this PRD covers only the licensing integration.
- File transfer optimization (chunking/resume). The channel supports binary frames; large-transfer UX is a separate effort.

## 5. System overview

### 5.1 Components

**Relay Server (new, Go).** Public, internet-facing WebSocket endpoint. Validates connection tokens, registers connections by pair ID and role, forwards opaque encrypted frames between the two ends of a pair, enforces concurrency slots, and executes revocations. Deliberately "dumb": it cannot mint credentials and cannot decrypt payloads.

**Auth & License Service (new, Go; may share a binary or repo with the relay but is logically separate).** Owns accounts, device records, pairing records, and license state. Integrates with Stripe (webhooks + API). Issues short-lived signed connection tokens (JWT, asymmetric keys). The relay holds only the public verification key.

**Backplane (Redis).** Shared registry for connection slots (atomic claim/evict), cross-instance message routing when running multiple relay instances, and the revocation pub/sub channel.

**Stripe.** Source of truth for subscription state. Products/Prices define entitlements (number of device pairs). Webhooks drive license activation, grace, and revocation.

**Clients.** The existing Android/iOS mobile apps and the Java desktop app, each embedding a Relay Client SDK (Section 8).

### 5.2 Connection topology

```
[Mobile app] --outbound wss--> [Relay (Go, Linux)] <--outbound wss-- [Java desktop app]
                                      |
                                      +-- Redis (slots, routing, revocation)
                                      +-- verifies JWTs (public key only)

[Auth & License Service] <--webhooks/API--> [Stripe]
        |                                   
        +-- issues short-lived JWTs to clients (login/refresh)
        +-- manages pairing records (QR flow)
        +-- publishes revocation events to Redis
```

Routing rule: a connection authenticated for `pair_id = X` with `role = mobile` can be bridged **only** to the connection holding `pair_id = X, role = desktop`, and vice versa. The target is derived from validated token claims; there is no client-specified addressing.

## 6. Licensing model and Stripe integration

### 6.1 Entitlement model

- A **Stripe Customer** maps 1:1 to a product **Account**.
- An active **Stripe Subscription** entitles the account to `max_pairs` device pairs. `max_pairs` is read from the Price/Product metadata (e.g., `metadata.max_pairs = "1"` on the base plan), so plans can be added in Stripe without code changes.
- For each entitled pair, the Auth & License Service mints a **License Key** (`lic_…`): an opaque, randomly generated identifier stored server-side and bound to the account and subscription item. License keys are displayed to the user (account page / desktop app settings) and are the durable identifier a desktop installation activates with.
- A **Pairing record** (`pair_id`) binds: `license_id`, `account_id`, `mobile_device_id`, `desktop_device_id`, both device public keys, creation time, and status (`active`, `revoked`).

A license key is **valid** if and only if its underlying Stripe subscription is in an allowed state (Section 6.3). Stripe is the authority; the local database is a synchronized mirror, never an independent source of truth.

### 6.2 Purchase and activation flow

1. User purchases via **Stripe Checkout** (or upgrades via the **Customer Portal**). `checkout.session.completed` → webhook creates/links the Stripe Customer to the account and provisions license key(s) per `max_pairs`.
2. User signs into the **desktop app** and activates it with a license key (or selects it from their account). The desktop registers itself as a device (`desktop_device_id`, generates its keypair, submits the public key).
3. User signs into the **mobile app**; it likewise registers (`mobile_device_id`, keypair).
4. The **existing QR sync flow** completes the pairing (Section 7.2), producing the `pair_id`.

### 6.3 Subscription state → license behavior

| Stripe subscription status | License behavior |
|---|---|
| `trialing`, `active` | License valid. Tokens issued normally. |
| `past_due` | **Grace period** (configurable, default 7 days, matching Stripe Smart Retries). License remains valid; user is notified in-app. |
| `canceled`, `unpaid`, `incomplete_expired` | License **revoked**. Token refresh fails; immediate revocation event published; existing connections closed. |
| `paused` | License suspended (same enforcement as revoked, but pairing records retained for easy resume). |

### 6.4 Webhook handling (Auth & License Service)

| Event | Action |
|---|---|
| `checkout.session.completed` | Link customer ↔ account; provision licenses per plan metadata. |
| `customer.subscription.created` / `updated` | Recompute entitlements: status transitions per 6.3; `max_pairs` changes may add or (on downgrade) flag excess licenses for the user to choose which pair(s) to deactivate. |
| `customer.subscription.deleted` | Revoke all licenses on the subscription; publish revocation for each `pair_id`. |
| `invoice.payment_failed` | Enter grace period; trigger user notification. |
| `invoice.paid` | Clear grace state. |

Requirements: webhook endpoint verifies Stripe signatures; handlers are idempotent (Stripe retries); events are processed via a durable queue with dead-lettering; a nightly reconciliation job re-reads subscription state from the Stripe API to heal any missed webhooks.

### 6.5 Enforcement points (defense in depth)

1. **Token issuance** — the Auth & License Service refuses to issue/refresh a connection token for a pair whose license is invalid. With a 10-minute token TTL, a lapsed subscription loses access within ≤ 15 minutes with no further mechanism.
2. **Revocation channel** — for immediate cutoff (cancellation, fraud, device removal), the service publishes `{pair_id | account_id}` on the Redis revocation channel; every relay instance closes matching connections at once.
3. **Connect-time validation** — the relay independently validates token signature, expiry, audience, and claims on every connection attempt.

Policy decision (default): downgrades and payment failure are enforced *gracefully* (block at next token refresh); cancellations, refunds, and abuse are enforced *immediately* (revocation event).

## 7. Functional requirements

### FR-1: Transport and connection

1.1 All client connections are WebSocket over TLS 1.2+ (`wss://`), initiated outbound by clients to a single public endpoint (e.g., `wss://relay.example.com/v1/connect`).
1.2 The connection token is presented in the `Authorization: Bearer …` header of the HTTP upgrade request. Tokens MUST NOT appear in URLs or query strings.
1.3 The relay completes the upgrade only after successful token validation; failures return HTTP 401/403 with a machine-readable reason code before upgrade.
1.4 Heartbeat: relay sends WebSocket ping every 25 s; a connection missing 2 consecutive pongs is closed. Clients implement the mirror-image liveness check.
1.5 Clients reconnect automatically with exponential backoff plus full jitter (base 1 s, cap 60 s), resetting on success.
1.6 Maximum message size: 256 KB per frame (configurable). Oversize frames are rejected with a protocol error; large transfers must be chunked by the application layer.

### FR-2: Pairing via the existing QR flow

2.1 The current QR sync flow is extended to perform relay pairing and key exchange in the same user gesture. The QR payload (versioned) carries: a one-time pairing token (issued to the signed-in desktop by the Auth & License Service, TTL ≤ 5 min), the desktop's X25519 public key, the desktop device ID, and the relay/auth endpoints.
2.2 The mobile app scans the QR, then calls the Auth & License Service over HTTPS presenting the pairing token, its own device ID, and its X25519 public key. The service verifies the token, verifies the account has license capacity (`pairs in use < max_pairs`), creates the Pairing record, and returns the `pair_id` plus the desktop public key (authoritative copy) to the mobile; the desktop receives the mobile's public key on its next poll/notification.
2.3 Both sides derive a shared secret via X25519 ECDH and HKDF (Section FR-5). Private keys never leave the device (stored in Android Keystore / iOS Keychain & Secure Enclave where available / OS keystore or encrypted file on desktop).
2.4 Re-pairing (new phone, reinstalled desktop) repeats the flow; the service replaces the device entry on the pairing record and publishes a revocation for any session belonging to the replaced device.
2.5 Unpairing (user-initiated or license revoked) marks the pairing `revoked`, publishes revocation, and frees the license slot.

### FR-3: Authentication and authorization

3.1 Devices authenticate to the Auth & License Service (account credentials / existing app session) and receive a **connection token** (JWT, ES256 or EdDSA) and a refresh token.
3.2 Connection token claims: `iss`, `aud:"relay"`, `exp` (TTL 10 min), `iat`, `jti`, `account_id`, `pair_id`, `device_id`, `role` (`mobile` | `desktop`), `license_id`. The relay verifies with the public key only.
3.3 Routing is computed exclusively from validated claims: `(pair_id, opposite role)`. No client-supplied addressing exists in the protocol.
3.4 **Slot enforcement:** per pair, exactly one live `mobile` connection and one live `desktop` connection. On connect, the relay performs an atomic claim in Redis (`SET pair:{id}:{role} connId NX` semantics with instance ownership). Default conflict policy: **evict the older connection** and notify it with close code `4001 superseded` (handles crashed-but-not-yet-timed-out sockets and "signed in elsewhere").
3.5 **Token refresh over the live socket:** clients send a fresh token (control message `auth_refresh`) before expiry; the relay re-validates and extends the session. A session whose token expires without refresh is closed with `4003 token_expired`. Refresh requests to the Auth & License Service re-check license validity (Section 6.5).
3.6 **Revocation:** relay instances subscribe to the Redis revocation channel and close matching sessions within ≤ 2 s of the event, close code `4004 revoked`.
3.7 (Phase 2, recommended) Sender-constrained tokens: the connect handshake includes a server nonce signed by the device's pairing private key, binding the bearer token to the device keypair so a stolen token alone is unusable.

### FR-4: Message protocol

4.1 Envelope (JSON in v1; field names fixed to allow a later binary encoding):

```json
{
  "v": 1,
  "type": "msg | ack | auth_refresh | error | sys",
  "id": "uuidv7",
  "ts": 1765432100123,
  "payload": "<base64url ciphertext>"
}
```

4.2 The relay reads only `v`, `type`, `id`; `payload` is opaque ciphertext end-to-end. `sys` messages (relay → client) carry peer presence (`peer_online`, `peer_offline`), slot eviction notices, and shutdown warnings.
4.3 Delivery semantics: at-most-once per frame at the relay; application-level `ack` by message `id` gives clients at-least-once with sender-side retry and receiver-side dedup on `id`. The relay does not persist messages.
4.4 If the peer is offline, the relay responds `error{code: peer_offline}` immediately; clients surface this state (and may use it to trigger the mobile push-wake described in 8.2).

### FR-5: End-to-end encryption

5.1 Key establishment: X25519 ECDH using the long-term identity keys exchanged in the QR pairing flow plus a fresh ephemeral X25519 keypair per session (public half exchanged in the first handshake frame); HKDF-SHA256 over the combined keying material derives directional session keys; payloads sealed with **XChaCha20-Poly1305** (AEAD) with a random 24-byte nonce per message, nonce prepended to ciphertext. The envelope `id` and `ts` are bound as AEAD associated data so they cannot be tampered with or spliced onto a different ciphertext. Verbatim replay of a whole envelope is prevented by a per-session anti-replay window on the receive side (reject already-seen ids and timestamps older than the window).
5.2 Session keys are derived per connection session by mixing four X25519 shared secrets (Noise-KK style) into the HKDF input keying material: `ss` (identity↔identity, authenticates the peer), `ee` (ephemeral↔ephemeral, provides forward secrecy), and the two cross terms `md`/`dm`. Because the ephemeral private keys are discarded after the session, **this provides forward secrecy (FR-5.2):** compromise of a device's long-term identity key does not expose recorded past/future session traffic. Full per-message ratcheting remains out of scope for v1.
5.3 Approved implementations only — no custom cryptography:

| Platform | Library |
|---|---|
| Go (test harness / tooling) | `golang.org/x/crypto` (curve25519, chacha20poly1305, hkdf) |
| Android (Kotlin) | Google **Tink** or **lazysodium-android** |
| iOS (Swift) | **CryptoKit** (Curve25519, ChaChaPoly) — XChaCha via swift-sodium if needed for cross-platform nonce parity |
| Desktop (Java) | **Tink (Java)** or **lazysodium-java** (bundled libsodium for Linux/Windows/macOS) |

5.4 The relay performs no cryptographic operations on payloads and stores no payload data. Logging of payload bytes is prohibited by code review policy and verified by tests.

## 8. Client integration requirements

A thin **Relay Client SDK** is delivered for each platform with an identical conceptual API: `connect(credentials)`, `send(bytes) -> ack`, `onMessage`, `onStateChange(connected | reconnecting | peer_offline | revoked | superseded)`, `pair(qrPayload)` / `generatePairingQr()`. All SDKs implement FR-1 reconnect/heartbeat, FR-3 token refresh, and FR-5 crypto internally so the host applications deal only in plaintext app messages and connection state.

### 8.1 Android (existing mobile app)

- WebSocket: **OkHttp** `WebSocket` (Kotlin). Token attached via the upgrade-request `Authorization` header.
- Crypto: Tink or lazysodium-android; private key in **Android Keystore**.
- Lifecycle: foreground service is NOT required. The SDK maintains the socket while the app is foregrounded, releases it in background, and re-establishes on resume. For desktop-initiated contact while backgrounded, integrate **FCM** push-to-wake: the desktop's message attempt returns `peer_offline`, the desktop (or Auth service on its behalf) triggers a data push, the app wakes and reconnects. Respect Doze/App Standby constraints.
- Network churn (Wi-Fi ↔ cellular) is handled by the standard reconnect path; the session token remains valid across transports.

### 8.2 iOS (existing mobile app)

- WebSocket: **URLSessionWebSocketTask** (no third-party dependency) or Starscream if preferred.
- Crypto: **CryptoKit**; private key protected by Keychain/Secure Enclave.
- Lifecycle: same pattern as Android — connected while foregrounded; background sockets are not reliable on iOS, so desktop-initiated contact uses **APNs** push-to-wake (silent push `content-available`, subject to iOS budgeting; user-visible push as fallback for important events).

### 8.3 Desktop Java application (Linux, Windows, macOS)

- WebSocket: **`java.net.http.WebSocket`** (built into JDK 11+; zero added dependency) or OkHttp (JVM). Custom `Authorization` header set on the upgrade request via the builder.
- Crypto: Tink (pure-Java path available) or lazysodium-java (ships native libsodium for all three OSes — verify packaging for the app's installer formats).
- The desktop is the **always-on** side: the SDK runs on a daemon thread for the lifetime of the application, with indefinite reconnection (backoff cap 60 s) and OS sleep/wake awareness (resume → immediate reconnect attempt).
- License activation UI: settings panel to enter/select the license key (Section 6.2), show pairing QR (reusing the existing QR sync screen), and display connection/license status.
- Java 11+ required (current app baseline to be confirmed — see Open Questions).

### 8.4 Existing QR sync flow changes

The QR generation (desktop) and scanning (mobile) code paths are reused. Required changes: (a) versioned QR payload schema adding the pairing token, device public key, and endpoints (FR-2.1); (b) post-scan HTTPS call to complete pairing (FR-2.2); (c) backward compatibility — a QR with the new fields absent triggers the legacy local-sync behavior only.

## 9. Server requirements (Go relay on Linux)

### 9.1 Implementation

- Language: **Go** (chosen for connection density, single static binary, and development velocity; see capacity targets in 10.1).
- WebSocket library: `github.com/coder/websocket` (or `gobwas/ws` if the epoll model is later needed for >100k connections per instance).
- JWT verification: `golang-jwt/jwt` with ES256/EdDSA public key, keys rotated via JWKS endpoint of the Auth service.
- Redis client: `go-redis`. All slot claims via atomic Lua/`SET NX` operations; cross-instance routing via pub/sub channels keyed by `pair_id`; revocation channel `revocations`.
- Stripe: `stripe-go` in the Auth & License Service only. The relay has no Stripe dependency.
- Configuration via environment variables; secrets via the platform secret store; no secrets in the image.

### 9.2 Deployment and container hardening

- Build: multi-stage Docker build, `CGO_ENABLED=0`, `-ldflags="-s -w"`.
- Final image: **`gcr.io/distroless/static:nonroot`** — single Go binary, no shell, no package manager, non-root user; base image pinned by digest.
- Runtime: read-only root filesystem, `cap-drop=ALL`, `no-new-privileges`, resource limits set; `ulimit -n` (nofile) raised above the per-instance connection target; kernel TCP buffer sizes tuned for many idle connections.
- TLS terminates at the relay (autocert/ACME) or at a fronting L4/L7 proxy — decided per environment; if a proxy is used it must pass WebSocket upgrades and preserve client IPs (PROXY protocol or `X-Forwarded-For`).
- Hosting: any Linux host. Initial target: one small VPS-class instance (e.g., 2 vCPU / 4 GB) plus managed or co-located Redis; architecture supports N instances behind a TCP/HTTP load balancer with the Redis backplane from day one.
- Zero-downtime deploys: on SIGTERM the relay stops accepting connections, sends `sys{shutdown}` to clients, and drains for up to 30 s; client reconnect logic (with jitter) redistributes load to remaining instances.

### 9.3 Observability

- Metrics (Prometheus): concurrent connections by role, connect/auth failure counts by reason code, messages and bytes relayed, p50/p95/p99 relay forwarding latency, slot evictions, revocations executed, reconnect-storm gauge (connects/sec).
- Structured logs: connection lifecycle and auth decisions with `account_id`/`pair_id`/`jti` — never payload contents (FR-5.4).
- Alerts: auth-failure spike, connection-count saturation vs. fd limit, Redis unavailability, webhook processing lag, certificate expiry.

## 10. Non-functional requirements

### 10.1 Capacity and performance

| Metric | Target (v1) |
|---|---|
| Concurrent connections per 4 GB / 2 vCPU instance | ≥ 50,000 (Go baseline; load test to verify) |
| Added relay latency (frame in → frame out), p99 | ≤ 50 ms intra-region |
| TLS handshake throughput (reconnect storm) | Full instance reconnect absorbed ≤ 60 s with jittered backoff |
| Token validation overhead | ≤ 1 ms p99 (local public-key verify, no network call) |
| Revocation propagation | ≤ 2 s from webhook processing to socket close |

Each active user consumes **two** connections (mobile + desktop, when both online); capacity planning uses connections, not users.

### 10.2 Security requirements

- TLS 1.2+ only, modern cipher suites; HSTS on any HTTP surface.
- All licensing/authorization decisions on the server side; clients are untrusted.
- Stripe webhook signature verification mandatory; webhook secret rotation supported.
- Key hygiene: JWT signing keys in the Auth service only (HSM/KMS-backed where available), rotated ≤ 90 days via JWKS; device private keys never transmitted.
- Rate limiting: per-IP connection attempts and per-account auth attempts at the relay and auth endpoints; protocol-error and oversize-frame strikes lead to disconnect and temporary bans.
- Penetration test of the relay and pairing flow before GA; threat model document maintained alongside this PRD (key threats: token theft → mitigated by short TTL + Phase-2 sender constraint; relay compromise → mitigated by E2EE and no-mint design; credential sharing → mitigated by slot enforcement).
- Privacy: relay stores no message content; connection metadata retention ≤ 30 days; document data flows for GDPR/Law 25 (Quebec) compliance review.

### 10.3 Reliability

- Relay availability target: 99.9% monthly.
- Redis outage degrades gracefully: existing single-instance routing continues; new slot claims fail closed (reject new connections) rather than fail open.
- Stripe outage: licensing decisions continue from the local mirror; reconciliation heals on recovery.

## 11. Rollout plan

| Milestone | Scope | Exit criteria |
|---|---|---|
| M1 — Relay core | Go relay, wss, heartbeat, static-token auth, single instance, echo between Go test clients | Soak test: 10k idle conns, 24 h, zero leaks |
| M2 — Auth & licensing | Auth service, JWT issue/refresh, Stripe products/webhooks, license keys, slot enforcement, revocation channel | Subscription lifecycle E2E in Stripe test mode (purchase → use → fail payment → grace → cancel → cutoff) |
| M3 — Pairing & E2EE | QR flow extension, X25519/HKDF/XChaCha20-Poly1305 on Go reference clients, ciphertext-only relay verified | Interop test vectors pass on all crypto libs |
| M4 — Client SDKs | Kotlin, Swift, Java SDKs with common surface; integration into the three existing apps behind a feature flag | Cross-platform E2E: Android↔Java, iOS↔Java on all desktop OSes |
| M5 — Hardening & scale | Distroless deployment, observability, load test (50k conns, reconnect storm), pen test, multi-instance + Redis routing | Targets in 10.1 met; pen-test highs resolved |
| M6 — GA | Gradual rollout by account cohort; dashboards and alerts live | < 0.1% connect-failure rate over 14 days |

## 12. Success metrics

- ≥ 95% of connection attempts by validly licensed devices succeed within 3 s.
- p99 added relay latency ≤ 50 ms sustained in production.
- 100% of canceled subscriptions lose relay access within the policy window (15 min graceful / 2 s immediate).
- Zero incidents of payload exposure (verified by audit: relay logs and storage contain no plaintext).
- Support tickets for "can't connect mobile to desktop" reduced vs. QR-proximity baseline (target −50% in 90 days).

## 13. Risks and open questions

**Risks**
1. iOS background limitations may make desktop→mobile initiation feel unreliable; mitigation is APNs wake, but silent-push budgeting is OS-controlled. UX must set expectations.
2. lazysodium native packaging across three desktop OSes and the app's installer pipeline needs early validation (M3 spike).
3. Corporate networks that block non-HTTP(S) ports are mitigated by running wss on 443; networks with TLS-inspecting proxies may still break connections — document as a known limitation, consider an HTTP long-poll fallback post-v1.
4. Stripe webhook delivery gaps could strand license state; mitigated by idempotent handlers + nightly reconciliation, but reconciliation must exist at M2, not later.

**Open questions**
1. Desktop Java baseline version — is JDK 11+ guaranteed across the installed base (required for `java.net.http.WebSocket`)? If not, OkHttp-JVM is the fallback.
2. Grace-period length for `past_due` (default 7 days proposed) — Product/Finance to confirm against the Stripe dunning configuration.
3. Eviction policy on slot conflict (default: newest wins) — confirm desired UX for "signed in on another device."
4. Does any plan need `max_pairs > 1` at launch, or is multi-pair Phase 2?
5. Which existing backend (if any) hosts accounts today, and does the Auth & License Service extend it or stand alone?
6. Hosting decision for production (self-managed VPS vs. PaaS) — cost analysis from engineering spike; architecture is host-agnostic.

## Appendix A — Connection token (JWT) example

```json
{
  "iss": "https://auth.example.com",
  "aud": "relay",
  "sub": "device:dev_9f3k2",
  "jti": "0196a1b2-...",
  "iat": 1765432100,
  "exp": 1765432700,
  "account_id": "acct_7Hq2",
  "pair_id": "pair_Xk21",
  "device_id": "dev_9f3k2",
  "role": "desktop",
  "license_id": "lic_4Jq9"
}
```

## Appendix B — Close codes

| Code | Meaning | Client behavior |
|---|---|---|
| 1000/1001 | Normal / going away (deploy drain) | Reconnect with jitter |
| 4001 | superseded (slot evicted) | Do not auto-reconnect; surface "connected elsewhere" |
| 4003 | token_expired | Refresh token, reconnect |
| 4004 | revoked (license/pairing) | Do not reconnect; surface licensing state |
| 4005 | protocol_error / oversize | Log, limited retries |

## Appendix C — Pairing sequence (happy path)

1. Desktop (signed in, licensed) requests pairing token from Auth service → renders QR `{v, pairing_token, desktop_pubkey, desktop_device_id, endpoints}`.
2. Mobile scans QR → `POST /v1/pairings {pairing_token, mobile_device_id, mobile_pubkey}`.
3. Auth service validates token + license capacity → creates `pair_id` → returns `{pair_id, desktop_pubkey}`; desktop receives `{pair_id, mobile_pubkey}`.
4. Both sides: X25519(priv, peer_pub) → HKDF → session keys.
5. Both connect to relay with fresh JWTs; relay claims slots; `sys{peer_online}` delivered to each; encrypted traffic flows.
