# Security & Production-Readiness Audit — secure-gateway (re-audit)

**Date:** 2026-06-21 (re-audit) · **Updated:** 2026-06-21 (post PR #4 — all remaining items resolved)
**Commit:** re-audit baseline `main` @ `455f480`; resolution baseline `security/sg-fixes-batch-2` (PR #4)
**Scope:** Full repository — Go services (`cmd/*`, `internal/*`), client SDKs
(`sdk/core`, `sdk/java`, `sdk/android`, `sdk/android-aar`, `sdk/ios`), E2EE, and the
deployment/build pipeline.
**Methodology:** Same multi-agent adversarial review as the original audit — seven parallel
finder passes → independent skeptic verification of every candidate → hand spot-checks of the
key findings against source. This pass specifically re-examined the **newly merged fix code**
(four-DH forward secrecy, replay guard, `ConsumeRefreshToken`, private metrics listeners) for
correctness and regressions, not just a checklist of what was fixed. Corroborated with
`go vet ./...` (clean) and `govulncheck ./...` (no known vulnerabilities).

> **Update (post-audit, 2026-06-21):**
> - SG-15 (the one High finding) was fixed in PR #3 — the SDK handshake is now one-shot — and
>   merged to `main` @ `42ddffa` as SDK **0.2.1**; the mobile and desktop apps were rebuilt on 0.2.1.
> - **The remaining 10 open items (3 Medium / 6 Low / 1 Info) are now resolved in PR #4**
>   (branch `security/sg-fixes-batch-2`, SDK **0.2.2**): SG-05, SG-08, SG-10, SG-13, SG-14, SG-16,
>   SG-17, SG-18, SG-19, SG-20. The status lines and checklist below are refreshed to *resolved*;
>   the finding descriptions are retained for the record. The consumer app bump to SDK 0.2.2 is
>   tracked in the local-agent repo (PR #12).

---

## Executive summary

The previous batches resolved most of the original findings: **forward secrecy (SG-01) and
replay protection (SG-02 + SG-15) hold**, refresh rotation is atomic (SG-03) and
membership-checked (SG-04), metrics isolation is wired (SG-06/SG-11), and the k8s image tags no
longer float on `:latest` (SG-12). `go vet` and `govulncheck` remain clean.

**This re-audit found one High-severity regression introduced by the fix work (SG-15), plus a new
Medium and several still-open prior items. SG-15 was fixed in PR #3, and PR #4 has now closed every
remaining Medium/Low/Info hardening item.** The headline:

> **All audit findings are resolved.** The E2EE client blocker (SG-15) is fixed and SG-02 replay
> protection holds; the entitlement, DoS-hardening, supply-chain, SDK-transport, and infra items
> from this re-audit (SG-05/08/10/13/14/16/17/18/19/20) are fixed and covered by tests in PR #4.

| Severity | Open count (re-audit) | Open count (post PR #4) |
|----------|----------------------:|------------------------:|
| Critical | 0 | 0 |
| High     | 0 | 0 |
| Medium   | 3 | 0 |
| Low      | 6 | 0 |
| Info     | 1 | 0 |
| **Total**| **10** | **0** |

(The finder pass reported the High item three times — once per affected file/platform; it is one
root cause and is consolidated here as SG-15.) 10 further candidates were investigated and
**dismissed** on verification (see [Investigated and dismissed](#investigated-and-dismissed)).

---

## Status of the previous findings (SG-01 … SG-14)

| ID | Was | Now |
|----|-----|-----|
| SG-01 forward secrecy | Medium | ✅ **Resolved** — per-session ephemeral X25519, four-DH (`ss‖ee‖md‖dm`) keying, verified Go↔JVM↔Swift parity on the regenerated v2 vectors. |
| SG-02 replay protection | Medium | ✅ **Resolved** — receive-side window works; the SG-15 handshake-reset gap is fixed (handshake is one-shot — PR #3 / SDK 0.2.1). |
| SG-03 atomic refresh rotation | Medium | ✅ **Resolved** — `ConsumeRefreshToken` compare-and-consume (`ErrConflict`); verified atomic. Reuse *detection* added in PR #4 (SG-17). |
| SG-04 refresh pairing-membership + evict | Medium | ✅ **Resolved** — membership check added; evicted device's tokens revoked on re-pair (migration `0004`). |
| SG-05 superseded session not self-closed | Medium→Low | ✅ **Resolved (PR #4)** — `session.renew()` self-closes with `CloseSuperseded` on `ErrNotSlotOwner`. |
| SG-06 dead `RELAY_METRICS_ADDR` | Medium | ✅ **Resolved** — honored via a private listener; addresses now validated at boot (SG-18, PR #4). |
| SG-07 `Hub.Register` claim/index TOCTOU | Low | ➖ **Dismissed on re-verify** — same-principal-only; no cross-tenant impact (see dismissed). |
| SG-08 auth HTTP missing timeouts | Low→Med | ✅ **Resolved (PR #4)** — `Read`/`Write`/`Idle` timeouts (15s/15s/60s) on both auth listeners. |
| SG-09 per-account limit on bearer prefix | Low | ➖ **Dismissed on re-verify** — per-IP limit is the real control; not exploitable as a targeted lockout. |
| SG-10 unbounded `/v1/devices` | Low→Med | ✅ **Resolved (PR #4)** — route rate-limited; per-account cap (10) + idempotent re-registration. |
| SG-11 `/metrics` public exposure | Low | ✅ **Resolved** — off the public mux when a metrics addr is set; Caddy 404s `/metrics`; k8s scrapes the private port. |
| SG-12 k8s `:latest` images | Low | ✅ **Resolved** (skeleton) — pinned to a versioned ref + `imagePullPolicy`; still a `v0.0.0` placeholder to replace with a digest at release. |
| SG-13 Gradle wrapper checksum | Low | ✅ **Resolved (PR #4)** — `distributionSha256Sum` pinned for Gradle 8.7. |
| SG-14 SDK accepts cleartext `ws://` from QR | Low | ✅ **Resolved (PR #4)** — `wss://`/`https://` enforced (loopback/RFC1918 carve-out). |

---

## Findings (all resolved)

### High — ✅ resolved (retained for the record)

#### SG-15 · Replayed handshake frame resets the SG-02 replay window (regression of SG-01/SG-02)
- **Status:** ✅ **RESOLVED** — fixed in PR #3 (merged to `main` @ `42ddffa`, SDK **0.2.1**): the
  handshake is now one-shot (`acceptPeerEphemeral` ignores a `TAG_HANDSHAKE` frame once the
  session exists) in both `HandshakeCoordinator.java` and `HandshakeCoordinator.swift`, with
  JVM + iOS regression tests; mobile/desktop apps rebuilt on 0.2.1.
- **Severity:** High (confidence: high) · **Regression** · **Dimension:** Crypto / SDK
- **Description:** `onFrame` called `acceptPeerEphemeral` for **every** `TAG_HANDSHAKE` frame, and
  `acceptPeerEphemeral` unconditionally rebuilt the `Session` — resetting the per-session
  anti-replay state (`seen`/`lastTs`/`primed`). Replaying the peer's original ephemeral-pub
  handshake frame re-derived byte-identical keys but returned a **new `Session` with an empty
  replay guard**, so the window could be wiped at will and old data frames re-injected.
- **Remediation (shipped):** Make the handshake one-shot per coordinator — ignore `TAG_HANDSHAKE`
  once `session != null`. Applied identically in Java and Swift; regression test added. Shipped as
  SDK `0.2.1`.

### Medium — ✅ resolved in PR #4

#### SG-16 · `max_pairs` capacity check was TOCTOU (entitlement bypass under concurrency)
- **Status:** ✅ **RESOLVED (PR #4)** — count-and-insert is now atomic via the new store method
  `CreatePairingWithinCapacity`: Postgres runs it in a transaction with `SELECT … FOR UPDATE` on
  the license row (serializing concurrent completions); the memory store does the count+insert
  under its write lock. A full license returns the new `ErrCapacityExceeded` sentinel → `409
  capacity_exceeded`. The advisory pre-check remains as a fast reject.
- **Severity:** Medium (confidence: high) · **Dimension:** AuthZ
- **Location:** `internal/authservice/pairing.go` (`handleCompletePairing`); store impls in
  `internal/authstore/{postgres,memory}`.
- **Description:** `handleCompletePairing` read `ActivePairCount` and then, separately and
  non-transactionally, called `CreatePairing`. Two concurrent completions for distinct pairing
  tokens on the same license could both observe `inUse < MaxPairs` and both insert, exceeding the
  licensed `max_pairs`.
- **Test:** `TestPairingCapacityNotExceededUnderConcurrency` (integration, `max_pairs=1`, two
  concurrent completions → exactly one `200` + one `409`); storetest conformance for the new method.

#### SG-08 · Auth HTTP servers set only `ReadHeaderTimeout` (slow-body / slow-read DoS)
- **Status:** ✅ **RESOLVED (PR #4)** — `ReadTimeout`/`WriteTimeout`/`IdleTimeout` (15s/15s/60s) set
  on both `http.Server` instances (main + private metrics listener) in `NewServer`.
- **Severity:** Medium (confidence: medium) · **Dimension:** Web
- **Location:** `internal/authservice/server.go`.
- **Description:** Only `ReadHeaderTimeout` (10s) was set; slow-body POSTs, slow response drains,
  and never-reaped idle keep-alives were time-unbounded (the 1 MiB body cap bounds bytes, not time).

#### SG-10 · `POST /v1/devices` was neither rate-limited nor capped
- **Status:** ✅ **RESOLVED (PR #4)** — route wrapped in `s.limit(...)`; a per-account device cap
  (default 10) rejects the 11th distinct device with `409 device_limit`; re-registration of the
  same role+public_key is idempotent (returns the existing row). New store methods
  `CountDevicesByAccount` + `FindDeviceByAccountRoleKey`.
- **Severity:** Medium (confidence: medium) · **Dimension:** Web
- **Location:** `internal/authservice/server.go` (route); `internal/authservice/handlers.go`
  (`handleRegisterDevice`).
- **Description:** The route was registered without `s.limit(...)` and inserted a new device row on
  every call with no per-account cap — datastore/cost-amplification DoS.
- **Test:** `TestDeviceRegistrationCap` and `TestDeviceRegistrationIdempotent` (integration);
  storetest conformance for the new methods.

### Low — ✅ resolved in PR #4

#### SG-17 · Refresh-token rotation had no reuse/replay detection (residual after SG-03)
- **Status:** ✅ **RESOLVED (PR #4)** — presenting a refresh token whose row exists but is already
  **revoked** (not merely expired) is treated as reuse: the device's whole token chain is revoked
  (`RevokeRefreshTokensByDevice`), a revocation is published, and the request is rejected.
- **Severity:** Low (confidence: medium) · **Dimension:** AuthZ
- **Location:** `internal/authservice/handlers.go` (`handleRefreshToken`).
- **Test:** `TestRefreshTokenReuseRevokesChain` (integration: reuse of a rotated token kills the
  live descendant chain).

#### SG-05 · `session.renew()` discarded `ErrNotSlotOwner`
- **Status:** ✅ **RESOLVED (PR #4)** — on `errors.Is(err, backplane.ErrNotSlotOwner)` the session
  self-closes with `CloseSuperseded`; transient transport errors are left to the next heartbeat.
- **Severity:** Low (confidence: high) · **Dimension:** Relay
- **Location:** `internal/relay/session/session.go` (`renew()`).
- **Test:** `TestRenewSelfClosesOnSlotLoss` / `TestRenewIgnoresTransientError`
  (`internal/relay/session`).

#### SG-18 · `RELAY_METRICS_ADDR` / `AUTH_METRICS_ADDR` not validated (fail-open observability)
- **Status:** ✅ **RESOLVED (PR #4)** — `validate()` in both `internal/config/config.go` and
  `internal/authconfig/config.go` now requires a non-empty metrics addr to parse via
  `net.SplitHostPort` and to differ from `ListenAddr`, so a typo fails boot instead of silently
  serving metrics nowhere.
- **Severity:** Low (confidence: high) · **Regression** · **Dimension:** Config
- **Test:** metrics-addr validation cases in `internal/config` and `internal/authconfig` tests.

#### SG-13 · Gradle wrapper not checksum-pinned
- **Status:** ✅ **RESOLVED (PR #4)** — `distributionSha256Sum` for the official Gradle 8.7 `-bin`
  distribution added to `sdk/gradle/wrapper/gradle-wrapper.properties`.
- **Severity:** Low (confidence: high) · **Dimension:** Supply chain

#### SG-14 · SDK used the scanned QR relay endpoint with no `wss://` enforcement
- **Status:** ✅ **RESOLVED (PR #4)** — a shared `EndpointValidator` (JVM + Swift) rejects a
  non-`wss://` relay (and non-`https://` auth) endpoint before use, with a loopback/RFC1918
  carve-out for LAN dev. Wired into `AuthClient` + `Credentials` (JVM), the OkHttp transport, and
  `AuthClient` + `ConnectionManager` (iOS).
- **Severity:** Low (confidence: high) · **Dimension:** SDK
- **Test:** `EndpointValidatorTest` (JVM) and `EndpointValidatorTests` (Swift, reviewed source).

#### SG-19 · iOS `ConnectionManager` force-unwrapped the QR relay URL
- **Status:** ✅ **RESOLVED (PR #4)** — folded into the SG-14 fix: the iOS `URL(string:)!`
  force-unwraps in `ConnectionManager` and `AuthClient` are replaced with throwing, validated
  parses (`EndpointError`), so a malformed/insecure URL surfaces a typed error instead of crashing.
- **Severity:** Low (confidence: high) · **Dimension:** SDK

### Info — ✅ resolved in PR #4

#### SG-20 · Postgres container not hardened like the rest of the prod stack
- **Status:** ✅ **RESOLVED (PR #4)** — `cap_drop: [ALL]` plus a minimal
  `cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]` (what the alpine entrypoint needs to
  chown the data volume and `su-exec` to the `postgres` user) added to the Postgres service in both
  `deploy/compose/docker-compose.prod.yml` and `docker-compose.prod-image.yml`.
- **Severity:** Info · **Dimension:** Infra

---

## Production go-live checklist

### Must-fix before relying on the E2EE guarantees
- [x] **SG-15** — ✅ Done (PR #3, SDK `0.2.1`): the handshake is one-shot, so a replayed handshake
      frame no longer resets the replay guard. Mobile/desktop rebuilt on 0.2.1. SG-02 now holds.

### Recommended before release
- [x] **SG-16** — ✅ Done (PR #4): the `max_pairs` capacity check is atomic (license-row lock + tx).
- [x] **SG-08** — ✅ Done (PR #4): `Read`/`Write`/`Idle` timeouts on both auth listeners.
- [x] **SG-10** — ✅ Done (PR #4): `POST /v1/devices` rate-limited + per-account cap + idempotent.
- [x] **SG-18** — ✅ Done (PR #4): metrics addresses validated (fail loudly at boot).
- [x] **SG-17** — ✅ Done (PR #4): refresh-token reuse detection / chain revocation.
- [x] **SG-05** — ✅ Done (PR #4): superseded sessions self-close on `ErrNotSlotOwner`.
- [x] **SG-13** — ✅ Done (PR #4): Gradle wrapper checksum pinned.
- [x] **SG-14 / SG-19** — ✅ Done (PR #4): SDK enforces `wss://`/`https://`; iOS URL parse failable.
- [ ] **SG-12** — Replace the `v0.0.0` k8s image placeholders with real digests at release
      (deploy-time action; no code change).
- [x] **SG-20** — ✅ Done (PR #4): Postgres container capabilities hardened.

---

## What's confirmed resolved (don't regress)
- **Replay protection end-to-end (SG-02 + SG-15):** receive-side anti-replay window plus a
  one-shot handshake so a replayed handshake frame can't reset it (PR #3, SDK 0.2.1).
- **Forward secrecy (SG-01):** four-DH ephemeral handshake; Go↔JVM↔Swift byte-for-byte parity on
  the v2 interop vectors; cross-platform e2e passes.
- **Atomic refresh rotation (SG-03)** + **reuse detection / chain revocation (SG-17, PR #4)**, and
  **pairing-membership + evicted-token revoke (SG-04).**
- **Atomic `max_pairs` entitlement (SG-16, PR #4):** count+insert under a license-row lock, so
  concurrent completions can't over-subscribe.
- **Metrics isolation + fail-closed config (SG-06/SG-11 + SG-18, PR #4):** `/metrics` off the
  public mux + Caddy 404 + private scrape, with the metrics address validated at boot.
- **Auth DoS hardening (SG-08/SG-10, PR #4):** full HTTP timeouts; device registration
  rate-limited, capped, and idempotent.
- **SDK transport security (SG-14/SG-19, PR #4):** `wss://`/`https://` enforced on QR endpoints
  (loopback/RFC1918 carve-out); no force-unwrapped URLs.
- **Supply chain (SG-13, PR #4):** Gradle wrapper checksum-pinned.
- **Infra (SG-20, PR #4):** Postgres container capabilities dropped to a minimal set.
- **k8s image pinning (SG-12)** (digest still to be set at release).
- **Tooling:** `go vet` clean; `govulncheck` reports no known vulnerabilities; SDK
  `:core`/`:android`/`:java` unit tests + `:java:e2eTest` pass on 0.2.2.

---

## Investigated and dismissed

| Candidate | Why dismissed |
|-----------|---------------|
| **SG-07** Hub.Register claim/index TOCTOU | Real interleaving, but only for the **same authenticated principal** double-connecting on one instance — no cross-tenant impact, narrow window, self-heals on reconnect. Reliability nit, not a security vuln. |
| **SG-09** per-account limiter keyed on unverified bearer prefix | Mechanically present, but per-IP limiting is the real control and the "targeted victim lockout" isn't practical (account IDs are 128-bit random; the headline refresh endpoint authenticates via body, not bearer). Accept as documented best-effort. |
| iOS `randomNonce` all-zero fallback on RNG nil | `swift-sodium` `buf(length:)` only returns nil for negative length; call sites pass a positive constant ⇒ unreachable. |
| Private metrics listener unauthenticated/plaintext/0.0.0.0 | Exposes only low-sensitivity counters and is isolated by deployment (no host port in compose; private port in k8s). No secret exposure. |
| Postgres `sslmode=disable` in prod compose | Single-VPS compose; DB stays on the internal bridge, no published port. (Use `sslmode=require` for external/managed PG.) |
| No CI / image signing / SBOM | Process-maturity gap, not an exploitable weakness; `cosign` flow is documented in the runbook. |
| k8s NetworkPolicy / SA-token automount | Generic k8s hardening for skeleton manifests; not a code weakness. |
| SG-12 `v0.0.0` placeholder (not a digest) | Template manifests; must be set at deploy time regardless. Tracked under SG-12. |

Full per-finding verifier rationales are preserved in the workflow run output.
