import Foundation

/// iOS mobile SDK facade (PRD §8.2) — the single entry point the host app toggles behind its
/// relay feature flag. It scans the desktop QR (`pair`), completes pairing and key exchange,
/// then connects to the relay over `URLSessionWebSocketTask` and exposes the common
/// `send`/`onMessage`/`onStateChange` surface. Mirrors the JVM/Android `MobileClient`.
///
/// Security L2: the phone authenticates token issue/refresh + unpair with the per-pair
/// credential minted at pairing — not the account secret, which no longer rides the QR. Persist
/// `currentDeviceId`/`currentPairId`/`desktopPublicKeyB64`/`currentPairCredential` after a
/// successful `pair` and feed them back through the initializer to reconnect (the QR's pairing
/// token is single-use, so a relaunch/toggle reuses the saved pairing instead of re-pairing).
public final class MobileClient {
    private let authURL: String
    /// Legacy account credential (pre-L2). Kept only as a fallback against a legacy gateway that
    /// returns no per-pair credential; new pairings authenticate with `pairCredential`.
    private var accountSecret: String?
    private let keyStore: KeyStore
    private let pushWaker: PushWaker
    private let auth: AuthClient
    private let identity: KeyPair
    private let logger: (String) -> Void

    // Seeded from the initializer to support reconnect-without-repair; otherwise learned at `pair`.
    private var deviceId: String?
    private var pairId: String?
    private var peerPub: Data?
    private var relayURL: String?
    private var pairCredential: String?
    private var manager: ConnectionManager?

    public var onMessage: (Data) -> Void = { _ in }
    public var onStateChange: (ConnectionState) -> Void = { _ in }

    /// - Parameters:
    ///   - relayURL: normally learned from the scanned QR, so may be nil on a first pair; required
    ///     (via this seed) to reconnect.
    ///   - accountSecret: legacy fallback only (nil for L2).
    ///   - deviceId/pairId/desktopPublicKeyB64/pairCredential: restore a prior pairing so `connect`
    ///     can run WITHOUT re-`pair`ing. Set `pairId` + `desktopPublicKeyB64` together —
    ///     `isPaired()` gates on both.
    public init(authURL: String,
                relayURL: String? = nil,
                accountSecret: String? = nil,
                deviceId: String? = nil,
                pairId: String? = nil,
                desktopPublicKeyB64: String? = nil,
                pairCredential: String? = nil,
                keyStore: KeyStore = KeychainKeyStore(),
                pushWaker: PushWaker = NoopPushWaker(),
                logger: @escaping (String) -> Void = { _ in }) throws {
        self.authURL = authURL
        self.relayURL = relayURL
        self.accountSecret = accountSecret
        self.deviceId = deviceId
        self.pairId = pairId
        self.peerPub = desktopPublicKeyB64.flatMap { Data(base64Encoded: $0) }
        self.pairCredential = pairCredential
        self.keyStore = keyStore
        self.pushWaker = pushWaker
        self.logger = logger
        self.auth = try AuthClient(baseURL: authURL)
        self.identity = try keyStore.loadOrCreateIdentity()
    }

    public var currentPairId: String? { pairId }
    public var currentDeviceId: String? { deviceId }
    /// The per-pair credential learned at `pair` (L2; nil before pairing or against a legacy gateway).
    public var currentPairCredential: String? { pairCredential }
    /// Base64-std of the desktop's X25519 public key learned at `pair` (nil before pairing).
    public var desktopPublicKeyB64: String? { peerPub?.base64EncodedString() }

    /// True once paired — in this process via `pair`, or restored from a prior pairing via the
    /// initializer seeds. When true, `connect` can run on its own (no spent-token 401).
    public func isPaired() -> Bool { pairId != nil && peerPub != nil }

    /// Scan a QR payload: complete pairing (the gateway registers this device from its public key
    /// and returns the id + per-pair credential), exchange public keys.
    public func pair(_ qr: QrPayload) async throws {
        let pubB64 = identity.publicKey.base64EncodedString()
        pushWaker.register(deviceToken: "apns-token") // host supplies the real APNs token (deferred)
        logger("pair: completing pairing token=\(qr.pairingToken.prefix(8))… (gateway registers the device)")
        let result = try await auth.completePairing(pairingToken: qr.pairingToken,
                                                    mobileDeviceId: deviceId,
                                                    mobilePublicKeyB64: pubB64)
        pairId = result.pairId
        peerPub = Data(base64Encoded: result.desktopPublicKey)
        deviceId = result.mobileDeviceId ?? deviceId
        pairCredential = result.pairCredential
        relayURL = qr.relayEndpoint ?? relayURL
        let credState = (pairCredential?.isEmpty ?? true) ? "MISSING(legacy gateway → account-secret fallback)" : "present"
        logger("pair: ok pairId=\(pairId ?? "nil") deviceId=\(deviceId ?? "nil") cred=\(credState) peerPubKey=\(peerPub?.count ?? 0)B relay=\(relayURL ?? "nil")")
    }

    /// Parse a scanned QR JSON string and pair.
    public func pair(qrJSON: String) async throws { try await pair(QrPayload.fromJSON(qrJSON)) }

    /// Issue a connection token (per-pair credential) and open the relay session. Runs from a
    /// seeded pairing without a prior in-process `pair`.
    public func connect() async throws {
        guard let pid = pairId, let peer = peerPub, let url = relayURL, let dev = deviceId else {
            throw AuthError(status: 0, code: "not_paired")
        }
        let cred = try credential()
        logger("connect: issuing token for pairId=\(pid) device=\(dev); opening relay at \(url)")
        let tok = try await auth.issueToken(credential: cred, deviceId: dev, pairId: pid)
        let mgr = try ConnectionManager(wsURL: url, role: .mobile, myPriv: identity.privateKey, peerPub: peer,
                                        auth: auth, token: tok.token, refresh: tok.refreshToken)
        mgr.onMessage = onMessage
        mgr.onStateChange = onStateChange
        manager = mgr
        mgr.start()
    }

    public func send(_ plaintext: Data) async throws { try await manager?.send(plaintext) }

    /// Revoke this pairing at the gateway (FR-2.5): the relay session is cut and the pair slot
    /// freed, so the desktop can pair a new phone. No-op if pairing never completed. Call `close`
    /// afterward to drop the session.
    public func unpair() async throws {
        guard let pid = pairId else { return }
        logger("unpair: revoking pairId=\(pid)")
        try await auth.unpair(credential: try credential(), pairId: pid)
        pairId = nil
        peerPub = nil
        pairCredential = nil
    }

    public func close() { manager?.close() }

    /// The credential the phone authenticates token issue/refresh + unpair with: the per-pair
    /// credential (L2), falling back to a legacy account secret only when no pair credential exists.
    private func credential() throws -> String {
        if let c = pairCredential, !c.isEmpty { return c }
        if let s = accountSecret, !s.isEmpty { return s }
        throw AuthError(status: 0, code: "no_credential")
    }
}
