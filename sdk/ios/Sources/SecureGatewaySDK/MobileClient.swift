import Foundation

/// iOS mobile SDK facade (PRD §8.2) — the single entry point the host app toggles behind its
/// relay feature flag. It scans the desktop QR (`pair`), completes pairing and key exchange,
/// then connects to the relay over `URLSessionWebSocketTask` and exposes the common
/// `send`/`onMessage`/`onStateChange` surface.
public final class MobileClient {
    private let authURL: String
    private let accountSecret: String
    private let keyStore: KeyStore
    private let pushWaker: PushWaker
    private let auth: AuthClient
    private let identity: KeyPair

    private var deviceId: String?
    private var pairId: String?
    private var peerPub: Data?
    private var relayURL: String?
    private var manager: ConnectionManager?

    public var onMessage: (Data) -> Void = { _ in }
    public var onStateChange: (ConnectionState) -> Void = { _ in }

    public init(authURL: String, accountSecret: String,
                keyStore: KeyStore = KeychainKeyStore(), pushWaker: PushWaker = NoopPushWaker()) throws {
        self.authURL = authURL
        self.accountSecret = accountSecret
        self.keyStore = keyStore
        self.pushWaker = pushWaker
        self.auth = AuthClient(baseURL: authURL)
        self.identity = try keyStore.loadOrCreateIdentity()
    }

    public var currentPairId: String? { pairId }

    /// Scan a QR payload: register this device, complete pairing, exchange public keys.
    public func pair(_ qr: QrPayload) async throws {
        pushWaker.register(deviceToken: "apns-token") // host supplies the real APNs token
        let pubB64 = identity.publicKey.base64EncodedString()
        let dev = try await auth.registerDevice(accountSecret: accountSecret, role: .mobile, publicKeyB64: pubB64)
        deviceId = dev
        let result = try await auth.completePairing(pairingToken: qr.pairingToken, mobileDeviceId: dev, mobilePublicKeyB64: pubB64)
        pairId = result.pairId
        peerPub = Data(base64Encoded: result.desktopPublicKey)
        relayURL = qr.relayEndpoint
    }

    public func pair(qrJSON: String) async throws { try await pair(QrPayload.fromJSON(qrJSON)) }

    /// Issue a connection token and open the relay session. Requires `pair` to have run.
    public func connect() async throws {
        guard let pid = pairId, let peer = peerPub, let url = relayURL, let dev = deviceId else {
            throw CryptoError.badLength
        }
        let tok = try await auth.issueToken(accountSecret: accountSecret, deviceId: dev, pairId: pid)
        let mgr = ConnectionManager(wsURL: url, role: .mobile, myPriv: identity.privateKey, peerPub: peer,
                                    auth: auth, token: tok.token, refresh: tok.refreshToken)
        mgr.onMessage = onMessage
        mgr.onStateChange = onStateChange
        manager = mgr
        mgr.start()
    }

    public func send(_ plaintext: Data) async throws { try await manager?.send(plaintext) }

    public func close() { manager?.close() }
}
