import Foundation

/// Versioned QR pairing payload (PRD FR-2.1), matching the Go `qrPayload` and the JVM SDK.
public struct QrPayload: Codable {
    public var v: Int
    public var pairingToken: String
    public var desktopPubkey: String
    public var desktopDeviceId: String
    public var endpoints: [String: String]

    enum CodingKeys: String, CodingKey {
        case v
        case pairingToken = "pairing_token"
        case desktopPubkey = "desktop_pubkey"
        case desktopDeviceId = "desktop_device_id"
        case endpoints
    }

    public var relayEndpoint: String? { endpoints["relay"] }
    public var authEndpoint: String? { endpoints["auth"] }

    public static func fromJSON(_ s: String) throws -> QrPayload {
        try JSONDecoder().decode(QrPayload.self, from: Data(s.utf8))
    }
}

public struct AuthError: Error { public let status: Int; public let code: String }

/// HTTPS client for the Auth & License Service pairing/token API (PRD FR-2/FR-3), matching
/// `internal/authservice`. Public keys are base64-std of raw 32 bytes.
public final class AuthClient {
    private let baseURL: URL
    private let session: URLSession

    public init(baseURL: String, session: URLSession = .shared) throws {
        // Enforce https:// (except loopback/RFC1918 for LAN dev) and replace the old
        // force-unwrap with a throwing, validated parse (SG-14/SG-19).
        self.baseURL = try EndpointValidator.requireSecureAuth(baseURL)
        self.session = session
    }

    public struct DeviceResult: Codable { let deviceId: String
        enum CodingKeys: String, CodingKey { case deviceId = "device_id" } }
    /// Security L2: the gateway registers the mobile device from its public key inside pairing and
    /// mints a per-pair credential; both are null against a legacy (pre-L2) gateway.
    public struct CompletePairingResult: Codable {
        public let pairId: String
        public let desktopPublicKey: String
        public let mobileDeviceId: String?
        public let pairCredential: String?
        enum CodingKeys: String, CodingKey {
            case pairId = "pair_id"
            case desktopPublicKey = "desktop_public_key"
            case mobileDeviceId = "mobile_device_id"
            case pairCredential = "pair_credential"
        }
    }
    public struct TokenResult: Codable { public let token: String; public let refreshToken: String; public let expiresIn: Int
        enum CodingKeys: String, CodingKey { case token; case refreshToken = "refresh_token"; case expiresIn = "expires_in" } }

    /// Register a device under the account. Kept for parity with the JVM SDK; the L2 mobile pair
    /// path no longer calls this (the gateway registers the mobile device inside `completePairing`).
    public func registerDevice(accountSecret: String, role: Role, publicKeyB64: String) async throws -> String {
        try await post("/v1/devices", bearer: accountSecret,
                       body: ["role": role.rawValue, "public_key": publicKeyB64], as: DeviceResult.self).deviceId
    }

    /// Mobile: complete pairing with its X25519 public key (the pairing token authorizes). Security L2:
    /// `mobileDeviceId` may be nil — the gateway then registers the mobile device from its public key
    /// under the token's account and returns the id + a per-pair credential, so the phone needs no
    /// account secret to register or to authenticate token issue/refresh + unpair.
    public func completePairing(pairingToken: String, mobileDeviceId: String?, mobilePublicKeyB64: String) async throws -> CompletePairingResult {
        var body = ["pairing_token": pairingToken, "mobile_public_key": mobilePublicKeyB64]
        if let mobileDeviceId, !mobileDeviceId.isEmpty { body["mobile_device_id"] = mobileDeviceId }
        return try await post("/v1/pairings", bearer: nil, body: body, as: CompletePairingResult.self)
    }

    /// Issue a connection JWT + refresh token for a (device, pair). `credential` is the per-pair
    /// credential (L2), falling back to the legacy account secret only against a pre-L2 gateway.
    public func issueToken(credential: String, deviceId: String, pairId: String) async throws -> TokenResult {
        try await post("/v1/token", bearer: credential,
                       body: ["device_id": deviceId, "pair_id": pairId], as: TokenResult.self)
    }

    public func refreshToken(_ refresh: String) async throws -> TokenResult {
        try await post("/v1/token/refresh", bearer: nil, body: ["refresh_token": refresh], as: TokenResult.self)
    }

    /// Revoke a pairing (FR-2.5): the peer's live session is cut and the pair slot freed, so a new
    /// device can pair. Authenticated with the per-pair credential (L2).
    public func unpair(credential: String, pairId: String) async throws {
        try await postVoid("/v1/pairings/unpair", bearer: credential, body: ["pair_id": pairId])
    }

    private func post<T: Decodable>(_ path: String, bearer: String?, body: [String: String], as: T.Type) async throws -> T {
        let data = try await postRaw(path, bearer: bearer, body: body)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// POST that ignores the (possibly empty) response body — for endpoints like unpair.
    private func postVoid(_ path: String, bearer: String?, body: [String: String]) async throws {
        _ = try await postRaw(path, bearer: bearer, body: body)
    }

    @discardableResult
    private func postRaw(_ path: String, bearer: String?, body: [String: String]) async throws -> Data {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let bearer { req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await session.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            let code = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String ?? "http_\(status)"
            throw AuthError(status: status, code: code)
        }
        return data
    }
}
