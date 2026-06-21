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
    public struct CompletePairingResult: Codable { public let pairId: String; public let desktopPublicKey: String
        enum CodingKeys: String, CodingKey { case pairId = "pair_id"; case desktopPublicKey = "desktop_public_key" } }
    public struct TokenResult: Codable { public let token: String; public let refreshToken: String; public let expiresIn: Int
        enum CodingKeys: String, CodingKey { case token; case refreshToken = "refresh_token"; case expiresIn = "expires_in" } }

    public func registerDevice(accountSecret: String, role: Role, publicKeyB64: String) async throws -> String {
        try await post("/v1/devices", bearer: accountSecret,
                       body: ["role": role.rawValue, "public_key": publicKeyB64], as: DeviceResult.self).deviceId
    }

    public func completePairing(pairingToken: String, mobileDeviceId: String, mobilePublicKeyB64: String) async throws -> CompletePairingResult {
        try await post("/v1/pairings", bearer: nil,
                       body: ["pairing_token": pairingToken, "mobile_device_id": mobileDeviceId, "mobile_public_key": mobilePublicKeyB64],
                       as: CompletePairingResult.self)
    }

    public func issueToken(accountSecret: String, deviceId: String, pairId: String) async throws -> TokenResult {
        try await post("/v1/token", bearer: accountSecret,
                       body: ["device_id": deviceId, "pair_id": pairId], as: TokenResult.self)
    }

    public func refreshToken(_ refresh: String) async throws -> TokenResult {
        try await post("/v1/token/refresh", bearer: nil, body: ["refresh_token": refresh], as: TokenResult.self)
    }

    private func post<T: Decodable>(_ path: String, bearer: String?, body: [String: String], as: T.Type) async throws -> T {
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
        return try JSONDecoder().decode(T.self, from: data)
    }
}
