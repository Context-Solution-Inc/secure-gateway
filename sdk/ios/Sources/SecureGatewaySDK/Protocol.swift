import Foundation

/// Relay wire envelope + vocabulary (PRD FR-4, Appendix B), matching the Go reference and
/// the JVM SDK. For `msg`/`ack` the payload is the ciphertext as a base64-std JSON string
/// (matching Go `json.Marshal([]byte)`); `sys`/`error`/`auth_refresh` use JSON objects.
enum MessageType {
    static let msg = "msg"
    static let ack = "ack"
    static let authRefresh = "auth_refresh"
    static let error = "error"
    static let sys = "sys"
}

enum SysKind {
    static let peerOnline = "peer_online"
    static let peerOffline = "peer_offline"
    static let shutdown = "shutdown"
}

enum ErrorCode {
    static let peerOffline = "peer_offline"
}

enum CloseCode {
    static let normal = 1000
    static let goingAway = 1001
    static let superseded = 4001
    static let tokenExpired = 4003
    static let revoked = 4004
    static let protocolError = 4005
}

struct Envelope: Codable {
    var v: Int = 1
    var type: String
    var id: String
    var ts: Int64
    var payload: AnyCodable?
}

/// Minimal type-erased JSON value so an Envelope payload can be a base64 string (msg/ack) or
/// an object (sys/error/auth_refresh).
struct AnyCodable: Codable {
    let value: Any

    init(_ value: Any) { self.value = value }

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self) { value = s }
        else if let d = try? c.decode([String: AnyCodable].self) { value = d.mapValues { $0.value } }
        else if let i = try? c.decode(Int64.self) { value = i }
        else { value = NSNull() }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case let s as String: try c.encode(s)
        case let d as [String: Any]: try c.encode(d.mapValues { AnyCodable($0) })
        case let i as Int64: try c.encode(i)
        default: try c.encodeNil()
        }
    }
}

enum Protocol {
    static let version = 1
    private static let encoder = JSONEncoder()
    private static let decoder = JSONDecoder()

    static func encode(_ env: Envelope) throws -> Data { try encoder.encode(env) }
    static func decode(_ data: Data) throws -> Envelope { try decoder.decode(Envelope.self, from: data) }

    static func msg(id: String, ts: Int64, ciphertext: Data) -> Envelope {
        Envelope(type: MessageType.msg, id: id, ts: ts, payload: AnyCodable(ciphertext.base64EncodedString()))
    }

    static func ack(id: String, ts: Int64) -> Envelope {
        Envelope(type: MessageType.ack, id: id, ts: ts, payload: nil)
    }

    static func authRefresh(id: String, ts: Int64, token: String) -> Envelope {
        Envelope(type: MessageType.authRefresh, id: id, ts: ts, payload: AnyCodable(["token": token]))
    }

    static func ciphertext(_ env: Envelope) -> Data? {
        guard let s = env.payload?.value as? String else { return nil }
        return Data(base64Encoded: s)
    }

    static func sysKind(_ env: Envelope) -> String? {
        (env.payload?.value as? [String: Any])?["kind"] as? String
    }

    static func errorCode(_ env: Envelope) -> String? {
        (env.payload?.value as? [String: Any])?["code"] as? String
    }
}
