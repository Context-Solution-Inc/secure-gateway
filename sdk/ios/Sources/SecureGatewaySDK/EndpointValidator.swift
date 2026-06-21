import Foundation

/// Typed error for an endpoint that fails transport-security validation (SG-14/SG-19).
public enum EndpointError: Error, Equatable {
    case missing(String)      // empty/absent endpoint
    case invalidURL(String)   // unparseable / no scheme or host
    case insecure(String)     // plaintext scheme on a non-private host
}

/// Validates relay/auth endpoints taken from the (untrusted) pairing QR before they are used to
/// open a connection. Relay endpoints must be `wss://` and auth endpoints must be `https://`,
/// UNLESS the host is loopback or an RFC1918 private address (the LAN-development carve-out where
/// plaintext `ws://`/`http://` is allowed). Mirrors the JVM `EndpointValidator`.
///
/// Without this a malicious QR could downgrade the connection JWT (sent as an
/// `Authorization: Bearer` header on the upgrade) to cleartext, or crash the app via a
/// force-unwrapped `URL(string:)` on a malformed value (SG-19).
enum EndpointValidator {

    /// Returns the parsed relay URL or throws `EndpointError`.
    static func requireSecureRelay(_ url: String) throws -> URL {
        try require(url, plain: "ws", secure: "wss", what: "relay")
    }

    /// Returns the parsed auth URL or throws `EndpointError`.
    static func requireSecureAuth(_ url: String) throws -> URL {
        try require(url, plain: "http", secure: "https", what: "auth")
    }

    private static func require(_ url: String, plain: String, secure: String, what: String) throws -> URL {
        if url.isEmpty { throw EndpointError.missing(what) }
        guard let parsed = URL(string: url), let scheme = parsed.scheme?.lowercased(), let host = parsed.host else {
            throw EndpointError.invalidURL(url)
        }
        if scheme == secure {
            return parsed
        }
        if scheme == plain && isPrivateOrLoopback(host) {
            return parsed
        }
        throw EndpointError.insecure(url)
    }

    /// True for localhost, 127.0.0.0/8, ::1, and the RFC1918 ranges (10/8, 172.16/12, 192.168/16).
    static func isPrivateOrLoopback(_ host: String) -> Bool {
        var h = host
        if h.hasPrefix("[") && h.hasSuffix("]") { // bracketed IPv6 literal
            h = String(h.dropFirst().dropLast())
        }
        if h.caseInsensitiveCompare("localhost") == .orderedSame || h == "::1" {
            return true
        }
        let parts = h.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else {
            return false // not a dotted-quad IPv4 literal => treat as public
        }
        var octets = [Int](repeating: 0, count: 4)
        for i in 0..<4 {
            guard let v = Int(parts[i]), v >= 0, v <= 255 else { return false }
            octets[i] = v
        }
        if octets[0] == 127 { return true }                              // loopback
        if octets[0] == 10 { return true }                               // 10/8
        if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 { return true } // 172.16/12
        return octets[0] == 192 && octets[1] == 168                      // 192.168/16
    }
}
