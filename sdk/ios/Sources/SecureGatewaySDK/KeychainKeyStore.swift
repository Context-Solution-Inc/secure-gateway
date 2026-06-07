import Foundation

/// Where the device's X25519 identity private key lives (FR-2.3).
public protocol KeyStore {
    func loadOrCreateIdentity() throws -> KeyPair
}

/// Non-persistent keystore for tests.
public final class InMemoryKeyStore: KeyStore {
    private var identity: KeyPair?
    public init(_ identity: KeyPair? = nil) { self.identity = identity }
    public func loadOrCreateIdentity() throws -> KeyPair {
        if let id = identity { return id }
        let kp = Crypto.generateKeyPair()
        identity = kp
        return kp
    }
}

/// Keychain-backed keystore (PRD §8.2: Keychain / Secure Enclave). The Secure Enclave does
/// not support X25519 keys directly, so the production design wraps the X25519 private key
/// with a Secure-Enclave P-256 / AES key and stores the wrapped blob in the Keychain; the
/// unwrapped key lives only transiently in memory. This default stores the raw private key as
/// a Keychain generic-password item (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly).
///
/// TODO(ios): add the Secure-Enclave wrapping layer for hardware-bound protection.
public final class KeychainKeyStore: KeyStore {
    private let account: String
    private let service: String

    public init(service: String = "com.securegateway.sdk", account: String = "x25519-identity") {
        self.service = service
        self.account = account
    }

    public func loadOrCreateIdentity() throws -> KeyPair {
        if let priv = try read() {
            return KeyPair(privateKey: priv, publicKey: try Crypto.publicFromPrivate(priv))
        }
        let kp = Crypto.generateKeyPair()
        try write(kp.privateKey)
        return kp
    }

    private func read() throws -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw NSError(domain: "KeychainKeyStore", code: Int(status))
        }
        return data
    }

    private func write(_ priv: Data) throws {
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: priv,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainKeyStore", code: Int(status))
        }
    }
}
