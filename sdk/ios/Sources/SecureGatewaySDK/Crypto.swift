import Foundation
import Crypto      // CryptoKit on Apple platforms
import Sodium

/// E2EE crypto primitives (PRD FR-5), matching the Go reference `internal/e2ee/e2ee.go` and
/// the JVM SDK byte-for-byte. The interop vectors in `internal/e2ee/testdata/vectors.json`
/// are the cross-platform contract.
///
/// - X25519 ECDH via CryptoKit `Curve25519.KeyAgreement` (raw shared secret, low-order
///   points rejected by CryptoKit).
/// - HKDF-SHA256 via CryptoKit `HKDF<SHA256>` (RFC 5869 — matches Go's x/crypto/hkdf).
/// - XChaCha20-Poly1305 (24-byte nonce) via libsodium (swift-sodium); CryptoKit's ChaChaPoly
///   is the 12-byte IETF variant and would NOT match.
public enum Role: String {
    case mobile
    case desktop
}

public struct KeyPair {
    public let privateKey: Data  // 32 bytes
    public let publicKey: Data   // 32 bytes
}

public enum CryptoError: Error, Equatable {
    case ecdhFailed
    case sealFailed
    case openFailed
    case badLength
    case replay // SG-02: envelope id already delivered on this session
    case stale  // SG-02: envelope ts is outside the replay window
}

public enum Crypto {
    public static let keySize = 32
    public static let nonceSize = 24
    static let infoPrefix = "secure-gateway/e2ee/v2|"

    private static let sodium = Sodium()

    public static func generateKeyPair() -> KeyPair {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        return KeyPair(privateKey: priv.rawRepresentation, publicKey: priv.publicKey.rawRepresentation)
    }

    public static func publicFromPrivate(_ priv: Data) throws -> Data {
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv)
        return key.publicKey.rawRepresentation
    }

    /// Raw X25519 shared secret (matches Go's curve25519.X25519).
    public static func sharedSecret(myPriv: Data, peerPub: Data) throws -> Data {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPriv)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPub)
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
        return secret.withUnsafeBytes { Data($0) }
    }

    /// HKDF-SHA256 over the keying material, info = "secure-gateway/e2ee/v2|"+dir.
    static func deriveKey(ikm: Data, salt: Data, dir: String) -> Data {
        let info = Data((infoPrefix + dir).utf8)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: info,
            outputByteCount: keySize)
        return key.withUnsafeBytes { Data($0) }
    }

    /// AEAD associated data: utf8(id) || big-endian uint64(ts).
    static func aad(id: String, ts: Int64) -> Data {
        var d = Data(id.utf8)
        var be = UInt64(bitPattern: ts).bigEndian
        withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
        return d
    }

    /// XChaCha20-Poly1305 seal with an explicit nonce. Returns ciphertext+tag (no nonce).
    static func aeadSeal(key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data {
        guard let ct = sodium.aead.xchacha20poly1305ietf.encrypt(
            message: [UInt8](plaintext),
            secretKey: [UInt8](key),
            nonce: [UInt8](nonce),
            additionalData: [UInt8](aad)) else {
            throw CryptoError.sealFailed
        }
        return Data(ct)
    }

    static func aeadOpen(key: Data, nonce: Data, aad: Data, cipher: Data) throws -> Data {
        guard let pt = sodium.aead.xchacha20poly1305ietf.decrypt(
            authenticatedCipherText: [UInt8](cipher),
            secretKey: [UInt8](key),
            nonce: [UInt8](nonce),
            additionalData: [UInt8](aad)) else {
            throw CryptoError.openFailed
        }
        return Data(pt)
    }

    static func randomNonce() -> Data {
        var bytes = [UInt8](repeating: 0, count: nonceSize)
        _ = sodium.randomBytes.buf(length: nonceSize).map { bytes = $0 }
        return Data(bytes)
    }
}
