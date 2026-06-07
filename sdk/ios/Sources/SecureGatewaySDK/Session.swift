import Foundation

/// One connection session's directional keys, mirroring the Go `e2ee.Session` and the JVM
/// SDK: mobile seals with K_m2d / opens with K_d2m; desktop is the reverse. Salt is always
/// mobile-nonce-first, fixed by role.
public struct Session {
    private let sendKey: Data
    private let recvKey: Data

    public static func create(myPriv: Data, peerPub: Data, role: Role,
                              mobileNonce: Data, desktopNonce: Data) throws -> Session {
        let shared = try Crypto.sharedSecret(myPriv: myPriv, peerPub: peerPub)
        let kM2D = Crypto.deriveKey(shared: shared, mobileNonce: mobileNonce, desktopNonce: desktopNonce, dir: "m2d")
        let kD2M = Crypto.deriveKey(shared: shared, mobileNonce: mobileNonce, desktopNonce: desktopNonce, dir: "d2m")
        return role == .mobile ? Session(sendKey: kM2D, recvKey: kD2M)
                               : Session(sendKey: kD2M, recvKey: kM2D)
    }

    /// Seal plaintext: returns nonce(24) || ciphertext+tag, ready as the envelope payload.
    public func seal(id: String, ts: Int64, plaintext: Data) throws -> Data {
        try sealWith(nonce: Crypto.randomNonce(), id: id, ts: ts, plaintext: plaintext)
    }

    /// Seal with an explicit nonce — for the deterministic interop vectors/tests.
    func sealWith(nonce: Data, id: String, ts: Int64, plaintext: Data) throws -> Data {
        let ct = try Crypto.aeadSeal(key: sendKey, nonce: nonce, aad: Crypto.aad(id: id, ts: ts), plaintext: plaintext)
        return nonce + ct
    }

    public func open(id: String, ts: Int64, wire: Data) throws -> Data {
        guard wire.count >= Crypto.nonceSize else { throw CryptoError.badLength }
        let nonce = wire.prefix(Crypto.nonceSize)
        let ct = wire.suffix(from: wire.startIndex + Crypto.nonceSize)
        return try Crypto.aeadOpen(key: recvKey, nonce: Data(nonce), aad: Crypto.aad(id: id, ts: ts), cipher: Data(ct))
    }
}
