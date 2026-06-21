import Foundation

/// Per-session handshake (PRD FR-5.2): each side generates a fresh ephemeral X25519 keypair
/// and exchanges its public half in the first frame, then both derive the directional
/// `Session` keys (mixing the ephemeral DH into the keying material for forward secrecy).
/// Mirrors the JVM SDK: a 1-byte tag inside the opaque relay payload distinguishes a
/// cleartext ephemeral public key from an encrypted application frame.
final class HandshakeCoordinator {
    static let tagHandshake: UInt8 = 0x01
    static let tagData: UInt8 = 0x02

    private let idPriv: Data
    private let peerIdPub: Data
    private let myRole: Role
    private let ephPriv: Data
    private let ephPub: Data
    private var session: Session?

    init(myPriv: Data, peerPub: Data, myRole: Role) {
        self.idPriv = myPriv
        self.peerIdPub = peerPub
        self.myRole = myRole
        let eph = Crypto.generateKeyPair()
        self.ephPriv = eph.privateKey
        self.ephPub = eph.publicKey
    }

    var isComplete: Bool { session != nil }

    func handshakeFrame() -> Data {
        var d = Data([Self.tagHandshake])
        d.append(ephPub)
        return d
    }

    /// Returns decrypted plaintext for a data frame, or nil for a handshake frame.
    func onFrame(_ payload: Data, id: String, ts: Int64) throws -> Data? {
        guard let tag = payload.first else { throw CryptoError.badLength }
        let body = payload.suffix(from: payload.startIndex + 1)
        switch tag {
        case Self.tagHandshake:
            try acceptPeerEphemeral(Data(body))
            return nil
        case Self.tagData:
            guard let s = session else { throw CryptoError.openFailed }
            return try s.open(id: id, ts: ts, wire: Data(body))
        default:
            throw CryptoError.badLength
        }
    }

    func sealFrame(id: String, ts: Int64, plaintext: Data) throws -> Data {
        guard let s = session else { throw CryptoError.sealFailed }
        var d = Data([Self.tagData])
        d.append(try s.seal(id: id, ts: ts, plaintext: plaintext))
        return d
    }

    private func acceptPeerEphemeral(_ peerEphPub: Data) throws {
        // The handshake is one-shot (SG-15): once the session exists, ignore any further
        // TAG_HANDSHAKE frame instead of rebuilding. Rebuilding would mint a fresh Session
        // with an empty anti-replay window (SG-02), letting a malicious/compromised relay
        // re-inject the peer's original (cleartext) handshake frame to reset the replay guard
        // and then replay previously delivered data frames. Dropping the duplicate keeps the
        // established session and its replay state intact.
        if session != nil { return }
        guard peerEphPub.count == Crypto.keySize else { throw CryptoError.badLength }
        session = try Session.create(idPriv: idPriv, peerIdPub: peerIdPub,
                                     ephPriv: ephPriv, peerEphPub: peerEphPub, role: myRole)
    }
}
