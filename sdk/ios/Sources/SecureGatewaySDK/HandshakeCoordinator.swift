import Foundation

/// Per-session handshake (PRD FR-5.2): each side exchanges a 32-byte nonce in the first
/// frame, then both derive the directional `Session` keys. Mirrors the JVM SDK: a 1-byte tag
/// inside the opaque relay payload distinguishes a cleartext handshake nonce from an
/// encrypted application frame.
final class HandshakeCoordinator {
    static let tagHandshake: UInt8 = 0x01
    static let tagData: UInt8 = 0x02

    private let myPriv: Data
    private let peerPub: Data
    private let myRole: Role
    private let myNonce: Data
    private var session: Session?

    init(myPriv: Data, peerPub: Data, myRole: Role) {
        self.myPriv = myPriv
        self.peerPub = peerPub
        self.myRole = myRole
        self.myNonce = Crypto.newHandshakeNonce()
    }

    var isComplete: Bool { session != nil }

    func handshakeFrame() -> Data {
        var d = Data([Self.tagHandshake])
        d.append(myNonce)
        return d
    }

    /// Returns decrypted plaintext for a data frame, or nil for a handshake frame.
    func onFrame(_ payload: Data, id: String, ts: Int64) throws -> Data? {
        guard let tag = payload.first else { throw CryptoError.badLength }
        let body = payload.suffix(from: payload.startIndex + 1)
        switch tag {
        case Self.tagHandshake:
            try acceptPeerNonce(Data(body))
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

    private func acceptPeerNonce(_ peerNonce: Data) throws {
        let mobileNonce = myRole == .mobile ? myNonce : peerNonce
        let desktopNonce = myRole == .mobile ? peerNonce : myNonce
        session = try Session.create(myPriv: myPriv, peerPub: peerPub, role: myRole,
                                     mobileNonce: mobileNonce, desktopNonce: desktopNonce)
    }
}
