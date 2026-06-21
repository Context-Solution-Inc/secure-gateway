import Foundation

/// One connection session's directional keys, mirroring the Go `e2ee.Session` and the JVM
/// SDK: mobile seals with K_m2d / opens with K_d2m; desktop is the reverse. Salt is always
/// mobile-nonce-first, fixed by role.
///
/// This is a `final class` (not a `struct`) because `open` maintains per-session anti-replay
/// state (SG-02) that must persist across calls on the same instance.
public final class Session {
    private let sendKey: Data
    private let recvKey: Data

    /// Envelope ts is unix-milliseconds (the relay protocol's ts unit); an inbound envelope
    /// older than this many ms behind the highest seen ts is rejected. Mirrors the Go
    /// reference `defaultReplayWindowMillis` (5 minutes).
    private static let replayWindowMillis: Int64 = 5 * 60 * 1000

    // Anti-replay state, advanced only with id/ts the AEAD has authenticated.
    private var seen: [String: Int64] = [:]
    private var lastTs: Int64 = 0
    private var primed = false

    private init(sendKey: Data, recvKey: Data) {
        self.sendKey = sendKey
        self.recvKey = recvKey
    }

    /// Derive the directional session keys for one connection. `idPriv`/`peerIdPub` are this
    /// device's long-term identity private key and the peer's identity public key (exchanged
    /// at pairing); `ephPriv`/`peerEphPub` are this session's ephemeral private key and the
    /// peer's ephemeral public key (exchanged in the handshake). Mixing the ephemeral DH into
    /// the keying material gives forward secrecy (FR-5.2); the identity DH authenticates the
    /// peer. Mirrors the Go reference `e2ee.NewSession`.
    public static func create(idPriv: Data, peerIdPub: Data, ephPriv: Data, peerEphPub: Data,
                              role: Role) throws -> Session {
        let myEphPub = try Crypto.publicFromPrivate(ephPriv)
        // Four X25519 shared secrets (Noise-KK style):
        let ss = try Crypto.sharedSecret(myPriv: idPriv, peerPub: peerIdPub)   // identity<->identity (auth)
        let ee = try Crypto.sharedSecret(myPriv: ephPriv, peerPub: peerEphPub) // ephemeral<->ephemeral (FS)
        let md: Data
        let dm: Data
        if role == .mobile {
            md = try Crypto.sharedSecret(myPriv: idPriv, peerPub: peerEphPub)  // mobileIdentity <-> desktopEphemeral
            dm = try Crypto.sharedSecret(myPriv: ephPriv, peerPub: peerIdPub)  // desktopIdentity <-> mobileEphemeral
        } else {
            md = try Crypto.sharedSecret(myPriv: ephPriv, peerPub: peerIdPub)  // == DH(mobileIdentity, desktopEphemeral)
            dm = try Crypto.sharedSecret(myPriv: idPriv, peerPub: peerEphPub)  // == DH(desktopIdentity, mobileEphemeral)
        }
        let ikm = ss + ee + md + dm

        let mobileEphPub = role == .mobile ? myEphPub : peerEphPub
        let desktopEphPub = role == .mobile ? peerEphPub : myEphPub
        let salt = mobileEphPub + desktopEphPub

        let kM2D = Crypto.deriveKey(ikm: ikm, salt: salt, dir: "m2d")
        let kD2M = Crypto.deriveKey(ikm: ikm, salt: salt, dir: "d2m")
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
        let pt = try Crypto.aeadOpen(key: recvKey, nonce: Data(nonce), aad: Crypto.aad(id: id, ts: ts), cipher: Data(ct))
        // Reject duplicate delivery only after the AEAD has authenticated id/ts, so forged
        // metadata cannot advance the replay window (SG-02, FR-5.1).
        try checkReplay(id: id, ts: ts)
        return pt
    }

    private func checkReplay(id: String, ts: Int64) throws {
        if primed && ts < lastTs - Session.replayWindowMillis {
            throw CryptoError.stale
        }
        if seen[id] != nil {
            throw CryptoError.replay
        }
        seen[id] = ts
        if !primed || ts > lastTs {
            lastTs = ts
        }
        primed = true
        let floor = lastTs - Session.replayWindowMillis
        seen = seen.filter { $0.value >= floor }
    }
}
