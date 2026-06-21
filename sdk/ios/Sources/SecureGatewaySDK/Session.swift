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
