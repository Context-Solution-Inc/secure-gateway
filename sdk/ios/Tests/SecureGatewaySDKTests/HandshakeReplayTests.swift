import XCTest
@testable import SecureGatewaySDK

// SG-15 regression: a replayed handshake frame must NOT reset the per-session anti-replay
// window (SG-02). The handshake is one-shot, so re-feeding the peer's original handshake frame
// is ignored and a replayed data frame is still rejected.
//
// NOTE: macOS/Xcode only — cannot run on Linux CI (CryptoKit + swift-sodium). Run with
// `swift test` on macOS. The Linux pipeline ships this as reviewed source.
final class HandshakeReplayTests: XCTestCase {

    func testHandshakeIsOneShotAndPreservesReplayGuard() throws {
        let mobile = Crypto.generateKeyPair()
        let desktop = Crypto.generateKeyPair()
        let m = HandshakeCoordinator(myPriv: mobile.privateKey, peerPub: desktop.publicKey, myRole: .mobile)
        let d = HandshakeCoordinator(myPriv: desktop.privateKey, peerPub: mobile.publicKey, myRole: .desktop)

        let mHandshake = m.handshakeFrame()
        XCTAssertNil(try d.onFrame(mHandshake, id: "h", ts: 0))
        XCTAssertNil(try m.onFrame(d.handshakeFrame(), id: "h", ts: 0))
        XCTAssertTrue(d.isComplete)

        // Deliver an application frame once.
        let plain = Data("command-1".utf8)
        let data = try m.sealFrame(id: "id-1", ts: 1_000, plaintext: plain)
        XCTAssertEqual(try d.onFrame(data, id: "id-1", ts: 1_000), plain)

        // A malicious relay re-injects the peer's original handshake frame — must be ignored
        // (the established session and its replay guard are kept).
        XCTAssertNil(try d.onFrame(mHandshake, id: "h", ts: 0))

        // Replaying the already-delivered data frame must now be rejected.
        XCTAssertThrowsError(try d.onFrame(data, id: "id-1", ts: 1_000)) { err in
            XCTAssertEqual(err as? CryptoError, .replay)
        }
    }
}
