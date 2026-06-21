import XCTest
@testable import SecureGatewaySDK

// SG-02 regression: the iOS Session must reject duplicate delivery of an authenticated
// envelope, matching the Go reference and the JVM SDK.
//
// NOTE: macOS/Xcode only — cannot run on Linux CI (CryptoKit + swift-sodium). Run with
// `swift test` on macOS. The Linux pipeline ships this as reviewed source.
final class SessionReplayTests: XCTestCase {

    private func pair() throws -> (mobile: Session, desktop: Session) {
        let m = Crypto.generateKeyPair()  // mobile identity
        let d = Crypto.generateKeyPair()  // desktop identity
        let me = Crypto.generateKeyPair() // mobile ephemeral
        let de = Crypto.generateKeyPair() // desktop ephemeral
        let mobile = try Session.create(idPriv: m.privateKey, peerIdPub: d.publicKey,
                                        ephPriv: me.privateKey, peerEphPub: de.publicKey, role: .mobile)
        let desktop = try Session.create(idPriv: d.privateKey, peerIdPub: m.publicKey,
                                         ephPriv: de.privateKey, peerEphPub: me.publicKey, role: .desktop)
        return (mobile, desktop)
    }

    func testReplayRejected() throws {
        let (mobile, desktop) = try pair()
        let plain = Data("deliver once".utf8)
        let wire = try mobile.seal(id: "id-1", ts: 1_765_432_100_123, plaintext: plain)

        XCTAssertEqual(try desktop.open(id: "id-1", ts: 1_765_432_100_123, wire: wire), plain)
        XCTAssertThrowsError(try desktop.open(id: "id-1", ts: 1_765_432_100_123, wire: wire)) { err in
            XCTAssertEqual(err as? CryptoError, .replay)
        }
    }

    func testStaleTimestampRejected() throws {
        let (mobile, desktop) = try pair()
        // Advance the receive high-water mark.
        let recent = try mobile.seal(id: "id-new", ts: 10_000_000, plaintext: Data("recent".utf8))
        _ = try desktop.open(id: "id-new", ts: 10_000_000, wire: recent)
        // A far-older authenticated message (outside the window) is refused.
        let old = try mobile.seal(id: "id-old", ts: 1, plaintext: Data("ancient".utf8))
        XCTAssertThrowsError(try desktop.open(id: "id-old", ts: 1, wire: old)) { err in
            XCTAssertEqual(err as? CryptoError, .stale)
        }
    }
}
