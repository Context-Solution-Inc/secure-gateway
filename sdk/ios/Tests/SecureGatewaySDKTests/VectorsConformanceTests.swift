import XCTest
@testable import SecureGatewaySDK

// The M4 exit gate for the iOS SDK (PRD §11): reproduce the committed interop vectors
// (internal/e2ee/testdata/vectors.json) byte-for-byte and decrypt them, matching the Go
// reference and the JVM SDKs.
//
// NOTE: macOS/Xcode only — cannot run on Linux CI (CryptoKit + swift-sodium). Run with
// `swift test` on macOS. The Linux pipeline ships this as reviewed source.
final class VectorsConformanceTests: XCTestCase {

    struct Vector: Decodable {
        let name, sender: String
        let mobile_private, mobile_public, desktop_private, desktop_public: String
        let mobile_handshake_nonce, desktop_handshake_nonce: String
        let key_m2d, key_d2m, message_nonce, id: String
        let ts: Int64
        let plaintext, wire_ciphertext: String
    }
    struct File: Decodable { let vectors: [Vector] }

    func testVectors() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "vectors", withExtension: "json"))
        let file = try JSONDecoder().decode(File.self, from: Data(contentsOf: url))
        XCTAssertGreaterThanOrEqual(file.vectors.count, 4)

        for v in file.vectors {
            let mobilePriv = hex(v.mobile_private), mobilePub = hex(v.mobile_public)
            let desktopPriv = hex(v.desktop_private), desktopPub = hex(v.desktop_public)
            let mobileNonce = hex(v.mobile_handshake_nonce), desktopNonce = hex(v.desktop_handshake_nonce)
            let messageNonce = hex(v.message_nonce)
            let plaintext = hex(v.plaintext), wire = hex(v.wire_ciphertext)
            let sender = Role(rawValue: v.sender)!

            // Public keys derive from the committed privates.
            XCTAssertEqual(try Crypto.publicFromPrivate(mobilePriv), mobilePub, v.name)
            XCTAssertEqual(try Crypto.publicFromPrivate(desktopPriv), desktopPub, v.name)

            // Directional keys match (X25519 + HKDF-SHA256).
            let shared = try Crypto.sharedSecret(myPriv: mobilePriv, peerPub: desktopPub)
            XCTAssertEqual(Crypto.deriveKey(shared: shared, mobileNonce: mobileNonce, desktopNonce: desktopNonce, dir: "m2d"), hex(v.key_m2d), v.name)
            XCTAssertEqual(Crypto.deriveKey(shared: shared, mobileNonce: mobileNonce, desktopNonce: desktopNonce, dir: "d2m"), hex(v.key_d2m), v.name)

            // Re-seal with the fixed nonce → must equal the committed wire bytes.
            let senderPriv = sender == .mobile ? mobilePriv : desktopPriv
            let peerPub = sender == .mobile ? desktopPub : mobilePub
            let senderSession = try Session.create(myPriv: senderPriv, peerPub: peerPub, role: sender, mobileNonce: mobileNonce, desktopNonce: desktopNonce)
            let produced = try senderSession.sealWith(nonce: messageNonce, id: v.id, ts: v.ts, plaintext: plaintext)
            XCTAssertEqual(produced, wire, "wire ciphertext: \(v.name)")

            // Peer opens it back to plaintext.
            let peerRole: Role = sender == .mobile ? .desktop : .mobile
            let recvPriv = sender == .mobile ? desktopPriv : mobilePriv
            let recvPeer = sender == .mobile ? mobilePub : desktopPub
            let recvSession = try Session.create(myPriv: recvPriv, peerPub: recvPeer, role: peerRole, mobileNonce: mobileNonce, desktopNonce: desktopNonce)
            XCTAssertEqual(try recvSession.open(id: v.id, ts: v.ts, wire: wire), plaintext, "decrypt: \(v.name)")
        }
    }

    private func hex(_ s: String) -> Data {
        var data = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            data.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return data
    }
}
