import XCTest
@testable import SecureGatewaySDK

// SG-14/SG-19 regression: relay endpoints must be wss:// and auth endpoints https://, except
// for loopback / RFC1918 hosts (LAN-dev carve-out). A malformed URL throws a typed error rather
// than force-unwrapping into a crash.
//
// NOTE: reviewed source on the Linux pipeline; run with `swift test` on macOS.
final class EndpointValidatorTests: XCTestCase {

    func testSecureSchemesAccepted() throws {
        XCTAssertEqual(try EndpointValidator.requireSecureRelay("wss://relay.example.com/v1/connect").scheme, "wss")
        XCTAssertEqual(try EndpointValidator.requireSecureAuth("https://auth.example.com").scheme, "https")
    }

    func testPlaintextRejectedForPublicHosts() {
        XCTAssertThrowsError(try EndpointValidator.requireSecureRelay("ws://relay.example.com/v1/connect"))
        XCTAssertThrowsError(try EndpointValidator.requireSecureAuth("http://auth.example.com"))
        XCTAssertThrowsError(try EndpointValidator.requireSecureRelay("ws://8.8.8.8:8443/v1/connect"))
    }

    func testPlaintextAllowedForLoopbackAndPrivateRanges() throws {
        XCTAssertNoThrow(try EndpointValidator.requireSecureRelay("ws://127.0.0.1:8443/v1/connect"))
        XCTAssertNoThrow(try EndpointValidator.requireSecureRelay("ws://localhost:8443/v1/connect"))
        XCTAssertNoThrow(try EndpointValidator.requireSecureAuth("http://192.168.1.10:8080"))
        XCTAssertNoThrow(try EndpointValidator.requireSecureRelay("ws://10.0.0.5/v1/connect"))
        XCTAssertNoThrow(try EndpointValidator.requireSecureRelay("ws://172.16.0.9/v1/connect"))
    }

    func testMalformedAndEmptyRejected() {
        XCTAssertThrowsError(try EndpointValidator.requireSecureRelay(""))
        XCTAssertThrowsError(try EndpointValidator.requireSecureRelay("not a url"))
        XCTAssertThrowsError(try EndpointValidator.requireSecureRelay("wss://"))
    }

    func testPrivateRangeBoundaries() {
        XCTAssertTrue(EndpointValidator.isPrivateOrLoopback("172.31.255.254"))
        XCTAssertFalse(EndpointValidator.isPrivateOrLoopback("172.32.0.1"))
        XCTAssertFalse(EndpointValidator.isPrivateOrLoopback("172.15.0.1"))
        XCTAssertTrue(EndpointValidator.isPrivateOrLoopback("192.168.255.1"))
        XCTAssertFalse(EndpointValidator.isPrivateOrLoopback("192.169.0.1"))
        XCTAssertFalse(EndpointValidator.isPrivateOrLoopback("relay.internal"))
    }
}
