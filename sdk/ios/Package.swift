// swift-tools-version:5.7
import PackageDescription

// SecureGatewaySDK — the iOS Relay Client SDK (PRD §8.2). Source-only in this repo's Linux
// CI (no Xcode); build and run the vectors-conformance tests on macOS with `swift test`.
//
// Crypto: CryptoKit provides X25519 (Curve25519.KeyAgreement) and HKDF<SHA256> natively
// (matching the Go reference and the JVM SDK); XChaCha20-Poly1305 (24-byte nonce) is NOT in
// CryptoKit (its ChaChaPoly is the 12-byte IETF variant), so swift-sodium supplies it.
let package = Package(
    name: "SecureGatewaySDK",
    platforms: [.iOS(.v14), .macOS(.v11)],
    products: [
        .library(name: "SecureGatewaySDK", targets: ["SecureGatewaySDK"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1"),
    ],
    targets: [
        .target(
            name: "SecureGatewaySDK",
            dependencies: [.product(name: "Sodium", package: "swift-sodium")]
        ),
        .testTarget(
            name: "SecureGatewaySDKTests",
            dependencies: ["SecureGatewaySDK"],
            resources: [.copy("Resources/vectors.json")]
        ),
    ]
)
