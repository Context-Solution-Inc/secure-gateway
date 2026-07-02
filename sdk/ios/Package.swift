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
        // Provides the `Crypto` module (X25519 + HKDF-SHA256). On Apple platforms swift-crypto
        // defers to the system CryptoKit; declaring it lets the package build standalone and be
        // resolved by a host Xcode app.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "SecureGatewaySDK",
            dependencies: [
                .product(name: "Sodium", package: "swift-sodium"),
                // Direct libsodium C API — swift-sodium's Swift `encrypt` generates its own nonce;
                // XChaCha20-Poly1305 with an EXPLICIT (deterministic) nonce needs the C function.
                .product(name: "Clibsodium", package: "swift-sodium"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "SecureGatewaySDKTests",
            dependencies: ["SecureGatewaySDK"],
            resources: [.copy("Resources/vectors.json")]
        ),
    ]
)
