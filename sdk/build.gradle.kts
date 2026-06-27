import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.plugins.signing.SigningExtension

// Root build for the Secure Gateway client SDKs (M4).
// Shared configuration for all JVM modules: JDK 17 toolchain, JUnit 5 tests.
plugins {
    java
}

subprojects {
    repositories {
        google()
        mavenCentral()
    }

    // Publishing (M4):
    //  - `./gradlew publishToMavenLocal` — local dev; the mobile-agent client consumes
    //    com.contextsolutions.securegateway:{core,java,android}:<version> from mavenLocal during co-development.
    //  - `./gradlew publish` — pushes the GPG-signed artifacts to GitHub Packages
    //    (see .github/workflows/publish-sdk.yml). The consumer (local-agent) pins these via
    //    Gradle dependency verification, so the published jars are signed.
    // Signing is skipped when no key is configured, so publishToMavenLocal stays keyless.
    apply(plugin = "maven-publish")
    apply(plugin = "signing")

    // The GitHub Packages remote — credentials from gradle props (gpr.user/gpr.key) or CI env
    // (GITHUB_ACTOR/GITHUB_TOKEN). Repositories are independent of publications, so this is
    // safe for every module (modules with no publication simply publish nothing here).
    afterEvaluate {
        extensions.findByType<PublishingExtension>()?.apply {
            repositories {
                maven {
                    name = "GitHubPackages"
                    url = uri("https://maven.pkg.github.com/Context-Solutions-Inc/secure-gateway")
                    credentials {
                        username = (findProperty("gpr.user") as String?) ?: System.getenv("GITHUB_ACTOR")
                        password = (findProperty("gpr.key") as String?) ?: System.getenv("GITHUB_TOKEN")
                    }
                }
            }
        }
    }

    // Only the JVM modules publish their `java` component here. Deliberate exceptions:
    //  - :android (plain-JVM) is NOT published — it exists only so the cross-platform
    //    e2eTest can drive the Kotlin mobile SDK on the JVM. The shippable mobile artifact
    //    is :android-aar.
    //  - :android-aar is a com.android.library (no `java` component); it configures its
    //    own publication (from the Android `release` variant, artifactId "android") and its
    //    own signing in its build script — so the com.contextsolutions.securegateway:android coordinate is
    //    preserved.
    if (name == "core" || name == "java") {
        afterEvaluate {
            extensions.configure<PublishingExtension> {
                publications {
                    create<MavenPublication>("maven") {
                        from(components["java"])
                        configureSdkPom(artifactId)
                    }
                }
            }
            signSdkPublications()
        }
    }
}

allprojects {
    group = "com.contextsolutions.securegateway"
    // 0.2.0: breaking E2EE handshake change (v1 -> v2 ephemeral forward secrecy,
    // SG-01) plus replay protection (SG-02). Bumped so consumers re-resolve from
    // mavenLocal rather than reuse a cached 0.1.0.
    // 0.2.1: SG-15 fix — the handshake is one-shot so a replayed handshake frame can no
    // longer reset the SG-02 replay window. No wire/KDF change; interop-compatible with 0.2.0.
    // 0.2.2: SG-14/SG-19 — transports reject non-wss:// relay / non-https:// auth endpoints
    // (loopback/RFC1918 carve-out) and the iOS URL parse is failable, not force-unwrapped. No
    // wire/KDF change; interop-compatible with 0.2.x.
    // 0.2.3: peer-reconnect re-key fix — the handshake stays one-shot for an *identical* (replayed)
    // ephemeral (SG-15 holds) but rebuilds the session when the peer reconnects with a *new*
    // ephemeral, instead of keeping stale keys and silently dropping every frame ("green-but-hung
    // after reconnect"). No wire/KDF change; interop-compatible with 0.2.x.
    // 0.2.4: security L2 — per-pair credential. The gateway mints a pairing-scoped credential at
    // completion (and registers the mobile device via the pairing token), so the desktop's account
    // secret no longer rides the QR: DesktopClient stops injecting QrPayload.accountSecret, and
    // MobileClient issues/refreshes/unpairs with the per-pair credential (CompletePairingResult
    // .pairCredential/.mobileDeviceId; MobileConfig.pairCredential for reconnect). Account-secret
    // fallback retained for a legacy gateway. No wire/KDF change; interop-compatible with 0.2.x.
    //
    // NOTE: this version is the coordinate consumers resolve. When local-agent adopts the
    // GitHub Packages publish path (M4 Step 2), bump in lockstep with the consumer's
    // libs.versions.toml + verification-metadata regen so a stale mavenLocal jar can't shadow
    // the signed remote.
    version = "0.2.4"
}

/** Minimal POM metadata for the published SDK coordinates (GitHub Packages / consumer hygiene). */
fun MavenPublication.configureSdkPom(artifact: String) {
    pom {
        name.set("Secure Gateway SDK ($artifact)")
        description.set(
            "End-to-end-encrypted mobile↔desktop relay client SDK " +
                "(libsodium X25519 + XChaCha20-Poly1305).",
        )
        url.set("https://github.com/Context-Solutions-Inc/secure-gateway")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://github.com/Context-Solutions-Inc/secure-gateway/blob/main/LICENSE")
            }
        }
        developers {
            developer {
                name.set("Context Solutions Inc.")
                organization.set("Context Solutions Inc.")
                organizationUrl.set("https://github.com/Context-Solutions-Inc")
            }
        }
        scm {
            url.set("https://github.com/Context-Solutions-Inc/secure-gateway")
            connection.set("scm:git:https://github.com/Context-Solutions-Inc/secure-gateway.git")
            developerConnection.set("scm:git:git@github.com:Context-Solutions-Inc/secure-gateway.git")
        }
    }
}

/**
 * GPG-sign every publication when a key is configured (CI release). When no key is present
 * (local dev / publishToMavenLocal), publish UNSIGNED rather than failing the build — GitHub
 * Packages does not require signatures, but a release build SHOULD set [signingKey].
 *
 * Keys are supplied in-memory (ASCII-armored private key + passphrase) via the `signingKey` /
 * `signingPassword` gradle props or the `SIGNING_KEY` / `SIGNING_PASSWORD` env vars.
 */
fun Project.signSdkPublications() {
    val signingKey = (findProperty("signingKey") as String?) ?: System.getenv("SIGNING_KEY")
    val signingPassword = (findProperty("signingPassword") as String?) ?: System.getenv("SIGNING_PASSWORD")
    if (signingKey.isNullOrBlank()) {
        logger.lifecycle("secure-gateway SDK ($name): no signing key — publishing UNSIGNED (ok for mavenLocal/dev).")
        return
    }
    extensions.configure<SigningExtension> {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(extensions.getByType<PublishingExtension>().publications)
    }
}
