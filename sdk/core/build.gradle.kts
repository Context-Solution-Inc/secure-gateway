import java.security.MessageDigest

plugins {
    `java-library`
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
    withSourcesJar()
}

dependencies {
    // XChaCha20-Poly1305 (24-byte nonce) + X25519 via native libsodium — the only
    // construction that matches the Go reference byte-for-byte (Tink/CryptoKit's
    // ChaChaPoly is the 12-byte IETF variant and would diverge). HKDF-SHA256 is done
    // with javax.crypto.Mac (RFC 5869), not libsodium, since libsodium has no HKDF.
    //
    // lazysodium is compileOnly: Crypto types against the base LazySodium (the concrete
    // binding arrives via a platform SodiumProvider, see that interface), so :core does
    // NOT leak lazysodium-java onto consumers. The desktop :java and the Android AAR each
    // declare their own flavor (lazysodium-java vs lazysodium-android). jna is dropped
    // entirely — nothing here imports it directly, and each lazysodium flavor pulls the
    // right jna variant (the jar on the JVM, the @aar on Android).
    compileOnly(libs.lazysodium.java)
    api(libs.jackson.databind)
    runtimeOnly(libs.slf4j.nop)

    // :core's own unit tests run Crypto, so they need a concrete binding + a registered
    // JVM SodiumProvider (the provider impl lives in test, never in main — see below).
    testImplementation(libs.lazysodium.java)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
}

// vectors.json is single-sourced from the Go reference (internal/e2ee/testdata).
// Copy it fresh into test resources every build so the SDK conformance test and the
// Go reference can never drift; also stamp its SHA-256 so corruption fails loudly.
val vectorsSrc = rootDir.parentFile.resolve("internal/e2ee/testdata/vectors.json")
val vectorsOut = layout.buildDirectory.dir("generated-resources/vectors")

val copyVectors = tasks.register("copyVectors") {
    inputs.file(vectorsSrc)
    outputs.dir(vectorsOut)
    doLast {
        val dest = vectorsOut.get().asFile
        dest.mkdirs()
        val target = dest.resolve("vectors.json")
        vectorsSrc.copyTo(target, overwrite = true)
        val sha = MessageDigest.getInstance("SHA-256")
            .digest(target.readBytes())
            .joinToString("") { "%02x".format(it) }
        dest.resolve("vectors.sha256").writeText(sha)
    }
}

sourceSets {
    test {
        resources { srcDir(vectorsOut) }
    }
}

tasks.named("processTestResources") { dependsOn(copyVectors) }

tasks.test { useJUnitPlatform() }
