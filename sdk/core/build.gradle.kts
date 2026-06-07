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
    api(libs.lazysodium.java)
    api(libs.jna)
    api(libs.jackson.databind)
    runtimeOnly(libs.slf4j.nop)

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
