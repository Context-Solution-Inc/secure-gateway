import java.security.MessageDigest

plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Built as a plain Kotlin/JVM library so it compiles, unit-tests, and runs the
// cross-platform E2E on Linux (no Android SDK here). The Android-specific seams
// (Android Keystore, FCM) are stubbed behind :core interfaces; a real Android
// library build would re-target these with `com.android.library` + lazysodium-android.
kotlin {
    jvmToolchain(17)
}

dependencies {
    api(project(":core"))
    api(libs.okhttp)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
}

// The Kotlin SDK must pass the same crypto vectors as the Java SDK. Reuse the
// single-sourced vectors.json from the Go reference.
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
