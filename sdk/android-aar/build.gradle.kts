import org.gradle.plugins.signing.SigningExtension

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

// The REAL Android library: the same mobile SDK Kotlin sources as :android, but built as a
// com.android.library on lazysodium-android (native arm64 libsodium) so the relay crypto
// actually runs on a Pixel 7. The plain-JVM :android stays for the hermetic e2eTest; this
// module is what ships and what publishes the com.contextsolutions.securegateway:android coordinate.
android {
    namespace = "com.contextsolutions.securegateway.mobile"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // Share the platform-agnostic mobile SDK sources with :android (MobileClient,
    // MobileConfig, SecureGateway, OkHttpWebSocketTransport). The Android-only seam — the
    // lazysodium-android SodiumProvider — lives in this module's own src/main/kotlin.
    sourceSets.getByName("main").kotlin.srcDir("../android/src/main/kotlin")

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api(project(":core"))
    api(libs.okhttp)
    // The Android-native libsodium binding. :core declares lazysodium only compileOnly, so
    // this is the single concrete flavor on the device classpath. lazysodium-android's
    // SodiumAndroid is JNA-based and needs libjnidispatch.so (arm64) at runtime — but its
    // POM pulls jna as the plain JAR (no native), so JNA can't load on-device. Exclude that
    // and pull jna's @aar (classes + per-ABI libjnidispatch.so) at the version lazysodium
    // expects, so AGP unpacks the native into the consuming APK.
    implementation(libs.lazysodium.android) {
        exclude(group = "net.java.dev.jna", module = "jna")
    }
    implementation("net.java.dev.jna:jna:5.17.0@aar")
}

// Preserve the com.contextsolutions.securegateway:android coordinate (mobile-agent consumes it unchanged):
// publish the Android `release` variant under artifactId "android", not the module name. The
// GitHub Packages repository is wired by the root build's subprojects block (M4); here we add
// the POM metadata + GPG signing for this module's own `release` publication (the root can't —
// the `release` component only exists after AGP evaluates this module).
afterEvaluate {
    extensions.configure<PublishingExtension> {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "android"
                pom {
                    name.set("Secure Gateway SDK (android)")
                    description.set(
                        "End-to-end-encrypted mobile↔desktop relay client SDK " +
                            "(libsodium X25519 + XChaCha20-Poly1305), Android/lazysodium-android build.",
                    )
                    url.set("https://github.com/Context-Solution-Inc/secure-gateway")
                    licenses {
                        license {
                            name.set("MIT License")
                            url.set("https://github.com/Context-Solution-Inc/secure-gateway/blob/main/LICENSE")
                        }
                    }
                    developers {
                        developer {
                            name.set("Context Solutions Inc.")
                            organization.set("Context Solutions Inc.")
                            organizationUrl.set("https://github.com/Context-Solution-Inc")
                        }
                    }
                    scm {
                        url.set("https://github.com/Context-Solution-Inc/secure-gateway")
                        connection.set("scm:git:https://github.com/Context-Solution-Inc/secure-gateway.git")
                        developerConnection.set("scm:git:git@github.com:Context-Solution-Inc/secure-gateway.git")
                    }
                }
            }
        }
    }

    // GPG-sign when a key is configured (CI release); publish unsigned for keyless dev /
    // publishToMavenLocal. Mirrors signSdkPublications() in the root build (the helper
    // functions there aren't visible across build scripts).
    val signingKey = (findProperty("signingKey") as String?) ?: System.getenv("SIGNING_KEY")
    val signingPassword = (findProperty("signingPassword") as String?) ?: System.getenv("SIGNING_PASSWORD")
    if (signingKey.isNullOrBlank()) {
        logger.lifecycle("secure-gateway :android-aar: no signing key — publishing UNSIGNED (ok for mavenLocal/dev).")
    } else {
        extensions.configure<SigningExtension> {
            useInMemoryPgpKeys(signingKey, signingPassword)
            sign(extensions.getByType<PublishingExtension>().publications)
        }
    }
}
