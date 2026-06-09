plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

// The REAL Android library: the same mobile SDK Kotlin sources as :android, but built as a
// com.android.library on lazysodium-android (native arm64 libsodium) so the relay crypto
// actually runs on a Pixel 7. The plain-JVM :android stays for the hermetic e2eTest; this
// module is what ships and what publishes the com.securegateway:android coordinate.
android {
    namespace = "com.securegateway.mobile"
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

// Preserve the com.securegateway:android coordinate (mobile-agent consumes it unchanged):
// publish the Android `release` variant under artifactId "android", not the module name.
afterEvaluate {
    extensions.configure<PublishingExtension> {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "android"
            }
        }
    }
}
