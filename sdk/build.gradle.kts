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

    // Publish to the local Maven repo so the mobile-agent client (desktop :shared +
    // :androidApp) can consume com.securegateway:{core,java,android}:<version> via
    // mavenLocal(). Run `./gradlew publishToMavenLocal`.
    apply(plugin = "maven-publish")

    // Only the JVM modules publish their `java` component here. Deliberate exceptions:
    //  - :android (plain-JVM) is NOT published — it exists only so the cross-platform
    //    e2eTest can drive the Kotlin mobile SDK on the JVM. The shippable mobile artifact
    //    is :android-aar.
    //  - :android-aar is a com.android.library (no `java` component); it configures its
    //    own publication from the Android `release` variant, with artifactId "android", in
    //    its own build script — so the com.securegateway:android coordinate is preserved.
    if (name == "core" || name == "java") {
        afterEvaluate {
            extensions.configure<PublishingExtension> {
                publications {
                    create<MavenPublication>("maven") {
                        from(components["java"])
                    }
                }
            }
        }
    }
}

allprojects {
    group = "com.securegateway"
    // 0.2.0: breaking E2EE handshake change (v1 -> v2 ephemeral forward secrecy,
    // SG-01) plus replay protection (SG-02). Bumped so consumers re-resolve from
    // mavenLocal rather than reuse a cached 0.1.0.
    version = "0.2.0"
}
