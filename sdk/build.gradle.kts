// Root build for the Secure Gateway client SDKs (M4).
// Shared configuration for all JVM modules: JDK 17 toolchain, JUnit 5 tests.
plugins {
    java
}

subprojects {
    repositories {
        mavenCentral()
    }

    // Publish each JVM module to the local Maven repo so the mobile-agent client
    // (desktop :shared + :androidApp) can consume com.securegateway:{core,java,
    // android}:<version> via mavenLocal(). Run `./gradlew publishToMavenLocal`.
    apply(plugin = "maven-publish")
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

allprojects {
    group = "com.securegateway"
    version = "0.1.0"
}
