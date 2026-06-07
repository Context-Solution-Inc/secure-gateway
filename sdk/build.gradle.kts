// Root build for the Secure Gateway client SDKs (M4).
// Shared configuration for all JVM modules: JDK 17 toolchain, JUnit 5 tests.
plugins {
    java
}

subprojects {
    repositories {
        mavenCentral()
    }
}

allprojects {
    group = "com.securegateway"
    version = "0.1.0"
}
