rootProject.name = "secure-gateway-sdk"

// google() is required for the Android Gradle Plugin (:android-aar) — it isn't on
// Maven Central or the Plugin Portal.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

// :android is the plain-JVM mobile SDK (kept so the hermetic cross-platform e2eTest runs
// on the JVM); :android-aar is the real Android library (lazysodium-android) that ships to
// devices and publishes the com.contextsolutions.securegateway:android coordinate.
include(":core", ":java", ":android", ":android-aar")
