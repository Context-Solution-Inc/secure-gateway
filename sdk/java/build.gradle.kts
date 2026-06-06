plugins {
    `java-library`
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
    withSourcesJar()
}

// A dedicated source set for the cross-platform E2E test: it boots the real Go
// relay + auth binaries and drives the Kotlin (mobile) and Java (desktop) SDKs
// against them. Kept out of the normal `test` task so unit builds stay fast and
// hermetic; run with `./gradlew :java:e2eTest`.
val e2eTest: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations[e2eTest.implementationConfigurationName].extendsFrom(configurations.testImplementation.get())
configurations[e2eTest.runtimeOnlyConfigurationName].extendsFrom(configurations.testRuntimeOnly.get())

dependencies {
    api(project(":core"))

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)

    // The E2E source set drives both SDKs through the relay.
    "e2eTestImplementation"(project(":core"))
    "e2eTestImplementation"(project(":android"))
}

tasks.test { useJUnitPlatform() }

tasks.register<Test>("e2eTest") {
    description = "Cross-platform E2E: boots cmd/relay + cmd/auth and runs Kotlin<->Java through the live relay."
    group = "verification"
    testClassesDirs = e2eTest.output.classesDirs
    classpath = e2eTest.runtimeClasspath
    useJUnitPlatform()
    // Located by GoBackend at runtime; overridable.
    systemProperty("sdk.repoRoot", rootDir.parentFile.absolutePath)
}
