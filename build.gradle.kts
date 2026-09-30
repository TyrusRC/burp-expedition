plugins {
    kotlin("jvm") version "2.0.21"
    id("com.gradleup.shadow") version "9.6.1"
}

group = "expedition"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    implementation("io.netty:netty-all:4.1.138.Final")
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.85")

    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.7")
    testImplementation(platform("org.junit:junit-bom:5.11.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// Target JVM 17 bytecode (Burp's minimum) but compile with whatever JDK runs Gradle
// (Gradle 9 already requires 17+, so JDK 21 works). Deliberately NOT `jvmToolchain(17)`:
// that pins the build to a JDK 17 *installation* and fails on machines that only have
// JDK 21 unless they download one. `-Xjdk-release=17` limits the compile to the JDK 17
// API so we cannot accidentally depend on a newer method that would break in Burp.
kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
        freeCompilerArgs.add("-Xjdk-release=17")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveClassifier.set("")
    relocate("io.netty", "expedition.shaded.netty")
    relocate("org.bouncycastle", "expedition.shaded.bouncycastle")
}
