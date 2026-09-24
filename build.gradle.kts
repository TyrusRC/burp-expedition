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

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveClassifier.set("")
    relocate("io.netty", "expedition.shaded.netty")
    relocate("org.bouncycastle", "expedition.shaded.bouncycastle")
}
