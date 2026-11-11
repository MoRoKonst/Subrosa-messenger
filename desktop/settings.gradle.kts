pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    plugins {
        kotlin("jvm")                            version "2.0.21"
        id("org.jetbrains.compose")              version "1.7.3"
        id("org.jetbrains.kotlin.plugin.compose") version "2.0.21"
        kotlin("plugin.serialization")           version "2.0.21"
    }
}

// No foojay-resolver here, deliberately. It would let Gradle DOWNLOAD a JDK
// from an external service when none is installed, and F-Droid's scanner
// rejects that outright ("Found usual suspect 'org.gradle.toolchains.foojay-
// resolver'") because a toolchain fetched at build time cannot be verified
// against source. JDK 21 is instead located among already-installed ones, via
// gradle/gradle-daemon-jvm.properties; a machine without one gets a clear
// error rather than a silent download.
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        // maven.pkg.jetbrains.space/public/p/compose/dev removed 2026-11-11:
        // it is a development channel, not on F-Droid's list of known
        // repositories, and the scanner flags it. Compose Multiplatform 1.7.3
        // is a released version and resolves from mavenCentral.
    }
}

rootProject.name = "subrosa-desktop"
