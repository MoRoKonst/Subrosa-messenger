pluginManagement {
    repositories {
        gradlePluginPortal()
        maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
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

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
    }
}

rootProject.name = "beacon-desktop"
