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

// Resolves the jvmToolchain(21) that build.gradle.kts asks for on any machine --
// locating an already-installed JDK 21 or provisioning one. The root build has
// used this all along; without it here, JDK selection fell back to a hardcoded
// absolute path in desktop/gradle.properties (see that file's own comment for
// how that failed).
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
    }
}

rootProject.name = "subrosa-desktop"
