pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
// foojay-resolver removed 2026-11-11. It lets Gradle DOWNLOAD a JDK from an
// external service when none is installed, which F-Droid's scanner rejects
// ("Found usual suspect 'org.gradle.toolchains.foojay-resolver'") since a
// toolchain fetched at build time cannot be verified against source. Nothing
// here asked for it anyway: the :app module declares no jvmToolchain, so the
// JDK running Gradle is the one used.
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // jitpack.io removed in the same pass: no dependency in this build
        // resolved from it (checked across build.gradle.kts and
        // libs.versions.toml -- not one com.github.* coordinate). An unused
        // repository is pure supply-chain surface, and it is the kind of thing
        // a reviewer asks about.
    }
}

rootProject.name = "subrosa"
include(":app")
 