import org.jetbrains.compose.desktop.application.dsl.TargetFormat

// jlink (used by Compose Desktop native packaging) fails when the project path
// contains non-ASCII characters because it writes the output path into an args
// file as UTF-8 but reads it back as the system ANSI codepage (Windows-1252),
// producing mojibake. Redirect the build directory to an ASCII path to avoid this.
layout.buildDirectory.set(file("C:/subrosa_desktop_build"))

plugins {
    kotlin("jvm")
    id("org.jetbrains.compose") version "1.7.3"
    id("org.jetbrains.kotlin.plugin.compose")
    kotlin("plugin.serialization")
}

group = "com.subrosa.desktop"
version = "1.0.0"

kotlin {
    jvmToolchain(21)
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

dependencies {
    // Compose Desktop
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)

    // WebSocket (OkHttp — works on JVM without changes from Android)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.9.0")

    // JSON serialization (replaces org.json / manual parsing)
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    // Bouncy Castle — EC key generation & ECDSA (same algorithms as Android, different provider)
    // 1.79+ required for org.bouncycastle.pqc.crypto.mlkem (ML-KEM, used in the hybrid PQ X3DH handshake)
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    // bcpkix — X.509 certificate builder (JcaX509v3CertificateBuilder, JcaContentSignerBuilder)
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")

    // org.json for compatibility with adapted Android code
    implementation("org.json:json:20240303")

    // JNA — native OS APIs (screen capture prevention, memory locking)
    implementation("net.java.dev.jna:jna:5.15.0")
    implementation("net.java.dev.jna:jna-platform:5.15.0")

    // WebRTC — JNI wrapper around native libwebrtc. Java API classes (no classifier)
    // plus the Windows-only native binary classifier for now (dev machine);
    // revisit for cross-platform packaging.
    implementation("dev.onvoid.webrtc:webrtc-java:0.14.0")
    implementation(group = "dev.onvoid.webrtc", name = "webrtc-java", version = "0.14.0", classifier = "windows-x86_64")

    // JAVE2 — Java wrapper around bundled ffmpeg binaries (jave-all-deps
    // includes windows+linux native binaries, no separate ffmpeg install
    // needed). Used only to transcode an incoming Android-recorded voice
    // message (AMR-NB in a 3GPP container, MediaRecorder's format) to WAV
    // for local playback via javax.sound.sampled, which has no AMR decoder
    // of its own — see AudioTranscoder.kt.
    implementation("ws.schild:jave-all-deps:3.5.0")

    // ZXing — QR code generation (own invite code) and now also decoding
    // (add-contact-by-QR-image-file — no camera on most desktops, so a file
    // picker replaces Android's camera scanner). Same core library/version
    // as Android (app/build.gradle.kts). `javase` adds BufferedImageLuminanceSource
    // for decoding a BufferedImage straight from a loaded file.
    implementation("com.google.zxing:core:3.5.4")
    implementation("com.google.zxing:javase:3.5.4")
}

// Headless smoke test for the crypto/network path (IntegrationSmokeTest.kt) —
// no GUI. Needs its own APPDATA per instance (set before invoking Gradle) so
// each run gets an independent identity. Example (PowerShell, two terminals):
//   $env:APPDATA = "C:\temp\beacon_alice"
//   ./gradlew.bat smokeTest -Pargs="alice C:\temp\alice.json C:\temp\bob.json"
tasks.register<JavaExec>("smokeTest") {
    group = "verification"
    description = "Headless two-process smoke test of connect/X3DH-PQ-hybrid/message round-trip."
    mainClass.set("com.subrosa.desktop.IntegrationSmokeTestKt")
    classpath = sourceSets["main"].runtimeClasspath
    if (project.hasProperty("args")) {
        args((project.property("args") as String).split(" "))
    }
}

// Switches the CURRENT console to codepage 65001 (UTF-8) before the app's
// JVM starts, so it agrees with the jvmArgs UTF-8 encoding set above —
// chcp affects the console object itself (inherited from whatever shell
// launched gradlew), not just this one process, so it fixes display for
// the app's actual output too. Windows-only; a no-op elsewhere since chcp
// doesn't exist there and the console already defaults to UTF-8.
if (System.getProperty("os.name").lowercase().contains("win")) {
    // afterEvaluate — the Compose Desktop plugin registers "run" while
    // processing the compose.desktop { application {} } block above, which
    // (depending on plugin internals) may not have happened yet at this
    // point in top-to-bottom script evaluation. tasks.named("run") looked
    // up eagerly here failed with "Task with name 'run' not found" even
    // though the task exists once the whole project finishes configuring.
    afterEvaluate {
        tasks.named<JavaExec>("run") {
            doFirst {
                // Plain ProcessBuilder, not Gradle's exec {} DSL — avoids
                // the Gradle 9.x ExecOperations/configuration-cache API
                // churn entirely; inheritIO() so it shares this task's
                // actual console handle instead of a detached one.
                ProcessBuilder("cmd", "/c", "chcp", "65001")
                    .inheritIO()
                    .start()
                    .waitFor()
            }
        }
    }
}

// Prints the resolved runtime classpath (one entry per line) so the smoke
// test can also be launched directly via `java -cp ...` with a
// per-process APPDATA override, bypassing any Gradle-daemon env caching.
tasks.register("printRuntimeClasspath") {
    doLast {
        println(sourceSets["main"].runtimeClasspath.joinToString(System.lineSeparator()) { it.absolutePath })
    }
}

compose.desktop {
    application {
        mainClass = "com.subrosa.desktop.MainKt"

        // Without this, Cyrillic console output (System.err.println/println
        // calls throughout the codebase — the primary way this client logs
        // during live debugging) gets mis-encoded before it ever reaches the
        // terminal: the JVM's default stdout/stderr charset on Windows
        // follows the console's ACTIVE codepage, not UTF-8, so real UTF-8
        // Cyrillic text written by the app comes out as "я┐╜я┐╜я┐╜..." mojibake
        // regardless of what the console itself is set to. This forces the
        // JVM side of the encoding to UTF-8; the console side still needs
        // `chcp 65001` (see the "run" task's doFirst below) for the two to
        // actually agree. Found live, 2026-09-13 — repeatedly garbled
        // console pastes were wasting real debugging time across an entire
        // session.
        jvmArgs += listOf(
            "-Dfile.encoding=UTF-8",
            "-Dstdout.encoding=UTF-8",
            "-Dstderr.encoding=UTF-8"
        )

        nativeDistributions {
            targetFormats(TargetFormat.Exe, TargetFormat.Msi, TargetFormat.Deb, TargetFormat.Dmg)
            packageName = "Subrosa"

            // jlink не включает эти модули автоматически, но они нужны зависимостям:
            //   java.management  — OkHttp (TaskRunner использует ManagementFactory для мониторинга тредов)
            //   jdk.unsupported  — Kotlin coroutines / JNA (Unsafe, sun.misc)
            //   java.naming      — BouncyCastle / SSL (JNDI-провайдер)
            //   jdk.crypto.ec    — нативные EC-операции (TLS ECDH, ECDSA)
            modules("java.management", "jdk.unsupported", "java.naming", "jdk.crypto.ec")
            packageVersion = "1.0.2"
            description = "Subrosa Messenger — secure desktop client"
            copyright = "© 2025 Subrosa"
            vendor = "Subrosa"

            windows {
                iconFile.set(project.file("icons/icon.ico"))
                menuGroup = "Subrosa"
                upgradeUuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                dirChooser = true          // диалог выбора папки при установке
                perUserInstall = true      // установка без прав администратора
                shortcut = true            // ярлык на рабочем столе
            }
        }
    }
}
