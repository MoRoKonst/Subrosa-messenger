package com.subrosa.desktop

import androidx.compose.runtime.*
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import androidx.compose.ui.unit.dp
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets

fun main() = application {
    // build.gradle.kts's -Dstdout.encoding=UTF-8 + chcp-65001 doFirst only
    // fire for the Gradle "run" task — an IntelliJ run configuration for
    // MainKt (or a jpackage-built .exe) launches the JVM directly and skips
    // both, so Cyrillic println() output still came out as mojibake no
    // matter what the console's codepage was set to. Forcing System.out/err
    // to real UTF-8 PrintStreams here applies unconditionally, regardless of
    // launch method. Found live, 2026-09-18 — still garbled after the
    // Gradle-side fix from 2026-09-13 because launches were going through
    // IntelliJ, not `gradlew run`.
    System.setOut(PrintStream(FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8))
    System.setErr(PrintStream(FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8))

    NativeProtection.restrictDllSearchToSystem32()
    NativeProtection.disableCrashDumps()
    // Initialise platform layer before any UI
    DesktopStorage.init()
    enforceOnStartup()          // exit immediately if debugger detected (when enabled)
    DesktopCryptoManager.init()
    CryptoManager.init()
    SessionKeyManager.init()
    DesktopNotificationService.init()

    val windowState = rememberWindowState(width = 960.dp, height = 700.dp)

    Window(
        onCloseRequest = {
            WebSocketClient.disconnect()
            exitApplication()
        },
        title = "Subrosa Messenger",
        state = windowState
    ) {
        // 'window' is ComposeWindow (extends java.awt.Window) provided by FrameWindowScope.
        // Prevent this window from appearing in screen captures / recordings.
        DisposableEffect(window) {
            NativeProtection.enableScreenCaptureProtection(window)
            AppFocusTracker.attach(window)
            onDispose {}
        }

        // Read-receipt dwell timer (Telegram-Desktop-style) — keyed on
        // isFocused so Compose cancels the delay() the instant focus is
        // lost, restarting fresh on the next focus-in. Deliberately global
        // (not per-ChatScreen): the dwell is about "is anyone actually at
        // this machine", not about which contact happens to be open, so
        // switching chats while already past the dwell shouldn't force a
        // second 30s wait. See AppFocusTracker's own comment and
        // ChatScreen.kt's read-receipt handlers for how this gets used.
        LaunchedEffect(AppFocusTracker.isFocused) {
            if (AppFocusTracker.isFocused) {
                kotlinx.coroutines.delay(AppFocusTracker.READ_DWELL_MS)
                AppFocusTracker.markActivelyPresent()
            }
        }

        CompositionLocalProvider(LocalStrings provides AppLanguage.strings) {
            AppNavigation()
        }
    }
}
