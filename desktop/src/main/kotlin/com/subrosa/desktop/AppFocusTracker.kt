package com.subrosa.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.awt.Window
import java.awt.event.WindowEvent
import java.awt.event.WindowFocusListener

/** Tracks whether the app's main window currently has OS focus — registered
 *  once in main.kt against the ComposeWindow, read from ChatScreen.kt to
 *  gate when read receipts actually go out.
 *
 *  Without this, ChatScreen sent "read" the instant a message arrived (or
 *  the chat was opened) purely based on which contact's Composable happened
 *  to be mounted — with no signal that anyone was actually looking at the
 *  screen. A message that flashes into an unfocused/background window, or
 *  a chat left open on an unattended machine, got marked read anyway.
 *  Mirrors Telegram Desktop: focus alone isn't enough either (see
 *  ChatScreen's own "dwell timer" using this flag), but it's the
 *  prerequisite signal the dwell timer needs. Found live, 2026-09-18. */
object AppFocusTracker {
    var isFocused by mutableStateOf(false)
        private set

    /** True once [isFocused] has held continuously for READ_DWELL_MS — the
     *  actual signal ChatScreen gates read receipts on. Driven by a
     *  LaunchedEffect(isFocused) in main.kt's Window composable: Compose
     *  cancels/restarts that effect's delay() automatically the instant
     *  isFocused flips, so losing focus mid-countdown never lets a stale
     *  delayed callback mark it true late. Flips back to false the moment
     *  focus is lost — the next focus-in needs a fresh dwell, same as a
     *  fresh install. */
    var isActivelyPresent by mutableStateOf(false)
        private set

    /** Mirror of AppNavigation's own `screen` nav-state string (e.g.
     *  "chat:$contact", "group:$groupId"), kept in sync by a LaunchedEffect
     *  there. Lets DesktopNotificationService (a plain object, not a
     *  composable) know which chat is on screen, to suppress a toast for a
     *  chat the user is already looking at — same "is anyone actually here"
     *  question this object already answers for read receipts. */
    var currentScreen by mutableStateOf("")

    const val READ_DWELL_MS = 30_000L

    fun attach(window: Window) {
        isFocused = window.isFocused
        window.addWindowFocusListener(object : WindowFocusListener {
            override fun windowGainedFocus(e: WindowEvent) { isFocused = true }
            override fun windowLostFocus(e: WindowEvent) { isFocused = false; isActivelyPresent = false }
        })
    }

    fun markActivelyPresent() { isActivelyPresent = true }
}
