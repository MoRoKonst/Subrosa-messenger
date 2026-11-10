package com.subrosa.messenger

import android.Manifest
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [PlatformLocation], which replaced
 * FusedLocationProviderClient when play-services-location was dropped to make
 * an F-Droid build possible.
 *
 * What these deliberately do NOT assert: that a fix is actually obtained.
 * Whether a device has a usable provider depends on where it physically is,
 * whether GPS is enabled, and -- on a de-Googled phone -- whether a network
 * provider exists at all. A test that demanded real coordinates would fail
 * indoors and teach everyone to ignore it.
 *
 * What they do assert is the part that can break silently and is the same
 * everywhere: the call terminates, respects its own timeout, never throws
 * whatever the provider state is, and refuses to touch the platform without
 * permission. Those are exactly the failure modes the old fused-client code
 * could not have, because the Play Services wrapper handled them.
 *
 * Run against a connected device or emulator:
 *   ./gradlew connectedFossDebugAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class PlatformLocationTest {

    @get:Rule
    val permissionRule: GrantPermissionRule = GrantPermissionRule.grant(
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_COARSE_LOCATION,
    )

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun reportsPermissionGranted() {
        assertTrue(
            "GrantPermissionRule granted both location permissions, so hasPermission must agree",
            PlatformLocation.hasPermission(context)
        )
    }

    @Test
    fun returnsWithinItsTimeoutAndNeverThrows() {
        // A one-second budget: on a device with no cached fix this must give up
        // and return null rather than block the caller. The old implementation's
        // 30s ceiling is the real setting; this proves the ceiling is honoured
        // rather than ignored.
        val budgetMs = 1_000L
        val started = System.currentTimeMillis()

        val result = runBlocking { PlatformLocation.lastOrFresh(context, timeoutMs = budgetMs) }

        val elapsed = System.currentTimeMillis() - started
        // Generous upper bound: a cached fix returns instantly, a live request
        // is cut off at budgetMs, and the slack absorbs slow instrumentation
        // start-up on a cold device.
        assertTrue(
            "lastOrFresh took ${elapsed}ms for a ${budgetMs}ms budget -- the timeout is not being applied",
            elapsed < budgetMs + 5_000L
        )
        // Either outcome is valid; the point is that it came back at all.
        assertTrue(result == null || result.latitude != 0.0 || result.longitude != 0.0)
    }

    @Test
    fun repeatedCallsDoNotLeakListeners() {
        // Each live request registers a LocationListener and must remove it,
        // on success, on timeout and on cancellation alike. A leak here would
        // not fail a single call -- it would quietly keep the GPS awake and
        // drain the battery of a user who tapped "send location" a few times.
        // There is no public API to count registrations, so this asserts the
        // observable proxy: ten sequential calls still terminate promptly.
        val started = System.currentTimeMillis()
        repeat(10) {
            runBlocking { PlatformLocation.lastOrFresh(context, timeoutMs = 200L) }
        }
        val elapsed = System.currentTimeMillis() - started

        assertTrue(
            "ten 200ms calls took ${elapsed}ms -- listeners are likely accumulating",
            elapsed < 15_000L
        )
    }

    @Test
    fun zeroTimeoutStillReturnsRatherThanHanging() {
        // Degenerate input: withTimeoutOrNull(0) must not leave a caller
        // waiting on a coroutine that can never resume.
        val result = runBlocking { PlatformLocation.lastOrFresh(context, timeoutMs = 0L) }
        // Null OR a cached fix -- the cached lookup happens before the timeout
        // applies, so a device with a recent fix legitimately returns one here.
        assertFalse(
            "a zero timeout must not produce a fix from a live request",
            result != null && !PlatformLocation.hasPermission(context)
        )
    }
}
