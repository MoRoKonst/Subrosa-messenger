package com.subrosa.messenger

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The ordering invariant in PasswordGate is the whole point of that file, and
 * it is the kind of thing that reads as obviously fine and is obviously wrong
 * the other way round. Specifically:
 *
 *  - the panic password must be checked BEFORE the rate limit, so a locked-out
 *    user under coercion can still destroy their data. Getting this backwards
 *    is what the previous LoginScreen code did, and arming the attempt counter
 *    without fixing it would have been a regression, not a fix.
 *  - a failed attempt must actually be recorded. Nothing called
 *    `recordFailedAttempt` anywhere in the app, so the documented
 *    3-strikes-then-escalating-block never engaged at all.
 *
 * Seams rather than real storage: everything underneath reaches
 * EncryptedSharedPreferences, which needs an AndroidKeyStore Robolectric does
 * not simulate (same constraint as GroupManagerTest).
 */
@Config(sdk = [34])
@RunWith(RobolectricTestRunner::class)
class PasswordGateTest {

    private lateinit var context: Context

    private var failuresRecorded = 0
    private var successesRecorded = 0
    private var panicChecked = false
    private var realChecked = false
    private var lockoutChecked = false

    private val realPassword = "correct-horse-battery"
    private val panicPassword = "burn-it-all-down"

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        failuresRecorded = 0
        successesRecorded = 0
        panicChecked = false
        realChecked = false
        lockoutChecked = false

        PasswordGate.panicMatcher = { _, p -> panicChecked = true; p == panicPassword }
        PasswordGate.passwordMatcher = { _, p -> realChecked = true; p == realPassword }
        PasswordGate.lockoutCheck = { lockoutChecked = true; Pair(true, 0L) }
        PasswordGate.onFailure = { failuresRecorded++ }
        PasswordGate.onSuccess = { successesRecorded++ }
    }

    @After
    fun tearDown() {
        PasswordGate.resetSeamsForTest()
    }

    private fun lockedOutFor(seconds: Long) {
        PasswordGate.lockoutCheck = { lockoutChecked = true; Pair(false, seconds) }
    }

    @Test
    fun `correct password is accepted and resets the counter`() {
        val outcome = PasswordGate.evaluateBlocking(context, realPassword)

        assertEquals(PasswordGate.Outcome.Correct, outcome)
        assertEquals("a successful login must reset the attempt counter", 1, successesRecorded)
        assertEquals(0, failuresRecorded)
    }

    @Test
    fun `wrong password is rejected and the failure is recorded`() {
        // The bug this guards: recordFailedAttempt() was never called from
        // anywhere, so the counter sat at 0 forever and the lockout was inert.
        val outcome = PasswordGate.evaluateBlocking(context, "not-it")

        assertEquals(PasswordGate.Outcome.Wrong, outcome)
        assertEquals("a wrong password must count against the limit", 1, failuresRecorded)
        assertEquals(0, successesRecorded)
    }

    @Test
    fun `panic password is recognised`() {
        val outcome = PasswordGate.evaluateBlocking(context, panicPassword)

        assertEquals(PasswordGate.Outcome.Panic, outcome)
    }

    @Test
    fun `panic password works while locked out`() {
        // The invariant. Under coercion the duress wipe has to stay reachable
        // no matter how many failed attempts preceded it.
        lockedOutFor(900)

        val outcome = PasswordGate.evaluateBlocking(context, panicPassword)

        assertEquals(
            "a locked-out user must still be able to trigger the duress wipe",
            PasswordGate.Outcome.Panic,
            outcome
        )
    }

    @Test
    fun `panic password is checked before the lockout is consulted`() {
        lockedOutFor(900)

        PasswordGate.evaluateBlocking(context, panicPassword)

        assertTrue("panic must be evaluated first", panicChecked)
        assertFalse(
            "the rate limiter must not even be consulted once panic matched",
            lockoutChecked
        )
    }

    @Test
    fun `lockout blocks the real password and reports the remaining time`() {
        lockedOutFor(754)

        val outcome = PasswordGate.evaluateBlocking(context, realPassword)

        assertEquals(PasswordGate.Outcome.LockedOut(754), outcome)
        assertFalse("the real password must not be checked while locked out", realChecked)
    }

    @Test
    fun `a blocked attempt does not count as another failure`() {
        // Otherwise every attempt made during a block extends the block, and a
        // user who keeps trying can never get back in.
        lockedOutFor(300)

        PasswordGate.evaluateBlocking(context, "whatever")

        assertEquals(0, failuresRecorded)
    }

    @Test
    fun `a blank password is a normal wrong answer, not a crash`() {
        val outcome = PasswordGate.evaluateBlocking(context, "")

        assertEquals(PasswordGate.Outcome.Wrong, outcome)
        assertEquals(1, failuresRecorded)
    }

    @Test
    fun `a panic password identical to the login password resolves to panic`() {
        // Documents why ProfileScreen now refuses to set them equal: the gate
        // cannot do anything else here, so the collision has to be prevented at
        // the point of configuration rather than resolved at login.
        PasswordGate.panicMatcher = { _, p -> p == realPassword }

        val outcome = PasswordGate.evaluateBlocking(context, realPassword)

        assertEquals(PasswordGate.Outcome.Panic, outcome)
        assertEquals("the real-password path must not have run", 0, successesRecorded)
    }
}
