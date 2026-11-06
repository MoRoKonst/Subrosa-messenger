package com.subrosa.messenger

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The one place a typed password is turned into a decision.
 *
 * It exists because there were three copies of that decision — LoginScreen's
 * button and the app-lock screen's `onDone` and `onClick` handlers — and they
 * had already drifted apart in ways that mattered:
 *
 *  - **The lockout was never armed.** `LoginAttemptManager.recordFailedAttempt()`
 *    and `recordSuccessfulLogin()` were not called from anywhere in the app.
 *    The counter stayed at 0 and `block_until` at 0 forever, so
 *    `canAttemptLogin()` always answered "yes" and the documented
 *    3-attempts-then-5/15/30/60-minutes escalation never engaged. Login was
 *    effectively unlimited-attempt.
 *  - **The app-lock screen had no gate at all**, not even the inert call. It is
 *    a second password prompt reachable without restarting the app, so even a
 *    working gate on LoginScreen alone would have been trivially bypassed.
 *  - **Ordering.** LoginScreen checked the lockout *before* the panic password.
 *    Arming the counter without fixing that would have introduced a worse bug
 *    than the one it fixed: a locked-out user could no longer trigger the
 *    duress wipe. Under coercion the wipe must always be reachable, so the
 *    panic password is checked first and is never rate-limited. A wrong guess
 *    at it leaks nothing (it falls through to the normal path), and a correct
 *    guess by an attacker destroys the data — which is the owner's desired
 *    outcome, not a risk.
 *  - **Thread.** Both checks are PBKDF2 at 100 000 iterations
 *    (`UserStorage.hashPasswordV2`), and both ran on the main thread via
 *    `rememberCoroutineScope()`. Everything here is on `Dispatchers.IO`.
 *
 * Centralising it means the ordering invariant is a property of this file
 * rather than of three call sites staying in agreement.
 */
object PasswordGate {

    sealed class Outcome {
        /** Panic password matched. Caller must trigger the duress path and must
         *  not distinguish this from a normal login in anything the user can
         *  see. */
        object Panic : Outcome()

        /** Real password matched; the attempt counter has been reset. */
        object Correct : Outcome()

        /** Neither matched; the failure has been recorded. */
        object Wrong : Outcome()

        /** Too many failures. [remainingSeconds] is what the caller shows. */
        data class LockedOut(val remainingSeconds: Long) : Outcome()
    }

    // Test seams, same pattern and the same reason as GroupManager.prefsProvider:
    // everything below reaches EncryptedSharedPreferences, which needs a working
    // AndroidKeyStore that Robolectric does not provide. Production always uses
    // the real implementations.
    internal var panicMatcher: (Context, String) -> Boolean =
        { context, password -> UserStorage.isPanicPassword(context, password) }
    internal var passwordMatcher: (Context, String) -> Boolean =
        { context, password -> UserStorage.checkPassword(context, password) }
    internal var lockoutCheck: (Context) -> Pair<Boolean, Long> =
        { context -> LoginAttemptManager.canAttemptLogin(context) }
    internal var onFailure: (Context) -> Unit =
        { context -> LoginAttemptManager.recordFailedAttempt(context) }
    internal var onSuccess: (Context) -> Unit =
        { context -> LoginAttemptManager.recordSuccessfulLogin(context) }

    internal fun resetSeamsForTest() {
        panicMatcher = { context, password -> UserStorage.isPanicPassword(context, password) }
        passwordMatcher = { context, password -> UserStorage.checkPassword(context, password) }
        lockoutCheck = { context -> LoginAttemptManager.canAttemptLogin(context) }
        onFailure = { context -> LoginAttemptManager.recordFailedAttempt(context) }
        onSuccess = { context -> LoginAttemptManager.recordSuccessfulLogin(context) }
    }

    suspend fun evaluate(context: Context, password: String): Outcome =
        withContext(Dispatchers.IO) { evaluateBlocking(context, password) }

    /** The decision itself, synchronous so it is directly testable. Call
     *  [evaluate] from UI code — this does PBKDF2 twice and blocking prefs IO. */
    internal fun evaluateBlocking(context: Context, password: String): Outcome {
        // 1. Duress first, and deliberately outside the rate limit.
        if (panicMatcher(context, password)) return Outcome.Panic

        // 2. Rate limit applies only to attempts at the real password.
        val (canAttempt, remainingSeconds) = lockoutCheck(context)
        if (!canAttempt) return Outcome.LockedOut(remainingSeconds)

        // 3. The real password.
        return if (passwordMatcher(context, password)) {
            onSuccess(context)
            Outcome.Correct
        } else {
            onFailure(context)
            Outcome.Wrong
        }
    }
}
