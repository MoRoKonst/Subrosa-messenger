package com.subrosa.messenger

import android.content.Context

object LoginAttemptManager {

    private const val PREFS_NAME      = "login_attempts"
    private const val KEY_ATTEMPTS    = "attempts"
    private const val KEY_BLOCK_UNTIL = "block_until"
    private const val KEY_BLOCK_COUNT = "block_count"
    private const val MAX_ATTEMPTS    = 3

    private val BLOCK_DURATIONS_MS = longArrayOf(
        5  * 60 * 1000L,
        15 * 60 * 1000L,
        30 * 60 * 1000L,
        60 * 60 * 1000L,
        Long.MAX_VALUE / 2
    )

    private val lock = Any()

    fun canAttemptLogin(context: Context): Pair<Boolean, Long> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val blockUntil = prefs.getLong(KEY_BLOCK_UNTIL, 0)
        val now = System.currentTimeMillis()
        return if (blockUntil > now) {
            val remainingSeconds = (blockUntil - now) / 1000
            Pair(false, remainingSeconds)
        } else {
            Pair(true, 0)
        }
    }

    fun recordFailedAttempt(context: Context) = synchronized(lock) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val attempts   = prefs.getInt(KEY_ATTEMPTS,    0)
        val blockCount = prefs.getInt(KEY_BLOCK_COUNT, 0)
        val newAttempts = attempts + 1

        if (newAttempts >= MAX_ATTEMPTS) {
            val newBlockCount = blockCount + 1
            val durationMs = BLOCK_DURATIONS_MS.getOrElse(newBlockCount - 1) { BLOCK_DURATIONS_MS.last() }

            prefs.edit()
                .putInt(KEY_ATTEMPTS,    0)
                .putInt(KEY_BLOCK_COUNT, newBlockCount)
                .putLong(KEY_BLOCK_UNTIL, System.currentTimeMillis() + durationMs)
                .commit()
        } else {
            prefs.edit()
                .putInt(KEY_ATTEMPTS, newAttempts)
                .commit()
        }
    }

    fun recordSuccessfulLogin(context: Context) = synchronized(lock) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit()
            .putInt(KEY_ATTEMPTS,    0)
            .putInt(KEY_BLOCK_COUNT, 0)
            .putLong(KEY_BLOCK_UNTIL, 0)
            .commit()
    }

    fun getRemainingAttempts(context: Context): Int {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val attempts = prefs.getInt(KEY_ATTEMPTS, 0)
        return MAX_ATTEMPTS - attempts
    }

    fun isPermanentlyLocked(context: Context): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val blockUntil = prefs.getLong(KEY_BLOCK_UNTIL, 0)
        return blockUntil > System.currentTimeMillis() + 365L * 24 * 3600 * 1000
    }
}
