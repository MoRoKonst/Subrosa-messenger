package com.bcon.messenger

import android.content.Context

object SessionManager {

    private const val PREFS_NAME = "session_prefs"
    private const val KEY_LAST_ACTIVE = "last_active_time"
    private const val TIMEOUT_MINUTES = 5

    fun updateLastActive(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_LAST_ACTIVE, System.currentTimeMillis())
            .apply()
    }

    fun isSessionExpired(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val lastActive = prefs.getLong(KEY_LAST_ACTIVE, 0)

        if (lastActive == 0L) return false

        val elapsed = System.currentTimeMillis() - lastActive
        val timeoutMillis = TIMEOUT_MINUTES * 60 * 1000

        return elapsed > timeoutMillis
    }

    fun clearSession(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .apply()
    }
}

