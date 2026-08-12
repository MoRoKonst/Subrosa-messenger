package com.subrosa.messenger

import android.content.Context

/**
 * "Забота о собеседнике" — peer health-check for established 1:1 channels.
 * See docs/ISSUE_backup_identity_hijack.md, "взаимный health-check контактов
 * через N времени тишины". sendAnonTokensTo() is purely reactive (only fires
 * right after a real send/receive) — this tracks silence and drives the
 * proactive ping/mailbox-retry cycle MessengerService runs on top of it.
 *
 * Not tracked here at all: UI. By design this stays entirely internal —
 * the 15-minute threshold is a recovery mechanism, not a user-facing alarm.
 */
object ContactHealthManager {
    private const val PREFS_NAME = "contact_health"
    private fun prefs(ctx: Context) = EncryptedStorage.getEncryptedPrefs(ctx, PREFS_NAME)

    const val SILENCE_THRESHOLD_MS = 15 * 60 * 1000L
    const val MAILBOX_RETRY_WAIT_MS = 5 * 60 * 1000L

    enum class PingState { NONE, PINGED, MAILBOX_TRIED }

    /** Call whenever real traffic (a decrypted message, a session_init, an
     * incoming ping) is received from [contactId] — resets the silence
     * clock and any in-progress ping/retry state. */
    fun recordIncoming(ctx: Context, contactId: String) {
        prefs(ctx).edit()
            .putLong("last_in_$contactId", System.currentTimeMillis())
            .putString("state_$contactId", PingState.NONE.name)
            .apply()
    }

    /** Call when a `delivered` ack arrives for one of our own outgoing
     * messages to [contactId]. */
    fun recordDelivered(ctx: Context, contactId: String) {
        prefs(ctx).edit().putLong("last_delivered_$contactId", System.currentTimeMillis()).apply()
    }

    /** Call whenever we actually attempt to send [contactId] something —
     * distinguishes "never talked to them" (not silence, just never
     * started) from "used to talk, now quiet". */
    fun recordOutgoingAttempt(ctx: Context, contactId: String) {
        prefs(ctx).edit().putLong("last_out_$contactId", System.currentTimeMillis()).apply()
    }

    private fun getLong(ctx: Context, key: String): Long = prefs(ctx).getLong(key, 0L)

    /** True once both directions have gone quiet for SILENCE_THRESHOLD_MS —
     * the spec's trigger condition ("входящие сообщения прекратились И
     * перестали приходить delivered-подтверждения"), not just one or the
     * other (a contact who reads but doesn't reply yet isn't "silent"). */
    fun isSilent(ctx: Context, contactId: String): Boolean {
        val lastIn = getLong(ctx, "last_in_$contactId")
        val lastOut = getLong(ctx, "last_out_$contactId")
        // Never actually talked to this contact at all — nothing to recover.
        if (lastIn == 0L && lastOut == 0L) return false
        val now = System.currentTimeMillis()
        val lastDelivered = getLong(ctx, "last_delivered_$contactId")
        val silentIncoming = lastIn == 0L || now - lastIn > SILENCE_THRESHOLD_MS
        val silentDelivered = lastOut == 0L || lastDelivered == 0L || now - lastDelivered > SILENCE_THRESHOLD_MS
        return silentIncoming && silentDelivered
    }

    fun getState(ctx: Context, contactId: String): PingState =
        try {
            PingState.valueOf(prefs(ctx).getString("state_$contactId", PingState.NONE.name) ?: PingState.NONE.name)
        } catch (e: Exception) {
            PingState.NONE
        }

    fun setState(ctx: Context, contactId: String, state: PingState) {
        prefs(ctx).edit()
            .putString("state_$contactId", state.name)
            .putLong("state_at_$contactId", System.currentTimeMillis())
            .apply()
    }

    fun stateElapsedMs(ctx: Context, contactId: String): Long =
        System.currentTimeMillis() - getLong(ctx, "state_at_$contactId")

    /** Wipes all silence-tracking state for [contactId] — call on contact
     * deletion. Without this, re-adding the same fingerprint (fresh invite
     * exchange) inherits old last_in/last_out/last_delivered timestamps and
     * ping state, so the health-check cycle doesn't behave like a genuinely
     * new relationship until enough real traffic overwrites them. */
    fun clearContact(ctx: Context, contactId: String) {
        prefs(ctx).edit()
            .remove("last_in_$contactId")
            .remove("last_delivered_$contactId")
            .remove("last_out_$contactId")
            .remove("state_$contactId")
            .remove("state_at_$contactId")
            .apply()
    }
}
