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

    // Purely a UI-facing "recently active" signal, distinct from isSilent()'s
    // 15-minute recovery trigger below. There is no real presence protocol
    // here by design — anonymous token routing means the server can't tell
    // us who's connected (that would leak who's talking to whom). This is
    // the best honest approximation: "we've actually heard from them, or had
    // something delivered to them, in the last few minutes" — not "they are
    // connected right now", which this app has no way to know.
    const val RECENTLY_ACTIVE_MS = 2 * 60 * 1000L

    // Separate from isSilent()'s time-based check above — this is a plain
    // consecutive-count trigger: 10 of our own messages to a contact in a row
    // with not one "delivered" landing in between. isSilent() needs 15
    // minutes of quiet in BOTH directions to fire, which is the right
    // threshold for the background health-check/reconnect cycle, but too
    // slow for "stop letting the user shout into the void" — a burst of 10
    // unconfirmed sends can happen in well under 15 minutes.
    const val UNCONFIRMED_SEND_BLOCK_THRESHOLD = 10

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
        prefs(ctx).edit()
            .putLong("last_delivered_$contactId", System.currentTimeMillis())
            .putInt("unconfirmed_count_$contactId", 0)
            .apply()
    }

    /** Call whenever we actually attempt to send [contactId] something —
     * distinguishes "never talked to them" (not silence, just never
     * started) from "used to talk, now quiet". Also advances the
     * consecutive-unconfirmed-send counter used by isSendBlocked(). */
    fun recordOutgoingAttempt(ctx: Context, contactId: String) {
        val count = getInt(ctx, "unconfirmed_count_$contactId") + 1
        prefs(ctx).edit()
            .putLong("last_out_$contactId", System.currentTimeMillis())
            .putInt("unconfirmed_count_$contactId", count)
            .apply()
    }

    /** True once UNCONFIRMED_SEND_BLOCK_THRESHOLD of our own messages to
     * [contactId] have gone out in a row with no `delivered` in between —
     * the UI uses this to stop the user from sending further into a channel
     * that clearly isn't getting through, rather than silently queuing an
     * unbounded pile of doomed sends. Cleared the moment one delivered ack
     * lands (recordDelivered), regardless of which message it was for. */
    fun isSendBlocked(ctx: Context, contactId: String): Boolean =
        getInt(ctx, "unconfirmed_count_$contactId") >= UNCONFIRMED_SEND_BLOCK_THRESHOLD

    private fun getLong(ctx: Context, key: String): Long = prefs(ctx).getLong(key, 0L)
    private fun getInt(ctx: Context, key: String): Int = prefs(ctx).getInt(key, 0)

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

    /** See RECENTLY_ACTIVE_MS above — an honest "heard from them (or they
     * confirmed receipt of something) within the last couple minutes", not
     * a claim they're connected right now. */
    fun isRecentlyActive(ctx: Context, contactId: String): Boolean {
        val now = System.currentTimeMillis()
        val lastIn = getLong(ctx, "last_in_$contactId")
        val lastDelivered = getLong(ctx, "last_delivered_$contactId")
        val last = maxOf(lastIn, lastDelivered)
        return last != 0L && now - last <= RECENTLY_ACTIVE_MS
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
            .remove("unconfirmed_count_$contactId")
            .apply()
    }
}
