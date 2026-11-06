package com.subrosa.desktop

/**
 * Desktop port of Android's ContactHealthManager ("Забота о собеседнике" —
 * peer health-check for established 1:1 channels). See
 * docs/ISSUE_backup_identity_hijack.md, "взаимный health-check контактов
 * через N времени тишины", and app/src/main/java/com/example/test/
 * ContactHealthManager.kt for the Android original this mirrors field-for-
 * field. sendAnonTokensTo()-style reactive token refresh alone doesn't
 * notice a channel gone quiet *after* it was established — this tracks
 * silence and drives the ping/mailbox-retry cycle WebSocketClient runs on
 * top of it. No UI here by design — the threshold is a recovery mechanism,
 * not a user-facing alarm.
 */
object ContactHealthManager {
    private const val PREFIX = "contact_health_"

    const val SILENCE_THRESHOLD_MS = 15 * 60 * 1000L
    const val MAILBOX_RETRY_WAIT_MS = 5 * 60 * 1000L

    // Purely a UI-facing "recently active" signal, distinct from isSilent()'s
    // 15-minute recovery trigger above — mirrors Android's ContactHealthManager
    // exactly (see its own comment: no real presence protocol exists here by
    // design, anonymous token routing means the server can't tell us who's
    // connected). "We've actually heard from them, or had something delivered
    // to them, in the last few minutes" — not "they are connected right now".
    // Was missing entirely on Desktop; Desktop's ChatScreen.kt currently has
    // no online/typing/offline status UI at all to drive with it (unlike
    // Android's), so this is ported as a data-layer function only — an
    // intentional feature difference, not pretended parity, until/unless
    // such a UI is added. Found in the 2026-09-13 ContactHealthManager audit.
    const val RECENTLY_ACTIVE_MS = 2 * 60 * 1000L

    // Separate from isSilent()'s time-based check above — a plain
    // consecutive-count trigger: 10 of our own messages to a contact in a
    // row with not one "delivered" landing in between. Mirrors Android's
    // ContactHealthManager exactly. Was missing entirely on Desktop — no
    // counter, no isSendBlocked(), and the send button had no gate at all,
    // so a channel that stopped delivering let the user keep silently
    // queuing an unbounded pile of doomed sends. Found in the 2026-09-13
    // ContactHealthManager audit.
    const val UNCONFIRMED_SEND_BLOCK_THRESHOLD = 10

    enum class PingState { NONE, PINGED, MAILBOX_TRIED }

    // Guards unconfirmed_count_<contact>'s read-modify-write
    // (recordOutgoingAttempt()/recordDelivered()) — mirrors Android's fix
    // exactly. WebSocketClient dispatches per-message handling in separate
    // coroutines, so two sends/delivery-acks for the same contact landing
    // close together could otherwise race and lose an increment.
    private val counterLock = Any()

    private fun getLong(key: String): Long = DesktopStorage.get(PREFIX + key)?.toLongOrNull() ?: 0L
    private fun putLong(key: String, value: Long) = DesktopStorage.put(PREFIX + key, value.toString())
    private fun getInt(key: String): Int = DesktopStorage.getInt(PREFIX + key, 0)

    /** Call whenever real traffic (a decrypted message, a session_init, an
     * incoming ping) is received from [contactId] — resets the silence
     * clock and any in-progress ping/retry state. */
    fun recordIncoming(contactId: String) {
        putLong("last_in_$contactId", System.currentTimeMillis())
        DesktopStorage.put(PREFIX + "state_$contactId", PingState.NONE.name)
    }

    /** Call when a `delivered` ack arrives for one of our own outgoing
     * messages to [contactId]. Also resets the consecutive-unconfirmed-send
     * counter used by isSendBlocked() — mirrors Android exactly. */
    fun recordDelivered(contactId: String) = synchronized(counterLock) {
        putLong("last_delivered_$contactId", System.currentTimeMillis())
        DesktopStorage.putInt(PREFIX + "unconfirmed_count_$contactId", 0)
    }

    /** Call whenever we actually attempt to send [contactId] something —
     * distinguishes "never talked to them" from "used to talk, now quiet".
     * Also advances the consecutive-unconfirmed-send counter used by
     * isSendBlocked() — mirrors Android exactly. */
    fun recordOutgoingAttempt(contactId: String) = synchronized(counterLock) {
        val count = getInt("unconfirmed_count_$contactId") + 1
        putLong("last_out_$contactId", System.currentTimeMillis())
        DesktopStorage.putInt(PREFIX + "unconfirmed_count_$contactId", count)
    }

    /** True once UNCONFIRMED_SEND_BLOCK_THRESHOLD of our own messages to
     *  [contactId] have gone out in a row with no `delivered` in between —
     *  mirrors Android's isSendBlocked() exactly. See
     *  ChatScreen.kt's doSend() for the send-button gate this drives. */
    fun isSendBlocked(contactId: String): Boolean =
        getInt("unconfirmed_count_$contactId") >= UNCONFIRMED_SEND_BLOCK_THRESHOLD

    /** See RECENTLY_ACTIVE_MS above — an honest "heard from them (or they
     *  confirmed receipt of something) within the last couple minutes", not
     *  a claim they're connected right now. Mirrors Android exactly. */
    fun isRecentlyActive(contactId: String): Boolean {
        val now = System.currentTimeMillis()
        val lastIn = getLong("last_in_$contactId")
        val lastDelivered = getLong("last_delivered_$contactId")
        val last = maxOf(lastIn, lastDelivered)
        return last != 0L && now - last <= RECENTLY_ACTIVE_MS
    }

    /** True once both directions have gone quiet for SILENCE_THRESHOLD_MS. */
    fun isSilent(contactId: String): Boolean {
        val lastIn = getLong("last_in_$contactId")
        val lastOut = getLong("last_out_$contactId")
        if (lastIn == 0L && lastOut == 0L) return false
        val now = System.currentTimeMillis()
        val lastDelivered = getLong("last_delivered_$contactId")
        val silentIncoming = lastIn == 0L || now - lastIn > SILENCE_THRESHOLD_MS
        val silentDelivered = lastOut == 0L || lastDelivered == 0L || now - lastDelivered > SILENCE_THRESHOLD_MS
        return silentIncoming && silentDelivered
    }

    fun getState(contactId: String): PingState =
        try {
            PingState.valueOf(DesktopStorage.get(PREFIX + "state_$contactId") ?: PingState.NONE.name)
        } catch (e: Exception) {
            PingState.NONE
        }

    fun setState(contactId: String, state: PingState) {
        DesktopStorage.put(PREFIX + "state_$contactId", state.name)
        putLong("state_at_$contactId", System.currentTimeMillis())
    }

    fun stateElapsedMs(contactId: String): Long =
        System.currentTimeMillis() - getLong("state_at_$contactId")

    // "Восстановить связь" — manual user-initiated retry button, cooldown-
    // gated so mashing it can't spam mailbox deposits/session resets.
    // Mirrors Android's ContactHealthManager exactly. Was missing entirely
    // from Desktop (and so was the button itself) — found in the
    // 2026-09-12 full-logic audit.
    const val MANUAL_RESTORE_COOLDOWN_MS = 5 * 60 * 1000L

    fun canManualRestore(contactId: String): Boolean =
        System.currentTimeMillis() - getLong("last_manual_restore_$contactId") >= MANUAL_RESTORE_COOLDOWN_MS

    /** Milliseconds remaining before canManualRestore() is true again — for
     *  showing "подождите ещё N" in the UI instead of just hiding the
     *  button silently. */
    fun manualRestoreRemainingMs(contactId: String): Long =
        (MANUAL_RESTORE_COOLDOWN_MS - (System.currentTimeMillis() - getLong("last_manual_restore_$contactId")))
            .coerceAtLeast(0L)

    fun recordManualRestore(contactId: String) {
        putLong("last_manual_restore_$contactId", System.currentTimeMillis())
    }

    /** Wipes all silence-tracking state for [contactId] — call on contact
     *  deletion. Without this, re-adding the same fingerprint (fresh invite
     *  exchange) inherits old last_in/last_out/last_delivered timestamps and
     *  ping state, so the health-check cycle doesn't behave like a genuinely
     *  new relationship until enough real traffic overwrites them. */
    fun clearContact(contactId: String) {
        DesktopStorage.remove(PREFIX + "last_in_$contactId")
        DesktopStorage.remove(PREFIX + "last_delivered_$contactId")
        DesktopStorage.remove(PREFIX + "last_out_$contactId")
        DesktopStorage.remove(PREFIX + "state_$contactId")
        DesktopStorage.remove(PREFIX + "state_at_$contactId")
        DesktopStorage.remove(PREFIX + "last_manual_restore_$contactId")
        // Was missing — mirrors Android's clearContact() exactly. Without
        // this, a re-added contact under the same fingerprint could inherit
        // a stale unconfirmed-send count left over from before the delete,
        // potentially starting the new relationship already send-blocked
        // (or, conversely, one send away from it) for no reason connected
        // to any actual traffic with the fresh relationship. Found in the
        // 2026-09-13 ContactHealthManager audit.
        DesktopStorage.remove(PREFIX + "unconfirmed_count_$contactId")
    }
}
