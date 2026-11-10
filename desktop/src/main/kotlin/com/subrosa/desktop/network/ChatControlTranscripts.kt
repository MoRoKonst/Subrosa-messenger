// Package is com.subrosa.desktop, not com.subrosa.desktop.network, despite the
// directory — matching WebSocketClient.kt, which this file was extracted from.
package com.subrosa.desktop

/**
 * Signature transcripts for the three chat-control types
 * (`message_delete`, `group_message_delete`, `disappear_timer`).
 *
 * These strings are a WIRE CONTRACT shared with the Android client
 * (`MessengerService.kt`) and partially validated by the server
 * (`server.py`'s `sanitize_chat_control`). Changing one without changing the
 * other silently breaks delete-for-everyone across platforms — and, worse, a
 * mismatch degrades into "signature invalid", which the receive handlers treat
 * as a hostile frame. That failure mode is indistinguishable from an attack in
 * the logs, so it is easy to misdiagnose.
 *
 * They were inlined at six separate call sites (three send, three receive)
 * before being collected here. They are centralised for ONE reason: so
 * ChatControlTranscriptsTest can assert their exact literal values against the
 * contract Android implements. A constant alone cannot stop cross-platform
 * divergence — only a test pinning the literal can.
 *
 * Domain separation (S6-54, external review 2026-09-06): each type carries its
 * own `SUBROSA_*_V1:` prefix so a signature produced for one operation can
 * never verify for another. `group_member_removed` signs `"$groupId:$removed"`,
 * which has the same two-colon-joined shape as a group delete's transcript, so
 * an unprefixed scheme would risk exactly that collision.
 */
internal object ChatControlTranscripts {

    /** Transcript for `message_delete`. Binds the message id only — a direct
     *  1:1 conversation has just two possible authors, so authorization is
     *  settled by the local copy's own `isOwn` flag, not by the transcript. */
    fun messageDelete(messageId: String): String =
        "SUBROSA_MESSAGE_DELETE_V1:$messageId"

    /** Transcript for `group_message_delete`. Binds BOTH ids so a signature
     *  valid for a deletion in one group cannot be replayed against another
     *  group that happens to reference the same message id. */
    fun groupMessageDelete(groupId: String, messageId: String): String =
        "SUBROSA_GROUP_MESSAGE_DELETE_V1:$groupId:$messageId"

    /**
     * Transcript for `disappear_timer`.
     *
     * UNVERSIONED, deliberately: Android signs the bare `seconds.toString()`
     * and this must match it byte for byte. It is the one chat-control
     * transcript S6-54 did not domain-separate.
     *
     * Residual risk, accepted rather than silently ignored: the signed value
     * space is only {"0", "3600", "86400", "604800"}, so a signature over one
     * of those four strings is replayable as any other operation whose
     * transcript could equal a bare decimal. No current transcript can — every
     * other signed value is either prefixed, base64 ciphertext, or
     * colon-joined ids — so this is not reachable today. Fixing it properly
     * means a compatibility window (accept both the bare and the prefixed form
     * on receive, emit the prefixed form only once both shipped clients
     * verify it), which is a protocol change, not a cleanup.
     */
    fun disappearTimer(seconds: Long): String = seconds.toString()
}
