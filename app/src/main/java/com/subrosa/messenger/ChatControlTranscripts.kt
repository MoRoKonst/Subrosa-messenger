package com.subrosa.messenger

/**
 * Signature transcripts for the three chat-control types
 * (`message_delete`, `group_message_delete`, `disappear_timer`).
 *
 * The Android half of a WIRE CONTRACT shared with the desktop client
 * (`desktop/.../ChatControlTranscripts.kt`, deliberately the same object name
 * and the same function names) and partially validated by the server
 * (`server.py`'s `sanitize_chat_control`). Changing one side without the other
 * breaks delete-for-everyone across platforms, and does so in a misleading
 * way: a transcript mismatch surfaces as "invalid or missing signature", which
 * both receive handlers treat as a hostile frame. In the logs that is
 * indistinguishable from an attack.
 *
 * Extracted from six inlined call sites in MessengerService.kt (three send,
 * three receive) for ONE reason: so ChatControlTranscriptsTest can assert the
 * exact literals against the contract desktop implements. A shared constant
 * cannot prevent cross-platform divergence on its own — the two clients are
 * separate Gradle builds with no common module — only a test pinning the
 * literal on each side can.
 *
 * Domain separation (S6-54, external review 2026-09-06): each type carries its
 * own `SUBROSA_*_V1:` prefix so a signature produced for one operation can
 * never verify for another. `group_member_removed` signs `"$groupId:$removed"`,
 * the same two-colon-joined shape as a group delete's transcript, so an
 * unprefixed scheme would risk exactly that collision.
 */
object ChatControlTranscripts {

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
     * UNVERSIONED, deliberately: the shipped desktop client signs the bare
     * `seconds.toString()` and this must match it byte for byte. It is the one
     * chat-control transcript S6-54 did not domain-separate.
     *
     * Residual risk, accepted rather than silently ignored: the signed value
     * space is only {"0", "3600", "86400", "604800"}, so a signature over one
     * of those four strings is replayable as any other operation whose
     * transcript could equal a bare decimal. No current transcript can — every
     * other signed value is either prefixed, base64 ciphertext, or
     * colon-joined ids — so this is not reachable today. Fixing it properly
     * needs a compatibility window (accept both the bare and the prefixed form
     * on receive, emit the prefixed form only once both shipped clients verify
     * it), which is a protocol change, not a cleanup.
     */
    fun disappearTimer(seconds: Long): String = seconds.toString()
}
