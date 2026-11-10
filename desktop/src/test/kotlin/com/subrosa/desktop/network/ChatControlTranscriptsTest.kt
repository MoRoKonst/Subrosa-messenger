// Package matches the production file under test (see its own note on why the
// directory and package differ in this module).
package com.subrosa.desktop

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the chat-control signature transcripts against the cross-platform wire
 * contract, and proves the domain separation S6-54 relies on actually holds.
 *
 * Why the literals are duplicated here instead of imported: importing
 * [ChatControlTranscripts] for the expected value would make this test
 * tautological — it would pass for any string the production code happens to
 * produce, including one Android no longer agrees with. The literals below are
 * transcribed from Android's `MessengerService.kt` (`sendDeleteMessage`,
 * `sendGroupDeleteMessage`, `sendDisappearTimer` and their matching receive
 * handlers). If this test fails, the two clients have diverged and
 * delete-for-everyone is broken across platforms — do NOT "fix" it by copying
 * the new desktop value in.
 *
 * Signing here goes through raw JCA rather than [CryptoManager.sign], which
 * needs an initialised on-disk identity. Verification DOES go through the real
 * [CryptoManager.verify], so the production verify path is the one under test.
 */
class ChatControlTranscriptsTest {

    private val keyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private val publicKeyB64: String =
        Base64.getEncoder().encodeToString(keyPair.public.encoded)

    private fun sign(transcript: String): String =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(transcript.toByteArray())
            Base64.getEncoder().encodeToString(sign())
        }

    // ── Wire contract ──────────────────────────────────────────────────────

    @Test
    fun `message_delete transcript matches the Android contract`() {
        assertEquals(
            "SUBROSA_MESSAGE_DELETE_V1:abc-123",
            ChatControlTranscripts.messageDelete("abc-123")
        )
    }

    @Test
    fun `group_message_delete transcript matches the Android contract`() {
        assertEquals(
            "SUBROSA_GROUP_MESSAGE_DELETE_V1:group-7:msg-9",
            ChatControlTranscripts.groupMessageDelete("group-7", "msg-9")
        )
    }

    @Test
    fun `disappear_timer transcript is the bare seconds value`() {
        // Deliberately unversioned -- Android signs seconds.toString(). See
        // ChatControlTranscripts.disappearTimer's own comment for the accepted
        // residual risk and why fixing it needs a compatibility window.
        assertEquals("3600", ChatControlTranscripts.disappearTimer(3600L))
        assertEquals("0", ChatControlTranscripts.disappearTimer(0L))
    }

    // ── Domain separation (the property S6-54 added) ───────────────────────

    @Test
    fun `a direct delete signature does not verify as a group delete`() {
        // The collision S6-54's domain separators exist to prevent: a group
        // transcript is "<prefix>:$groupId:$messageId", so without prefixes a
        // direct delete of the id "group-7:msg-9" would produce a byte-identical
        // transcript to a group delete of msg-9 in group-7.
        val signature = sign(ChatControlTranscripts.messageDelete("group-7:msg-9"))

        assertFalse(
            CryptoManager.verify(
                ChatControlTranscripts.groupMessageDelete("group-7", "msg-9"),
                signature,
                publicKeyB64
            ),
            "a message_delete signature must never verify as a group_message_delete"
        )
    }

    @Test
    fun `a group delete signature is bound to both ids`() {
        val signature = sign(ChatControlTranscripts.groupMessageDelete("group-7", "msg-9"))

        assertTrue(
            CryptoManager.verify(
                ChatControlTranscripts.groupMessageDelete("group-7", "msg-9"),
                signature,
                publicKeyB64
            ),
            "the signature must verify for the exact group/message pair it covers"
        )
        assertFalse(
            CryptoManager.verify(
                ChatControlTranscripts.groupMessageDelete("group-OTHER", "msg-9"),
                signature,
                publicKeyB64
            ),
            "replaying the signature against a different group must fail"
        )
        assertFalse(
            CryptoManager.verify(
                ChatControlTranscripts.groupMessageDelete("group-7", "msg-OTHER"),
                signature,
                publicKeyB64
            ),
            "replaying the signature against a different message must fail"
        )
    }

    @Test
    fun `verify rejects a signature made by a different identity`() {
        val attacker = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val forged = Signature.getInstance("SHA256withECDSA").run {
            initSign(attacker.private)
            update(ChatControlTranscripts.messageDelete("msg-9").toByteArray())
            Base64.getEncoder().encodeToString(sign())
        }

        assertFalse(
            CryptoManager.verify(
                ChatControlTranscripts.messageDelete("msg-9"),
                forged,
                publicKeyB64
            ),
            "a delete signed by another identity must not verify against this contact's key"
        )
    }

    @Test
    fun `verify returns false instead of throwing on malformed input`() {
        // The receive handlers treat `false` as "hostile frame, drop it". If
        // verify threw instead, a malformed signature would unwind the message
        // loop rather than being rejected cleanly.
        assertFalse(
            CryptoManager.verify(
                ChatControlTranscripts.messageDelete("msg-9"),
                "not-base64-at-all!!",
                publicKeyB64
            )
        )
        assertFalse(
            CryptoManager.verify(
                ChatControlTranscripts.messageDelete("msg-9"),
                sign(ChatControlTranscripts.messageDelete("msg-9")),
                "not-a-key"
            )
        )
    }
}
