package com.subrosa.messenger

import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Android half of the cross-platform pin on the chat-control signature
 * transcripts. The desktop half is `ChatControlTranscriptsTest` in
 * `desktop/src/test` — same test names, same expected literals, separate
 * Gradle builds.
 *
 * Why the literals are duplicated here instead of imported from
 * [ChatControlTranscripts]: importing the value under test would make this
 * tautological — it would pass for whatever the production code happens to
 * produce, including a value the desktop client no longer agrees with. The
 * literals below ARE the contract. If this test fails, the two clients have
 * diverged and delete-for-everyone is broken across platforms; do NOT "fix" it
 * by pasting in the new value.
 *
 * Unlike [MailboxSignatureTest], which has to reimplement its algorithm
 * because MessengerService's transcript helpers are private instance methods,
 * this test calls the real production code: the transcripts were extracted out
 * of MessengerService into [ChatControlTranscripts] precisely so they could be
 * reached from here.
 *
 * Signing goes through raw JCA rather than `CryptoManager.sign`, which needs an
 * initialised on-disk identity. Verification DOES go through the real
 * [CryptoManager.verify], so the production verify path is under test.
 * Robolectric is required because that path uses `android.util.Base64`.
 */
@Config(sdk = [34])
@RunWith(RobolectricTestRunner::class)
class ChatControlTranscriptsTest {

    private lateinit var keyPair: KeyPair
    private lateinit var publicKeyB64: String

    @Before
    fun setUp() {
        ApplicationProvider.getApplicationContext<android.content.Context>()
        keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        publicKeyB64 = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
    }

    private fun sign(transcript: String, key: java.security.PrivateKey = keyPair.private): String =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(transcript.toByteArray())
            Base64.encodeToString(sign(), Base64.NO_WRAP)
        }

    // ── Wire contract ──────────────────────────────────────────────────────

    @Test
    fun `message_delete transcript matches the desktop contract`() {
        assertEquals(
            "SUBROSA_MESSAGE_DELETE_V1:abc-123",
            ChatControlTranscripts.messageDelete("abc-123")
        )
    }

    @Test
    fun `group_message_delete transcript matches the desktop contract`() {
        assertEquals(
            "SUBROSA_GROUP_MESSAGE_DELETE_V1:group-7:msg-9",
            ChatControlTranscripts.groupMessageDelete("group-7", "msg-9")
        )
    }

    @Test
    fun `disappear_timer transcript is the bare seconds value`() {
        // Deliberately unversioned — the shipped desktop client signs
        // seconds.toString(). See ChatControlTranscripts.disappearTimer's own
        // comment for the accepted residual risk.
        assertEquals("3600", ChatControlTranscripts.disappearTimer(3600L))
        assertEquals("0", ChatControlTranscripts.disappearTimer(0L))
    }

    // ── Domain separation (the property S6-54 added) ───────────────────────

    @Test
    fun `a direct delete signature does not verify as a group delete`() {
        // The collision the domain separators exist to prevent: a group
        // transcript is "<prefix>:$groupId:$messageId", so without prefixes a
        // direct delete of the id "group-7:msg-9" would produce a
        // byte-identical transcript to a group delete of msg-9 in group-7.
        val signature = sign(ChatControlTranscripts.messageDelete("group-7:msg-9"))

        assertFalse(
            "a message_delete signature must never verify as a group_message_delete",
            CryptoManager.verify(
                ChatControlTranscripts.groupMessageDelete("group-7", "msg-9"),
                signature,
                publicKeyB64
            )
        )
    }

    @Test
    fun `a group delete signature is bound to both ids`() {
        val signature = sign(ChatControlTranscripts.groupMessageDelete("group-7", "msg-9"))

        assertTrue(
            "the signature must verify for the exact group/message pair it covers",
            CryptoManager.verify(
                ChatControlTranscripts.groupMessageDelete("group-7", "msg-9"),
                signature,
                publicKeyB64
            )
        )
        assertFalse(
            "replaying the signature against a different group must fail",
            CryptoManager.verify(
                ChatControlTranscripts.groupMessageDelete("group-OTHER", "msg-9"),
                signature,
                publicKeyB64
            )
        )
        assertFalse(
            "replaying the signature against a different message must fail",
            CryptoManager.verify(
                ChatControlTranscripts.groupMessageDelete("group-7", "msg-OTHER"),
                signature,
                publicKeyB64
            )
        )
    }

    @Test
    fun `verify rejects a signature made by a different identity`() {
        val attacker = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val forged = sign(ChatControlTranscripts.messageDelete("msg-9"), attacker.private)

        assertFalse(
            "a delete signed by another identity must not verify against this contact's key",
            CryptoManager.verify(
                ChatControlTranscripts.messageDelete("msg-9"),
                forged,
                publicKeyB64
            )
        )
    }

    @Test
    fun `verify returns false instead of throwing on malformed input`() {
        // The receive handlers in MessengerService throw SecurityException on a
        // `false` result, which suppresses the anon_delivery ack. If verify
        // itself threw a non-SecurityException instead, a malformed frame would
        // take a different, untested path out of the message loop.
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
