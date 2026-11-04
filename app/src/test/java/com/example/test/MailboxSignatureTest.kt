package com.subrosa.messenger

import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Cross-platform golden tests for the 2026-09-13 mailbox-authentication fix
 * (MessengerService.mailboxTranscript() / WebSocketClient.mailboxTranscript()
 * on Desktop — identical algorithm on both, see their own comments).
 * MessengerService is an Android Service and its transcript/canonicalization
 * helpers are private instance methods, not practically invokable from a
 * plain unit test without standing up the whole service — this
 * independently reimplements the exact same algorithm (recursive
 * canonicalizeValue(), sorted keys at every depth, length-prefixed,
 * "SUBROSA_MAILBOX_V1" domain tag, "signature" excluded) the same way
 * InviteCodeManagerCrossPlatformTest stands in for Desktop's module, which
 * this test classpath can't see directly. A blob built this way is
 * byte-for-byte what a genuine Android or Desktop sender would produce.
 */
@Config(sdk = [34])
@RunWith(RobolectricTestRunner::class)
class MailboxSignatureTest {

    @Before
    fun setUp() {
        ApplicationProvider.getApplicationContext<android.content.Context>()
    }

    // ── Reimplementation under test — must stay byte-identical to both
    // platforms' real mailboxTranscript()/canonicalizeValue() ──────────────

    private fun canonicalizeValue(v: Any?): String = when {
        v == null || v === JSONObject.NULL -> "n"
        v is JSONObject -> {
            val keys = v.keys().asSequence().sorted().toList()
            val sb = StringBuilder("o").append(keys.size).append(':')
            for (k in keys) {
                sb.append(k.length).append(':').append(k)
                val cv = canonicalizeValue(v.get(k))
                sb.append(cv.length).append(':').append(cv)
            }
            sb.toString()
        }
        v is JSONArray -> {
            val sb = StringBuilder("a").append(v.length()).append(':')
            for (i in 0 until v.length()) {
                val cv = canonicalizeValue(v.get(i))
                sb.append(cv.length).append(':').append(cv)
            }
            sb.toString()
        }
        v is String -> "s${v.length}:$v"
        v is Boolean -> "b${if (v) 1 else 0}"
        v is Int -> "i$v"
        v is Long -> "l$v"
        v is Double -> "d$v"
        else -> { val s = v.toString(); "s${s.length}:$s" }
    }

    private fun mailboxTranscript(inner: JSONObject): String {
        val keys = inner.keys().asSequence().filter { it != "signature" }.sorted()
        val sb = StringBuilder("SUBROSA_MAILBOX_V1")
        for (k in keys) {
            val cv = canonicalizeValue(inner.get(k))
            sb.append(':').append(k.length).append(':').append(k)
            sb.append(':').append(cv.length).append(':').append(cv)
        }
        return sb.toString()
    }

    private fun signTranscript(privateKey: PrivateKey, transcript: String): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKey)
        sig.update(transcript.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
    }

    private fun verifyTranscript(publicKey: PublicKey, transcript: String, sigB64: String): Boolean {
        return try {
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(publicKey)
            sig.update(transcript.toByteArray(Charsets.UTF_8))
            sig.verify(Base64.decode(sigB64, Base64.NO_WRAP))
        } catch (e: Exception) {
            false
        }
    }

    private fun freshKeyPair() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private fun buildInner(from: String, tokens: List<String> = listOf("aa", "bb")): JSONObject =
        JSONObject().apply {
            put("from", from)
            put("name", "Alice")
            put("text", "__beacon_tokens_only__")
            put("tokens", JSONArray(tokens))
            put("mailbox_tag", "deadbeef00000000deadbeef00000000")
            put("reply", false)
            put("id", "fixed-test-id-1")
        }

    @Test
    fun `valid mailbox signature verifies with the real sender key`() {
        val kp = freshKeyPair()
        val inner = buildInner(from = "ALICE0000000001")
        val transcript = mailboxTranscript(inner)
        val sig = signTranscript(kp.private, transcript)
        inner.put("signature", sig)

        // Verifier recomputes the transcript from the received (already
        // includes "signature") JSON — mailboxTranscript() excludes it, so
        // this must reproduce the exact same pre-signature transcript.
        assertTrue(verifyTranscript(kp.public, mailboxTranscript(inner), sig))
    }

    @Test
    fun `signature from a different key does not verify`() {
        val realSender = freshKeyPair()
        val attacker = freshKeyPair()
        val inner = buildInner(from = "VICTIM00000001")
        val transcript = mailboxTranscript(inner)
        // Attacker signs with THEIR OWN key while claiming victim's fingerprint
        // in "from" — this is exactly the forged-mailbox scenario the fix
        // closes. Verifying against the REAL (victim's) key must fail.
        val forgedSig = signTranscript(attacker.private, transcript)
        assertFalse(verifyTranscript(realSender.public, transcript, forgedSig))
    }

    @Test
    fun `tampering any bound field invalidates the signature`() {
        val kp = freshKeyPair()
        val inner = buildInner(from = "ALICE0000000001")
        val sig = signTranscript(kp.private, mailboxTranscript(inner))
        inner.put("signature", sig)

        val fields = listOf(
            "from" to "MALLORY0000001",
            "text" to "not the same text",
            "mailbox_tag" to "11111111111111111111111111111111",
            "reply" to true,
            "id" to "different-id"
        )
        for ((key, tamperedValue) in fields) {
            val tampered = JSONObject(inner.toString())
            tampered.put(key, tamperedValue)
            assertFalse(
                "tampering '$key' must invalidate the signature",
                verifyTranscript(kp.public, mailboxTranscript(tampered), sig)
            )
        }

        // Tampering the token list (an array field) must also be caught —
        // recursive canonicalization, not just top-level scalar fields.
        val tokensTampered = JSONObject(inner.toString())
        tokensTampered.put("tokens", JSONArray(listOf("cc", "dd")))
        assertFalse(verifyTranscript(kp.public, mailboxTranscript(tokensTampered), sig))
    }

    @Test
    fun `nested session_init_packet is covered by the signature`() {
        val kp = freshKeyPair()
        val sessionInitPacket = JSONObject().apply {
            put("sender_ik", "AAAA")
            put("x3dh_header", JSONObject().apply { put("ephemeral_key", "BBBB") })
        }
        val inner = JSONObject().apply {
            put("from", "ALICE0000000001")
            put("name", "Alice")
            put("text", "__beacon_session_init__")
            put("session_init_packet", sessionInitPacket)
            put("id", "fixed-test-id-2")
        }
        val sig = signTranscript(kp.private, mailboxTranscript(inner))
        inner.put("signature", sig)

        // Mutate a field INSIDE the nested object — must still be caught by
        // the recursive canonicalization, proving session_init_packet isn't
        // treated as an opaque/unsigned blob.
        val tampered = JSONObject(inner.toString())
        tampered.getJSONObject("session_init_packet").put("sender_ik", "ZZZZ")
        assertFalse(verifyTranscript(kp.public, mailboxTranscript(tampered), sig))
    }

    @Test
    fun `signature field itself is excluded from its own transcript`() {
        val kp = freshKeyPair()
        val inner = buildInner(from = "ALICE0000000001")
        val transcriptBeforeSigning = mailboxTranscript(inner)
        val sig = signTranscript(kp.private, transcriptBeforeSigning)
        inner.put("signature", sig)
        // Recomputing AFTER "signature" was added must reproduce the exact
        // same transcript — otherwise no receiver could ever verify a
        // signed payload (chicken-and-egg on the signature's own presence).
        assertTrue(mailboxTranscript(inner) == transcriptBeforeSigning)
    }
}
