package com.subrosa.messenger

import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * Cross-platform "golden" test for the invite-code wire format shared by
 * Android's and Desktop's InviteCodeManager.kt (docs: both files' own
 * "Wire format" comment). Desktop is a separate Gradle module Android's
 * test classpath can't see, so this doesn't literally invoke Desktop's
 * Kotlin — instead it independently re-implements the documented byte
 * layout (version, ts, nonce, mailbox tag, fingerprint, EC point, name,
 * raw ECDSA signature) using plain java.security APIs, exactly as Desktop's
 * generateInviteLinkFresh()/derToRaw() do, and feeds the result into
 * Android's real parseInviteCode()/verifyInviteCode(). A payload built this
 * way succeeding here is exactly what would happen for a genuine
 * Desktop-generated invite, since both implementations perform the same
 * primitive operations (EC keygen, SHA-256, SHA256withECDSA, raw r||s
 * encoding) over the same byte layout — see docs/SECURITY_INVARIANTS.md for
 * the shared format spec this guards. Found/added in the 2026-09-13
 * cross-platform InviteCodeManager audit.
 */
@Config(sdk = [34])
@RunWith(RobolectricTestRunner::class)
class InviteCodeManagerCrossPlatformTest {

    private fun rawToDer(raw: ByteArray): ByteArray {
        fun derEncodeInt(b: ByteArray): ByteArray {
            val stripped = b.dropWhile { it == 0.toByte() }.toByteArray()
                .let { if (it.isEmpty()) byteArrayOf(0) else it }
            return if (stripped[0].toInt() and 0x80 != 0) byteArrayOf(0) + stripped else stripped
        }
        val r = derEncodeInt(raw.copyOfRange(0, 32))
        val s = derEncodeInt(raw.copyOfRange(32, 64))
        val body = byteArrayOf(0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    /** Raw (r||s, 32 bytes each) ECDSA signature over [data] — mirrors both
     *  platforms' derToRaw(Signature.sign()) exactly. */
    private fun signRaw(privateKey: java.security.PrivateKey, data: ByteArray): ByteArray {
        val der = Signature.getInstance("SHA256withECDSA").apply {
            initSign(privateKey)
            update(data)
        }.sign()
        // DER -> raw, same algorithm as both platforms' derToRaw().
        var pos = 2
        pos++
        val rLen = der[pos++].toInt() and 0xFF
        val r = der.copyOfRange(pos, pos + rLen); pos += rLen
        pos++
        val sLen = der[pos++].toInt() and 0xFF
        val s = der.copyOfRange(pos, pos + sLen)
        fun padOrTrim32(b: ByteArray): ByteArray {
            val stripped = b.dropWhile { it == 0.toByte() }.toByteArray()
                .let { if (it.isEmpty()) byteArrayOf(0) else it }
            return when {
                stripped.size > 32 -> stripped.copyOfRange(stripped.size - 32, stripped.size)
                stripped.size < 32 -> ByteArray(32 - stripped.size) + stripped
                else -> stripped
            }
        }
        return padOrTrim32(r) + padOrTrim32(s)
    }

    /** Builds a wire-format invite string exactly per the documented byte
     *  layout, independent of Android's own generateInviteCode(). Stands in
     *  for "a Desktop-generated invite" — see class doc comment. */
    private fun buildGoldenInvite(
        publicKeyEncoded: ByteArray,
        privateKey: java.security.PrivateKey,
        displayName: String,
        mailboxTagHex: String,
        timestampSeconds: Long,
        nonce: ByteArray = ByteArray(8).also { SecureRandom().nextBytes(it) }
    ): String {
        val ecPoint = publicKeyEncoded.copyOfRange(publicKeyEncoded.size - 65, publicKeyEncoded.size)
        val fpBytes = MessageDigest.getInstance("SHA-256").digest(publicKeyEncoded).copyOfRange(0, 8)
        val tagBytes = mailboxTagHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val nameBytes = displayName.toByteArray(Charsets.UTF_8)

        val preSign = ByteBuffer.allocate(1 + 4 + 8 + 16 + 8 + 65 + 1 + nameBytes.size).apply {
            put(0x03.toByte())
            putInt(timestampSeconds.toInt())
            put(nonce)
            put(tagBytes)
            put(fpBytes)
            put(ecPoint)
            put(nameBytes.size.toByte())
            put(nameBytes)
        }.array()

        val rawSig = signRaw(privateKey, preSign)
        val payload = preSign + rawSig
        val encoded = Base64.encodeToString(payload, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return "bc:$encoded"
    }

    @Test
    fun `golden invite built independently per spec parses and verifies on Android`() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()

        val nowSec = System.currentTimeMillis() / 1000
        val mailboxTag = ByteArray(16).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }

        val invite = buildGoldenInvite(
            publicKeyEncoded = kp.public.encoded,
            privateKey = kp.private,
            displayName = "Alice",
            mailboxTagHex = mailboxTag,
            timestampSeconds = nowSec
        )

        val data = InviteCodeManager.parseInviteCode(invite)
        assertNotNull("golden invite must parse", data)
        assertTrue("golden invite must verify", InviteCodeManager.verifyInviteCode(data!!))
        assertEquals("Alice", data.displayName)
        assertEquals(mailboxTag, data.mailboxTag)

        val expectedFp = MessageDigest.getInstance("SHA-256").digest(kp.public.encoded)
            .take(8).joinToString("") { "%02X".format(it) }
        assertEquals(expectedFp, data.fingerprint)

        // Round-trips through the exact same key: decoding InviteData.publicKey
        // must reconstruct a public key equal to the one that signed it —
        // covers item 3's canonicalization fix (padded internal
        // representation) end to end, not just "decode doesn't throw".
        val decodedKey = KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(Base64.decode(data.publicKey.replace('-', '+').replace('_', '/'), Base64.NO_WRAP))
        ) as ECPublicKey
        assertEquals((kp.public as ECPublicKey).w, decodedKey.w)
    }

    @Test
    fun `android-generated invite round-trips through its own parser`() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val tag = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

        val code = InviteCodeManager.generateInviteCode(kp.public, kp.private, "Bob", tag)
        val data = InviteCodeManager.parseInviteCode(code)
        assertNotNull(data)
        assertTrue(InviteCodeManager.verifyInviteCode(data!!))
        assertEquals("Bob", data.displayName)
        assertEquals(tag, data.mailboxTag)
    }

    @Test
    fun `trailing bytes after the signature are rejected`() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val tag = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val code = InviteCodeManager.generateInviteCode(kp.public, kp.private, "Eve", tag)

        val payload = Base64.decode(code.removePrefix("bc:"), Base64.URL_SAFE or Base64.NO_WRAP)
        val tampered = payload + byteArrayOf(0x7F)
        val tamperedCode = "bc:" + Base64.encodeToString(tampered, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        assertNull("payload with trailing junk must be rejected at parse time", InviteCodeManager.parseInviteCode(tamperedCode))
    }

    @Test
    fun `payload shorter than the structural minimum is rejected`() {
        val tooShort = ByteArray(10)
        val code = "bc:" + Base64.encodeToString(tooShort, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        assertNull(InviteCodeManager.parseInviteCode(code))
    }
}
