package com.bcon.messenger

import android.util.Base64
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

object InviteCodeManager {

    private const val INVITE_TTL_SECONDS = 7L * 24 * 3600
    private const val FORMAT_VERSION: Byte = 0x03
    private const val FORMAT_VERSION_LEGACY: Byte = 0x02
    private const val PREFIX = "bc:"

    private val EC_P256_X509_HEADER: ByteArray =
        "3059301306072a8648ce3d020106082a8648ce3d030107034200"
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    fun generateInviteCode(publicKey: PublicKey, privateKey: PrivateKey, displayName: String): String {
        val x509Bytes = publicKey.encoded

        val ecPoint = x509Bytes.copyOfRange(x509Bytes.size - 65, x509Bytes.size)

        val fpBytes = MessageDigest.getInstance("SHA-256").digest(x509Bytes).copyOfRange(0, 8)

        val rng = SecureRandom()

        val nonce = ByteArray(8).also { rng.nextBytes(it) }

        val mailboxTagBytes = ByteArray(16).also { rng.nextBytes(it) }

        val ts = (System.currentTimeMillis() / 1000).toInt()

        val nameBytes = displayName.toByteArray(Charsets.UTF_8).let {
            if (it.size > 255) it.copyOfRange(0, 255) else it
        }

        val preSign = ByteBuffer.allocate(1 + 4 + 8 + 16 + 8 + 65 + 1 + nameBytes.size).apply {
            put(FORMAT_VERSION)
            putInt(ts)
            put(nonce)
            put(mailboxTagBytes)
            put(fpBytes)
            put(ecPoint)
            put(nameBytes.size.toByte())
            put(nameBytes)
        }.array()

        val derSig = Signature.getInstance("SHA256withECDSA").apply {
            initSign(privateKey)
            update(preSign)
        }.sign()
        val rawSig = derToRaw(derSig)

        val payload = preSign + rawSig
        val encoded = Base64.encodeToString(payload, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return "$PREFIX$encoded"
    }

    fun parseInviteCode(inviteCode: String): InviteData? {
        val code = inviteCode.trim()
        if (!code.startsWith(PREFIX)) return null

        return try {
            val payload = Base64.decode(
                code.removePrefix(PREFIX),
                Base64.URL_SAFE or Base64.NO_WRAP
            )
            val buf = ByteBuffer.wrap(payload)

            val version = buf.get()
            if (version != FORMAT_VERSION && version != FORMAT_VERSION_LEGACY) return null

            val ts = buf.int.toLong() and 0xFFFFFFFFL
            val nonce = ByteArray(8).also { buf.get(it) }

            val mailboxTagHex: String? = if (version == FORMAT_VERSION) {
                val tagBytes = ByteArray(16).also { buf.get(it) }
                tagBytes.joinToString("") { "%02x".format(it) }
            } else null
            val fpBytes = ByteArray(8).also { buf.get(it) }
            val ecPoint = ByteArray(65).also { buf.get(it) }
            val nameLen = buf.get().toInt() and 0xFF
            val nameBytes = ByteArray(nameLen).also { buf.get(it) }
            val rawSig = ByteArray(64).also { buf.get(it) }

            val x509Bytes = EC_P256_X509_HEADER + ecPoint
            val publicKeyB64 = Base64.encodeToString(x509Bytes, Base64.URL_SAFE or Base64.NO_WRAP)

            val fingerprintHex = fpBytes.joinToString("") { "%02X".format(it) }
            val nonceHex = nonce.joinToString("") { "%02X".format(it) }
            val sigB64 = Base64.encodeToString(rawSig, Base64.URL_SAFE or Base64.NO_WRAP)
            val displayName = String(nameBytes, Charsets.UTF_8)

            InviteData(publicKeyB64, fingerprintHex, nonceHex, sigB64, displayName, ts, mailboxTagHex)
        } catch (e: Exception) {
            null
        }
    }

    fun verifyInviteCode(inviteData: InviteData): Boolean {
        return try {
            val timestamp = inviteData.timestamp ?: return false

            val x509Bytes = Base64.decode(inviteData.publicKey, Base64.URL_SAFE)
            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(x509Bytes))

            val digest = MessageDigest.getInstance("SHA-256").digest(x509Bytes)
            val expectedFp = digest.take(8).joinToString("") { "%02X".format(it) }
            if (expectedFp != inviteData.fingerprint) return false

            val now = System.currentTimeMillis() / 1000
            if (now - timestamp > INVITE_TTL_SECONDS) return false
            if (timestamp > now + 300) return false

            val fpBytes = inviteData.fingerprint.chunked(2)
                .map { it.toInt(16).toByte() }.toByteArray()
            val nonceBytes = inviteData.nonce.chunked(2)
                .map { it.toInt(16).toByte() }.toByteArray()
            val nameBytes = inviteData.displayName.toByteArray(Charsets.UTF_8)
            val ecPoint = x509Bytes.copyOfRange(x509Bytes.size - 65, x509Bytes.size)

            val mailboxTagBytes = inviteData.mailboxTag?.chunked(2)
                ?.map { it.toInt(16).toByte() }?.toByteArray()
            val version = if (mailboxTagBytes != null) FORMAT_VERSION else FORMAT_VERSION_LEGACY
            val preSign = ByteBuffer.allocate(1 + 4 + 8 + (mailboxTagBytes?.size ?: 0) + 8 + 65 + 1 + nameBytes.size).apply {
                put(version)
                putInt(timestamp.toInt())
                put(nonceBytes)
                if (mailboxTagBytes != null) put(mailboxTagBytes)
                put(fpBytes)
                put(ecPoint)
                put(nameBytes.size.toByte())
                put(nameBytes)
            }.array()

            val rawSig = Base64.decode(inviteData.signature, Base64.URL_SAFE)
            val derSig = rawToDer(rawSig)

            Signature.getInstance("SHA256withECDSA").apply {
                initVerify(publicKey)
                update(preSign)
            }.verify(derSig)
        } catch (e: Exception) {
            false
        }
    }

    private fun derToRaw(der: ByteArray): ByteArray {
        var pos = 2
        pos++
        val rLen = der[pos++].toInt() and 0xFF
        val r = der.copyOfRange(pos, pos + rLen); pos += rLen
        pos++
        val sLen = der[pos++].toInt() and 0xFF
        val s = der.copyOfRange(pos, pos + sLen)
        return padOrTrim32(r) + padOrTrim32(s)
    }

    private fun rawToDer(raw: ByteArray): ByteArray {
        val r = derEncodeInt(raw.copyOfRange(0, 32))
        val s = derEncodeInt(raw.copyOfRange(32, 64))
        val body = byteArrayOf(0x02.toByte(), r.size.toByte()) + r +
                   byteArrayOf(0x02.toByte(), s.size.toByte()) + s
        return byteArrayOf(0x30.toByte(), body.size.toByte()) + body
    }

    private fun padOrTrim32(b: ByteArray): ByteArray {
        val stripped = b.dropWhile { it == 0.toByte() }.toByteArray()
            .let { if (it.isEmpty()) byteArrayOf(0) else it }
        return when {
            stripped.size > 32 -> stripped.copyOfRange(stripped.size - 32, stripped.size)
            stripped.size < 32 -> ByteArray(32 - stripped.size) + stripped
            else -> stripped
        }
    }

    private fun derEncodeInt(b: ByteArray): ByteArray {
        val stripped = b.dropWhile { it == 0.toByte() }.toByteArray()
            .let { if (it.isEmpty()) byteArrayOf(0) else it }
        return if (stripped[0].toInt() and 0x80 != 0) byteArrayOf(0.toByte()) + stripped else stripped
    }

    data class InviteData(
        val publicKey: String,
        val fingerprint: String,
        val nonce: String,
        val signature: String,
        val displayName: String,
        val timestamp: Long? = null,
        val mailboxTag: String? = null
    )
}
