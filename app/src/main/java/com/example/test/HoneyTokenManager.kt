package com.subrosa.messenger

import android.content.Context
import android.util.Base64
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// Tamper-detection canary. The bait file is stored at the exact same path
// shape as real encrypted attachments (blobs/<uuid>.enc, pure random bytes,
// no plaintext header) and its reference MAC is keyed with a per-install
// secret held only in Keystore-backed EncryptedStorage — so reading this
// source file tells an attacker the *mechanism* but not which blob on a
// given device is the canary, nor how to forge a valid MAC for a modified
// one without that device's Keystore-protected secret.
object HoneyTokenManager {

    private const val HMAC_ALGO = "HmacSHA256"
    private const val FAKE_DATA_SIZE = 256

    fun init(context: Context) {
        val fileName = UserStorage.getHoneyFileName(context).ifEmpty {
            UUID.randomUUID().toString().also { UserStorage.setHoneyFileName(context, it) }
        }
        val file = blobFile(context, fileName)
        if (!file.exists()) {
            val macKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
            UserStorage.setHoneyMacKey(context, Base64.encodeToString(macKey, Base64.NO_WRAP))
            val data = generateFakeData()
            file.parentFile?.mkdirs()
            file.writeBytes(data)
            UserStorage.setHoneyMac(context, hmacHex(macKey, data))
        }
    }

    fun checkIntegrity(context: Context): Boolean {
        return try {
            val fileName = UserStorage.getHoneyFileName(context)
            if (fileName.isEmpty()) return true
            val file = blobFile(context, fileName)
            if (!file.exists()) return false
            val expected = UserStorage.getHoneyMac(context)
            val macKeyB64 = UserStorage.getHoneyMacKey(context)
            if (expected.isEmpty() || macKeyB64.isEmpty()) return true
            val macKey = Base64.decode(macKeyB64, Base64.NO_WRAP)
            hmacHex(macKey, file.readBytes()) == expected
        } catch (_: Exception) { true }
    }

    private fun blobFile(context: Context, id: String): File =
        SecureFileStorage.blobFile(context.filesDir, id)

    private fun generateFakeData(): ByteArray =
        ByteArray(FAKE_DATA_SIZE).also { SecureRandom().nextBytes(it) }

    private fun hmacHex(key: ByteArray, data: ByteArray): String {
        val mac = Mac.getInstance(HMAC_ALGO)
        mac.init(SecretKeySpec(key, HMAC_ALGO))
        return mac.doFinal(data).joinToString("") { "%02x".format(it) }
    }
}
