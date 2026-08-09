package com.subrosa.messenger

import android.content.Context
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 6238 TOTP (HMAC-SHA1, 30s step, 6 digits) used to add a second
 * factor on top of the backup password when restoring identity from a
 * backup file — see docs/ISSUE_backup_identity_hijack.md, "Candidate
 * fixes" #4. The secret is generated on-device and never stored inside
 * the backup blob itself; the user is expected to save it in a separate
 * offline vault, so file+password alone stays insufficient to import.
 */
object TotpManager {
    private const val PREFS_NAME = "totp_prefs"
    private const val KEY_SECRET = "totp_secret"
    private const val KEY_ENABLED = "totp_enabled"

    private const val TIME_STEP_SECONDS = 30L
    private const val CODE_DIGITS = 6
    private const val DRIFT_WINDOW = 1

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun isEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ENABLED, false)

    fun getSecret(context: Context): String? {
        val stored = prefs(context).getString(KEY_SECRET, null) ?: return null
        return try {
            String(StorageKeyManager.unwrapBytes(stored), Charsets.US_ASCII)
        } catch (_: Exception) {
            null
        }
    }

    fun generateSecret(): String {
        val bytes = ByteArray(20)
        SecureRandom().nextBytes(bytes)
        return base32Encode(bytes)
    }

    fun enable(context: Context, secretBase32: String) {
        val wrapped = StorageKeyManager.wrapBytes(secretBase32.toByteArray(Charsets.US_ASCII))
        prefs(context).edit()
            .putString(KEY_SECRET, wrapped)
            .putBoolean(KEY_ENABLED, true)
            .apply()
    }

    fun disable(context: Context) {
        prefs(context).edit()
            .remove(KEY_SECRET)
            .putBoolean(KEY_ENABLED, false)
            .apply()
    }

    fun otpAuthUri(secretBase32: String, account: String, issuer: String = "Subrosa"): String =
        "otpauth://totp/$issuer:$account?secret=$secretBase32&issuer=$issuer&digits=$CODE_DIGITS&period=$TIME_STEP_SECONDS"

    fun verifyCode(secretBase32: String, code: String, timeMillis: Long = System.currentTimeMillis()): Boolean {
        val normalized = code.trim()
        if (normalized.isEmpty()) return false
        val counter = timeMillis / 1000 / TIME_STEP_SECONDS
        for (drift in -DRIFT_WINDOW..DRIFT_WINDOW) {
            if (generateCode(secretBase32, counter + drift) == normalized) return true
        }
        return false
    }

    private fun generateCode(secretBase32: String, counter: Long): String {
        val key = base32Decode(secretBase32)
        val counterBytes = ByteArray(8)
        var value = counter
        for (i in 7 downTo 0) {
            counterBytes[i] = (value and 0xff).toByte()
            value = value shr 8
        }
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        val hash = mac.doFinal(counterBytes)
        val offset = hash[hash.size - 1].toInt() and 0x0f
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)
        val modulus = Math.pow(10.0, CODE_DIGITS.toDouble()).toInt()
        return (binary % modulus).toString().padStart(CODE_DIGITS, '0')
    }

    private fun base32Encode(data: ByteArray): String {
        val sb = StringBuilder()
        var bits = 0
        var value = 0
        for (b in data) {
            value = (value shl 8) or (b.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                sb.append(BASE32_ALPHABET[(value ushr (bits - 5)) and 0x1f])
                bits -= 5
            }
        }
        if (bits > 0) {
            sb.append(BASE32_ALPHABET[(value shl (5 - bits)) and 0x1f])
        }
        return sb.toString()
    }

    private fun base32Decode(str: String): ByteArray {
        val clean = str.trim().uppercase().replace("=", "").replace(" ", "")
        val out = ByteArrayOutputStream()
        var bits = 0
        var value = 0
        for (ch in clean) {
            val idx = BASE32_ALPHABET.indexOf(ch)
            if (idx < 0) continue
            value = (value shl 5) or idx
            bits += 5
            if (bits >= 8) {
                out.write((value ushr (bits - 8)) and 0xff)
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    private fun prefs(context: Context) =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
}
