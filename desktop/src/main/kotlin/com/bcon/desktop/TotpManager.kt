package com.subrosa.desktop

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Desktop port of Android's TotpManager — RFC 6238 TOTP (HMAC-SHA1, 30s
 * step, 6 digits). Needed so a backup with TOTP protection enabled (see
 * docs/ISSUE_backup_identity_hijack.md) is actually gated on Desktop too —
 * before this, importBackup() here never looked at the backup's
 * totp_enabled flag at all, so dragging a TOTP-protected backup onto
 * Desktop skipped the second factor entirely (file + password alone was
 * sufficient here, defeating the whole point).
 *
 * secret/enabled/recoveryHashes are persisted together as ONE SMK-wrapped
 * JSON record (KEY_STATE) — mirrors Android's atomicity exactly (Android's
 * enable()/disable() each do a single SharedPreferences.Editor.apply(),
 * itself one atomic write). This used to be 2-3 separate DesktopStorage.put()/
 * remove() calls, each its own independent flush()-to-disk — a crash between
 * them could leave `enabled=true` with no secret, or a disable() that
 * cleared the secret but not the recovery hashes. One record, one write,
 * closes that window. Found in the 2026-09-13 TotpManager audit.
 */
object TotpManager {
    private const val KEY_STATE = "totp_state"

    // Legacy separate keys — read only for one-time migration, never
    // written again once KEY_STATE exists. The old secret was already
    // SMK-wrapped; the old recovery-hash list was NOT (plain CSV) — the
    // second confirmed gap this audit fixes, see saveState()/loadState().
    private const val LEGACY_KEY_SECRET = "totp_secret"
    private const val LEGACY_KEY_ENABLED = "totp_enabled"
    private const val LEGACY_KEY_RECOVERY_HASHES = "totp_recovery_hashes"

    private const val TIME_STEP_SECONDS = 30L
    private const val CODE_DIGITS = 6
    private const val DRIFT_WINDOW = 1

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    private data class State(
        val secret: String? = null,
        val enabled: Boolean = false,
        val recoveryHashes: List<String> = emptyList()
    )

    private fun toJson(s: State): String = JSONObject().apply {
        put("secret", s.secret ?: JSONObject.NULL)
        put("enabled", s.enabled)
        put("recovery_hashes", JSONArray(s.recoveryHashes))
    }.toString()

    private fun fromJson(json: String): State {
        val obj = JSONObject(json)
        val secret = if (obj.isNull("secret")) null else obj.optString("secret", null)
        val enabled = obj.optBoolean("enabled", false)
        val arr = obj.optJSONArray("recovery_hashes")
        val hashes = if (arr != null) (0 until arr.length()).map { arr.getString(it) } else emptyList()
        return State(secret, enabled, hashes)
    }

    /** Never destroys existing state while locked — a locked SMK just means
     *  this call returns what it can (possibly with secret unreadable, same
     *  tolerance Android's own getSecret() already has), not that anything
     *  gets overwritten or dropped on disk. */
    private fun loadState(): State {
        val stored = DesktopStorage.get(KEY_STATE)
        if (stored != null) {
            return try {
                val json = if (stored.startsWith(StorageKeyManager.SMK_PREFIX)) {
                    String(StorageKeyManager.unwrapBytes(stored), Charsets.UTF_8)
                } else {
                    // Self-heal a plain-JSON record saved while locked —
                    // same pattern as ChatStorage/GroupManager/SessionKeyManager/
                    // KeyHistoryManager elsewhere in this codebase.
                    if (StorageKeyManager.isUnlocked) {
                        try {
                            DesktopStorage.put(KEY_STATE, StorageKeyManager.wrapBytes(stored.toByteArray(Charsets.UTF_8)))
                        } catch (_: Exception) {}
                    }
                    stored
                }
                fromJson(json)
            } catch (e: Exception) {
                State()
            }
        }
        return migrateLegacyState()
    }

    /** One-time migration from the pre-fix separate keys — never destroys
     *  them until they've actually been folded into a persisted, protected
     *  KEY_STATE record, and only attempts that while unlocked. */
    private fun migrateLegacyState(): State {
        val legacySecretStored = DesktopStorage.get(LEGACY_KEY_SECRET)
        val legacyEnabled = DesktopStorage.getBoolean(LEGACY_KEY_ENABLED, false)
        val legacyHashesStored = DesktopStorage.get(LEGACY_KEY_RECOVERY_HASHES)
        if (legacySecretStored == null && !legacyEnabled && legacyHashesStored == null) {
            return State()
        }
        val secret = legacySecretStored?.let {
            try { String(StorageKeyManager.unwrapBytes(it), Charsets.US_ASCII) } catch (_: Exception) { null }
        }
        val hashes = legacyHashesStored?.split(",")?.filter { it.isNotBlank() } ?: emptyList()
        val state = State(secret, legacyEnabled, hashes)
        if (StorageKeyManager.isUnlocked) {
            saveState(state)
            DesktopStorage.remove(LEGACY_KEY_SECRET)
            DesktopStorage.remove(LEGACY_KEY_ENABLED)
            DesktopStorage.remove(LEGACY_KEY_RECOVERY_HASHES)
        }
        return state
    }

    /** Single write for the whole record — this IS the atomicity fix: every
     *  public mutator below goes through here exactly once, never a
     *  sequence of independent DesktopStorage calls. */
    private fun saveState(state: State) {
        val json = toJson(state)
        val toStore = if (StorageKeyManager.isUnlocked)
            StorageKeyManager.wrapBytes(json.toByteArray(Charsets.UTF_8))
        else json
        DesktopStorage.put(KEY_STATE, toStore)
    }

    fun isEnabled(): Boolean = loadState().enabled

    fun getSecret(): String? = loadState().secret

    fun generateSecret(): String {
        val bytes = ByteArray(20)
        SecureRandom().nextBytes(bytes)
        return base32Encode(bytes)
    }

    fun enable(secretBase32: String) {
        saveState(loadState().copy(secret = secretBase32, enabled = true))
    }

    fun disable() {
        // Recovery hashes cleared here too, same record — mirrors Android's
        // disable() exactly, and can no longer land as a separate write
        // that a crash could skip.
        saveState(State(secret = null, enabled = false, recoveryHashes = emptyList()))
    }

    /** Hash for the recovery codes shown once at setup — same normalization
     *  as the server side (_hash_recovery_code): trim + uppercase before
     *  hashing. Mirrors Android's TotpManager.hashRecoveryCode(). */
    fun hashRecoveryCode(code: String): String {
        val normalized = code.trim().uppercase()
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(normalized.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** Persists the recovery-code hashes locally so exportBackup() can embed
     *  them in the backup file — mirrors Android's TotpManager.
     *  saveRecoveryCodeHashes(), including the SMK-wrap: was previously
     *  stored as a plain comma-joined string directly in DesktopStorage,
     *  unlike the secret right next to it. Found in the 2026-09-13
     *  TotpManager audit. */
    fun saveRecoveryCodeHashes(hashes: List<String>) {
        saveState(loadState().copy(recoveryHashes = hashes))
    }

    fun getRecoveryCodeHashes(): List<String> = loadState().recoveryHashes

    fun otpAuthUri(secretBase32: String, account: String, issuer: String = "Subrosa"): String =
        "otpauth://totp/$issuer:$account?secret=$secretBase32&issuer=$issuer&digits=$CODE_DIGITS&period=$TIME_STEP_SECONDS"

    fun currentCode(secretBase32: String, timeMillis: Long = System.currentTimeMillis()): String =
        generateCode(secretBase32, timeMillis / 1000 / TIME_STEP_SECONDS)

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
}
