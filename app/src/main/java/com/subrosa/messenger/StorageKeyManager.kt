package com.subrosa.messenger

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object StorageKeyManager {

    const val SMK_PREFIX = "smk1:"

    private const val PREFS_NAME       = "smk_config"
    private const val KEY_ENC_SMK_PWD  = "enc_smk_pwd"
    private const val KEY_SALT         = "smk_salt"
    private const val KEY_ENC_SMK_KS   = "enc_smk_ks"
    private const val KS_ALIAS         = "beacon_smk_wrap"
    private const val PBKDF2_ITER      = 300_000
    private const val AES_GCM          = "AES/GCM/NoPadding"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    @Volatile private var smk: ByteArray? = null

    val isUnlocked: Boolean get() = smk != null

    fun isSetup(context: Context): Boolean =
        prefs(context).getString(KEY_ENC_SMK_PWD, null) != null

    fun setup(context: Context, password: String) {
        val newSmk = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val salt   = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val encPwd = encryptWithPassword(newSmk, password, salt)

        // KS-путь — необязательный бонус для быстрой разблокировки (биометрия).
        // Требует secure lock screen на устройстве; без него генерация ключа падает
        // с IllegalStateException. Пароль остаётся основным и всегда рабочим способом.
        val encKs = try {
            encryptWithKeystore(newSmk, context)
        } catch (e: Exception) {
            null
        }

        prefs(context).edit().apply {
            putString(KEY_ENC_SMK_PWD, Base64.encodeToString(encPwd, Base64.NO_WRAP))
            putString(KEY_SALT,        Base64.encodeToString(salt,   Base64.NO_WRAP))
            if (encKs != null) {
                putString(KEY_ENC_SMK_KS, Base64.encodeToString(encKs, Base64.NO_WRAP))
            }
        }.apply()

        SecureMemory.wipe(smk)
        smk = newSmk

        // Missing entirely before this fix, unlike unlockWithPassword()/
        // unlockWithKeystore() below — SessionKeyManager.initialize() runs
        // at app/service startup, BEFORE the user has registered/logged in,
        // i.e. while this object is still locked. Its own generateOrRotateSpk()
        // correctly leaves currentSpk/currentPqKem null in that case
        // ("waiting for unlock") and relies entirely on a later
        // reloadSessionsIfNeeded() call to actually generate/restore them
        // once a real SMK exists. setup() (called on every register()/
        // re-register, per LoginScreen.kt and RegisterScreen.kt — mints a
        // brand-new SMK each time) never made that call, so currentSpk
        // stayed permanently null for the rest of the process on any device
        // that already had stored SPK data from a prior SMK generation.
        // Ported from the identical Desktop bug, found live 2026-09-18 —
        // see SessionKeyManager.kt's isWrappedUnderStaleSmk comment there.
        SessionKeyManager.reloadSessionsIfNeeded()
    }

    fun unlockWithPassword(context: Context, password: String): Boolean {
        val p = prefs(context)
        val encB64  = p.getString(KEY_ENC_SMK_PWD, null) ?: return false
        val saltB64 = p.getString(KEY_SALT, null)         ?: return false
        return try {
            val blob = Base64.decode(encB64,  Base64.NO_WRAP)
            val salt = Base64.decode(saltB64, Base64.NO_WRAP)
            val decrypted = decryptWithPassword(blob, password, salt)
            SecureMemory.wipe(smk)
            smk = decrypted
            SessionKeyManager.reloadSessionsIfNeeded()
            true
        } catch (_: Exception) {
            false
        }
    }

    fun unlockWithKeystore(context: Context): Boolean {
        val encB64 = prefs(context).getString(KEY_ENC_SMK_KS, null) ?: return false
        return try {
            val blob = Base64.decode(encB64, Base64.NO_WRAP)
            val decrypted = decryptWithKeystore(blob)
            SecureMemory.wipe(smk)
            smk = decrypted
            migrateKsKeyIfNeeded(context, decrypted)
            SessionKeyManager.reloadSessionsIfNeeded()
            true
        } catch (_: Exception) {
            false
        }
    }

    fun lock() {
        SecureMemory.wipe(smk)
        smk = null
    }

    fun changePassword(context: Context, newPassword: String) {
        val key = smk ?: error("StorageKeyManager locked")
        val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val encPwd = encryptWithPassword(key, newPassword, salt)
        prefs(context).edit()
            .putString(KEY_ENC_SMK_PWD, Base64.encodeToString(encPwd,  Base64.NO_WRAP))
            .putString(KEY_SALT,        Base64.encodeToString(salt,    Base64.NO_WRAP))
            .commit()
    }

    fun encrypt(data: ByteArray): ByteArray {
        val key = smk ?: error("StorageKeyManager is locked")
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return iv + cipher.doFinal(data)
    }

    fun decrypt(data: ByteArray): ByteArray {
        val key = smk ?: error("StorageKeyManager is locked")
        val iv  = data.copyOfRange(0, 12)
        val ct  = data.copyOfRange(12, data.size)
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    fun wrapBytes(bytes: ByteArray): String =
        SMK_PREFIX + Base64.encodeToString(encrypt(bytes), Base64.NO_WRAP)

    fun unwrapBytes(stored: String): ByteArray {
        if (!stored.startsWith(SMK_PREFIX)) {

            return Base64.decode(stored, Base64.NO_WRAP)
        }
        val blob = Base64.decode(stored.removePrefix(SMK_PREFIX), Base64.NO_WRAP)
        return decrypt(blob)
    }

    private fun prefs(context: Context) =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)

    /**
     * Two copies used to be left behind on every call, both now wiped:
     *
     *  - `password.toCharArray()` was created inline, so nothing held a
     *    reference to zero afterwards. `spec.clearPassword()` only clears
     *    `PBEKeySpec`'s own internal clone, not the array we handed it.
     *  - `raw` — the derived 256-bit key — was passed straight into
     *    `SecretKeySpec`, which *clones* its input. The original stayed on the
     *    heap for the GC to get to eventually, next to the password.
     *
     * `SecretKeySpec`'s own clone cannot be reached from here (AOSP does not
     * implement `destroy()` on it) and neither can whatever the provider
     * copies during `Cipher.init`. See [SecureMemory]'s class doc.
     */
    private fun deriveKey(password: String, salt: ByteArray): SecretKey {
        val chars = password.toCharArray()
        var raw: ByteArray? = null
        try {
            val spec = PBEKeySpec(chars, salt, PBKDF2_ITER, 256)
            try {
                raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            } finally {
                spec.clearPassword()
            }
            return SecretKeySpec(raw, "AES")
        } finally {
            SecureMemory.wipe(chars)
            SecureMemory.wipe(raw)
        }
    }

    private fun encryptWithPassword(smkBytes: ByteArray, password: String, salt: ByteArray): ByteArray {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt), GCMParameterSpec(128, iv))
        return iv + cipher.doFinal(smkBytes)
    }

    private fun decryptWithPassword(blob: ByteArray, password: String, salt: ByteArray): ByteArray {
        val iv  = blob.copyOfRange(0, 12)
        val ct  = blob.copyOfRange(12, blob.size)
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    private fun getOrCreateKsKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        if (!ks.containsAlias(KS_ALIAS)) {
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            kg.init(
                KeyGenParameterSpec.Builder(
                    KS_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(10)
                    .build()
            )
            kg.generateKey()
        }
        return ks.getKey(KS_ALIAS, null) as SecretKey
    }

    private fun migrateKsKeyIfNeeded(context: Context, currentSmk: ByteArray) {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            val key = ks.getKey(KS_ALIAS, null) as? SecretKey ?: return
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (!info.isUserAuthenticationRequired) {
                ks.deleteEntry(KS_ALIAS)
                val newEncKs = encryptWithKeystore(currentSmk, context)
                prefs(context).edit()
                    .putString(KEY_ENC_SMK_KS, Base64.encodeToString(newEncKs, Base64.NO_WRAP))
                    .apply()
            }
        } catch (_: Exception) {

        }
    }

    private fun encryptWithKeystore(smkBytes: ByteArray, context: Context): ByteArray {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKsKey(), GCMParameterSpec(128, iv))
        return iv + cipher.doFinal(smkBytes)
    }

    private fun decryptWithKeystore(blob: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        val key = ks.getKey(KS_ALIAS, null) as? SecretKey
            ?: error("Keystore key not found: $KS_ALIAS")
        val iv  = blob.copyOfRange(0, 12)
        val ct  = blob.copyOfRange(12, blob.size)
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }
}
