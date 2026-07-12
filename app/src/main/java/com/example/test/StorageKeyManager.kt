package com.bcon.messenger

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

/**
 * Storage Master Key (SMK) — второй слой шифрования поверх EncryptedSharedPreferences.
 *
 * SMK — 32 случайных байта, хранится зашифрованным двумя способами:
 *   1. PBKDF2(password, 300K iterations) → enc_smk_pwd  [офлайн-защита]
 *   2. AndroidKeyStore AES-256 key       → enc_smk_ks   [биометрия / быстрый ре-лок]
 *
 * В памяти: smk обнуляется при lock() и при wipe.
 *
 * Защищает:
 *   - EC identity private key (CryptoManager)
 *   - Group AES keys (GroupManager)
 *   - Chat message blobs (ChatStorage)
 *
 * Прозрачная миграция через prefix "smk1:":
 *   wrapBytes(b)  → "smk1:" + Base64(iv + AES-GCM(b, smk))
 *   unwrapBytes(s) → если нет prefix — Base64.decode(s) (legacy); иначе — decrypt
 */
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

    /** true пока SMK загружен в память. */
    val isUnlocked: Boolean get() = smk != null

    // ─── Lifecycle ──────────────────────────────────────────────────────────

    /** true если SMK уже был инициализирован (enc_smk_pwd присутствует). */
    fun isSetup(context: Context): Boolean =
        prefs(context).getString(KEY_ENC_SMK_PWD, null) != null

    /**
     * Первый запуск: генерировать SMK, зашифровать обоими способами, сохранить.
     * После вызова smk загружен в память (isUnlocked = true).
     */
    fun setup(context: Context, password: String) {
        val newSmk = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val salt   = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val encPwd = encryptWithPassword(newSmk, password, salt)
        val encKs  = encryptWithKeystore(newSmk, context)

        prefs(context).edit()
            .putString(KEY_ENC_SMK_PWD, Base64.encodeToString(encPwd, Base64.NO_WRAP))
            .putString(KEY_SALT,        Base64.encodeToString(salt,   Base64.NO_WRAP))
            .putString(KEY_ENC_SMK_KS,  Base64.encodeToString(encKs,  Base64.NO_WRAP))
            .apply()

        smk?.fill(0)
        smk = newSmk
    }

    /**
     * Разблокировать SMK через пароль (PBKDF2).
     * Вызывать в IO-потоке (PBKDF2 300K итераций — медленно).
     * @return true при успехе, false если неверный пароль.
     */
    fun unlockWithPassword(context: Context, password: String): Boolean {
        val p = prefs(context)
        val encB64  = p.getString(KEY_ENC_SMK_PWD, null) ?: return false
        val saltB64 = p.getString(KEY_SALT, null)         ?: return false
        return try {
            val blob = Base64.decode(encB64,  Base64.NO_WRAP)
            val salt = Base64.decode(saltB64, Base64.NO_WRAP)
            val decrypted = decryptWithPassword(blob, password, salt)
            smk?.fill(0)
            smk = decrypted
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Разблокировать SMK через AndroidKeyStore ключ (для биометрии).
     * Работает пока устройство разблокировано (keystore доступен).
     * @return true при успехе.
     */
    fun unlockWithKeystore(context: Context): Boolean {
        val encB64 = prefs(context).getString(KEY_ENC_SMK_KS, null) ?: return false
        return try {
            val blob = Base64.decode(encB64, Base64.NO_WRAP)
            val decrypted = decryptWithKeystore(blob)
            smk?.fill(0)
            smk = decrypted
            migrateKsKeyIfNeeded(context, decrypted)
            true
        } catch (_: Exception) {
            false
        }
    }

    /** Обнулить SMK из памяти. Вызывать при блокировке и wipe. */
    fun lock() {
        smk?.fill(0)
        smk = null
    }

    /**
     * Перешифровать SMK новым паролем (при смене пароля пользователя).
     * Требует, чтобы SMK уже был разблокирован.
     */
    fun changePassword(context: Context, newPassword: String) {
        val key = smk ?: error("StorageKeyManager locked")
        val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val encPwd = encryptWithPassword(key, newPassword, salt)
        prefs(context).edit()
            .putString(KEY_ENC_SMK_PWD, Base64.encodeToString(encPwd,  Base64.NO_WRAP))
            .putString(KEY_SALT,        Base64.encodeToString(salt,    Base64.NO_WRAP))
            .commit()
    }

    // ─── Симметричное шифрование данных с SMK ───────────────────────────────

    /**
     * Зашифровать данные текущим SMK.
     * Возвращает iv(12) + ciphertext + tag(16).
     * Бросает исключение если SMK не загружен.
     */
    fun encrypt(data: ByteArray): ByteArray {
        val key = smk ?: error("StorageKeyManager is locked")
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return iv + cipher.doFinal(data)
    }

    /**
     * Расшифровать данные текущим SMK.
     * @param data iv(12) + ciphertext + tag(16)
     * Бросает исключение если SMK не загружен или данные повреждены.
     */
    fun decrypt(data: ByteArray): ByteArray {
        val key = smk ?: error("StorageKeyManager is locked")
        val iv  = data.copyOfRange(0, 12)
        val ct  = data.copyOfRange(12, data.size)
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    // ─── Обёртки для SharedPreferences значений ─────────────────────────────

    /**
     * Обернуть байты SMK-шифрованием.
     * Результат: "smk1:" + Base64(iv + ct + tag).
     * Бросает исключение если SMK не загружен.
     */
    fun wrapBytes(bytes: ByteArray): String =
        SMK_PREFIX + Base64.encodeToString(encrypt(bytes), Base64.NO_WRAP)

    /**
     * Развернуть значение из хранилища.
     * Если нет prefix "smk1:" — legacy путь: Base64.decode как обычно (backward compat).
     * Если есть prefix — decrypt с SMK (бросает если SMK не загружен).
     */
    fun unwrapBytes(stored: String): ByteArray {
        if (!stored.startsWith(SMK_PREFIX)) {
            // Legacy: plain Base64-encoded bytes
            return Base64.decode(stored, Base64.NO_WRAP)
        }
        val blob = Base64.decode(stored.removePrefix(SMK_PREFIX), Base64.NO_WRAP)
        return decrypt(blob)
    }

    // ─── Внутренние методы ──────────────────────────────────────────────────

    private fun prefs(context: Context) =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)

    private fun deriveKey(password: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITER, 256)
        val raw  = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(raw, "AES")
    }

    private fun encryptWithPassword(smkBytes: ByteArray, password: String, salt: ByteArray): ByteArray {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt), GCMParameterSpec(128, iv))
        return iv + cipher.doFinal(smkBytes)  // iv(12) + ct(32) + tag(16) = 60
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

    // Мигрирует существующий KS-ключ без setUserAuthenticationRequired на новый с биометрией.
    // Вызывается после успешного unlockWithKeystore(), пока SMK ещё в памяти.
    private fun migrateKsKeyIfNeeded(context: Context, currentSmk: ByteArray) {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            val key = ks.getKey(KS_ALIAS, null) as? SecretKey ?: return
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (!info.isUserAuthenticationRequired) {
                ks.deleteEntry(KS_ALIAS)
                val newEncKs = encryptWithKeystore(currentSmk, context) // создаёт новый ключ через getOrCreateKsKey
                prefs(context).edit()
                    .putString(KEY_ENC_SMK_KS, Base64.encodeToString(newEncKs, Base64.NO_WRAP))
                    .apply()
            }
        } catch (_: Exception) {
            // Миграция не критична — старый ключ продолжит работу
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
