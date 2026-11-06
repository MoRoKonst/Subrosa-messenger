package com.subrosa.desktop

import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import java.io.File

/**
 * Storage Master Key (SMK) — второй слой шифрования поверх DesktopStorage.
 *
 * SMK — 32 случайных байта, хранится зашифрованным двумя способами:
 *   1. PBKDF2(password, 300K iterations) → enc_smk_pwd  [офлайн-защита]
 *   2. DesktopKeyStore AES-256 key       → enc_smk_ks   [быстрый ре-лок]
 */
object StorageKeyManager {

    const val SMK_PREFIX = "smk1:"

    private const val KEY_ENC_SMK_PWD  = "enc_smk_pwd"
    private const val KEY_SALT         = "smk_salt"
    private const val KEY_ENC_SMK_KS   = "enc_smk_ks"
    private const val KS_ALIAS         = "BEACON_smk_wrap"
    private const val PBKDF2_ITER      = 300_000
    private const val AES_GCM          = "AES/GCM/NoPadding"

    // Prefer a native locked buffer; fall back to heap ByteArray if JNA unavailable.
    @Volatile private var smkBuf: NativeProtection.LockedBuffer? = null
    @Volatile private var smkArr: ByteArray? = null          // fallback

    /** true пока SMK загружен в память. */
    val isUnlocked: Boolean get() = smkBuf != null || smkArr != null

    // ── SMK memory helpers ───────────────────────────────────────────────────

    private fun storeSmk(bytes: ByteArray) {
        clearSmk()
        val buf = NativeProtection.allocateLockedBuffer(bytes.size)
        if (buf != null) {
            buf.write(bytes)
            smkBuf = buf
        } else {
            smkArr = bytes.copyOf()
        }
        bytes.fill(0)   // wipe the incoming array regardless
    }

    private fun readSmk(): ByteArray =
        smkBuf?.read() ?: smkArr?.copyOf() ?: error("StorageKeyManager is locked")

    private fun clearSmk() {
        smkBuf?.clear(); smkBuf?.free(); smkBuf = null
        smkArr?.fill(0);                 smkArr = null
    }

    // ─── Lifecycle ──────────────────────────────────────────────────────────

    /** true если SMK уже был инициализирован (enc_smk_pwd присутствует). */
    fun isSetup(): Boolean =
        DesktopStorage.get(KEY_ENC_SMK_PWD) != null

    /**
     * Первый запуск: генерировать SMK, зашифровать обоими способами, сохранить.
     * После вызова smk загружен в память (isUnlocked = true).
     */
    fun setup(password: String) {
        val newSmk = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val salt   = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val encPwd = encryptWithPassword(newSmk, password, salt)
        val encKs  = encryptWithKeystore(newSmk)

        val encoder = Base64.getEncoder()
        DesktopStorage.put(KEY_ENC_SMK_PWD, encoder.encodeToString(encPwd))
        DesktopStorage.put(KEY_SALT,        encoder.encodeToString(salt))
        DesktopStorage.put(KEY_ENC_SMK_KS,  encoder.encodeToString(encKs))

        storeSmk(newSmk)
        // Missing entirely before this fix, unlike unlockWithPassword()/
        // unlockWithKeystore() below — main.kt's SessionKeyManager.init()
        // runs unconditionally at app startup, BEFORE the user has
        // registered/logged in, i.e. while this object is still locked. Its
        // generateOrRotateSpk() correctly leaves currentSpk/currentPqKem
        // null in that case ("waiting for unlock" — see that function's own
        // comment) and relies entirely on a later reloadSessionsIfNeeded()
        // call to actually generate/restore them once a real SMK exists.
        // setup() (the register() path — mints a brand-new SMK every time,
        // see DeviceKeyManager's comment) never made that call, so
        // currentSpk stayed permanently null for the rest of the process:
        // every getLocalPrekeyBundle()/generatePrekeyBundle() threw "SPK не
        // инициализирован", silently swallowed by WebSocketClient's
        // publishPrekeyBundle(), so this device's prekey bundle was NEVER
        // published on a fresh register() — confirmed live, 2026-09-18,
        // reproduced even after fixing generateOrRotateSpk()'s own stale-SMK
        // detection, because that fix never got a chance to run at all on
        // this path.
        SessionKeyManager.reloadSessionsIfNeeded()
    }

    /**
     * Разблокировать SMK через пароль (PBKDF2).
     */
    fun unlockWithPassword(password: String): Boolean {
        val encB64  = DesktopStorage.get(KEY_ENC_SMK_PWD) ?: return false
        val saltB64 = DesktopStorage.get(KEY_SALT)         ?: return false
        return try {
            val decoder = Base64.getDecoder()
            val blob = decoder.decode(encB64)
            val salt = decoder.decode(saltB64)
            val decrypted = decryptWithPassword(blob, password, salt)
            storeSmk(decrypted)
            SessionKeyManager.reloadSessionsIfNeeded()
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Разблокировать SMK через DesktopKeyStore ключ.
     */
    fun unlockWithKeystore(): Boolean {
        val encB64 = DesktopStorage.get(KEY_ENC_SMK_KS) ?: return false
        return try {
            val decoder = Base64.getDecoder()
            val blob = decoder.decode(encB64)
            val decrypted = decryptWithKeystore(blob)
            storeSmk(decrypted)
            SessionKeyManager.reloadSessionsIfNeeded()
            true
        } catch (_: Exception) {
            false
        }
    }

    /** Обнулить SMK из памяти. */
    fun lock() {
        clearSmk()
    }

    /**
     * Перешифровать SMK новым паролем.
     */
    fun changePassword(newPassword: String) {
        val key = readSmk()
        try {
            val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val encPwd = encryptWithPassword(key, newPassword, salt)
            val encoder = Base64.getEncoder()
            DesktopStorage.put(KEY_ENC_SMK_PWD, encoder.encodeToString(encPwd))
            DesktopStorage.put(KEY_SALT,        encoder.encodeToString(salt))
        } finally { key.fill(0) }
    }

    // ─── Симметричное шифрование данных с SMK ───────────────────────────────

    fun encrypt(data: ByteArray): ByteArray {
        val key = readSmk()
        return try {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
            val iv = cipher.iv  // 12 bytes
            iv + cipher.doFinal(data)
        } finally { key.fill(0) }
    }

    fun decrypt(data: ByteArray): ByteArray {
        val key = readSmk()
        return try {
            val iv  = data.copyOfRange(0, 12)
            val ct  = data.copyOfRange(12, data.size)
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            cipher.doFinal(ct)
        } finally { key.fill(0) }
    }

    // ─── Обёртки для SharedPreferences значений ─────────────────────────────

    fun wrapBytes(bytes: ByteArray): String =
        SMK_PREFIX + Base64.getEncoder().encodeToString(encrypt(bytes))

    fun unwrapBytes(stored: String): ByteArray {
        val decoder = Base64.getDecoder()
        if (!stored.startsWith(SMK_PREFIX)) {
            return decoder.decode(stored)
        }
        val blob = decoder.decode(stored.removePrefix(SMK_PREFIX))
        return decrypt(blob)
    }

    // ─── Внутренние методы ──────────────────────────────────────────────────

    private fun deriveKey(password: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITER, 256)
        val raw  = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(raw, "AES")
    }

    private fun encryptWithPassword(smkBytes: ByteArray, password: String, salt: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt))
        return cipher.iv + cipher.doFinal(smkBytes)
    }

    private fun decryptWithPassword(blob: ByteArray, password: String, salt: ByteArray): ByteArray {
        val iv  = blob.copyOfRange(0, 12)
        val ct  = blob.copyOfRange(12, blob.size)
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    private fun getOrCreateKsKey(): SecretKey {
        // Используем DesktopKeyStore для получения ключа шифрования SMK
        return DesktopKeyStore.getOrCreateStorageKey(DesktopStorage.resolveDataDir())
    }

    private fun encryptWithKeystore(smkBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKsKey())
        return cipher.iv + cipher.doFinal(smkBytes)
    }

    private fun decryptWithKeystore(blob: ByteArray): ByteArray {
        val key = getOrCreateKsKey()
        val iv  = blob.copyOfRange(0, 12)
        val ct  = blob.copyOfRange(12, blob.size)
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }
}
