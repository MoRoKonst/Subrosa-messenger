package com.subrosa.desktop

/**
 * Replaces Android's EncryptedSharedPreferences.
 *
 * Data is stored as AES-256-GCM encrypted JSON in:
 *   Windows : %APPDATA%\BeaconMessenger\storage.enc
 *   Linux   : ~/.config/BeaconMessenger/storage.enc
 *   macOS   : ~/Library/Application Support/BeaconMessenger/storage.enc
 *
 * The encryption key lives in a PKCS12 keystore next to the data file
 * (see DesktopKeyStore). On first run both files are created automatically.
 */

import kotlinx.serialization.json.*
import java.io.File
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

object DesktopStorage {

    private val dataDir: File by lazy {
        val os = System.getProperty("os.name", "").lowercase()
        val base = when {
            os.contains("win")   -> File(System.getenv("APPDATA")  ?: System.getProperty("user.home"))
            os.contains("mac")   -> File(System.getProperty("user.home"), "Library/Application Support")
            else                 -> File(System.getProperty("user.home"), ".config")
        }
        File(base, "BeaconMessenger").also { dir ->
            dir.mkdirs()
            restrictToOwnerIfPosix(dir)
        }
    }

    /**
     * On Linux/macOS, the default umask can leave ~/.config subdirectories
     * group/world-readable, letting another local account on a shared machine
     * read storage.enc / the PKCS12 keystore. Windows profiles are already
     * private via NTFS ACLs, so this only applies off-Windows.
     */
    private fun restrictToOwnerIfPosix(dir: File) {
        if (System.getProperty("os.name", "").lowercase().contains("win")) return
        try {
            val path = dir.toPath()
            val perms = java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")
            java.nio.file.Files.setPosixFilePermissions(path, perms)
        } catch (_: Exception) { /* non-POSIX filesystem — nothing to do */ }
    }

    private val storageFile: File get() = File(dataDir, "storage.enc")

    // ── In-memory map (loaded once, flushed on every write) ──────────────────
    private val map = mutableMapOf<String, String>()
    private var secretKey: SecretKey? = null

    fun init() {
        secretKey = DesktopKeyStore.getOrCreateStorageKey(dataDir)
        if (storageFile.exists()) {
            try {
                val plain = decrypt(storageFile.readBytes())
                val json  = Json.parseToJsonElement(plain).jsonObject
                json.forEach { (k, v) -> map[k] = v.jsonPrimitive.content }
            } catch (e: Exception) {
                System.err.println("DesktopStorage: failed to load — ${e.message}")
            }
        }
    }

    // ── Public API (mirrors SharedPreferences) ────────────────────────────────

    fun get(key: String): String? = map[key]

    fun getBoolean(key: String, default: Boolean = false): Boolean =
        map[key]?.toBooleanStrictOrNull() ?: default

    fun getInt(key: String, default: Int = 0): Int =
        map[key]?.toIntOrNull() ?: default

    fun put(key: String, value: String) {
        map[key] = value
        flush()
    }

    fun putBoolean(key: String, value: Boolean) = put(key, value.toString())

    fun putInt(key: String, value: Int) = put(key, value.toString())

    fun remove(key: String) {
        map.remove(key)
        flush()
    }

    fun contains(key: String): Boolean = map.containsKey(key)

    fun getAllKeys(): Set<String> = map.keys

    /** Expose the resolved data directory (used by DesktopKeyStore / DesktopCryptoManager). */
    fun resolveDataDir(): java.io.File = dataDir

    // ── Persistence ───────────────────────────────────────────────────────────

    private fun flush() {
        try {
            val json  = JsonObject(map.mapValues { JsonPrimitive(it.value) }).toString()
            storageFile.writeBytes(encrypt(json))
        } catch (e: Exception) {
            System.err.println("DesktopStorage: flush failed — ${e.message}")
        }
    }

    // ── Secure deletion ───────────────────────────────────────────────────────

    /**
     * Безопасное удаление: 3 прохода (случайные → нули → delete) + fsync.
     * Снижает вероятность восстановления данных криминалистическими инструментами.
     * Не защищает от SSD wear-levelling и journaling FS на уровне блоков.
     */
    fun secureDelete(file: File) {
        if (!file.exists()) return
        val size = maxOf(file.length(), 1L)
        val rng  = SecureRandom()
        val buf  = ByteArray(4096)
        // Проход 1: случайные данные
        file.outputStream().use { out ->
            var rem = size
            while (rem > 0) {
                rng.nextBytes(buf)
                val n = minOf(rem, buf.size.toLong()).toInt()
                out.write(buf, 0, n); rem -= n
            }
            out.flush(); try { out.fd.sync() } catch (_: Exception) {}
        }
        // Проход 2: нули
        buf.fill(0)
        file.outputStream().use { out ->
            var rem = size
            while (rem > 0) {
                val n = minOf(rem, buf.size.toLong()).toInt()
                out.write(buf, 0, n); rem -= n
            }
            out.flush(); try { out.fd.sync() } catch (_: Exception) {}
        }
        file.delete()
    }

    /** Безопасно уничтожить всё хранилище (panic / factory reset). */
    fun secureWipeAll() {
        secureDelete(storageFile)
        map.clear()
        secretKey = null
    }

    // ── AES-256-GCM helpers ───────────────────────────────────────────────────

    private fun encrypt(plain: String): ByteArray {
        val key    = secretKey ?: error("DesktopStorage not initialised")
        val iv     = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        // layout: [12 bytes IV][ciphertext+tag]
        return ByteBuffer.allocate(12 + ct.size).put(iv).put(ct).array()
    }

    private fun decrypt(data: ByteArray): String {
        val key    = secretKey ?: error("DesktopStorage not initialised")
        val iv     = data.copyOfRange(0, 12)
        val ct     = data.copyOfRange(12, data.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    // ── Binary file encryption (изображения / файлы на диске) ────────────────
    // Тот же машинно-привязанный ключ что и у storage.enc.
    // Формат: [12 bytes IV][ciphertext+tag]

    fun encryptRaw(data: ByteArray): ByteArray {
        val key    = secretKey ?: error("DesktopStorage not initialised")
        val iv     = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(data)
        return ByteBuffer.allocate(12 + ct.size).put(iv).put(ct).array()
    }

    fun decryptRaw(data: ByteArray): ByteArray {
        val key    = secretKey ?: error("DesktopStorage not initialised")
        val iv     = data.copyOfRange(0, 12)
        val ct     = data.copyOfRange(12, data.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }
}
