package com.bcon.messenger

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import java.io.File

/**
 * Централизованный менеджер уничтожения данных.
 *
 * SOFT   — кэши + сессии в RAM. Данные восстановимы при следующем входе.
 * HARD   — полное крипто-уничтожение: ключи удалены, зашифрованные файлы
 *          нечитаемы. Идентично бывшему emergencyWipe().
 * NUCLEAR — HARD + ActivityManager.clearApplicationUserData() для
 *           системной гарантии очистки. Убивает процесс самостоятельно.
 */
object WipeManager {

    enum class Level { SOFT, HARD, NUCLEAR }

    fun wipe(context: Context, level: Level, withDecoy: Boolean = false) {
        StorageKeyManager.lock()  // Обнулить SMK из памяти первым делом
        PanicNotificationManager.dismiss(context)
        when (level) {
            Level.SOFT    -> softWipe(context)
            Level.HARD    -> hardWipe(context, withDecoy)
            Level.NUCLEAR -> nuclearWipe(context, withDecoy)
        }
    }

    // ── Soft: только кэши и in-memory сессии ─────────────────────────────────

    private fun softWipe(context: Context) {
        try {
            SessionKeyManager.deleteAllSessions()
            context.cacheDir.deleteRecursively()
            context.externalCacheDir?.deleteRecursively()
        } catch (_: Exception) {}
    }

    // ── Hard: полное крипто-уничтожение (бывший emergencyWipe) ───────────────

    fun hardWipe(context: Context, withDecoy: Boolean = false) {
        StorageKeyManager.lock()  // Обнулить SMK если вызов напрямую (минуя wipe())
        // ── Сохраняем данные ДО вайпа ────────────────────────────────────────
        var savedPasswordHash: String? = null
        var savedUsername: String? = null
        var savedUserId: String? = null
        var savedCalcDisguise = false
        try {
            val enc = EncryptedStorage.getEncryptedPrefs(context, "user_prefs")
            savedCalcDisguise = enc.getBoolean("calculator_disguise", false)
            if (withDecoy) {
                savedPasswordHash = enc.getString("password_hash", null)
                savedUsername     = enc.getString("username",      null)
                savedUserId       = enc.getString("user_id",       null)
            }
        } catch (_: Exception) {}

        try {
            // 0. RAM: обнуляем секреты до удаления файлов
            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()

            // 1. AndroidKeyStore master-ключи EncryptedSharedPreferences
            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                listOf("_androidx_security_master_key", "_androidx_security_crypto_master_key_", "beacon_smk_wrap")
                    .filter { ks.containsAlias(it) }
                    .forEach { ks.deleteEntry(it) }
            } catch (_: Exception) {}

            val dataDir = context.applicationInfo.dataDir

            // 2. SharedPreferences (обычные и EncryptedSharedPreferences)
            File(dataDir, "shared_prefs").deleteRecursively()

            // 3. Внутренние файлы (вложения, honey token и т.д.)
            context.filesDir.deleteRecursively()

            // 4. Кэш и временные файлы
            context.cacheDir.deleteRecursively()
            context.externalCacheDir?.deleteRecursively()

            // 5. Базы данных SQLite
            File(dataDir, "databases").deleteRecursively()

            // 6. WebView-данные
            File(dataDir, "app_webview").deleteRecursively()

            // 7. no_backup
            File(dataDir, "no_backup").deleteRecursively()

            // 8. Внешнее хранилище приложения
            context.getExternalFilesDir(null)?.parentFile?.deleteRecursively()

            // 9. Останавливаем сервис
            context.stopService(Intent(context, MessengerService::class.java))

            // ── Recovery state ────────────────────────────────────────────────
            if (savedUsername != null && savedPasswordHash != null || savedCalcDisguise) {
                try {
                    val ed = context.getSharedPreferences("beacon_recovery", Context.MODE_PRIVATE).edit()
                    if (savedUsername != null && savedPasswordHash != null) {
                        ed.putString("username",      savedUsername)
                            .putString("user_id",       savedUserId ?: "")
                            .putString("password_hash", savedPasswordHash)
                    }
                    if (savedCalcDisguise) ed.putBoolean("calculator_disguise", true)
                    ed.commit()
                } catch (_: Exception) {}
            }
        } catch (e: Exception) {
            android.util.Log.e("WipeManager", "Ошибка hard wipe: ${e.message}", e)
        } finally {
            android.os.Process.killProcess(android.os.Process.myPid())
        }
    }

    // ── Decoy-safe: вайп без убийства процесса ───────────────────────────────
    // Вызывается при вводе panic password: данные стираются в фоне пока
    // DecoyScreen уже отображается. Процесс остаётся живым — никакого
    // подозрительного перезапуска. При следующем холодном старте
    // UserStorage.migrateDecoyState() восстанавливает decoy-credentials.

    fun wipeForDecoyKeepAlive(context: Context) {
        StorageKeyManager.lock()
        try {
            // 1. Зануляем секреты в RAM
            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()

            // 2. Сохраняем recovery state ДО удаления prefs
            var savedPasswordHash: String? = null
            var savedUsername: String? = null
            var savedUserId: String? = null
            var savedCalcDisguise = false
            try {
                val enc = EncryptedStorage.getEncryptedPrefs(context, "user_prefs")
                savedPasswordHash = enc.getString("password_hash", null)
                savedUsername     = enc.getString("username",      null)
                savedUserId       = enc.getString("user_id",       null)
                savedCalcDisguise = enc.getBoolean("calculator_disguise", false)
            } catch (_: Exception) {}

            // 3. Удаляем AndroidKeyStore master-ключи EncryptedSharedPreferences
            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                listOf("_androidx_security_master_key", "_androidx_security_crypto_master_key_", "beacon_smk_wrap")
                    .filter { ks.containsAlias(it) }
                    .forEach { ks.deleteEntry(it) }
            } catch (_: Exception) {}

            val dataDir = context.applicationInfo.dataDir

            // 4. Удаляем все данные
            File(dataDir, "shared_prefs").deleteRecursively()
            context.filesDir.deleteRecursively()
            context.cacheDir.deleteRecursively()
            context.externalCacheDir?.deleteRecursively()
            File(dataDir, "databases").deleteRecursively()
            File(dataDir, "app_webview").deleteRecursively()
            File(dataDir, "no_backup").deleteRecursively()
            context.getExternalFilesDir(null)?.parentFile?.deleteRecursively()
            context.stopService(Intent(context, MessengerService::class.java))

            // 5. Сохраняем recovery для следующего холодного старта
            if (savedUsername != null && savedPasswordHash != null || savedCalcDisguise) {
                val ed = context.getSharedPreferences("beacon_recovery", Context.MODE_PRIVATE).edit()
                if (savedUsername != null && savedPasswordHash != null) {
                    ed.putString("username",      savedUsername)
                        .putString("user_id",       savedUserId ?: "")
                        .putString("password_hash", savedPasswordHash)
                }
                if (savedCalcDisguise) ed.putBoolean("calculator_disguise", true)
                ed.commit()
            }
            // Процесс остаётся живым — DecoyScreen продолжает отображаться
        } catch (_: Exception) {}
    }

    // ── Nuclear: hard + системная очистка ────────────────────────────────────
    // Вызов hardWipe не нужен отдельно — clearApplicationUserData() уничтожает
    // всё приложение системно. Но сначала обнуляем ключи в RAM и KeyStore.

    private fun nuclearWipe(context: Context, withDecoy: Boolean = false) {
        try {
            // Обнуляем RAM
            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()
            // Удаляем AndroidKeyStore ключи
            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                listOf("_androidx_security_master_key", "_androidx_security_crypto_master_key_", "beacon_smk_wrap")
                    .filter { ks.containsAlias(it) }
                    .forEach { ks.deleteEntry(it) }
            } catch (_: Exception) {}
        } catch (_: Exception) {}

        // Системный atomic wipe — убивает процесс самостоятельно
        try {
            val am = context.getSystemService(ActivityManager::class.java)
            am.clearApplicationUserData()
        } catch (_: Exception) {
            // Fallback: если clearApplicationUserData недоступен — hard wipe
            hardWipe(context, withDecoy)
        }
    }
}
