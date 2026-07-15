package com.bcon.messenger

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import java.io.File

object WipeManager {

    enum class Level { SOFT, HARD, NUCLEAR }

    fun wipe(context: Context, level: Level, withDecoy: Boolean = false) {
        StorageKeyManager.lock()
        PanicNotificationManager.dismiss(context)
        when (level) {
            Level.SOFT    -> softWipe(context)
            Level.HARD    -> hardWipe(context, withDecoy)
            Level.NUCLEAR -> nuclearWipe(context, withDecoy)
        }
    }

    private fun softWipe(context: Context) {
        try {
            SessionKeyManager.deleteAllSessions()
            context.cacheDir.deleteRecursively()
            context.externalCacheDir?.deleteRecursively()
        } catch (_: Exception) {}
    }

    fun hardWipe(context: Context, withDecoy: Boolean = false) {
        StorageKeyManager.lock()

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

            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()

            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                listOf("_androidx_security_master_key", "_androidx_security_crypto_master_key_", "beacon_smk_wrap")
                    .filter { ks.containsAlias(it) }
                    .forEach { ks.deleteEntry(it) }
            } catch (_: Exception) {}

            val dataDir = context.applicationInfo.dataDir

            File(dataDir, "shared_prefs").deleteRecursively()

            context.filesDir.deleteRecursively()

            context.cacheDir.deleteRecursively()
            context.externalCacheDir?.deleteRecursively()

            File(dataDir, "databases").deleteRecursively()

            File(dataDir, "app_webview").deleteRecursively()

            File(dataDir, "no_backup").deleteRecursively()

            context.getExternalFilesDir(null)?.parentFile?.deleteRecursively()

            context.stopService(Intent(context, MessengerService::class.java))

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

    fun wipeForDecoyKeepAlive(context: Context) {
        StorageKeyManager.lock()
        try {

            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()

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

            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                listOf("_androidx_security_master_key", "_androidx_security_crypto_master_key_", "beacon_smk_wrap")
                    .filter { ks.containsAlias(it) }
                    .forEach { ks.deleteEntry(it) }
            } catch (_: Exception) {}

            val dataDir = context.applicationInfo.dataDir

            File(dataDir, "shared_prefs").deleteRecursively()
            context.filesDir.deleteRecursively()
            context.cacheDir.deleteRecursively()
            context.externalCacheDir?.deleteRecursively()
            File(dataDir, "databases").deleteRecursively()
            File(dataDir, "app_webview").deleteRecursively()
            File(dataDir, "no_backup").deleteRecursively()
            context.getExternalFilesDir(null)?.parentFile?.deleteRecursively()
            context.stopService(Intent(context, MessengerService::class.java))

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

        } catch (_: Exception) {}
    }

    private fun nuclearWipe(context: Context, withDecoy: Boolean = false) {
        try {

            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()

            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                listOf("_androidx_security_master_key", "_androidx_security_crypto_master_key_", "beacon_smk_wrap")
                    .filter { ks.containsAlias(it) }
                    .forEach { ks.deleteEntry(it) }
            } catch (_: Exception) {}
        } catch (_: Exception) {}

        try {
            val am = context.getSystemService(ActivityManager::class.java)
            am.clearApplicationUserData()
        } catch (_: Exception) {

            hardWipe(context, withDecoy)
        }
    }
}
