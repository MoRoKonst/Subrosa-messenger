package com.bcon.messenger

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object UserStorage {

    private const val PREFS_NAME = "user_prefs"
    private const val KEY_USERNAME = "username"
    private const val KEY_USER_ID = "user_id"
    private const val KEY_PASSWORD_HASH = "password_hash"
    private const val KEY_INVITE_CODE = "invite_code"
    private const val KEY_PANIC_PASSWORD_HASH = "panic_password_hash"

    // ─── Password Hashing ────────────────────────────────────────────────────

    /**
     * Legacy SHA-256 (без соли) — используется ТОЛЬКО для миграции старых аккаунтов.
     * Новые пароли всегда хэшируются через [hashPasswordV2].
     */
    private fun hashPasswordLegacy(password: String): String {
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest(password.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * PBKDF2WithHmacSHA256 + случайная 16-байтная соль, 100 000 итераций.
     * Возвращает строку вида "v2:<saltBase64>:<hashBase64>".
     */
    private fun hashPasswordV2(password: String): String {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        return deriveV2(password, salt)
    }

    private fun deriveV2(password: String, salt: ByteArray): String {
        val spec = PBEKeySpec(password.toCharArray(), salt, 100_000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val hash = factory.generateSecret(spec).encoded
        val saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP)
        val hashB64 = Base64.encodeToString(hash, Base64.NO_WRAP)
        return "v2:$saltB64:$hashB64"
    }

    /**
     * Проверяет пароль против сохранённого хэша.
     * Поддерживает оба формата:
     *   - Старый: чистый hex SHA-256 (без префикса)
     *   - Новый:  "v2:<saltBase64>:<hashBase64>" — PBKDF2WithHmacSHA256
     */
    private fun verifyPassword(password: String, stored: String): Boolean {
        return if (stored.startsWith("v2:")) {
            val parts = stored.split(":")
            if (parts.size != 3) return false
            try {
                val salt = Base64.decode(parts[1], Base64.NO_WRAP)
                deriveV2(password, salt) == stored
            } catch (e: Exception) { false }
        } else {
            // Обратная совместимость: сравниваем с legacy SHA-256
            hashPasswordLegacy(password) == stored
        }
    }

    // ─── Invite Code ─────────────────────────────────────────────────────────

    fun saveInviteCode(context: Context, inviteCode: String) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit()
            .putString(KEY_INVITE_CODE, inviteCode)
            .apply()
    }

    fun getInviteCode(context: Context): String? {
        return EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString(KEY_INVITE_CODE, null)
    }

    // ─── Panic Password ───────────────────────────────────────────────────────

    fun setPanicPassword(context: Context, panicPassword: String) {
        val hash = hashPasswordV2(panicPassword)
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit()
            .putString(KEY_PANIC_PASSWORD_HASH, hash)
            .apply()
    }

    fun hasPanicPassword(context: Context): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.contains(KEY_PANIC_PASSWORD_HASH)
    }

    fun isPanicPassword(context: Context, password: String): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val savedHash = prefs.getString(KEY_PANIC_PASSWORD_HASH, null) ?: return false
        return verifyPassword(password, savedHash)
    }

    // ─── Registration / Login ────────────────────────────────────────────────

    fun isRegistered(context: Context): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.contains(KEY_USERNAME)
    }

    fun register(context: Context, username: String, password: String) {
        // Генерируем уникальный ID: username_xxxx
        val randomPart = UUID.randomUUID().toString().take(4)
        val userId = "${username.lowercase()}_$randomPart"

        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit()
            .putString(KEY_USERNAME, username)
            .putString(KEY_USER_ID, userId)
            .putString(KEY_PASSWORD_HASH, hashPasswordV2(password))   // PBKDF2 + salt
            .putString("display_name", username)
            .apply()
        android.util.Log.d("UserStorage", "Registered new user")
    }

    fun setUserId(context: Context, userId: String) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit()
            .putString(KEY_USER_ID, userId)
            .apply()
    }

    /**
     * Проверяет пароль.
     * При успешной проверке старого SHA-256 хэша автоматически мигрирует на v2 (PBKDF2).
     */
    fun checkPassword(context: Context, password: String): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val savedHash = prefs.getString(KEY_PASSWORD_HASH, null) ?: return false
        if (!verifyPassword(password, savedHash)) return false
        // Автомиграция с legacy SHA-256 → PBKDF2+salt
        if (!savedHash.startsWith("v2:")) {
            prefs.edit().putString(KEY_PASSWORD_HASH, hashPasswordV2(password)).apply()
            android.util.Log.i("UserStorage", "Пароль мигрирован с SHA-256 на PBKDF2+salt")
        }
        return true
    }

    fun getUsername(context: Context): String {
        return EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString(KEY_USERNAME, "") ?: ""
    }

    fun getUserId(context: Context): String {
        return EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString(KEY_USER_ID, "") ?: ""
    }

    fun logout(context: Context) {
        CryptoManager.deleteKeys()
        SessionManager.clearSession(context)
        context.deleteSharedPreferences(PREFS_NAME)
        context.deleteSharedPreferences("chat_storage_encrypted")
        context.deleteSharedPreferences("message_queue")
    }

    fun saveUsername(context: Context, username: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().putString(KEY_USERNAME, username).apply()
    }

    fun saveUserDisplayName(context: Context, name: String) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit()
            .putString("display_name", name)
            .apply()
    }

    fun getUserDisplayName(context: Context): String {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.getString("display_name", null) ?: getUsername(context)
    }

    // ─── Device ID ───────────────────────────────────────────────────────────

    // Уникальный ID устройства — генерируется один раз при первом запуске.
    // Хранится в ЗАШИФРОВАННЫХ prefs (EncryptedSharedPreferences), чтобы исключить
    // утечку через незашифрованный app_prefs (другие приложения с правами чтения).
    // При первом вызове после обновления выполняется автоматическая миграция.
    fun getDeviceId(context: Context): String {
        val encPrefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        // Уже мигрировано / изначально в зашифрованном хранилище
        val existing = encPrefs.getString("device_id", null)
        if (existing != null) return existing
        // Миграция: device_id был в незашифрованных prefs → переносим
        val plainPrefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
        val fromPlain = plainPrefs.getString("device_id", null)
        if (fromPlain != null) {
            encPrefs.edit().putString("device_id", fromPlain).apply()
            plainPrefs.edit().remove("device_id").apply()
            return fromPlain
        }
        // Первый запуск — генерируем новый UUID
        return UUID.randomUUID().toString().also { newId ->
            encPrefs.edit().putString("device_id", newId).apply()
        }
    }

    // ─── Emergency Wipe ───────────────────────────────────────────────────────

    fun isEmergencyWipeEnabled(context: Context): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.getBoolean("emergency_wipe_enabled", true) // По умолчанию включено
    }

    fun setEmergencyWipeEnabled(context: Context, enabled: Boolean) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().putBoolean("emergency_wipe_enabled", enabled).apply()
    }

    // ─── Panic Button (lock screen notification) ──────────────────────────────

    fun getPanicButtonEnabled(context: Context): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.getBoolean("panic_button_enabled", false)
    }

    fun setPanicButtonEnabled(context: Context, enabled: Boolean) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().putBoolean("panic_button_enabled", enabled).apply()
    }

    fun getPanicButtonDecoy(context: Context): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.getBoolean("panic_button_decoy", false)
    }

    fun setPanicButtonDecoy(context: Context, enabled: Boolean) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().putBoolean("panic_button_decoy", enabled).apply()
    }

    // ─── Calculator Disguise ──────────────────────────────────────────────────

    fun getCalculatorDisguise(context: Context): Boolean {
        return EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getBoolean("calculator_disguise", false)
    }

    fun setCalculatorDisguise(context: Context, enabled: Boolean) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putBoolean("calculator_disguise", enabled).apply()
        // Переключаем иконку/название в лончере
        val pm = context.packageManager
        val pkg = context.packageName
        pm.setComponentEnabledSetting(
            android.content.ComponentName(pkg, "$pkg.CalculatorLauncher"),
            if (enabled) android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            else android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            android.content.pm.PackageManager.DONT_KILL_APP
        )
        pm.setComponentEnabledSetting(
            android.content.ComponentName(pkg, "$pkg.MainLauncher"),
            if (enabled) android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            else android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
            android.content.pm.PackageManager.DONT_KILL_APP
        )
    }

    // ─── Paranoid Mode ────────────────────────────────────────────────────────

    fun getParanoidMode(context: Context): Boolean {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.getBoolean("paranoid_mode", false)
    }

    fun setParanoidMode(context: Context, enabled: Boolean) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().putBoolean("paranoid_mode", enabled).apply()
    }

    // ─── HoneyToken ──────────────────────────────────────────────────────────

    fun getHoneyHash(context: Context): String =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString("honey_integrity_hash", "") ?: ""

    fun setHoneyHash(context: Context, hash: String) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putString("honey_integrity_hash", hash).apply()
    }

    // ─── Alert URL ───────────────────────────────────────────────────────────

    fun getAlertUrl(context: Context): String =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString("paranoid_alert_url", "") ?: ""

    fun setAlertUrl(context: Context, url: String) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putString("paranoid_alert_url", url).apply()
    }

    // ─── Dead Man's Switch ───────────────────────────────────────────────────

    fun getDmsEnabled(context: Context): Boolean =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getBoolean("dms_enabled", false)

    fun setDmsEnabled(context: Context, v: Boolean) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putBoolean("dms_enabled", v).apply()
    }

    fun getDmsIntervalHours(context: Context): Int =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getInt("dms_interval_hours", 24)

    fun setDmsIntervalHours(context: Context, h: Int) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putInt("dms_interval_hours", h).apply()
    }

    fun getDmsLastCheckin(context: Context): Long =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getLong("dms_last_checkin", 0L)

    fun setDmsLastCheckin(context: Context, ts: Long) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putLong("dms_last_checkin", ts).apply()
    }

    // ─── Timeout Wipe ────────────────────────────────────────────────────────

    fun getTimeoutWipeHours(context: Context): Int =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getInt("timeout_wipe_hours", 0)

    fun setTimeoutWipeHours(context: Context, h: Int) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putInt("timeout_wipe_hours", h).apply()
    }

    fun getLastPasswordEntry(context: Context): Long =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getLong("last_password_entry", 0L)

    fun setLastPasswordEntry(context: Context, ts: Long) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putLong("last_password_entry", ts).apply()
    }

    // ─── Wipe on Breach ──────────────────────────────────────────────────────

    fun getWipeOnBreach(context: Context): Boolean =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getBoolean("wipe_on_breach", false)

    fun setWipeOnBreach(context: Context, v: Boolean) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putBoolean("wipe_on_breach", v).apply()
    }

    fun getBreachWipeLevel(context: Context): String =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString("breach_wipe_level", "HARD") ?: "HARD"

    fun setBreachWipeLevel(context: Context, level: String) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putString("breach_wipe_level", level).apply()
    }

    // ─── Notification Content ────────────────────────────────────────────────

    fun getHideNotificationContent(context: Context): Boolean {
        return EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getBoolean("hide_notif_content", false)
    }

    fun setHideNotificationContent(context: Context, hide: Boolean) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putBoolean("hide_notif_content", hide).apply()
    }

    // ─── Auto-Lock ────────────────────────────────────────────────────────────

    // 0 = выкл, иначе количество секунд неактивности до блокировки
    fun getAutoLockTimeout(context: Context): Int {
        return EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getInt("auto_lock_timeout", 0)
    }

    fun setAutoLockTimeout(context: Context, seconds: Int) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putInt("auto_lock_timeout", seconds).apply()
    }

    // ─── Language ─────────────────────────────────────────────────────────────

    /** "ru" или "en" */
    fun getLanguage(context: Context): String {
        return context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
            .getString("app_language", "ru") ?: "ru"
    }

    fun setLanguage(context: Context, langCode: String) {
        context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
            .edit().putString("app_language", langCode).apply()
    }

    // ─── Theme ────────────────────────────────────────────────────────────────

    fun getTheme(context: Context): com.bcon.messenger.ui.theme.BeaconTheme {
        val name = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
            .getString("app_theme", com.bcon.messenger.ui.theme.BeaconTheme.NAVY.name)
            ?: com.bcon.messenger.ui.theme.BeaconTheme.NAVY.name
        return try {
            com.bcon.messenger.ui.theme.BeaconTheme.valueOf(name)
        } catch (e: Exception) {
            com.bcon.messenger.ui.theme.BeaconTheme.NAVY
        }
    }

    fun setTheme(context: Context, theme: com.bcon.messenger.ui.theme.BeaconTheme) {
        context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
            .edit().putString("app_theme", theme.name).apply()
    }

    // ─── Constant-Rate Cover Traffic ────────────────────────────────────────

    enum class CoverTrafficMode { OFF, MODERATE, AGGRESSIVE }

    fun getCoverTrafficMode(context: Context): CoverTrafficMode {
        val v = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
            .getString("cover_traffic_mode", CoverTrafficMode.OFF.name) ?: CoverTrafficMode.OFF.name
        return try { CoverTrafficMode.valueOf(v) } catch (e: Exception) { CoverTrafficMode.OFF }
    }

    fun setCoverTrafficMode(context: Context, mode: CoverTrafficMode) {
        context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
            .edit().putString("cover_traffic_mode", mode.name).apply()
    }

    // ─── Post-Wipe Decoy Mode ────────────────────────────────────────────────

    /**
     * После экстренного вайпа emergencyWipe() записывает минимальные учётные данные
     * в незашифрованные SharedPreferences ("beacon_recovery").
     * При следующем запуске приложения этот метод переносит их в свежий
     * EncryptedSharedPreferences и выставляет флаг decoy_mode.
     * Пользователь вводит свой настоящий пароль → видит фейковые чаты.
     */
    fun migrateDecoyState(context: Context) {
        val recovery = context.getSharedPreferences("beacon_recovery", Context.MODE_PRIVATE)

        // Восстанавливаем маскировку калькулятора (независимо от decoy-аккаунта)
        if (recovery.getBoolean("calculator_disguise", false)) {
            setCalculatorDisguise(context, true)
            // Надёжный plain-prefs сигнал для onUnlock: показать DecoyScreen
            context.getSharedPreferences("beacon_ui_state", Context.MODE_PRIVATE)
                .edit().putBoolean("calc_pending_decoy", true).apply()
        }

        val username     = recovery.getString("username",      null)
        val passwordHash = recovery.getString("password_hash", null)
        if (username == null || passwordHash == null) {
            recovery.edit().clear().apply()
            return
        }
        val userId = recovery.getString("user_id", "") ?: ""

        try {
            val enc = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            if (!enc.contains(KEY_USERNAME)) {  // только если прошёл полный вайп
                enc.edit()
                    .putString(KEY_USERNAME,      username)
                    .putString(KEY_USER_ID,       userId)
                    .putString(KEY_PASSWORD_HASH, passwordHash)
                    .putBoolean("decoy_mode",     true)
                    .commit()
            }
        } catch (_: Exception) {}

        recovery.edit().clear().apply()  // удаляем временный файл
    }

    /** Возвращает true если устройство находится в режиме фейка после экстренного вайпа. */
    fun isDecoyMode(context: Context): Boolean {
        return try {
            EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
                .getBoolean("decoy_mode", false)
        } catch (_: Exception) { false }
    }

    /**
     * Возвращает сохранённые индексы фейковых чатов (случайный выбор из пула).
     * При первом вызове выбирает [count] случайных индексов из [poolSize] и сохраняет.
     * Один и тот же набор отображается между перезапусками — полиция не заметит расхождений.
     * После нового вайпа+decoy пул пересоздаётся заново.
     */
    fun getOrCreateDecoySelection(context: Context, poolSize: Int, count: Int = 6): List<Int> {
        return try {
            val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            val saved = prefs.getString("decoy_selection", null)
            if (!saved.isNullOrBlank()) {
                val indices = saved.split(",").mapNotNull { it.trim().toIntOrNull() }
                    .filter { it in 0 until poolSize }
                if (indices.size == count) return indices
            }
            val indices = (0 until poolSize).toList().shuffled().take(count)
            prefs.edit().putString("decoy_selection", indices.joinToString(",")).apply()
            indices
        } catch (_: Exception) {
            (0 until minOf(count, poolSize)).toList()
        }
    }

    // ─── My Avatar ────────────────────────────────────────────────────────────

    /** Сохраняет свой аватар как base64-строку (JPEG 128×128). */
    fun saveMyAvatar(context: Context, base64: String) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putString("my_avatar_b64", base64).apply()
    }

    /** Возвращает сохранённый base64-аватар или null если не установлен. */
    fun getMyAvatar(context: Context): String? {
        return EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString("my_avatar_b64", null)
    }
}
