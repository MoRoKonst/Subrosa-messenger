package com.subrosa.desktop

import java.util.Base64
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

    private fun hashPasswordLegacy(password: String): String {
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest(password.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun hashPasswordV2(password: String): String {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        return deriveV2(password, salt)
    }

    private fun deriveV2(password: String, salt: ByteArray): String {
        val spec = PBEKeySpec(password.toCharArray(), salt, 100_000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val hash = factory.generateSecret(spec).encoded
        val saltB64 = Base64.getEncoder().encodeToString(salt)
        val hashB64 = Base64.getEncoder().encodeToString(hash)
        return "v2:$saltB64:$hashB64"
    }

    private fun verifyPassword(password: String, stored: String): Boolean {
        return if (stored.startsWith("v2:")) {
            val parts = stored.split(":")
            if (parts.size != 3) return false
            try {
                val salt = Base64.getDecoder().decode(parts[1])
                deriveV2(password, salt) == stored
            } catch (e: Exception) { false }
        } else {
            hashPasswordLegacy(password) == stored
        }
    }

    // ─── Invite Code ─────────────────────────────────────────────────────────

    fun saveInviteCode(inviteCode: String) {
        DesktopStorage.put(KEY_INVITE_CODE, inviteCode)
    }

    fun getInviteCode(): String? {
        return DesktopStorage.get(KEY_INVITE_CODE)
    }

    // ─── Panic Password ───────────────────────────────────────────────────────

    fun setPanicPassword(panicPassword: String) {
        val hash = hashPasswordV2(panicPassword)
        DesktopStorage.put(KEY_PANIC_PASSWORD_HASH, hash)
    }

    fun hasPanicPassword(): Boolean {
        return DesktopStorage.contains(KEY_PANIC_PASSWORD_HASH)
    }

    fun isPanicPassword(password: String): Boolean {
        val savedHash = DesktopStorage.get(KEY_PANIC_PASSWORD_HASH) ?: return false
        return verifyPassword(password, savedHash)
    }

    // ─── Decoy Mode ──────────────────────────────────────────────────────────
    // Mirrors Android's isDecoyMode/getOrCreateDecoySelection. Once a panic
    // wipe has happened (EmergencyWipe.wipeForDecoyKeepAlive), decoy_mode
    // stays true forever on this device — logging in again, even with the
    // real original password (its hash is deliberately preserved across the
    // wipe for exactly this), shows the fake messenger, never the real one.

    fun isDecoyMode(): Boolean = DesktopStorage.getBoolean("decoy_mode", false)
    fun setDecoyMode(enabled: Boolean) = DesktopStorage.putBoolean("decoy_mode", enabled)

    /** Picks [count] stable (persisted) indices out of a [poolSize]-sized
     *  pool of fake chat templates, so the same decoy contact list shows up
     *  every time this device enters decoy mode rather than re-randomizing
     *  on every launch. */
    fun getOrCreateDecoySelection(poolSize: Int, count: Int = 6): List<Int> {
        return try {
            val saved = DesktopStorage.get("decoy_selection")
            if (!saved.isNullOrBlank()) {
                val indices = saved.split(",").mapNotNull { it.trim().toIntOrNull() }
                    .filter { it in 0 until poolSize }
                if (indices.size == count) return indices
            }
            val indices = (0 until poolSize).toList().shuffled().take(count)
            DesktopStorage.put("decoy_selection", indices.joinToString(","))
            indices
        } catch (_: Exception) {
            (0 until minOf(count, poolSize)).toList()
        }
    }

    // ─── Registration / Login ────────────────────────────────────────────────

    fun isRegistered(): Boolean {
        return DesktopStorage.contains(KEY_USERNAME)
    }

    fun register(username: String, password: String) {
        val randomPart = UUID.randomUUID().toString().take(4)
        val userId = "${username.lowercase()}_$randomPart"

        DesktopStorage.put(KEY_USERNAME, username)
        DesktopStorage.put(KEY_USER_ID, userId)
        DesktopStorage.put(KEY_PASSWORD_HASH, hashPasswordV2(password))
        DesktopStorage.put("display_name", username)
        println("UserStorage: Registered new user")
    }

    fun setUserId(userId: String) {
        DesktopStorage.put(KEY_USER_ID, userId)
    }

    fun changePassword(oldPassword: String, newPassword: String): Boolean {
        if (!checkPassword(oldPassword)) return false
        DesktopStorage.put(KEY_PASSWORD_HASH, hashPasswordV2(newPassword))
        return true
    }

    fun checkPassword(password: String): Boolean {
        val savedHash = DesktopStorage.get(KEY_PASSWORD_HASH) ?: return false
        if (!verifyPassword(password, savedHash)) return false
        if (!savedHash.startsWith("v2:")) {
            DesktopStorage.put(KEY_PASSWORD_HASH, hashPasswordV2(password))
            println("UserStorage: Password migrated from SHA-256 to PBKDF2+salt")
        }
        return true
    }

    fun getUsername(): String {
        return DesktopStorage.get(KEY_USERNAME) ?: ""
    }

    fun getUserId(): String {
        return DesktopStorage.get(KEY_USER_ID) ?: ""
    }

    /** Clears every field that makes this device "a registered account" —
     *  used by BackupManager.resetCompromisedIdentity() ("Меня
     *  скомпрометировали") so the app falls back to RegisterScreen and the
     *  NEXT registration mints a genuinely fresh identity (mirrors
     *  Android's UserStorage.resetIdentityFields()). Deliberately leaves
     *  device-level settings (TOTP secret is cleared separately by the
     *  caller, panic password, auto-lock timeout, cover traffic mode)
     *  untouched — unlike the full emergency wipe ("Это не я"), this is an
     *  identity rotation, not a duress wipe. */
    fun resetIdentityFields() {
        DesktopStorage.remove(KEY_USERNAME)
        DesktopStorage.remove(KEY_USER_ID)
        DesktopStorage.remove(KEY_PASSWORD_HASH)
        DesktopStorage.remove("display_name")
        DesktopStorage.remove(KEY_INVITE_CODE)
        DesktopStorage.remove("my_avatar_b64")
        // Mirrors Android's resetIdentityFields() — a pending list from an
        // earlier, unrelated backup restore that never reconnected must not
        // survive into a freshly reset identity: WebSocketClient would send
        // session_reset to contacts that have nothing to do with the new
        // identity at all. Added alongside this audit's own
        // setPendingSessionResetContacts()/getAndClearPendingSessionResetContacts().
        DesktopStorage.remove("pending_session_reset_contacts")
    }

    fun logout() {
        CryptoManager.deleteKeys()
        // SessionManager.clearSession() // need to adapt SessionManager
        // For desktop logout might mean clearing DesktopStorage
    }

    /** Persists contacts whose Double Ratchet session was just wiped by a
     *  backup restore, so WebSocketClient's "register_ok" handler can send
     *  each one a fresh session_reset/pq_bundle_refresh on the next
     *  successful reconnect and clear the flag — mirrors Android's
     *  UserStorage.setPendingSessionResetContacts()/
     *  getAndClearPendingSessionResetContacts() exactly. Without this, a
     *  restored contact keeps having messages sent against — or worse,
     *  received and misattributed to — the Double Ratchet ratchet state
     *  this device just wiped, with nothing telling either side to
     *  re-handshake. See BackupManager.importBackup(). */
    fun setPendingSessionResetContacts(contactIds: List<String>) {
        DesktopStorage.put("pending_session_reset_contacts", org.json.JSONArray(contactIds).toString())
    }

    fun getAndClearPendingSessionResetContacts(): List<String> {
        val json = DesktopStorage.get("pending_session_reset_contacts") ?: return emptyList()
        val contacts = try {
            val arr = org.json.JSONArray(json)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (_: Exception) {
            emptyList()
        }
        if (contacts.isNotEmpty()) {
            DesktopStorage.remove("pending_session_reset_contacts")
        }
        return contacts
    }

    fun saveUsername(username: String) {
        DesktopStorage.put(KEY_USERNAME, username)
    }

    fun saveUserDisplayName(name: String) {
        DesktopStorage.put("display_name", name)
    }

    fun getUserDisplayName(): String {
        return DesktopStorage.get("display_name") ?: getUsername()
    }

    fun getDeviceId(): String {
        val existing = DesktopStorage.get("device_id")
        if (existing != null) return existing
        return UUID.randomUUID().toString().also { newId ->
            DesktopStorage.put("device_id", newId)
        }
    }

    // ─── Emergency Wipe ───────────────────────────────────────────────────────

    fun isEmergencyWipeEnabled(): Boolean {
        return DesktopStorage.getBoolean("emergency_wipe_enabled", true)
    }

    fun setEmergencyWipeEnabled(enabled: Boolean) {
        DesktopStorage.putBoolean("emergency_wipe_enabled", enabled)
    }

    // ─── Tor ──────────────────────────────────────────────────────────────────
    // Mirrors Android's isTorEnabled toggle: routes ALL traffic through the
    // local Tor SOCKS proxy regardless of the server address, not just
    // .onion ones (WebSocketClient still force-routes .onion addresses
    // through Tor unconditionally on top of this, since those can't resolve
    // any other way).

    fun getTorEnabled(): Boolean = DesktopStorage.getBoolean("tor_enabled", false)
    fun setTorEnabled(enabled: Boolean) = DesktopStorage.putBoolean("tor_enabled", enabled)

    // "Hide IP during calls" — forces WebRTC's ICE transport policy to
    // RELAY-only (see DesktopCallManager's createPeerConnection()/
    // createGroupPeerConnection()), so media never takes a direct/host/srflx
    // path that would reveal either side's real IP to the other. Read fresh
    // on every new RTCPeerConnection, not cached — toggling mid-call
    // intentionally does not migrate the active call. Mirrors Android's
    // identical UserStorage.getHideIpDuringCalls()/setHideIpDuringCalls().
    fun getHideIpDuringCalls(): Boolean = DesktopStorage.getBoolean("hide_ip_during_calls", false)
    fun setHideIpDuringCalls(enabled: Boolean) = DesktopStorage.putBoolean("hide_ip_during_calls", enabled)

    // ─── Notification Content ────────────────────────────────────────────────

    fun getHideNotificationContent(): Boolean {
        return DesktopStorage.getBoolean("hide_notif_content", false)
    }

    fun setHideNotificationContent(hide: Boolean) {
        DesktopStorage.putBoolean("hide_notif_content", hide)
    }

    /** Whether DesktopNotificationService shows an OS toast at all. */
    fun getNotificationsEnabled(): Boolean = DesktopStorage.getBoolean("notifications_enabled", true)
    fun setNotificationsEnabled(enabled: Boolean) = DesktopStorage.putBoolean("notifications_enabled", enabled)

    /** Whether DesktopNotificationService plays its chime alongside the toast. */
    fun getNotificationSoundEnabled(): Boolean = DesktopStorage.getBoolean("notification_sound_enabled", true)
    fun setNotificationSoundEnabled(enabled: Boolean) = DesktopStorage.putBoolean("notification_sound_enabled", enabled)

    // ─── Per-chat mute ────────────────────────────────────────────────────────
    // 0 = not muted, Long.MAX_VALUE = muted indefinitely, otherwise an epoch-
    // millis expiry. Computed on read (muteUntil > now) rather than tracked
    // with a background unmute job — same idiom as ContactHealthManager's
    // cooldown checks elsewhere in this codebase.

    fun getContactMuteUntil(contactId: String): Long =
        DesktopStorage.get("mute_contact_$contactId")?.toLongOrNull() ?: 0L
    fun setContactMuteUntil(contactId: String, until: Long) =
        DesktopStorage.put("mute_contact_$contactId", until.toString())

    fun getGroupMuteUntil(groupId: String): Long =
        DesktopStorage.get("mute_group_$groupId")?.toLongOrNull() ?: 0L
    fun setGroupMuteUntil(groupId: String, until: Long) =
        DesktopStorage.put("mute_group_$groupId", until.toString())

    /** Independent of the duration-mute above: keeps the toast visible but
     *  skips DesktopNotificationService's chime. */
    fun getContactMuteSound(contactId: String): Boolean = DesktopStorage.getBoolean("mute_sound_contact_$contactId", false)
    fun setContactMuteSound(contactId: String, muted: Boolean) = DesktopStorage.putBoolean("mute_sound_contact_$contactId", muted)

    fun getGroupMuteSound(groupId: String): Boolean = DesktopStorage.getBoolean("mute_sound_group_$groupId", false)
    fun setGroupMuteSound(groupId: String, muted: Boolean) = DesktopStorage.putBoolean("mute_sound_group_$groupId", muted)

    // ─── Language ─────────────────────────────────────────────────────────────

    fun getLanguage(): String {
        return DesktopStorage.get("app_language") ?: "ru"
    }

    fun setLanguage(langCode: String) {
        DesktopStorage.put("app_language", langCode)
    }

    // ─── Theme ────────────────────────────────────────────────────────────────

    fun getTheme(): String {
        return DesktopStorage.get("app_theme") ?: "NAVY"
    }

    fun setTheme(theme: String) {
        DesktopStorage.put("app_theme", theme)
    }

    // ─── My Avatar ────────────────────────────────────────────────────────────

    fun saveMyAvatar(base64: String) {
        DesktopStorage.put("my_avatar_b64", base64)
    }

    fun getMyAvatar(): String? {
        return DesktopStorage.get("my_avatar_b64")
    }

    // ─── Security Settings ────────────────────────────────────────────────────

    fun getExitOnDebugger(): Boolean = DesktopStorage.getBoolean("exit_on_debugger", false)
    fun setExitOnDebugger(v: Boolean) = DesktopStorage.putBoolean("exit_on_debugger", v)

    /** Timeout in seconds; 0 = disabled */
    fun getAutoLockTimeout(): Int = DesktopStorage.get("auto_lock_timeout")?.toIntOrNull() ?: 0
    fun setAutoLockTimeout(seconds: Int) = DesktopStorage.put("auto_lock_timeout", seconds.toString())

    /** Cover traffic: constant-rate noise packets that mask real-message timing. Mirrors Android. */
    enum class CoverTrafficMode { OFF, MODERATE, AGGRESSIVE }

    fun getCoverTrafficMode(): CoverTrafficMode =
        runCatching { CoverTrafficMode.valueOf(DesktopStorage.get("cover_traffic_mode") ?: "OFF") }
            .getOrDefault(CoverTrafficMode.OFF)

    fun setCoverTrafficMode(mode: CoverTrafficMode) =
        DesktopStorage.put("cover_traffic_mode", mode.name)

    /** Per-chat auto-delete timer in seconds; 0 = disabled */
    fun getChatAutoDelete(contact: String): Long =
        DesktopStorage.get("auto_delete_$contact")?.toLongOrNull() ?: 0L
    fun setChatAutoDelete(contact: String, seconds: Long) =
        DesktopStorage.put("auto_delete_$contact", seconds.toString())
}
