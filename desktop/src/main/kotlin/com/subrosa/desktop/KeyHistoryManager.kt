package com.subrosa.desktop

import org.json.JSONArray
import org.json.JSONObject

/**
 * Desktop port of Android's KeyHistoryManager (TOFU key-history store).
 * Field-for-field mirror of app/src/main/java/com/example/test/
 * KeyHistoryManager.kt, backed by DesktopStorage instead of
 * EncryptedSharedPreferences. See WebSocketClient's "prekey_bundle_response"
 * handler for where checkKeyChange()/the "revoked" flag drive
 * onKeyChanged/onContactRevoked, and ui/ChatScreen.kt for the warning
 * dialogs that consume them.
 */
object KeyHistoryManager {
    private const val PREFIX = "key_history_"

    // Serializes every read-modify-write on a contact's history — mirrors
    // Android's KeyHistoryManager exactly (same reasoning as
    // AnonTokenManager/GroupManager/SessionKeyManager elsewhere in this
    // codebase). WebSocketClient dispatches per-message handling in
    // separate coroutines, so two calls for the same contactId (e.g. a
    // prekey_bundle_response and a session_init landing close together) can
    // race; a shared lock (not per-function) closes the whole class of
    // races, not just one call site's own window. Found in the 2026-09-13
    // KeyHistoryManager audit.
    private val lock = Any()

    data class KeyRecord(
        val publicKey: String,
        val timestamp: Long,
        val verified: Boolean = false
    )

    /** Returns true iff [newKey] differs from the most recently recorded key
     *  for [contactId] (false for the very first key ever seen). A changed
     *  key is APPENDED here as a new, unverified record before returning —
     *  was previously detected but never recorded, so history.last() stayed
     *  pinned to the OLD key forever: every later fetch of the SAME (by
     *  then already-adopted) new key kept re-triggering this same "changed"
     *  branch indefinitely, and markAsVerified()/isVerified() (which always
     *  operate on history.last()) ended up reading/marking the stale OLD
     *  record instead of the key actually in use. Appending here makes
     *  history.last() always equal "the key currently treated as this
     *  contact's identity". Mirrors Android's fix exactly — found in the
     *  2026-09-13 KeyHistoryManager audit. */
    fun checkKeyChange(contactId: String, newKey: String): Boolean = synchronized(lock) {
        val history = getHistory(contactId)
        if (history.isEmpty()) {
            addKey(contactId, newKey)
            return@synchronized false
        }
        val lastKey = history.last().publicKey
        if (lastKey == newKey) return@synchronized false
        addKey(contactId, newKey)
        true
    }

    fun getHistory(contactId: String): List<KeyRecord> {
        val raw = DesktopStorage.get(PREFIX + contactId) ?: "[]"
        val json = if (raw.startsWith(StorageKeyManager.SMK_PREFIX)) {
            String(StorageKeyManager.unwrapBytes(raw), Charsets.UTF_8)
        } else {
            // Self-heal legacy/plain-JSON history — mirrors the same fix
            // applied to ChatStorage/GroupManager/SessionKeyManager this
            // audit: a history saved while locked (saveHistory()'s own
            // plain-JSON fallback below) stayed on only that weaker
            // protection indefinitely. Re-saving here on every load once
            // unlocked closes that gap. Never drops existing history — the
            // raw JSON is read and returned either way, this only upgrades
            // its on-disk representation. Found in the 2026-09-13
            // KeyHistoryManager audit — was entirely unencrypted before
            // this fix (plain DesktopStorage JSON, unlike Android's
            // EncryptedStorage-backed history).
            if (raw != "[]" && StorageKeyManager.isUnlocked) {
                try {
                    // wrapBytes() already returns the full "smk1:..."-prefixed
                    // string form, ready to persist directly.
                    val wrapped = StorageKeyManager.wrapBytes(raw.toByteArray(Charsets.UTF_8))
                    DesktopStorage.put(PREFIX + contactId, wrapped)
                } catch (_: Exception) {}
            }
            raw
        }
        val array = JSONArray(json)
        val list = mutableListOf<KeyRecord>()
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            list.add(KeyRecord(
                publicKey = obj.getString("key"),
                timestamp = obj.getLong("timestamp"),
                verified = obj.optBoolean("verified", false)
            ))
        }
        return list
    }

    fun addKey(contactId: String, publicKey: String) = synchronized(lock) {
        val history = getHistory(contactId).toMutableList()
        history.add(KeyRecord(publicKey = publicKey, timestamp = System.currentTimeMillis(), verified = false))
        saveHistory(contactId, history)
    }

    fun markAsVerified(contactId: String) = synchronized(lock) {
        val history = getHistory(contactId).toMutableList()
        if (history.isNotEmpty()) {
            val last = history.last()
            history[history.size - 1] = last.copy(verified = true)
            saveHistory(contactId, history)
        }
    }

    fun isVerified(contactId: String): Boolean =
        getHistory(contactId).lastOrNull()?.verified ?: false

    fun clearHistory(contactId: String) = synchronized(lock) {
        DesktopStorage.remove(PREFIX + contactId)
    }

    // Wrapped with StorageKeyManager/SMK when unlocked, same as
    // ChatStorage/GroupManager/SessionKeyManager — falls back to plain JSON
    // only while locked (self-healed by getHistory() above on the next
    // unlocked load), rather than refusing to write outright: an
    // unrecorded TOFU observation is a worse outcome here than a
    // temporarily-unwrapped one, since the whole point of this store is to
    // never silently miss a key change.
    private fun saveHistory(contactId: String, history: List<KeyRecord>) {
        val array = JSONArray()
        history.forEach { record ->
            array.put(JSONObject().apply {
                put("key", record.publicKey)
                put("timestamp", record.timestamp)
                put("verified", record.verified)
            })
        }
        val jsonStr = array.toString()
        val toStore = if (StorageKeyManager.isUnlocked)
            StorageKeyManager.wrapBytes(jsonStr.toByteArray(Charsets.UTF_8))
        else jsonStr
        DesktopStorage.put(PREFIX + contactId, toStore)
    }
}
