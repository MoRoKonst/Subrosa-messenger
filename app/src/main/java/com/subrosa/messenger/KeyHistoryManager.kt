package com.subrosa.messenger

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object KeyHistoryManager {

    private const val PREFS_NAME = "key_history"
    // Serializes every read-modify-write on a contact's history —
    // checkKeyChange/addKey/markAsVerified/clearHistory all do
    // getHistory() -> mutate -> saveHistory(), the same lost-update shape
    // already fixed for AnonTokenManager/GroupManager/SessionKeyManager
    // elsewhere in this codebase. MessengerService dispatches per-message
    // handling on Dispatchers.IO, so two calls for the same contactId
    // (e.g. a prekey_bundle_response and a session_init landing close
    // together) can race; a shared lock (not per-function) closes the
    // whole class of races, not just one call site's own window. Found in
    // the 2026-09-13 KeyHistoryManager audit.
    private val lock = Any()

    data class KeyRecord(
        val publicKey: String,
        val timestamp: Long,
        val verified: Boolean = false
    )

    /** Returns true iff [newKey] differs from the most recently recorded key
     *  for [contactId] (false for the very first key ever seen — nothing to
     *  compare against yet). A changed key is APPENDED here as a new,
     *  unverified record before returning — was previously detected but
     *  never recorded, so history.last() stayed pinned to the OLD key
     *  forever: every later fetch of the SAME (by then already-adopted) new
     *  key kept re-triggering this same "changed" branch indefinitely, and
     *  markAsVerified()/isVerified() (which always operate on history.last())
     *  ended up reading/marking the stale OLD record instead of the key
     *  actually in use. Appending here makes history.last() always equal
     *  "the key currently treated as this contact's identity", so the next
     *  fetch of that same key correctly compares equal (no more warning),
     *  and verifying it marks the right record. Found in the 2026-09-13
     *  KeyHistoryManager audit — this was the answer to "where/when is the
     *  new key added": nowhere, until this fix. */
    fun checkKeyChange(context: Context, contactId: String, newKey: String): Boolean = synchronized(lock) {
        // Reentrant — addKey() below acquires the same lock again, safe on
        // the same thread (Kotlin's synchronized is a reentrant monitor,
        // same reasoning as SessionKeyManager/GroupManager elsewhere).
        val history = getHistory(context, contactId)
        if (history.isEmpty()) {
            addKey(context, contactId, newKey)
            return@synchronized false
        }

        val lastKey = history.last().publicKey
        if (lastKey == newKey) return@synchronized false
        addKey(context, contactId, newKey)
        true
    }

    fun getHistory(context: Context, contactId: String): List<KeyRecord> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val json = prefs.getString(contactId, "[]") ?: "[]"
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

    fun addKey(context: Context, contactId: String, publicKey: String) = synchronized(lock) {
        val history = getHistory(context, contactId).toMutableList()
        history.add(KeyRecord(
            publicKey = publicKey,
            timestamp = System.currentTimeMillis(),
            verified = false
        ))
        saveHistory(context, contactId, history)
    }

    fun markAsVerified(context: Context, contactId: String) = synchronized(lock) {
        val history = getHistory(context, contactId).toMutableList()
        if (history.isNotEmpty()) {
            val last = history.last()
            history[history.size - 1] = last.copy(verified = true)
            saveHistory(context, contactId, history)
        }
    }

    fun clearHistory(context: Context, contactId: String) = synchronized(lock) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().remove(contactId).apply()
    }

    private fun saveHistory(context: Context, contactId: String, history: List<KeyRecord>) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val array = JSONArray()
        history.forEach { record ->
            array.put(JSONObject().apply {
                put("key", record.publicKey)
                put("timestamp", record.timestamp)
                put("verified", record.verified)
            })
        }
        prefs.edit().putString(contactId, array.toString()).apply()
    }
}