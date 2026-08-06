package com.subrosa.messenger

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object KeyHistoryManager {

    private const val PREFS_NAME = "key_history"

    data class KeyRecord(
        val publicKey: String,
        val timestamp: Long,
        val verified: Boolean = false
    )

    fun checkKeyChange(context: Context, contactId: String, newKey: String): Boolean {
        val history = getHistory(context, contactId)
        if (history.isEmpty()) {

            addKey(context, contactId, newKey)
            return false
        }

        val lastKey = history.last().publicKey
        return lastKey != newKey
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

    fun addKey(context: Context, contactId: String, publicKey: String) {
        val history = getHistory(context, contactId).toMutableList()
        history.add(KeyRecord(
            publicKey = publicKey,
            timestamp = System.currentTimeMillis(),
            verified = false
        ))
        saveHistory(context, contactId, history)
    }

    fun markAsVerified(context: Context, contactId: String) {
        val history = getHistory(context, contactId).toMutableList()
        if (history.isNotEmpty()) {
            val last = history.last()
            history[history.size - 1] = last.copy(verified = true)
            saveHistory(context, contactId, history)
        }
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