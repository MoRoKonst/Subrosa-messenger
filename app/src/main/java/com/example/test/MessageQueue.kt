package com.bcon.messenger

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object MessageQueue {

    private const val PREFS_NAME = "message_queue"
    private const val KEY_QUEUE = "queue"

    data class QueuedMessage(
        val id: String,
        val to: String,
        val text: String,
        val timestamp: Long = System.currentTimeMillis()
    )

    fun add(context: Context, message: QueuedMessage) {
        val queue = load(context).toMutableList()
        queue.add(message)
        save(context, queue)
    }

    fun load(context: Context): List<QueuedMessage> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val json = prefs.getString(KEY_QUEUE, "[]") ?: "[]"
        val array = JSONArray(json)
        val list = mutableListOf<QueuedMessage>()

        val now = System.currentTimeMillis()
        val maxAge = 7 * 24 * 60 * 60 * 1000L

        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            val timestamp = obj.getLong("timestamp")

            if (now - timestamp > maxAge) {
                continue
            }

            list.add(QueuedMessage(
                id = obj.getString("id"),
                to = obj.getString("to"),
                text = obj.getString("text"),
                timestamp = timestamp
            ))
        }

        if (list.size != array.length()) {
            save(context, list)
        }

        return list
    }

    fun remove(context: Context, id: String) {
        val queue = load(context).filter { it.id != id }
        save(context, queue)
    }

    private fun save(context: Context, queue: List<QueuedMessage>) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val array = JSONArray()
        queue.forEach { msg ->
            array.put(JSONObject().apply {
                put("id", msg.id)
                put("to", msg.to)
                put("text", msg.text)
                put("timestamp", msg.timestamp)
            })
        }
        prefs.edit().putString(KEY_QUEUE, array.toString()).apply()
    }
}