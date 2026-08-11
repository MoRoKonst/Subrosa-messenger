package com.subrosa.messenger

import java.util.UUID
import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

object ChatStorage {

    private const val PREFS_NAME = "chat_storage_encrypted"

    data class StoredMessage(
        val id: String = UUID.randomUUID().toString(),
        val text: String,
        val isOwn: Boolean,
        val timestamp: Long = System.currentTimeMillis(),
        val reactions: Map<String, String> = emptyMap(),
        val voicePath: String? = null,
        val voiceDuration: Int = 0,
        val isEdited: Boolean = false,
        val imagePath: String? = null,
        val filePath: String? = null,
        val fileName: String? = null,
        val isDelivered: Boolean = false,
        val isRead: Boolean = false,
        val replyToId: String? = null,
        val expiresAt: Long = 0L,
        val videoPath: String? = null,
        val videoDuration: Int = 0,
        val isFailed: Boolean = false
    )

    private fun chatKey(myUserId: String, recipientUserId: String): String {
        val pair = listOf(myUserId, recipientUserId).sorted()
        val key = "chat_${pair[0]}_${pair[1]}"
        return key
    }

    fun loadMessages(
        context: Context,
        myUserId: String,
        recipientUserId: String
    ): MutableList<StoredMessage> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val array = loadJsonArray(prefs, chatKey(myUserId, recipientUserId))
        val list = mutableListOf<StoredMessage>()

        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            val voicePath = obj.optString("voice_path", null)
            val voiceDuration = obj.optInt("voice_duration", 0)
            val imagePath = obj.optString("image_path", null)
            val filePath = obj.optString("file_path", null)
            val fileName = obj.optString("file_name", null)
            val videoPath = obj.optString("video_path", null)
            val videoDuration = obj.optInt("video_duration", 0)

            val reactions = mutableMapOf<String, String>()
            val reactionsJson = obj.optJSONObject("reactions")
            if (reactionsJson != null) {
                val keys = reactionsJson.keys()
                while (keys.hasNext()) {
                    val user = keys.next()
                    reactions[user] = reactionsJson.getString(user)
                }
            }

            val expiresAt = obj.optLong("expires_at", 0L)

            if (expiresAt > 0L && System.currentTimeMillis() > expiresAt) continue

            list.add(
                StoredMessage(
                    id = obj.getString("id"),
                    text = obj.getString("text"),
                    isOwn = obj.getBoolean("isOwn"),
                    timestamp = obj.getLong("timestamp"),
                    reactions = reactions,
                    voicePath = if (voicePath.isNullOrBlank()) null else voicePath,
                    voiceDuration = voiceDuration,
                    isEdited = obj.optBoolean("is_edited", false),
                    imagePath = if (imagePath.isNullOrBlank()) null else imagePath,
                    filePath = if (filePath.isNullOrBlank()) null else filePath,
                    fileName = if (fileName.isNullOrBlank()) null else fileName,
                    isDelivered = obj.optBoolean("is_delivered", false),
                    isRead = obj.optBoolean("is_read", false),
                    isFailed = obj.optBoolean("is_failed", false),
                    replyToId = obj.optString("reply_to_id", null).takeIf { !it.isNullOrBlank() },
                    expiresAt = expiresAt,
                    videoPath = if (videoPath.isNullOrBlank()) null else videoPath,
                    videoDuration = videoDuration
            )
            )
        }

        return list
    }

    fun saveOrUpdateMessage(
        context: Context,
        myUserId: String,
        recipientUserId: String,
        message: StoredMessage
    ) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val key = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(prefs, key)

        var updated = false

        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optString("id") == message.id) {

                val reactionsJson = JSONObject()
                message.reactions.forEach { (user, emoji) ->
                    reactionsJson.put(user, emoji)
                }
                obj.put("reactions", reactionsJson)
                obj.put("voice_path", message.voicePath)
                obj.put("voice_duration", message.voiceDuration)
                obj.put("is_edited", message.isEdited)
                obj.put("text", message.text)
                obj.put("image_path", message.imagePath)
                obj.put("file_path", message.filePath)
                obj.put("file_name", message.fileName)
                obj.put("is_delivered", message.isDelivered)
                obj.put("is_read", message.isRead)
                obj.put("is_failed", message.isFailed)
                obj.put("reply_to_id", message.replyToId ?: "")
                obj.put("expires_at", message.expiresAt)
                obj.put("video_path", message.videoPath)
                obj.put("video_duration", message.videoDuration)
                updated = true
                break
            }
        }

            if (!updated) {
                val reactionsJson = JSONObject()
                message.reactions.forEach { (user, emoji) ->
                    reactionsJson.put(user, emoji)
                }

                array.put(JSONObject().apply {
                    put("id", message.id)
                    put("text", message.text)
                    put("isOwn", message.isOwn)
                    put("timestamp", message.timestamp)
                    put("reactions", reactionsJson)
                    put("voice_path", message.voicePath)
                    put("voice_duration", message.voiceDuration)
                    put("is_edited", message.isEdited ?: false)
                    put("image_path", message.imagePath)
                    put("file_path", message.filePath)
                    put("file_name", message.fileName)
                    put("is_delivered", message.isDelivered)
                    put("is_read", message.isRead)
                    put("is_failed", message.isFailed)
                    put("reply_to_id", message.replyToId ?: "")
                    put("expires_at", message.expiresAt)
                    put("video_path", message.videoPath)
                    put("video_duration", message.videoDuration)
                })
            }

        saveJsonArray(prefs, key, array)
        }

    fun getContacts(context: Context): MutableList<String> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val json = prefs.getString("contacts", "[]") ?: "[]"
        val array = JSONArray(json)
        val list = mutableListOf<String>()
        for (i in 0 until array.length()) {
            list.add(array.getString(i))
        }
        return list
    }

    fun addContact(context: Context, username: String) {
        val contacts = getContacts(context)
        if (!contacts.contains(username)) {
            contacts.add(username)
            val array = JSONArray(contacts)
            EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
                .edit()
                .putString("contacts", array.toString())
                .apply()
        }
    }

    fun removeContact(context: Context, contactId: String) {
        val contacts = getContacts(context)
        if (contacts.remove(contactId)) {
            val array = JSONArray(contacts)
            EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
                .edit()
                .putString("contacts", array.toString())
                .apply()
        }
    }

    fun getLastMessage(context: Context, username: String, recipient: String): StoredMessage? {
        return loadMessages(context, username, recipient).lastOrNull()
    }

    fun saveDraft(context: Context, myUserId: String, recipientUserId: String, text: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val key = "draft_${chatKey(myUserId, recipientUserId)}"
        if (text.isBlank()) prefs.edit().remove(key).apply()
        else prefs.edit().putString(key, text).apply()
    }

    fun loadDraft(context: Context, myUserId: String, recipientUserId: String): String =
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString("draft_${chatKey(myUserId, recipientUserId)}", "") ?: ""

    /** Found live: this used to remove only the message history and the
     * contacts-list entry — the cached public key ("key_$contactId") was
     * left in place, and so was MessengerService's own in-memory
     * publicKeys/publicKeysPq cache and the Double Ratchet session
     * (SessionKeyManager), and the mailbox tag (AnonTokenManager). Any
     * routine background traffic still arriving from the other side (who
     * has no idea they were deleted — health-check pings, token refills)
     * still verified successfully against the surviving key and silently
     * re-added the contact via ChatStorage.addContact() in the message
     * handlers, but with the "channel" actually just stale leftover state,
     * not anything freshly (re-)established. See
     * MessengerService.forgetContact(), which now also clears the
     * session/tokens/in-memory caches — this function only owns the
     * on-disk parts ChatStorage is responsible for. */
    fun deleteChat(context: Context, username: String, recipient: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)

        prefs.edit()
            .remove(chatKey(username, recipient))
            .remove("key_$recipient")
            .remove("avatar_$recipient")
            .apply()

        val contacts = getContacts(context)
        contacts.remove(recipient)
        val array = org.json.JSONArray(contacts)
        prefs.edit().putString("contacts", array.toString()).apply()
    }

    fun deleteMessage(context: Context, myUserId: String, recipientUserId: String, messageId: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val key = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(prefs, key)
        val newArray = JSONArray()
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optString("id") != messageId) newArray.put(obj)
        }
        saveJsonArray(prefs, key, newArray)
    }

    fun getDisappearTimer(context: Context, myUserId: String, recipientUserId: String): Long {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.getLong("disappear_${chatKey(myUserId, recipientUserId)}", 0L)
    }
    fun setDisappearTimer(context: Context, myUserId: String, recipientUserId: String, seconds: Long) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().putLong("disappear_${chatKey(myUserId, recipientUserId)}", seconds).apply()
    }

    fun markDelivered(context: Context, myUserId: String, recipientUserId: String, messageId: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val key   = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(prefs, key)
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optString("id") == messageId) {
                obj.put("is_delivered", true)
                obj.put("is_failed", false)
                break
            }
        }
        saveJsonArray(prefs, key, array)
    }

    fun markFailed(context: Context, myUserId: String, recipientUserId: String, messageId: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val key   = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(prefs, key)
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optString("id") == messageId) {
                obj.put("is_failed", true)
                break
            }
        }
        saveJsonArray(prefs, key, array)
    }

    fun markIncomingAsRead(context: Context, myUserId: String, contactId: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val key   = chatKey(myUserId, contactId)
        val array = loadJsonArray(prefs, key)
        var anyUpdated = false
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (!obj.optBoolean("isOwn", true) && !obj.optBoolean("is_read", false)) {
                obj.put("is_read", true)
                anyUpdated = true
            }
        }
        if (anyUpdated) saveJsonArray(prefs, key, array)
    }

    fun markRead(context: Context, myUserId: String, recipientUserId: String, messageId: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val key   = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(prefs, key)
        var anyUpdated = false
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)

            if (obj.optBoolean("isOwn", false) && !obj.optBoolean("is_read", false)) {
                obj.put("is_read", true)
                obj.put("is_delivered", true)
                anyUpdated = true
            }
        }
        if (anyUpdated) saveJsonArray(prefs, key, array)
    }

    fun saveContactName(context: Context, contactId: String, name: String?) {
        if (name.isNullOrBlank()) return

        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().putString("name_$contactId", name).apply()
    }

    fun getContactName(context: Context, contactId: String): String {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.getString("name_$contactId", null)?.takeIf { it.isNotBlank() }
            ?: contactId.substringBefore("_")
    }

    fun saveContactPublicKey(context: Context, contactId: String, publicKey: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        prefs.edit().putString("key_$contactId", publicKey).apply()
    }

    fun getContactPublicKey(context: Context, contactId: String): String? {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        return prefs.getString("key_$contactId", null)
    }

    fun saveContactAvatar(context: Context, contactId: String, base64: String) {
        EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .edit().putString("avatar_$contactId", base64).apply()
    }

    fun getContactAvatar(context: Context, contactId: String): String? {
        return EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
            .getString("avatar_$contactId", null)
    }
    fun saveMessagesBatch(
        context: Context,
        myUserId: String,
        recipientUserId: String,
        newMessages: List<StoredMessage>
    ) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val key = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(prefs, key)

        val existingIds = mutableSetOf<String>()
        for (i in 0 until array.length()) {
            existingIds.add(array.getJSONObject(i).optString("id"))
        }

        newMessages.forEach { message ->
            if (!existingIds.contains(message.id)) {
                array.put(JSONObject().apply {
                    put("id", message.id)
                    put("text", message.text)
                    put("isOwn", message.isOwn)
                    put("timestamp", message.timestamp)
                    put("reactions", JSONObject())
                    put("voice_path", message.voicePath)
                    put("voice_duration", message.voiceDuration)
                    put("is_edited", message.isEdited)
                    put("image_path", message.imagePath)
                    put("file_path", message.filePath)
                    put("file_name", message.fileName)
                })
            }
        }

        saveJsonArray(prefs, key, array)
    }

    private fun loadJsonArray(prefs: SharedPreferences, key: String): JSONArray {
        val raw = prefs.getString(key, "[]") ?: "[]"
        val jsonStr = if (raw.startsWith(StorageKeyManager.SMK_PREFIX)) {
            val blob = Base64.decode(raw.removePrefix(StorageKeyManager.SMK_PREFIX), Base64.NO_WRAP)
            String(StorageKeyManager.decrypt(blob), Charsets.UTF_8)
        } else {

            if (raw != "[]" && StorageKeyManager.isUnlocked) {
                try {
                    val wrapped = StorageKeyManager.SMK_PREFIX + Base64.encodeToString(
                        StorageKeyManager.encrypt(raw.toByteArray(Charsets.UTF_8)),
                        Base64.NO_WRAP
                    )
                    prefs.edit().putString(key, wrapped).apply()
                } catch (_: Exception) {}
            }
            raw
        }
        return JSONArray(jsonStr)
    }

    private fun saveJsonArray(prefs: SharedPreferences, key: String, array: JSONArray) {
        if (!StorageKeyManager.isUnlocked) return
        val toStore = StorageKeyManager.SMK_PREFIX + Base64.encodeToString(
            StorageKeyManager.encrypt(array.toString().toByteArray(Charsets.UTF_8)),
            Base64.NO_WRAP
        )
        prefs.edit().putString(key, toStore).apply()
    }
}