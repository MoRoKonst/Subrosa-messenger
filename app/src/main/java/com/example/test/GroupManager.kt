package com.subrosa.messenger

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class Group(
    val id: String,
    val name: String,
    val avatar: String,
    val members: List<String>,
    val admins: List<String>,
    val createdBy: String,
    val createdAt: Long = System.currentTimeMillis(),
    val groupKey: ByteArray? = null,
    val description: String = ""
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as Group
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

data class GroupMessage(
    val id: String,
    val groupId: String,
    val senderId: String,
    val senderName: String,
    val text: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isOwn: Boolean = false,
    val reactions: Map<String, String> = emptyMap(),
    // Mirrors ChatStorage.StoredMessage's attachment fields — group chat
    // previously had no photo/file support at all (UI buttons were literal
    // "(coming soon)" stubs, no send/receive path existed). imagePath/
    // filePath point at the same SecureFileStorage-encrypted blob files
    // 1:1 attachments use.
    val imagePath: String? = null,
    val filePath: String? = null,
    val fileName: String? = null
)

object GroupManager {

    private const val PREFS_NAME = "groups"
    private const val KEY_GROUPS = "my_groups"
    private val lock = Any()

    // Test seam: production always uses the real EncryptedStorage path.
    // Robolectric has no working AndroidKeyStore simulation (a well-known
    // limitation, not something worth reimplementing a fake KeyStore SPI
    // for), so GroupManagerTest overrides this to plain
    // context.getSharedPreferences() -- the authorization/membership logic
    // under test doesn't depend on the storage layer being encrypted, only
    // on it being consistent read-after-write.
    internal var prefsProvider: (Context, String) -> android.content.SharedPreferences =
        { context, name -> EncryptedStorage.getEncryptedPrefs(context, name) }

    private fun prefs(context: Context) = prefsProvider(context, PREFS_NAME)

    fun generateGroupKey(): ByteArray {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256, SecureRandom())
        return keyGen.generateKey().encoded
    }

    fun encryptGroupKeyForMember(groupKey: ByteArray, memberPublicKey: String, memberPqPublicKey: ByteArray): String {
        val keyBase64 = Base64.encodeToString(groupKey, Base64.NO_WRAP)
        return CryptoManager.encrypt(keyBase64, memberPublicKey, memberPqPublicKey)
    }

    fun decryptGroupKey(encryptedGroupKey: String): ByteArray {
        val keyBase64 = CryptoManager.decrypt(encryptedGroupKey)
        return Base64.decode(keyBase64, Base64.NO_WRAP)
    }

    fun encryptGroupMessage(message: String, groupKey: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(groupKey, "AES")

        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

        val encrypted = cipher.doFinal(message.toByteArray(Charsets.UTF_8))

        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decryptGroupMessage(encryptedMessage: String, groupKey: ByteArray): String {
        val combined = Base64.decode(encryptedMessage, Base64.NO_WRAP)
        if (combined.size <= 12) throw IllegalArgumentException("Слишком короткое зашифрованное сообщение")

        val iv = combined.copyOfRange(0, 12)
        val encrypted = combined.copyOfRange(12, combined.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(groupKey, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

        val decrypted = cipher.doFinal(encrypted)
        return String(decrypted, Charsets.UTF_8)
    }

    fun saveGroup(context: Context, group: Group) = synchronized(lock) {
        val prefs = prefs(context)

        val existingRawKeys = mutableMapOf<String, String>()
        try {
            val existing = JSONArray(prefs.getString(KEY_GROUPS, "[]") ?: "[]")
            for (i in 0 until existing.length()) {
                val obj = existing.getJSONObject(i)
                val id = obj.optString("id")
                val rawKey = obj.optString("groupKey", null)
                if (id.isNotEmpty() && rawKey != null) existingRawKeys[id] = rawKey
            }
        } catch (_: Exception) {}

        val groups = loadGroups(context).toMutableList()
        groups.removeIf { it.id == group.id }
        groups.add(group)

        val json = JSONArray()
        groups.forEach { g ->
            json.put(JSONObject().apply {
                put("id", g.id)
                put("name", g.name)
                put("avatar", g.avatar)
                put("members", JSONArray(g.members))
                put("admins", JSONArray(g.admins))
                put("createdBy", g.createdBy)
                put("createdAt", g.createdAt)
                put("description", g.description)
                if (g.groupKey != null) {
                    val groupKeyStored = if (StorageKeyManager.isUnlocked) {
                        StorageKeyManager.wrapBytes(g.groupKey)
                    } else {

                        existingRawKeys[g.id]
                            ?: Base64.encodeToString(g.groupKey, Base64.NO_WRAP)
                    }
                    put("groupKey", groupKeyStored)
                }
            })
        }

        prefs.edit().putString(KEY_GROUPS, json.toString()).apply()
    }

    /** Wipes every group and its messages — used when replacing the device's
     * active identity with a different one from a backup, see
     * BackupManager.wipeCurrentIdentityData(). Group messages live in
     * separate per-group prefs files, so the group list must still be
     * readable when this is called (before clearing it). */
    fun clearAll(context: Context) = synchronized(lock) {
        loadGroups(context).forEach { group ->
            EncryptedStorage.getEncryptedPrefs(context, "group_messages_${group.id}").edit().clear().apply()
        }
        prefs(context).edit().clear().apply()
    }

    fun loadGroups(context: Context): List<Group> = synchronized(lock) {
        val prefs = prefs(context)
        val jsonStr = prefs.getString(KEY_GROUPS, "[]") ?: "[]"

        return try {
            val json = JSONArray(jsonStr)
            var migrated = false

            val groups = (0 until json.length()).map { i ->
                val obj = json.getJSONObject(i)
                val storedKey = if (obj.has("groupKey")) obj.getString("groupKey") else null
                val groupKey = if (storedKey != null) StorageKeyManager.unwrapBytes(storedKey) else null

                if (storedKey != null
                    && !storedKey.startsWith(StorageKeyManager.SMK_PREFIX)
                    && StorageKeyManager.isUnlocked
                    && groupKey != null
                ) {
                    obj.put("groupKey", StorageKeyManager.wrapBytes(groupKey))
                    migrated = true
                }

                Group(
                    id = obj.getString("id"),
                    name = obj.getString("name"),
                    avatar = obj.getString("avatar"),
                    members = (0 until obj.getJSONArray("members").length()).map {
                        obj.getJSONArray("members").getString(it)
                    },
                    admins = (0 until obj.getJSONArray("admins").length()).map {
                        obj.getJSONArray("admins").getString(it)
                    },
                    createdBy = obj.getString("createdBy"),
                    createdAt = obj.getLong("createdAt"),
                    groupKey = groupKey,
                    description = obj.optString("description", "")
                )
            }

            if (migrated) {
                prefs.edit().putString(KEY_GROUPS, json.toString()).apply()
            }

            groups
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun getGroup(context: Context, groupId: String): Group? {
        return loadGroups(context).find { it.id == groupId }
    }

    fun deleteGroup(context: Context, groupId: String) = synchronized(lock) {
        val prefs = prefs(context)

        val existingRawKeys = mutableMapOf<String, String>()
        try {
            val existing = JSONArray(prefs.getString(KEY_GROUPS, "[]") ?: "[]")
            for (i in 0 until existing.length()) {
                val obj = existing.getJSONObject(i)
                val id = obj.optString("id")
                val rawKey = obj.optString("groupKey", null)
                if (id.isNotEmpty() && rawKey != null) existingRawKeys[id] = rawKey
            }
        } catch (_: Exception) {}

        val groups = loadGroups(context).filter { it.id != groupId }

        val json = JSONArray()
        groups.forEach { g ->
            json.put(JSONObject().apply {
                put("id", g.id)
                put("name", g.name)
                put("avatar", g.avatar)
                put("members", JSONArray(g.members))
                put("admins", JSONArray(g.admins))
                put("createdBy", g.createdBy)
                put("createdAt", g.createdAt)
                put("description", g.description)
                if (g.groupKey != null) {
                    val groupKeyStored = if (StorageKeyManager.isUnlocked) {
                        StorageKeyManager.wrapBytes(g.groupKey)
                    } else {
                        existingRawKeys[g.id]
                            ?: Base64.encodeToString(g.groupKey, Base64.NO_WRAP)
                    }
                    put("groupKey", groupKeyStored)
                }
            })
        }

        prefs.edit().putString(KEY_GROUPS, json.toString()).apply()
    }

    // All three below wrapped in synchronized(lock) (external review 2026-08-23):
    // each did getGroup() (its own brief lock, released) -> build an updated
    // list outside any lock -> saveGroup() (a separate lock acquisition). Two
    // concurrent calls (e.g. removing two different members at once) could
    // both read the same pre-mutation roster and the later save would
    // silently undo the earlier one's change -- a classic lost update.
    // saveGroup()'s own synchronized block didn't help, since the race window
    // was the read-decide part, before saveGroup() was ever called. Wrapping
    // the whole read-modify-write here in the same lock object closes it --
    // Kotlin's synchronized is a reentrant monitor, so the nested
    // getGroup()/saveGroup() calls re-entering the same lock is safe, not a
    // deadlock.
    //
    // actorId + internal isAdmin() check added (docs/THREAT_MODEL.md threat B /
    // docs/TODO.md's "GroupManager authorization" item): every current call
    // site already gated these behind its own isAdmin check before calling in
    // (UI buttons hidden for non-admins, remote group_* messages verified
    // against the sender's admin status + signature in MessengerService --
    // see docs/SECURITY.md's group-key-rotation fix history), so this is
    // defense-in-depth against a future caller forgetting that check, not a
    // fix for a currently-reachable bypass. removeMember keeps a self-removal
    // exception -- a member must be able to leave a group without being an
    // admin of it.
    fun addMember(context: Context, groupId: String, actorId: String, userId: String) = synchronized(lock) {
        val group = getGroup(context, groupId) ?: return@synchronized
        if (!isAdmin(context, groupId, actorId)) {
            android.util.Log.w("GroupManager", "addMember: $actorId is not admin of $groupId — rejected")
            return@synchronized
        }
        val updatedMembers = group.members.toMutableList()

        if (!updatedMembers.contains(userId)) {
            updatedMembers.add(userId)
            saveGroup(context, group.copy(members = updatedMembers))
        }
    }

    fun removeMember(context: Context, groupId: String, actorId: String, userId: String) = synchronized(lock) {
        val group = getGroup(context, groupId) ?: return@synchronized
        val selfRemoval = actorId == userId
        if (!selfRemoval && !isAdmin(context, groupId, actorId)) {
            android.util.Log.w("GroupManager", "removeMember: $actorId is not admin of $groupId — rejected")
            return@synchronized
        }
        val updatedMembers = group.members.toMutableList()
        val updatedAdmins = group.admins.toMutableList()

        updatedMembers.remove(userId)
        updatedAdmins.remove(userId)

        saveGroup(context, group.copy(
            members = updatedMembers,
            admins = updatedAdmins
        ))
    }

    fun promoteToAdmin(context: Context, groupId: String, actorId: String, userId: String) = synchronized(lock) {
        val group = getGroup(context, groupId) ?: return@synchronized
        if (!isAdmin(context, groupId, actorId)) {
            android.util.Log.w("GroupManager", "promoteToAdmin: $actorId is not admin of $groupId — rejected")
            return@synchronized
        }
        val updatedAdmins = group.admins.toMutableList()

        if (!updatedAdmins.contains(userId) && group.members.contains(userId)) {
            updatedAdmins.add(userId)
            saveGroup(context, group.copy(admins = updatedAdmins))
        }
    }

    // Now also requires current membership (external review 2026-08-23): was
    // `admins.contains(userId) || createdBy == userId` -- the createdBy check
    // had no membership requirement at all, so a creator who was later
    // removed from the group (removeMember() strips them from both members
    // and admins) was still treated as admin by this function forever,
    // regardless of actually being in the group anymore.
    fun isAdmin(context: Context, groupId: String, userId: String): Boolean {
        val group = getGroup(context, groupId) ?: return false
        if (userId !in group.members) return false
        return group.admins.contains(userId) || group.createdBy == userId
    }

    fun saveGroupMessage(context: Context, userId: String, message: GroupMessage) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, "group_messages_${message.groupId}")
        val messages = loadGroupMessages(context, userId, message.groupId).toMutableList()

        messages.removeIf { it.id == message.id }
        messages.add(message)

        val json = JSONArray()
        messages.forEach { msg ->
            json.put(JSONObject().apply {
                put("id", msg.id)
                put("groupId", msg.groupId)
                put("senderId", msg.senderId)
                put("senderName", msg.senderName)
                put("text", msg.text)
                put("timestamp", msg.timestamp)
                put("isOwn", msg.isOwn)
                put("reactions", JSONObject(msg.reactions))
                msg.imagePath?.let { put("imagePath", it) }
                msg.filePath?.let { put("filePath", it) }
                msg.fileName?.let { put("fileName", it) }
            })
        }

        prefs.edit().putString("messages", json.toString()).apply()
    }

    fun deleteGroupMessage(context: Context, userId: String, groupId: String, messageId: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, "group_messages_$groupId")
        val messages = loadGroupMessages(context, userId, groupId).toMutableList()
        messages.removeIf { it.id == messageId }
        val json = JSONArray()
        messages.forEach { msg ->
            json.put(JSONObject().apply {
                put("id", msg.id)
                put("groupId", msg.groupId)
                put("senderId", msg.senderId)
                put("senderName", msg.senderName)
                put("text", msg.text)
                put("timestamp", msg.timestamp)
                put("isOwn", msg.isOwn)
                put("reactions", JSONObject(msg.reactions))
                msg.imagePath?.let { put("imagePath", it) }
                msg.filePath?.let { put("filePath", it) }
                msg.fileName?.let { put("fileName", it) }
            })
        }
        prefs.edit().putString("messages", json.toString()).apply()
    }

    fun loadGroupMessages(context: Context, userId: String, groupId: String): List<GroupMessage> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, "group_messages_$groupId")
        val jsonStr = prefs.getString("messages", "[]") ?: "[]"

        return try {
            val json = JSONArray(jsonStr)
            (0 until json.length()).map { i ->
                val obj = json.getJSONObject(i)
                val reactions = mutableMapOf<String, String>()
                val reactionsObj = obj.getJSONObject("reactions")
                reactionsObj.keys().forEach { key ->
                    reactions[key] = reactionsObj.getString(key)
                }

                GroupMessage(
                    id = obj.getString("id"),
                    groupId = obj.getString("groupId"),
                    senderId = obj.getString("senderId"),
                    senderName = obj.getString("senderName"),
                    text = obj.getString("text"),
                    timestamp = obj.getLong("timestamp"),
                    isOwn = obj.getBoolean("isOwn"),
                    reactions = reactions,
                    imagePath = obj.optString("imagePath", null),
                    filePath = obj.optString("filePath", null),
                    fileName = obj.optString("fileName", null)
                )
            }.sortedBy { it.timestamp }
        } catch (e: Exception) {
            emptyList()
        }
    }
}