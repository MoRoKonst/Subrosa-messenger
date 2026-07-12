package com.bcon.messenger

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
    val avatar: String, // emoji
    val members: List<String>, // userId list
    val admins: List<String>,
    val createdBy: String,
    val createdAt: Long = System.currentTimeMillis(),
    val groupKey: ByteArray? = null, // Локально хранится зашифрованный ключ
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
    val reactions: Map<String, String> = emptyMap()
)

object GroupManager {

    private const val PREFS_NAME = "groups"
    private const val KEY_GROUPS = "my_groups"
    private val lock = Any()

    // ─── Генерация группового ключа ──────────────────────────────────────────

    /**
     * Генерирует случайный AES-256 ключ для группы
     */
    fun generateGroupKey(): ByteArray {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256, SecureRandom())
        return keyGen.generateKey().encoded
    }

    /**
     * Шифрует групповой ключ для конкретного участника
     */
    fun encryptGroupKeyForMember(groupKey: ByteArray, memberPublicKey: String): String {
        val keyBase64 = Base64.encodeToString(groupKey, Base64.NO_WRAP)
        return CryptoManager.encrypt(keyBase64, memberPublicKey)
    }

    /**
     * Расшифровывает групповой ключ (получен от создателя группы)
     */
    fun decryptGroupKey(encryptedGroupKey: String): ByteArray {
        val keyBase64 = CryptoManager.decrypt(encryptedGroupKey)
        return Base64.decode(keyBase64, Base64.NO_WRAP)
    }

    // ─── Шифрование сообщений группы ─────────────────────────────────────────

    /**
     * Шифрует сообщение групповым ключом
     */
    fun encryptGroupMessage(message: String, groupKey: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(groupKey, "AES")
        // Явная генерация IV через SecureRandom — не полагаемся на внутреннюю реализацию провайдера.
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

        val encrypted = cipher.doFinal(message.toByteArray(Charsets.UTF_8))

        // Формат: [IV][зашифрованные данные]
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * Расшифровывает сообщение групповым ключом
     */
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

    // ─── Хранение групп ──────────────────────────────────────────────────────

    /**
     * Сохранить группу локально
     */
    fun saveGroup(context: Context, group: Group) = synchronized(lock) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)

        // Считываем raw-строки существующих ключей — нужны если SMK залочен
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
                        // SMK залочен — сохраняем уже существующий raw ключ чтобы
                        // не понижать защиту до plain Base64. Новый ключ (ротация)
                        // будет re-wrap при следующей загрузке когда SMK разблокируется.
                        existingRawKeys[g.id]
                            ?: Base64.encodeToString(g.groupKey, Base64.NO_WRAP)
                    }
                    put("groupKey", groupKeyStored)
                }
            })
        }

        prefs.edit().putString(KEY_GROUPS, json.toString()).apply()
    }

    /**
     * Загрузить все группы
     */
    fun loadGroups(context: Context): List<Group> = synchronized(lock) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)
        val jsonStr = prefs.getString(KEY_GROUPS, "[]") ?: "[]"

        return try {
            val json = JSONArray(jsonStr)
            var migrated = false

            val groups = (0 until json.length()).map { i ->
                val obj = json.getJSONObject(i)
                val storedKey = if (obj.has("groupKey")) obj.getString("groupKey") else null
                val groupKey = if (storedKey != null) StorageKeyManager.unwrapBytes(storedKey) else null

                // Eager re-wrap: если ключ хранился как plain Base64 и SMK теперь доступен
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

    /**
     * Получить группу по ID
     */
    fun getGroup(context: Context, groupId: String): Group? {
        return loadGroups(context).find { it.id == groupId }
    }

    /**
     * Удалить группу
     */
    fun deleteGroup(context: Context, groupId: String) = synchronized(lock) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_NAME)

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

    // ─── Управление участниками ──────────────────────────────────────────────

    /**
     * Добавить участника в группу
     */
    fun addMember(context: Context, groupId: String, userId: String) {
        val group = getGroup(context, groupId) ?: return
        val updatedMembers = group.members.toMutableList()

        if (!updatedMembers.contains(userId)) {
            updatedMembers.add(userId)
            saveGroup(context, group.copy(members = updatedMembers))
        }
    }

    /**
     * Удалить участника из группы
     */
    fun removeMember(context: Context, groupId: String, userId: String) {
        val group = getGroup(context, groupId) ?: return
        val updatedMembers = group.members.toMutableList()
        val updatedAdmins = group.admins.toMutableList()

        updatedMembers.remove(userId)
        updatedAdmins.remove(userId)

        saveGroup(context, group.copy(
            members = updatedMembers,
            admins = updatedAdmins
        ))
    }

    /**
     * Сделать админом
     */
    fun promoteToAdmin(context: Context, groupId: String, userId: String) {
        val group = getGroup(context, groupId) ?: return
        val updatedAdmins = group.admins.toMutableList()

        if (!updatedAdmins.contains(userId) && group.members.contains(userId)) {
            updatedAdmins.add(userId)
            saveGroup(context, group.copy(admins = updatedAdmins))
        }
    }

    /**
     * Проверка прав администратора
     */
    fun isAdmin(context: Context, groupId: String, userId: String): Boolean {
        val group = getGroup(context, groupId) ?: return false
        return group.admins.contains(userId) || group.createdBy == userId
    }

    // ─── Сообщения группы ────────────────────────────────────────────────────

    /**
     * Сохранить сообщение группы
     */
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
            })
        }

        prefs.edit().putString("messages", json.toString()).apply()
    }

    /**
     * Удалить сообщение группы локально
     */
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
            })
        }
        prefs.edit().putString("messages", json.toString()).apply()
    }

    /**
     * Загрузить сообщения группы
     */
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
                    reactions = reactions
                )
            }.sortedBy { it.timestamp }
        } catch (e: Exception) {
            emptyList()
        }
    }
}