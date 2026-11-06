package com.subrosa.desktop

import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// id-only equals()/hashCode() removed — mirrors Android's identical fix
// (GroupManager.kt, found live 2026-09-21): every screen holds the active
// group as `var group by remember { mutableStateOf<Group?>(...) }`, whose
// default structuralEqualityPolicy short-circuits recomposition when the
// NEW value `equals()`s the OLD one. With equals() comparing only `id`,
// reassigning `group = GroupManager.getGroup(groupId)` after a
// members/avatar/admins change was silently treated as "no change" by
// Compose. A plain data class's default structural equality doesn't have
// this problem; no code relies on id-only Group equality.
data class Group(
    val id: String,
    val name: String,
    val avatar: String, // emoji
    val members: List<String>,
    val admins: List<String>,
    val createdBy: String,
    val createdAt: Long = System.currentTimeMillis(),
    val groupKey: ByteArray? = null,
    val description: String = "",
    // Photo avatar (DesktopStorage-encrypted blob path) — mirrors Android's
    // identical field. Null means "use the emoji in `avatar` instead".
    val avatarPath: String? = null
)

data class GroupMessage(
    val id: String,
    val groupId: String,
    val senderId: String,
    val senderName: String,
    val text: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isOwn: Boolean = false,
    val reactions: Map<String, String> = emptyMap(),
    // Mirrors Android's GroupMessage exactly.
    val imagePath: String? = null,
    val filePath: String? = null,
    val fileName: String? = null,
    // Mirrors ChatStorage.StoredMessage.replyToId — group chat previously
    // had no reply support at all, unlike 1:1. The quoted preview is
    // resolved at render time (GroupChatScreen.kt looks this id up in the
    // already-loaded message list), same as 1:1's own repliedMsg pattern.
    val replyToId: String? = null
)

object GroupManager {

    private const val KEY_GROUPS = "my_groups"
    private val lock = Any()

    fun generateGroupKey(): ByteArray {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256, SecureRandom())
        return keyGen.generateKey().encoded
    }

    fun encryptGroupKeyForMember(groupKey: ByteArray, memberPublicKey: String, memberPqPublicKey: ByteArray): String {
        val keyBase64 = Base64.getEncoder().encodeToString(groupKey)
        return CryptoManager.encrypt(keyBase64, memberPublicKey, memberPqPublicKey)
    }

    fun decryptGroupKey(encryptedGroupKey: String): ByteArray {
        val keyBase64 = CryptoManager.decrypt(encryptedGroupKey)
        return Base64.getDecoder().decode(keyBase64)
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
        return Base64.getEncoder().encodeToString(combined)
    }

    fun decryptGroupMessage(encryptedMessage: String, groupKey: ByteArray): String {
        val combined = Base64.getDecoder().decode(encryptedMessage)
        if (combined.size <= 12) throw IllegalArgumentException("Too short message")
        val iv = combined.copyOfRange(0, 12)
        val encrypted = combined.copyOfRange(12, combined.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(groupKey, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val decrypted = cipher.doFinal(encrypted)
        return String(decrypted, Charsets.UTF_8)
    }

    fun saveGroup(group: Group) = synchronized(lock) {
        // Preserve whatever raw wrapped groupKey is already on disk for a
        // group when locked — mirrors Android's saveGroup() exactly. Without
        // this, saving ANY group while StorageKeyManager is locked (not just
        // the one being saved — this rewrites the whole list) downgraded
        // every other group's key from an SMK-wrapped blob to plain Base64,
        // regressing their protection for as long as the app stayed locked.
        // Found in the 2026-09-13 full-logic audit.
        val existingRawKeys = mutableMapOf<String, String>()
        try {
            val existing = JSONArray(DesktopStorage.get(KEY_GROUPS) ?: "[]")
            for (i in 0 until existing.length()) {
                val obj = existing.getJSONObject(i)
                val id = obj.optString("id")
                val rawKey = obj.optString("groupKey", null)
                if (id.isNotEmpty() && rawKey != null) existingRawKeys[id] = rawKey
            }
        } catch (_: Exception) {}

        val groups = loadGroups().toMutableList()
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
                g.avatarPath?.let { put("avatarPath", it) }
                if (g.groupKey != null) {
                    val groupKeyStored = if (StorageKeyManager.isUnlocked) {
                        StorageKeyManager.wrapBytes(g.groupKey)
                    } else {
                        existingRawKeys[g.id]
                            ?: Base64.getEncoder().encodeToString(g.groupKey)
                    }
                    put("groupKey", groupKeyStored)
                }
            })
        }
        DesktopStorage.put(KEY_GROUPS, json.toString())
    }

    /** Wipes every group and its messages — used when replacing this
     * device's active identity with a different one from a backup, see
     * BackupManager.wipeCurrentIdentityData(). Mirrors Android's
     * GroupManager.clearAll(). */
    fun clearAll() = synchronized(lock) {
        loadGroups().forEach { group ->
            DesktopStorage.remove("group_messages_${group.id}_messages")
        }
        DesktopStorage.remove(KEY_GROUPS)
    }

    fun loadGroups(): List<Group> = synchronized(lock) {
        val jsonStr = DesktopStorage.get(KEY_GROUPS) ?: "[]"
        return@synchronized try {
            val json = JSONArray(jsonStr)
            var migrated = false

            val groups = (0 until json.length()).map { i ->
                val obj = json.getJSONObject(i)
                val storedKey = if (obj.has("groupKey")) obj.getString("groupKey") else null
                val groupKey = if (storedKey != null) StorageKeyManager.unwrapBytes(storedKey) else null

                // Self-heal legacy/plain-Base64 group keys — mirrors
                // Android's loadGroups() exactly: a key saved while locked
                // (saveGroup()'s own plain-Base64 fallback above) stayed on
                // only that weaker protection indefinitely, with no re-wrap
                // unless that specific group was saved again. Re-wrapping
                // here on every load once unlocked closes that gap instead
                // of leaving it to chance. On-disk schema is unchanged — the
                // "groupKey" field just moves from a plain-Base64 string to
                // an SMK-wrapped one, same as it would from a real save.
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
                    description = obj.optString("description", ""),
                    avatarPath = obj.optString("avatarPath", null)
                )
            }

            if (migrated) {
                DesktopStorage.put(KEY_GROUPS, json.toString())
            }

            groups
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun getGroup(groupId: String): Group? {
        return loadGroups().find { it.id == groupId }
    }

    fun deleteGroup(groupId: String) = synchronized(lock) {
        // Same raw-key preservation as saveGroup() above — see its comment.
        val existingRawKeys = mutableMapOf<String, String>()
        try {
            val existing = JSONArray(DesktopStorage.get(KEY_GROUPS) ?: "[]")
            for (i in 0 until existing.length()) {
                val obj = existing.getJSONObject(i)
                val id = obj.optString("id")
                val rawKey = obj.optString("groupKey", null)
                if (id.isNotEmpty() && rawKey != null) existingRawKeys[id] = rawKey
            }
        } catch (_: Exception) {}

        val groups = loadGroups().filter { it.id != groupId }
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
                g.avatarPath?.let { put("avatarPath", it) }
                if (g.groupKey != null) {
                    val groupKeyStored = if (StorageKeyManager.isUnlocked) {
                        StorageKeyManager.wrapBytes(g.groupKey)
                    } else {
                        existingRawKeys[g.id]
                            ?: Base64.getEncoder().encodeToString(g.groupKey)
                    }
                    put("groupKey", groupKeyStored)
                }
            })
        }
        DesktopStorage.put(KEY_GROUPS, json.toString())
    }

    // actorId + isAdmin() gate added (external review 2026-09-08, S6-60) —
    // mirrors Android's GroupManager, which already enforces this
    // (docs/THREAT_MODEL.md threat B / docs/TODO.md's "GroupManager
    // authorization" item). Previously these three took no actor at all, so
    // ANY call site — including a network handler applying an unauthorized
    // remote message — silently succeeded with no authorization check
    // whatsoever. removeMember keeps a self-removal exception: a member
    // must be able to leave a group without being an admin of it.
    // All three below wrapped in synchronized(lock) — mirrors Android's
    // GroupManager exactly (external review 2026-08-23 there): each did
    // getGroup() (its own brief, now-lock-free read) -> build an updated
    // list outside any lock -> saveGroup() (a separate lock acquisition).
    // Two concurrent calls (e.g. removing two different members at once)
    // could both read the same pre-mutation roster and the later save would
    // silently undo the earlier one's change — a classic lost update.
    // saveGroup()'s own lock didn't help, since the race window was the
    // read-decide part, before saveGroup() was ever called. Wrapping the
    // whole read-modify-write here in the same lock object closes it —
    // Kotlin's synchronized is a reentrant monitor, so the nested
    // getGroup()/saveGroup() calls re-entering the same lock is safe, not a
    // deadlock. Was entirely unsynchronized on Desktop — found in the
    // 2026-09-13 full-logic audit.
    fun addMember(groupId: String, actorId: String, userId: String) = synchronized(lock) {
        val group = getGroup(groupId) ?: return@synchronized
        if (!isAdmin(groupId, actorId)) {
            System.err.println("GroupManager: addMember: $actorId is not admin of $groupId — rejected")
            return@synchronized
        }
        val updatedMembers = group.members.toMutableList()
        if (!updatedMembers.contains(userId)) {
            updatedMembers.add(userId)
            saveGroup(group.copy(members = updatedMembers))
        }
    }

    fun removeMember(groupId: String, actorId: String, userId: String) = synchronized(lock) {
        val group = getGroup(groupId) ?: return@synchronized
        val selfRemoval = actorId == userId
        if (!selfRemoval && !isAdmin(groupId, actorId)) {
            System.err.println("GroupManager: removeMember: $actorId is not admin of $groupId — rejected")
            return@synchronized
        }

        // If the account being removed is THIS device's own account —
        // whether by leaving voluntarily or being kicked and told about it
        // remotely — there's no reason to keep a local record of a group
        // we're no longer in. Mirrors the identical Android fix (found
        // live: leaving only stripped membership, so the group silently
        // stayed in the chat list forever afterward).
        if (userId == WebSocketClient.myFingerprint) {
            deleteGroup(groupId)
            return@synchronized
        }

        val updatedMembers = group.members.toMutableList()
        val updatedAdmins = group.admins.toMutableList()
        updatedMembers.remove(userId)
        updatedAdmins.remove(userId)
        saveGroup(group.copy(members = updatedMembers, admins = updatedAdmins))
    }

    fun promoteToAdmin(groupId: String, actorId: String, userId: String) = synchronized(lock) {
        val group = getGroup(groupId) ?: return@synchronized
        if (!isAdmin(groupId, actorId)) {
            System.err.println("GroupManager: promoteToAdmin: $actorId is not admin of $groupId — rejected")
            return@synchronized
        }
        val updatedAdmins = group.admins.toMutableList()
        if (!updatedAdmins.contains(userId) && group.members.contains(userId)) {
            updatedAdmins.add(userId)
            saveGroup(group.copy(admins = updatedAdmins))
        }
    }

    // Now also requires current membership (external review 2026-09-08,
    // S6-60, mirrors Android's own earlier fix for the same gap) — was
    // `admins.contains(userId) || createdBy == userId` with no membership
    // requirement, so a creator later removed from the group (removeMember()
    // strips them from both members and admins) was still treated as admin
    // by this function forever, regardless of actually being in the group.
    fun isAdmin(groupId: String, userId: String): Boolean {
        val group = getGroup(groupId) ?: return false
        if (userId !in group.members) return false
        return group.admins.contains(userId) || group.createdBy == userId
    }

    fun saveGroupMessage(userId: String, message: GroupMessage) {
        val key = "group_messages_${message.groupId}_messages"
        val messages = loadGroupMessages(userId, message.groupId).toMutableList()
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
                msg.replyToId?.let { put("replyToId", it) }
            })
        }
        DesktopStorage.put(key, json.toString())
    }

    fun deleteGroupMessage(userId: String, groupId: String, messageId: String) {
        val key = "group_messages_${groupId}_messages"
        val messages = loadGroupMessages(userId, groupId).toMutableList()
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
                msg.replyToId?.let { put("replyToId", it) }
            })
        }
        DesktopStorage.put(key, json.toString())
    }

    fun loadGroupMessages(userId: String, groupId: String): List<GroupMessage> {
        val key = "group_messages_${groupId}_messages"
        val jsonStr = DesktopStorage.get(key) ?: "[]"
        return try {
            val json = JSONArray(jsonStr)
            (0 until json.length()).map { i ->
                val obj = json.getJSONObject(i)
                val reactions = mutableMapOf<String, String>()
                val reactionsObj = obj.getJSONObject("reactions")
                reactionsObj.keys().forEach { k -> reactions[k] = reactionsObj.getString(k) }

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
                    fileName = obj.optString("fileName", null),
                    replyToId = obj.optString("replyToId", null)
                )
            }.sortedBy { it.timestamp }
        } catch (e: Exception) {
            emptyList()
        }
    }
}
