package com.subrosa.messenger

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object BackupManager {

    fun getBackupFileName(): String {
        val sdf = java.text.SimpleDateFormat("yyyy_MM_dd", java.util.Locale.US)
        return "beacon_backup_${sdf.format(java.util.Date())}.bin"
    }

    fun exportBackup(context: Context, password: String): String {
        if (!StorageKeyManager.isUnlocked) {
            throw IllegalStateException("Приложение заблокировано — сначала разблокируйте его, чтобы экспортировать бэкап")
        }

        val username = UserStorage.getUserId(context)

        val displayName = UserStorage.getUserDisplayName(context)

        val ecPrefs = EncryptedStorage.getEncryptedPrefs(context, "beacon_ec_keys_enc")
        val privStored = ecPrefs.getString("ec_priv", null)
        val pubB64     = ecPrefs.getString("ec_pub", null)

        val backup = JSONObject().apply {
            put("version", 6)
            put("timestamp", System.currentTimeMillis())
            put("totp_enabled", TotpManager.isEnabled(context))
            put("username", username)
            put("display_name", displayName)

            if (privStored != null && pubB64 != null) {
                val privRaw = StorageKeyManager.unwrapBytes(privStored)
                put("ec_private_key", Base64.encodeToString(privRaw, Base64.NO_WRAP))
                put("ec_public_key", pubB64)
                privRaw.fill(0)
            }

            put("servers", JSONArray().apply {
                ServerManager.getServers(context).forEach { server ->
                    put(JSONObject().apply {
                        put("host", server.host)
                        put("port", server.port)
                        put("name", server.name)
                        put("enabled", server.enabled)
                    })
                }
            })

            put("contacts", JSONArray().apply {
                ChatStorage.getContacts(context).forEach { contactId ->
                    put(JSONObject().apply {
                        put("id", contactId)
                        put("name", ChatStorage.getContactName(context, contactId))
                        val publicKey = ChatStorage.getContactPublicKey(context, contactId)
                        if (publicKey != null) {
                            put("public_key", publicKey)
                        }
                        // Anon-routing state for this contact — without it, the
                        // first message to them after a restore has neither a
                        // token nor a mailbox tag to go out anonymously with,
                        // and falls back to direct addressing (see
                        // docs/ISSUE_backup_identity_hijack.md, "прямая
                        // адресация, не через анон-токен", item 2). Not a new
                        // exposure: anyone with the backup+password already has
                        // full identity control and could bootstrap fresh
                        // tokens/tags the normal way regardless.
                        val tokens = AnonTokenManager.getContactTokens(context, contactId)
                        if (tokens.isNotEmpty()) {
                            put("anon_tokens", JSONArray(tokens))
                        }
                        val mailboxTag = AnonTokenManager.getContactMailboxTag(context, contactId)
                        if (mailboxTag != null) {
                            put("mailbox_tag", mailboxTag)
                        }
                    })
                }
            })

            put("messages", JSONArray().apply {
                ChatStorage.getContacts(context).forEach { contactId ->
                    val messages = ChatStorage.loadMessages(context, username, contactId)
                    messages.forEach { msg ->
                        put(JSONObject().apply {
                            put("contact", contactId)
                            put("text", msg.text)
                            put("isOwn", msg.isOwn)
                            put("timestamp", msg.timestamp)

                        })
                    }
                }
            })

            put("groups", JSONArray().apply {
                GroupManager.loadGroups(context).forEach { group ->
                    put(JSONObject().apply {
                        put("id", group.id)
                        put("name", group.name)
                        put("avatar", group.avatar)
                        put("members", JSONArray(group.members))
                        put("admins", JSONArray(group.admins))
                        put("createdBy", group.createdBy)
                        put("createdAt", group.createdAt)

                        if (group.groupKey != null) {
                            put("groupKey", Base64.encodeToString(group.groupKey, Base64.NO_WRAP))
                        }
                    })
                }
            })

            put("group_messages", JSONArray().apply {
                GroupManager.loadGroups(context).forEach { group ->
                    val messages = GroupManager.loadGroupMessages(context, username, group.id)
                    messages.forEach { msg ->
                        put(JSONObject().apply {
                            put("group_id", msg.groupId)
                            put("sender_id", msg.senderId)
                            put("sender_name", msg.senderName)
                            put("text", msg.text)
                            put("timestamp", msg.timestamp)
                            put("isOwn", msg.isOwn)
                        })
                    }
                }
            })
        }

        val jsonBytes = backup.toString().toByteArray(Charsets.UTF_8)
        val compressedBytes = gzip(jsonBytes)
        jsonBytes.fill(0)

        val result = encryptBackup(compressedBytes, password)
        compressedBytes.fill(0)

        return result
    }

    fun importBackup(
        context: Context,
        encryptedData: String,
        password: String,
        totpSecret: String? = null,
        totpCode: String? = null
    ): Result<String> {
        return try {
            val decryptedBytes = decryptBackup(encryptedData, password)

            val jsonBytes = try {
                val decompressed = ungzip(decryptedBytes)
                decryptedBytes.fill(0)
                decompressed
            } catch (e: Exception) {
                decryptedBytes
            }

            val backup = JSONObject(String(jsonBytes, Charsets.UTF_8))
            jsonBytes.fill(0)

            if (backup.optBoolean("totp_enabled", false)) {
                if (totpSecret.isNullOrBlank() || totpCode.isNullOrBlank()) {
                    return Result.failure(IllegalStateException("Этот бэкап защищён TOTP — введите секрет и текущий код"))
                }
                if (!TotpManager.verifyCode(totpSecret, totpCode)) {
                    return Result.failure(IllegalStateException("Неверный TOTP-код"))
                }
                if (!StorageKeyManager.isUnlocked) {
                    return Result.failure(IllegalStateException("Приложение заблокировано — сначала разблокируйте его, чтобы импортировать бэкап"))
                }
                TotpManager.enable(context, totpSecret)
            }

            val username = UserStorage.getUserId(context)
            val version = backup.optInt("version", 1)

            if (version >= 5) {
                val savedDisplayName = backup.optString("display_name", "")
                if (savedDisplayName.isNotBlank()) {
                    UserStorage.saveUserDisplayName(context, savedDisplayName)
                }
            }

            if (version >= 6 && backup.has("ec_private_key") && backup.has("ec_public_key")) {
                if (!StorageKeyManager.isUnlocked) {
                    return Result.failure(IllegalStateException("SMK не разблокирован — невозможно безопасно сохранить приватный ключ"))
                }
                val privRaw = Base64.decode(backup.getString("ec_private_key"), Base64.NO_WRAP)
                val pubB64  = backup.getString("ec_public_key")
                val ecPrefs = EncryptedStorage.getEncryptedPrefs(context, "beacon_ec_keys_enc")
                val privToStore = StorageKeyManager.wrapBytes(privRaw)
                ecPrefs.edit().putString("ec_priv", privToStore).putString("ec_pub", pubB64).commit()
                privRaw.fill(0)

                try {
                    val pubBytes = Base64.decode(pubB64, Base64.NO_WRAP)
                    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(pubBytes)
                    val restoredUserId = digest.take(8).joinToString("") { "%02X".format(it) }
                    UserStorage.setUserId(context, restoredUserId)
                } catch (_: Exception) {}
            }

            if (backup.has("servers")) {
                val servers = backup.getJSONArray("servers")
                val serverList = mutableListOf<ServerManager.Server>()
                for (i in 0 until servers.length()) {
                    val obj = servers.getJSONObject(i)
                    serverList.add(ServerManager.Server(
                        host    = obj.getString("host"),
                        port    = obj.getInt("port"),
                        name    = obj.getString("name"),
                        enabled = obj.getBoolean("enabled")
                    ))
                }
                ServerManager.saveServers(context, serverList)
            }

            if (backup.has("contacts")) {
                val contacts = backup.getJSONArray("contacts")
                val restoredContactIds = mutableListOf<String>()
                for (i in 0 until contacts.length()) {
                    val obj = contacts.getJSONObject(i)
                    val contactId = obj.getString("id")
                    ChatStorage.addContact(context, contactId)
                    ChatStorage.saveContactName(context, contactId, obj.getString("name"))

                    if (obj.has("public_key")) {
                        ChatStorage.saveContactPublicKey(context, contactId, obj.getString("public_key"))
                    }

                    val tokensArr = obj.optJSONArray("anon_tokens")
                    if (tokensArr != null) {
                        val tokens = (0 until tokensArr.length()).map { tokensArr.getString(it) }
                        AnonTokenManager.addContactTokens(context, contactId, tokens)
                    }
                    obj.optString("mailbox_tag", null)?.let { tag ->
                        AnonTokenManager.setContactMailboxTag(context, contactId, tag)
                    }

                    restoredContactIds.add(contactId)
                }
                // The backup never carries Double Ratchet session state —
                // flag these contacts so MessengerService sends them
                // session_reset on its next handshake, instead of silently
                // failing to decrypt their next message.
                if (restoredContactIds.isNotEmpty()) {
                    UserStorage.setPendingSessionResetContacts(context, restoredContactIds)
                }
            }

            if (backup.has("messages")) {
                val messages = backup.getJSONArray("messages")
                val messagesByContact = mutableMapOf<String, MutableList<ChatStorage.StoredMessage>>()
                for (i in 0 until messages.length()) {
                    val obj = messages.getJSONObject(i)
                    val contact = obj.getString("contact")
                    messagesByContact.getOrPut(contact) { mutableListOf() }.add(
                        ChatStorage.StoredMessage(
                            text      = obj.getString("text"),
                            isOwn     = obj.getBoolean("isOwn"),
                            timestamp = obj.getLong("timestamp")

                        )
                    )
                }
                messagesByContact.forEach { (contact, msgs) ->
                    ChatStorage.saveMessagesBatch(context, username, contact, msgs)
                }
            }

            if (version >= 4 && backup.has("groups")) {
                val groups = backup.getJSONArray("groups")
                for (i in 0 until groups.length()) {
                    val obj = groups.getJSONObject(i)

                    val members = mutableListOf<String>()
                    val membersArray = obj.getJSONArray("members")
                    for (j in 0 until membersArray.length()) {
                        members.add(membersArray.getString(j))
                    }

                    val admins = mutableListOf<String>()
                    val adminsArray = obj.getJSONArray("admins")
                    for (j in 0 until adminsArray.length()) {
                        admins.add(adminsArray.getString(j))
                    }

                    val groupKey = if (obj.has("groupKey")) {
                        Base64.decode(obj.getString("groupKey"), Base64.NO_WRAP)
                    } else null

                    val group = Group(
                        id = obj.getString("id"),
                        name = obj.getString("name"),
                        avatar = obj.getString("avatar"),
                        members = members,
                        admins = admins,
                        createdBy = obj.getString("createdBy"),
                        createdAt = obj.getLong("createdAt"),
                        groupKey = groupKey
                    )

                    GroupManager.saveGroup(context, group)
                }
            }

            if (version >= 4 && backup.has("group_messages")) {
                val groupMessages = backup.getJSONArray("group_messages")
                for (i in 0 until groupMessages.length()) {
                    val obj = groupMessages.getJSONObject(i)

                    val msg = GroupMessage(
                        id = java.util.UUID.randomUUID().toString(),
                        groupId = obj.getString("group_id"),
                        senderId = obj.getString("sender_id"),
                        senderName = obj.getString("sender_name"),
                        text = obj.getString("text"),
                        timestamp = obj.getLong("timestamp"),
                        isOwn = obj.getBoolean("isOwn")
                    )

                    GroupManager.saveGroupMessage(context, username, msg)
                }
            }

            Result.success("Импортировано успешно (версия $version)")
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun gzip(data: ByteArray): ByteArray {
        val bos = ByteArrayOutputStream()
        GZIPOutputStream(bos).use { it.write(data) }
        return bos.toByteArray()
    }

    private fun ungzip(data: ByteArray): ByteArray {
        return GZIPInputStream(ByteArrayInputStream(data)).use { it.readBytes() }
    }

    private fun encryptBackup(data: ByteArray, password: String): String {
        val salt = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val iv   = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val key  = deriveKey(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(data)
        key.fill(0)

        val combined = salt + iv + encrypted
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decryptBackup(encryptedB64: String, password: String): ByteArray {
        val combined = Base64.decode(encryptedB64, Base64.NO_WRAP)

        if (combined.size < 32 + 12 + 16) {
            throw IllegalArgumentException("Файл бэкапа повреждён или неверный формат")
        }

        val salt      = combined.copyOfRange(0, 32)
        val iv        = combined.copyOfRange(32, 44)
        val encrypted = combined.copyOfRange(44, combined.size)

        val key = deriveKey(password, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        key.fill(0)

        return cipher.doFinal(encrypted)
    }

    private fun deriveKey(password: String, salt: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withParallelism(1)
            .withMemoryAsKB(65_536)
            .withIterations(3)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val key = ByteArray(32)
        gen.generateBytes(password.toCharArray(), key)
        return key
    }
}