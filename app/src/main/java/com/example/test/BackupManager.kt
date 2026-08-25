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

    /** Clears every identity-scoped local store before a backup is restored
     * on top of it — contacts, messages, groups, sessions, anon-routing
     * token/tag state. Deliberately does NOT touch device-level settings
     * (theme, language, wipe/dead-man's-switch config) — those are about
     * this device, not about which identity is currently active on it. Not
     * a security/panic wipe (no process kill, no AndroidKeyStore alias
     * cleanup) — see WipeManager for that. See
     * docs/ISSUE_backup_identity_hijack.md, "Смешение identity при импорте
     * на уже используемое устройство". */
    private fun wipeCurrentIdentityData(context: Context) {
        UserStorage.logout(context)
        GroupManager.clearAll(context)
        AnonTokenManager.clearAll(context)
        SessionKeyManager.deleteAllSessions()
    }

    /** "Я думаю, меня скомпрометировали" — identity-only reset. Deliberately
     * cheap: doesn't try to figure out which device is legitimate, doesn't
     * notify old contacts via the (possibly-compromised) old key, doesn't
     * migrate anything. Burns the current identity (EC keypair, username,
     * contacts, messages, groups, sessions, anon-routing tokens, SMK wrap)
     * and leaves the user on RegisterScreen to create a fresh account —
     * same code path as a new install. Device-level settings (TOTP secret,
     * panic password, wipe/dead-man's-switch config, app-lock timeout,
     * calculator disguise, theme/language) are deliberately left untouched
     * — unlike the "Не я!" duress panic wipe (WipeManager.hardWipe), which
     * nukes everything including those. See
     * docs/ISSUE_backup_identity_hijack.md, "Identity-rotation flow". */
    fun resetCompromisedIdentity(context: Context) {
        UserStorage.resetIdentityFields(context)
        GroupManager.clearAll(context)
        AnonTokenManager.clearAll(context)
        SessionKeyManager.deleteAllSessions()
        CryptoManager.deleteKeys()

        StorageKeyManager.lock()
        context.deleteSharedPreferences("smk_config")
        try {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            if (ks.containsAlias("beacon_smk_wrap")) ks.deleteEntry("beacon_smk_wrap")
        } catch (_: Exception) {}
    }

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
            // Hashes only, not the raw codes — same principle as the secret
            // itself never living inside the backup. Lets importBackup()
            // accept one of these saved-elsewhere recovery codes in place of
            // the secret+live-code pair when the secret itself is lost. See
            // docs/ISSUE_backup_identity_hijack.md, "Восстановление при
            // утере TOTP-секрета".
            val recoveryHashes = TotpManager.getRecoveryCodeHashes(context)
            if (recoveryHashes.isNotEmpty()) {
                put("totp_recovery_hashes", JSONArray(recoveryHashes))
            }
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
        totpCode: String? = null,
        recoveryCode: String? = null
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

            // Decision only, no state mutation yet (external review 2026-08-23):
            // TotpManager.enable()/disable() used to be called right here,
            // before wipeCurrentIdentityData() and before any of the actual
            // restore work below. If contacts/messages/EC-key restore then
            // failed and this function returned Result.failure, the device's
            // TOTP state had already been changed for an identity restore
            // that never actually completed. Applied instead only after every
            // other restore step below has succeeded, right before returning
            // Result.success.
            var recoveryUsed = false
            var totpSecretToEnable: String? = null
            if (backup.optBoolean("totp_enabled", false)) {
                if (!StorageKeyManager.isUnlocked) {
                    return Result.failure(IllegalStateException("Приложение заблокировано — сначала разблокируйте его, чтобы импортировать бэкап"))
                }
                val recoveryHashes = backup.optJSONArray("totp_recovery_hashes")
                val recoveryMatch = !recoveryCode.isNullOrBlank() && recoveryHashes != null &&
                    (0 until recoveryHashes.length()).any { i ->
                        recoveryHashes.getString(i) == TotpManager.hashRecoveryCode(recoveryCode)
                    }
                if (recoveryMatch) {
                    // Same principle as the server-side device-gated flow's
                    // recovery-code fallback: a code substitutes for the lost
                    // secret exactly once, and leaves TOTP protection off
                    // afterward rather than silently carrying the old,
                    // now-partially-compromised secret forward — the caller
                    // is expected to prompt the user to set it up fresh.
                    // NOTE this "exactly once" is only enforced by whatever
                    // gates re-registration server-side (device_id) -- this
                    // local check just compares a hash against the backup
                    // file's own embedded list, so decrypting the same backup
                    // file with the same code again reproduces the same
                    // match every time. Not fixable client-side in a way that
                    // means anything; flagged, not silently claimed as solved.
                    recoveryUsed = true
                } else if (!totpSecret.isNullOrBlank() && !totpCode.isNullOrBlank()) {
                    if (!TotpManager.verifyCode(totpSecret, totpCode)) {
                        return Result.failure(IllegalStateException("Неверный TOTP-код"))
                    }
                    totpSecretToEnable = totpSecret
                } else {
                    return Result.failure(IllegalStateException("Этот бэкап защищён TOTP — введите секрет и текущий код, либо один из резервных кодов"))
                }
            }

            // Full wipe of whatever identity is currently active on this
            // device before restoring the backup's — see
            // docs/ISSUE_backup_identity_hijack.md, "Смешение identity при
            // импорте на уже используемое устройство". The backup path was
            // never meant to merge/roll back into an existing identity's
            // history; the user's call: this is strictly "I lost my phone,
            // give me my data back", not a chat-history time machine. A
            // no-op on the RegisterScreen onboarding path (nothing to wipe
            // there yet).
            wipeCurrentIdentityData(context)

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

            // Captured only now, after the identity above may have just been
            // overwritten — messages/groups below are stored under a key
            // namespaced by this value (see ChatStorage.chatKey()), so
            // capturing it before the swap would silently save everything
            // under the OLD identity's key, invisible once the app starts
            // reading as the new one. Found while wiring the wipe above.
            val username = UserStorage.getUserId(context)

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

            // TOTP state applied only now, after everything above succeeded --
            // see the comment where these were decided, above.
            if (recoveryUsed) {
                // Was previously never actually called despite the success
                // message below already claiming TOTP was reset (external
                // review 2026-08-23) -- disable() also clears this identity's
                // stale recovery-code hashes now (see TotpManager.disable()).
                TotpManager.disable(context)
            } else if (totpSecretToEnable != null) {
                TotpManager.enable(context, totpSecretToEnable)
            }

            if (recoveryUsed) {
                Result.success("Импортировано успешно (версия $version). TOTP-защита сброшена резервным кодом — включите её заново в настройках.")
            } else {
                Result.success("Импортировано успешно (версия $version)")
            }
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
        // Wipe moved into finally (external review 2026-08-23) -- previously
        // sat after doFinal() unconditionally, so an exception from doFinal()
        // (or init()) skipped it and left the derived key sitting in the heap.
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            val encrypted = cipher.doFinal(data)
            val combined = salt + iv + encrypted
            return Base64.encodeToString(combined, Base64.NO_WRAP)
        } finally {
            key.fill(0)
        }
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
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            return cipher.doFinal(encrypted)
        } finally {
            key.fill(0)
        }
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
        // password.toCharArray() captured into a local so it can be wiped --
        // previously created inline and passed straight to generateBytes(),
        // meaning there was no reference left to zero afterward (external
        // review 2026-08-23). The underlying Kotlin/JVM String itself still
        // can't be reliably wiped from the heap either way -- that would need
        // the password to never be a String in the first place (CharArray
        // from the UI layer down), which is a larger change than this file;
        // this at least stops compounding the exposure with an extra,
        // unwiped copy on every call.
        val passwordChars = password.toCharArray()
        val key = ByteArray(32)
        try {
            gen.generateBytes(passwordChars, key)
            return key
        } finally {
            passwordChars.fill(' ')
        }
    }
}