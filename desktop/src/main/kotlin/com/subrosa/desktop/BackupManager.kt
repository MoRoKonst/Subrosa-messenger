package com.subrosa.desktop

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Desktop counterpart of Android's BackupManager.
 * Same format (version 7, AES-256-GCM + Argon2id, GZIP-compressed JSON)
 * so the encryption/derivation logic matches — but desktop has no
 * multi-server list or channels, so those sections are omitted. Bumped to
 * 7 alongside Android (desktop/Android symmetry audit, 2026-09-03) to add
 * the SPK/PQ prekey snapshot + OPK counter — see exportBackup() below.
 */
object BackupManager {

    /** Clears every identity-scoped local store before a backup is restored
     * on top of it — contacts, messages, groups, sessions, anon-routing
     * token/tag state. Deliberately does NOT touch device-level settings.
     * Mirrors Android's BackupManager.wipeCurrentIdentityData() — see
     * docs/ISSUE_backup_identity_hijack.md, "Смешение identity при импорте
     * на уже используемое устройство". Also called from RegisterScreen when
     * creating a brand-new local account on a machine profile that already
     * has data from a previous local identity — a fresh identity keypair
     * (see DesktopCryptoManager.regenerateKeyPair()) with the OLD identity's
     * chat history/contacts/sessions still attached is not actually a fresh
     * account. Found live, 2026-09-12. */
    internal fun wipeCurrentIdentityData() {
        // The identity key itself isn't cleared here — importBackup() is
        // responsible for either restoring a real one (backup carries
        // ec_private_key/ec_public_key) or minting a genuinely fresh one via
        // DesktopCryptoManager.regenerateKeyPair() when it doesn't (see its
        // own "hasIdentityFields" check, validated BEFORE this function is
        // even called) — never leaving the PREVIOUS identity in place
        // either way. CryptoManager.deleteKeys() used to be described here
        // as "a no-op stub, not a real delete" — no longer true (fixed in
        // the CryptoManager cross-platform audit), but this function still
        // doesn't call it directly: DesktopCryptoManager keeps its own
        // in-memory keypair cache separate from CryptoManager's, and only
        // importKeyPair()/regenerateKeyPair() update both the disk keystore
        // and that cache together.
        ChatStorage.clearAll()
        GroupManager.clearAll()
        AnonTokenManager.clearAll()
        SessionKeyManager.deleteAllSessions()
        // Found in the 2026-09-13 full-logic audit, same reasoning as
        // Android's wipeCurrentIdentityData(): a cached sender_cert is
        // signed by the server over THIS device's OLD fingerprint — exactly
        // as identity-scoped as the EC keypair itself, but nothing cleared
        // it here before this fix. After a restore/regenerate swaps in a
        // different identity, every outgoing sealed packet would keep
        // attaching the OLD identity's cert to messages now claiming to be
        // from the NEW fingerprint. WebSocketClient requests a fresh one
        // automatically after the next register_ok, same as any device that
        // never had one.
        SenderCertManager.clear()
        // Found in the 2026-09-13 InviteCodeManager audit: the cached
        // invite code (InviteCodeManager's own PREF_INVITE_LINK) lives in
        // DesktopStorage under a key none of the clearAll() calls above
        // touch, and generateInviteLink() used to reuse it based only on
        // timestamp — with no check that it belonged to the identity active
        // NOW. Every caller of this function (resetCompromisedIdentity(),
        // RegisterScreen's new-local-account path, and importBackup()) is
        // about to make that false, and a stale invite would redistribute
        // the OLD fingerprint/public key under the NEW identity — and, via
        // the invite's embedded mailbox tag, resurrect OLD anon-routing
        // state into the new identity's active invite-tag polling.
        // generateInviteLink() now also independently verifies this itself
        // (belongsToCurrentIdentity()), but this explicit clear is a
        // second, independent safeguard at the point identity actually
        // changes.
        InviteCodeManager.clearCachedInvite()
    }

    /** "Меня скомпрометировали" — mirrors Android's BackupManager.
     *  resetCompromisedIdentity(): wipes every identity-scoped local store
     *  (contacts, messages, groups, sessions, anon-routing tokens) and
     *  clears the fields that make this device "a registered account",
     *  leaving the user on RegisterScreen to create a fresh account — same
     *  code path as a new install. Device-level settings (TOTP secret,
     *  panic password, auto-lock timeout, cover traffic mode, theme/
     *  language) are deliberately left untouched, unlike the full duress
     *  wipe ("Это не я", see EmergencyWipe.wipeEverythingAndExit()) which
     *  nukes everything including those. TOTP in particular: it protects
     *  THIS DEVICE's app-lock, not the identity being abandoned — a
     *  compromised identity key doesn't mean the device's second factor is
     *  compromised too, and RegisterScreen already has its own handling for
     *  a "TOTP flag looks already enabled" leftover from a prior identity
     *  (same as Android's). Previously this function called
     *  TotpManager.disable(), an unexplained divergence from Android's
     *  explicit "device-level, deliberately untouched" design — found in
     *  the 2026-09-13 full-logic audit. The identity keypair itself isn't
     *  deleted here — RegisterScreen's DesktopCryptoManager.
     *  regenerateKeyPair() call mints the actual replacement the next time
     *  the user registers, same as Desktop's other "new account" path.
     *  Was missing entirely before this fix — a compromised Desktop
     *  identity had no way to revoke/reset itself at all. Found live,
     *  2026-09-12. */
    fun resetCompromisedIdentity() {
        UserStorage.resetIdentityFields()
        wipeCurrentIdentityData()
        SenderCertManager.clear()
        // Mirrors Android's identical call here — was missing on Desktop
        // (found 2026-09-25 auditing OPEN-9). The device keypair proves
        // possession of THIS device to the server, independent of the
        // identity being abandoned; leaving a stale one behind isn't a
        // "preserve device trust" choice the way TOTP above is, it's just
        // dead SMK-wrapped state a fresh registration doesn't need.
        DeviceKeyManager.clear()
        StorageKeyManager.lock()
    }

    fun getBackupFileName(): String {
        val sdf = java.text.SimpleDateFormat("yyyy_MM_dd", java.util.Locale.US)
        return "Subrosa_desktop_backup_${sdf.format(java.util.Date())}.bin"
    }

    fun exportBackup(password: String): String {
        // Fail-closed, mirrors Android's exportBackup() exactly. Without
        // this, exporting while locked would read groups/messages/SPK/PQ
        // private material through DesktopStorage's own get()/loadJsonArray()
        // fallbacks for a value it can't unwrap (raw ciphertext instead of
        // plaintext, or a stale/garbage read depending on the field), and
        // silently pack whatever came back into a backup that LOOKS
        // complete but is actually missing or corrupt secret state, with no
        // indication to the user. Found in the 2026-09-13 full-logic audit.
        if (!StorageKeyManager.isUnlocked) {
            throw IllegalStateException("Приложение заблокировано — сначала разблокируйте его, чтобы экспортировать бэкап")
        }

        val userId = UserStorage.getUserId()
        val displayName = UserStorage.getUserDisplayName()

        val backup = JSONObject().apply {
            put("version", 7)
            put("timestamp", System.currentTimeMillis())
            put("totp_enabled", TotpManager.isEnabled())
            // Hashes only, not the raw codes — lets importBackup() accept a
            // saved-elsewhere recovery code in place of the secret+live-code
            // pair when the secret itself is lost. Mirrors Android's
            // exportBackup() — was missing entirely on Desktop before this.
            val recoveryHashes = TotpManager.getRecoveryCodeHashes()
            if (recoveryHashes.isNotEmpty()) {
                put("totp_recovery_hashes", JSONArray(recoveryHashes))
            }
            put("username", userId)
            put("display_name", displayName)

            val privRaw = DesktopCryptoManager.exportPrivateKeyBytes()
            val pubRaw  = DesktopCryptoManager.exportPublicKeyBytes()
            put("ec_private_key", Base64.getEncoder().encodeToString(privRaw))
            put("ec_public_key", Base64.getEncoder().encodeToString(pubRaw))
            privRaw.fill(0)

            // Current SPK+PQ prekey (not the OPK pool — see below), plus the
            // OPK issuance counter. Throws rather than silently omitting —
            // mirrors Android's BackupManager.exportBackup() and the same
            // desktop/Android symmetry audit that added restorePrekeyFromBackup()
            // (docs/SECURITY_INVARIANTS.md #15). Without this, every restore
            // is an unplanned, ungraced key rotation that breaks incoming
            // decryption for contacts with an already-cached bundle.
            val prekey = SessionKeyManager.exportCurrentPrekeyForBackup()
                ?: throw IllegalStateException("Нет текущего SPK/PQ-ключа — экспорт бэкапа отменён")
            put("spk_id", prekey.spkId)
            put("spk_created_at", prekey.spkCreatedAt)
            put("spk_public", Base64.getEncoder().encodeToString(prekey.spkPublic))
            put("spk_private", Base64.getEncoder().encodeToString(prekey.spkPrivate))
            put("pq_public", Base64.getEncoder().encodeToString(prekey.pqPublic))
            put("pq_private", Base64.getEncoder().encodeToString(prekey.pqPrivate))
            put("opk_counter", SessionKeyManager.exportOpkCounterForBackup())

            // MY_TOKENS/my mailbox tag — mirrors Android's exportBackup().
            // Without these, a contact who wasn't backed up at the same
            // time keeps holding tokens/a mailbox address this device
            // forgets the instant the restore wipe clears its pool — found
            // via a desktop/Android literal wire-field audit, 2026-09-11
            // (Desktop's backup never carried these at all before this fix).
            val myTokens = AnonTokenManager.getMyTokens()
            if (myTokens.isNotEmpty()) {
                put("my_tokens", JSONArray(myTokens))
            }
            put("my_mailbox_tag", AnonTokenManager.getOrCreateMyPersistentMailboxTag())

            put("contacts", JSONArray().apply {
                ChatStorage.getContacts().forEach { contactId ->
                    put(JSONObject().apply {
                        put("id", contactId)
                        put("name", ChatStorage.getContactName(contactId))
                        val publicKey = ChatStorage.getContactPublicKey(contactId)
                        if (publicKey != null) put("public_key", publicKey)
                        // Without this, sealPacketForRecipient()/sendAnonTokensTo()
                        // both require it before they can seal anything for this
                        // contact, so a restored device falls back to the slower
                        // mailbox bootstrap for every single restored contact.
                        val pqPublicKey = ChatStorage.getContactPqPublicKey(contactId)
                        if (pqPublicKey != null) {
                            put("pq_public_key", Base64.getEncoder().encodeToString(pqPublicKey))
                        }
                        // Anon-routing state for this contact.
                        val tokens = AnonTokenManager.getContactTokens(contactId)
                        if (tokens.isNotEmpty()) {
                            put("anon_tokens", JSONArray(tokens))
                        }
                        val mailboxTag = AnonTokenManager.getContactMailboxTag(contactId)
                        if (mailboxTag != null) {
                            put("mailbox_tag", mailboxTag)
                        }
                    })
                }
            })

            put("messages", JSONArray().apply {
                ChatStorage.getContacts().forEach { contactId ->
                    val messages = ChatStorage.loadMessages(userId, contactId)
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
                GroupManager.loadGroups().forEach { group ->
                    put(JSONObject().apply {
                        put("id", group.id)
                        put("name", group.name)
                        put("avatar", group.avatar)
                        put("members", JSONArray(group.members))
                        put("admins", JSONArray(group.admins))
                        put("createdBy", group.createdBy)
                        put("createdAt", group.createdAt)
                        put("description", group.description)
                        if (group.groupKey != null) {
                            put("groupKey", Base64.getEncoder().encodeToString(group.groupKey))
                        }
                    })
                }
            })

            put("group_messages", JSONArray().apply {
                GroupManager.loadGroups().forEach { group ->
                    val messages = GroupManager.loadGroupMessages(userId, group.id)
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

            // Fail-closed — traced Desktop's only current importBackup()
            // caller (ProfileScreen.kt): it's reachable only from an active,
            // already-unlocked session, same shape as Android's equivalent
            // "already logged in, replacing identity" caller, so this never
            // actually trips today. Kept as an explicit backstop rather than
            // relying solely on the quieter fail-closed no-ops now in
            // ChatStorage.saveJsonArray()/GroupManager.saveGroup() (which
            // would otherwise silently restore zero messages/groups instead
            // of writing them as plaintext) — this fails the whole restore
            // loudly instead. Desktop has no onboarding/fresh-install import
            // path yet (unlike Android's RegisterScreen import dialog,
            // which sets StorageKeyManager up from the backup password
            // before ever reaching here) — if one is ever wired up, it must
            // call StorageKeyManager.setup()/unlockWithPassword() first,
            // same as Android's importBackup() does, not bypass this check.
            // Found in the 2026-09-13 full-logic audit.
            if (!StorageKeyManager.isUnlocked) {
                return Result.failure(IllegalStateException("Приложение заблокировано — сначала разблокируйте его, чтобы импортировать бэкап"))
            }

            // Previously not checked at all here — a TOTP-protected backup
            // could be dragged onto Desktop and imported with just the file
            // + password, silently skipping the second factor entirely. See
            // docs/ISSUE_backup_identity_hijack.md. Recovery-code fallback
            // mirrors Android's importBackup() ordering (added here —
            // Desktop previously had no fallback at all, so a TOTP-protected
            // backup with a lost secret couldn't be restored on Desktop no
            // matter what): secret+code tried first when present, recovery
            // code only consulted when they weren't provided or didn't verify.
            var recoveryUsed = false
            var totpSecretToEnable: String? = null
            if (backup.optBoolean("totp_enabled", false)) {
                if (!totpSecret.isNullOrBlank() && !totpCode.isNullOrBlank() && TotpManager.verifyCode(totpSecret, totpCode)) {
                    totpSecretToEnable = totpSecret
                } else {
                    val recoveryHashes = backup.optJSONArray("totp_recovery_hashes")
                    val recoveryMatch = !recoveryCode.isNullOrBlank() && recoveryHashes != null &&
                        (0 until recoveryHashes.length()).any { i ->
                            recoveryHashes.getString(i) == TotpManager.hashRecoveryCode(recoveryCode)
                        }
                    if (recoveryMatch) {
                        // Same "exactly once" caveat as Android's own comment:
                        // this only enforces the check against the backup
                        // file's own embedded hash list, not a durable
                        // server-side consumption — decrypting the same file
                        // with the same code again reproduces the same match.
                        recoveryUsed = true
                    } else if (!totpSecret.isNullOrBlank() && !totpCode.isNullOrBlank()) {
                        return Result.failure(IllegalStateException("Неверный TOTP-код"))
                    } else {
                        return Result.failure(IllegalStateException("Этот бэкап защищён TOTP — введите секрет и текущий код, либо один из резервных кодов"))
                    }
                }
            }

            // Validated BEFORE the destructive wipe below — mirrors
            // Android's exact "never silently retain the pre-import
            // identity" contract. wipeCurrentIdentityData() does not itself
            // touch the identity keypair — it relied entirely on the block
            // below running afterward to overwrite it, which is only true
            // when the backup actually carries one. An older/malformed
            // backup (missing these fields, or version < 6) used to
            // silently leave the PREVIOUS device identity in place while
            // contacts/messages/groups/tokens were wiped and replaced with
            // the backup's — a mismatched, mixed-identity state returned as
            // a plain success with no warning. Found in the 2026-09-13
            // full-logic audit.
            val version = backup.optInt("version", 1)
            val hasIdentityFields = version >= 6 && backup.has("ec_private_key") && backup.has("ec_public_key")

            // Full wipe of whatever identity is currently active on this
            // device before restoring the backup's — mirrors the same
            // decision made on Android, see
            // docs/ISSUE_backup_identity_hijack.md, "Смешение identity при
            // импорте на уже используемое устройство".
            wipeCurrentIdentityData()

            if (!hasIdentityFields) {
                // Mirrors Android's defined safe behavior for this exact
                // case (see its own "identityWarning" below): does NOT
                // retain the old identity, and does NOT fail the whole
                // restore either — mints a genuinely NEW keypair (the same
                // unconditional call RegisterScreen's "new account" flow
                // uses), so the old and new identities can never end up
                // mixed. The loud warning below tells the user their
                // fingerprint changed instead of a silent no-op.
                DesktopCryptoManager.regenerateKeyPair()
            }

            // Restore MY_TOKENS/my mailbox tag exactly as they were at
            // backup time — must happen right after the wipe, before the
            // next subscribe_tokens call picks up whatever's in
            // AnonTokenManager. Mirrors Android's importBackup() — was
            // missing entirely on Desktop before this fix.
            val myTokensArr = backup.optJSONArray("my_tokens")
            if (myTokensArr != null) {
                val myTokens = (0 until myTokensArr.length()).map { myTokensArr.getString(it) }
                AnonTokenManager.restoreMyTokens(myTokens)
            }
            backup.optString("my_mailbox_tag", null)?.let { tag ->
                AnonTokenManager.syncMyPersistentMailboxTag(tag)
            }

            if (version >= 5) {
                val savedDisplayName = backup.optString("display_name", "")
                if (savedDisplayName.isNotBlank()) UserStorage.saveUserDisplayName(savedDisplayName)
            }

            if (hasIdentityFields) {
                val privRaw = Base64.getDecoder().decode(backup.getString("ec_private_key"))
                val pubRaw  = Base64.getDecoder().decode(backup.getString("ec_public_key"))
                DesktopCryptoManager.importKeyPair(privRaw, pubRaw)
                privRaw.fill(0)

                try {
                    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(pubRaw)
                    val restoredUserId = digest.take(8).joinToString("") { "%02X".format(it) }
                    UserStorage.setUserId(restoredUserId)
                } catch (_: Exception) {}
            }

            // SPK+PQ prekey + OPK counter — mirrors Android's importBackup()
            // (docs/SECURITY_INVARIANTS.md #15/#16). Restored right after the
            // identity key, before anything else touches SessionKeyManager,
            // so a post-restore SPK looks like an ordinary (correctly graced)
            // rotation instead of an unplanned one. OPK key material itself
            // is deliberately never restored — only the counter, to avoid
            // reissuing a one-time key id already consumed for real between
            // export and a later restore of the same file.
            if (version >= 7 && backup.has("spk_id") && backup.has("spk_public") && backup.has("pq_public")) {
                val decoder = Base64.getDecoder()
                SessionKeyManager.restorePrekeyFromBackup(
                    SessionKeyManager.PrekeySnapshot(
                        spkId = backup.getInt("spk_id"),
                        spkCreatedAt = backup.optLong("spk_created_at", System.currentTimeMillis()),
                        spkPublic = decoder.decode(backup.getString("spk_public")),
                        spkPrivate = decoder.decode(backup.getString("spk_private")),
                        pqPublic = decoder.decode(backup.getString("pq_public")),
                        pqPrivate = decoder.decode(backup.getString("pq_private"))
                    )
                )
            }
            if (version >= 7 && backup.has("opk_counter")) {
                SessionKeyManager.restoreOpkCounterFromBackup(backup.getInt("opk_counter"))
            }

            // Captured only now, after the identity above may have just been
            // overwritten — messages/groups below are stored under a key
            // namespaced by this value, so capturing it before the swap
            // would silently save everything under the OLD identity's key.
            // Same bug found and fixed on Android.
            val userId = UserStorage.getUserId()

            if (backup.has("contacts")) {
                val contacts = backup.getJSONArray("contacts")
                val restoredContactIds = mutableListOf<String>()
                for (i in 0 until contacts.length()) {
                    val obj = contacts.getJSONObject(i)
                    val contactId = obj.getString("id")
                    ChatStorage.addContact(contactId)
                    ChatStorage.saveContactName(contactId, obj.getString("name"))
                    if (obj.has("public_key")) {
                        ChatStorage.saveContactPublicKey(contactId, obj.getString("public_key"))
                    }
                    if (obj.has("pq_public_key")) {
                        ChatStorage.saveContactPqPublicKey(contactId, Base64.getDecoder().decode(obj.getString("pq_public_key")))
                    }
                    val tokensArr = obj.optJSONArray("anon_tokens")
                    if (tokensArr != null) {
                        val tokens = (0 until tokensArr.length()).map { tokensArr.getString(it) }
                        AnonTokenManager.addContactTokens(contactId, tokens)
                    }
                    obj.optString("mailbox_tag", null)?.let { tag ->
                        AnonTokenManager.setContactMailboxTag(contactId, tag)
                    }
                    restoredContactIds.add(contactId)
                }
                // The backup never carries Double Ratchet session state —
                // flag these contacts so WebSocketClient sends them
                // session_reset on its next handshake, instead of silently
                // sending/receiving against ratchet state this restore just
                // wiped. Mirrors Android's importBackup() exactly. Was
                // missing entirely on Desktop — found in the 2026-09-13
                // full-logic audit.
                if (restoredContactIds.isNotEmpty()) {
                    UserStorage.setPendingSessionResetContacts(restoredContactIds)
                }
            }

            if (backup.has("messages")) {
                // saveMessagesBatch(), not a per-message saveOrUpdateMessage()
                // loop — mirrors Android's importBackup() exactly. The old
                // per-message loop re-loaded and re-saved the WHOLE
                // per-contact message array on every single message (O(n²)
                // for an n-message history), each save independently subject
                // to saveJsonArray()'s SMK-lock check. Found in the
                // 2026-09-13 full-logic audit.
                val messages = backup.getJSONArray("messages")
                val messagesByContact = mutableMapOf<String, MutableList<ChatStorage.StoredMessage>>()
                for (i in 0 until messages.length()) {
                    val obj = messages.getJSONObject(i)
                    val contact = obj.getString("contact")
                    messagesByContact.getOrPut(contact) { mutableListOf() }.add(
                        ChatStorage.StoredMessage(
                            text = obj.getString("text"),
                            isOwn = obj.getBoolean("isOwn"),
                            timestamp = obj.getLong("timestamp")
                        )
                    )
                }
                messagesByContact.forEach { (contact, msgs) ->
                    ChatStorage.saveMessagesBatch(userId, contact, msgs)
                }
            }

            if (version >= 4 && backup.has("groups")) {
                val groups = backup.getJSONArray("groups")
                for (i in 0 until groups.length()) {
                    val obj = groups.getJSONObject(i)
                    val members = mutableListOf<String>()
                    val membersArray = obj.getJSONArray("members")
                    for (j in 0 until membersArray.length()) members.add(membersArray.getString(j))
                    val admins = mutableListOf<String>()
                    val adminsArray = obj.getJSONArray("admins")
                    for (j in 0 until adminsArray.length()) admins.add(adminsArray.getString(j))
                    val groupKey = if (obj.has("groupKey")) {
                        Base64.getDecoder().decode(obj.getString("groupKey"))
                    } else null

                    GroupManager.saveGroup(
                        Group(
                            id = obj.getString("id"),
                            name = obj.getString("name"),
                            avatar = obj.getString("avatar"),
                            members = members,
                            admins = admins,
                            createdBy = obj.getString("createdBy"),
                            createdAt = obj.getLong("createdAt"),
                            groupKey = groupKey,
                            description = obj.optString("description", "")
                        )
                    )
                }
            }

            if (version >= 4 && backup.has("group_messages")) {
                val groupMessages = backup.getJSONArray("group_messages")
                for (i in 0 until groupMessages.length()) {
                    val obj = groupMessages.getJSONObject(i)
                    GroupManager.saveGroupMessage(
                        userId,
                        GroupMessage(
                            id = java.util.UUID.randomUUID().toString(),
                            groupId = obj.getString("group_id"),
                            senderId = obj.getString("sender_id"),
                            senderName = obj.getString("sender_name"),
                            text = obj.getString("text"),
                            timestamp = obj.getLong("timestamp"),
                            isOwn = obj.getBoolean("isOwn")
                        )
                    )
                }
            }

            // TOTP state applied only now, after everything above succeeded —
            // mirrors Android's importBackup() ordering (decided earlier,
            // above; no state mutation until the restore itself is known-good).
            if (recoveryUsed) {
                TotpManager.disable()
            } else if (totpSecretToEnable != null) {
                TotpManager.enable(totpSecretToEnable)
            }

            // Mirrors Android's identityWarning exactly — a loud warning
            // instead of the silent no-op this used to be (see
            // hasIdentityFields above).
            val identityWarning = if (!hasIdentityFields) {
                " ВНИМАНИЕ: этот бэкап не содержал ключ личности — у вас НОВЫЙ фингерпринт, старые контакты вас не найдут, пока вы не обменяетесь с ними инвайт-кодом заново."
            } else ""

            if (recoveryUsed) {
                Result.success("Импортировано успешно (версия $version). TOTP-защита сброшена резервным кодом — включите её заново в настройках.$identityWarning")
            } else {
                Result.success("Импортировано успешно (версия $version)$identityWarning")
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

    private fun ungzip(data: ByteArray): ByteArray =
        GZIPInputStream(ByteArrayInputStream(data)).use { it.readBytes() }

    private fun encryptBackup(data: ByteArray, password: String): String {
        val salt = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val iv   = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val key  = deriveKey(password, salt)
        // Wipe moved into finally — mirrors Android's encryptBackup() exactly.
        // Was unconditional after doFinal(), so an exception from doFinal()/
        // init() (e.g. Cipher.getInstance() failing) skipped the wipe and
        // left the derived key sitting in the heap. Found in the 2026-09-13
        // full-logic audit.
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            val encrypted = cipher.doFinal(data)
            val combined = salt + iv + encrypted
            return Base64.getEncoder().encodeToString(combined)
        } finally {
            key.fill(0)
        }
    }

    private fun decryptBackup(encryptedB64: String, password: String): ByteArray {
        val combined = Base64.getDecoder().decode(encryptedB64)
        if (combined.size < 32 + 12 + 16) {
            throw IllegalArgumentException("Файл бэкапа повреждён или неверный формат")
        }
        val salt      = combined.copyOfRange(0, 32)
        val iv        = combined.copyOfRange(32, 44)
        val encrypted = combined.copyOfRange(44, combined.size)

        val key = deriveKey(password, salt)
        // Wipe moved into finally — mirrors Android's decryptBackup() exactly
        // (was wiping the key BEFORE doFinal() ran at all, relying on
        // SecretKeySpec's constructor having already copied the bytes —
        // functionally safe today, but fragile against a future refactor
        // and inconsistent with encryptBackup()'s own pattern). Found in the
        // 2026-09-13 full-logic audit.
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
        // password.toCharArray() captured into a local so it can be wiped —
        // mirrors Android's deriveKey() exactly. Was created inline and
        // passed straight to generateBytes(), leaving no reference to zero
        // afterward. The underlying JVM String itself still can't be
        // reliably wiped from the heap either way — same caveat as
        // Android's own comment — but this at least stops compounding the
        // exposure with an extra, unwiped copy on every call. Found in the
        // 2026-09-13 full-logic audit.
        val passwordChars = password.toCharArray()
        val key = ByteArray(32)
        try {
            gen.generateBytes(passwordChars, key)
            return key
        } finally {
            passwordChars.fill(' ')
        }
    }
}
