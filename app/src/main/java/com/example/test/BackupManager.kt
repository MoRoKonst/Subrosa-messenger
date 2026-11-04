package com.subrosa.messenger

import android.content.Context
import android.util.Base64
import android.util.Log
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
        // Found live 2026-08-30: a cached sender_cert (SECURITY.md item 32)
        // is signed by the server over THIS device's fingerprint — it's
        // exactly as identity-scoped as the EC keypair itself, but nothing
        // cleared it here. After a restore swaps in a different identity,
        // every outgoing sealed packet kept attaching the OLD identity's
        // cert to messages now claiming to be from the NEW fingerprint —
        // confirmed live via the recipient's own "sender_cert выписан на
        // X, а from=Y — не совпадает" warning. Not currently a delivery
        // blocker (that check is intentionally non-enforcing during
        // rollout, see item 32's "Deployment gaps" note) but it's live,
        // incorrect sealed-sender metadata reaching a real recipient, not a
        // cosmetic log line. MessengerService requests a fresh one from the
        // server automatically on next connect (see its post-register
        // request_sender_cert call), same as any device that never had one.
        SenderCertManager.clear(context)
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
        // Same reasoning as wipeCurrentIdentityData() above — a sender_cert
        // is bound to the fingerprint being abandoned here.
        SenderCertManager.clear(context)

        // Must run BEFORE the SMK is locked/destroyed below — see
        // DeviceKeyManager.clear()'s own comment: device_priv is SMK-wrapped,
        // and the next register() sets up a brand-new SMK from scratch, under
        // which the current device_priv can never decrypt again. Left
        // uncleared, it silently rotted into an undecryptable blob instead
        // of being treated as "no device key yet" for the new identity.
        // Found in the 2026-09-13 DeviceKeyManager audit.
        DeviceKeyManager.clear(context)

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
        return "subrosa_backup_${sdf.format(java.util.Date())}.bin"
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
        // Found live 2026-08-31: this used to be an `if (privStored != null
        // && pubB64 != null)` around the "ec_private_key"/"ec_public_key"
        // put() calls below with no else — if the identity keypair happened
        // to be missing at export time (any state where CryptoManager.hasKeys()
        // is false), exportBackup() silently produced a "successful" backup
        // that just didn't carry the identity. importBackup() then silently
        // skipped identity restore too (same shape of bug, see the check
        // around "ec_private_key" further down), and the next connect
        // silently minted a brand-new keypair — a totally different
        // fingerprint, with zero indication to the user that anything was
        // wrong. Failing loudly here is the only safe option: a backup that
        // can't prove restoring it keeps the same fingerprint isn't a
        // backup, it's a trap.
        if (privStored == null || pubB64 == null) {
            throw IllegalStateException("Не удалось найти ключ личности для бэкапа — обратитесь в поддержку, экспорт отменён во избежание бэкапа без личности")
        }

        val backup = JSONObject().apply {
            put("version", 7)
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

            // MY_TOKENS — the tokens THIS device generated and handed out for
            // others to reach it. Without these, a contact who wasn't backed
            // up at the same time keeps holding tokens this device forgets
            // the instant wipeCurrentIdentityData() clears its pool on
            // restore — see AnonTokenManager.restoreMyTokens()'s comment.
            // Not a new exposure: same reasoning as anon_tokens/mailbox_tag
            // below, anyone with the backup+password already controls the
            // full identity.
            val myTokens = AnonTokenManager.getMyTokens(context)
            if (myTokens.isNotEmpty()) {
                put("my_tokens", JSONArray(myTokens))
            }
            put("my_mailbox_tag", AnonTokenManager.getOrCreateMyPersistentMailboxTag(context))

            if (privStored != null && pubB64 != null) {
                val privRaw = StorageKeyManager.unwrapBytes(privStored)
                put("ec_private_key", Base64.encodeToString(privRaw, Base64.NO_WRAP))
                put("ec_public_key", pubB64)
                privRaw.fill(0)
            }

            // Found live 2026-09-02: without this, every restore forces an
            // unplanned SPK/PQ-KEM rotation with no grace period (the old
            // one is physically gone — see WipeManager.hardWipe()) — every
            // contact's already-cached copy of our bundle goes stale with
            // nothing to bridge the gap, however carefully the "please
            // refetch" notification is delivered afterward. Carrying the
            // CURRENT prekey forward means a restore isn't a rotation event
            // at all from a contact's point of view. See
            // SessionKeyManager.restorePrekeyFromBackup()'s comment.
            //
            // Same "fail loudly, not silently" principle as the ec_priv/
            // ec_pub check above (2026-08-31): exportCurrentPrekeyForBackup()
            // returns null only if SessionKeyManager.initialize() never ran
            // in this process (e.g. exporting before ever successfully
            // connecting once) — silently producing a backup missing this
            // block would look identical to a successful v7 export while
            // quietly falling back to the exact pre-fix behavior on
            // restore, with nothing telling the user why.
            val prekey = SessionKeyManager.exportCurrentPrekeyForBackup()
                ?: throw IllegalStateException("Ключи сессии ещё не готовы — подключитесь к серверу хотя бы раз, прежде чем делать бэкап")
            put("spk_id", prekey.spkId)
            put("spk_created_at", prekey.spkCreatedAt)
            put("spk_public", Base64.encodeToString(prekey.spkPublic, Base64.NO_WRAP))
            put("spk_private", Base64.encodeToString(prekey.spkPrivate, Base64.NO_WRAP))
            put("pq_public", Base64.encodeToString(prekey.pqPublic, Base64.NO_WRAP))
            put("pq_private", Base64.encodeToString(prekey.pqPrivate, Base64.NO_WRAP))

            // Only the OPK id counter is worth carrying forward, not the
            // actual one-time keypairs — see
            // SessionKeyManager.restoreOpkCounterFromBackup()'s comment for
            // why restoring real OPK key material broke on a second
            // restore of the same file.
            val opkCounter = SessionKeyManager.exportOpkCounterForBackup()
            if (opkCounter > 0) {
                put("opk_counter", opkCounter)
            }

            put("servers", JSONArray().apply {
                ServerManager.getServers(context).forEach { server ->
                    put(JSONObject().apply {
                        put("host", server.host)
                        put("port", server.port)
                        put("name", server.name)
                        put("enabled", server.enabled)
                        // Found live 2026-09-02: path/accessCode used to be
                        // dropped here. toWssUrl() appends `path` to build the
                        // actual connect URL (e.g. the default server's "ws"
                        // → ".../ws") — losing it on export meant
                        // importBackup() below rebuilt this server with
                        // path="" (the Server data class default), silently
                        // changing the URL a restored device connects to from
                        // ".../ws" to the bare origin. That origin doesn't
                        // upgrade to a WebSocket, so every reconnect after a
                        // restore failed the handshake ("Expected HTTP 101
                        // response but was '200 OK'") — not a crypto/identity
                        // bug, just a wrong URL.
                        put("path", server.path)
                        if (server.accessCode != null) put("accessCode", server.accessCode)
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
                        // Found live 2026-08-30: only the classical EC key was ever
                        // backed up here — the hybrid ML-KEM (post-quantum) key
                        // handleFetchedPrekeyBundle() caches per contact
                        // (ChatStorage.getContactPqPublicKey) was missing entirely.
                        // sealPacketForRecipient()/sendAnonTokensTo() both require
                        // it before they can seal anything for this contact, so a
                        // restored device without it falls back to the slower
                        // mailbox bootstrap for every single restored contact,
                        // even ones it already had a fully established channel
                        // with — until a live get_prekey_bundle round trip happens
                        // to repopulate it.
                        val pqPublicKey = ChatStorage.getContactPqPublicKey(context, contactId)
                        if (pqPublicKey != null) {
                            put("pq_public_key", Base64.encodeToString(pqPublicKey, Base64.NO_WRAP))
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
                        // Was missing entirely — Group.description existed
                        // on this same data class but was never carried
                        // into the backup, so exporting then reimporting a
                        // group on Android itself silently lost its
                        // description (Desktop's export/import already had
                        // this field). Found in the 2026-09-13 version-7
                        // cross-platform format audit.
                        put("description", group.description)

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

            // Captured before any of the SMK/UserStorage fixups below run —
            // distinguishes "genuinely fresh device" (RegisterScreen's import
            // dialog: no active session, nothing to preserve) from "already
            // logged in, replacing the active identity with a different
            // backup" (BackupScreen.kt: there IS an existing device login to
            // preserve). See the restorePasswordHash() call further down.
            val wasAlreadyActiveSession = StorageKeyManager.isUnlocked
            val existingPasswordHash = if (wasAlreadyActiveSession) UserStorage.getPasswordHash(context) else null

            // Found live 2026-08-30: this whole function unconditionally
            // required StorageKeyManager.isUnlocked (see the TOTP check right
            // below, and the EC-key restore further down) — fine for the
            // "already logged in, importing a replacement identity" caller
            // (BackupScreen.kt): isUnlocked is already true there (you can't
            // reach Profile>Backup without an active unlocked session), so
            // none of this block ever runs for that caller — it's scoped to
            // !isUnlocked below, which an active session never is.
            //
            // The ONBOARDING caller (RegisterScreen.kt's import dialog) is
            // the one that needed this. First attempt (2026-08-30) only
            // handled the truly-fresh-install case (StorageKeyManager never
            // set up at all) by calling setup() unconditionally when
            // !isSetup(). Still failed the same way when isSetup() was
            // already true but isUnlocked was false — a very common state in
            // practice during testing: reinstalling the same debug APK over
            // itself (adb install -r, or just tapping Install again) leaves
            // the previous install's EncryptedSharedPreferences on disk,
            // including "smk_config", so isSetup() sees a stale SMK from a
            // session nobody ever actually unlocked in this process. Handled
            // properly now: try unlocking the existing SMK with the backup
            // password first (covers the rare case it happens to match);
            // if that fails, this can only be onboarding-with-stale-data
            // (an active logged-in session is never !isUnlocked, so this
            // branch is unreachable for the already-logged-in caller) — safe
            // to discard the orphaned SMK nobody has unlocked yet and set up
            // fresh with the backup's password, which decrypting the backup
            // just proved the caller actually knows.
            if (!StorageKeyManager.isUnlocked) {
                val alreadySetUp = StorageKeyManager.isSetup(context)
                val unlockedExisting = alreadySetUp && StorageKeyManager.unlockWithPassword(context, password)
                if (!unlockedExisting) {
                    if (alreadySetUp) {
                        context.deleteSharedPreferences("smk_config")
                    }
                    StorageKeyManager.setup(context, password)
                }
            }

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
                // Order matters (fixed 2026-08-30): the recovery-code check
                // used to run FIRST, unconditionally taking priority over a
                // valid secret+code whenever the caller happened to fill in
                // both — the recovery-code field's label says "or, if the
                // secret is lost," but nothing in the code actually treated
                // it as a fallback. A user who filled every field they had
                // (understandable — the dialog shows all three at once) got
                // their TOTP protection silently reset and a recovery code
                // burned, even though their live secret+code were correct
                // and nothing needed resetting at all. Now secret+code is
                // tried first when present; recovery-code is only consulted
                // when secret+code weren't provided or didn't verify.
                if (!totpSecret.isNullOrBlank() && !totpCode.isNullOrBlank() && TotpManager.verifyCode(totpSecret, totpCode)) {
                    totpSecretToEnable = totpSecret
                } else {
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
                        // Secret+code were given but didn't verify, and no valid
                        // recovery code either — a specific, more useful error
                        // than the generic "nothing was provided" one below.
                        return Result.failure(IllegalStateException("Неверный TOTP-код"))
                    } else {
                        return Result.failure(IllegalStateException("Этот бэкап защищён TOTP — введите секрет и текущий код, либо один из резервных кодов"))
                    }
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

            // Restore MY_TOKENS/my mailbox tag exactly as they were at backup
            // time — must happen right after the wipe above, before
            // connect()'s next subscribe_tokens call picks up whatever's in
            // AnonTokenManager. See AnonTokenManager.restoreMyTokens()'s
            // comment: without this, a contact who wasn't backed up keeps
            // holding tokens/a mailbox address this device would otherwise
            // forget and never resubscribe/repoll, silently orphaning them.
            val myTokensArr = backup.optJSONArray("my_tokens")
            if (myTokensArr != null) {
                val myTokens = (0 until myTokensArr.length()).map { myTokensArr.getString(it) }
                AnonTokenManager.restoreMyTokens(context, myTokens)
            }
            backup.optString("my_mailbox_tag", null)?.let { tag ->
                AnonTokenManager.syncMyPersistentMailboxTag(context, tag)
            }

            // Found live 2026-08-30, same root cause as the StorageKeyManager
            // gap above: wipeCurrentIdentityData()'s UserStorage.logout()
            // deletes the entire user_prefs file (username, password hash,
            // everything) and nothing recreated it — UserStorage.setUserId()
            // a bit further down only ever touches the user_id field. Left
            // isRegistered()/checkPassword() broken after ANY successful
            // restore, onboarding or already-logged-in alike: on the
            // onboarding path there was never a registration to begin with;
            // on the already-logged-in "replace my identity with a different
            // backup" path, the CURRENT device login silently stopped
            // working the moment this returned success. Re-registers using
            // the backup's own saved username and (for now) the backup's own
            // password — correct as the FINAL state only for the genuinely
            // fresh-device case; restorePasswordHash() below immediately
            // undoes the password part for the already-logged-in case.
            UserStorage.register(context, backup.optString("username", "restored_user"), password)

            // Bug found live 2026-08-30, reported directly ("пароль от
            // аккаунта после бэка не подходит"): for the already-logged-in
            // "replace identity" path, StorageKeyManager's SMK is
            // deliberately left untouched (still wrapped with the device's
            // EXISTING password — see the isUnlocked guard above, which
            // skips re-setup entirely when a session is already active). But
            // register() just above unconditionally overwrote UserStorage's
            // password hash with the BACKUP's password regardless — leaving
            // the SMK and the login-check hash wrapped by two DIFFERENT
            // passwords. Neither password then worked fully on the next
            // login: the device's old password failed checkPassword()
            // outright, and the backup's password passed checkPassword() but
            // then failed to unlock the (untouched) SMK. Restoring the
            // captured pre-wipe hash here undoes register()'s password
            // change for this case only — the device's own login password
            // must not silently change just because the active identity did
            // (same "device-level, not identity-level" principle already
            // applied to TOTP/panic-password/wipe-config elsewhere).
            if (wasAlreadyActiveSession && existingPasswordHash != null) {
                UserStorage.restorePasswordHash(context, existingPasswordHash)
            }

            val version = backup.optInt("version", 1)

            if (version >= 5) {
                val savedDisplayName = backup.optString("display_name", "")
                if (savedDisplayName.isNotBlank()) {
                    UserStorage.saveUserDisplayName(context, savedDisplayName)
                }
            }

            // Found live 2026-08-31: this block used to be silently skipped
            // whenever the backup lacked "ec_private_key"/"ec_public_key"
            // (older exports made before commit b686914, or an export hit by
            // the sibling bug in exportBackup() above) — no error, no
            // warning, just Result.success("Импортировано успешно") further
            // down as if nothing was wrong. Identity never got restored;
            // CryptoManager.hasKeys() stayed false, so the very next connect
            // silently generated a brand-new keypair (see
            // MessengerService.kt's `if (!CryptoManager.hasKeys())
            // generateKeyPair()`) — a completely different fingerprint,
            // discovered only much later as "contacts can't reach me after
            // restore." identityRestored below drives an explicit warning in
            // the final result message instead of a silent no-op.
            var identityRestored = false
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
                    identityRestored = true
                } catch (_: Exception) {}
            }

            // Must run right after the EC identity restore above, while
            // StorageKeyManager is still guaranteed unlocked (same check),
            // and before this process's SessionKeyManager.initialize() ever
            // runs — see restorePrekeyFromBackup()'s comment for why this
            // is the real fix for the "contacts can't reach me after
            // restore" BAD_DECRYPT loop, not just a mitigation for it.
            if (version >= 7 && backup.has("spk_public") && backup.has("pq_public")) {
                try {
                    SessionKeyManager.restorePrekeyFromBackup(
                        context,
                        SessionKeyManager.PrekeySnapshot(
                            spkId = backup.getInt("spk_id"),
                            spkCreatedAt = backup.getLong("spk_created_at"),
                            spkPublic = Base64.decode(backup.getString("spk_public"), Base64.NO_WRAP),
                            spkPrivate = Base64.decode(backup.getString("spk_private"), Base64.NO_WRAP),
                            pqPublic = Base64.decode(backup.getString("pq_public"), Base64.NO_WRAP),
                            pqPrivate = Base64.decode(backup.getString("pq_private"), Base64.NO_WRAP)
                        )
                    )
                } catch (e: Exception) {
                    Log.w("BackupManager", "Не удалось восстановить prekey из бэкапа: ${e.message}")
                }
            }

            if (version >= 7 && backup.has("opk_counter")) {
                try {
                    SessionKeyManager.restoreOpkCounterFromBackup(context, backup.getInt("opk_counter"))
                } catch (e: Exception) {
                    Log.w("BackupManager", "Не удалось поднять OPK-счётчик из бэкапа: ${e.message}")
                }
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
                        host       = obj.getString("host"),
                        port       = obj.getInt("port"),
                        name       = obj.getString("name"),
                        enabled    = obj.getBoolean("enabled"),
                        path       = obj.optString("path", ""),
                        accessCode = obj.optString("accessCode", null)
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
                    if (obj.has("pq_public_key")) {
                        ChatStorage.saveContactPqPublicKey(context, contactId, Base64.decode(obj.getString("pq_public_key"), Base64.NO_WRAP))
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
                        groupKey = groupKey,
                        description = obj.optString("description", "")
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

            val identityWarning = if (!identityRestored) {
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
            passwordChars.fill('\u0000')
        }
    }
}