package com.subrosa.desktop

import java.util.UUID
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

object ChatStorage {

    private const val PREFS_NAME = "chat_storage_encrypted"

    // No voicePath/voiceDuration or videoPath/videoDuration, unlike
    // Android's StoredMessage — traced, both intentional:
    //  - Voice IS supported on Desktop, but reuses the generic filePath/
    //    fileName pair with a VoiceRecorder.FILE_NAME sentinel (see
    //    ChatScreen.kt's FileRow: `isVoice = fileName == VoiceRecorder.
    //    FILE_NAME`) instead of a dedicated field — already fully persisted/
    //    restored across restart via imagePath/filePath's existing storage,
    //    same as any other file attachment. Duration is never persisted or
    //    displayed at all (the player UI just says "click to listen", no
    //    timer), so there's nothing for voiceDuration to carry. Adding a
    //    parallel voicePath field would duplicate filePath with no caller
    //    ever populating it separately.
    //  - Video has no send/receive/UI path on Desktop whatsoever (no
    //    equivalent of Android's sendVideoCircle/video_circle_batch) — not
    //    a persistence gap, a whole feature that doesn't exist yet. Adding
    //    videoPath/videoDuration now would be dead schema with no producer.
    // Found in the 2026-09-13 full-logic audit.
    data class StoredMessage(
        val id: String = UUID.randomUUID().toString(),
        val text: String,
        val isOwn: Boolean,
        val timestamp: Long = System.currentTimeMillis(),
        val reactions: Map<String, String> = emptyMap(),
        val isEdited: Boolean = false,
        val imagePath: String? = null,
        val filePath: String? = null,
        val fileName: String? = null,
        val isDelivered: Boolean = false,
        val isRead: Boolean = false,
        val isFailed: Boolean = false,
        val replyToId: String? = null,
        val expiresAt: Long = 0L,
        // Was entirely absent before this fix -- the "voice" wire frame
        // already carried duration (WebSocketClient's signature transcript
        // uses it) but it was discarded before reaching storage, so FileRow
        // never had anything to show beyond "click to listen", and every
        // voice bubble showed as identical zero-length after an app
        // restart. See WebSocketClient.onFileReceived's own comment.
        val voiceDuration: Int = 0,
        // Video circle (Telegram-style round video message) — ported from
        // Android's VideoCircleScreen. videoPath is an encrypted-at-rest
        // blob path (like imagePath/filePath), not the plaintext MP4.
        val videoPath: String? = null,
        val videoDuration: Int = 0
    )

    private fun chatKey(myUserId: String, recipientUserId: String): String {
        val pair = listOf(myUserId, recipientUserId).sorted()
        return "chat_${pair[0]}_${pair[1]}"
    }

    /** Wipes every contact, message thread, cached key/avatar/draft — used
     * when replacing this device's active identity with a different one
     * from a backup, see BackupManager.wipeCurrentIdentityData(). Prefix
     * scan rather than enumerating contacts first, since chatKey() depends
     * on myUserId too and this needs to catch threads under any prior
     * identity, not just the current one. */
    fun clearAll() {
        // Was missing "pqkey_" and "blocked_contacts" — this function's own
        // contract is "wipes every contact, message thread, cached key/
        // avatar/draft" on identity replacement (see
        // BackupManager.wipeCurrentIdentityData()), but a leftover PQ key
        // cache or block-list entry from the OLD identity surviving into a
        // freshly restored/registered one is exactly the kind of stale
        // cross-identity state this function exists to prevent (same class
        // of bug as the AnonTokenManager/GroupManager equivalents already
        // fixed this audit). Found in the 2026-09-13 full-logic audit.
        val prefixes = listOf("chat_", "name_", "key_", "avatar_", "draft_", "disappear_", "pqkey_")
        DesktopStorage.getAllKeys()
            .filter { it == "contacts" || it == "blocked_contacts" || prefixes.any { p -> it.startsWith(p) } }
            .forEach { DesktopStorage.remove(it) }
    }

    fun loadMessages(
        myUserId: String,
        recipientUserId: String
    ): MutableList<StoredMessage> {
        val array = loadJsonArray(chatKey(myUserId, recipientUserId))
        val list = mutableListOf<StoredMessage>()

        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            val imagePath = obj.optString("image_path", null)
            val filePath  = obj.optString("file_path", null)
            val fileName  = obj.optString("file_name", null)
            val videoPath = obj.optString("video_path", null)

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
                    isEdited = obj.optBoolean("is_edited", false),
                    imagePath = if (imagePath.isNullOrBlank()) null else imagePath,
                    filePath = if (filePath.isNullOrBlank()) null else filePath,
                    fileName = if (fileName.isNullOrBlank()) null else fileName,
                    isDelivered = obj.optBoolean("is_delivered", false),
                    isRead = obj.optBoolean("is_read", false),
                    isFailed = obj.optBoolean("is_failed", false),
                    replyToId = obj.optString("reply_to_id", null).takeIf { !it.isNullOrBlank() },
                    expiresAt = expiresAt,
                    voiceDuration = obj.optInt("voice_duration", 0),
                    videoPath = if (videoPath.isNullOrBlank()) null else videoPath,
                    videoDuration = obj.optInt("video_duration", 0)
                )
            )
        }
        return list
    }

    fun saveOrUpdateMessage(
        myUserId: String,
        recipientUserId: String,
        message: StoredMessage
    ) {
        val key = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(key)

        var updated = false
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optString("id") == message.id) {
                val reactionsJson = JSONObject()
                message.reactions.forEach { (user, emoji) -> reactionsJson.put(user, emoji) }
                obj.put("reactions", reactionsJson)
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
                obj.put("voice_duration", message.voiceDuration)
                obj.put("video_path", message.videoPath)
                obj.put("video_duration", message.videoDuration)
                updated = true
                break
            }
        }

        if (!updated) {
            val reactionsJson = JSONObject()
            message.reactions.forEach { (user, emoji) -> reactionsJson.put(user, emoji) }
            array.put(JSONObject().apply {
                put("id", message.id)
                put("text", message.text)
                put("isOwn", message.isOwn)
                put("timestamp", message.timestamp)
                put("reactions", reactionsJson)
                put("is_edited", message.isEdited)
                put("image_path", message.imagePath)
                put("file_path", message.filePath)
                put("file_name", message.fileName)
                put("is_delivered", message.isDelivered)
                put("is_read", message.isRead)
                put("is_failed", message.isFailed)
                put("reply_to_id", message.replyToId ?: "")
                put("expires_at", message.expiresAt)
                put("voice_duration", message.voiceDuration)
                put("video_path", message.videoPath)
                put("video_duration", message.videoDuration)
            })
        }
        saveJsonArray(key, array)
    }

    fun getContacts(): MutableList<String> {
        val json = DesktopStorage.get("contacts") ?: "[]"
        val array = JSONArray(json)
        val list = mutableListOf<String>()
        for (i in 0 until array.length()) {
            list.add(array.getString(i))
        }
        return list
    }

    fun addContact(username: String) {
        val contacts = getContacts()
        if (!contacts.contains(username)) {
            contacts.add(username)
            DesktopStorage.put("contacts", JSONArray(contacts).toString())
        }
        // A redeemed invite is an explicit, fresh trust decision — mirrors
        // Android's ChatStorage.addContact()/unblockContact() comment.
        unblockContact(username)
    }

    /** Local-only block list (never sent to the server) — mirrors Android's
     *  ChatStorage.kt. Checked first thing in the "session_init" handler so
     *  a deleted contact can't silently re-establish a session/be
     *  resurrected by a stray or replayed session_init. Auto-lifted by
     *  addContact() if the fingerprint is ever legitimately re-invited. */
    fun getBlockedContacts(): MutableList<String> {
        val json = DesktopStorage.get("blocked_contacts") ?: "[]"
        val array = JSONArray(json)
        val list = mutableListOf<String>()
        for (i in 0 until array.length()) {
            list.add(array.getString(i))
        }
        return list
    }

    fun isBlocked(fingerprint: String): Boolean =
        getBlockedContacts().contains(fingerprint)

    fun blockContact(fingerprint: String) {
        val blocked = getBlockedContacts()
        if (!blocked.contains(fingerprint)) {
            blocked.add(fingerprint)
            DesktopStorage.put("blocked_contacts", JSONArray(blocked).toString())
        }
    }

    fun unblockContact(fingerprint: String) {
        val blocked = getBlockedContacts()
        if (blocked.remove(fingerprint)) {
            DesktopStorage.put("blocked_contacts", JSONArray(blocked).toString())
        }
    }

    fun removeContact(contactId: String) {
        val contacts = getContacts()
        if (contacts.remove(contactId)) {
            DesktopStorage.put("contacts", JSONArray(contacts).toString())
        }
    }

    fun getLastMessage(username: String, recipient: String): StoredMessage? {
        return loadMessages(username, recipient).lastOrNull()
    }

    fun saveDraft(myUserId: String, recipientUserId: String, text: String) {
        val key = "draft_${chatKey(myUserId, recipientUserId)}"
        if (text.isBlank()) DesktopStorage.remove(key)
        else DesktopStorage.put(key, text)
    }

    fun loadDraft(myUserId: String, recipientUserId: String): String =
        DesktopStorage.get("draft_${chatKey(myUserId, recipientUserId)}") ?: ""

    /** Mirrors the same fix on Android — see ChatStorage.deleteChat()'s
     *  comment there. Used to leave the cached public key behind, letting a
     *  deleted contact's routine background traffic (health-check pings,
     *  token refills) keep verifying against it and silently resurrect the
     *  contact via addContact() in the message handlers. */
    fun deleteChat(username: String, recipient: String) {
        DesktopStorage.remove(chatKey(username, recipient))
        DesktopStorage.remove("key_$recipient")
        DesktopStorage.remove("pqkey_$recipient")
        DesktopStorage.remove("avatar_$recipient")
        // Was missing — mirrors Android's ChatStorage.deleteChat() exactly,
        // which removes "name_$recipient" alongside the other caches.
        // Without this, a re-added contact under the same fingerprint kept
        // showing their old cached display name even if they'd since
        // changed it, instead of falling back to getContactName()'s
        // fingerprint-derived default until a fresh name arrives. Found in
        // the 2026-09-13 full-logic audit.
        DesktopStorage.remove("name_$recipient")
        // TOFU key history is a separate on-disk store, keyed by contactId —
        // same "survives delete" bug class as the key caches above. Mirrors
        // Android's ChatStorage.deleteChat().
        KeyHistoryManager.clearHistory(recipient)
        // Mirrors Android's ChatStorage.deleteChat() exactly (found live
        // 2026-08-29 there): without this, a message/typing indicator still
        // queued server-side (recipient offline, or deleted before it was
        // acked) resurfaces into a freshly re-added conversation with the
        // same fingerprint — the fix has to be "stop re-subscribing the old
        // token", not something more surgical. Both calls were missing
        // entirely on Desktop; clearContactTokens() didn't even exist.
        AnonTokenManager.clearContactTokens(recipient)
        AnonTokenManager.wipeMyTokenPool()
        // Was missing — mirrors Android's ChatStorage.deleteChat() exactly:
        // without this, getContactMailboxTag(recipient) survives a
        // "delete". The mailbox spam gate (see WebSocketClient's mutual-add
        // check on mailbox deposit) only checks whether this tag is
        // non-null, as a proxy for "did I ever independently add this
        // person" — a stale tag left over from before this delete makes
        // that check pass again, letting a deposit from a fresh re-add on
        // the OTHER side silently resurrect a nameless contact on THIS side
        // before this user has done anything themselves, defeating the
        // whole point of requiring mutual add. Found in the 2026-09-13
        // full-logic audit.
        AnonTokenManager.clearContactMailboxTag(recipient)
        val contacts = getContacts()
        contacts.remove(recipient)
        DesktopStorage.put("contacts", JSONArray(contacts).toString())
    }

    fun deleteMessage(myUserId: String, recipientUserId: String, messageId: String) {
        val key = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(key)
        val newArray = JSONArray()
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optString("id") != messageId) newArray.put(obj)
        }
        saveJsonArray(key, newArray)
    }

    fun getDisappearTimer(myUserId: String, recipientUserId: String): Long {
        return DesktopStorage.get("disappear_${chatKey(myUserId, recipientUserId)}")?.toLongOrNull() ?: 0L
    }

    fun setDisappearTimer(myUserId: String, recipientUserId: String, seconds: Long) {
        DesktopStorage.put("disappear_${chatKey(myUserId, recipientUserId)}", seconds.toString())
    }

    fun markDelivered(myUserId: String, recipientUserId: String, messageId: String) {
        val key   = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(key)
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optString("id") == messageId) {
                obj.put("is_delivered", true)
                // Was missing — mirrors Android's markDelivered() exactly: a
                // message that failed once (Desktop's own !sent-at-send-time
                // convention, see ChatScreen.kt's sendText(), or a later
                // manual retry) and subsequently gets delivered should stop
                // showing the failed indicator. Found in the 2026-09-13
                // full-logic audit.
                obj.put("is_failed", false)
                break
            }
        }
        saveJsonArray(key, array)
    }

    // No markFailed() here, unlike Android — traced: Desktop already has a
    // complete, working equivalent, just structured differently. Android's
    // markFailed() is called from ChatScreen.kt's resend flow after a 60s
    // delivery-timeout job with no ack. Desktop's ChatScreen.kt has no such
    // timeout job — it sets `isFailed = !sent` directly on
    // WebSocketClient.sendText()'s synchronous return value at send time
    // (see sendMessage()'s StoredMessage construction), and its manual
    // "retry" action clears isFailed via a direct saveOrUpdateMessage() call
    // (see FileRow/onRetry). Adding an uncalled markFailed() here would be
    // dead API — see saveMessagesBatch()'s own note below for why that's
    // avoided elsewhere in this file too.

    fun markIncomingAsRead(myUserId: String, contactId: String) {
        val key   = chatKey(myUserId, contactId)
        val array = loadJsonArray(key)
        var anyUpdated = false
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (!obj.optBoolean("isOwn", true) && !obj.optBoolean("is_read", false)) {
                obj.put("is_read", true)
                anyUpdated = true
            }
        }
        if (anyUpdated) saveJsonArray(key, array)
    }

    fun markRead(myUserId: String, recipientUserId: String, messageId: String) {
        val key   = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(key)
        var anyUpdated = false
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optBoolean("isOwn", false) && !obj.optBoolean("is_read", false)) {
                obj.put("is_read", true)
                obj.put("is_delivered", true)
                anyUpdated = true
            }
        }
        if (anyUpdated) saveJsonArray(key, array)
    }

    fun saveContactName(contactId: String, name: String?) {
        if (name.isNullOrBlank()) return
        DesktopStorage.put("name_$contactId", name)
    }

    fun getContactName(contactId: String): String {
        return DesktopStorage.get("name_$contactId")?.takeIf { it.isNotBlank() }
            ?: contactId.substringBefore("_")
    }

    fun saveContactPublicKey(contactId: String, publicKey: String) {
        DesktopStorage.put("key_$contactId", publicKey)
    }

    fun getContactPublicKey(contactId: String): String? {
        return DesktopStorage.get("key_$contactId")
    }

    /** Mirrors Android's ChatStorage.saveContactPqPublicKey/getContactPqPublicKey
     *  — persists the hybrid ML-KEM (post-quantum) key learned from a fetched
     *  prekey bundle, same "pqkey_" field convention. Without this, every
     *  restart lost this device's entire cache of contacts' PQ keys (it only
     *  ever lived in WebSocketClient's in-memory peerPqPublicKeys map), so
     *  images/files/group-key-distribution/Sealed-Sender all needed a fresh
     *  bundle round-trip for EVERY contact after every restart before they'd
     *  work again — found via a desktop/Android literal wire-field audit,
     *  2026-09-11. */
    fun saveContactPqPublicKey(contactId: String, pqPublicKey: ByteArray) {
        DesktopStorage.put("pqkey_$contactId", java.util.Base64.getEncoder().encodeToString(pqPublicKey))
    }

    fun getContactPqPublicKey(contactId: String): ByteArray? {
        val b64 = DesktopStorage.get("pqkey_$contactId") ?: return null
        return try { java.util.Base64.getDecoder().decode(b64) } catch (e: Exception) { null }
    }

    /** Forces the next send to [contactId] to refetch a fresh prekey bundle —
     *  call whenever this device knows its cached copy of their SPK/PQ-KEM
     *  can no longer be trusted (their session_reset, a pq_bundle_refresh, a
     *  panic-restore on their end). Was entirely missing from Desktop's
     *  "session_reset" handler — mirrors Android's ChatStorage.
     *  clearContactPqPublicKey(), see its own comment for the "не заживает"
     *  (never heals) bug this exists to prevent: sealing against a stale-
     *  but-present cached public key always "succeeds" locally, only the
     *  recipient sees BAD_DECRYPT, forever, with zero error on this side.
     *  Found in the 2026-09-12 full-logic audit. */
    fun clearContactPqPublicKey(contactId: String) {
        DesktopStorage.remove("pqkey_$contactId")
    }

    fun saveContactAvatar(contactId: String, base64: String) {
        DesktopStorage.put("avatar_$contactId", base64)
    }

    fun getContactAvatar(contactId: String): String? {
        return DesktopStorage.get("avatar_$contactId")
    }

    /** Batch-appends [newMessages], deduping by id, with a single load/save
     *  of the per-contact array — mirrors Android's ChatStorage.
     *  saveMessagesBatch() exactly (same minimal field set — no reactions/
     *  delivery-state/reply/expiry, matching Android's own restore
     *  contract). Was missing on Desktop; BackupManager.importBackup()'s
     *  message-restore loop previously called saveOrUpdateMessage() once per
     *  message instead, each call independently re-loading and re-saving
     *  the whole per-contact array — O(n²) for an n-message history, and
     *  more read-modify-write cycles for saveJsonArray()'s SMK-lock check to
     *  race against. Ported for that real caller, not as a speculative API —
     *  Android's own saveMessagesBatch() has no OTHER caller either. Found
     *  in the 2026-09-13 full-logic audit. */
    fun saveMessagesBatch(
        myUserId: String,
        recipientUserId: String,
        newMessages: List<StoredMessage>
    ) {
        val key = chatKey(myUserId, recipientUserId)
        val array = loadJsonArray(key)

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
                    put("is_edited", message.isEdited)
                    put("image_path", message.imagePath)
                    put("file_path", message.filePath)
                    put("file_name", message.fileName)
                })
            }
        }

        saveJsonArray(key, array)
    }

    private fun loadJsonArray(key: String): JSONArray {
        val raw = DesktopStorage.get(key) ?: "[]"
        val jsonStr = if (raw.startsWith(StorageKeyManager.SMK_PREFIX)) {
            val blob = Base64.getDecoder().decode(raw.removePrefix(StorageKeyManager.SMK_PREFIX))
            String(StorageKeyManager.decrypt(blob), Charsets.UTF_8)
        } else {
            // Self-heal legacy/plain-JSON chat history — mirrors Android's
            // loadJsonArray() exactly: a history saved while locked (this
            // function's own plain-JSON fallback below) stayed on only that
            // weaker protection indefinitely, with no re-wrap unless that
            // specific chat was saved again. Re-saving here on every load
            // once unlocked closes that gap instead of leaving it to
            // chance. Found in the 2026-09-13 full-logic audit.
            if (raw != "[]" && StorageKeyManager.isUnlocked) {
                try {
                    val wrapped = StorageKeyManager.SMK_PREFIX + Base64.getEncoder().encodeToString(
                        StorageKeyManager.encrypt(raw.toByteArray(Charsets.UTF_8))
                    )
                    DesktopStorage.put(key, wrapped)
                } catch (_: Exception) {}
            }
            raw
        }
        return JSONArray(jsonStr)
    }

    private fun saveJsonArray(key: String, array: JSONArray) {
        // Never downgrade an existing/new chat history from SMK protection
        // to raw JSON merely because SMK is locked — mirrors Android's
        // saveJsonArray() exactly. Was fail-open: any save attempted while
        // locked (e.g. a message arriving before the user unlocks this run)
        // silently wrote the history in the clear instead of refusing, the
        // opposite of Android's "return without writing" contract. Found in
        // the 2026-09-13 full-logic audit.
        if (!StorageKeyManager.isUnlocked) return
        val toStore = StorageKeyManager.SMK_PREFIX + Base64.getEncoder().encodeToString(
            StorageKeyManager.encrypt(array.toString().toByteArray(Charsets.UTF_8))
        )
        DesktopStorage.put(key, toStore)
    }
}
