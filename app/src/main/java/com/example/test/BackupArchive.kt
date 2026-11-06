package com.subrosa.messenger

import org.json.JSONArray
import org.json.JSONObject

/**
 * Read-only view of a backup file.
 *
 * The problem this solves: [BackupManager.importBackup] is the only way to get
 * at the contents of a backup, and importing is a destructive, identity-level
 * operation — it wipes whatever identity is currently on the device, needs the
 * TOTP secret or a recovery code, and leaves the device claiming to *be* the
 * backed-up identity. None of that is acceptable for "the server is gone and I
 * need to read one conversation".
 *
 * So this path deliberately does less, and the restrictions are the feature:
 *
 *  - **Never writes.** No `Context` is taken anywhere in this file, which is
 *    the structural reason it cannot touch `SharedPreferences`, the keystore,
 *    `filesDir`, or the live identity. That is enforced by the absence of the
 *    parameter, not by a convention someone has to remember.
 *  - **Never restores keys.** The identity private key, SPK/ML-KEM privates,
 *    group keys and anon tokens are all present in the decrypted JSON and are
 *    all deliberately dropped on the floor by [parse]. Opening an archive
 *    cannot make the device able to send anything, impersonate the backed-up
 *    identity, or decrypt anything else — it is a text viewer.
 *  - **Never contacts the server.** There is no network code here, which is
 *    the whole point: it works with the server dead, seized or shut down.
 *  - **In-memory only, and clearable.** [Archive.close] overwrites what can be
 *    overwritten. The caller is expected to call it when the screen leaves the
 *    composition or the app is backgrounded — see ArchiveScreen.
 *
 * Password handling is unchanged from import: Argon2id (64 MiB, t=3, p=1) over
 * the file's own salt, then AES-GCM. A wrong password fails the GCM tag and is
 * indistinguishable from a corrupted file, which is why [open] reports them
 * together rather than guessing.
 *
 * Attachments depend on which container the file is:
 *
 *  - **Version 7** (export without the attachments option, and every backup
 *    made before 2026-11-06) carries message *text* only, so photos, voice
 *    notes, videos and files are absent — not even their names.
 *    Attachment-only messages therefore have an empty body, and
 *    [Msg.isAttachmentPlaceholder] marks them so the viewer says so out loud
 *    instead of rendering a blank bubble.
 *  - **Version 8** ([BackupContainer]) carries the attachment bytes. They are
 *    extracted lazily, one at a time, by [Archive.extract] — never all at once,
 *    which is the difference between viewing a 2 GB backup and crashing on one.
 *    Extraction still writes nothing: the bytes are handed to the caller, and
 *    only an explicit "save" action in the UI (which owns the `Context`) puts
 *    them anywhere.
 */
/** Shared by the export summary and the attachment rows in the viewer. */
internal fun formatBytes(bytes: Long): String = when {
    bytes >= 1_073_741_824 -> String.format(java.util.Locale.US, "%.1f GB", bytes / 1_073_741_824.0)
    bytes >= 1_048_576 -> String.format(java.util.Locale.US, "%.1f MB", bytes / 1_048_576.0)
    bytes >= 1024 -> "${bytes / 1024} KB"
    else -> "$bytes B"
}

object BackupArchive {

    /**
     * An attachment the backup declares. Only present in version 8 containers
     * (the "include attachments" export option); a version 7 file has none,
     * which is why [Msg.isAttachmentPlaceholder] still exists.
     */
    data class Attachment(
        val blobId: String,
        /** `image` | `voice` | `video` | `file` */
        val kind: String,
        val name: String?,
        val durationSeconds: Int = 0
    )

    data class Msg(
        val text: String,
        val isOwn: Boolean,
        val timestamp: Long,
        val senderName: String? = null,
        val attachment: Attachment? = null
    ) {
        /**
         * Empty body and nothing declared == the original message carried only
         * an attachment and this backup was written without them. Distinguished
         * from a genuinely empty text message because the app does not allow
         * sending one.
         */
        val isAttachmentPlaceholder: Boolean get() = text.isBlank() && attachment == null
    }

    data class Thread(
        val id: String,
        val name: String,
        val isGroup: Boolean,
        val messages: List<Msg>
    ) {
        val lastTimestamp: Long get() = messages.lastOrNull()?.timestamp ?: 0L
    }

    class Archive(
        val username: String,
        val displayName: String,
        val createdAt: Long,
        val version: Int,
        val threads: List<Thread>,
        /** Contacts present in the backup that have no messages at all. */
        val emptyContacts: List<String>,
        /** Blob ids in container-frame order; empty for a version 7 file. */
        internal val blobOrder: List<String> = emptyList(),
        /** Reopens the container for lazy attachment extraction; null for version 7. */
        internal val source: (() -> java.io.InputStream)? = null,
        /** Derived container key, owned by this object and wiped by [close]. */
        internal val key: ByteArray? = null
    ) {
        val messageCount: Int get() = threads.sumOf { it.messages.size }

        val hasAttachments: Boolean get() = blobOrder.isNotEmpty()

        @Volatile
        var closed: Boolean = false
            private set

        /**
         * Pulls one attachment's bytes out of the container.
         *
         * Walks the file from the start each time, skipping earlier blobs. That
         * is O(file) per extraction rather than a seek, and it is deliberate:
         * the frames are chained by an AAD that includes the frame index, so
         * decrypting frame *n* requires having counted every frame before it.
         * An index of byte offsets would let a tampered file redirect a read to
         * a frame that authenticates under a different position — exactly the
         * substitution the chain exists to prevent. Attachments are opened one
         * at a time by a human tapping them, so the cost is paid where it is
         * affordable.
         *
         * Returns null if closed, absent, zero-length (the export's marker for
         * "the file was already gone"), or larger than [maxBytes].
         */
        fun extract(blobId: String, maxBytes: Int = 64 * 1024 * 1024): ByteArray? {
            if (closed) return null
            val src = source ?: return null
            val k = key ?: return null
            if (!blobOrder.contains(blobId)) return null

            return try {
                BackupContainer.Reader(src(), k).use { reader ->
                    reader.readMetadata()
                    for (id in blobOrder) {
                        if (id != blobId) {
                            reader.skipBlob(id)
                            continue
                        }
                        val out = java.io.ByteArrayOutputStream()
                        val written = reader.readBlob(id) { chunk, len ->
                            if (out.size() + len > maxBytes) throw TooLargeException()
                            out.write(chunk, 0, len)
                        }
                        return if (written == 0L) null else out.toByteArray()
                    }
                    null
                }
            } catch (e: TooLargeException) {
                null
            } catch (e: Exception) {
                null
            }
        }

        private class TooLargeException : Exception()

        /**
         * Best-effort scrub of the decrypted content.
         *
         * Honest about its limits: the message bodies are `String`s by the time
         * they come out of `JSONObject`, and Strings cannot be reliably wiped
         * on ART (see [SecureMemory.wipe]). What this actually guarantees is
         * that the archive stops being *reachable* from the screen, so the GC
         * can reclaim it, and that [closed] makes a use-after-close a visible
         * bug rather than a silent read of stale plaintext. The byte-level
         * buffers — the ciphertext, the gzip stream and the decrypted JSON —
         * are wiped properly inside [open], before any of this exists.
         */
        fun close() {
            closed = true
            SecureMemory.wipe(key)
        }
    }

    sealed class Result {
        data class Ok(val archive: Archive) : Result()
        /** Wrong password or damaged file — deliberately not distinguished. */
        object BadPasswordOrCorrupt : Result()
        data class Unreadable(val detail: String) : Result()
    }

    /**
     * Decrypts and parses, wiping every intermediate buffer on the way out.
     *
     * [encryptedB64] is the file contents as written by the export
     * (Base64 of salt‖iv‖ciphertext). It is a `String` coming from the file
     * picker and shares the String limitation described above; it is, however,
     * only ciphertext.
     */
    fun open(encryptedB64: String, password: String): Result {
        var compressed: ByteArray? = null
        var json: ByteArray? = null
        return try {
            compressed = BackupManager.decryptBackup(encryptedB64.trim(), password)
            json = BackupManager.ungzip(compressed)
            Result.Ok(parse(String(json, Charsets.UTF_8)))
        } catch (e: BackupContainer.InvalidContainerException) {
            Result.Unreadable(e.message ?: "container")
        } catch (e: javax.crypto.AEADBadTagException) {
            Result.BadPasswordOrCorrupt
        } catch (e: javax.crypto.BadPaddingException) {
            // Older providers surface a GCM tag failure as the generic parent
            // class, so both have to be treated as the same outcome.
            Result.BadPasswordOrCorrupt
        } catch (e: IllegalArgumentException) {
            // Base64 garbage or a file shorter than salt+iv+tag — i.e. not a
            // Subrosa backup at all.
            Result.BadPasswordOrCorrupt
        } catch (e: java.util.zip.ZipException) {
            // Decrypted under the right key but the plaintext isn't gzip:
            // either a future format or genuine corruption past the AEAD.
            Result.Unreadable("gzip: ${e.message}")
        } catch (e: Exception) {
            Result.Unreadable(e.message ?: e.javaClass.simpleName)
        } finally {
            SecureMemory.wipe(json)
            SecureMemory.wipe(compressed)
        }
    }

    /**
     * Opens either container, detected from the first bytes.
     *
     * [source] is a factory, not a stream: the version can only be told from
     * the magic, the v7 path then needs the whole file as text from the
     * beginning, and attachment extraction later needs to walk the container
     * again. Reopening is more honest than pretending a `content://` stream can
     * be reliably reset.
     *
     * Note that no `Context` appears here either — the caller builds the
     * factory, so this file still cannot reach storage.
     */
    fun open(source: () -> java.io.InputStream, password: String): Result {
        val sniff = try {
            source().use { input ->
                val head = ByteArray(BackupContainer.SNIFF_LEN)
                var read = 0
                while (read < head.size) {
                    val n = input.read(head, read, head.size - read)
                    if (n < 0) break
                    read += n
                }
                head.copyOf(read)
            }
        } catch (e: Exception) {
            return Result.Unreadable(e.message ?: "read")
        }

        if (!BackupContainer.isV8Container(sniff)) {
            val text = try {
                source().use { it.bufferedReader().readText() }
            } catch (e: Exception) {
                return Result.Unreadable(e.message ?: "read")
            }
            return open(text, password)
        }

        return try {
            BackupContainer.Reader(source(), password).use { reader ->
                val json = reader.readMetadata()
                val base = parse(json)
                Result.Ok(
                    Archive(
                        username = base.username,
                        displayName = base.displayName,
                        createdAt = base.createdAt,
                        version = base.version,
                        threads = base.threads,
                        emptyContacts = base.emptyContacts,
                        blobOrder = base.blobOrder,
                        source = source,
                        key = reader.copyKey()
                    )
                )
            }
        } catch (e: javax.crypto.AEADBadTagException) {
            Result.BadPasswordOrCorrupt
        } catch (e: javax.crypto.BadPaddingException) {
            Result.BadPasswordOrCorrupt
        } catch (e: BackupContainer.InvalidContainerException) {
            // A wrong password surfaces here too — the metadata frame fails its
            // GCM tag, and on some providers that arrives as a container error
            // rather than AEADBadTagException. Reported as the same outcome so
            // the viewer never says "corrupt file" at someone who just mistyped.
            Result.BadPasswordOrCorrupt
        } catch (e: java.io.EOFException) {
            Result.BadPasswordOrCorrupt
        } catch (e: Exception) {
            Result.Unreadable(e.message ?: e.javaClass.simpleName)
        }
    }

    /**
     * Pure JSON → model. Separate from [open] so it is testable without paying
     * for Argon2id, and so it is obvious by inspection that nothing here reads
     * a key field.
     */
    internal fun parse(jsonText: String): Archive {
        val root = JSONObject(jsonText)

        val username = root.optString("username", "")
        val displayName = root.optString("display_name", "").ifBlank { username }

        val contactNames = HashMap<String, String>()
        root.optJSONArray("contacts")?.forEachObject { c ->
            val id = c.optString("id", "")
            if (id.isNotEmpty()) {
                contactNames[id] = c.optString("name", "").ifBlank { id }
            }
        }

        val byContact = LinkedHashMap<String, MutableList<Msg>>()
        root.optJSONArray("messages")?.forEachObject { m ->
            val contact = m.optString("contact", "")
            if (contact.isEmpty()) return@forEachObject
            byContact.getOrPut(contact) { mutableListOf() }.add(
                Msg(
                    text = m.optString("text", ""),
                    isOwn = m.optBoolean("isOwn", false),
                    timestamp = m.optLong("timestamp", 0L),
                    attachment = readAttachment(m)
                )
            )
        }

        val groupNames = HashMap<String, String>()
        root.optJSONArray("groups")?.forEachObject { g ->
            val id = g.optString("id", "")
            if (id.isNotEmpty()) {
                groupNames[id] = g.optString("name", "").ifBlank { id }
            }
        }

        val byGroup = LinkedHashMap<String, MutableList<Msg>>()
        root.optJSONArray("group_messages")?.forEachObject { m ->
            val groupId = m.optString("group_id", "")
            if (groupId.isEmpty()) return@forEachObject
            byGroup.getOrPut(groupId) { mutableListOf() }.add(
                Msg(
                    text = m.optString("text", ""),
                    isOwn = m.optBoolean("isOwn", false),
                    timestamp = m.optLong("timestamp", 0L),
                    senderName = m.optString("sender_name", "").ifBlank { null },
                    attachment = readAttachment(m)
                )
            )
        }

        val threads = ArrayList<Thread>(byContact.size + byGroup.size)
        byContact.forEach { (id, msgs) ->
            threads.add(
                Thread(
                    id = id,
                    name = contactNames[id] ?: id,
                    isGroup = false,
                    // Export order follows storage order, which is append-only
                    // in practice but not guaranteed by the format; sort so the
                    // viewer never shows a scrambled conversation.
                    messages = msgs.sortedBy { it.timestamp }
                )
            )
        }
        byGroup.forEach { (id, msgs) ->
            threads.add(
                Thread(
                    id = id,
                    name = groupNames[id] ?: id,
                    isGroup = true,
                    messages = msgs.sortedBy { it.timestamp }
                )
            )
        }

        val blobOrder = ArrayList<String>()
        root.optJSONArray("attachments")?.let { arr ->
            for (i in 0 until arr.length()) {
                arr.optString(i, "").takeIf { it.isNotEmpty() }?.let { blobOrder.add(it) }
            }
        }

        return Archive(
            username = username,
            displayName = displayName,
            createdAt = root.optLong("timestamp", 0L),
            version = root.optInt("version", 0),
            threads = threads.sortedByDescending { it.lastTimestamp },
            emptyContacts = contactNames.filterKeys { !byContact.containsKey(it) }.values.sorted(),
            blobOrder = blobOrder
        )
    }

    /**
     * Reads only what is needed to *describe* an attachment — id, kind, name,
     * duration. No path is read even though version 8 messages could have
     * carried one: a path out of a backup file is an attacker-controlled
     * string, and the viewer has no business touching the filesystem anyway.
     */
    private fun readAttachment(m: JSONObject): Attachment? {
        val blobId = m.optString("blob", "")
        if (blobId.isEmpty()) return null
        val kind = m.optString("blobKind", "").ifBlank { "file" }
        return Attachment(
            blobId = blobId,
            kind = kind,
            name = m.optString("fileName", "").ifBlank { null },
            durationSeconds = when (kind) {
                "voice" -> m.optInt("voiceDuration", 0)
                "video" -> m.optInt("videoDuration", 0)
                else -> 0
            }
        )
    }

    private inline fun JSONArray.forEachObject(action: (JSONObject) -> Unit) {
        for (i in 0 until length()) {
            optJSONObject(i)?.let(action)
        }
    }
}
