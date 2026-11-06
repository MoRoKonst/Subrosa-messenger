package com.subrosa.messenger

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Covers the read-only archive path. Robolectric is needed only for
 * `android.util.Base64` and `org.json`; nothing here touches storage, which is
 * the point of [BackupArchive] — see its class doc.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BackupArchiveTest {

    /** The subset of the v7 export format the viewer actually reads. */
    private fun sampleBackup(): String = JSONObject().apply {
        put("version", 7)
        put("timestamp", 1_762_000_000_000L)
        put("username", "ABCD1234")
        put("display_name", "Alice")
        // Key material that MUST be ignored by the parser. The values are not
        // keys: they are base64 of the words "secret-private-key",
        // "spk-private" and "pq-private". Gitleaks flags the first on entropy
        // alone, hence the marker.
        put("ec_private_key", "c2VjcmV0LXByaXZhdGUta2V5") // gitleaks:allow
        put("spk_private", "c3BrLXByaXZhdGU=")
        put("pq_private", "cHEtcHJpdmF0ZQ==")
        put("contacts", JSONArray().apply {
            put(JSONObject().apply { put("id", "CONTACT1"); put("name", "Rebecca Caldwell") })
            put(JSONObject().apply { put("id", "CONTACT2"); put("name", "David Keller") })
            put(JSONObject().apply { put("id", "SILENT"); put("name", "No Messages") })
        })
        put("messages", JSONArray().apply {
            // Deliberately out of chronological order.
            put(JSONObject().apply {
                put("contact", "CONTACT1"); put("text", "Second"); put("isOwn", true); put("timestamp", 2000L)
            })
            put(JSONObject().apply {
                put("contact", "CONTACT1"); put("text", "First"); put("isOwn", false); put("timestamp", 1000L)
            })
            put(JSONObject().apply {
                // Attachment-only message: the export writes an empty text.
                put("contact", "CONTACT2"); put("text", ""); put("isOwn", false); put("timestamp", 5000L)
            })
        })
        put("groups", JSONArray().apply {
            put(JSONObject().apply { put("id", "GROUP1"); put("name", "Matter OIX-9336") })
        })
        put("group_messages", JSONArray().apply {
            put(JSONObject().apply {
                put("group_id", "GROUP1"); put("sender_name", "Thomas"); put("text", "Filed")
                put("isOwn", false); put("timestamp", 3000L)
            })
        })
    }.toString()

    @Test
    fun `parse reads conversations and groups`() {
        val archive = BackupArchive.parse(sampleBackup())

        assertEquals("ABCD1234", archive.username)
        assertEquals("Alice", archive.displayName)
        assertEquals(7, archive.version)
        assertEquals(4, archive.messageCount)
        // CONTACT1, CONTACT2, GROUP1 — SILENT has no messages and is not a thread.
        assertEquals(3, archive.threads.size)
        assertEquals(listOf("No Messages"), archive.emptyContacts)

        val group = archive.threads.single { it.isGroup }
        assertEquals("Matter OIX-9336", group.name)
        assertEquals("Thomas", group.messages.single().senderName)
    }

    @Test
    fun `messages are ordered chronologically within a thread`() {
        val thread = BackupArchive.parse(sampleBackup()).threads.single { it.id == "CONTACT1" }
        assertEquals(listOf("First", "Second"), thread.messages.map { it.text })
        assertEquals(listOf(false, true), thread.messages.map { it.isOwn })
    }

    @Test
    fun `threads are ordered by most recent activity`() {
        val names = BackupArchive.parse(sampleBackup()).threads.map { it.id }
        // CONTACT2 @5000, GROUP1 @3000, CONTACT1 @2000.
        assertEquals(listOf("CONTACT2", "GROUP1", "CONTACT1"), names)
    }

    @Test
    fun `attachment-only messages are flagged rather than shown blank`() {
        val thread = BackupArchive.parse(sampleBackup()).threads.single { it.id == "CONTACT2" }
        assertTrue(thread.messages.single().isAttachmentPlaceholder)

        val normal = BackupArchive.parse(sampleBackup()).threads.single { it.id == "CONTACT1" }
        assertFalse(normal.messages.any { it.isAttachmentPlaceholder })
    }

    /**
     * The security property the whole file rests on: the decrypted JSON is full
     * of private keys, and none of them may reach the model the UI renders.
     * Asserted over the rendered text rather than by inspecting fields, so
     * adding a field that happens to carry key material fails this test.
     */
    @Test
    fun `no key material survives parsing`() {
        val archive = BackupArchive.parse(sampleBackup())
        val rendered = buildString {
            append(archive.username).append(archive.displayName)
            archive.threads.forEach { t ->
                append(t.id).append(t.name)
                t.messages.forEach { m -> append(m.text).append(m.senderName ?: "") }
            }
            archive.emptyContacts.forEach { append(it) }
        }
        listOf("c2VjcmV0LXByaXZhdGUta2V5", "c3BrLXByaXZhdGU=", "cHEtcHJpdmF0ZQ==").forEach {
            assertFalse("key material leaked into the archive model: $it", rendered.contains(it))
        }
    }

    @Test
    fun `open round-trips a real encrypted backup`() {
        val password = "correct horse battery staple"
        val blob = BackupManager.encryptBackup(
            BackupManager.gzip(sampleBackup().toByteArray(Charsets.UTF_8)),
            password
        )

        val result = BackupArchive.open(blob, password)
        assertTrue("expected Ok, got $result", result is BackupArchive.Result.Ok)
        val archive = (result as BackupArchive.Result.Ok).archive
        assertEquals(4, archive.messageCount)
        assertFalse(archive.closed)
        archive.close()
        assertTrue(archive.closed)
    }

    @Test
    fun `wrong password is reported as bad password, not a crash`() {
        val blob = BackupManager.encryptBackup(
            BackupManager.gzip(sampleBackup().toByteArray(Charsets.UTF_8)),
            "the right one"
        )
        assertEquals(
            BackupArchive.Result.BadPasswordOrCorrupt,
            BackupArchive.open(blob, "the wrong one")
        )
    }

    @Test
    fun `a file that is not a backup is reported as bad password or corrupt`() {
        // Short, long-but-random, and not-Base64 all have to land on the same
        // outcome — the viewer must never leak which part of the format failed.
        listOf(
            "",
            "nope",
            "!!! not base64 at all !!!",
            android.util.Base64.encodeToString(ByteArray(200) { it.toByte() }, android.util.Base64.NO_WRAP)
        ).forEach { junk ->
            assertEquals(
                "junk input should be indistinguishable from a wrong password: '$junk'",
                BackupArchive.Result.BadPasswordOrCorrupt,
                BackupArchive.open(junk, "whatever")
            )
        }
    }

    @Test
    fun `open detects a v8 container and exposes its attachments`() {
        val password = "correct horse battery staple"
        val photo = ByteArray(3000) { (it % 97).toByte() }
        val doc = "particulars of claim".toByteArray()

        val metadata = JSONObject(sampleBackup()).apply {
            put("version", 8)
            put("attachments", JSONArray().apply { put("blob-photo"); put("blob-doc") })
            // Attach one to a 1:1 message and one to a group message.
            getJSONArray("messages").getJSONObject(0).apply {
                put("blob", "blob-photo")
                put("blobKind", "image")
            }
            getJSONArray("group_messages").getJSONObject(0).apply {
                put("blob", "blob-doc")
                put("blobKind", "file")
                put("fileName", "claim.pdf")
            }
        }.toString()

        val out = java.io.ByteArrayOutputStream()
        BackupContainer.Writer(out, password).use { writer ->
            writer.writeMetadata(metadata)
            writer.writeBlob("blob-photo", java.io.ByteArrayInputStream(photo))
            writer.writeBlob("blob-doc", java.io.ByteArrayInputStream(doc))
        }
        val file = out.toByteArray()

        val result = BackupArchive.open({ java.io.ByteArrayInputStream(file) }, password)
        assertTrue("expected Ok, got $result", result is BackupArchive.Result.Ok)
        val archive = (result as BackupArchive.Result.Ok).archive
        try {
            assertEquals(8, archive.version)
            assertTrue(archive.hasAttachments)

            val img = archive.threads.single { it.id == "CONTACT1" }
                .messages.single { it.attachment != null }.attachment!!
            assertEquals("image", img.kind)

            val fileAtt = archive.threads.single { it.isGroup }
                .messages.single().attachment!!
            assertEquals("claim.pdf", fileAtt.name)

            // Extraction is lazy and order-independent from the caller's side —
            // the second attachment first, to prove the reader re-walks rather
            // than depending on where a previous read left off.
            assertArrayEquals(doc, archive.extract("blob-doc"))
            assertArrayEquals(photo, archive.extract("blob-photo"))

            // Cap honoured, and an unknown id is simply absent.
            assertNull(archive.extract("blob-photo", maxBytes = 10))
            assertNull(archive.extract("no-such-blob"))
        } finally {
            archive.close()
        }

        // After close the key is gone, so extraction must stop working rather
        // than serving plaintext from a screen that believes it was cleared.
        assertNull(archive.extract("blob-doc"))
    }

    @Test
    fun `open still reads a v7 file through the stream API`() {
        val password = "correct horse battery staple"
        val blob = BackupManager.encryptBackup(
            BackupManager.gzip(sampleBackup().toByteArray(Charsets.UTF_8)),
            password
        ).toByteArray(Charsets.US_ASCII)

        val result = BackupArchive.open({ java.io.ByteArrayInputStream(blob) }, password)
        assertTrue("expected Ok, got $result", result is BackupArchive.Result.Ok)
        val archive = (result as BackupArchive.Result.Ok).archive
        assertEquals(7, archive.version)
        assertFalse(archive.hasAttachments)
        // v7 has no container to extract from, and must say so rather than throw.
        assertNull(archive.extract("anything"))
    }

    @Test
    fun `a v8 file with the wrong password reports bad password`() {
        val out = java.io.ByteArrayOutputStream()
        BackupContainer.Writer(out, "the right one").use { it.writeMetadata(sampleBackup()) }
        val file = out.toByteArray()

        assertEquals(
            BackupArchive.Result.BadPasswordOrCorrupt,
            BackupArchive.open({ java.io.ByteArrayInputStream(file) }, "the wrong one")
        )
    }

    @Test
    fun `an empty backup parses to an empty archive rather than failing`() {
        val archive = BackupArchive.parse(
            JSONObject().apply {
                put("version", 7)
                put("username", "ABCD1234")
            }.toString()
        )
        assertEquals(0, archive.threads.size)
        assertEquals(0, archive.messageCount)
        // display_name absent — falls back to the user id rather than "".
        assertEquals("ABCD1234", archive.displayName)
    }
}
