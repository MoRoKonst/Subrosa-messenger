package com.subrosa.messenger

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * The v8 container carries attachments, so the failure modes that matter here
 * are not "does it round-trip" (it obviously does) but the tampering ones:
 * reordering frames, splicing one attachment's bytes onto another's identity,
 * and truncation. Each of those gets its own test below, because each is
 * prevented by a different part of the format and a refactor could silently
 * drop any one of them.
 *
 * Argon2id at 64 MiB runs once per container built here, so these tests are
 * deliberately few and each one builds the smallest container that proves its
 * point.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BackupContainerTest {

    private val password = "correct horse battery staple"

    private fun build(
        metadata: String = """{"version":8,"username":"ABCD1234"}""",
        blobs: List<Pair<String, ByteArray>> = emptyList()
    ): ByteArray {
        val out = ByteArrayOutputStream()
        BackupContainer.Writer(out, password).use { writer ->
            writer.writeMetadata(metadata)
            blobs.forEach { (id, bytes) ->
                writer.writeBlob(id, ByteArrayInputStream(bytes))
            }
        }
        return out.toByteArray()
    }

    @Test
    fun `magic distinguishes v8 from a v7 base64 file`() {
        val v8 = build()
        assertTrue(BackupContainer.isV8Container(v8))

        // A v7 backup is pure Base64; the magic's trailing newline cannot occur
        // at that offset in Base64 output, which is what makes sniffing safe.
        val v7 = android.util.Base64.encodeToString(ByteArray(64) { 1 }, android.util.Base64.NO_WRAP)
        assertTrue(!BackupContainer.isV8Container(v7.toByteArray(Charsets.US_ASCII)))
    }

    @Test
    fun `metadata and blobs round-trip`() {
        val a = ByteArray(5000) { (it % 256).toByte() }
        val b = "attachment two".toByteArray()
        val file = build(blobs = listOf("blob-a" to a, "blob-b" to b))

        BackupContainer.Reader(ByteArrayInputStream(file), password).use { reader ->
            assertEquals("""{"version":8,"username":"ABCD1234"}""", reader.readMetadata())

            val outA = ByteArrayOutputStream()
            assertEquals(a.size.toLong(), reader.readBlob("blob-a", outA))
            assertArrayEquals(a, outA.toByteArray())

            val outB = ByteArrayOutputStream()
            assertEquals(b.size.toLong(), reader.readBlob("blob-b", outB))
            assertArrayEquals(b, outB.toByteArray())
        }
    }

    /**
     * The reason for chunking at all: peak memory must not scale with
     * attachment size. 2.5 chunks exercises a partial final chunk, which is
     * where an off-by-one in the fill loop would show up.
     */
    @Test
    fun `a blob larger than one chunk round-trips byte for byte`() {
        val big = ByteArray((BackupContainer.CHUNK_SIZE * 2.5).toInt()) { (it * 31 % 251).toByte() }
        val file = build(blobs = listOf("big" to big))

        BackupContainer.Reader(ByteArrayInputStream(file), password).use { reader ->
            reader.readMetadata()
            val out = ByteArrayOutputStream()
            assertEquals(big.size.toLong(), reader.readBlob("big", out))
            assertArrayEquals(big, out.toByteArray())
        }
    }

    @Test
    fun `an empty blob round-trips as zero bytes`() {
        // This is what the export writes for an attachment whose file was
        // already gone — import relies on it to keep the frame sequence aligned.
        val file = build(blobs = listOf("gone" to ByteArray(0)))
        BackupContainer.Reader(ByteArrayInputStream(file), password).use { reader ->
            reader.readMetadata()
            assertEquals(0L, reader.readBlob("gone", ByteArrayOutputStream()))
        }
    }

    @Test
    fun `wrong password fails on the metadata frame`() {
        val file = build()
        try {
            BackupContainer.Reader(ByteArrayInputStream(file), "wrong").use { it.readMetadata() }
            fail("a wrong password must not yield readable metadata")
        } catch (e: Exception) {
            // AEADBadTagException or InvalidContainerException depending on the
            // provider; either is a refusal, which is all that is required.
            assertTrue(e is javax.crypto.AEADBadTagException || e is BackupContainer.InvalidContainerException)
        }
    }

    /**
     * Reading a blob under the wrong id must fail even though the ciphertext is
     * intact and the password is right — this is the AAD label doing its job,
     * and it is what stops attachment A's bytes being served as attachment B.
     */
    @Test
    fun `a blob cannot be read under a different id`() {
        val file = build(blobs = listOf("real-id" to "secret".toByteArray()))
        BackupContainer.Reader(ByteArrayInputStream(file), password).use { reader ->
            reader.readMetadata()
            try {
                reader.readBlob("other-id", ByteArrayOutputStream())
                fail("frame accepted under the wrong label")
            } catch (e: Exception) {
                assertTrue(e is javax.crypto.AEADBadTagException)
            }
        }
    }

    /**
     * Skipping the metadata frame shifts every later frame's index, so the
     * first blob frame no longer authenticates. This is the frame-index half of
     * the AAD, tested separately from the label half above.
     */
    @Test
    fun `frames cannot be consumed out of order`() {
        val file = build(blobs = listOf("blob-a" to "data".toByteArray()))
        BackupContainer.Reader(ByteArrayInputStream(file), password).use { reader ->
            try {
                // Straight to the blob, without consuming frame 0.
                reader.readBlob("blob-a", ByteArrayOutputStream())
                fail("a frame authenticated at the wrong index")
            } catch (e: Exception) {
                assertTrue(e is javax.crypto.AEADBadTagException || e is BackupContainer.InvalidContainerException)
            }
        }
    }

    /**
     * Truncation at a frame boundary is the one edit that leaves every
     * remaining frame individually authentic, which is why the blob's trailer
     * declares its total length. Without that, a cut file would restore a
     * half attachment and call it a success.
     */
    @Test
    fun `a truncated blob is rejected rather than half-restored`() {
        val big = ByteArray(BackupContainer.CHUNK_SIZE * 2) { 7 }
        val file = build(blobs = listOf("big" to big))
        // Drop the tail: the final chunk and the trailer frame.
        val cut = file.copyOfRange(0, file.size - (BackupContainer.CHUNK_SIZE / 2))

        try {
            BackupContainer.Reader(ByteArrayInputStream(cut), password).use { reader ->
                reader.readMetadata()
                reader.readBlob("big", ByteArrayOutputStream())
            }
            fail("truncated container accepted")
        } catch (e: Exception) {
            assertTrue(
                "unexpected failure: $e",
                e is java.io.EOFException || e is BackupContainer.InvalidContainerException ||
                    e is javax.crypto.AEADBadTagException
            )
        }
    }

    @Test
    fun `a bit flip anywhere in the payload is rejected`() {
        val file = build(blobs = listOf("blob-a" to ByteArray(2000) { 3 })).copyOf()
        // Somewhere inside the first blob frame's ciphertext.
        val target = file.size / 2
        file[target] = (file[target].toInt() xor 0x01).toByte()

        try {
            BackupContainer.Reader(ByteArrayInputStream(file), password).use { reader ->
                reader.readMetadata()
                reader.readBlob("blob-a", ByteArrayOutputStream())
            }
            fail("modified container accepted")
        } catch (e: Exception) {
            assertTrue("unexpected failure: $e", e is javax.crypto.AEADBadTagException ||
                e is BackupContainer.InvalidContainerException || e is java.io.EOFException)
        }
    }

    @Test
    fun `a declared frame length beyond the cap is refused before allocating`() {
        val file = build()
        // Overwrite the first frame's length field (magic 6 + salt 32 + iv 12)
        // with ~2 GiB. A reader that trusted it would try to allocate that.
        val lenAt = 6 + BackupContainer.SALT_LEN + 12
        file[lenAt] = 0x7F
        file[lenAt + 1] = 0x00
        file[lenAt + 2] = 0x00
        file[lenAt + 3] = 0x00

        try {
            BackupContainer.Reader(ByteArrayInputStream(file), password).use { it.readMetadata() }
            fail("implausible frame length accepted")
        } catch (e: BackupContainer.InvalidContainerException) {
            assertTrue(e.message!!.contains("frame length"))
        }
    }

    @Test
    fun `a borrowed key reopens the container without re-deriving it`() {
        val file = build(blobs = listOf("blob-a" to "payload".toByteArray()))

        val key = BackupContainer.Reader(ByteArrayInputStream(file), password).use { it.copyKey() }

        // This is the path the archive viewer uses for every attachment tap.
        BackupContainer.Reader(ByteArrayInputStream(file), key).use { reader ->
            reader.readMetadata()
            val out = ByteArrayOutputStream()
            reader.readBlob("blob-a", out)
            assertEquals("payload", String(out.toByteArray()))
        }

        // Borrowed means not wiped by close() — the owner is still responsible.
        assertTrue("close() wiped a borrowed key", key.any { it != 0.toByte() })
        SecureMemory.wipe(key)
    }

    @Test
    fun `each frame gets a distinct iv`() {
        // Same key across every frame in the file, so IV reuse would be a
        // catastrophic GCM failure rather than a cosmetic one.
        val file = build(blobs = listOf("a" to ByteArray(10), "b" to ByteArray(10)))
        val ivs = mutableListOf<String>()
        var pos = 6 + BackupContainer.SALT_LEN
        while (pos + 16 <= file.size) {
            val iv = file.copyOfRange(pos, pos + 12)
            ivs.add(iv.joinToString("") { "%02x".format(it) })
            var len = 0
            for (i in 0 until 4) len = (len shl 8) or (file[pos + 12 + i].toInt() and 0xFF)
            pos += 12 + 4 + len
        }
        assertTrue("expected several frames, found ${ivs.size}", ivs.size >= 5)
        assertEquals("IV reused across frames", ivs.size, ivs.toSet().size)
    }
}
