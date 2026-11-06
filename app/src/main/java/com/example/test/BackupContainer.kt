package com.subrosa.messenger

import java.io.Closeable
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Format version 8 — the container used when a backup includes attachments.
 *
 * ## Why a new container instead of extending version 7
 *
 * A v7 backup is one AES-GCM blob: `base64(salt ‖ iv ‖ GCM(gzip(json)))`,
 * produced and consumed as a single `String`. Attachments cannot go in there
 * safely. Base64-ing a 50 MB video into the JSON means the export holds, at
 * peak, the JSON bytes *and* the gzip output *and* the ciphertext *and* the
 * Base64 string — four copies of a payload that was already inflated 4/3× by
 * Base64. On a phone that is an `OutOfMemoryError` on a feature whose entire
 * purpose is not losing data.
 *
 * So v8 is a framed, streamed container. Peak memory is one chunk
 * ([CHUNK_SIZE], 1 MiB) plus its ciphertext, regardless of whether the backup
 * carries 2 MB or 2 GB of attachments.
 *
 * ```
 * "SRBK8\n"                       6 bytes, ASCII magic
 * salt                           32 bytes, Argon2id salt
 * frame*                          repeated to EOF
 *
 * frame := iv(12) ‖ len(4, big-endian) ‖ ciphertext(len)   // len includes the 16-byte tag
 * ```
 *
 * One key for the whole file: `Argon2id(password, salt, 64 MiB, t=3, p=1)` —
 * identical parameters to v7, so the offline-brute-force cost of a v8 file is
 * unchanged. Deriving once matters: Argon2id at 64 MiB per frame would make a
 * 500-frame backup take minutes and allocate 64 MiB over and over.
 *
 * ## What binds the frames together
 *
 * Each frame's AAD is `"SRBK8|<frameIndex>|<label>"`, where `label` is `meta`
 * for frame 0 and `blob:<id>` for every frame of an attachment. GCM
 * authenticates that string without encrypting it, so an attacker who holds
 * the file cannot:
 *
 *  - reorder frames (the index is wrong),
 *  - delete a frame from the middle (every later index shifts),
 *  - move attachment A's bytes onto attachment B (the label is wrong),
 *  - splice a frame in from a *different* backup of the same password (index
 *    and label would have to match exactly, and the plaintext would then be
 *    the content that legitimately belongs at that position anyway).
 *
 * Truncating the file at a frame boundary is the one edit that stays
 * authentic-looking, which is why the frame *inside* an attachment carries a
 * type byte: a blob is only accepted once its [TYPE_BLOB_END] frame has been
 * read, and that frame declares the total plaintext length. A truncated
 * attachment therefore fails rather than silently restoring a half file.
 *
 * ## Why the frame type is inside the ciphertext, not in the header
 *
 * The reader has to know a frame's AAD *before* it can decrypt the frame, so
 * the AAD cannot depend on anything the frame itself declares. A 1-byte type
 * prefix on the plaintext (`0x00` meta, `0x01` chunk, `0x02` blob end) lets
 * the reader learn "this was the last chunk of this blob" after decryption,
 * while the AAD stays computable from state the reader already has (frame
 * index, plus which blob id it is currently walking, which the metadata frame
 * told it).
 *
 * A side effect worth stating: the frame *sizes* are visible to anyone holding
 * the file, so the number of attachments and their approximate sizes leak.
 * That is true of v7 too (total size), and of any container that does not pad
 * to a fixed size — which for multi-gigabyte media would be absurd. An
 * attacker who has the file already knows they have a messenger backup.
 */
object BackupContainer {

    const val VERSION = 8

    /** Chosen so the magic cannot collide with a v7 file, which is pure Base64 — `\n` is not in the Base64 alphabet. */
    private const val MAGIC = "SRBK8\n"
    private val MAGIC_BYTES = MAGIC.toByteArray(Charsets.US_ASCII)

    const val SALT_LEN = 32
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    /** 1 MiB: large enough that per-frame overhead (28 bytes) is noise, small enough to keep peak heap flat. */
    const val CHUNK_SIZE = 1 shl 20

    private const val TYPE_META: Byte = 0x00
    private const val TYPE_BLOB_CHUNK: Byte = 0x01
    private const val TYPE_BLOB_END: Byte = 0x02

    private const val LABEL_META = "meta"
    private fun blobLabel(id: String) = "blob:$id"

    /**
     * Refuses anything that is not plausibly a frame, before allocating for it.
     * A corrupt or hostile length field is the one value in this format that is
     * read before it can be authenticated.
     */
    private const val MAX_FRAME_LEN = CHUNK_SIZE + 4096

    fun isV8Container(firstBytes: ByteArray): Boolean =
        firstBytes.size >= MAGIC_BYTES.size &&
            MAGIC_BYTES.indices.all { firstBytes[it] == MAGIC_BYTES[it] }

    /** Bytes needed by [isV8Container] — read this much, then decide. */
    val SNIFF_LEN: Int get() = MAGIC_BYTES.size

    class Writer(
        private val out: OutputStream,
        password: String
    ) : Closeable {

        private val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        private val key = BackupManager.deriveKey(password, salt)
        private val rng = SecureRandom()
        private var frameIndex = 0

        init {
            out.write(MAGIC_BYTES)
            out.write(salt)
        }

        fun writeMetadata(json: String) {
            val raw = json.toByteArray(Charsets.UTF_8)
            val gz = try { BackupManager.gzip(raw) } finally { SecureMemory.wipe(raw) }
            try {
                frame(LABEL_META, TYPE_META, gz, gz.size)
            } finally {
                SecureMemory.wipe(gz)
            }
        }

        /**
         * Streams one attachment in. Returns the plaintext byte count, so the
         * caller can report a total and abort on a blob that turned out to be
         * absurdly large.
         *
         * The input is *plaintext* — the caller decrypts out of
         * `SecureFileStorage` (device-bound Keystore key) and this re-encrypts
         * under the backup password. That re-encryption is the whole reason
         * attachments can be restored on a different device at all: the
         * on-disk `.enc` files are bound to the Keystore of the device that
         * wrote them and are worthless anywhere else.
         */
        fun writeBlob(id: String, input: InputStream): Long {
            val label = blobLabel(id)
            val buf = ByteArray(CHUNK_SIZE)
            var total = 0L
            try {
                while (true) {
                    var filled = 0
                    // read() is free to return short; fill the chunk so frame
                    // sizes stay uniform and don't leak the read pattern of
                    // whatever stream implementation is underneath.
                    while (filled < buf.size) {
                        val n = input.read(buf, filled, buf.size - filled)
                        if (n < 0) break
                        filled += n
                    }
                    if (filled > 0) {
                        frame(label, TYPE_BLOB_CHUNK, buf, filled)
                        total += filled
                    }
                    if (filled < buf.size) break
                }
                val trailer = ByteArray(8)
                for (i in 0 until 8) trailer[i] = (total ushr (56 - 8 * i)).toByte()
                frame(label, TYPE_BLOB_END, trailer, trailer.size)
            } finally {
                SecureMemory.wipe(buf)
            }
            return total
        }

        private fun frame(label: String, type: Byte, body: ByteArray, bodyLen: Int) {
            val plaintext = ByteArray(1 + bodyLen)
            plaintext[0] = type
            System.arraycopy(body, 0, plaintext, 1, bodyLen)

            val iv = ByteArray(IV_LEN).also { rng.nextBytes(it) }
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
                cipher.updateAAD(aad(frameIndex, label))
                val ct = cipher.doFinal(plaintext)
                out.write(iv)
                writeInt(out, ct.size)
                out.write(ct)
                frameIndex++
            } finally {
                SecureMemory.wipe(plaintext)
            }
        }

        override fun close() {
            SecureMemory.wipe(key)
        }
    }

    /** Thrown for every rejected container, with no detail about *which* check failed. */
    class InvalidContainerException(message: String) : Exception(message)

    /**
     * Sequential reader. Frames must be consumed in the order the metadata
     * declares; that is not a limitation to work around but the thing that
     * makes the AAD chain meaningful.
     */
    class Reader private constructor(
        source: InputStream,
        password: String?,
        borrowedKey: ByteArray?
    ) : Closeable {

        constructor(source: InputStream, password: String) : this(source, password, null)

        /**
         * Reopen with a key derived earlier. The archive viewer extracts one
         * attachment at a time by walking the container again from the start,
         * and re-running Argon2id at 64 MiB for every tap would make that
         * unusable — while keeping the *password* around to re-derive it is
         * worse than keeping the per-file key, which is useless anywhere else.
         * The key is borrowed: [close] does not wipe it, its owner does.
         */
        constructor(source: InputStream, key: ByteArray) : this(source, null, key)

        private val input = DataInputStream(source.buffered())
        private val key: ByteArray
        private val ownsKey: Boolean
        private var frameIndex = 0

        init {
            val magic = ByteArray(MAGIC_BYTES.size)
            input.readFully(magic)
            if (!isV8Container(magic)) throw InvalidContainerException("not a v8 container")
            val salt = ByteArray(SALT_LEN)
            input.readFully(salt)
            if (borrowedKey != null) {
                key = borrowedKey
                ownsKey = false
            } else {
                key = BackupManager.deriveKey(password!!, salt)
                ownsKey = true
            }
        }

        /** Copy of the derived key, for a caller that intends to reopen later. Caller owns the copy. */
        fun copyKey(): ByteArray = key.copyOf()

        /** Frame 0. Must be called exactly once, first. */
        fun readMetadata(): String {
            val (type, body) = readFrame(LABEL_META)
            try {
                if (type != TYPE_META) throw InvalidContainerException("first frame is not metadata")
                val raw = BackupManager.ungzip(body)
                return try { String(raw, Charsets.UTF_8) } finally { SecureMemory.wipe(raw) }
            } finally {
                SecureMemory.wipe(body)
            }
        }

        /**
         * Streams the next attachment out to [out]. Returns the plaintext byte
         * count, which the caller may compare against anything it expected.
         *
         * [out] is not closed here — the caller owns it, because on the import
         * path it is an `EncryptedFile` output stream whose own close() writes
         * the final authentication tag, and that has to happen only if the
         * whole blob arrived intact.
         */
        fun readBlob(id: String, out: OutputStream): Long =
            readBlob(id) { chunk, len -> out.write(chunk, 0, len) }

        /**
         * Callback form, so a consumer that wants to cap or inspect the stream
         * (the archive viewer, which refuses to materialise an attachment past
         * a size limit) does not have to wrap an OutputStream to do it. The
         * array handed to [sink] is reused — copy if it must outlive the call.
         */
        fun readBlob(id: String, sink: (ByteArray, Int) -> Unit): Long {
            val label = blobLabel(id)
            var total = 0L
            while (true) {
                val (type, body) = readFrame(label)
                try {
                    when (type) {
                        TYPE_BLOB_CHUNK -> {
                            sink(body, body.size)
                            total += body.size
                        }
                        TYPE_BLOB_END -> {
                            if (body.size != 8) throw InvalidContainerException("bad blob trailer")
                            var declared = 0L
                            for (b in body) declared = (declared shl 8) or (b.toLong() and 0xFF)
                            // The one edit that survives the AAD chain is a cut
                            // at a frame boundary, so the declared length is
                            // what turns a truncated attachment into a failure
                            // instead of a silently half-restored file.
                            if (declared != total) {
                                throw InvalidContainerException("blob truncated: $total of $declared bytes")
                            }
                            return total
                        }
                        else -> throw InvalidContainerException("unexpected frame type $type")
                    }
                } finally {
                    SecureMemory.wipe(body)
                }
            }
        }

        /** Walks past an attachment without materialising it. */
        fun skipBlob(id: String) {
            readBlob(id, NullOutputStream)
        }

        private fun readFrame(label: String): Pair<Byte, ByteArray> {
            val iv = ByteArray(IV_LEN)
            input.readFully(iv)
            val len = input.readInt()
            if (len <= 16 || len > MAX_FRAME_LEN) {
                // Read before it can be authenticated — the only unauthenticated
                // value in the format. Bounded so a hostile file cannot make us
                // allocate at will.
                throw InvalidContainerException("implausible frame length $len")
            }
            val ct = ByteArray(len)
            input.readFully(ct)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(aad(frameIndex, label))
            val plaintext = cipher.doFinal(ct)
            frameIndex++

            if (plaintext.isEmpty()) throw InvalidContainerException("empty frame")
            val body = plaintext.copyOfRange(1, plaintext.size)
            val type = plaintext[0]
            SecureMemory.wipe(plaintext)
            return type to body
        }

        override fun close() {
            if (ownsKey) SecureMemory.wipe(key)
            try { input.close() } catch (_: Exception) {}
        }
    }

    private fun aad(frameIndex: Int, label: String): ByteArray =
        "SRBK8|$frameIndex|$label".toByteArray(Charsets.UTF_8)

    private fun writeInt(out: OutputStream, value: Int) {
        out.write((value ushr 24) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private object NullOutputStream : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {}
    }
}
