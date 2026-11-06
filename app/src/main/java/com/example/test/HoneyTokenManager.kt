package com.subrosa.messenger

import android.content.Context
import android.util.Base64
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Tamper-detection canary.
 *
 * The bait is a blob under `blobs/<uuid>.enc` whose reference MAC is keyed
 * with a per-install secret held only in Keystore-backed EncryptedStorage, so
 * reading this source tells an attacker the mechanism but not which blob on a
 * given device is the canary, nor how to forge a valid MAC for a modified one
 * without that device's Keystore-protected secret.
 *
 * What changed, and why the previous version was trivially spottable: the
 * canary used to be 256 bytes written with a bare `File.writeBytes()` of
 * SecureRandom output. Four separate things gave it away to anyone who got a
 * directory listing of `blobs/`:
 *
 *  1. No header. Real attachments go through SecureFileStorage.write(), i.e.
 *     Tink's AES256_GCM_HKDF_4KB streaming format, which begins with a header
 *     length byte (0x28), a 32-byte salt and a 7-byte nonce prefix. Raw random
 *     bytes match that first byte with probability 1/256, so reading one byte
 *     per file isolated the canary immediately. The old comment in this file
 *     advertised "pure random bytes, no plaintext header" as a feature; it was
 *     the single clearest marker on disk.
 *  2. Constant size. No genuine attachment can be 256 bytes — the framing
 *     alone is 56, and the payload is a compressed image, audio or document.
 *  3. Oldest mtime. It was created in MainActivity.onCreate on first launch
 *     and never touched again, so sorting `blobs/` by mtime put it first,
 *     stamped with the install time.
 *  4. Orphan. Every real blob is referenced from a message record in
 *     ChatStorage (imagePath/voicePath/filePath/videoPath). This one was
 *     referenced by nothing, so a cross-reference of the chat store against
 *     the directory returned exactly one unaccounted-for file.
 *
 * All four are addressed: the canary is now written through
 * SecureFileStorage.write() so it carries a genuine Tink header, it holds a
 * real openable PDF of plausible size, its mtime tracks the timestamp of the
 * decoy message that carries it, and it is referenced as a document
 * attachment from a generated decoy thread (see DecoyData).
 *
 * Residual leak, not papered over: the reference in (4) lives in the decoy
 * dataset, which is derived from a Keystore-backed seed, not in the
 * password-wrapped real chat store. An attacker who obtains the user's real
 * password and cross-references the real chat history against `blobs/` still
 * finds one unreferenced blob. Closing that would require the canary to be
 * referenced from real chat data, which means mutating the user's genuine
 * history — a worse trade. The hardening here defeats a directory listing and
 * passive inspection; it does not defeat a full post-password audit.
 */
object HoneyTokenManager {

    private const val HMAC_ALGO = "HmacSHA256"

    /** First byte of Tink's AesGcmHkdfStreaming header: 1 + 32-byte salt +
     *  7-byte nonce prefix. Used only to detect pre-hardening canaries left
     *  over on existing installs, which must be replaced rather than kept. */
    private const val TINK_HEADER_LEN = 0x28.toByte()

    fun init(context: Context) {
        try {
            val existing = UserStorage.getHoneyFileName(context)
            if (existing.isNotEmpty()) {
                val file = blobFile(context, existing)
                if (file.exists() && !isLegacyCanary(file)) {
                    realignTimestamp(context)
                    return
                }
                // Pre-hardening canary (raw random bytes, fixed 256 length):
                // replace it outright, and under a fresh id — the old one may
                // already be known. Re-baselining tamper detection is the
                // acceptable cost of removing a blob that advertised itself.
                file.takeIf { it.exists() }?.delete()
            }

            val fileName = UUID.randomUUID().toString()
            UserStorage.setHoneyFileName(context, fileName)
            // DecoyData pins the blob id for the process on first access (see
            // its Session doc comment). If a decoy was already rendered before
            // the canary existed, that pinned copy has no attachment in it —
            // drop it so the id just minted is picked up.
            DecoyData.resetSession()

            val file = blobFile(context, fileName)
            file.parentFile?.mkdirs()
            SecureFileStorage.write(context, file, DecoyData.honeyDocBytes(context))

            val macKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
            UserStorage.setHoneyMacKey(context, Base64.encodeToString(macKey, Base64.NO_WRAP))
            UserStorage.setHoneyMac(context, hmacHex(macKey, file.readBytes()))

            realignTimestamp(context)
        } catch (_: Exception) {
            // Keystore hiccup (SecureFileStorage needs MasterKeys) must not
            // take down onCreate. With no MAC stored, checkIntegrity() reports
            // "fine" rather than tripping a wipe on our own failure to write.
        }
    }

    fun checkIntegrity(context: Context): Boolean {
        return try {
            val fileName = UserStorage.getHoneyFileName(context)
            if (fileName.isEmpty()) return true
            val file = blobFile(context, fileName)
            if (!file.exists()) return false
            val expected = UserStorage.getHoneyMac(context)
            val macKeyB64 = UserStorage.getHoneyMacKey(context)
            if (expected.isEmpty() || macKeyB64.isEmpty()) return true
            val macKey = Base64.decode(macKeyB64, Base64.NO_WRAP)
            hmacHex(macKey, file.readBytes()) == expected
        } catch (_: Exception) { true }
    }

    /**
     * Points the blob's mtime at the timestamp of the decoy message that
     * carries it. Called on normal foreground launches, alongside the decoy
     * timeline anchor refresh (MainActivity): the anchor moves, so the
     * attachment's apparent "received at" moves with it, and a blob whose
     * mtime contradicted the chat it appears in would be its own tell.
     *
     * mtime is not covered by the MAC, so this is safe to do repeatedly and
     * cannot cause a false tamper trip.
     */
    fun realignTimestamp(context: Context) {
        try {
            val fileName = UserStorage.getHoneyFileName(context)
            if (fileName.isEmpty()) return
            val file = blobFile(context, fileName)
            if (!file.exists()) return
            val want = DecoyData.honeyAttachmentTimestamp(context)
            if (want > 0L && file.lastModified() != want) file.setLastModified(want)
        } catch (_: Exception) {}
    }

    private fun isLegacyCanary(file: File): Boolean = try {
        // Anything not starting with the Tink header byte was written by the
        // old bare-writeBytes path.
        file.inputStream().use { it.read() }.toByte() != TINK_HEADER_LEN
    } catch (_: Exception) { false }

    private fun blobFile(context: Context, id: String): File =
        SecureFileStorage.blobFile(context.filesDir, id)

    private fun hmacHex(key: ByteArray, data: ByteArray): String {
        val mac = Mac.getInstance(HMAC_ALGO)
        mac.init(SecretKeySpec(key, HMAC_ALGO))
        return mac.doFinal(data).joinToString("") { "%02x".format(it) }
    }
}
