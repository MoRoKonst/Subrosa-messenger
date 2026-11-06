package com.subrosa.desktop

/**
 * Desktop counterpart of Android's CryptoManager.
 *
 * Differences from Android version:
 *   - No android.util.Base64  → java.util.Base64
 *   - No android.util.Log     → System.err / println
 *   - No android.content.Context → storage paths from DesktopStorage / DesktopKeyStore
 *   - EC key stored in PKCS12 keystore (DesktopKeyStore) instead of AndroidKeyStore
 *
 * The cryptographic operations themselves are identical:
 *   - Key exchange : ECDH over P-256
 *   - Encryption   : AES-256-GCM (IV prepended)
 *   - Signing      : SHA256withECDSA
 *
 * Text messages go through the full X3DH + Double Ratchet SessionKeyManager
 * (see SessionKeyManager.kt), not through this class — this class only handles
 * identity keys, signing, and image/file encryption (ephemeral per-transfer ECDH).
 */

import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object DesktopCryptoManager {

    private lateinit var keyPair: KeyPair

    // Peer public keys received from server: username → Base64 X.509
    private val peerKeys = mutableMapOf<String, String>()

    fun init() {
        // DesktopStorage.init() must be called first (done in main.kt)
        keyPair = DesktopKeyStore.getOrCreateECKeyPair(DesktopStorage.resolveDataDir())
    }

    /** Re-reads the identity key pair from DesktopKeyStore — call after a backup import. */
    fun reloadKeyPair() {
        keyPair = DesktopKeyStore.getOrCreateECKeyPair(DesktopStorage.resolveDataDir())
    }

    /** Forces a brand-new identity keypair (and therefore a new server
     *  fingerprint) — call when the user is creating a genuinely new local
     *  account, mirroring Android's RegisterScreen.kt CryptoManager.
     *  generateKeyPair() call. See DesktopKeyStore.regenerateECKeyPair()'s
     *  own comment for why reusing getOrCreateECKeyPair() here was wrong. */
    fun regenerateKeyPair() {
        keyPair = DesktopKeyStore.regenerateECKeyPair(DesktopStorage.resolveDataDir())
    }

    // ── Public key (sent to server on register) ───────────────────────────────

    fun getPublicKeyBase64(): String =
        Base64.getEncoder().encodeToString(keyPair.public.encoded)

    // ── Backup export/import ───────────────────────────────────────────────────

    /** Raw PKCS8 private key bytes — used only for encrypted backup export. */
    fun exportPrivateKeyBytes(): ByteArray = keyPair.private.encoded

    /** Raw X.509 public key bytes — used only for encrypted backup export. */
    fun exportPublicKeyBytes(): ByteArray = keyPair.public.encoded

    /** Restores the identity key pair from a decrypted backup. */
    fun importKeyPair(privateKeyBytes: ByteArray, publicKeyBytes: ByteArray) {
        keyPair = DesktopKeyStore.storeECKeyPair(
            DesktopStorage.resolveDataDir(), privateKeyBytes, publicKeyBytes
        )
    }

    // ── ECDSA signature (challenge-response) ─────────────────────────────────

    fun signBase64(data: ByteArray): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(data)
        return Base64.getEncoder().encodeToString(sig.sign())
    }

    // ── Peer key storage ──────────────────────────────────────────────────────

    fun storePeerPublicKey(username: String, pubKeyBase64: String) {
        peerKeys[username] = pubKeyBase64
    }

    // ── ECDSA signature verification ─────────────────────────────────────────

    fun verifySignature(data: ByteArray, sigBase64: String): Boolean {
        return try {
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(keyPair.public)
            sig.update(data)
            sig.verify(Base64.getDecoder().decode(sigBase64))
        } catch (e: Exception) { false }
    }

    // ── Image / file bytes decrypt ─────────────────────────────────────────────
    //
    // Wire format produced by mobile CryptoManager.packEncryptedFile():
    //   [2 bytes BE: ephemeralKeyLen]
    //   [ephemeralKeyLen bytes: X.509 ephemeral EC public key]
    //   [2 bytes BE: pqCiphertextLen]
    //   [pqCiphertextLen bytes: ML-KEM ciphertext]
    //   [1 byte: ivLen]
    //   [ivLen bytes: AES-GCM IV]
    //   [remaining: AES-256-GCM ciphertext + 16-byte tag]
    //
    // After decryption the plaintext contains a padding prefix:
    //   [4 bytes BE: padLen][padLen bytes: random pad][original bytes]
    // Used for images, generic files, and voice messages alike — the format
    // is content-agnostic. Hybridized with ML-KEM (PqCrypto) the same way as
    // CryptoManager.encrypt()/decrypt() — see there for the harvest-now-
    // decrypt-later rationale.

    // ── Peer key lookup ───────────────────────────────────────────────────────

    fun getPeerPublicKey(username: String): String? = peerKeys[username]

    // ── Image chunk signing (mirrors mobile CryptoManager.signChunk) ──────────
    //
    // Signs: SHA256withECDSA over transferId‖chunkIndex(4BE)‖chunkData
    // This binds the signature to a specific chunk position preventing reorder.

    fun signChunk(chunkData: String, transferId: String, chunkIndex: Int): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(transferId.toByteArray(Charsets.UTF_8))
        sig.update(byteArrayOf(
            (chunkIndex shr 24).toByte(),
            (chunkIndex shr 16).toByte(),
            (chunkIndex shr 8).toByte(),
            (chunkIndex and 0xFF).toByte()
        ))
        sig.update(chunkData.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(sig.sign())
    }

    // ── Image bytes encrypt (inverse of decryptImageBytes) ────────────────────
    //
    // Produces the same wire format as mobile CryptoManager.packEncryptedFile():
    //   [2 bytes BE: ephemeralKeyLen]
    //   [ephemeralKeyLen bytes: X.509 ephemeral EC public key]
    //   [1 byte: ivLen = 12]
    //   [12 bytes: AES-GCM IV]
    //   [remaining: AES-256-GCM ciphertext + 16-byte tag]
    //
    // Plaintext before encryption has padding prefix:
    //   [4 bytes BE: padLen][padLen bytes: random pad][original image bytes]

    fun encryptImageBytes(recipientPubKeyBase64: String, rawBytes: ByteArray, recipientPqPublicKey: ByteArray): ByteArray? {
        return try {
            // ── 1. Generate ephemeral EC key pair (P-256) ─────────────────────
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val ephKeyPair = kpg.generateKeyPair()

            // ── 2. ECDH: ephemeral private × recipient public ─────────────────
            val recipientPubBytes = Base64.getDecoder().decode(recipientPubKeyBase64)
            val recipientPubKey   = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(recipientPubBytes))
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(ephKeyPair.private)
            ka.doPhase(recipientPubKey, true)
            val classicalSecret = ka.generateSecret()

            // ── 2b. Hybrid PQ component: encapsulate against recipient's ML-KEM key ──
            val encapsulated = PqCrypto.encapsulate(recipientPqPublicKey)
            val combinedSecret = classicalSecret + encapsulated.sharedSecret

            // ── 3. HKDF-extract + expand (same as decryptImageBytes) ──────────
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec("BeaconHKDF".toByteArray(Charsets.UTF_8), "HmacSHA256"))
            val prk = mac.doFinal(combinedSecret)
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update("BeaconFileEncryptionPq".toByteArray(Charsets.UTF_8))
            mac.update(0x01.toByte())
            val aesKey = mac.doFinal().copyOfRange(0, 32)

            // ── 4. Add padding: [4 bytes BE padLen][random pad][image bytes] ──
            // Range matches Android CryptoManager.addFilePadding() exactly
            // (1024-4095 bytes) — was 128-255, a narrower range that leaked
            // more precise file-size metadata to ciphertext-length
            // observation than Android's own file encryption does. Found
            // during the CryptoManager cross-platform constant audit;
            // wire format itself (4-byte BE length prefix) was already
            // compatible either way.
            val padLen = 1024 + SecureRandom().nextInt(3072)
            val pad    = ByteArray(padLen).also { SecureRandom().nextBytes(it) }
            val padded = ByteArray(4 + padLen + rawBytes.size)
            padded[0] = (padLen shr 24).toByte()
            padded[1] = (padLen shr 16).toByte()
            padded[2] = (padLen shr 8).toByte()
            padded[3] = (padLen and 0xFF).toByte()
            pad.copyInto(padded, 4)
            rawBytes.copyInto(padded, 4 + padLen)

            // ── 5. AES-256-GCM encrypt ────────────────────────────────────────
            val iv     = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, iv))
            val ciphertext = cipher.doFinal(padded)

            // ── 6. Pack wire format ───────────────────────────────────────────
            val ephPubBytes = ephKeyPair.public.encoded
            val pqCt = encapsulated.ciphertext
            val packed = ByteArray(2 + ephPubBytes.size + 2 + pqCt.size + 1 + iv.size + ciphertext.size)
            var offset = 0
            packed[offset++] = (ephPubBytes.size shr 8).toByte()
            packed[offset++] = (ephPubBytes.size and 0xFF).toByte()
            ephPubBytes.copyInto(packed, offset); offset += ephPubBytes.size
            packed[offset++] = (pqCt.size shr 8).toByte()
            packed[offset++] = (pqCt.size and 0xFF).toByte()
            pqCt.copyInto(packed, offset);         offset += pqCt.size
            packed[offset++] = iv.size.toByte()
            iv.copyInto(packed, offset);          offset += iv.size
            ciphertext.copyInto(packed, offset)

            packed
        } catch (e: Exception) {
            System.err.println("DesktopCryptoManager: encryptImageBytes failed — ${e.message}")
            null
        }
    }

    fun decryptImageBytes(@Suppress("UNUSED_PARAMETER") from: String, data: ByteArray): ByteArray? {
        return try {
            // ── 1. Unpack the packed binary ───────────────────────────────────
            var offset = 0
            val keyLen = ((data[offset++].toInt() and 0xFF) shl 8) or
                         (data[offset++].toInt() and 0xFF)
            val ephPubBytes = data.copyOfRange(offset, offset + keyLen)
            offset += keyLen
            val pqCtLen = ((data[offset++].toInt() and 0xFF) shl 8) or
                          (data[offset++].toInt() and 0xFF)
            val pqCiphertext = data.copyOfRange(offset, offset + pqCtLen)
            offset += pqCtLen
            val ivLen  = data[offset++].toInt() and 0xFF
            val iv     = data.copyOfRange(offset, offset + ivLen)
            offset    += ivLen
            val ct     = data.copyOfRange(offset, data.size)

            // ── 2. ECDH: ephemeral public key × our long-term private key ────
            val ephPubKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(ephPubBytes))
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(keyPair.private)
            ka.doPhase(ephPubKey, true)
            val classicalSecret = ka.generateSecret()

            // ── 2b. Hybrid PQ component — try current key, then previous
            // (grace period) — ML-KEM's implicit rejection means we can't
            // tell which was right until the AES-GCM tag check succeeds.
            val candidates = listOfNotNull(
                SessionKeyManager.getCurrentPqPrivateKey(),
                SessionKeyManager.getPreviousPqPrivateKeyIfValid()
            )
            for (pqPrivateKey in candidates) {
                try {
                    val pqSharedSecret = PqCrypto.decapsulate(pqPrivateKey, pqCiphertext)
                    val combinedSecret = classicalSecret + pqSharedSecret

                    val mac = Mac.getInstance("HmacSHA256")
                    mac.init(SecretKeySpec("BeaconHKDF".toByteArray(Charsets.UTF_8), "HmacSHA256"))
                    val prk = mac.doFinal(combinedSecret)
                    mac.init(SecretKeySpec(prk, "HmacSHA256"))
                    mac.update("BeaconFileEncryptionPq".toByteArray(Charsets.UTF_8))
                    mac.update(0x01.toByte())
                    val aesKey = mac.doFinal().copyOfRange(0, 32)

                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, iv))
                    val padded = cipher.doFinal(ct)

                    val padLen = ((padded[0].toInt() and 0xFF) shl 24) or
                                 ((padded[1].toInt() and 0xFF) shl 16) or
                                 ((padded[2].toInt() and 0xFF) shl 8)  or
                                 (padded[3].toInt() and 0xFF)
                    return padded.copyOfRange(4 + padLen, padded.size)
                } catch (_: Exception) { /* try next candidate */ }
            }
            null
        } catch (e: Exception) {
            System.err.println("DesktopCryptoManager: image decrypt failed — ${e.message}")
            null
        }
    }
}
