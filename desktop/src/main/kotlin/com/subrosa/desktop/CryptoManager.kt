package com.subrosa.desktop

import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.util.Base64
import org.json.JSONObject

object CryptoManager {

    private const val KEY_ALIAS = "ec_key"

    fun init() {
        // Desktop initialization if needed
    }

    private fun getSoftwareKeyPair(): java.security.KeyPair {
        return DesktopKeyStore.getOrCreateECKeyPair(DesktopStorage.resolveDataDir())
    }

    fun generateKeyPair() {
        getSoftwareKeyPair()
    }

    fun hasKeys(): Boolean {
        return DesktopKeyStore.hasECKeyPair(DesktopStorage.resolveDataDir())
    }

    fun getPublicKeyString(): String {
        return Base64.getEncoder().encodeToString(getSoftwareKeyPair().public.encoded)
    }

    fun getPublicKey(): java.security.PublicKey {
        return getSoftwareKeyPair().public
    }

    fun getPrivateKeyPublic(): java.security.PrivateKey = getPrivateKey()

    private fun getPrivateKey(): java.security.PrivateKey {
        return getSoftwareKeyPair().private
    }

    // ─── Режим 1: Hybrid PQ + Ephemeral ECDH (fallback / legacy / groups) ─────
    //
    // Combines a classical ephemeral-ECDH shared secret with an ML-KEM
    // encapsulated shared secret (PqCrypto) so this path — used for the
    // pre-session fallback, edit messages, and group key distribution — is
    // hardened against harvest-now-decrypt-later the same way the X3DH
    // handshake is (see SessionKeyManager.kt). Breaking either component
    // alone is not enough to recover the AES key.
    //
    // Wire format: [2B ephKeyLen][ephKey][2B pqCtLen][pqCiphertext][iv+ciphertext]

    fun encrypt(plaintext: String, recipientPublicKeyStr: String, recipientPqPublicKey: ByteArray): String {
        val ephemeralKeyPair = generateEphemeralKeyPair()
        val classicalSecret = ecdh(ephemeralKeyPair.private, loadPublicKey(recipientPublicKeyStr))
        val encapsulated = PqCrypto.encapsulate(recipientPqPublicKey)
        val combinedSecret = classicalSecret + encapsulated.sharedSecret
        val aesKey = deriveAesKey(combinedSecret, "BeaconECDHpq")
        val encrypted = aesEncrypt(plaintext, aesKey)

        SecureMemory.wipe(classicalSecret)
        SecureMemory.wipe(encapsulated.sharedSecret)
        SecureMemory.wipe(combinedSecret)
        SecureMemory.wipe(aesKey)

        val ephemeralPublicBytes = ephemeralKeyPair.public.encoded
        val keyLen = ephemeralPublicBytes.size
        val pqCtLen = encapsulated.ciphertext.size

        val combined = ByteArray(2 + keyLen + 2 + pqCtLen + encrypted.size)
        var pos = 0
        combined[pos++] = (keyLen shr 8).toByte()
        combined[pos++] = (keyLen and 0xFF).toByte()
        System.arraycopy(ephemeralPublicBytes, 0, combined, pos, keyLen); pos += keyLen
        combined[pos++] = (pqCtLen shr 8).toByte()
        combined[pos++] = (pqCtLen and 0xFF).toByte()
        System.arraycopy(encapsulated.ciphertext, 0, combined, pos, pqCtLen); pos += pqCtLen
        System.arraycopy(encrypted, 0, combined, pos, encrypted.size)

        return Base64.getEncoder().encodeToString(combined)
    }

    fun decrypt(ciphertext: String): String {
        val combined = Base64.getDecoder().decode(ciphertext)
        var pos = 0

        if (combined.size < pos + 2) throw IllegalArgumentException("Пакет слишком короткий")
        val keyLen = ((combined[pos].toInt() and 0xFF) shl 8) or (combined[pos + 1].toInt() and 0xFF)
        pos += 2
        if (combined.size < pos + keyLen) throw IllegalArgumentException("Пакет повреждён (ephemeral key)")
        val ephemeralPublicBytes = combined.copyOfRange(pos, pos + keyLen)
        pos += keyLen

        if (combined.size < pos + 2) throw IllegalArgumentException("Пакет повреждён (pq ciphertext length)")
        val pqCtLen = ((combined[pos].toInt() and 0xFF) shl 8) or (combined[pos + 1].toInt() and 0xFF)
        pos += 2
        if (combined.size < pos + pqCtLen) throw IllegalArgumentException("Пакет повреждён (pq ciphertext)")
        val pqCiphertext = combined.copyOfRange(pos, pos + pqCtLen)
        pos += pqCtLen

        val encrypted = combined.copyOfRange(pos, combined.size)
        val ephemeralPublicKey = loadPublicKey(Base64.getEncoder().encodeToString(ephemeralPublicBytes))
        val classicalSecret = ecdh(getPrivateKey(), ephemeralPublicKey)

        try {
            // ML-KEM has implicit rejection — decapsulating with the wrong key
            // still returns *a* secret, never an error — so we can't know which
            // PQ key version (current vs. still-in-grace-period previous) was
            // used just from decapsulating. Try both and let AES-GCM's tag
            // check decide which one was actually correct.
            val candidates = listOfNotNull(
                SessionKeyManager.getCurrentPqPrivateKey(),
                SessionKeyManager.getPreviousPqPrivateKeyIfValid()
            )
            if (candidates.isEmpty()) throw IllegalStateException("Нет PQ KEM ключа для расшифровки")

            var lastError: Exception? = null
            for (pqPrivateKey in candidates) {
                var pqSharedSecret: ByteArray? = null
                var combinedSecret: ByteArray? = null
                var aesKey: ByteArray? = null
                try {
                    pqSharedSecret = PqCrypto.decapsulate(pqPrivateKey, pqCiphertext)
                    combinedSecret = classicalSecret + pqSharedSecret
                    aesKey = deriveAesKey(combinedSecret, "BeaconECDHpq")
                    return aesDecrypt(encrypted, aesKey)
                } catch (e: Exception) {
                    lastError = e
                } finally {
                    pqSharedSecret?.let { SecureMemory.wipe(it) }
                    combinedSecret?.let { SecureMemory.wipe(it) }
                    aesKey?.let { SecureMemory.wipe(it) }
                }
            }
            throw lastError ?: IllegalStateException("Расшифровка не удалась")
        } finally {
            SecureMemory.wipe(classicalSecret)
            SecureMemory.wipe(encrypted)
        }
    }

    // ─── Classical-only variant — anonymous-mailbox first-contact bootstrap ───
    //
    // The invite code that seeds a mailbox exchange carries only a classical
    // EC identity key (no PQ key — embedding a ~1.2 KB ML-KEM key would make
    // invite links/QR codes impractically large). This one bootstrap message
    // is therefore classical-only; the session established immediately after
    // it is full PQ-hybrid X3DH. Documented as a known, narrow exception in
    // SECURITY.md. Do not use this for anything else.

    fun encryptClassicalOnly(plaintext: String, recipientPublicKeyStr: String): String {
        val ephemeralKeyPair = generateEphemeralKeyPair()
        val sharedSecret = ecdh(ephemeralKeyPair.private, loadPublicKey(recipientPublicKeyStr))
        val aesKey = deriveAesKey(sharedSecret, "BeaconECDH")
        val encrypted = aesEncrypt(plaintext, aesKey)

        SecureMemory.wipe(sharedSecret)
        SecureMemory.wipe(aesKey)

        val ephemeralPublicBytes = ephemeralKeyPair.public.encoded
        val keyLen = ephemeralPublicBytes.size

        val combined = ByteArray(2 + keyLen + encrypted.size)
        combined[0] = (keyLen shr 8).toByte()
        combined[1] = (keyLen and 0xFF).toByte()
        System.arraycopy(ephemeralPublicBytes, 0, combined, 2, keyLen)
        System.arraycopy(encrypted, 0, combined, 2 + keyLen, encrypted.size)

        return Base64.getEncoder().encodeToString(combined)
    }

    fun decryptClassicalOnly(ciphertext: String): String {
        val combined = Base64.getDecoder().decode(ciphertext)

        if (combined.size < 2) throw IllegalArgumentException("Пакет слишком короткий")
        val keyLen = ((combined[0].toInt() and 0xFF) shl 8) or (combined[1].toInt() and 0xFF)

        if (combined.size < 2 + keyLen) {
            throw IllegalArgumentException("Пакет повреждён: keyLen=$keyLen, размер=${combined.size}")
        }

        val ephemeralPublicBytes = combined.copyOfRange(2, 2 + keyLen)
        val encrypted = combined.copyOfRange(2 + keyLen, combined.size)

        val ephemeralPublicKey = loadPublicKey(Base64.getEncoder().encodeToString(ephemeralPublicBytes))

        val sharedSecret = ecdh(getPrivateKey(), ephemeralPublicKey)
        val aesKey = deriveAesKey(sharedSecret, "BeaconECDH")
        return try {
            aesDecrypt(encrypted, aesKey)
        } finally {
            SecureMemory.wipe(sharedSecret)
            SecureMemory.wipe(aesKey)
            SecureMemory.wipe(encrypted)
        }
    }

    private fun validateECPoint(publicKey: java.security.PublicKey) {
        val ecKey = publicKey as? ECPublicKey
            ?: throw SecurityException("Ключ не является EC ключом")

        val point = ecKey.w
        if (point == ECPoint.POINT_INFINITY) {
            throw SecurityException("Invalid Curve Attack: точка в бесконечности")
        }

        val params = ecKey.params
        val p = (params.curve.field as java.security.spec.ECFieldFp).p
        val x = point.affineX
        val y = point.affineY

        if (x < java.math.BigInteger.ZERO || x >= p) {
            throw SecurityException("Invalid Curve Attack: x вне поля")
        }
        if (y < java.math.BigInteger.ZERO || y >= p) {
            throw SecurityException("Invalid Curve Attack: y вне поля")
        }

        val a = params.curve.a
        val b = params.curve.b
        val lhs = y.modPow(java.math.BigInteger.valueOf(2), p)
        val rhs = x.modPow(java.math.BigInteger.valueOf(3), p)
            .add(a.multiply(x))
            .add(b)
            .mod(p)

        if (lhs != rhs) {
            throw SecurityException("Invalid Curve Attack: точка не лежит на кривой secp256r1")
        }
    }

    private fun deriveAesKey(sharedSecret: ByteArray, info: String): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec("BeaconHKDF".toByteArray(Charsets.UTF_8), "HmacSHA256"))
        val prk = mac.doFinal(sharedSecret)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info.toByteArray())
        mac.update(0x01.toByte())
        val okm = mac.doFinal()
        SecureMemory.wipe(prk)
        return okm.copyOfRange(0, 32)
    }

    fun encryptWithForwardSecrecy(
        contactId: String,
        plaintext: String
    ): Pair<String, JSONObject> {
        return SessionKeyManager.encryptWithSession(contactId, plaintext)
    }

    fun decryptWithForwardSecrecy(
        contactId: String,
        ciphertextB64: String,
        header: JSONObject
    ): String {
        return SessionKeyManager.decryptWithSession(contactId, ciphertextB64, header)
    }

    fun sign(message: String): String {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(getPrivateKey())
        signature.update(message.toByteArray())
        return Base64.getEncoder().encodeToString(signature.sign())
    }

    fun verify(message: String, signatureStr: String, publicKeyStr: String): Boolean {
        return try {
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(loadPublicKey(publicKeyStr))
            signature.update(message.toByteArray())
            signature.verify(Base64.getDecoder().decode(signatureStr))
        } catch (e: Exception) {
            false
        }
    }

    fun signBytes(data: ByteArray): String {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(getPrivateKey())
        signature.update(data)
        return Base64.getEncoder().encodeToString(signature.sign())
    }

    fun signChunk(chunkData: String, transferId: String, chunkIndex: Int): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(getPrivateKey())
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

    fun verifyChunk(chunkData: String, signatureStr: String, publicKeyStr: String, transferId: String, chunkIndex: Int): Boolean {
        return try {
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(loadPublicKey(publicKeyStr))
            sig.update(transferId.toByteArray(Charsets.UTF_8))
            sig.update(byteArrayOf(
                (chunkIndex shr 24).toByte(),
                (chunkIndex shr 16).toByte(),
                (chunkIndex shr 8).toByte(),
                (chunkIndex and 0xFF).toByte()
            ))
            sig.update(chunkData.toByteArray(Charsets.UTF_8))
            sig.verify(Base64.getDecoder().decode(signatureStr))
        } catch (e: Exception) {
            false
        }
    }

    private fun generateEphemeralKeyPair(): java.security.KeyPair {
        val keyPairGen = java.security.KeyPairGenerator.getInstance("EC")
        keyPairGen.initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        return keyPairGen.generateKeyPair()
    }

    private fun ecdh(
        privateKey: java.security.PrivateKey,
        publicKey: java.security.PublicKey
    ): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    fun loadPublicKey(keyString: String): java.security.PublicKey {
        val keyBytes = Base64.getDecoder().decode(keyString)
        val keyFactory = java.security.KeyFactory.getInstance("EC")
        val publicKey = keyFactory.generatePublic(java.security.spec.X509EncodedKeySpec(keyBytes))
        validateECPoint(publicKey)
        return publicKey
    }

    private val secureRandom = java.security.SecureRandom()

    private fun addPadding(data: ByteArray): ByteArray {
        val padLen = 128 + secureRandom.nextInt(385)
        val pad = ByteArray(padLen).also { secureRandom.nextBytes(it) }
        val result = ByteArray(2 + padLen + data.size)
        result[0] = (padLen shr 8).toByte()
        result[1] = (padLen and 0xFF).toByte()
        System.arraycopy(pad, 0, result, 2, padLen)
        System.arraycopy(data, 0, result, 2 + padLen, data.size)
        return result
    }

    private fun removePadding(data: ByteArray): ByteArray {
        if (data.size < 2) throw IllegalArgumentException("Пакет слишком короткий")
        val padLen = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        if (data.size < 2 + padLen) {
            throw IllegalArgumentException("Паддинг повреждён: padLen=$padLen size=${data.size}")
        }
        return data.copyOfRange(2 + padLen, data.size)
    }

    private fun aesEncrypt(plaintext: String, key: ByteArray): ByteArray {
        val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(key, 0, 32, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val padded = addPadding(plaintext.toByteArray(Charsets.UTF_8))
        val ciphertext = try { cipher.doFinal(padded) } finally { SecureMemory.wipe(padded) }
        return iv + ciphertext
    }

    private fun aesDecrypt(encrypted: ByteArray, key: ByteArray): String {
        val iv = encrypted.copyOfRange(0, 12)
        val ciphertext = encrypted.copyOfRange(12, encrypted.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(key, 0, 32, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val padded = cipher.doFinal(ciphertext)
        val unpadded = try { removePadding(padded) } finally { SecureMemory.wipe(padded) }
        val result = try { String(unpadded, Charsets.UTF_8) } finally { SecureMemory.wipe(unpadded) }
        return result
    }

    fun deleteKeys() {
        DesktopKeyStore.deleteECKeyPair(DesktopStorage.resolveDataDir())
    }

    fun getFingerprintEmoji(): String {
        return try {
            val publicKeyBytes = Base64.getDecoder().decode(getPublicKeyString())
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(publicKeyBytes)
            digest.take(5).joinToString("  ") {
                EMOJI_SET[it.toInt().and(0xFF) % EMOJI_SET.size]
            }
        } catch (e: Exception) {
            "Ошибка: ${e.message}"
        }
    }

    private val EMOJI_SET = listOf(
        "🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼",
        "🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔",
        "🐧","🐦","🦆","🦅","🦉","🦇","🐺","🐗",
        "🐴","🦄","🐝","🐛","🦋","🐌","🐞","🐜",
        "🦟","🦗","🦂","🐢","🐍","🦎","🦖","🦕",
        "🐙","🦑","🦐","🦀","🐡","🐠","🐟","🐬",
        "🐳","🐋","🦈","🐊","🐅","🐆","🦓","🦍",
        "🦧","🐘","🦛","🦏","🐪","🐫","🦒","🦘"
    )
}
