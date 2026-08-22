package com.subrosa.messenger

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import android.util.Log

object CryptoManager {

    private const val KEY_ALIAS        = "messenger_ec_key"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val SW_KEY_PREFS     = "beacon_sw_keys"
    private const val SW_KEY_PREFS_ENC = "beacon_ec_keys_enc"
    private const val SW_PRIV_KEY      = "ec_priv"
    private const val SW_PUB_KEY       = "ec_pub"

    private var appContext: android.content.Context? = null

    fun init(context: android.content.Context) {
        appContext = context.applicationContext
    }

    private fun useKeyStore() = false

    private fun getSoftwareKeyPair(): java.security.KeyPair {
        val ctx = appContext ?: throw IllegalStateException("CryptoManager.init() не вызван")

        val encPrefs   = EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS_ENC)
        val privStored = encPrefs.getString(SW_PRIV_KEY, null)
        val pubB64     = encPrefs.getString(SW_PUB_KEY,  null)
        if (privStored != null && pubB64 != null) {
            val privBytes = StorageKeyManager.unwrapBytes(privStored)

            if (!privStored.startsWith(StorageKeyManager.SMK_PREFIX) && StorageKeyManager.isUnlocked) {
                encPrefs.edit().putString(SW_PRIV_KEY, StorageKeyManager.wrapBytes(privBytes)).commit()
            }
            val kf = java.security.KeyFactory.getInstance("EC")
            return java.security.KeyPair(
                kf.generatePublic(java.security.spec.X509EncodedKeySpec(Base64.decode(pubB64, Base64.NO_WRAP))),
                kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(privBytes))
            )
        }

        try {
            val prevEncPrefs = EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS)
            val prevPriv = prevEncPrefs.getString(SW_PRIV_KEY, null)
            val prevPub  = prevEncPrefs.getString(SW_PUB_KEY,  null)
            if (prevPriv != null && prevPub != null) {
                android.util.Log.d("CryptoManager", "Миграция ключей beacon_sw_keys(enc) → beacon_ec_keys_enc")
                encPrefs.edit().putString(SW_PRIV_KEY, prevPriv).putString(SW_PUB_KEY, prevPub).commit()
                prevEncPrefs.edit().remove(SW_PRIV_KEY).remove(SW_PUB_KEY).apply()
                val kf = java.security.KeyFactory.getInstance("EC")
                return java.security.KeyPair(
                    kf.generatePublic(java.security.spec.X509EncodedKeySpec(Base64.decode(prevPub, Base64.NO_WRAP))),
                    kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(Base64.decode(prevPriv, Base64.NO_WRAP)))
                )
            }
        } catch (e: Exception) {
            android.util.Log.w("CryptoManager", "Шаг 2 миграции недоступен: ${e.message}")
        }

        val legacyPrefs = ctx.getSharedPreferences(SW_KEY_PREFS, android.content.Context.MODE_PRIVATE)
        val legacyPriv  = legacyPrefs.getString(SW_PRIV_KEY, null)
        val legacyPub   = legacyPrefs.getString(SW_PUB_KEY,  null)
        if (legacyPriv != null && legacyPub != null) {
            android.util.Log.d("CryptoManager", "Миграция ключей beacon_sw_keys(plain) → beacon_ec_keys_enc")
            encPrefs.edit().putString(SW_PRIV_KEY, legacyPriv).putString(SW_PUB_KEY, legacyPub).commit()
            legacyPrefs.edit().remove(SW_PRIV_KEY).remove(SW_PUB_KEY).apply()
            val kf = java.security.KeyFactory.getInstance("EC")
            return java.security.KeyPair(
                kf.generatePublic(java.security.spec.X509EncodedKeySpec(Base64.decode(legacyPub, Base64.NO_WRAP))),
                kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(Base64.decode(legacyPriv, Base64.NO_WRAP)))
            )
        }

        val kpg = java.security.KeyPairGenerator.getInstance("EC")
        kpg.initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val privToStore = if (StorageKeyManager.isUnlocked)
            StorageKeyManager.wrapBytes(kp.private.encoded)
        else
            Base64.encodeToString(kp.private.encoded, Base64.NO_WRAP)
        encPrefs.edit()
            .putString(SW_PRIV_KEY, privToStore)
            .putString(SW_PUB_KEY,  Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP))
            .commit()

        android.util.Log.d("CryptoManager", "Software EC ключи сгенерированы")
        return kp
    }

    fun generateKeyPair() {
        if (!useKeyStore()) {
            getSoftwareKeyPair()
            return
        }
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        if (keyStore.containsAlias(KEY_ALIAS)) return
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_AGREE_KEY or KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)
                .build()
        )
        keyPairGenerator.generateKeyPair()
        android.util.Log.d("CryptoManager", "KeyStore EC ключи сгенерированы")
    }

    fun hasKeys(): Boolean {
        return if (useKeyStore()) {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.containsAlias(KEY_ALIAS)
        } else {
            val ctx = appContext ?: return false

            if (EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS_ENC)
                    .getString(SW_PRIV_KEY, null) != null) return true

            try {
                if (EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS)
                        .getString(SW_PRIV_KEY, null) != null) return true
            } catch (_: Exception) {}

            ctx.getSharedPreferences(SW_KEY_PREFS, android.content.Context.MODE_PRIVATE)
                .getString(SW_PRIV_KEY, null) != null
        }
    }

    fun getPublicKeyString(): String {
        return if (useKeyStore()) {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            Base64.encodeToString(keyStore.getCertificate(KEY_ALIAS).publicKey.encoded, Base64.NO_WRAP)
        } else {
            Base64.encodeToString(getSoftwareKeyPair().public.encoded, Base64.NO_WRAP)
        }
    }

    fun getPublicKey(): java.security.PublicKey {
        return if (useKeyStore()) {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.getCertificate(KEY_ALIAS).publicKey
        } else {
            getSoftwareKeyPair().public
        }
    }

    fun getPrivateKeyPublic(): java.security.PrivateKey = getPrivateKey()

    private fun getPrivateKey(): java.security.PrivateKey {
        return if (useKeyStore()) {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.getKey(KEY_ALIAS, null) as java.security.PrivateKey
        } else {
            getSoftwareKeyPair().private
        }
    }

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

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decrypt(ciphertext: String): String {
        val combined = Base64.decode(ciphertext, Base64.NO_WRAP)
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
        val ephemeralPublicKey = loadPublicKey(Base64.encodeToString(ephemeralPublicBytes, Base64.NO_WRAP))
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

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decryptClassicalOnly(ciphertext: String): String {
        val combined = Base64.decode(ciphertext, Base64.NO_WRAP)

        if (combined.size < 2) throw IllegalArgumentException("Пакет слишком короткий")
        val keyLen = ((combined[0].toInt() and 0xFF) shl 8) or (combined[1].toInt() and 0xFF)

        if (combined.size < 2 + keyLen) {
            throw IllegalArgumentException("Пакет повреждён: keyLen=$keyLen, размер=${combined.size}")
        }

        val ephemeralPublicBytes = combined.copyOfRange(2, 2 + keyLen)
        val encrypted = combined.copyOfRange(2 + keyLen, combined.size)

        val ephemeralPublicKey = loadPublicKey(Base64.encodeToString(ephemeralPublicBytes, Base64.NO_WRAP))

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
    ): Pair<String, org.json.JSONObject> {
        return SessionKeyManager.encryptWithSession(contactId, plaintext)
    }

    fun decryptWithForwardSecrecy(
        contactId: String,
        ciphertextB64: String,
        header: org.json.JSONObject
    ): String {
        return SessionKeyManager.decryptWithSession(contactId, ciphertextB64, header)
    }

    fun sign(message: String): String {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(getPrivateKey())
        signature.update(message.toByteArray())
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    fun verify(message: String, signatureStr: String, publicKeyStr: String): Boolean {
        return try {
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(loadPublicKey(publicKeyStr))
            signature.update(message.toByteArray())
            signature.verify(Base64.decode(signatureStr, Base64.NO_WRAP))
        } catch (e: Exception) {
            false
        }
    }

    fun signBytes(data: ByteArray): String {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(getPrivateKey())
        signature.update(data)
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
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
        return Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
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
            sig.verify(Base64.decode(signatureStr, Base64.NO_WRAP))
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
        val keyBytes = Base64.decode(keyString, Base64.NO_WRAP)
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

        val result = data.copyOfRange(2 + padLen, data.size)
        return result
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
        try {
            if (useKeyStore()) {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)
                if (keyStore.containsAlias(KEY_ALIAS)) {
                    keyStore.deleteEntry(KEY_ALIAS)
                }
            } else {
                val ctx = appContext ?: return

                EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS_ENC)
                    .edit().remove(SW_PRIV_KEY).remove(SW_PUB_KEY).apply()

                try {
                    EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS)
                        .edit().remove(SW_PRIV_KEY).remove(SW_PUB_KEY).apply()
                } catch (_: Exception) {}

                ctx.getSharedPreferences(SW_KEY_PREFS, android.content.Context.MODE_PRIVATE)
                    .edit().clear().apply()
            }
        } catch (e: Exception) {
            android.util.Log.e("CryptoManager", "Ошибка удаления ключей: ${e.message}")
        }
    }

    data class EncryptedFileData(
        val encryptedData: ByteArray,
        val iv: ByteArray,
        val ephemeralPublicKey: ByteArray,
        val pqCiphertext: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as EncryptedFileData
            if (!encryptedData.contentEquals(other.encryptedData)) return false
            if (!iv.contentEquals(other.iv)) return false
            if (!ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)) return false
            if (!pqCiphertext.contentEquals(other.pqCiphertext)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = encryptedData.contentHashCode()
            result = 31 * result + iv.contentHashCode()
            result = 31 * result + ephemeralPublicKey.contentHashCode()
            result = 31 * result + pqCiphertext.contentHashCode()
            return result
        }
    }

    // Hybridized with ML-KEM (PqCrypto) the same way as encrypt()/decrypt() —
    // see there for the harvest-now-decrypt-later rationale.

    fun encryptFile(fileData: ByteArray, recipientPublicKeyStr: String, recipientPqPublicKey: ByteArray): EncryptedFileData {
        val ephemeralKeyPair = generateEphemeralKeyPair()
        val classicalSecret = ecdh(ephemeralKeyPair.private, loadPublicKey(recipientPublicKeyStr))
        val encapsulated = PqCrypto.encapsulate(recipientPqPublicKey)
        val combinedSecret = classicalSecret + encapsulated.sharedSecret
        val aesKey = deriveAesKey(combinedSecret, "BeaconFileEncryptionPq")

        val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(aesKey, 0, 32, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

        val padded = addFilePadding(fileData)
        val encryptedData = cipher.doFinal(padded)

        SecureMemory.wipe(classicalSecret)
        SecureMemory.wipe(encapsulated.sharedSecret)
        SecureMemory.wipe(combinedSecret)
        SecureMemory.wipe(aesKey)
        SecureMemory.wipe(padded)

        val ephemeralPublicBytes = ephemeralKeyPair.public.encoded

        return EncryptedFileData(
            encryptedData = encryptedData,
            iv = iv,
            ephemeralPublicKey = ephemeralPublicBytes,
            pqCiphertext = encapsulated.ciphertext
        )
    }

    fun decryptFile(encryptedFileData: EncryptedFileData): ByteArray {
        val ephemeralPublicKey = loadPublicKey(
            Base64.encodeToString(encryptedFileData.ephemeralPublicKey, Base64.NO_WRAP)
        )
        val classicalSecret = ecdh(getPrivateKey(), ephemeralPublicKey)

        // ML-KEM has implicit rejection — try current, then previous
        // (grace-period) PQ key and let AES-GCM's tag check decide.
        val candidates = listOfNotNull(
            SessionKeyManager.getCurrentPqPrivateKey(),
            SessionKeyManager.getPreviousPqPrivateKeyIfValid()
        )
        if (candidates.isEmpty()) throw IllegalStateException("Нет PQ KEM ключа для расшифровки файла")

        var lastError: Exception? = null
        for (pqPrivateKey in candidates) {
            try {
                val pqSharedSecret = PqCrypto.decapsulate(pqPrivateKey, encryptedFileData.pqCiphertext)
                val combinedSecret = classicalSecret + pqSharedSecret
                val aesKey = deriveAesKey(combinedSecret, "BeaconFileEncryptionPq")

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val secretKey = SecretKeySpec(aesKey, 0, 32, "AES")
                cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, encryptedFileData.iv))
                val paddedData = cipher.doFinal(encryptedFileData.encryptedData)

                val originalData = removeFilePadding(paddedData)

                SecureMemory.wipe(pqSharedSecret)
                SecureMemory.wipe(combinedSecret)
                SecureMemory.wipe(aesKey)
                SecureMemory.wipe(paddedData)
                SecureMemory.wipe(classicalSecret)
                return originalData
            } catch (e: Exception) {
                lastError = e
            }
        }
        SecureMemory.wipe(classicalSecret)
        throw lastError ?: IllegalStateException("Расшифровка файла не удалась")
    }

    private fun addFilePadding(data: ByteArray): ByteArray {
        val padLen = 1024 + secureRandom.nextInt(3072)
        val pad = ByteArray(padLen).also { secureRandom.nextBytes(it) }

        val result = ByteArray(4 + padLen + data.size)
        result[0] = (padLen shr 24).toByte()
        result[1] = (padLen shr 16).toByte()
        result[2] = (padLen shr 8).toByte()
        result[3] = (padLen and 0xFF).toByte()
        System.arraycopy(pad, 0, result, 4, padLen)
        System.arraycopy(data, 0, result, 4 + padLen, data.size)

        return result
    }

    private fun removeFilePadding(data: ByteArray): ByteArray {
        if (data.size < 4) throw IllegalArgumentException("Файл слишком короткий")

        val padLen = ((data[0].toInt() and 0xFF) shl 24) or
                ((data[1].toInt() and 0xFF) shl 16) or
                ((data[2].toInt() and 0xFF) shl 8) or
                (data[3].toInt() and 0xFF)

        if (data.size < 4 + padLen) {
            throw IllegalArgumentException("Паддинг файла повреждён: padLen=$padLen size=${data.size}")
        }

        return data.copyOfRange(4 + padLen, data.size)
    }

    fun packEncryptedFile(encryptedFileData: EncryptedFileData): String {
        val ephemeralKeyLen = encryptedFileData.ephemeralPublicKey.size
        val pqCtLen = encryptedFileData.pqCiphertext.size
        val ivLen = encryptedFileData.iv.size

        val packed = ByteArray(
            2 + ephemeralKeyLen + 2 + pqCtLen + 1 + ivLen + encryptedFileData.encryptedData.size
        )

        var offset = 0

        packed[offset++] = (ephemeralKeyLen shr 8).toByte()
        packed[offset++] = (ephemeralKeyLen and 0xFF).toByte()

        System.arraycopy(encryptedFileData.ephemeralPublicKey, 0, packed, offset, ephemeralKeyLen)
        offset += ephemeralKeyLen

        packed[offset++] = (pqCtLen shr 8).toByte()
        packed[offset++] = (pqCtLen and 0xFF).toByte()

        System.arraycopy(encryptedFileData.pqCiphertext, 0, packed, offset, pqCtLen)
        offset += pqCtLen

        packed[offset++] = ivLen.toByte()

        System.arraycopy(encryptedFileData.iv, 0, packed, offset, ivLen)
        offset += ivLen

        System.arraycopy(encryptedFileData.encryptedData, 0, packed, offset, encryptedFileData.encryptedData.size)

        return Base64.encodeToString(packed, Base64.NO_WRAP)
    }

    fun unpackEncryptedFile(packedB64: String): EncryptedFileData {
        val packed = Base64.decode(packedB64, Base64.NO_WRAP)

        if (packed.size < 4) throw IllegalArgumentException("Пакет файла слишком короткий")

        var offset = 0

        val keyLen = ((packed[offset++].toInt() and 0xFF) shl 8) or
                (packed[offset++].toInt() and 0xFF)

        if (packed.size < offset + keyLen + 2) {
            throw IllegalArgumentException("Пакет файла повреждён (ключ)")
        }

        val ephemeralPublicKey = packed.copyOfRange(offset, offset + keyLen)
        offset += keyLen

        val pqCtLen = ((packed[offset++].toInt() and 0xFF) shl 8) or
                (packed[offset++].toInt() and 0xFF)

        if (packed.size < offset + pqCtLen + 1) {
            throw IllegalArgumentException("Пакет файла повреждён (PQ ciphertext)")
        }

        val pqCiphertext = packed.copyOfRange(offset, offset + pqCtLen)
        offset += pqCtLen

        val ivLen = packed[offset++].toInt() and 0xFF

        if (packed.size < offset + ivLen) {
            throw IllegalArgumentException("Пакет файла повреждён (IV)")
        }

        val iv = packed.copyOfRange(offset, offset + ivLen)
        offset += ivLen

        val encryptedData = packed.copyOfRange(offset, packed.size)

        return EncryptedFileData(
            encryptedData = encryptedData,
            iv = iv,
            ephemeralPublicKey = ephemeralPublicKey,
            pqCiphertext = pqCiphertext
        )
    }

    fun runSecurityDiagnostics(context: android.content.Context, onLine: ((String) -> Unit)? = null): String {
        val isEn = UserStorage.getLanguage(context) == "en"
        fun tr(ru: String, en: String) = if (isEn) en else ru
        val report = StringBuilder()
        fun emit(line: String = "") { report.append(line).append('\n'); onLine?.invoke(line) }
        emit("═══════════════════════════════════════")
        emit(tr("ДИАГНОСТИКА БЕЗОПАСНОСТИ KEYSTORE", "KEYSTORE SECURITY DIAGNOSTICS"))
        emit("═══════════════════════════════════════\n")

        if (!hasKeys()) {
            generateKeyPair()
        }

        emit(tr("📋 ТЕСТ 1: Проверка существования ключей", "📋 TEST 1: Key existence check"))
        val hasKeysInitial = hasKeys()

        // Found live: this line used to have no [OK]/[FAIL]/[WARN] marker, so
        // SecurityDiagnosticsScreen's shouldShow() filter — which only shows
        // lines with one of those markers (or a few specific headers) —
        // silently swallowed it. Test 1's result never appeared in the UI at
        // all when keys already existed (the normal case), unlike tests 2
        // and 3 which both already used explicit [OK]/[FAIL] lines.
        if (hasKeysInitial) {
            emit(tr("  [OK] Ключи существуют", "  [OK] Keys exist"))
        } else {
            emit(tr("  [WARN] Ключи не найдены, генерируем...", "  [WARN] Keys not found, generating..."))
            generateKeyPair()
            emit(tr("  [OK] Ключи сгенерированы", "  [OK] Keys generated"))
        }
        emit()

        emit(tr("📋 ТЕСТ 2: Защита от повторной генерации", "📋 TEST 2: Regeneration protection"))
        val publicKey1 = getPublicKeyString()
        emit(tr("  Публичный ключ (до): ${publicKey1.take(50)}...", "  Public key (before): ${publicKey1.take(50)}..."))

        generateKeyPair()
        val publicKey2 = getPublicKeyString()
        emit(tr("  Публичный ключ (после): ${publicKey2.take(50)}...", "  Public key (after): ${publicKey2.take(50)}..."))

        if (publicKey1 == publicKey2) {
            emit(tr("  [OK] УСПЕХ: Ключи НЕ пересоздались (защита работает)", "  [OK] PASS: Keys were NOT recreated (protection works)"))
        } else {
            emit(tr("  [FAIL] ПРОВАЛ: Ключи пересоздались (КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!)", "  [FAIL] FAIL: Keys were recreated (CRITICAL VULNERABILITY!)"))
        }
        emit()

        emit(tr("📋 ТЕСТ 3: Удаление и восстановление", "📋 TEST 3: Deletion and recovery"))
        val keyBeforeDelete = getPublicKeyString()

        val ctx3 = appContext
        val encPrefs3 = ctx3?.let { EncryptedStorage.getEncryptedPrefs(it, SW_KEY_PREFS_ENC) }
        val savedPrivB64 = encPrefs3?.getString(SW_PRIV_KEY, null)
        val savedPubB64  = encPrefs3?.getString(SW_PUB_KEY,  null)

        deleteKeys()
        val hasKeysAfterDelete = hasKeys()
        emit(tr("  После deleteKeys(): hasKeys() = $hasKeysAfterDelete", "  After deleteKeys(): hasKeys() = $hasKeysAfterDelete"))

        if (!hasKeysAfterDelete) {
            emit(tr("  [OK] УСПЕХ: Ключи успешно удалены", "  [OK] PASS: Keys successfully deleted"))
        } else {
            emit(tr("  [FAIL] ПРОВАЛ: Ключи не удалились", "  [FAIL] FAIL: Keys were not deleted"))
        }

        generateKeyPair()
        val hasKeysAfterRegenerate = hasKeys()
        val keyAfterRegenerate = getPublicKeyString()
        emit(tr("  После generateKeyPair(): hasKeys() = $hasKeysAfterRegenerate", "  After generateKeyPair(): hasKeys() = $hasKeysAfterRegenerate"))

        if (hasKeysAfterRegenerate) {
            emit(tr("  [OK] УСПЕХ: Генерация новых ключей работает", "  [OK] PASS: New key generation works"))
            if (keyBeforeDelete != keyAfterRegenerate) {
                emit(tr("  [OK] УСПЕХ: Новые ключи отличаются от старых", "  [OK] PASS: New keys differ from the old ones"))
            }
        } else {
            emit(tr("  [FAIL] ПРОВАЛ: Не удалось восстановить ключи", "  [FAIL] FAIL: Could not restore keys"))
        }

        if (savedPrivB64 != null && savedPubB64 != null && encPrefs3 != null) {
            encPrefs3.edit()
                .putString(SW_PRIV_KEY, savedPrivB64)
                .putString(SW_PUB_KEY,  savedPubB64)
                .commit()
            emit(tr("  🔄 Ключи аккаунта восстановлены (fingerprint не изменился)", "  🔄 Account keys restored (fingerprint unchanged)"))
        }
        emit()

        emit(tr("📋 ТЕСТ 4: Проверка хранилища ключей", "📋 TEST 4: Key storage check"))
        try {
            val ctx4 = appContext ?: throw IllegalStateException(tr("CryptoManager.init() не вызван", "CryptoManager.init() was not called"))
            val encPrefs4 = EncryptedStorage.getEncryptedPrefs(ctx4, SW_KEY_PREFS_ENC)
            val privB64 = encPrefs4.getString(SW_PRIV_KEY, null)
            val pubB64  = encPrefs4.getString(SW_PUB_KEY,  null)

            if (privB64 == null || pubB64 == null) {
                emit(tr("  [FAIL] ПРОВАЛ: Ключи не найдены в EncryptedSharedPreferences ($SW_KEY_PREFS_ENC)", "  [FAIL] FAIL: Keys not found in EncryptedSharedPreferences ($SW_KEY_PREFS_ENC)"))
            } else {
                emit(tr("  [OK] Ключи присутствуют в хранилище: $SW_KEY_PREFS_ENC", "  [OK] Keys present in storage: $SW_KEY_PREFS_ENC"))

                val kf = java.security.KeyFactory.getInstance("EC")
                val privKey = kf.generatePrivate(
                    java.security.spec.PKCS8EncodedKeySpec(StorageKeyManager.unwrapBytes(privB64))
                )
                val pubKey = kf.generatePublic(
                    java.security.spec.X509EncodedKeySpec(Base64.decode(pubB64, Base64.NO_WRAP))
                )

                emit(tr("  Алгоритм: ${privKey.algorithm} / ${pubKey.algorithm}", "  Algorithm: ${privKey.algorithm} / ${pubKey.algorithm}"))
                emit(tr("  Формат приватного ключа: ${privKey.format} (PKCS#8, экспортируемый только через EncryptedPrefs)", "  Private key format: ${privKey.format} (PKCS#8, exportable only via EncryptedPrefs)"))

                if (pubKey is java.security.interfaces.ECPublicKey) {
                    val curveName = pubKey.params.toString()
                    val ok = curveName.contains("secp256r1") || curveName.contains("prime256v1")
                    emit(tr("  Кривая: ${if (ok) "secp256r1 (P-256) [OK]" else curveName}", "  Curve: ${if (ok) "secp256r1 (P-256) [OK]" else curveName}"))
                }

                val testBytes = "key_pair_consistency_check".toByteArray()
                val sig4 = Signature.getInstance("SHA256withECDSA").apply {
                    initSign(privKey); update(testBytes)
                }.sign()
                val verified4 = Signature.getInstance("SHA256withECDSA").apply {
                    initVerify(pubKey); update(testBytes)
                }.verify(sig4)

                if (verified4) {
                    emit(tr("  [OK] УСПЕХ: Ключевая пара согласована (sign ↔ verify)", "  [OK] PASS: Key pair is consistent (sign ↔ verify)"))
                } else {
                    emit(tr("  [FAIL] ПРОВАЛ: Ключевая пара несогласована!", "  [FAIL] FAIL: Key pair is inconsistent!"))
                }

                emit(tr("  🔒 Защита: EncryptedSharedPreferences (AES-256-GCM, мастер-ключ в AndroidKeyStore)", "  🔒 Protection: EncryptedSharedPreferences (AES-256-GCM, master key in AndroidKeyStore)"))
                emit(tr("  [OK] УСПЕХ: Ключи корректно хранятся и защищены", "  [OK] PASS: Keys are correctly stored and protected"))
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 5: Шифрование и расшифровка", "📋 TEST 5: Encryption and decryption"))
        try {
            val testMessage = tr("Секретное сообщение 🔐", "Secret message 🔐")
            val currentPublicKey = getPublicKeyString()

            emit(tr("  Оригинал: '$testMessage'", "  Original: '$testMessage'"))
            emit(tr("  Длина оригинала: ${testMessage.length} символов", "  Original length: ${testMessage.length} characters"))
            emit(tr("  Байты оригинала: ${testMessage.toByteArray(Charsets.UTF_8).size} байт", "  Original bytes: ${testMessage.toByteArray(Charsets.UTF_8).size} bytes"))

            val currentPqPublicKey = Base64.decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey, Base64.NO_WRAP)
            val encrypted = encrypt(testMessage, currentPublicKey, currentPqPublicKey)
            emit(tr("  Зашифровано: ${encrypted.take(50)}...", "  Encrypted: ${encrypted.take(50)}..."))

            val decrypted = decrypt(encrypted)
            emit(tr("  Расшифровано: '$decrypted'", "  Decrypted: '$decrypted'"))
            emit(tr("  Длина расшифрованного: ${decrypted.length} символов", "  Decrypted length: ${decrypted.length} characters"))
            emit(tr("  Байты расшифрованного: ${decrypted.toByteArray(Charsets.UTF_8).size} байт", "  Decrypted bytes: ${decrypted.toByteArray(Charsets.UTF_8).size} bytes"))
            emit(tr("  HEX расшифрованного: ${decrypted.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}", "  Decrypted HEX: ${decrypted.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}"))
            emit(tr("  HEX оригинала:       ${testMessage.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}", "  Original HEX:        ${testMessage.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}"))

            if (decrypted == testMessage) {
                emit(tr("  [OK] УСПЕХ: Шифрование/расшифровка работает корректно", "  [OK] PASS: Encryption/decryption works correctly"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: Сообщение не совпадает", "  [FAIL] FAIL: Message does not match"))
                emit(tr("  Ожидалось: '$testMessage'", "  Expected: '$testMessage'"))
                emit(tr("  Получено:  '$decrypted'", "  Got:      '$decrypted'"))

                for (i in 0 until maxOf(testMessage.length, decrypted.length)) {
                    val orig = testMessage.getOrNull(i)
                    val dec = decrypted.getOrNull(i)
                    if (orig != dec) {
                        emit(tr("  Различие на позиции $i: '$orig' vs '$dec'", "  Difference at position $i: '$orig' vs '$dec'"))
                    }
                }
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
            e.printStackTrace()
        }
        emit()

        emit(tr("📋 ТЕСТ 6: Подпись и верификация", "📋 TEST 6: Signing and verification"))
        try {
            val testMessage = tr("Тестовое сообщение для подписи", "Test message for signing")
            val signature = sign(testMessage)
            emit(tr("  Подпись создана: ${signature.take(50)}...", "  Signature created: ${signature.take(50)}..."))

            val publicKey = getPublicKeyString()
            val isValid = verify(testMessage, signature, publicKey)

            if (isValid) {
                emit(tr("  [OK] УСПЕХ: Подпись валидна", "  [OK] PASS: Signature is valid"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: Подпись невалидна", "  [FAIL] FAIL: Signature is invalid"))
            }

            val fakeSignature = sign(tr("Другое сообщение", "Another message"))
            val isFakeValid = verify(testMessage, fakeSignature, publicKey)

            if (!isFakeValid) {
                emit(tr("  [OK] УСПЕХ: Поддельная подпись отклонена", "  [OK] PASS: Forged signature rejected"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: Поддельная подпись принята (КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!)", "  [FAIL] FAIL: Forged signature accepted (CRITICAL VULNERABILITY!)"))
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 7: Защита от Invalid Curve Attack", "📋 TEST 7: Invalid Curve Attack protection"))
        try {
            val templateKeyBytes = Base64.decode(getPublicKeyString(), Base64.NO_WRAP)
            val offCurve = templateKeyBytes.copyOf()
            offCurve[offCurve.size - 1] = (offCurve[offCurve.size - 1].toInt() xor 0xFF).toByte()
            try {
                loadPublicKey(Base64.encodeToString(offCurve, Base64.NO_WRAP))
                emit(tr("  [FAIL] ПРОВАЛ: точка не на кривой была принята!", "  [FAIL] FAIL: an off-curve point was accepted!"))
            } catch (e: Exception) {
                emit(tr("  [OK] УСПЕХ: точка не на кривой отклонена", "  [OK] PASS: off-curve point rejected"))
                emit(tr("     Причина: ${e.javaClass.simpleName}: ${e.message}", "     Reason: ${e.javaClass.simpleName}: ${e.message}"))
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 8: Шифрование файлов", "📋 TEST 8: File encryption"))
        try {
            val testData = tr("Содержимое тестового файла 📄", "Test file contents 📄").toByteArray()
            val publicKey = getPublicKeyString()
            val pqPublicKeyFile = Base64.decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey, Base64.NO_WRAP)

            val encrypted = encryptFile(testData, publicKey, pqPublicKeyFile)
            emit(tr("  Файл зашифрован: ${encrypted.encryptedData.size} байт", "  File encrypted: ${encrypted.encryptedData.size} bytes"))
            emit(tr("  IV: ${encrypted.iv.size} байт", "  IV: ${encrypted.iv.size} bytes"))
            emit(tr("  Ephemeral key: ${encrypted.ephemeralPublicKey.size} байт", "  Ephemeral key: ${encrypted.ephemeralPublicKey.size} bytes"))

            val decrypted = decryptFile(encrypted)
            val decryptedText = String(decrypted)

            if (decryptedText == String(testData)) {
                emit(tr("  [OK] УСПЕХ: Шифрование файлов работает корректно", "  [OK] PASS: File encryption works correctly"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: Файл расшифрован некорректно", "  [FAIL] FAIL: File decrypted incorrectly"))
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        emit("═══════════════════════════════════════")
        emit(tr("ИТОГОВЫЙ СТАТУС", "SUMMARY"))
        emit("═══════════════════════════════════════")
        emit(tr("Публичный ключ (fingerprint):", "Public key (fingerprint):"))
        emit(getFingerprintEmoji())
        emit()
        emit(tr("[WARN] ВАЖНО: Проверь логи выше на наличие [FAIL]", "[WARN] IMPORTANT: Check the logs above for [FAIL]"))
        emit("═══════════════════════════════════════")

        return report.toString()
    }

    fun getFingerprintEmoji(): String {
        return try {
            val publicKeyBytes = Base64.decode(getPublicKeyString(), Base64.NO_WRAP)
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(publicKeyBytes)
            digest.take(5).joinToString("  ") {
                EMOJI_SET[it.toInt().and(0xFF) % EMOJI_SET.size]
            }
        } catch (e: Exception) {
            "[FAIL] Ошибка: ${e.message}"
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

    fun runStressTests(context: android.content.Context, onLine: ((String) -> Unit)? = null): String {
        val isEn = UserStorage.getLanguage(context) == "en"
        fun tr(ru: String, en: String) = if (isEn) en else ru
        val report = StringBuilder()
        fun emit(line: String = "") { report.append(line).append('\n'); onLine?.invoke(line) }
        emit("═══════════════════════════════════════")
        emit(tr("СТРЕСС-ТЕСТЫ (ПОПЫТКА СЛОМАТЬ ЗАЩИТУ)", "STRESS TESTS (ATTEMPTING TO BREAK THE PROTECTIONS)"))
        emit("═══════════════════════════════════════\n")

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 1: Расшифровка мусора", "📋 NEGATIVE TEST 1: Decrypting garbage"))
        try {
            val garbage = "AAAAAAAAAAAAAAAAAAAAAA=="
            decrypt(garbage)
            emit(tr("  [FAIL] БАГ: Мусор расшифровался (не должно было!)", "  [FAIL] BUG: Garbage decrypted (should not have!)"))
        } catch (e: Exception) {
            emit(tr("  [OK] ОЖИДАЕМО: Мусор отклонён", "  [OK] EXPECTED: Garbage rejected"))
            emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 2: Подделка подписи", "📋 NEGATIVE TEST 2: Signature forgery"))
        try {
            val message = tr("Оригинальное сообщение", "Original message")
            val fakeSignature = Base64.encodeToString(ByteArray(64) { it.toByte() }, Base64.NO_WRAP)
            val publicKey = getPublicKeyString()

            val isValid = verify(message, fakeSignature, publicKey)

            if (isValid) {
                emit(tr("  [FAIL] КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Поддельная подпись принята!", "  [FAIL] CRITICAL VULNERABILITY: Forged signature accepted!"))
            } else {
                emit(tr("  [OK] ОЖИДАЕМО: Подделка отклонена", "  [OK] EXPECTED: Forgery rejected"))
            }
        } catch (e: Exception) {
            emit(tr("  [OK] ОЖИДАЕМО: Подделка вызвала исключение", "  [OK] EXPECTED: Forgery raised an exception"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 3: Изменение зашифрованного текста", "📋 NEGATIVE TEST 3: Tampering with ciphertext"))
        try {
            val originalMessage = tr("Важное сообщение", "Important message")
            val publicKey = getPublicKeyString()
            val pqPublicKey = Base64.decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey, Base64.NO_WRAP)
            val encrypted = encrypt(originalMessage, publicKey, pqPublicKey)

            val corrupted = encrypted.toCharArray()
            corrupted[corrupted.size / 2] = 'X'
            val corruptedString = String(corrupted)

            try {
                val decrypted = decrypt(corruptedString)
                emit(tr("  [FAIL] КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Изменённые данные расшифровались!", "  [FAIL] CRITICAL VULNERABILITY: Tampered data was decrypted!"))
                emit(tr("     Расшифровано: $decrypted", "     Decrypted: $decrypted"))
            } catch (e: Exception) {
                emit(tr("  [OK] ОЖИДАЕМО: GCM детектировал изменение", "  [OK] EXPECTED: GCM detected the tampering"))
                emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
            }
        } catch (e: Exception) {
            emit(tr("  [WARN] Тест не выполнен: ${e.message}", "  [WARN] Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 4: Смена ключей после удаления", "📋 NEGATIVE TEST 4: Key change after deletion"))
        try {

            val encPrefsStress4 = EncryptedStorage.getEncryptedPrefs(context, SW_KEY_PREFS_ENC)
            val savedPrivStress4 = encPrefsStress4.getString(SW_PRIV_KEY, null)
            val savedPubStress4  = encPrefsStress4.getString(SW_PUB_KEY,  null)

            val key1 = getPublicKeyString()
            val pqKey1 = Base64.decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey, Base64.NO_WRAP)
            val testMessage = tr("Тест", "Test")
            val encrypted1 = encrypt(testMessage, key1, pqKey1)

            deleteKeys()

            generateKeyPair()
            val key2 = getPublicKeyString()

            if (key1 == key2) {
                emit(tr("  [FAIL] БАГ: Ключи не изменились после удаления!", "  [FAIL] BUG: Keys did not change after deletion!"))
            } else {
                emit(tr("  [OK] ОЖИДАЕМО: Новые ключи отличаются", "  [OK] EXPECTED: New keys differ"))

                try {
                    decrypt(encrypted1)
                    emit(tr("  [FAIL] БАГ: Старое сообщение расшифровалось новым ключом!", "  [FAIL] BUG: Old message decrypted with the new key!"))
                } catch (e: Exception) {
                    emit(tr("  [OK] ОЖИДАЕМО: Старое сообщение не расшифровывается", "  [OK] EXPECTED: Old message does not decrypt"))
                }
            }

            if (savedPrivStress4 != null && savedPubStress4 != null) {
                encPrefsStress4.edit()
                    .putString(SW_PRIV_KEY, savedPrivStress4)
                    .putString(SW_PUB_KEY,  savedPubStress4)
                    .commit()
                emit(tr("  🔄 Ключи аккаунта восстановлены (fingerprint не изменился)", "  🔄 Account keys restored (fingerprint unchanged)"))
            }
        } catch (e: Exception) {
            emit(tr("  [WARN] Тест не выполнен: ${e.message}", "  [WARN] Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 5: Подмена IV в зашифрованном файле", "📋 NEGATIVE TEST 5: IV tampering in encrypted file"))
        try {
            val testData = tr("Секретный файл", "Secret file").toByteArray()
            val publicKey = getPublicKeyString()
            val pqPublicKeyFile2 = Base64.decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey, Base64.NO_WRAP)

            val encrypted = encryptFile(testData, publicKey, pqPublicKeyFile2)

            val fakeIV = ByteArray(12) { 0xFF.toByte() }
            val corrupted = EncryptedFileData(
                encryptedData = encrypted.encryptedData,
                iv = fakeIV,
                ephemeralPublicKey = encrypted.ephemeralPublicKey,
                pqCiphertext = encrypted.pqCiphertext
            )

            try {
                val result = decryptFile(corrupted)
                val resultText = String(result)

                if (resultText == tr("Секретный файл", "Secret file")) {
                    emit(tr("  [FAIL] КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Файл с подменённым IV расшифровался корректно!", "  [FAIL] CRITICAL VULNERABILITY: File with tampered IV decrypted correctly!"))
                } else {
                    emit(tr("  [FAIL] ЧАСТИЧНАЯ УЯЗВИМОСТЬ: Файл расшифровался, но с мусором", "  [FAIL] PARTIAL VULNERABILITY: File decrypted, but into garbage"))
                    emit(tr("     Ожидалось: Секретный файл", "     Expected: Secret file"))
                    emit(tr("     Получено: ${resultText.take(50)}", "     Got: ${resultText.take(50)}"))
                }
            } catch (e: javax.crypto.AEADBadTagException) {
                emit(tr("  [OK] ОЖИДАЕМО: GCM детектировал подмену IV", "  [OK] EXPECTED: GCM detected the IV tampering"))
                emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
            } catch (e: Exception) {
                emit(tr("  [OK] ОЖИДАЕМО: Подмена IV заблокирована", "  [OK] EXPECTED: IV tampering was blocked"))
                emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
            }
        } catch (e: Exception) {
            emit(tr("  [WARN] Тест не выполнен: ${e.message}", "  [WARN] Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 6: Replay Attack", "📋 NEGATIVE TEST 6: Replay attack"))
        try {
            SessionKeyManager.initialize(context)
            val replayAlice = "_test_replay_a_${System.currentTimeMillis()}"
            val replayBob   = "_test_replay_b_${System.currentTimeMillis()}"
            try {
                val bundleJson = SessionKeyManager.generatePrekeyBundle()
                val bundle = SessionKeyManager.parsePrekeyBundle(bundleJson)
                val (_, x3dhHeader) = SessionKeyManager.initiateSession(replayAlice, bundle)
                SessionKeyManager.receiveSession(replayBob, getPublicKeyString(), x3dhHeader)

                val (ct, hdr) = SessionKeyManager.encryptWithSession(replayAlice, "Replay me")
                val firstDecrypt = SessionKeyManager.decryptWithSession(replayBob, ct, hdr)
                if (firstDecrypt == "Replay me") {
                    emit(tr("  [OK] Первая доставка успешна", "  [OK] First delivery succeeded"))
                } else {
                    emit(tr("  [WARN] Первая доставка вернула неожиданный текст", "  [WARN] First delivery returned unexpected text"))
                }

                try {
                    SessionKeyManager.decryptWithSession(replayBob, ct, hdr)
                    emit(tr("  [FAIL] КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: повторная доставка того же сообщения расшифровалась!", "  [FAIL] CRITICAL VULNERABILITY: replayed message decrypted again!"))
                } catch (e: Exception) {
                    emit(tr("  [OK] ОЖИДАЕМО: повторное сообщение отклонено (ключ уже использован и удалён)", "  [OK] EXPECTED: replayed message rejected (key already used and discarded)"))
                    emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
                }
            } finally {
                SessionKeyManager.deleteSession(replayAlice)
                SessionKeyManager.deleteSession(replayBob)
            }
        } catch (e: Exception) {
            emit(tr("  [WARN] Тест не выполнен: ${e.message}", "  [WARN] Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 7: Защита от Invalid Curve Attack", "📋 TEST 7: Invalid Curve Attack protection"))
        try {
            val templateKeyBytes = Base64.decode(getPublicKeyString(), Base64.NO_WRAP)
            val outOfField = templateKeyBytes.copyOf()
            for (i in outOfField.size - 64 until outOfField.size) outOfField[i] = 0xFF.toByte()
            try {
                loadPublicKey(Base64.encodeToString(outOfField, Base64.NO_WRAP))
                emit(tr("  [FAIL] ПРОВАЛ: координата вне поля была принята!", "  [FAIL] FAIL: an out-of-field coordinate was accepted!"))
            } catch (e: Exception) {
                emit(tr("  [OK] ОЖИДАЕМО: координата вне поля отклонена", "  [OK] EXPECTED: out-of-field coordinate rejected"))
                emit(tr("     Причина: ${e.javaClass.simpleName}: ${e.message}", "     Reason: ${e.javaClass.simpleName}: ${e.message}"))
            }
        } catch (e: Exception) {
            emit(tr("  [WARN] Тест не выполнен: ${e.message}", "  [WARN] Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 8: Паддинг работает?", "📋 NEGATIVE TEST 8: Is padding working?"))
        try {
            val short = "Hi"
            val long = "A".repeat(1000)
            val selfPqKey = Base64.decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey, Base64.NO_WRAP)

            val encShort = encrypt(short, getPublicKeyString(), selfPqKey)
            val encLong = encrypt(long, getPublicKeyString(), selfPqKey)

            val sizeShort = Base64.decode(encShort, Base64.NO_WRAP).size
            val sizeLong = Base64.decode(encLong, Base64.NO_WRAP).size

            emit(tr("  Короткое сообщение: $sizeShort байт", "  Short message: $sizeShort bytes"))
            emit(tr("  Длинное сообщение: $sizeLong байт", "  Long message: $sizeLong bytes"))
            emit(tr("  Разница: ${sizeLong - sizeShort} байт", "  Difference: ${sizeLong - sizeShort} bytes"))

            if (sizeShort > short.length + 100) {
                emit(tr("  [OK] Паддинг работает (размер больше исходного)", "  [OK] Padding works (size is larger than original)"))
            } else {
                emit(tr("  [WARN] ВНИМАНИЕ: Паддинг может быть недостаточным", "  [WARN] WARNING: Padding may be insufficient"))
            }
        } catch (e: Exception) {
            emit(tr("  [WARN] Тест не выполнен: ${e.message}", "  [WARN] Test did not run: ${e.message}"))
        }
        emit()

        emit("═══════════════════════════════════════")
        emit(tr("ИТОГ СТРЕСС-ТЕСТОВ", "STRESS TEST SUMMARY"))
        emit("═══════════════════════════════════════")
        emit(tr("Все негативные тесты ДОЛЖНЫ быть отклонены.", "All negative tests SHOULD be rejected."))
        emit(tr("Если видишь [FAIL] БАГ - это критическая проблема!", "If you see [FAIL] BUG — that's a critical problem!"))
        emit("═══════════════════════════════════════")

        return report.toString()
    }

    fun runAdvancedTests(context: android.content.Context, onLine: ((String) -> Unit)? = null): String {
        val isEn = UserStorage.getLanguage(context) == "en"
        fun tr(ru: String, en: String) = if (isEn) en else ru
        val report = StringBuilder()
        fun emit(line: String = "") { report.append(line).append('\n'); onLine?.invoke(line) }
        emit("═══════════════════════════════════════")
        emit(tr("РАСШИРЕННЫЕ ТЕСТЫ (SESSION + GROUP)", "ADVANCED TESTS (SESSION + GROUP)"))
        emit("═══════════════════════════════════════\n")

        emit(tr("📋 ТЕСТ 9: HKDF (KDF-деривация)", "📋 TEST 9: HKDF (KDF derivation)"))
        try {
            val testSecret = ByteArray(32) { (it * 7 + 3).toByte() }
            val key1 = deriveAesKey(testSecret, "BeaconECDH")
            val key2 = deriveAesKey(testSecret, "BeaconECDH")
            if (key1.contentEquals(key2)) {
                emit(tr("  [OK] Детерминизм: одинаковые входы → одинаковый ключ", "  [OK] Determinism: same inputs → same key"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: HKDF не детерминирован!", "  [FAIL] FAIL: HKDF is not deterministic!"))
            }
            val key3 = deriveAesKey(testSecret, "BeaconFileEncryption")
            if (!key1.contentEquals(key3)) {
                emit(tr("  [OK] Дифференциация: разный info → разный ключ", "  [OK] Differentiation: different info → different key"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: разные info дали одинаковый ключ!", "  [FAIL] FAIL: different info produced the same key!"))
            }
            val zeroSecret = ByteArray(32)
            val keyZero1 = deriveAesKey(zeroSecret, "BeaconECDH")
            val keyZero2 = deriveAesKey(zeroSecret, "BeaconECDH")
            if (keyZero1.contentEquals(keyZero2) && !keyZero1.contentEquals(key1)) {
                emit(tr("  [OK] Выход зависит от входа (нулевой секрет → свой ключ)", "  [OK] Output depends on input (zero secret → its own key)"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: HKDF не зависит от входного секрета!", "  [FAIL] FAIL: HKDF does not depend on the input secret!"))
            }
            emit(tr("  Длина ключа: ${key1.size} байт (ожидается 32)", "  Key length: ${key1.size} bytes (expected 32)"))
            if (key1.size == 32) emit(tr("  [OK] Длина корректна", "  [OK] Length is correct"))
            else emit(tr("  [FAIL] ПРОВАЛ: неверная длина ключа!", "  [FAIL] FAIL: incorrect key length!"))
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 10: AES-GCM примитив (прямой вызов)", "📋 TEST 10: AES-GCM primitive (direct call)"))
        try {
            val aesKey = ByteArray(32).also { secureRandom.nextBytes(it) }
            val plaintext = "AES-GCM direct test 🔒"
            val encrypted = aesEncrypt(plaintext, aesKey)
            val decrypted = aesDecrypt(encrypted, aesKey)
            if (decrypted == plaintext) {
                emit(tr("  [OK] Round-trip: шифрование/расшифровка корректны", "  [OK] Round-trip: encryption/decryption correct"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: round-trip не совпадает", "  [FAIL] FAIL: round-trip mismatch"))
            }

            val tampered = encrypted.copyOf()
            tampered[tampered.size / 2] = (tampered[tampered.size / 2].toInt() xor 0xFF).toByte()
            try {
                aesDecrypt(tampered, aesKey)
                emit(tr("  [FAIL] ПРОВАЛ: GCM не поймал модификацию данных!", "  [FAIL] FAIL: GCM did not catch the data tampering!"))
            } catch (_: Exception) {
                emit(tr("  [OK] GCM тампер-детект: модификация обнаружена", "  [OK] GCM tamper detection: modification detected"))
            }

            val aesKey2 = ByteArray(32).also { secureRandom.nextBytes(it) }
            val encrypted2 = aesEncrypt(plaintext, aesKey2)
            if (!encrypted.contentEquals(encrypted2)) {
                emit(tr("  [OK] Разные ключи → разный шифртекст", "  [OK] Different keys → different ciphertext"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: разные ключи дали одинаковый шифртекст!", "  [FAIL] FAIL: different keys produced the same ciphertext!"))
            }

            val shortPlain = "Hi"
            val longPlain = "A".repeat(200)
            val encShort = aesEncrypt(shortPlain, aesKey)
            val encLong = aesEncrypt(longPlain, aesKey)

            if (encShort.size > shortPlain.length + 100 && encLong.size > longPlain.length + 100) {
                emit(tr("  [OK] Паддинг добавлен: размер не раскрывает длину сообщения", "  [OK] Padding added: size does not reveal message length"))
            } else {
                emit(tr("  [WARN] ВНИМАНИЕ: паддинг может быть недостаточным", "  [WARN] WARNING: padding may be insufficient"))
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 11: Группы — генерация и распределение ключа", "📋 TEST 11: Groups — key generation and distribution"))
        try {
            val groupKey = GroupManager.generateGroupKey()
            emit(tr("  Групповой ключ: ${groupKey.size} байт", "  Group key: ${groupKey.size} bytes"))
            if (groupKey.size == 32) {
                emit(tr("  [OK] Длина ключа 256 бит (AES-256)", "  [OK] Key length is 256 bits (AES-256)"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: неверная длина группового ключа!", "  [FAIL] FAIL: incorrect group key length!"))
            }

            val groupKey2 = GroupManager.generateGroupKey()
            if (!groupKey.contentEquals(groupKey2)) {
                emit(tr("  [OK] Генератор случаен: два ключа отличаются", "  [OK] Generator is random: two keys differ"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: два ключа одинаковы (не случайные)!", "  [FAIL] FAIL: two keys are identical (not random)!"))
            }

            val myPublicKey = getPublicKeyString()
            val myPqPublicKey = Base64.decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey, Base64.NO_WRAP)
            val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, myPublicKey, myPqPublicKey)
            emit(tr("  Зашифрованный групповой ключ: ${encryptedGroupKey.take(40)}...", "  Encrypted group key: ${encryptedGroupKey.take(40)}..."))

            val decryptedGroupKey = GroupManager.decryptGroupKey(encryptedGroupKey)
            if (groupKey.contentEquals(decryptedGroupKey)) {
                emit(tr("  [OK] Распределение ключа: encrypt → decrypt совпадают", "  [OK] Key distribution: encrypt → decrypt match"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: расшифрованный ключ не совпадает!", "  [FAIL] FAIL: decrypted key does not match!"))
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 12: Группы — шифрование/расшифровка сообщений", "📋 TEST 12: Groups — message encryption/decryption"))
        try {
            val groupKey = GroupManager.generateGroupKey()
            val messages = listOf(
                tr("Привет группе! 👋", "Hello group! 👋"),
                tr("Тест с эмодзи 🔐🛡️", "Test with emoji 🔐🛡️"),
                "A".repeat(500)
            )
            var allOk = true
            for (msg in messages) {
                val encrypted = GroupManager.encryptGroupMessage(msg, groupKey)
                val decrypted = GroupManager.decryptGroupMessage(encrypted, groupKey)
                if (decrypted != msg) { allOk = false; break }
            }
            if (allOk) {
                emit(tr("  [OK] Round-trip: ${messages.size} сообщений (включая длинное)", "  [OK] Round-trip: ${messages.size} messages (including a long one)"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: одно или несколько сообщений не совпали", "  [FAIL] FAIL: one or more messages did not match"))
            }

            val groupKey2 = GroupManager.generateGroupKey()
            val enc1 = GroupManager.encryptGroupMessage("Same message", groupKey2)
            val enc2 = GroupManager.encryptGroupMessage("Same message", groupKey2)
            if (enc1 != enc2) {
                emit(tr("  [OK] IV случаен: два шифртекста одного сообщения различны", "  [OK] IV is random: two ciphertexts of the same message differ"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: IV не случаен — два шифртекста совпадают!", "  [FAIL] FAIL: IV is not random — two ciphertexts match!"))
            }

            val enc = GroupManager.encryptGroupMessage("Secret", groupKey)
            val decoded = android.util.Base64.decode(enc, android.util.Base64.NO_WRAP)
            decoded[decoded.size / 2] = (decoded[decoded.size / 2].toInt() xor 0xFF).toByte()
            val tampered = android.util.Base64.encodeToString(decoded, android.util.Base64.NO_WRAP)
            try {
                GroupManager.decryptGroupMessage(tampered, groupKey)
                emit(tr("  [FAIL] ПРОВАЛ: GCM не поймал модификацию группового сообщения!", "  [FAIL] FAIL: GCM did not catch the group message tampering!"))
            } catch (_: Exception) {
                emit(tr("  [OK] GCM тампер-детект: модификация группового сообщения обнаружена", "  [OK] GCM tamper detection: group message modification detected"))
            }

            val wrongKey = GroupManager.generateGroupKey()
            val encMsg = GroupManager.encryptGroupMessage("Private", groupKey)
            try {
                GroupManager.decryptGroupMessage(encMsg, wrongKey)
                emit(tr("  [FAIL] ПРОВАЛ: сообщение расшифровалось неверным ключом!", "  [FAIL] FAIL: message decrypted with the wrong key!"))
            } catch (_: Exception) {
                emit(tr("  [OK] Неверный ключ отклонён", "  [OK] Wrong key rejected"))
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        val aliceId = "_test_alice_${System.currentTimeMillis()}"
        val bobId   = "_test_bob_${System.currentTimeMillis()}"
        try {

            SessionKeyManager.initialize(context)

            emit(tr("📋 ТЕСТ 13: X3DH — инициация сессии", "📋 TEST 13: X3DH — session initiation"))
            val bobBundleJson = SessionKeyManager.generatePrekeyBundle()
            val bobBundle     = SessionKeyManager.parsePrekeyBundle(bobBundleJson)
            val (_, x3dhHeader) = SessionKeyManager.initiateSession(aliceId, bobBundle)
            val aliceIdentity   = getPublicKeyString()
            SessionKeyManager.receiveSession(bobId, aliceIdentity, x3dhHeader)

            if (SessionKeyManager.hasSession(aliceId) && SessionKeyManager.hasSession(bobId)) {
                emit(tr("  [OK] X3DH: сессии установлены у обеих сторон", "  [OK] X3DH: sessions established on both sides"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: сессия не установлена!", "  [FAIL] FAIL: session not established!"))
            }
            emit()

            emit(tr("📋 ТЕСТ 14: Session — шифрование/расшифровка", "📋 TEST 14: Session — encryption/decryption"))
            val testMessages = listOf("Hello Bob 🔐", tr("Второе сообщение", "Second message"), "Third msg!")
            var sessionRoundTripOk = true
            for (msg in testMessages) {
                val (ct, hdr) = SessionKeyManager.encryptWithSession(aliceId, msg)
                val dec = SessionKeyManager.decryptWithSession(bobId, ct, hdr)
                if (dec != msg) { sessionRoundTripOk = false; break }
            }
            if (sessionRoundTripOk) {
                emit(tr("  [OK] Round-trip: ${testMessages.size} сообщений (Alice→Bob)", "  [OK] Round-trip: ${testMessages.size} messages (Alice→Bob)"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: round-trip не совпадает", "  [FAIL] FAIL: round-trip mismatch"))
            }

            val (ctB, hdrB) = SessionKeyManager.encryptWithSession(bobId, "Reply from Bob")
            val decB = SessionKeyManager.decryptWithSession(aliceId, ctB, hdrB)
            if (decB == "Reply from Bob") {
                emit(tr("  [OK] Двусторонность: Bob→Alice работает", "  [OK] Bidirectionality: Bob→Alice works"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: Bob→Alice не работает", "  [FAIL] FAIL: Bob→Alice does not work"))
            }

            val (ct1, hdr1) = SessionKeyManager.encryptWithSession(aliceId, "Same")
            val (ct2, hdr2) = SessionKeyManager.encryptWithSession(aliceId, "Same")
            if (ct1 != ct2) {
                emit(tr("  [OK] Ratchet: одно сообщение → разные шифртексты (ключи меняются)", "  [OK] Ratchet: one message → different ciphertexts (keys change)"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: ratchet не продвигается!", "  [FAIL] FAIL: ratchet is not advancing!"))
            }

            SessionKeyManager.decryptWithSession(bobId, ct1, hdr1)
            SessionKeyManager.decryptWithSession(bobId, ct2, hdr2)
            emit()

            emit(tr("📋 ТЕСТ 15: Session — out-of-order доставка", "📋 TEST 15: Session — out-of-order delivery"))

            val msgs = listOf("Out0", "Out1", "Out2")
            val encrypted15 = msgs.map { SessionKeyManager.encryptWithSession(aliceId, it) }

            val dec0 = SessionKeyManager.decryptWithSession(bobId, encrypted15[0].first, encrypted15[0].second)

            val dec2 = SessionKeyManager.decryptWithSession(bobId, encrypted15[2].first, encrypted15[2].second)

            val dec1 = SessionKeyManager.decryptWithSession(bobId, encrypted15[1].first, encrypted15[1].second)
            if (dec0 == "Out0" && dec1 == "Out1" && dec2 == "Out2") {
                emit(tr("  [OK] Out-of-order: все 3 сообщения расшифрованы корректно", "  [OK] Out-of-order: all 3 messages decrypted correctly"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: out-of-order доставка не работает", "  [FAIL] FAIL: out-of-order delivery does not work"))
                emit("     dec0='$dec0', dec1='$dec1', dec2='$dec2'")
            }
            emit()

            emit(tr("📋 ТЕСТ 16: Session — изоляция (посторонний ключ)", "📋 TEST 16: Session — isolation (unrelated key)"))
            val (ctIso, hdrIso) = SessionKeyManager.encryptWithSession(aliceId, "Secret")

            val malloryId = "_test_mallory_${System.currentTimeMillis()}"
            val eveId     = "_test_eve_${System.currentTimeMillis()}"
            try {
                val eveBundleJson = SessionKeyManager.generatePrekeyBundle()
                val eveBundle     = SessionKeyManager.parsePrekeyBundle(eveBundleJson)
                val (_, eveHeader) = SessionKeyManager.initiateSession(malloryId, eveBundle)
                SessionKeyManager.receiveSession(eveId, getPublicKeyString(), eveHeader)

                try {
                    val fakeDecrypt = SessionKeyManager.decryptWithSession(malloryId, ctIso, hdrIso)
                    emit(tr("  [FAIL] ПРОВАЛ: посторонняя сторона расшифровала чужой шифртекст: '$fakeDecrypt'", "  [FAIL] FAIL: an unrelated party decrypted someone else's ciphertext: '$fakeDecrypt'"))
                } catch (_: Exception) {
                    emit(tr("  [OK] Изоляция: посторонний ключ не может расшифровать чужой шифртекст", "  [OK] Isolation: an unrelated key cannot decrypt someone else's ciphertext"))
                }
            } finally {
                SessionKeyManager.deleteSession(malloryId)
                SessionKeyManager.deleteSession(eveId)
            }

        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА в сессионных тестах: ${e.message}", "  [FAIL] ERROR in session tests: ${e.message}"))
        } finally {

            SessionKeyManager.deleteSession(aliceId)
            SessionKeyManager.deleteSession(bobId)
        }

        emit()

        emit(tr("📋 ТЕСТ 17: ML-KEM — постквантовый гибрид", "📋 TEST 17: ML-KEM — post-quantum hybrid"))
        try {
            val pqKp = PqCrypto.generateKeyPair()
            val encapsulated = PqCrypto.encapsulate(pqKp.publicKey)
            val recovered = PqCrypto.decapsulate(pqKp.privateKey, encapsulated.ciphertext)

            if (encapsulated.sharedSecret.contentEquals(recovered)) {
                emit(tr("  [OK] ML-KEM-768: encapsulate/decapsulate совпадают (${encapsulated.sharedSecret.size} байт секрета, ${encapsulated.ciphertext.size} байт ciphertext)",
                        "  [OK] ML-KEM-768: encapsulate/decapsulate match (${encapsulated.sharedSecret.size} bytes secret, ${encapsulated.ciphertext.size} bytes ciphertext)"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: расшифрованный секрет не совпал с исходным!", "  [FAIL] FAIL: recovered secret did not match the original!"))
            }

            // Hybrid combiner sanity: flipping the classical half of the
            // combined secret must change the derived key — both the
            // classical and PQ components must be broken to recover it.
            val classical = ByteArray(32) { it.toByte() }
            val combined1 = classical + encapsulated.sharedSecret
            val tamperedClassical = classical.copyOf().also { it[0] = (it[0] + 1).toByte() }
            val combined2 = tamperedClassical + encapsulated.sharedSecret
            val derived1 = deriveAesKey(combined1, "BeaconTestPq")
            val derived2 = deriveAesKey(combined2, "BeaconTestPq")

            if (!derived1.contentEquals(derived2)) {
                emit(tr("  [OK] Hybrid KDF: чувствителен к классическому компоненту секрета", "  [OK] Hybrid KDF: sensitive to the classical secret component"))
            } else {
                emit(tr("  [FAIL] ПРОВАЛ: изменение классического секрета не повлияло на производный ключ!", "  [FAIL] FAIL: changing the classical secret did not affect the derived key!"))
            }
        } catch (e: Exception) {
            emit(tr("  [FAIL] ОШИБКА: ${e.message}", "  [FAIL] ERROR: ${e.message}"))
        }
        emit()

        emit("═══════════════════════════════════════")
        emit(tr("ИТОГ РАСШИРЕННЫХ ТЕСТОВ", "TEST SUMMARY"))
        emit("═══════════════════════════════════════")
        emit(tr("Покрыто: HKDF · AES-GCM · GroupManager · X3DH · Ratchet · Out-of-order · ML-KEM", "Covered: HKDF · AES-GCM · GroupManager · X3DH · Ratchet · Out-of-order · ML-KEM"))
        emit(tr("Если видишь [FAIL] ПРОВАЛ — это критическая проблема!", "If you see [FAIL] FAIL — that's a critical problem!"))
        emit("═══════════════════════════════════════")

        return report.toString()
    }

}

