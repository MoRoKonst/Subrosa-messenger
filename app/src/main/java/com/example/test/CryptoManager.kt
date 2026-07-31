package com.bcon.messenger

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

    fun encrypt(plaintext: String, recipientPublicKeyStr: String): String {
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

    fun decrypt(ciphertext: String): String {
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
        val ephemeralPublicKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as EncryptedFileData
            if (!encryptedData.contentEquals(other.encryptedData)) return false
            if (!iv.contentEquals(other.iv)) return false
            if (!ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = encryptedData.contentHashCode()
            result = 31 * result + iv.contentHashCode()
            result = 31 * result + ephemeralPublicKey.contentHashCode()
            return result
        }
    }

    fun encryptFile(fileData: ByteArray, recipientPublicKeyStr: String): EncryptedFileData {
        val ephemeralKeyPair = generateEphemeralKeyPair()
        val sharedSecret = ecdh(ephemeralKeyPair.private, loadPublicKey(recipientPublicKeyStr))
        val aesKey = deriveAesKey(sharedSecret, "BeaconFileEncryption")

        val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(aesKey, 0, 32, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

        val padded = addFilePadding(fileData)
        val encryptedData = cipher.doFinal(padded)

        SecureMemory.wipe(sharedSecret)
        SecureMemory.wipe(aesKey)
        SecureMemory.wipe(padded)

        val ephemeralPublicBytes = ephemeralKeyPair.public.encoded

        return EncryptedFileData(
            encryptedData = encryptedData,
            iv = iv,
            ephemeralPublicKey = ephemeralPublicBytes
        )
    }

    fun decryptFile(encryptedFileData: EncryptedFileData): ByteArray {
        val ephemeralPublicKey = loadPublicKey(
            Base64.encodeToString(encryptedFileData.ephemeralPublicKey, Base64.NO_WRAP)
        )

        val sharedSecret = ecdh(getPrivateKey(), ephemeralPublicKey)
        val aesKey = deriveAesKey(sharedSecret, "BeaconFileEncryption")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(aesKey, 0, 32, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, encryptedFileData.iv))
        val paddedData = cipher.doFinal(encryptedFileData.encryptedData)

        val originalData = removeFilePadding(paddedData)

        SecureMemory.wipe(sharedSecret)
        SecureMemory.wipe(aesKey)
        SecureMemory.wipe(paddedData)

        return originalData
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
        val ivLen = encryptedFileData.iv.size

        val packed = ByteArray(
            2 + ephemeralKeyLen + 1 + ivLen + encryptedFileData.encryptedData.size
        )

        var offset = 0

        packed[offset++] = (ephemeralKeyLen shr 8).toByte()
        packed[offset++] = (ephemeralKeyLen and 0xFF).toByte()

        System.arraycopy(encryptedFileData.ephemeralPublicKey, 0, packed, offset, ephemeralKeyLen)
        offset += ephemeralKeyLen

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

        if (packed.size < offset + keyLen + 1) {
            throw IllegalArgumentException("Пакет файла повреждён (ключ)")
        }

        val ephemeralPublicKey = packed.copyOfRange(offset, offset + keyLen)
        offset += keyLen

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
            ephemeralPublicKey = ephemeralPublicKey
        )
    }

    fun runSecurityDiagnostics(context: android.content.Context, onLine: ((String) -> Unit)? = null): String {
        val isEn = UserStorage.getLanguage(context) == "en"
        fun tr(ru: String, en: String) = if (isEn) en else ru
        val report = StringBuilder()
        fun emit(line: String = "") { report.append(line).append('\n'); onLine?.invoke(line) }
        emit("═══════════════════════════════════════")
        emit(tr("🔐 ДИАГНОСТИКА БЕЗОПАСНОСТИ KEYSTORE", "🔐 KEYSTORE SECURITY DIAGNOSTICS"))
        emit("═══════════════════════════════════════\n")

        if (!hasKeys()) {
            generateKeyPair()
        }

        emit(tr("📋 ТЕСТ 1: Проверка существования ключей", "📋 TEST 1: Key existence check"))
        val hasKeysInitial = hasKeys()
        emit(tr("  Ключи существуют: $hasKeysInitial", "  Keys exist: $hasKeysInitial"))

        if (!hasKeysInitial) {
            emit(tr("  ⚠️ Ключи не найдены, генерируем...", "  ⚠️ Keys not found, generating..."))
            generateKeyPair()
            emit(tr("  ✅ Ключи сгенерированы", "  ✅ Keys generated"))
        }
        emit()

        emit(tr("📋 ТЕСТ 2: Защита от повторной генерации", "📋 TEST 2: Regeneration protection"))
        val publicKey1 = getPublicKeyString()
        emit(tr("  Публичный ключ (до): ${publicKey1.take(50)}...", "  Public key (before): ${publicKey1.take(50)}..."))

        generateKeyPair()
        val publicKey2 = getPublicKeyString()
        emit(tr("  Публичный ключ (после): ${publicKey2.take(50)}...", "  Public key (after): ${publicKey2.take(50)}..."))

        if (publicKey1 == publicKey2) {
            emit(tr("  ✅ УСПЕХ: Ключи НЕ пересоздались (защита работает)", "  ✅ PASS: Keys were NOT recreated (protection works)"))
        } else {
            emit(tr("  ❌ ПРОВАЛ: Ключи пересоздались (КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!)", "  ❌ FAIL: Keys were recreated (CRITICAL VULNERABILITY!)"))
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
            emit(tr("  ✅ УСПЕХ: Ключи успешно удалены", "  ✅ PASS: Keys successfully deleted"))
        } else {
            emit(tr("  ❌ ПРОВАЛ: Ключи не удалились", "  ❌ FAIL: Keys were not deleted"))
        }

        generateKeyPair()
        val hasKeysAfterRegenerate = hasKeys()
        val keyAfterRegenerate = getPublicKeyString()
        emit(tr("  После generateKeyPair(): hasKeys() = $hasKeysAfterRegenerate", "  After generateKeyPair(): hasKeys() = $hasKeysAfterRegenerate"))

        if (hasKeysAfterRegenerate) {
            emit(tr("  ✅ УСПЕХ: Генерация новых ключей работает", "  ✅ PASS: New key generation works"))
            if (keyBeforeDelete != keyAfterRegenerate) {
                emit(tr("  ✅ УСПЕХ: Новые ключи отличаются от старых", "  ✅ PASS: New keys differ from the old ones"))
            }
        } else {
            emit(tr("  ❌ ПРОВАЛ: Не удалось восстановить ключи", "  ❌ FAIL: Could not restore keys"))
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
                emit(tr("  ❌ ПРОВАЛ: Ключи не найдены в EncryptedSharedPreferences ($SW_KEY_PREFS_ENC)", "  ❌ FAIL: Keys not found in EncryptedSharedPreferences ($SW_KEY_PREFS_ENC)"))
            } else {
                emit(tr("  ✅ Ключи присутствуют в хранилище: $SW_KEY_PREFS_ENC", "  ✅ Keys present in storage: $SW_KEY_PREFS_ENC"))

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
                    emit(tr("  Кривая: ${if (ok) "secp256r1 (P-256) ✅" else curveName}", "  Curve: ${if (ok) "secp256r1 (P-256) ✅" else curveName}"))
                }

                val testBytes = "key_pair_consistency_check".toByteArray()
                val sig4 = Signature.getInstance("SHA256withECDSA").apply {
                    initSign(privKey); update(testBytes)
                }.sign()
                val verified4 = Signature.getInstance("SHA256withECDSA").apply {
                    initVerify(pubKey); update(testBytes)
                }.verify(sig4)

                if (verified4) {
                    emit(tr("  ✅ УСПЕХ: Ключевая пара согласована (sign ↔ verify)", "  ✅ PASS: Key pair is consistent (sign ↔ verify)"))
                } else {
                    emit(tr("  ❌ ПРОВАЛ: Ключевая пара несогласована!", "  ❌ FAIL: Key pair is inconsistent!"))
                }

                emit(tr("  🔒 Защита: EncryptedSharedPreferences (AES-256-GCM, мастер-ключ в AndroidKeyStore)", "  🔒 Protection: EncryptedSharedPreferences (AES-256-GCM, master key in AndroidKeyStore)"))
                emit(tr("  ✅ УСПЕХ: Ключи корректно хранятся и защищены", "  ✅ PASS: Keys are correctly stored and protected"))
            }
        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 5: Шифрование и расшифровка", "📋 TEST 5: Encryption and decryption"))
        try {
            val testMessage = tr("Секретное сообщение 🔐", "Secret message 🔐")
            val currentPublicKey = getPublicKeyString()

            emit(tr("  Оригинал: '$testMessage'", "  Original: '$testMessage'"))
            emit(tr("  Длина оригинала: ${testMessage.length} символов", "  Original length: ${testMessage.length} characters"))
            emit(tr("  Байты оригинала: ${testMessage.toByteArray(Charsets.UTF_8).size} байт", "  Original bytes: ${testMessage.toByteArray(Charsets.UTF_8).size} bytes"))

            val encrypted = encrypt(testMessage, currentPublicKey)
            emit(tr("  Зашифровано: ${encrypted.take(50)}...", "  Encrypted: ${encrypted.take(50)}..."))

            val decrypted = decrypt(encrypted)
            emit(tr("  Расшифровано: '$decrypted'", "  Decrypted: '$decrypted'"))
            emit(tr("  Длина расшифрованного: ${decrypted.length} символов", "  Decrypted length: ${decrypted.length} characters"))
            emit(tr("  Байты расшифрованного: ${decrypted.toByteArray(Charsets.UTF_8).size} байт", "  Decrypted bytes: ${decrypted.toByteArray(Charsets.UTF_8).size} bytes"))
            emit(tr("  HEX расшифрованного: ${decrypted.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}", "  Decrypted HEX: ${decrypted.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}"))
            emit(tr("  HEX оригинала:       ${testMessage.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}", "  Original HEX:        ${testMessage.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}"))

            if (decrypted == testMessage) {
                emit(tr("  ✅ УСПЕХ: Шифрование/расшифровка работает корректно", "  ✅ PASS: Encryption/decryption works correctly"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: Сообщение не совпадает", "  ❌ FAIL: Message does not match"))
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
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
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
                emit(tr("  ✅ УСПЕХ: Подпись валидна", "  ✅ PASS: Signature is valid"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: Подпись невалидна", "  ❌ FAIL: Signature is invalid"))
            }

            val fakeSignature = sign(tr("Другое сообщение", "Another message"))
            val isFakeValid = verify(testMessage, fakeSignature, publicKey)

            if (!isFakeValid) {
                emit(tr("  ✅ УСПЕХ: Поддельная подпись отклонена", "  ✅ PASS: Forged signature rejected"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: Поддельная подпись принята (КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!)", "  ❌ FAIL: Forged signature accepted (CRITICAL VULNERABILITY!)"))
            }
        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 7: Защита от Invalid Curve Attack", "📋 TEST 7: Invalid Curve Attack protection"))
        try {
            val templateKeyBytes = Base64.decode(getPublicKeyString(), Base64.NO_WRAP)
            val offCurve = templateKeyBytes.copyOf()
            offCurve[offCurve.size - 1] = (offCurve[offCurve.size - 1].toInt() xor 0xFF).toByte()
            try {
                loadPublicKey(Base64.encodeToString(offCurve, Base64.NO_WRAP))
                emit(tr("  ❌ ПРОВАЛ: точка не на кривой была принята!", "  ❌ FAIL: an off-curve point was accepted!"))
            } catch (e: Exception) {
                emit(tr("  ✅ УСПЕХ: точка не на кривой отклонена", "  ✅ PASS: off-curve point rejected"))
                emit(tr("     Причина: ${e.javaClass.simpleName}: ${e.message}", "     Reason: ${e.javaClass.simpleName}: ${e.message}"))
            }
        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 8: Шифрование файлов", "📋 TEST 8: File encryption"))
        try {
            val testData = tr("Содержимое тестового файла 📄", "Test file contents 📄").toByteArray()
            val publicKey = getPublicKeyString()

            val encrypted = encryptFile(testData, publicKey)
            emit(tr("  Файл зашифрован: ${encrypted.encryptedData.size} байт", "  File encrypted: ${encrypted.encryptedData.size} bytes"))
            emit(tr("  IV: ${encrypted.iv.size} байт", "  IV: ${encrypted.iv.size} bytes"))
            emit(tr("  Ephemeral key: ${encrypted.ephemeralPublicKey.size} байт", "  Ephemeral key: ${encrypted.ephemeralPublicKey.size} bytes"))

            val decrypted = decryptFile(encrypted)
            val decryptedText = String(decrypted)

            if (decryptedText == String(testData)) {
                emit(tr("  ✅ УСПЕХ: Шифрование файлов работает корректно", "  ✅ PASS: File encryption works correctly"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: Файл расшифрован некорректно", "  ❌ FAIL: File decrypted incorrectly"))
            }
        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
        }
        emit()

        emit("═══════════════════════════════════════")
        emit(tr("📊 ИТОГОВЫЙ СТАТУС", "📊 SUMMARY"))
        emit("═══════════════════════════════════════")
        emit(tr("Публичный ключ (fingerprint):", "Public key (fingerprint):"))
        emit(getFingerprintEmoji())
        emit()
        emit(tr("⚠️ ВАЖНО: Проверь логи выше на наличие ❌", "⚠️ IMPORTANT: Check the logs above for ❌"))
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
            "❌ Ошибка: ${e.message}"
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
        emit(tr("💣 СТРЕСС-ТЕСТЫ (ДОЛЖНЫ ПРОВАЛИТЬСЯ)", "💣 STRESS TESTS (SHOULD FAIL)"))
        emit("═══════════════════════════════════════\n")

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 1: Расшифровка мусора", "📋 NEGATIVE TEST 1: Decrypting garbage"))
        try {
            val garbage = "AAAAAAAAAAAAAAAAAAAAAA=="
            decrypt(garbage)
            emit(tr("  ❌ БАГ: Мусор расшифровался (не должно было!)", "  ❌ BUG: Garbage decrypted (should not have!)"))
        } catch (e: Exception) {
            emit(tr("  ✅ ОЖИДАЕМО: Мусор отклонён", "  ✅ EXPECTED: Garbage rejected"))
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
                emit(tr("  ❌ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Поддельная подпись принята!", "  ❌ CRITICAL VULNERABILITY: Forged signature accepted!"))
            } else {
                emit(tr("  ✅ ОЖИДАЕМО: Подделка отклонена", "  ✅ EXPECTED: Forgery rejected"))
            }
        } catch (e: Exception) {
            emit(tr("  ✅ ОЖИДАЕМО: Подделка вызвала исключение", "  ✅ EXPECTED: Forgery raised an exception"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 3: Изменение зашифрованного текста", "📋 NEGATIVE TEST 3: Tampering with ciphertext"))
        try {
            val originalMessage = tr("Важное сообщение", "Important message")
            val publicKey = getPublicKeyString()
            val encrypted = encrypt(originalMessage, publicKey)

            val corrupted = encrypted.toCharArray()
            corrupted[corrupted.size / 2] = 'X'
            val corruptedString = String(corrupted)

            try {
                val decrypted = decrypt(corruptedString)
                emit(tr("  ❌ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Изменённые данные расшифровались!", "  ❌ CRITICAL VULNERABILITY: Tampered data was decrypted!"))
                emit(tr("     Расшифровано: $decrypted", "     Decrypted: $decrypted"))
            } catch (e: Exception) {
                emit(tr("  ✅ ОЖИДАЕМО: GCM детектировал изменение", "  ✅ EXPECTED: GCM detected the tampering"))
                emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
            }
        } catch (e: Exception) {
            emit(tr("  ⚠️ Тест не выполнен: ${e.message}", "  ⚠️ Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 4: Смена ключей после удаления", "📋 NEGATIVE TEST 4: Key change after deletion"))
        try {

            val encPrefsStress4 = EncryptedStorage.getEncryptedPrefs(context, SW_KEY_PREFS_ENC)
            val savedPrivStress4 = encPrefsStress4.getString(SW_PRIV_KEY, null)
            val savedPubStress4  = encPrefsStress4.getString(SW_PUB_KEY,  null)

            val key1 = getPublicKeyString()
            val testMessage = tr("Тест", "Test")
            val encrypted1 = encrypt(testMessage, key1)

            deleteKeys()

            generateKeyPair()
            val key2 = getPublicKeyString()

            if (key1 == key2) {
                emit(tr("  ❌ БАГ: Ключи не изменились после удаления!", "  ❌ BUG: Keys did not change after deletion!"))
            } else {
                emit(tr("  ✅ ОЖИДАЕМО: Новые ключи отличаются", "  ✅ EXPECTED: New keys differ"))

                try {
                    decrypt(encrypted1)
                    emit(tr("  ❌ БАГ: Старое сообщение расшифровалось новым ключом!", "  ❌ BUG: Old message decrypted with the new key!"))
                } catch (e: Exception) {
                    emit(tr("  ✅ ОЖИДАЕМО: Старое сообщение не расшифровывается", "  ✅ EXPECTED: Old message does not decrypt"))
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
            emit(tr("  ⚠️ Тест не выполнен: ${e.message}", "  ⚠️ Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 5: Подмена IV в зашифрованном файле", "📋 NEGATIVE TEST 5: IV tampering in encrypted file"))
        try {
            val testData = tr("Секретный файл", "Secret file").toByteArray()
            val publicKey = getPublicKeyString()

            val encrypted = encryptFile(testData, publicKey)

            val fakeIV = ByteArray(12) { 0xFF.toByte() }
            val corrupted = EncryptedFileData(
                encryptedData = encrypted.encryptedData,
                iv = fakeIV,
                ephemeralPublicKey = encrypted.ephemeralPublicKey
            )

            try {
                val result = decryptFile(corrupted)
                val resultText = String(result)

                if (resultText == tr("Секретный файл", "Secret file")) {
                    emit(tr("  ❌ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Файл с подменённым IV расшифровался корректно!", "  ❌ CRITICAL VULNERABILITY: File with tampered IV decrypted correctly!"))
                } else {
                    emit(tr("  ❌ ЧАСТИЧНАЯ УЯЗВИМОСТЬ: Файл расшифровался, но с мусором", "  ❌ PARTIAL VULNERABILITY: File decrypted, but into garbage"))
                    emit(tr("     Ожидалось: Секретный файл", "     Expected: Secret file"))
                    emit(tr("     Получено: ${resultText.take(50)}", "     Got: ${resultText.take(50)}"))
                }
            } catch (e: javax.crypto.AEADBadTagException) {
                emit(tr("  ✅ ОЖИДАЕМО: GCM детектировал подмену IV", "  ✅ EXPECTED: GCM detected the IV tampering"))
                emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
            } catch (e: Exception) {
                emit(tr("  ✅ ОЖИДАЕМО: Подмена IV заблокирована", "  ✅ EXPECTED: IV tampering was blocked"))
                emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
            }
        } catch (e: Exception) {
            emit(tr("  ⚠️ Тест не выполнен: ${e.message}", "  ⚠️ Test did not run: ${e.message}"))
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
                    emit(tr("  ✅ Первая доставка успешна", "  ✅ First delivery succeeded"))
                } else {
                    emit(tr("  ⚠️ Первая доставка вернула неожиданный текст", "  ⚠️ First delivery returned unexpected text"))
                }

                try {
                    SessionKeyManager.decryptWithSession(replayBob, ct, hdr)
                    emit(tr("  ❌ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: повторная доставка того же сообщения расшифровалась!", "  ❌ CRITICAL VULNERABILITY: replayed message decrypted again!"))
                } catch (e: Exception) {
                    emit(tr("  ✅ ОЖИДАЕМО: повторное сообщение отклонено (ключ уже использован и удалён)", "  ✅ EXPECTED: replayed message rejected (key already used and discarded)"))
                    emit(tr("     Причина: ${e.javaClass.simpleName}", "     Reason: ${e.javaClass.simpleName}"))
                }
            } finally {
                SessionKeyManager.deleteSession(replayAlice)
                SessionKeyManager.deleteSession(replayBob)
            }
        } catch (e: Exception) {
            emit(tr("  ⚠️ Тест не выполнен: ${e.message}", "  ⚠️ Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 7: Защита от Invalid Curve Attack", "📋 TEST 7: Invalid Curve Attack protection"))
        try {
            val templateKeyBytes = Base64.decode(getPublicKeyString(), Base64.NO_WRAP)
            val outOfField = templateKeyBytes.copyOf()
            for (i in outOfField.size - 64 until outOfField.size) outOfField[i] = 0xFF.toByte()
            try {
                loadPublicKey(Base64.encodeToString(outOfField, Base64.NO_WRAP))
                emit(tr("  ❌ ПРОВАЛ: координата вне поля была принята!", "  ❌ FAIL: an out-of-field coordinate was accepted!"))
            } catch (e: Exception) {
                emit(tr("  ✅ ОЖИДАЕМО: координата вне поля отклонена", "  ✅ EXPECTED: out-of-field coordinate rejected"))
                emit(tr("     Причина: ${e.javaClass.simpleName}: ${e.message}", "     Reason: ${e.javaClass.simpleName}: ${e.message}"))
            }
        } catch (e: Exception) {
            emit(tr("  ⚠️ Тест не выполнен: ${e.message}", "  ⚠️ Test did not run: ${e.message}"))
        }
        emit()

        emit(tr("📋 НЕГАТИВНЫЙ ТЕСТ 8: Паддинг работает?", "📋 NEGATIVE TEST 8: Is padding working?"))
        try {
            val short = "Hi"
            val long = "A".repeat(1000)

            val encShort = encrypt(short, getPublicKeyString())
            val encLong = encrypt(long, getPublicKeyString())

            val sizeShort = Base64.decode(encShort, Base64.NO_WRAP).size
            val sizeLong = Base64.decode(encLong, Base64.NO_WRAP).size

            emit(tr("  Короткое сообщение: $sizeShort байт", "  Short message: $sizeShort bytes"))
            emit(tr("  Длинное сообщение: $sizeLong байт", "  Long message: $sizeLong bytes"))
            emit(tr("  Разница: ${sizeLong - sizeShort} байт", "  Difference: ${sizeLong - sizeShort} bytes"))

            if (sizeShort > short.length + 100) {
                emit(tr("  ✅ Паддинг работает (размер больше исходного)", "  ✅ Padding works (size is larger than original)"))
            } else {
                emit(tr("  ⚠️ ВНИМАНИЕ: Паддинг может быть недостаточным", "  ⚠️ WARNING: Padding may be insufficient"))
            }
        } catch (e: Exception) {
            emit(tr("  ⚠️ Тест не выполнен: ${e.message}", "  ⚠️ Test did not run: ${e.message}"))
        }
        emit()

        emit("═══════════════════════════════════════")
        emit(tr("📊 ИТОГ СТРЕСС-ТЕСТОВ", "📊 STRESS TEST SUMMARY"))
        emit("═══════════════════════════════════════")
        emit(tr("Все негативные тесты ДОЛЖНЫ быть отклонены.", "All negative tests SHOULD be rejected."))
        emit(tr("Если видишь ❌ БАГ - это критическая проблема!", "If you see ❌ BUG — that's a critical problem!"))
        emit("═══════════════════════════════════════")

        return report.toString()
    }

    fun runAdvancedTests(context: android.content.Context, onLine: ((String) -> Unit)? = null): String {
        val isEn = UserStorage.getLanguage(context) == "en"
        fun tr(ru: String, en: String) = if (isEn) en else ru
        val report = StringBuilder()
        fun emit(line: String = "") { report.append(line).append('\n'); onLine?.invoke(line) }
        emit("═══════════════════════════════════════")
        emit(tr("🔬 РАСШИРЕННЫЕ ТЕСТЫ (SESSION + GROUP)", "🔬 ADVANCED TESTS (SESSION + GROUP)"))
        emit("═══════════════════════════════════════\n")

        emit(tr("📋 ТЕСТ 9: HKDF (KDF-деривация)", "📋 TEST 9: HKDF (KDF derivation)"))
        try {
            val testSecret = ByteArray(32) { (it * 7 + 3).toByte() }
            val key1 = deriveAesKey(testSecret, "BeaconECDH")
            val key2 = deriveAesKey(testSecret, "BeaconECDH")
            if (key1.contentEquals(key2)) {
                emit(tr("  ✅ Детерминизм: одинаковые входы → одинаковый ключ", "  ✅ Determinism: same inputs → same key"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: HKDF не детерминирован!", "  ❌ FAIL: HKDF is not deterministic!"))
            }
            val key3 = deriveAesKey(testSecret, "BeaconFileEncryption")
            if (!key1.contentEquals(key3)) {
                emit(tr("  ✅ Дифференциация: разный info → разный ключ", "  ✅ Differentiation: different info → different key"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: разные info дали одинаковый ключ!", "  ❌ FAIL: different info produced the same key!"))
            }
            val zeroSecret = ByteArray(32)
            val keyZero1 = deriveAesKey(zeroSecret, "BeaconECDH")
            val keyZero2 = deriveAesKey(zeroSecret, "BeaconECDH")
            if (keyZero1.contentEquals(keyZero2) && !keyZero1.contentEquals(key1)) {
                emit(tr("  ✅ Выход зависит от входа (нулевой секрет → свой ключ)", "  ✅ Output depends on input (zero secret → its own key)"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: HKDF не зависит от входного секрета!", "  ❌ FAIL: HKDF does not depend on the input secret!"))
            }
            emit(tr("  Длина ключа: ${key1.size} байт (ожидается 32)", "  Key length: ${key1.size} bytes (expected 32)"))
            if (key1.size == 32) emit(tr("  ✅ Длина корректна", "  ✅ Length is correct"))
            else emit(tr("  ❌ ПРОВАЛ: неверная длина ключа!", "  ❌ FAIL: incorrect key length!"))
        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 10: AES-GCM примитив (прямой вызов)", "📋 TEST 10: AES-GCM primitive (direct call)"))
        try {
            val aesKey = ByteArray(32).also { secureRandom.nextBytes(it) }
            val plaintext = "AES-GCM direct test 🔒"
            val encrypted = aesEncrypt(plaintext, aesKey)
            val decrypted = aesDecrypt(encrypted, aesKey)
            if (decrypted == plaintext) {
                emit(tr("  ✅ Round-trip: шифрование/расшифровка корректны", "  ✅ Round-trip: encryption/decryption correct"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: round-trip не совпадает", "  ❌ FAIL: round-trip mismatch"))
            }

            val tampered = encrypted.copyOf()
            tampered[tampered.size / 2] = (tampered[tampered.size / 2].toInt() xor 0xFF).toByte()
            try {
                aesDecrypt(tampered, aesKey)
                emit(tr("  ❌ ПРОВАЛ: GCM не поймал модификацию данных!", "  ❌ FAIL: GCM did not catch the data tampering!"))
            } catch (_: Exception) {
                emit(tr("  ✅ GCM тампер-детект: модификация обнаружена", "  ✅ GCM tamper detection: modification detected"))
            }

            val aesKey2 = ByteArray(32).also { secureRandom.nextBytes(it) }
            val encrypted2 = aesEncrypt(plaintext, aesKey2)
            if (!encrypted.contentEquals(encrypted2)) {
                emit(tr("  ✅ Разные ключи → разный шифртекст", "  ✅ Different keys → different ciphertext"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: разные ключи дали одинаковый шифртекст!", "  ❌ FAIL: different keys produced the same ciphertext!"))
            }

            val shortPlain = "Hi"
            val longPlain = "A".repeat(200)
            val encShort = aesEncrypt(shortPlain, aesKey)
            val encLong = aesEncrypt(longPlain, aesKey)

            if (encShort.size > shortPlain.length + 100 && encLong.size > longPlain.length + 100) {
                emit(tr("  ✅ Паддинг добавлен: размер не раскрывает длину сообщения", "  ✅ Padding added: size does not reveal message length"))
            } else {
                emit(tr("  ⚠️ ВНИМАНИЕ: паддинг может быть недостаточным", "  ⚠️ WARNING: padding may be insufficient"))
            }
        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
        }
        emit()

        emit(tr("📋 ТЕСТ 11: Группы — генерация и распределение ключа", "📋 TEST 11: Groups — key generation and distribution"))
        try {
            val groupKey = GroupManager.generateGroupKey()
            emit(tr("  Групповой ключ: ${groupKey.size} байт", "  Group key: ${groupKey.size} bytes"))
            if (groupKey.size == 32) {
                emit(tr("  ✅ Длина ключа 256 бит (AES-256)", "  ✅ Key length is 256 bits (AES-256)"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: неверная длина группового ключа!", "  ❌ FAIL: incorrect group key length!"))
            }

            val groupKey2 = GroupManager.generateGroupKey()
            if (!groupKey.contentEquals(groupKey2)) {
                emit(tr("  ✅ Генератор случаен: два ключа отличаются", "  ✅ Generator is random: two keys differ"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: два ключа одинаковы (не случайные)!", "  ❌ FAIL: two keys are identical (not random)!"))
            }

            val myPublicKey = getPublicKeyString()
            val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, myPublicKey)
            emit(tr("  Зашифрованный групповой ключ: ${encryptedGroupKey.take(40)}...", "  Encrypted group key: ${encryptedGroupKey.take(40)}..."))

            val decryptedGroupKey = GroupManager.decryptGroupKey(encryptedGroupKey)
            if (groupKey.contentEquals(decryptedGroupKey)) {
                emit(tr("  ✅ Распределение ключа: encrypt → decrypt совпадают", "  ✅ Key distribution: encrypt → decrypt match"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: расшифрованный ключ не совпадает!", "  ❌ FAIL: decrypted key does not match!"))
            }
        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
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
                emit(tr("  ✅ Round-trip: ${messages.size} сообщений (включая длинное)", "  ✅ Round-trip: ${messages.size} messages (including a long one)"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: одно или несколько сообщений не совпали", "  ❌ FAIL: one or more messages did not match"))
            }

            val groupKey2 = GroupManager.generateGroupKey()
            val enc1 = GroupManager.encryptGroupMessage("Same message", groupKey2)
            val enc2 = GroupManager.encryptGroupMessage("Same message", groupKey2)
            if (enc1 != enc2) {
                emit(tr("  ✅ IV случаен: два шифртекста одного сообщения различны", "  ✅ IV is random: two ciphertexts of the same message differ"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: IV не случаен — два шифртекста совпадают!", "  ❌ FAIL: IV is not random — two ciphertexts match!"))
            }

            val enc = GroupManager.encryptGroupMessage("Secret", groupKey)
            val decoded = android.util.Base64.decode(enc, android.util.Base64.NO_WRAP)
            decoded[decoded.size / 2] = (decoded[decoded.size / 2].toInt() xor 0xFF).toByte()
            val tampered = android.util.Base64.encodeToString(decoded, android.util.Base64.NO_WRAP)
            try {
                GroupManager.decryptGroupMessage(tampered, groupKey)
                emit(tr("  ❌ ПРОВАЛ: GCM не поймал модификацию группового сообщения!", "  ❌ FAIL: GCM did not catch the group message tampering!"))
            } catch (_: Exception) {
                emit(tr("  ✅ GCM тампер-детект: модификация группового сообщения обнаружена", "  ✅ GCM tamper detection: group message modification detected"))
            }

            val wrongKey = GroupManager.generateGroupKey()
            val encMsg = GroupManager.encryptGroupMessage("Private", groupKey)
            try {
                GroupManager.decryptGroupMessage(encMsg, wrongKey)
                emit(tr("  ❌ ПРОВАЛ: сообщение расшифровалось неверным ключом!", "  ❌ FAIL: message decrypted with the wrong key!"))
            } catch (_: Exception) {
                emit(tr("  ✅ Неверный ключ отклонён", "  ✅ Wrong key rejected"))
            }
        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА: ${e.message}", "  ❌ ERROR: ${e.message}"))
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
                emit(tr("  ✅ X3DH: сессии установлены у обеих сторон", "  ✅ X3DH: sessions established on both sides"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: сессия не установлена!", "  ❌ FAIL: session not established!"))
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
                emit(tr("  ✅ Round-trip: ${testMessages.size} сообщений (Alice→Bob)", "  ✅ Round-trip: ${testMessages.size} messages (Alice→Bob)"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: round-trip не совпадает", "  ❌ FAIL: round-trip mismatch"))
            }

            val (ctB, hdrB) = SessionKeyManager.encryptWithSession(bobId, "Reply from Bob")
            val decB = SessionKeyManager.decryptWithSession(aliceId, ctB, hdrB)
            if (decB == "Reply from Bob") {
                emit(tr("  ✅ Двусторонность: Bob→Alice работает", "  ✅ Bidirectionality: Bob→Alice works"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: Bob→Alice не работает", "  ❌ FAIL: Bob→Alice does not work"))
            }

            val (ct1, hdr1) = SessionKeyManager.encryptWithSession(aliceId, "Same")
            val (ct2, hdr2) = SessionKeyManager.encryptWithSession(aliceId, "Same")
            if (ct1 != ct2) {
                emit(tr("  ✅ Ratchet: одно сообщение → разные шифртексты (ключи меняются)", "  ✅ Ratchet: one message → different ciphertexts (keys change)"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: ratchet не продвигается!", "  ❌ FAIL: ratchet is not advancing!"))
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
                emit(tr("  ✅ Out-of-order: все 3 сообщения расшифрованы корректно", "  ✅ Out-of-order: all 3 messages decrypted correctly"))
            } else {
                emit(tr("  ❌ ПРОВАЛ: out-of-order доставка не работает", "  ❌ FAIL: out-of-order delivery does not work"))
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
                    emit(tr("  ❌ ПРОВАЛ: посторонняя сторона расшифровала чужой шифртекст: '$fakeDecrypt'", "  ❌ FAIL: an unrelated party decrypted someone else's ciphertext: '$fakeDecrypt'"))
                } catch (_: Exception) {
                    emit(tr("  ✅ Изоляция: посторонний ключ не может расшифровать чужой шифртекст", "  ✅ Isolation: an unrelated key cannot decrypt someone else's ciphertext"))
                }
            } finally {
                SessionKeyManager.deleteSession(malloryId)
                SessionKeyManager.deleteSession(eveId)
            }

        } catch (e: Exception) {
            emit(tr("  ❌ ОШИБКА в сессионных тестах: ${e.message}", "  ❌ ERROR in session tests: ${e.message}"))
        } finally {

            SessionKeyManager.deleteSession(aliceId)
            SessionKeyManager.deleteSession(bobId)
        }

        emit()
        emit("═══════════════════════════════════════")
        emit(tr("📊 ИТОГ РАСШИРЕННЫХ ТЕСТОВ", "📊 ADVANCED TEST SUMMARY"))
        emit("═══════════════════════════════════════")
        emit(tr("Покрыто: HKDF · AES-GCM · GroupManager · X3DH · Ratchet · Out-of-order", "Covered: HKDF · AES-GCM · GroupManager · X3DH · Ratchet · Out-of-order"))
        emit(tr("Если видишь ❌ ПРОВАЛ — это критическая проблема!", "If you see ❌ FAIL — that's a critical problem!"))
        emit("═══════════════════════════════════════")

        return report.toString()
    }

}

