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
    private const val SW_KEY_PREFS     = "beacon_sw_keys"       // legacy plaintext (только для чтения при миграции)
    private const val SW_KEY_PREFS_ENC = "beacon_ec_keys_enc"   // новое зашифрованное хранилище (другое имя файла!)
    private const val SW_PRIV_KEY      = "ec_priv"
    private const val SW_PUB_KEY       = "ec_pub"

    private var appContext: android.content.Context? = null

    fun init(context: android.content.Context) {
        appContext = context.applicationContext
    }

    // Всегда используем software ключ — надёжно на всех версиях Android.
    // EC ключ хранится в EncryptedSharedPreferences (защищён KeyStore AES-256).
    private fun useKeyStore() = false

    // ─── Software ключ (для Android < 12) ────────────────────────────────────

    private fun getSoftwareKeyPair(): java.security.KeyPair {
        val ctx = appContext ?: throw IllegalStateException("CryptoManager.init() не вызван")

        // ── Шаг 1: Каноническое зашифрованное хранилище (beacon_ec_keys_enc) ──
        // Файл с отдельным именем — никогда не пересекается с legacy-файлом,
        // поэтому EncryptedStorage не может случайно удалить старый ключ.
        val encPrefs   = EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS_ENC)
        val privStored = encPrefs.getString(SW_PRIV_KEY, null)
        val pubB64     = encPrefs.getString(SW_PUB_KEY,  null)
        if (privStored != null && pubB64 != null) {
            val privBytes = StorageKeyManager.unwrapBytes(privStored)
            // Eager migration: если ключ ещё не обёрнут SMK, а SMK уже доступен — обернуть сразу
            if (!privStored.startsWith(StorageKeyManager.SMK_PREFIX) && StorageKeyManager.isUnlocked) {
                encPrefs.edit().putString(SW_PRIV_KEY, StorageKeyManager.wrapBytes(privBytes)).commit()
            }
            val kf = java.security.KeyFactory.getInstance("EC")
            return java.security.KeyPair(
                kf.generatePublic(java.security.spec.X509EncodedKeySpec(Base64.decode(pubB64, Base64.NO_WRAP))),
                kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(privBytes))
            )
        }

        // ── Шаг 2: Миграция из предыдущего зашифрованного хранилища (beacon_sw_keys enc) ──
        // Пользователи которые обновились до промежуточной версии имеют ключ здесь.
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

        // ── Шаг 3: Миграция из оригинального незашифрованного хранилища ──
        // Пользователи первой версии приложения хранили ключ здесь открытым текстом.
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

        // ── Шаг 4: Генерация новых ключей (первый запуск) ──
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
            .commit() // commit() вместо apply() — ключи должны быть записаны до возврата,
                      // иначе краш до завершения async-записи даст новый ключ при следующем запуске
        android.util.Log.d("CryptoManager", "Software EC ключи сгенерированы")
        return kp
    }

    // ─── Генерация / проверка ключей ──────────────────────────────────────────

    fun generateKeyPair() {
        if (!useKeyStore()) {
            getSoftwareKeyPair() // создаёт если не существует
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
            // Каноническое хранилище
            if (EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS_ENC)
                    .getString(SW_PRIV_KEY, null) != null) return true
            // Промежуточное зашифрованное (до переименования)
            try {
                if (EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS)
                        .getString(SW_PRIV_KEY, null) != null) return true
            } catch (_: Exception) {}
            // Legacy незашифрованное
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

    // ─── Режим 1: Ephemeral ECDH (fallback / legacy) ──────────────────────────
    //
    // АУДИТ #1: Static-Ephemeral ECDH — без PFS.
    // Используется только как fallback. Основной чат — encryptWithForwardSecrecy.

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

    // ─── АУДИТ #2: Проверка точки на кривой secp256r1 ────────────────────────
    //
    // Invalid Curve Attack: злоумышленник присылает точку не на кривой,
    // чтобы вычислить закрытый ключ из shared secret.
    // Проверяем: точка не в бесконечности, координаты в поле, уравнение y²=x³+ax+b (mod p).

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

        // y² = x³ + ax + b (mod p)
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

    // ─── HKDF-деривация AES ключа ────────────────────────────────────────────

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

    // ─── Режим 2: Session-based шифрование (Forward Secrecy) ─────────────────
    //
    // АУДИТ #1: Основной режим — всегда использовать для чата.
    // Каждое сообщение шифруется эфемерными ключами через Ratchet.

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

    // ─── Подписи ──────────────────────────────────────────────────────────────

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

    /**
     * Подписывает чанк с привязкой к transferId и chunkIndex.
     * Предотвращает DoS-атаку переупорядочивания чанков из разных передач:
     * даже если данные чанка совпадают, подпись с другим контекстом не пройдёт верификацию.
     * Формат подписываемых данных: [transferId bytes][4-byte big-endian chunkIndex][chunkData bytes]
     */
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

    // ─── Вспомогательные ─────────────────────────────────────────────────────

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

    // АУДИТ #2: validateECPoint вызывается здесь — защита для всех вызовов loadPublicKey
    fun loadPublicKey(keyString: String): java.security.PublicKey {
        val keyBytes = Base64.decode(keyString, Base64.NO_WRAP)
        val keyFactory = java.security.KeyFactory.getInstance("EC")
        val publicKey = keyFactory.generatePublic(java.security.spec.X509EncodedKeySpec(keyBytes))
        validateECPoint(publicKey)
        return publicKey
    }

    // ─── Рандомный паддинг ────────────────────────────────────────────────────
    //
    // Длина паддинга: случайно от 16 до 256 байт.
    // Наблюдатель видит пакеты разного размера и не может определить
    // тип сообщения (короткий текст, команда, голос) по длине трафика.
    //
    // Формат: [1 байт — длина паддинга][N байт случайного мусора][данные]

    private val secureRandom = java.security.SecureRandom()

    private fun addPadding(data: ByteArray): ByteArray {
        val padLen = 128 + secureRandom.nextInt(385) // 128..512 байт
        val pad = ByteArray(padLen).also { secureRandom.nextBytes(it) }
        val result = ByteArray(2 + padLen + data.size)  // <- 2 байта для длины
        result[0] = (padLen shr 8).toByte()  // <- Старший байт
        result[1] = (padLen and 0xFF).toByte()  // <- Младший байт
        System.arraycopy(pad, 0, result, 2, padLen)  // <- Со смещением 2
        System.arraycopy(data, 0, result, 2 + padLen, data.size)
        return result
    }

    private fun removePadding(data: ByteArray): ByteArray {
        if (data.size < 2) throw IllegalArgumentException("Пакет слишком короткий")
        val padLen = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)  // <- 2 байта

        if (data.size < 2 + padLen) {  // <- 2 + padLen
            throw IllegalArgumentException("Паддинг повреждён: padLen=$padLen size=${data.size}")
        }

        val result = data.copyOfRange(2 + padLen, data.size)  // <- Со смещением 2
        return result
    }

    private fun aesEncrypt(plaintext: String, key: ByteArray): ByteArray {
        val iv = ByteArray(12).also { secureRandom.nextBytes(it) }  // явный SecureRandom, не полагаемся на провайдера
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
                // Каноническое зашифрованное хранилище
                EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS_ENC)
                    .edit().remove(SW_PRIV_KEY).remove(SW_PUB_KEY).apply()
                // Промежуточное (до переименования)
                try {
                    EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS)
                        .edit().remove(SW_PRIV_KEY).remove(SW_PUB_KEY).apply()
                } catch (_: Exception) {}
                // Legacy незашифрованный
                ctx.getSharedPreferences(SW_KEY_PREFS, android.content.Context.MODE_PRIVATE)
                    .edit().clear().apply()
            }
        } catch (e: Exception) {
            android.util.Log.e("CryptoManager", "Ошибка удаления ключей: ${e.message}")
        }
    }
    // ─── Шифрование файлов ────────────────────────────────────────────────────

    /**
     * Данные зашифрованного файла
     */
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

    /**
     * Шифрует файл для отправки контакту.
     */
    fun encryptFile(fileData: ByteArray, recipientPublicKeyStr: String): EncryptedFileData {
        val ephemeralKeyPair = generateEphemeralKeyPair()
        val sharedSecret = ecdh(ephemeralKeyPair.private, loadPublicKey(recipientPublicKeyStr))
        val aesKey = deriveAesKey(sharedSecret, "BeaconFileEncryption")

        val iv = ByteArray(12).also { secureRandom.nextBytes(it) }  // явный SecureRandom
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

    /**
     * Расшифровывает полученный файл.
     */
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

    /**
     * Паддинг для файлов (скрывает точный размер).
     */
    private fun addFilePadding(data: ByteArray): ByteArray {
        val padLen = 1024 + secureRandom.nextInt(3072) // 1-4KB
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

    /**
     * Упаковка зашифрованного файла в Base64.
     */
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

    /**
     * Распаковка полученного зашифрованного файла.
     */
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
    // ─── ТЕСТЫ БЕЗОПАСНОСТИ ──────────────────────────────────────────────────

    /**
     * Полная диагностика KeyStore
     */
    fun runSecurityDiagnostics(context: android.content.Context, onLine: ((String) -> Unit)? = null): String {
        val report = StringBuilder()
        fun emit(line: String = "") { report.append(line).append('\n'); onLine?.invoke(line) }
        emit("═══════════════════════════════════════")
        emit("🔐 ДИАГНОСТИКА БЕЗОПАСНОСТИ KEYSTORE")
        emit("═══════════════════════════════════════\n")

        // ВАЖНО: Убеждаемся что ключи существуют перед всеми тестами
        if (!hasKeys()) {
            generateKeyPair()
        }

        // Тест 1: Проверка существования ключей
        emit("📋 ТЕСТ 1: Проверка существования ключей")
        val hasKeysInitial = hasKeys()
        emit("  Ключи существуют: $hasKeysInitial")

        if (!hasKeysInitial) {
            emit("  ⚠️ Ключи не найдены, генерируем...")
            generateKeyPair()
            emit("  ✅ Ключи сгенерированы")
        }
        emit()

        // Тест 2: Защита от повторной генерации
        emit("📋 ТЕСТ 2: Защита от повторной генерации")
        val publicKey1 = getPublicKeyString()
        emit("  Публичный ключ (до): ${publicKey1.take(50)}...")

        generateKeyPair() // Попытка пересоздать
        val publicKey2 = getPublicKeyString()
        emit("  Публичный ключ (после): ${publicKey2.take(50)}...")

        if (publicKey1 == publicKey2) {
            emit("  ✅ УСПЕХ: Ключи НЕ пересоздались (защита работает)")
        } else {
            emit("  ❌ ПРОВАЛ: Ключи пересоздались (КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!)")
        }
        emit()

        // Тест 3: Удаление и восстановление
        emit("📋 ТЕСТ 3: Удаление и восстановление")
        val keyBeforeDelete = getPublicKeyString()

        // ⚠️ Сохраняем реальные ключи аккаунта — тест НЕ должен менять fingerprint
        val ctx3 = appContext
        val encPrefs3 = ctx3?.let { EncryptedStorage.getEncryptedPrefs(it, SW_KEY_PREFS_ENC) }
        val savedPrivB64 = encPrefs3?.getString(SW_PRIV_KEY, null)
        val savedPubB64  = encPrefs3?.getString(SW_PUB_KEY,  null)

        deleteKeys()
        val hasKeysAfterDelete = hasKeys()
        emit("  После deleteKeys(): hasKeys() = $hasKeysAfterDelete")

        if (!hasKeysAfterDelete) {
            emit("  ✅ УСПЕХ: Ключи успешно удалены")
        } else {
            emit("  ❌ ПРОВАЛ: Ключи не удалились")
        }

        generateKeyPair()
        val hasKeysAfterRegenerate = hasKeys()
        val keyAfterRegenerate = getPublicKeyString()
        emit("  После generateKeyPair(): hasKeys() = $hasKeysAfterRegenerate")

        if (hasKeysAfterRegenerate) {
            emit("  ✅ УСПЕХ: Генерация новых ключей работает")
            if (keyBeforeDelete != keyAfterRegenerate) {
                emit("  ✅ УСПЕХ: Новые ключи отличаются от старых")
            }
        } else {
            emit("  ❌ ПРОВАЛ: Не удалось восстановить ключи")
        }

        // 🔄 Восстанавливаем оригинальные ключи аккаунта (чтобы fingerprint не изменился)
        if (savedPrivB64 != null && savedPubB64 != null && encPrefs3 != null) {
            encPrefs3.edit()
                .putString(SW_PRIV_KEY, savedPrivB64)
                .putString(SW_PUB_KEY,  savedPubB64)
                .commit()
            emit("  🔄 Ключи аккаунта восстановлены (fingerprint не изменился)")
        }
        emit()

        // Тест 4: Проверка хранилища ключей (software EC в EncryptedSharedPreferences)
        emit("📋 ТЕСТ 4: Проверка хранилища ключей")
        try {
            val ctx4 = appContext ?: throw IllegalStateException("CryptoManager.init() не вызван")
            val encPrefs4 = EncryptedStorage.getEncryptedPrefs(ctx4, SW_KEY_PREFS_ENC)
            val privB64 = encPrefs4.getString(SW_PRIV_KEY, null)
            val pubB64  = encPrefs4.getString(SW_PUB_KEY,  null)

            if (privB64 == null || pubB64 == null) {
                emit("  ❌ ПРОВАЛ: Ключи не найдены в EncryptedSharedPreferences ($SW_KEY_PREFS_ENC)")
            } else {
                emit("  ✅ Ключи присутствуют в хранилище: $SW_KEY_PREFS_ENC")

                val kf = java.security.KeyFactory.getInstance("EC")
                val privKey = kf.generatePrivate(
                    java.security.spec.PKCS8EncodedKeySpec(StorageKeyManager.unwrapBytes(privB64))
                )
                val pubKey = kf.generatePublic(
                    java.security.spec.X509EncodedKeySpec(Base64.decode(pubB64, Base64.NO_WRAP))
                )

                emit("  Алгоритм: ${privKey.algorithm} / ${pubKey.algorithm}")
                emit("  Формат приватного ключа: ${privKey.format} (PKCS#8, экспортируемый только через EncryptedPrefs)")

                if (pubKey is java.security.interfaces.ECPublicKey) {
                    val curveName = pubKey.params.toString()
                    val ok = curveName.contains("secp256r1") || curveName.contains("prime256v1")
                    emit("  Кривая: ${if (ok) "secp256r1 (P-256) ✅" else curveName}")
                }

                // Проверяем согласованность пары: подписываем приватным → верифицируем публичным
                val testBytes = "key_pair_consistency_check".toByteArray()
                val sig4 = Signature.getInstance("SHA256withECDSA").apply {
                    initSign(privKey); update(testBytes)
                }.sign()
                val verified4 = Signature.getInstance("SHA256withECDSA").apply {
                    initVerify(pubKey); update(testBytes)
                }.verify(sig4)

                if (verified4) {
                    emit("  ✅ УСПЕХ: Ключевая пара согласована (sign ↔ verify)")
                } else {
                    emit("  ❌ ПРОВАЛ: Ключевая пара несогласована!")
                }

                emit("  🔒 Защита: EncryptedSharedPreferences (AES-256-GCM, мастер-ключ в AndroidKeyStore)")
                emit("  ✅ УСПЕХ: Ключи корректно хранятся и защищены")
            }
        } catch (e: Exception) {
            emit("  ❌ ОШИБКА: ${e.message}")
        }
        emit()

        // Тест 5: Шифрование/расшифровка (ПОСЛЕ теста 3 - используем НОВЫЕ ключи)
        emit("📋 ТЕСТ 5: Шифрование и расшифровка")
        try {
            val testMessage = "Секретное сообщение 🔐"
            val currentPublicKey = getPublicKeyString() // Получаем актуальный ключ

            emit("  Оригинал: '$testMessage'")
            emit("  Длина оригинала: ${testMessage.length} символов")
            emit("  Байты оригинала: ${testMessage.toByteArray(Charsets.UTF_8).size} байт")

            val encrypted = encrypt(testMessage, currentPublicKey)
            emit("  Зашифровано: ${encrypted.take(50)}...")

            val decrypted = decrypt(encrypted)
            emit("  Расшифровано: '$decrypted'")
            emit("  Длина расшифрованного: ${decrypted.length} символов")
            emit("  Байты расшифрованного: ${decrypted.toByteArray(Charsets.UTF_8).size} байт")
            emit("  HEX расшифрованного: ${decrypted.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}")
            emit("  HEX оригинала:       ${testMessage.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }}")

            if (decrypted == testMessage) {
                emit("  ✅ УСПЕХ: Шифрование/расшифровка работает корректно")
            } else {
                emit("  ❌ ПРОВАЛ: Сообщение не совпадает")
                emit("  Ожидалось: '$testMessage'")
                emit("  Получено:  '$decrypted'")
                // Посимвольное сравнение
                for (i in 0 until maxOf(testMessage.length, decrypted.length)) {
                    val orig = testMessage.getOrNull(i)
                    val dec = decrypted.getOrNull(i)
                    if (orig != dec) {
                        emit("  Различие на позиции $i: '$orig' vs '$dec'")
                    }
                }
            }
        } catch (e: Exception) {
            emit("  ❌ ОШИБКА: ${e.message}")
            e.printStackTrace()
        }
        emit()

        // Тест 6: Подпись и верификация
        emit("📋 ТЕСТ 6: Подпись и верификация")
        try {
            val testMessage = "Тестовое сообщение для подписи"
            val signature = sign(testMessage)
            emit("  Подпись создана: ${signature.take(50)}...")

            val publicKey = getPublicKeyString()
            val isValid = verify(testMessage, signature, publicKey)

            if (isValid) {
                emit("  ✅ УСПЕХ: Подпись валидна")
            } else {
                emit("  ❌ ПРОВАЛ: Подпись невалидна")
            }

            val fakeSignature = sign("Другое сообщение")
            val isFakeValid = verify(testMessage, fakeSignature, publicKey)

            if (!isFakeValid) {
                emit("  ✅ УСПЕХ: Поддельная подпись отклонена")
            } else {
                emit("  ❌ ПРОВАЛ: Поддельная подпись принята (КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!)")
            }
        } catch (e: Exception) {
            emit("  ❌ ОШИБКА: ${e.message}")
        }
        emit()

        // Тест 7: Invalid Curve Attack (информационный)
        emit("📋 ТЕСТ 7: Защита от Invalid Curve Attack")
        emit("  ℹ️ Информационный тест")
        emit("  ✅ Защита реализована в методе validateECPoint()")
        emit("     - Вызывается внутри loadPublicKey() для ВСЕХ ключей")
        emit("     - Проверка: точка не в бесконечности")
        emit("     - Проверка: координаты в поле (0 < x,y < p)")
        emit("     - Проверка: y² = x³ + ax + b (mod p)")
        emit("  ✅ Каждый входящий ключ проверяется автоматически")
        emit("  ✅ Некорректные точки отклоняются с SecurityException")
        emit()

        // Тест 8: Шифрование файлов
        emit("📋 ТЕСТ 8: Шифрование файлов")
        try {
            val testData = "Содержимое тестового файла 📄".toByteArray()
            val publicKey = getPublicKeyString()

            val encrypted = encryptFile(testData, publicKey)
            emit("  Файл зашифрован: ${encrypted.encryptedData.size} байт")
            emit("  IV: ${encrypted.iv.size} байт")
            emit("  Ephemeral key: ${encrypted.ephemeralPublicKey.size} байт")

            val decrypted = decryptFile(encrypted)
            val decryptedText = String(decrypted)

            if (decryptedText == String(testData)) {
                emit("  ✅ УСПЕХ: Шифрование файлов работает корректно")
            } else {
                emit("  ❌ ПРОВАЛ: Файл расшифрован некорректно")
            }
        } catch (e: Exception) {
            emit("  ❌ ОШИБКА: ${e.message}")
        }
        emit()

        // Итоговый отчёт
        emit("═══════════════════════════════════════")
        emit("📊 ИТОГОВЫЙ СТАТУС")
        emit("═══════════════════════════════════════")
        emit("Публичный ключ (fingerprint):")
        emit(getFingerprintEmoji())
        emit()
        emit("⚠️ ВАЖНО: Проверь логи выше на наличие ❌")
        emit("═══════════════════════════════════════")

        return report.toString()
    }

    /**
     * Получить emoji fingerprint для визуальной верификации
     */
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

    // Emoji для fingerprint
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
    /**
     * СТРЕСС-ТЕСТЫ - проверяем что тесты реально ловят ошибки
     */
    fun runStressTests(context: android.content.Context, onLine: ((String) -> Unit)? = null): String {
        val report = StringBuilder()
        fun emit(line: String = "") { report.append(line).append('\n'); onLine?.invoke(line) }
        emit("═══════════════════════════════════════")
        emit("💣 СТРЕСС-ТЕСТЫ (ДОЛЖНЫ ПРОВАЛИТЬСЯ)")
        emit("═══════════════════════════════════════\n")

        // Тест 1: Попытка расшифровать мусор
        emit("📋 НЕГАТИВНЫЙ ТЕСТ 1: Расшифровка мусора")
        try {
            val garbage = "AAAAAAAAAAAAAAAAAAAAAA=="
            decrypt(garbage)
            emit("  ❌ БАГ: Мусор расшифровался (не должно было!)")
        } catch (e: Exception) {
            emit("  ✅ ОЖИДАЕМО: Мусор отклонён")
            emit("     Причина: ${e.javaClass.simpleName}")
        }
        emit()

        // Тест 2: Подделка подписи
        emit("📋 НЕГАТИВНЫЙ ТЕСТ 2: Подделка подписи")
        try {
            val message = "Оригинальное сообщение"
            val fakeSignature = Base64.encodeToString(ByteArray(64) { it.toByte() }, Base64.NO_WRAP)
            val publicKey = getPublicKeyString()

            val isValid = verify(message, fakeSignature, publicKey)

            if (isValid) {
                emit("  ❌ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Поддельная подпись принята!")
            } else {
                emit("  ✅ ОЖИДАЕМО: Подделка отклонена")
            }
        } catch (e: Exception) {
            emit("  ✅ ОЖИДАЕМО: Подделка вызвала исключение")
        }
        emit()

        // Тест 3: Модификация зашифрованных данных
        emit("📋 НЕГАТИВНЫЙ ТЕСТ 3: Изменение зашифрованного текста")
        try {
            val originalMessage = "Важное сообщение"
            val publicKey = getPublicKeyString()
            val encrypted = encrypt(originalMessage, publicKey)

            // Меняем один байт в зашифрованном тексте
            val corrupted = encrypted.toCharArray()
            corrupted[corrupted.size / 2] = 'X'
            val corruptedString = String(corrupted)

            try {
                val decrypted = decrypt(corruptedString)
                emit("  ❌ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Изменённые данные расшифровались!")
                emit("     Расшифровано: $decrypted")
            } catch (e: Exception) {
                emit("  ✅ ОЖИДАЕМО: GCM детектировал изменение")
                emit("     Причина: ${e.javaClass.simpleName}")
            }
        } catch (e: Exception) {
            emit("  ⚠️ Тест не выполнен: ${e.message}")
        }
        emit()

        // Тест 4: Проверка что ключи действительно меняются при удалении
        emit("📋 НЕГАТИВНЫЙ ТЕСТ 4: Смена ключей после удаления")
        try {
            // ⚠️ Сохраняем реальные ключи — тест НЕ должен менять fingerprint аккаунта
            val encPrefsStress4 = EncryptedStorage.getEncryptedPrefs(context, SW_KEY_PREFS_ENC)
            val savedPrivStress4 = encPrefsStress4.getString(SW_PRIV_KEY, null)
            val savedPubStress4  = encPrefsStress4.getString(SW_PUB_KEY,  null)

            val key1 = getPublicKeyString()
            val testMessage = "Тест"
            val encrypted1 = encrypt(testMessage, key1)

            // Удаляем ключи
            deleteKeys()

            // Генерируем новые (временные)
            generateKeyPair()
            val key2 = getPublicKeyString()

            if (key1 == key2) {
                emit("  ❌ БАГ: Ключи не изменились после удаления!")
            } else {
                emit("  ✅ ОЖИДАЕМО: Новые ключи отличаются")

                // Проверяем что старое сообщение нельзя расшифровать новым ключом
                try {
                    decrypt(encrypted1)
                    emit("  ❌ БАГ: Старое сообщение расшифровалось новым ключом!")
                } catch (e: Exception) {
                    emit("  ✅ ОЖИДАЕМО: Старое сообщение не расшифровывается")
                }
            }

            // 🔄 Восстанавливаем оригинальные ключи аккаунта (fingerprint не меняется)
            if (savedPrivStress4 != null && savedPubStress4 != null) {
                encPrefsStress4.edit()
                    .putString(SW_PRIV_KEY, savedPrivStress4)
                    .putString(SW_PUB_KEY,  savedPubStress4)
                    .commit()
                emit("  🔄 Ключи аккаунта восстановлены (fingerprint не изменился)")
            }
        } catch (e: Exception) {
            emit("  ⚠️ Тест не выполнен: ${e.message}")
        }
        emit()

        // Тест 5: Файл с изменённым IV
        emit("📋 НЕГАТИВНЫЙ ТЕСТ 5: Подмена IV в зашифрованном файле")
        try {
            val testData = "Секретный файл".toByteArray()
            val publicKey = getPublicKeyString()

            val encrypted = encryptFile(testData, publicKey)

            // Подменяем IV
            val fakeIV = ByteArray(12) { 0xFF.toByte() }
            val corrupted = EncryptedFileData(
                encryptedData = encrypted.encryptedData,
                iv = fakeIV,
                ephemeralPublicKey = encrypted.ephemeralPublicKey
            )

            try {
                val result = decryptFile(corrupted)
                val resultText = String(result)

                // Проверяем получили ли мы корректные данные
                if (resultText == "Секретный файл") {
                    emit("  ❌ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Файл с подменённым IV расшифровался корректно!")
                } else {
                    emit("  ❌ ЧАСТИЧНАЯ УЯЗВИМОСТЬ: Файл расшифровался, но с мусором")
                    emit("     Ожидалось: Секретный файл")
                    emit("     Получено: ${resultText.take(50)}")
                }
            } catch (e: javax.crypto.AEADBadTagException) {
                emit("  ✅ ОЖИДАЕМО: GCM детектировал подмену IV")
                emit("     Причина: ${e.javaClass.simpleName}")
            } catch (e: Exception) {
                emit("  ✅ ОЖИДАЕМО: Подмена IV заблокирована")
                emit("     Причина: ${e.javaClass.simpleName}")
            }
        } catch (e: Exception) {
            emit("  ⚠️ Тест не выполнен: ${e.message}")
        }
        emit()

        /// Тест 6: Replay Attack - повторная отправка старого сообщения
        emit("📋 НЕГАТИВНЫЙ ТЕСТ 6: Информационный - Replay Attack")
        emit("  ℹ️ Защита от Replay реализована на уровне MessengerService")
        emit("     (receivedMessageIds кеш последних 100 ID)")
        emit()

        // Тест 7: Invalid Curve Attack
        emit("📋 ТЕСТ 7: Защита от Invalid Curve Attack")
        emit("  ℹ️ Информационный тест")
        emit("  ✅ Защита реализована в методе validateECPoint()")
        emit("     - Вызывается внутри loadPublicKey() для ВСЕХ ключей")
        emit("     - Проверка: точка не в бесконечности")
        emit("     - Проверка: координаты в поле (0 < x,y < p)")
        emit("     - Проверка: y² = x³ + ax + b (mod p)")
        emit("  ✅ Каждый входящий ключ проверяется автоматически")
        emit("  ✅ Некорректные точки отклоняются с SecurityException")
        emit()

        // Тест 8: Проверка паддинга
        emit("📋 НЕГАТИВНЫЙ ТЕСТ 8: Паддинг работает?")
        try {
            val short = "Hi"
            val long = "A".repeat(1000)

            val encShort = encrypt(short, getPublicKeyString())
            val encLong = encrypt(long, getPublicKeyString())

            val sizeShort = Base64.decode(encShort, Base64.NO_WRAP).size
            val sizeLong = Base64.decode(encLong, Base64.NO_WRAP).size

            emit("  Короткое сообщение: $sizeShort байт")
            emit("  Длинное сообщение: $sizeLong байт")
            emit("  Разница: ${sizeLong - sizeShort} байт")

            // Проверяем что паддинг добавляется
            if (sizeShort > short.length + 100) {
                emit("  ✅ Паддинг работает (размер больше исходного)")
            } else {
                emit("  ⚠️ ВНИМАНИЕ: Паддинг может быть недостаточным")
            }
        } catch (e: Exception) {
            emit("  ⚠️ Тест не выполнен: ${e.message}")
        }
        emit()

        emit("═══════════════════════════════════════")
        emit("📊 ИТОГ СТРЕСС-ТЕСТОВ")
        emit("═══════════════════════════════════════")
        emit("Все негативные тесты ДОЛЖНЫ быть отклонены.")
        emit("Если видишь ❌ БАГ - это критическая проблема!")
        emit("═══════════════════════════════════════")

        return report.toString()
    }

    /**
     * РАСШИРЕННЫЕ ТЕСТЫ: покрывают слои, не проверяемые базовой диагностикой:
     * - HKDF (KDF-деривация)
     * - AES-GCM примитив напрямую (без ECIES обёртки)
     * - GroupManager: генерация/распределение/шифрование
     * - SessionKeyManager: X3DH + симметричный ratchet + out-of-order доставка
     */
    fun runAdvancedTests(context: android.content.Context, onLine: ((String) -> Unit)? = null): String {
        val report = StringBuilder()
        fun emit(line: String = "") { report.append(line).append('\n'); onLine?.invoke(line) }
        emit("═══════════════════════════════════════")
        emit("🔬 РАСШИРЕННЫЕ ТЕСТЫ (SESSION + GROUP)")
        emit("═══════════════════════════════════════\n")

        // ── Тест 9: HKDF детерминизм и дифференциация ────────────────────────
        emit("📋 ТЕСТ 9: HKDF (KDF-деривация)")
        try {
            val testSecret = ByteArray(32) { (it * 7 + 3).toByte() }
            val key1 = deriveAesKey(testSecret, "BeaconECDH")
            val key2 = deriveAesKey(testSecret, "BeaconECDH")
            if (key1.contentEquals(key2)) {
                emit("  ✅ Детерминизм: одинаковые входы → одинаковый ключ")
            } else {
                emit("  ❌ ПРОВАЛ: HKDF не детерминирован!")
            }
            val key3 = deriveAesKey(testSecret, "BeaconFileEncryption")
            if (!key1.contentEquals(key3)) {
                emit("  ✅ Дифференциация: разный info → разный ключ")
            } else {
                emit("  ❌ ПРОВАЛ: разные info дали одинаковый ключ!")
            }
            val zeroSecret = ByteArray(32)
            val keyZero1 = deriveAesKey(zeroSecret, "BeaconECDH")
            val keyZero2 = deriveAesKey(zeroSecret, "BeaconECDH")
            if (keyZero1.contentEquals(keyZero2) && !keyZero1.contentEquals(key1)) {
                emit("  ✅ Выход зависит от входа (нулевой секрет → свой ключ)")
            } else {
                emit("  ❌ ПРОВАЛ: HKDF не зависит от входного секрета!")
            }
            emit("  Длина ключа: ${key1.size} байт (ожидается 32)")
            if (key1.size == 32) emit("  ✅ Длина корректна")
            else emit("  ❌ ПРОВАЛ: неверная длина ключа!")
        } catch (e: Exception) {
            emit("  ❌ ОШИБКА: ${e.message}")
        }
        emit()

        // ── Тест 10: AES-GCM примитив ────────────────────────────────────────
        emit("📋 ТЕСТ 10: AES-GCM примитив (прямой вызов)")
        try {
            val aesKey = ByteArray(32).also { secureRandom.nextBytes(it) }
            val plaintext = "AES-GCM direct test 🔒"
            val encrypted = aesEncrypt(plaintext, aesKey)
            val decrypted = aesDecrypt(encrypted, aesKey)
            if (decrypted == plaintext) {
                emit("  ✅ Round-trip: шифрование/расшифровка корректны")
            } else {
                emit("  ❌ ПРОВАЛ: round-trip не совпадает")
            }
            // GCM tamper detection
            val tampered = encrypted.copyOf()
            tampered[tampered.size / 2] = (tampered[tampered.size / 2].toInt() xor 0xFF).toByte()
            try {
                aesDecrypt(tampered, aesKey)
                emit("  ❌ ПРОВАЛ: GCM не поймал модификацию данных!")
            } catch (_: Exception) {
                emit("  ✅ GCM тампер-детект: модификация обнаружена")
            }
            // Разные ключи → разный результат
            val aesKey2 = ByteArray(32).also { secureRandom.nextBytes(it) }
            val encrypted2 = aesEncrypt(plaintext, aesKey2)
            if (!encrypted.contentEquals(encrypted2)) {
                emit("  ✅ Разные ключи → разный шифртекст")
            } else {
                emit("  ❌ ПРОВАЛ: разные ключи дали одинаковый шифртекст!")
            }
            // Проверяем паддинг: размер шифртекста должен скрывать длину оригинала
            val shortPlain = "Hi"
            val longPlain = "A".repeat(200)
            val encShort = aesEncrypt(shortPlain, aesKey)
            val encLong = aesEncrypt(longPlain, aesKey)
            // Паддинг 128-512 байт → оба не должны точно отражать длину
            if (encShort.size > shortPlain.length + 100 && encLong.size > longPlain.length + 100) {
                emit("  ✅ Паддинг добавлен: размер не раскрывает длину сообщения")
            } else {
                emit("  ⚠️ ВНИМАНИЕ: паддинг может быть недостаточным")
            }
        } catch (e: Exception) {
            emit("  ❌ ОШИБКА: ${e.message}")
        }
        emit()

        // ── Тест 11: GroupManager — генерация и распределение ключа ──────────
        emit("📋 ТЕСТ 11: Группы — генерация и распределение ключа")
        try {
            val groupKey = GroupManager.generateGroupKey()
            emit("  Групповой ключ: ${groupKey.size} байт")
            if (groupKey.size == 32) {
                emit("  ✅ Длина ключа 256 бит (AES-256)")
            } else {
                emit("  ❌ ПРОВАЛ: неверная длина группового ключа!")
            }
            // Два вызова → разные ключи
            val groupKey2 = GroupManager.generateGroupKey()
            if (!groupKey.contentEquals(groupKey2)) {
                emit("  ✅ Генератор случаен: два ключа отличаются")
            } else {
                emit("  ❌ ПРОВАЛ: два ключа одинаковы (не случайные)!")
            }
            // Шифрование ключа для участника
            val myPublicKey = getPublicKeyString()
            val encryptedGroupKey = GroupManager.encryptGroupKeyForMember(groupKey, myPublicKey)
            emit("  Зашифрованный групповой ключ: ${encryptedGroupKey.take(40)}...")
            // Расшифровка
            val decryptedGroupKey = GroupManager.decryptGroupKey(encryptedGroupKey)
            if (groupKey.contentEquals(decryptedGroupKey)) {
                emit("  ✅ Распределение ключа: encrypt → decrypt совпадают")
            } else {
                emit("  ❌ ПРОВАЛ: расшифрованный ключ не совпадает!")
            }
        } catch (e: Exception) {
            emit("  ❌ ОШИБКА: ${e.message}")
        }
        emit()

        // ── Тест 12: GroupManager — шифрование сообщений ─────────────────────
        emit("📋 ТЕСТ 12: Группы — шифрование/расшифровка сообщений")
        try {
            val groupKey = GroupManager.generateGroupKey()
            val messages = listOf(
                "Привет группе! 👋",
                "Тест с эмодзи 🔐🛡️",
                "A".repeat(500)  // длинное сообщение
            )
            var allOk = true
            for (msg in messages) {
                val encrypted = GroupManager.encryptGroupMessage(msg, groupKey)
                val decrypted = GroupManager.decryptGroupMessage(encrypted, groupKey)
                if (decrypted != msg) { allOk = false; break }
            }
            if (allOk) {
                emit("  ✅ Round-trip: ${messages.size} сообщений (включая длинное)")
            } else {
                emit("  ❌ ПРОВАЛ: одно или несколько сообщений не совпали")
            }
            // Проверяем что IV случайный (два шифртекста одного сообщения различны)
            val groupKey2 = GroupManager.generateGroupKey()
            val enc1 = GroupManager.encryptGroupMessage("Same message", groupKey2)
            val enc2 = GroupManager.encryptGroupMessage("Same message", groupKey2)
            if (enc1 != enc2) {
                emit("  ✅ IV случаен: два шифртекста одного сообщения различны")
            } else {
                emit("  ❌ ПРОВАЛ: IV не случаен — два шифртекста совпадают!")
            }
            // GCM tamper detection
            val enc = GroupManager.encryptGroupMessage("Secret", groupKey)
            val decoded = android.util.Base64.decode(enc, android.util.Base64.NO_WRAP)
            decoded[decoded.size / 2] = (decoded[decoded.size / 2].toInt() xor 0xFF).toByte()
            val tampered = android.util.Base64.encodeToString(decoded, android.util.Base64.NO_WRAP)
            try {
                GroupManager.decryptGroupMessage(tampered, groupKey)
                emit("  ❌ ПРОВАЛ: GCM не поймал модификацию группового сообщения!")
            } catch (_: Exception) {
                emit("  ✅ GCM тампер-детект: модификация группового сообщения обнаружена")
            }
            // Неверный ключ → не расшифруется
            val wrongKey = GroupManager.generateGroupKey()
            val encMsg = GroupManager.encryptGroupMessage("Private", groupKey)
            try {
                GroupManager.decryptGroupMessage(encMsg, wrongKey)
                emit("  ❌ ПРОВАЛ: сообщение расшифровалось неверным ключом!")
            } catch (_: Exception) {
                emit("  ✅ Неверный ключ отклонён")
            }
        } catch (e: Exception) {
            emit("  ❌ ОШИБКА: ${e.message}")
        }
        emit()

        // ── Тесты 13–16: SessionKeyManager (X3DH + Ratchet) ─────────────────
        val aliceId = "_test_alice_${System.currentTimeMillis()}"
        val bobId   = "_test_bob_${System.currentTimeMillis()}"
        try {
            // Инициализируем если нужно
            SessionKeyManager.initialize(context)

            // ── Тест 13: X3DH инициация сессии ────────────────────────────────
            emit("📋 ТЕСТ 13: X3DH — инициация сессии")
            val bobBundleJson = SessionKeyManager.generatePrekeyBundle()
            val bobBundle     = SessionKeyManager.parsePrekeyBundle(bobBundleJson)
            val (_, x3dhHeader) = SessionKeyManager.initiateSession(aliceId, bobBundle)
            val aliceIdentity   = getPublicKeyString()
            SessionKeyManager.receiveSession(bobId, aliceIdentity, x3dhHeader)

            if (SessionKeyManager.hasSession(aliceId) && SessionKeyManager.hasSession(bobId)) {
                emit("  ✅ X3DH: сессии установлены у обеих сторон")
            } else {
                emit("  ❌ ПРОВАЛ: сессия не установлена!")
            }
            emit()

            // ── Тест 14: Encrypt/Decrypt round-trip ───────────────────────────
            emit("📋 ТЕСТ 14: Session — шифрование/расшифровка")
            val testMessages = listOf("Hello Bob 🔐", "Второе сообщение", "Third msg!")
            var sessionRoundTripOk = true
            for (msg in testMessages) {
                val (ct, hdr) = SessionKeyManager.encryptWithSession(aliceId, msg)
                val dec = SessionKeyManager.decryptWithSession(bobId, ct, hdr)
                if (dec != msg) { sessionRoundTripOk = false; break }
            }
            if (sessionRoundTripOk) {
                emit("  ✅ Round-trip: ${testMessages.size} сообщений (Alice→Bob)")
            } else {
                emit("  ❌ ПРОВАЛ: round-trip не совпадает")
            }
            // Bob → Alice
            val (ctB, hdrB) = SessionKeyManager.encryptWithSession(bobId, "Reply from Bob")
            val decB = SessionKeyManager.decryptWithSession(aliceId, ctB, hdrB)
            if (decB == "Reply from Bob") {
                emit("  ✅ Двусторонность: Bob→Alice работает")
            } else {
                emit("  ❌ ПРОВАЛ: Bob→Alice не работает")
            }
            // Разные ключи на каждое сообщение (шифртексты должны различаться)
            val (ct1, hdr1) = SessionKeyManager.encryptWithSession(aliceId, "Same")
            val (ct2, hdr2) = SessionKeyManager.encryptWithSession(aliceId, "Same")
            if (ct1 != ct2) {
                emit("  ✅ Ratchet: одно сообщение → разные шифртексты (ключи меняются)")
            } else {
                emit("  ❌ ПРОВАЛ: ratchet не продвигается!")
            }
            // Синхронизируем Bob — он должен получить ct1/ct2, чтобы счётчики совпали перед тестом 15
            SessionKeyManager.decryptWithSession(bobId, ct1, hdr1)
            SessionKeyManager.decryptWithSession(bobId, ct2, hdr2)
            emit()

            // ── Тест 15: Out-of-order доставка (skipped keys) ─────────────────
            emit("📋 ТЕСТ 15: Session — out-of-order доставка")
            // Alice шифрует 3 сообщения, Bob получает в порядке: 0, 2, 1
            val msgs = listOf("Out0", "Out1", "Out2")
            val encrypted15 = msgs.map { SessionKeyManager.encryptWithSession(aliceId, it) }
            // Доставляем 0 → OK
            val dec0 = SessionKeyManager.decryptWithSession(bobId, encrypted15[0].first, encrypted15[0].second)
            // Пропускаем 1, доставляем 2 → должно буфернуть ключ от msg1
            val dec2 = SessionKeyManager.decryptWithSession(bobId, encrypted15[2].first, encrypted15[2].second)
            // Доставляем 1 из буфера skipped keys
            val dec1 = SessionKeyManager.decryptWithSession(bobId, encrypted15[1].first, encrypted15[1].second)
            if (dec0 == "Out0" && dec1 == "Out1" && dec2 == "Out2") {
                emit("  ✅ Out-of-order: все 3 сообщения расшифрованы корректно")
            } else {
                emit("  ❌ ПРОВАЛ: out-of-order доставка не работает")
                emit("     dec0='$dec0', dec1='$dec1', dec2='$dec2'")
            }
            emit()

            // ── Тест 16: Изоляция сессий ──────────────────────────────────────
            emit("📋 ТЕСТ 16: Session — изоляция (неверный контакт)")
            val (ctIso, hdrIso) = SessionKeyManager.encryptWithSession(aliceId, "Secret")
            // Попытка расшифровать с неверным contactId (другой receive chain)
            try {
                val fakeDecrypt = SessionKeyManager.decryptWithSession(aliceId, ctIso, hdrIso)
                // Alice пытается расшифровать своё собственное сообщение — своим receive chain
                // Это должно либо выбросить исключение, либо дать мусор
                emit("  ⚠️ Чтение своего шифртекста своим ключом: '$fakeDecrypt'")
                emit("  ℹ️ (Alice отправляла sendChain, читает recvChain — ожидаем мусор)")
            } catch (_: Exception) {
                emit("  ✅ Изоляция: попытка расшифровать чужим ключом отклонена")
            }

        } catch (e: Exception) {
            emit("  ❌ ОШИБКА в сессионных тестах: ${e.message}")
        } finally {
            // Всегда чистим тестовые сессии
            SessionKeyManager.deleteSession(aliceId)
            SessionKeyManager.deleteSession(bobId)
        }

        emit()
        emit("═══════════════════════════════════════")
        emit("📊 ИТОГ РАСШИРЕННЫХ ТЕСТОВ")
        emit("═══════════════════════════════════════")
        emit("Покрыто: HKDF · AES-GCM · GroupManager · X3DH · Ratchet · Out-of-order")
        emit("Если видишь ❌ ПРОВАЛ — это критическая проблема!")
        emit("═══════════════════════════════════════")

        return report.toString()
    }

}





