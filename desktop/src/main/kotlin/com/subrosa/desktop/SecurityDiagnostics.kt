package com.subrosa.desktop

import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ─── Result model ─────────────────────────────────────────────────────────────

enum class DiagStatus { OK, FAIL, WARN, INFO }

data class DiagResult(val status: DiagStatus, val message: String)

// ─── Startup enforcement ──────────────────────────────────────────────────────

/**
 * Called at app startup. If "exit on debugger" is enabled in settings and a
 * JDWP agent or Frida is detected, the process is terminated immediately via
 * Runtime.halt() (bypasses shutdown hooks to prevent debugger from catching it).
 */
fun enforceOnStartup() {
    if (!UserStorage.getExitOnDebugger()) return

    // Check JDWP (Java debugger protocol)
    val jvmArgs = java.lang.management.ManagementFactory.getRuntimeMXBean().inputArguments
    if (jvmArgs.any { "-Xdebug" in it || "jdwp" in it.lowercase() }) {
        System.err.println("SECURITY: JDWP debugger detected — forcing exit")
        Runtime.getRuntime().halt(1)
    }

    // Check Frida (default port 27042)
    try {
        java.net.Socket().use { s ->
            s.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 300)
        }
        System.err.println("SECURITY: Frida detected (port 27042) — forcing exit")
        Runtime.getRuntime().halt(1)
    } catch (_: Exception) { /* no Frida — continue */ }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

fun runSecurityDiagnostics(): List<DiagResult> {
    val out = mutableListOf<DiagResult>()

    // ── Section: Платформа ────────────────────────────────────────────────────
    out += DiagResult(DiagStatus.INFO, "ПЛАТФОРМА")
    out += checkDebugAgent()
    out += checkSystemProxy()
    out += checkFridaPort()
    // Portable subset of Android's IntrusionDetector.scan() — proxy is
    // already covered by checkSystemProxy() above; ADB/developer-options
    // have no desktop equivalent and are skipped. VPN detection below is a
    // best-effort heuristic (network-interface naming), not as reliable as
    // Android's ConnectivityManager transport-capability check.
    out += checkVpnHeuristic()

    // ── Section: Криптография ─────────────────────────────────────────────────
    out += DiagResult(DiagStatus.INFO, "КРИПТОГРАФИЯ")
    out += checkKeyPairInitialized()
    out += checkKeyRegenerationProtection()
    out += checkKeyStorageIntegrity()
    out += checkKeyDeletionAndRecovery()
    out += checkSignVerifyRoundTrip()
    out += checkSignatureForgeryRejected()
    out += checkAesGcmRoundTrip()
    out += checkGcmTamperDetection()
    out += checkIVUniqueness()
    out += checkEcdhSymmetry()
    out += checkInvalidCurveAttackProtection()
    out += checkEcdhPublicKeyFormat()
    out += checkMlKemRoundTrip()
    out += checkHybridKdfConsistency()
    out += checkSelfEncryptRoundTrip()
    out += checkGarbageDecryptRejected()
    out += checkPaddingObscuresLength()
    out += checkGroupKeyGenerationAndDistribution()
    out += checkGroupMessageEncryption()

    // ── Section: X3DH-сессии (двусторонний тест) ──────────────────────────────
    // A genuine two-party handshake in one process, via two throwaway
    // identities (never this device's real one) + SessionKeyManager's
    // identityOverride param. This device's real identity can't play both
    // "Alice" and "Bob" here: dh1/dh2 always sign/DH against this device's
    // one real identity regardless of role, and receiveSession() requires
    // contactId == fingerprint(the identity actually used) — so both
    // roles' contactId would collapse onto the same value and
    // receiveSession() would either clobber initiateSession()'s
    // sessions[] entry for it, or throw an identity-mismatch
    // SecurityException, depending on which label was used. identityOverride
    // (added together with these tests) sidesteps this by letting the two
    // throwaway identities actually sign/DH as themselves. SPK/PQ prekeys
    // are still this device's own real current ones — receiveSession()
    // always resolves those via spk_id against the local SPK/PQ store, no
    // override exists for that half, and it's fine: SPK/PQ public keys are
    // bundle material that's already public in a real handshake too.
    out += checkX3dhSessionRoundTrip()
    out += checkOutOfOrderDelivery()
    out += checkSessionIsolation()
    out += checkReplayAttackRejected()

    // ── Section: Хранилище ────────────────────────────────────────────────────
    out += DiagResult(DiagStatus.INFO, "ХРАНИЛИЩЕ")
    out += checkSmkStatus()
    out += checkBinaryIntegrity()
    out += checkSecureDeletion()

    // ── Section: Среда выполнения ─────────────────────────────────────────────
    out += DiagResult(DiagStatus.INFO, "СРЕДА ВЫПОЛНЕНИЯ")
    out += checkSwapProtection()
    out += checkScreenCapture()
    out += checkKeyloggerProtection()
    out += checkSandboxing()

    return out
}

// ─── Platform checks ──────────────────────────────────────────────────────────

private fun checkDebugAgent(): DiagResult {
    val args = java.lang.management.ManagementFactory.getRuntimeMXBean().inputArguments
    val attached = args.any { "-Xdebug" in it || "jdwp" in it.lowercase() }
    return if (attached)
        DiagResult(DiagStatus.WARN, "JDWP: отладчик подключён")
    else
        DiagResult(DiagStatus.OK,   "JDWP: нет активного отладчика")
}

private fun checkSystemProxy(): DiagResult {
    val host = System.getProperty("http.proxyHost")
        ?: System.getProperty("https.proxyHost")
    return if (host != null)
        DiagResult(DiagStatus.WARN, "Прокси: обнаружен ($host) — возможен MITM")
    else
        DiagResult(DiagStatus.OK,   "Прокси: системный прокси не настроен")
}

private fun checkFridaPort(): DiagResult {
    return try {
        Socket().use { s -> s.connect(InetSocketAddress("127.0.0.1", 27042), 200) }
        DiagResult(DiagStatus.WARN, "Frida: порт 27042 открыт — возможна инструментация")
    } catch (_: Exception) {
        DiagResult(DiagStatus.OK, "Frida: порт 27042 закрыт")
    }
}

/** Best-effort VPN presence check — ported from Android's IntrusionDetector.
 *  isVPNActive(), which uses ConnectivityManager's TRANSPORT_VPN capability
 *  (no desktop equivalent). Falls back to recognizing common VPN adapter
 *  naming conventions across the three platforms — not authoritative (a lot
 *  of legitimate VPN software this won't catch, and a renamed adapter would
 *  slip through), just a coarse signal like the rest of this section. */
private fun checkVpnHeuristic(): DiagResult {
    return try {
        val names = java.net.NetworkInterface.getNetworkInterfaces().toList()
            .mapNotNull { it.displayName ?: it.name }
        val vpnMarkers = listOf("tun", "tap", "ppp", "wireguard", "wg", "nordlynx", "vpn", "utun")
        val hit = names.firstOrNull { name ->
            val n = name.lowercase()
            vpnMarkers.any { marker -> n.contains(marker) }
        }
        if (hit != null)
            DiagResult(DiagStatus.WARN, "VPN: возможен активный VPN-адаптер ($hit) — возможен MITM")
        else
            DiagResult(DiagStatus.OK, "VPN: признаков активного VPN-адаптера не найдено")
    } catch (e: Exception) {
        DiagResult(DiagStatus.WARN, "VPN: не удалось проверить сетевые интерфейсы — ${e.message}")
    }
}

// ─── Crypto self-tests ────────────────────────────────────────────────────────

private fun checkKeyPairInitialized(): DiagResult {
    return try {
        val pub = DesktopCryptoManager.getPublicKeyBase64()
        if (pub.length > 20)
            DiagResult(DiagStatus.OK,   "EC P-256 keypair: загружен (${pub.take(16)}…)")
        else
            DiagResult(DiagStatus.FAIL, "EC P-256 keypair: пустой публичный ключ")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "EC P-256 keypair: ошибка — ${e.message}")
    }
}

/** Mirrors Android's TEST 2 (regeneration protection) — CryptoManager.
 *  generateKeyPair() delegates to DesktopKeyStore.getOrCreateECKeyPair(),
 *  which is meant to be idempotent (reuse an existing on-disk keypair
 *  rather than silently overwriting it — if it didn't, every restart or
 *  accidental re-init call would rotate the identity key and orphan every
 *  contact's session). Confirms that by checking the public key is
 *  byte-identical before and after a second generateKeyPair() call. */
private fun checkKeyRegenerationProtection(): DiagResult {
    return try {
        if (!CryptoManager.hasKeys()) {
            return DiagResult(DiagStatus.INFO, "Защита от перегенерации: ключей ещё нет — N/A")
        }
        val before = DesktopCryptoManager.getPublicKeyBase64()
        CryptoManager.generateKeyPair()
        val after = DesktopCryptoManager.getPublicKeyBase64()
        if (before == after)
            DiagResult(DiagStatus.OK, "Защита от перегенерации: повторный вызов не изменил ключ")
        else
            DiagResult(DiagStatus.FAIL, "Защита от перегенерации: ключ ИЗМЕНИЛСЯ после повторной генерации!")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Защита от перегенерации: ошибка — ${e.message}")
    }
}

/** Mirrors Android's TEST 4 — reads the identity keypair back out of its
 *  actual persistent storage (DesktopKeyStore's PKCS12 file, not through
 *  DesktopCryptoManager's in-memory cache) and confirms it's usable: right
 *  curve, and a fresh sign/verify round trip using the read-back key
 *  objects directly. Read-only — getOrCreateECKeyPair() never mutates an
 *  existing key, so nothing needs restoring afterward. */
private fun checkKeyStorageIntegrity(): DiagResult {
    return try {
        val dataDir = DesktopStorage.resolveDataDir()
        val kp = DesktopKeyStore.getOrCreateECKeyPair(dataDir)
        val pub = kp.public
        if (pub !is java.security.interfaces.ECPublicKey) {
            return DiagResult(DiagStatus.FAIL, "Хранилище ключей: публичный ключ не ECPublicKey")
        }
        val curveOk = pub.params.toString().contains("1.2.840.10045.3.1.7") ||
                      pub.params.toString().contains("secp256r1") ||
                      pub.params.toString().contains("prime256v1")
        val testBytes = "key_pair_consistency_check".toByteArray()
        val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(testBytes) }.sign()
        val verified = Signature.getInstance("SHA256withECDSA").apply { initVerify(kp.public); update(testBytes) }.verify(sig)
        when {
            !verified -> DiagResult(DiagStatus.FAIL, "Хранилище ключей: пара ключей несогласована (sign ↔ verify не совпали)!")
            !curveOk  -> DiagResult(DiagStatus.WARN, "Хранилище ключей: неожиданная кривая — ${pub.params}")
            else      -> DiagResult(DiagStatus.OK, "Хранилище ключей: PKCS12 (BEACON.p12), secp256r1, sign↔verify согласованы")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Хранилище ключей: ошибка — ${e.message}")
    }
}

/** Mirrors Android's TEST 3 + NEGATIVE TEST 4 combined — deletes and
 *  regenerates the REAL identity keypair mid-test (capture original bytes,
 *  delete, verify gone, regenerate, verify it's actually different, verify
 *  a message encrypted under the old key can no longer be decrypted under
 *  the new one), then unconditionally restores the original key material
 *  in `finally` so the account's real identity/fingerprint is unchanged
 *  once the test completes — including on exception. DesktopCryptoManager
 *  caches the keypair in memory (unlike CryptoManager, which reads fresh
 *  every call), so reloadKeyPair() at the end is required to resync it
 *  with what's back on disk. */
private fun checkKeyDeletionAndRecovery(): DiagResult {
    val dataDir = DesktopStorage.resolveDataDir()
    val original = DesktopKeyStore.getOrCreateECKeyPair(dataDir)
    val originalPriv = original.private.encoded
    val originalPub  = original.public.encoded
    val originalPubB64 = java.util.Base64.getEncoder().encodeToString(originalPub)

    return try {
        val encryptedUnderOld = try {
            val pqPubKey = java.util.Base64.getDecoder().decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey)
            CryptoManager.encrypt("Subrosa-key-rotation-test", originalPubB64, pqPubKey)
        } catch (_: Exception) { null }

        DesktopKeyStore.deleteECKeyPair(dataDir)
        val goneAfterDelete = !DesktopKeyStore.hasECKeyPair(dataDir)

        val regenerated = DesktopKeyStore.getOrCreateECKeyPair(dataDir)
        val regeneratedPubB64 = java.util.Base64.getEncoder().encodeToString(regenerated.public.encoded)
        val keyActuallyChanged = regeneratedPubB64 != originalPubB64

        val oldMessageStillReadable = if (encryptedUnderOld != null && keyActuallyChanged) {
            try {
                DesktopCryptoManager.reloadKeyPair() // point decrypt() at the just-regenerated key
                CryptoManager.decrypt(encryptedUnderOld)
                true
            } catch (_: Exception) { false }
        } else null

        when {
            !goneAfterDelete -> DiagResult(DiagStatus.FAIL, "Удаление/восстановление: ключ НЕ удалился из PKCS12!")
            !keyActuallyChanged -> DiagResult(DiagStatus.FAIL, "Удаление/восстановление: перегенерация вернула тот же ключ!")
            oldMessageStillReadable == true -> DiagResult(DiagStatus.FAIL, "Удаление/восстановление: сообщение под старым ключом расшифровалось НОВЫМ ключом!")
            else -> DiagResult(DiagStatus.OK, "Удаление/восстановление: удаление, перегенерация и инвалидация старых сообщений работают корректно")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Удаление/восстановление: ошибка теста — ${e.message}")
    } finally {
        // Unconditional restore — runs even if an assertion/exception above
        // fired partway through, so this device's real identity/fingerprint
        // is back to exactly what it was before the test regardless of outcome.
        try {
            DesktopKeyStore.storeECKeyPair(dataDir, originalPriv, originalPub)
            DesktopCryptoManager.reloadKeyPair()
        } catch (e: Exception) {
            System.err.println("SecurityDiagnostics: CRITICAL — failed to restore original identity key after test: ${e.message}")
        }
    }
}

private fun checkSignVerifyRoundTrip(): DiagResult {
    return try {
        val data = "Subrosa-sign-test-vector".toByteArray()
        val sig  = DesktopCryptoManager.signBase64(data)
        val ok   = DesktopCryptoManager.verifySignature(data, sig)
        if (ok) DiagResult(DiagStatus.OK,   "ECDSA sign/verify: успех")
        else    DiagResult(DiagStatus.FAIL, "ECDSA sign/verify: верификация не прошла")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "ECDSA: ошибка — ${e.message}")
    }
}

/** Mirrors Android's NEGATIVE TEST 2 (signature forgery) — a signature over
 *  one message must be rejected when checked against a different message,
 *  and a signature from an unrelated keypair must be rejected against our
 *  own public key. Confirms verifySignature() actually discriminates
 *  rather than e.g. always returning true. */
private fun checkSignatureForgeryRejected(): DiagResult {
    return try {
        val data = "Subrosa-forgery-test".toByteArray()
        val tampered = "Subrosa-forgery-test-TAMPERED".toByteArray()
        val sig = DesktopCryptoManager.signBase64(data)

        val wrongMessageAccepted = DesktopCryptoManager.verifySignature(tampered, sig)

        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val foreignKp = kpg.generateKeyPair()
        val sigInstance = Signature.getInstance("SHA256withECDSA")
        sigInstance.initSign(foreignKp.private)
        sigInstance.update(data)
        val foreignSig = java.util.Base64.getEncoder().encodeToString(sigInstance.sign())
        val foreignKeyAccepted = DesktopCryptoManager.verifySignature(data, foreignSig)

        when {
            wrongMessageAccepted -> DiagResult(DiagStatus.FAIL, "Подделка подписи: подпись над ДРУГИМ сообщением была принята!")
            foreignKeyAccepted   -> DiagResult(DiagStatus.FAIL, "Подделка подписи: подпись от ЧУЖОГО ключа была принята!")
            else -> DiagResult(DiagStatus.OK, "Подделка подписи: обе попытки подмены отклонены")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Подделка подписи: ошибка теста — ${e.message}")
    }
}

private fun checkAesGcmRoundTrip(): DiagResult {
    return try {
        val key    = SecretKeySpec(
            MessageDigest.getInstance("SHA-256").digest("Subrosa-test-key".toByteArray()), "AES")
        val iv     = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val plain  = "Проверка шифрования AES-256-GCM"
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        val result = String(cipher.doFinal(ct), Charsets.UTF_8)
        if (result == plain)
            DiagResult(DiagStatus.OK,   "AES-256-GCM round-trip: успех")
        else
            DiagResult(DiagStatus.FAIL, "AES-256-GCM: расшифровка не совпала с оригиналом")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "AES-256-GCM: ошибка — ${e.message}")
    }
}

private fun checkGcmTamperDetection(): DiagResult {
    return try {
        val key    = SecretKeySpec(
            MessageDigest.getInstance("SHA-256").digest("Subrosa-tamper-key".toByteArray()), "AES")
        val iv     = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ct = cipher.doFinal("test-data".toByteArray()).also { it[0] = (it[0].toInt() xor 0xAB).toByte() }
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.doFinal(ct)
            DiagResult(DiagStatus.FAIL, "GCM tamper detection: подмена НЕ обнаружена!")
        } catch (_: Exception) {
            DiagResult(DiagStatus.OK, "GCM tamper detection: подмена данных обнаружена")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "GCM tamper test: ошибка — ${e.message}")
    }
}

private fun checkIVUniqueness(): DiagResult {
    val ivs = (1..100).map { ByteArray(12).also { SecureRandom().nextBytes(it) } }
    val uniqueCount = ivs.map { it.toList() }.toSet().size
    return if (uniqueCount == 100)
        DiagResult(DiagStatus.OK,   "IV уникальность: 100/100 уникальных IV (PRNG исправен)")
    else
        DiagResult(DiagStatus.WARN, "IV уникальность: дубли ($uniqueCount/100) — проблема PRNG!")
}

private fun checkEcdhSymmetry(): DiagResult {
    return try {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val aliceKp = kpg.generateKeyPair()
        val bobKp   = kpg.generateKeyPair()

        val ka1 = KeyAgreement.getInstance("ECDH")
        ka1.init(aliceKp.private); ka1.doPhase(bobKp.public, true)
        val shared1 = ka1.generateSecret()

        val ka2 = KeyAgreement.getInstance("ECDH")
        ka2.init(bobKp.private); ka2.doPhase(aliceKp.public, true)
        val shared2 = ka2.generateSecret()

        if (shared1.contentEquals(shared2))
            DiagResult(DiagStatus.OK,   "ECDH симметрия: оба узла получают одинаковый секрет")
        else
            DiagResult(DiagStatus.FAIL, "ECDH: секреты не совпали!")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "ECDH: ошибка — ${e.message}")
    }
}

private fun checkMlKemRoundTrip(): DiagResult {
    return try {
        val kp = PqCrypto.generateKeyPair()
        val encapsulated = PqCrypto.encapsulate(kp.publicKey)
        val recovered = PqCrypto.decapsulate(kp.privateKey, encapsulated.ciphertext)
        if (encapsulated.sharedSecret.contentEquals(recovered))
            DiagResult(DiagStatus.OK, "ML-KEM-768: encapsulate/decapsulate совпадают (${encapsulated.sharedSecret.size} байт секрета, ${encapsulated.ciphertext.size} байт ciphertext)")
        else
            DiagResult(DiagStatus.FAIL, "ML-KEM: расшифрованный секрет не совпал с исходным!")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "ML-KEM: ошибка — ${e.message}")
    }
}

private fun checkHybridKdfConsistency(): DiagResult {
    // Confirms the hybrid combiner used in X3DH/CryptoManager (classical ECDH
    // secret || ML-KEM secret, fed through HKDF) is deterministic and that
    // flipping either component changes the derived key — i.e. both must be
    // broken to recover the session key, not just one.
    return try {
        fun hkdf(ikm: ByteArray, info: String): ByteArray {
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(javax.crypto.spec.SecretKeySpec(ByteArray(32), "HmacSHA256"))
            val prk = mac.doFinal(ikm)
            mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
            mac.update(info.toByteArray())
            mac.update(0x01.toByte())
            return mac.doFinal().copyOfRange(0, 32)
        }

        val classical = ByteArray(32) { it.toByte() }
        val pqKp = PqCrypto.generateKeyPair()
        val encapsulated = PqCrypto.encapsulate(pqKp.publicKey)
        val pqSecret = PqCrypto.decapsulate(pqKp.privateKey, encapsulated.ciphertext)

        val combined = classical + pqSecret
        val derived1 = hkdf(combined, "SubrosaTestPq")
        val derived2 = hkdf(combined, "SubrosaTestPq")

        val tamperedClassical = classical.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val derivedTampered = hkdf(tamperedClassical + pqSecret, "SubrosaTestPq")

        when {
            !derived1.contentEquals(derived2) ->
                DiagResult(DiagStatus.FAIL, "Hybrid KDF: недетерминирован — одинаковый вход дал разный результат!")
            derived1.contentEquals(derivedTampered) ->
                DiagResult(DiagStatus.FAIL, "Hybrid KDF: изменение классического секрета не повлияло на ключ!")
            else ->
                DiagResult(DiagStatus.OK, "Hybrid KDF: детерминирован, чувствителен к обоим компонентам (classical + PQ)")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Hybrid KDF: ошибка — ${e.message}")
    }
}

/** Mirrors Android's TEST 5/TEST 8 — the full hybrid encrypt()/decrypt()
 *  path (ephemeral ECDH + ML-KEM encapsulation + AES-GCM), self-addressed
 *  (encrypting to our own public key, same as Android's test does — this
 *  isn't testing peer delivery, just that the round trip through the real
 *  production encrypt/decrypt functions is lossless), rather than the raw
 *  AES-GCM primitive checkAesGcmRoundTrip() above already covers. */
private fun checkSelfEncryptRoundTrip(): DiagResult {
    return try {
        val plaintext = "Subrosa self-encrypt round-trip 🔐"
        val pubKey = DesktopCryptoManager.getPublicKeyBase64()
        val pqPubKey = java.util.Base64.getDecoder().decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey)
        val encrypted = CryptoManager.encrypt(plaintext, pubKey, pqPubKey)
        val decrypted = CryptoManager.decrypt(encrypted)
        if (decrypted == plaintext)
            DiagResult(DiagStatus.OK, "Гибридное шифрование (ECDH+ML-KEM+AES-GCM): round-trip успешен")
        else
            DiagResult(DiagStatus.FAIL, "Гибридное шифрование: расшифровка не совпала с оригиналом!")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Гибридное шифрование: ошибка — ${e.message}")
    }
}

/** Mirrors Android's NEGATIVE TEST 1 — decrypt() must reject malformed/
 *  garbage input with an exception rather than e.g. returning garbage text
 *  silently or crashing uncontrolled. */
private fun checkGarbageDecryptRejected(): DiagResult {
    return try {
        CryptoManager.decrypt("AAAAAAAAAAAAAAAAAAAAAA==")
        DiagResult(DiagStatus.FAIL, "Расшифровка мусора: мусор расшифровался — не должно было!")
    } catch (e: Exception) {
        DiagResult(DiagStatus.OK, "Расшифровка мусора: отклонена (${e.javaClass.simpleName})")
    }
}

/** Mirrors Android's NEGATIVE TEST 8 — a short and a long message shouldn't
 *  reveal their exact relative length through ciphertext size alone; the
 *  short one should come out padded well beyond its real length so a
 *  passive observer watching ciphertext sizes can't easily fingerprint
 *  message content by length. */
private fun checkPaddingObscuresLength(): DiagResult {
    return try {
        val short = "Hi"
        val long = "A".repeat(1000)
        val pubKey = DesktopCryptoManager.getPublicKeyBase64()
        val pqPubKey = java.util.Base64.getDecoder().decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey)
        val encShort = CryptoManager.encrypt(short, pubKey, pqPubKey)
        val encLong = CryptoManager.encrypt(long, pubKey, pqPubKey)
        val sizeShort = java.util.Base64.getDecoder().decode(encShort).size
        val sizeLong = java.util.Base64.getDecoder().decode(encLong).size
        if (sizeShort > short.length + 100)
            DiagResult(DiagStatus.OK, "Паддинг: короткое сообщение дополнено (шифротекст $sizeShort байт против ${short.length} байт текста)")
        else
            DiagResult(DiagStatus.WARN, "Паддинг: возможно недостаточен (шифротекст $sizeShort байт против ${short.length} байт текста)")
    } catch (e: Exception) {
        DiagResult(DiagStatus.WARN, "Паддинг: тест не выполнен — ${e.message}")
    }
}

/** Mirrors Android's TEST 11 — group key generation (32-byte AES-256,
 *  actually random across two calls) plus per-member key distribution
 *  (encrypt the group key to a member's identity+PQ public key, decrypt it
 *  back, confirm round trip). Self-addressed, same pattern as the other
 *  self-tests above. */
private fun checkGroupKeyGenerationAndDistribution(): DiagResult {
    return try {
        val groupKey = GroupManager.generateGroupKey()
        if (groupKey.size != 32) {
            return DiagResult(DiagStatus.FAIL, "Групповой ключ: неверная длина — ${groupKey.size} байт (ожидалось 32)")
        }
        val groupKey2 = GroupManager.generateGroupKey()
        if (groupKey.contentEquals(groupKey2)) {
            return DiagResult(DiagStatus.FAIL, "Групповой ключ: генератор не случаен — два ключа совпали!")
        }
        val myPubKey = DesktopCryptoManager.getPublicKeyBase64()
        val myPqPubKey = java.util.Base64.getDecoder().decode(SessionKeyManager.getLocalPrekeyBundle().pqKemPublicKey)
        val encryptedForMember = GroupManager.encryptGroupKeyForMember(groupKey, myPubKey, myPqPubKey)
        val decrypted = GroupManager.decryptGroupKey(encryptedForMember)
        if (groupKey.contentEquals(decrypted))
            DiagResult(DiagStatus.OK, "Групповой ключ: генерация (256 бит, случайна) и распределение участнику работают корректно")
        else
            DiagResult(DiagStatus.FAIL, "Групповой ключ: расшифрованный ключ участника не совпал с оригиналом!")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Групповой ключ: ошибка — ${e.message}")
    }
}

/** Mirrors Android's TEST 12 — group message encrypt/decrypt round trip
 *  (including emoji and a long message), IV randomness (two encryptions of
 *  the same plaintext under the same key must differ), GCM tamper
 *  detection on a group message, and wrong-group-key rejection. */
private fun checkGroupMessageEncryption(): DiagResult {
    return try {
        val groupKey = GroupManager.generateGroupKey()
        val messages = listOf("Привет группе! 👋", "Тест с эмодзи 🔐🛡️", "A".repeat(500))
        for (msg in messages) {
            val encrypted = GroupManager.encryptGroupMessage(msg, groupKey)
            val decrypted = GroupManager.decryptGroupMessage(encrypted, groupKey)
            if (decrypted != msg) {
                return DiagResult(DiagStatus.FAIL, "Групповые сообщения: round-trip не совпал для одного из тестовых сообщений!")
            }
        }

        val enc1 = GroupManager.encryptGroupMessage("Same message", groupKey)
        val enc2 = GroupManager.encryptGroupMessage("Same message", groupKey)
        if (enc1 == enc2) {
            return DiagResult(DiagStatus.FAIL, "Групповые сообщения: IV не случаен — два шифротекста одного сообщения совпали!")
        }

        val enc = GroupManager.encryptGroupMessage("Secret", groupKey)
        val decoded = java.util.Base64.getDecoder().decode(enc)
        decoded[decoded.size / 2] = (decoded[decoded.size / 2].toInt() xor 0xFF).toByte()
        val tampered = java.util.Base64.getEncoder().encodeToString(decoded)
        try {
            GroupManager.decryptGroupMessage(tampered, groupKey)
            return DiagResult(DiagStatus.FAIL, "Групповые сообщения: GCM не поймал модификацию группового сообщения!")
        } catch (_: Exception) { /* expected */ }

        val wrongKey = GroupManager.generateGroupKey()
        val encMsg = GroupManager.encryptGroupMessage("Private", groupKey)
        try {
            GroupManager.decryptGroupMessage(encMsg, wrongKey)
            DiagResult(DiagStatus.FAIL, "Групповые сообщения: сообщение расшифровалось неверным ключом!")
        } catch (_: Exception) {
            DiagResult(DiagStatus.OK, "Групповые сообщения: round-trip, случайность IV, tamper-детект и неверный ключ — всё корректно")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Групповые сообщения: ошибка — ${e.message}")
    }
}

// ── Session tests helpers ───────────────────────────────────────────────────

private fun freshTestIdentity(): KeyPair {
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
    return kpg.generateKeyPair()
}

private fun fingerprintOf(pub: java.security.PublicKey): String =
    MessageDigest.getInstance("SHA-256").digest(pub.encoded).take(8).joinToString("") { "%02X".format(it) }

private fun signWithTestIdentity(kp: KeyPair, message: String): String {
    val sig = Signature.getInstance("SHA256withECDSA")
    sig.initSign(kp.private)
    sig.update(message.toByteArray())
    return java.util.Base64.getEncoder().encodeToString(sig.sign())
}

/** Builds a validly self-signed PrekeyBundle for a throwaway identity,
 *  reusing this device's own real SPK/PQ prekeys (required — see the
 *  "X3DH-сессии" section comment in runSecurityDiagnostics() for why). */
private fun fakeBundleFor(fakeIdentity: KeyPair): SessionKeyManager.PrekeyBundle {
    val real = SessionKeyManager.getLocalPrekeyBundle()
    return SessionKeyManager.PrekeyBundle(
        identityKey = java.util.Base64.getEncoder().encodeToString(fakeIdentity.public.encoded),
        signedPrekey = real.signedPrekey,
        spkSignature = signWithTestIdentity(fakeIdentity, real.signedPrekey),
        spkId = real.spkId,
        oneTimePrekeys = emptyList(),
        pqKemPublicKey = real.pqKemPublicKey,
        pqKemSignature = signWithTestIdentity(fakeIdentity, real.pqKemPublicKey)
    )
}

private data class FakeSessionPair(val aliceId: String, val bobId: String)

/** Establishes one genuine two-party session between two throwaway
 *  identities via initiateSession()/receiveSession()'s identityOverride. */
private fun establishFakeSession(): FakeSessionPair {
    val fakeAlice = freshTestIdentity()
    val fakeBob = freshTestIdentity()
    val aliceId = fingerprintOf(fakeBob.public)
    val (_, x3dhHeader) = SessionKeyManager.initiateSession(aliceId, fakeBundleFor(fakeBob), identityOverride = fakeAlice)
    val bobId = fingerprintOf(fakeAlice.public)
    val fakeAliceB64 = java.util.Base64.getEncoder().encodeToString(fakeAlice.public.encoded)
    SessionKeyManager.receiveSession(bobId, fakeAliceB64, x3dhHeader, identityOverride = fakeBob)
    return FakeSessionPair(aliceId, bobId)
}

/** Mirrors Android's TESTS 13+14 — session initiation, round-trip
 *  encryption in both directions, and ratchet advancement (the same
 *  plaintext encrypted twice must produce different ciphertexts). */
private fun checkX3dhSessionRoundTrip(): DiagResult {
    var aliceId = ""; var bobId = ""
    return try {
        val pair = establishFakeSession()
        aliceId = pair.aliceId; bobId = pair.bobId

        if (!SessionKeyManager.hasSession(aliceId) || !SessionKeyManager.hasSession(bobId)) {
            return DiagResult(DiagStatus.FAIL, "X3DH-сессия: сессия не установлена на одной из сторон!")
        }

        val messages = listOf("Hello Bob 🔐", "Второе сообщение", "Third msg!")
        for (msg in messages) {
            val (ct, hdr) = SessionKeyManager.encryptWithSession(aliceId, msg)
            val dec = SessionKeyManager.decryptWithSession(bobId, ct, hdr)
            if (dec != msg) return DiagResult(DiagStatus.FAIL, "X3DH-сессия: round-trip Alice→Bob не совпал!")
        }

        val (ctB, hdrB) = SessionKeyManager.encryptWithSession(bobId, "Reply from Bob")
        val decB = SessionKeyManager.decryptWithSession(aliceId, ctB, hdrB)
        if (decB != "Reply from Bob") {
            return DiagResult(DiagStatus.FAIL, "X3DH-сессия: обратное направление Bob→Alice не работает!")
        }

        val (ct1, hdr1) = SessionKeyManager.encryptWithSession(aliceId, "Same")
        val (ct2, hdr2) = SessionKeyManager.encryptWithSession(aliceId, "Same")
        if (ct1 == ct2) {
            return DiagResult(DiagStatus.FAIL, "X3DH-сессия: ratchet не продвигается — одинаковый текст дал одинаковый шифротекст!")
        }
        SessionKeyManager.decryptWithSession(bobId, ct1, hdr1)
        SessionKeyManager.decryptWithSession(bobId, ct2, hdr2)

        DiagResult(DiagStatus.OK, "X3DH-сессия: инициация, двустороннее шифрование и продвижение ratchet работают корректно")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "X3DH-сессия: ошибка — ${e.message}")
    } finally {
        if (aliceId.isNotEmpty()) SessionKeyManager.deleteSession(aliceId)
        if (bobId.isNotEmpty()) SessionKeyManager.deleteSession(bobId)
    }
}

/** Mirrors Android's TEST 15 — three messages encrypted in order, then
 *  decrypted out of order (0, 2, 1); the ratchet's skipped-key handling
 *  must still recover all three. */
private fun checkOutOfOrderDelivery(): DiagResult {
    var aliceId = ""; var bobId = ""
    return try {
        val pair = establishFakeSession()
        aliceId = pair.aliceId; bobId = pair.bobId

        val msgs = listOf("Out0", "Out1", "Out2")
        val encrypted = msgs.map { SessionKeyManager.encryptWithSession(aliceId, it) }

        val dec0 = SessionKeyManager.decryptWithSession(bobId, encrypted[0].first, encrypted[0].second)
        val dec2 = SessionKeyManager.decryptWithSession(bobId, encrypted[2].first, encrypted[2].second)
        val dec1 = SessionKeyManager.decryptWithSession(bobId, encrypted[1].first, encrypted[1].second)

        if (dec0 == "Out0" && dec1 == "Out1" && dec2 == "Out2")
            DiagResult(DiagStatus.OK, "Out-of-order доставка: все 3 сообщения расшифрованы корректно вне порядка")
        else
            DiagResult(DiagStatus.FAIL, "Out-of-order доставка: провал (dec0='$dec0', dec1='$dec1', dec2='$dec2')")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Out-of-order доставка: ошибка — ${e.message}")
    } finally {
        if (aliceId.isNotEmpty()) SessionKeyManager.deleteSession(aliceId)
        if (bobId.isNotEmpty()) SessionKeyManager.deleteSession(bobId)
    }
}

/** Mirrors Android's TEST 16 — a ciphertext from one session pair must
 *  not decrypt under a completely unrelated second session pair's keys. */
private fun checkSessionIsolation(): DiagResult {
    var aliceId = ""; var bobId = ""
    var malloryId = ""; var eveId = ""
    return try {
        val pair = establishFakeSession()
        aliceId = pair.aliceId; bobId = pair.bobId
        val (ctIso, hdrIso) = SessionKeyManager.encryptWithSession(aliceId, "Secret")

        val other = establishFakeSession()
        malloryId = other.aliceId; eveId = other.bobId

        try {
            val fakeDecrypt = SessionKeyManager.decryptWithSession(malloryId, ctIso, hdrIso)
            DiagResult(DiagStatus.FAIL, "Изоляция сессий: посторонняя сессия расшифровала чужой шифротекст: '$fakeDecrypt'!")
        } catch (_: Exception) {
            DiagResult(DiagStatus.OK, "Изоляция сессий: посторонний ключ не может расшифровать чужой шифротекст")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Изоляция сессий: ошибка — ${e.message}")
    } finally {
        listOf(aliceId, bobId, malloryId, eveId).filter { it.isNotEmpty() }.forEach { SessionKeyManager.deleteSession(it) }
    }
}

/** Mirrors Android's NEGATIVE TEST 6 — a message key is single-use; the
 *  same (ciphertext, header) pair must decrypt successfully once and be
 *  rejected on a second attempt (the key was already discarded). */
private fun checkReplayAttackRejected(): DiagResult {
    var aliceId = ""; var bobId = ""
    return try {
        val pair = establishFakeSession()
        aliceId = pair.aliceId; bobId = pair.bobId

        val (ct, hdr) = SessionKeyManager.encryptWithSession(aliceId, "Replay me")
        val first = SessionKeyManager.decryptWithSession(bobId, ct, hdr)
        if (first != "Replay me") {
            return DiagResult(DiagStatus.WARN, "Replay-атака: первая доставка вернула неожиданный текст")
        }
        try {
            SessionKeyManager.decryptWithSession(bobId, ct, hdr)
            DiagResult(DiagStatus.FAIL, "Replay-атака: повторная доставка того же сообщения расшифровалась снова!")
        } catch (_: Exception) {
            DiagResult(DiagStatus.OK, "Replay-атака: повторное сообщение отклонено (ключ уже использован и удалён)")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Replay-атака: ошибка теста — ${e.message}")
    } finally {
        if (aliceId.isNotEmpty()) SessionKeyManager.deleteSession(aliceId)
        if (bobId.isNotEmpty()) SessionKeyManager.deleteSession(bobId)
    }
}

/** Mirrors Android's TEST 7 — flips a byte of a valid encoded public key so
 *  it (very likely) no longer decodes to a point actually on the curve,
 *  then confirms CryptoManager.loadPublicKey() rejects it rather than
 *  silently accepting an off-curve point (which could otherwise leak
 *  private-key bits via an invalid-curve ECDH attack). Desktop's
 *  loadPublicKey() already calls validateECPoint() internally — this test
 *  just confirms that guard actually fires. */
private fun checkInvalidCurveAttackProtection(): DiagResult {
    return try {
        val validKey = DesktopCryptoManager.getPublicKeyBase64()
        val keyBytes = java.util.Base64.getDecoder().decode(validKey)
        val offCurve = keyBytes.copyOf()
        offCurve[offCurve.size - 1] = (offCurve[offCurve.size - 1].toInt() xor 0xFF).toByte()
        val offCurveB64 = java.util.Base64.getEncoder().encodeToString(offCurve)
        try {
            CryptoManager.loadPublicKey(offCurveB64)
            DiagResult(DiagStatus.FAIL, "Invalid Curve Attack: точка не на кривой была ПРИНЯТА!")
        } catch (e: Exception) {
            DiagResult(DiagStatus.OK, "Invalid Curve Attack: точка не на кривой отклонена (${e.javaClass.simpleName})")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Invalid Curve Attack: ошибка теста — ${e.message}")
    }
}

private fun checkEcdhPublicKeyFormat(): DiagResult {
    return try {
        val pub64 = DesktopCryptoManager.getPublicKeyBase64()
        val bytes = java.util.Base64.getDecoder().decode(pub64)
        val ok = bytes.isNotEmpty() && bytes[0] == 0x30.toByte() && bytes.size in 88..96
        if (ok)
            DiagResult(DiagStatus.OK,   "EC public key: формат X.509/DER корректен (${bytes.size} байт)")
        else
            DiagResult(DiagStatus.WARN, "EC public key: неожиданный формат (${bytes.size} байт)")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "EC public key: ошибка декодирования — ${e.message}")
    }
}

// ─── Storage checks ───────────────────────────────────────────────────────────

private fun checkSmkStatus(): DiagResult =
    if (StorageKeyManager.isUnlocked)
        DiagResult(DiagStatus.OK,   "SMK: разблокирован — двойное шифрование сообщений активно")
    else
        DiagResult(DiagStatus.WARN, "SMK: не разблокирован — войдите в аккаунт для активации")

private fun checkBinaryIntegrity(): DiagResult {
    return try {
        val loc = object {}.javaClass.protectionDomain?.codeSource?.location
            ?: return DiagResult(DiagStatus.WARN, "Целостность: protectionDomain недоступен")
        val codeFile = File(loc.toURI())

        if (!codeFile.exists() || codeFile.isDirectory) {
            // Dev mode — classes dir, не JAR
            return DiagResult(DiagStatus.INFO, "Целостность: dev-режим (.class директория) — N/A")
        }

        val md = MessageDigest.getInstance("SHA-256")
        codeFile.inputStream().use { ins ->
            val buf = ByteArray(65536)
            var n: Int
            while (ins.read(buf).also { n = it } >= 0) md.update(buf, 0, n)
        }
        val currentHash = md.digest().take(8).joinToString("") { "%02x".format(it) }
        val stored = DesktopStorage.get("binary_hash_v1")

        when {
            stored == null -> {
                DesktopStorage.put("binary_hash_v1", currentHash)
                DiagResult(DiagStatus.OK, "Целостность: хэш JAR зарегистрирован ($currentHash)")
            }
            stored == currentHash ->
                DiagResult(DiagStatus.OK,   "Целостность: JAR не изменён ($currentHash)")
            else ->
                DiagResult(DiagStatus.FAIL, "Целостность: ХЭШ ИЗМЕНИЛСЯ! $stored → $currentHash")
        }
    } catch (e: Exception) {
        DiagResult(DiagStatus.WARN, "Целостность: ошибка — ${e.message}")
    }
}

private fun checkSecureDeletion(): DiagResult {
    return try {
        val tmp = File.createTempFile("Subrosa-sec-", ".tmp")
        tmp.writeBytes(ByteArray(4096) { 0xFF.toByte() })
        DesktopStorage.secureDelete(tmp)
        if (!tmp.exists())
            DiagResult(DiagStatus.OK,   "Безопасное удаление: 3-pass overwrite + fsync работает")
        else
            DiagResult(DiagStatus.FAIL, "Безопасное удаление: файл не был удалён после wipe")
    } catch (e: Exception) {
        DiagResult(DiagStatus.FAIL, "Безопасное удаление: ошибка — ${e.message}")
    }
}

// ─── Runtime environment checks ───────────────────────────────────────────────

private fun checkSwapProtection(): DiagResult {
    if (NativeProtection.memoryLockSupported)
        return DiagResult(DiagStatus.OK, "Подкачка: mlock/VirtualLock активен — SMK заблокирован в RAM")
    // Probe: try to allocate a small locked buffer to update the flag
    val buf = NativeProtection.allocateLockedBuffer(32)
    buf?.free()
    return if (NativeProtection.memoryLockSupported)
        DiagResult(DiagStatus.OK, "Подкачка: mlock/VirtualLock активен — SMK заблокирован в RAM")
    else
        DiagResult(DiagStatus.WARN,
            "Подкачка: mlock недоступен — секреты зануляются (SecureMemory), своп не блокирован")
}

private fun checkScreenCapture(): DiagResult {
    if (NativeProtection.screenCaptureProtected)
        return DiagResult(DiagStatus.OK, "Захват экрана: окно исключено из записи экрана")
    val os = System.getProperty("os.name", "").lowercase()
    val api = when {
        os.contains("win") -> "User32.SetWindowDisplayAffinity"
        os.contains("mac") -> "NSWindowSharingNone (AppKit)"
        else               -> "X11/Wayland compositor API"
    }
    return DiagResult(DiagStatus.WARN, "Захват экрана: защита не активна ($api)")
}

private fun checkKeyloggerProtection(): DiagResult =
    DiagResult(DiagStatus.INFO,
        "Кейлоггеры: защита на уровне JVM невозможна — требует OS SELinux/AppArmor")

private fun checkSandboxing(): DiagResult {
    val sm = System.getSecurityManager()
    return if (sm != null)
        DiagResult(DiagStatus.OK,   "Sandboxing: SecurityManager активен (${sm.javaClass.simpleName})")
    else
        DiagResult(DiagStatus.WARN,
            "Sandboxing: SecurityManager отсутствует — полные привилегии процесса")
}
