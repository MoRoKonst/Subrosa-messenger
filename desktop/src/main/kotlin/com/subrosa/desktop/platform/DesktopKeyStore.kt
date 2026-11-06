package com.subrosa.desktop

/**
 * Replaces Android's AndroidKeyStore.
 *
 * Uses a PKCS12 keystore file stored alongside the data directory.
 * The keystore password is derived from a machine-unique seed so the
 * file is meaningless without the machine it was created on.
 *
 * Keys managed here:
 *   - "storage_key"  — AES-256 key used by DesktopStorage
 *   - "ec_key"       — EC P-256 key pair used by DesktopCryptoManager
 */

import java.io.File
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object DesktopKeyStore {

    private const val KEYSTORE_FILE = "BEACON.p12"
    private const val KEYSTORE_TYPE = "PKCS12"

    // ── Machine-bound keystore password ──────────────────────────────────────
    // Windows: random seed protected by DPAPI (bound to the Windows user account).
    // Linux/other: /etc/machine-id — more stable and harder to spoof than a MAC address.
    private fun keystorePassword(dataDir: File): CharArray {
        val os = System.getProperty("os.name", "").lowercase()
        return if (os.contains("win")) keystorePasswordWindows(dataDir)
               else                    keystorePasswordLinux(dataDir)
    }

    // Windows: use DPAPI to protect a random 32-byte seed stored next to the keystore.
    // DPAPI binds the encrypted blob to the current Windows user (uses the login password
    // internally, optionally backed by TPM) — the blob is useless on another machine/account.
    private fun keystorePasswordWindows(dataDir: File): CharArray {
        val seedFile = File(dataDir, "BEACON.seed.dpapi")
        val seed: ByteArray = if (seedFile.exists()) {
            try {
                val encrypted = seedFile.readBytes()
                com.sun.jna.platform.win32.Crypt32Util.cryptUnprotectData(encrypted)
            } catch (e: Exception) {
                System.err.println("DesktopKeyStore: DPAPI decrypt failed, regenerating seed (${e.message})")
                generateWindowsSeed(seedFile)
            }
        } else {
            generateWindowsSeed(seedFile)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(seed)
        return digest.joinToString("") { "%02x".format(it) }.toCharArray()
    }

    private fun generateWindowsSeed(seedFile: File): ByteArray {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val encrypted = com.sun.jna.platform.win32.Crypt32Util.cryptProtectData(seed)
        seedFile.writeBytes(encrypted)
        return seed
    }

    // Linux: derive from /etc/machine-id which is stable across reboots but
    // unique per installation — significantly better than a spoofable MAC address.
    private fun keystorePasswordLinux(dataDir: File): CharArray {
        val machineId = try {
            File("/etc/machine-id").readText().trim().takeIf { it.isNotEmpty() }
                ?: File("/var/lib/dbus/machine-id").readText().trim().takeIf { it.isNotEmpty() }
                ?: "fallback-no-machine-id"
        } catch (_: Exception) { "fallback-no-machine-id" }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("BEACON-ks-v2:$machineId".toByteArray())
        return digest.joinToString("") { "%02x".format(it) }.toCharArray()
    }

    // ── Load or create keystore ───────────────────────────────────────────────

    private fun openKeyStore(dataDir: File): Pair<KeyStore, CharArray> {
        val ksFile = File(dataDir, KEYSTORE_FILE)
        val pwd    = keystorePassword(dataDir)
        val ks     = KeyStore.getInstance(KEYSTORE_TYPE)
        if (ksFile.exists()) {
            try {
                ksFile.inputStream().use { ks.load(it, pwd) }
            } catch (e: Exception) {
                // Stale keystore (wrong password after code change, or corruption).
                // Delete and recreate — a new EC keypair will be generated.
                System.err.println("DesktopKeyStore: unreadable keystore, regenerating (${e.message})")
                ksFile.delete()
                ks.load(null, pwd)
            }
        } else {
            ks.load(null, pwd)
        }
        return ks to pwd
    }

    private fun saveKeyStore(ks: KeyStore, dataDir: File, pwd: CharArray) {
        File(dataDir, KEYSTORE_FILE).outputStream().use { ks.store(it, pwd) }
    }

    // ── AES-256 storage key ───────────────────────────────────────────────────

    fun getOrCreateStorageKey(dataDir: File): SecretKey {
        val (ks, pwd) = openKeyStore(dataDir)
        val alias     = "storage_key"

        if (ks.containsAlias(alias)) {
            val entry = ks.getEntry(alias, KeyStore.PasswordProtection(pwd))
                    as? KeyStore.SecretKeyEntry
            if (entry != null) return entry.secretKey
        }

        // Generate a new AES-256 key and persist it
        val kg  = KeyGenerator.getInstance("AES")
        kg.init(256, SecureRandom())
        val key = kg.generateKey()
        ks.setEntry(alias, KeyStore.SecretKeyEntry(key), KeyStore.PasswordProtection(pwd))
        saveKeyStore(ks, dataDir, pwd)
        return key
    }

    // ── EC P-256 key pair (same curve as Android CryptoManager) ──────────────

    fun getOrCreateECKeyPair(dataDir: File): KeyPair {
        val (ks, pwd) = openKeyStore(dataDir)
        val alias     = "ec_key"

        if (ks.containsAlias(alias)) {
            val entry = ks.getEntry(alias, KeyStore.PasswordProtection(pwd))
                    as? KeyStore.PrivateKeyEntry
            if (entry != null) return KeyPair(entry.certificate.publicKey, entry.privateKey)
        }

        // Generate EC P-256 self-signed certificate for PKCS12 storage
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val kp = kpg.generateKeyPair()

        // PKCS12 requires a certificate chain — create a self-signed stub
        val cert = SelfSignedCert.generate(kp)
        ks.setEntry(alias, KeyStore.PrivateKeyEntry(kp.private, arrayOf(cert)),
            KeyStore.PasswordProtection(pwd))
        saveKeyStore(ks, dataDir, pwd)
        return kp
    }

    /**
     * Unconditionally overwrites "ec_key" with a freshly generated keypair —
     * used by RegisterScreen when creating a brand-new local account.
     * getOrCreateECKeyPair() deliberately REUSES whatever's already in the
     * PKCS12 file, which is correct for every other caller (app startup
     * should never silently change the user's identity/fingerprint), but
     * meant "create a new account" reused the SAME identity key — and
     * therefore the SAME server fingerprint, with whatever TOTP/device
     * pinning state the server already had on file for it — every time,
     * unlike Android's RegisterScreen.kt which calls CryptoManager.
     * generateKeyPair() (an unconditional fresh keypair) on every
     * registration. Found live, 2026-09-12: a second "new account" attempt
     * on the same machine profile came back device_auth_failed, because it
     * was really a reconnect to an already-TOTP-enabled identity whose
     * device_id had a DIFFERENT device pubkey already pinned server-side.
     */
    fun regenerateECKeyPair(dataDir: File): KeyPair {
        val (ks, pwd) = openKeyStore(dataDir)
        val alias     = "ec_key"

        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val kp = kpg.generateKeyPair()

        val cert = SelfSignedCert.generate(kp)
        ks.setEntry(alias, KeyStore.PrivateKeyEntry(kp.private, arrayOf(cert)),
            KeyStore.PasswordProtection(pwd))
        saveKeyStore(ks, dataDir, pwd)
        return kp
    }

    /**
     * Non-creating existence check — unlike getOrCreateECKeyPair(), never
     * generates or persists a key. Opening the keystore itself is safe: a
     * missing BEACON.p12 just yields an empty in-memory KeyStore (ks.load(null, pwd)),
     * no file is written. Mirrors Android CryptoManager.hasKeys()'s contract
     * exactly (existence check only). Was missing entirely — Desktop's
     * CryptoManager.hasKeys() previously hardcoded `true` unconditionally.
     */
    fun hasECKeyPair(dataDir: File): Boolean {
        val (ks, _) = openKeyStore(dataDir)
        return ks.containsAlias("ec_key")
    }

    /**
     * Real deletion — removes the "ec_key" entry from the PKCS12 keystore
     * and persists the change. Mirrors Android CryptoManager.deleteKeys()'s
     * contract exactly (delete-if-present, silent no-op otherwise). Was
     * missing entirely — Desktop's CryptoManager.deleteKeys() was a no-op
     * stub, so "delete identity -> generate new identity" never actually
     * produced a new key (getOrCreateECKeyPair() would just find the old
     * "ec_key" entry still there and reuse it).
     */
    fun deleteECKeyPair(dataDir: File) {
        val (ks, pwd) = openKeyStore(dataDir)
        val alias = "ec_key"
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias)
            saveKeyStore(ks, dataDir, pwd)
        }
    }

    /**
     * Overwrites the stored EC key pair with one restored from a backup
     * (PKCS8 private key bytes + X.509 public key bytes). Used by BackupManager
     * on import to restore identity/fingerprint from an existing backup.
     */
    fun storeECKeyPair(dataDir: File, privateKeyBytes: ByteArray, publicKeyBytes: ByteArray): KeyPair {
        val (ks, pwd) = openKeyStore(dataDir)
        val alias = "ec_key"

        val kf = KeyFactory.getInstance("EC")
        val privateKey = kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes))
        val publicKey  = kf.generatePublic(java.security.spec.X509EncodedKeySpec(publicKeyBytes))
        val kp = KeyPair(publicKey, privateKey)

        val cert = SelfSignedCert.generate(kp)
        ks.setEntry(alias, KeyStore.PrivateKeyEntry(kp.private, arrayOf(cert)),
            KeyStore.PasswordProtection(pwd))
        saveKeyStore(ks, dataDir, pwd)
        return kp
    }
}

// ── Minimal self-signed X.509 cert generator (no Bouncy Castle needed) ────────
// Uses Sun's internal PKIX API available in all JDK distributions.
private object SelfSignedCert {
    fun generate(kp: KeyPair): java.security.cert.Certificate {
        // Reflection-free approach: use the BouncyCastle provider that is
        // already on the classpath (added via build.gradle.kts).
        val provider = Security.getProvider("BC")
            ?: run {
                Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
                Security.getProvider("BC")!!
            }

        val subjectName = org.bouncycastle.asn1.x500.X500Name("CN=SubrosaDesktop")
        val serial      = java.math.BigInteger.valueOf(System.currentTimeMillis())
        val notBefore   = java.util.Date()
        val notAfter    = java.util.Date(System.currentTimeMillis() + 10L * 365 * 24 * 3600 * 1000)

        val certBuilder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            subjectName, serial, notBefore, notAfter, subjectName, kp.public
        )
        val signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(provider)
            .build(kp.private)

        return org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
            .setProvider(provider)
            .getCertificate(certBuilder.build(signer))
    }
}
