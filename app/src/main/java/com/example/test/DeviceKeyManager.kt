package com.subrosa.messenger

import android.content.Context
import android.util.Base64
import java.security.Signature

/** Separate device-level EC keypair (external review 2026-09-03) — proves
 *  live possession of THIS specific device to server.py's authorized_devices
 *  device_pubkey pinning, independent of the identity keypair
 *  (CryptoManager). Deliberately stored under its own SharedPreferences
 *  file (PREFS_ENC = "device_keys_enc"), never "beacon_ec_keys_enc" (the
 *  identity key's file) and never swept into BackupManager.exportBackup()
 *  at all — that function only ever touches beacon_ec_keys_enc/user_prefs/
 *  etc. by explicit name, so a new prefs file is invisible to it by
 *  construction. This is intentional, not an oversight: a stolen identity
 *  backup alone must never be enough to produce a valid device signature,
 *  or the whole point of device_pubkey pinning (see server.py's register())
 *  is defeated. The identity key CAN be restored from a backup onto a
 *  brand-new device — that new device then correctly has no device
 *  keypair of its own yet, and must go through the TOTP-gated first-time
 *  pin under a fresh device_id, exactly like any other never-seen-before
 *  device would. */
object DeviceKeyManager {

    private const val PREFS_ENC = "device_keys_enc"
    private const val PRIV_KEY  = "device_priv"
    private const val PUB_KEY   = "device_pub"

    // Must match server.py's register() verification byte-for-byte: the
    // literal ASCII prefix, then raw challenge bytes, then username and
    // device_id each UTF-8 encoded, concatenated with no separators.
    private const val SIGN_PREFIX = "SUBROSA_DEVICE_V1"

    // Guards the whole load-or-generate-and-persist sequence below — without
    // it, two concurrent first-use calls (e.g. a reconnect racing the
    // initial connect, both on Dispatchers.IO) could each see "no key yet",
    // independently generate DIFFERENT keypairs, and both persist —
    // last-write-wins in storage. getPublicKeyString() and
    // signDeviceChallenge() are two SEPARATE calls into this function; if
    // one raced a concurrent generate between them, the register packet
    // could end up carrying public key A (read before the race) signed by
    // key B (read after) — a mismatch the server would reject
    // unpredictably, not a decision either caller made on purpose. Found in
    // the 2026-09-13 DeviceKeyManager audit.
    private val lock = Any()

    private fun getOrCreateKeyPair(context: Context): java.security.KeyPair = synchronized(lock) {
        val ctx = context.applicationContext
        val encPrefs   = EncryptedStorage.getEncryptedPrefs(ctx, PREFS_ENC)
        val privStored = encPrefs.getString(PRIV_KEY, null)
        val pubB64      = encPrefs.getString(PUB_KEY, null)
        if (privStored != null && pubB64 != null) {
            val privBytes = StorageKeyManager.unwrapBytes(privStored)
            // Same lazy re-wrap-once-unlocked pattern as
            // CryptoManager.getSoftwareKeyPair() — a key generated before
            // the screen-lock passphrase was ever entered this session
            // starts out only base64-encoded; once StorageKeyManager
            // unlocks, upgrade it to properly wrapped in place.
            if (!privStored.startsWith(StorageKeyManager.SMK_PREFIX) && StorageKeyManager.isUnlocked) {
                encPrefs.edit().putString(PRIV_KEY, StorageKeyManager.wrapBytes(privBytes)).commit()
            }
            val kf = java.security.KeyFactory.getInstance("EC")
            return java.security.KeyPair(
                kf.generatePublic(java.security.spec.X509EncodedKeySpec(Base64.decode(pubB64, Base64.NO_WRAP))),
                kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(privBytes))
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
            .putString(PRIV_KEY, privToStore)
            .putString(PUB_KEY, Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP))
            .commit()
        android.util.Log.d("DeviceKeyManager", "Device EC keypair сгенерирован")
        return kp
    }

    /** Wipes the device keypair — call ONLY when intentionally starting a
     *  genuinely new local identity (BackupManager.resetCompromisedIdentity()),
     *  and call it BEFORE that same operation destroys/replaces the SMK
     *  (smk_config / beacon_smk_wrap). device_priv is SMK-wrapped like the
     *  TOTP secret; a brand-new SMK set up on the next register() can never
     *  decrypt a device_priv wrapped under the OLD one, so leaving it in
     *  place doesn't "preserve" anything — it just leaves a permanently
     *  undecryptable blob that getOrCreateKeyPair() would otherwise have to
     *  treat as corrupt. Must NOT be called for an ordinary reconnect/
     *  same-identity restart, or for a backup restore that keeps the
     *  existing SMK (BackupScreen.kt's "already logged in" caller) — in
     *  both of those the current device_priv is still valid and still
     *  matches whatever device_pubkey the server has pinned for this
     *  device_id; clearing it there would force a needless, disruptive
     *  device re-pin. Was missing entirely — found in the 2026-09-13
     *  DeviceKeyManager audit. */
    fun clear(context: Context) {
        EncryptedStorage.getEncryptedPrefs(context.applicationContext, PREFS_ENC)
            .edit().clear().apply()
    }

    /** X.509 SubjectPublicKeyInfo DER, base64 — same encoding
     *  CryptoManager.getPublicKeyString() uses for the identity key, and
     *  what server.py's cryptography.hazmat load_der_public_key() expects
     *  directly, no reformatting needed on either side. */
    fun getPublicKeyString(context: Context): String =
        Base64.encodeToString(getOrCreateKeyPair(context).public.encoded, Base64.NO_WRAP)

    /** Signs SUBROSA_DEVICE_V1 || challenge || username || device_id with
     *  the device private key — called on EVERY register(), not just first
     *  enrollment (see server.py's own comment on why: challenge is fresh
     *  per-connection, so this also doubles as replay protection, not just
     *  a one-time enrollment proof). `username` here is the identity
     *  fingerprint (uppercase hex SHA-256[:8] of the identity public key —
     *  same string sent as register()'s own "from" field), not a
     *  human-chosen display name. */
    fun signDeviceChallenge(context: Context, challenge: ByteArray, username: String, deviceId: String): String {
        val kp = getOrCreateKeyPair(context)
        val signedData = SIGN_PREFIX.toByteArray(Charsets.US_ASCII) +
            challenge +
            username.toByteArray(Charsets.UTF_8) +
            deviceId.toByteArray(Charsets.UTF_8)
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(kp.private)
        signature.update(signedData)
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }
}
