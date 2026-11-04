package com.subrosa.desktop

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Desktop port of Android's DeviceKeyManager — a separate device-level EC
 *  keypair that proves live possession of THIS specific device to
 *  server.py's authorized_devices device_pubkey pinning, independent of the
 *  identity keypair. Stored under its own DesktopStorage keys ("device_priv"/
 *  "device_pub"), SMK-wrapped like the TOTP secret — never swept into
 *  BackupManager.exportBackup() (which only touches its own explicitly-named
 *  fields), so a stolen identity backup alone can never produce a valid
 *  device signature.
 *
 *  Missing entirely before this fix — Desktop's register() packet never
 *  carried device_public_key/device_signature at all. Harmless for a brand
 *  new account (server only requires them once TOTP is enabled for the
 *  account — see server.py register()'s `if candidate_username in
 *  user_totp_secrets` gate), but since TOTP setup is MANDATORY immediately
 *  after registration on both platforms, this meant every Desktop account
 *  would get "device_auth_failed" on its very next register() (any
 *  reconnect — app restart, network blip) after finishing the onboarding
 *  TOTP step, with no retry path — a near-guaranteed lockout for every
 *  Desktop user. Found via a desktop/Android literal wire-field audit,
 *  2026-09-11 — critical severity. */
object DeviceKeyManager {

    private const val KEY_PRIV = "device_priv"
    private const val KEY_PUB  = "device_pub"

    // Must match server.py's register() verification byte-for-byte: the
    // literal ASCII prefix, then raw challenge bytes, then username and
    // device_id each UTF-8 encoded, concatenated with no separators.
    private const val SIGN_PREFIX = "SUBROSA_DEVICE_V1"

    // Guards the whole load-or-generate-and-persist sequence below — mirrors
    // Android's fix exactly. Without it, two concurrent first-use calls
    // could each see "no key yet", independently generate DIFFERENT
    // keypairs, and both persist (last-write-wins). getPublicKeyString()
    // and signDeviceChallenge() are separate calls into this function; a
    // race between them could produce a register packet carrying public
    // key A (read before the race) signed by key B (read after) — a
    // mismatch the server would reject unpredictably. Found in the
    // 2026-09-13 DeviceKeyManager audit.
    private val lock = Any()

    private fun getOrCreateKeyPair(): java.security.KeyPair = synchronized(lock) {
        val privStored = DesktopStorage.get(KEY_PRIV)
        val pubB64      = DesktopStorage.get(KEY_PUB)
        if (privStored != null && pubB64 != null) {
            // Fail closed while genuinely locked — mirrors the required
            // semantics exactly: a temporarily-inaccessible key (SMK not
            // yet unlocked this session) is NOT the same thing as a
            // deliberately-invalidated one, and must never be silently
            // overwritten just because it can't be read back RIGHT NOW.
            // Without this check, StorageKeyManager.readSmk()'s own
            // `error("StorageKeyManager is locked")` (an IllegalStateException)
            // used to be caught by the broad catch below and misread as "old
            // account's key, safe to replace" — permanently destroying an
            // already server-pinned device key the very first time this ran
            // before the user ever unlocked. Found in the 2026-09-13
            // DeviceKeyManager audit.
            if (privStored.startsWith(StorageKeyManager.SMK_PREFIX) && !StorageKeyManager.isUnlocked) {
                throw IllegalStateException(
                    "DeviceKeyManager: device_priv is SMK-wrapped and locked — refusing to regenerate a possibly-still-valid, already-pinned device key"
                )
            }
            try {
                val privBytes = StorageKeyManager.unwrapBytes(privStored)
                val kf = KeyFactory.getInstance("EC")
                return java.security.KeyPair(
                    kf.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(pubB64))),
                    kf.generatePrivate(PKCS8EncodedKeySpec(privBytes))
                )
            } catch (e: javax.crypto.AEADBadTagException) {
                // StorageKeyManager.setup() mints a brand-new random SMK on
                // EVERY register() (see its own comment — it's not derived
                // deterministically from the password), so a device_priv left
                // over from a previous local account/test run on this same
                // machine profile is undecryptable under the CURRENT SMK —
                // this specific exception (GCM tag mismatch = decrypted
                // under the WRONG key) is the one safe, identifiable signal
                // for that case, distinct from "locked" (caught above) or
                // any other unexpected corruption (rethrown below, not
                // silently overwritten). A blob that fails to authenticate
                // under the CURRENT, unlocked SMK is functionally a
                // different identity's leftover key, so minting a fresh one
                // is the correct recovery here specifically. Found live,
                // 2026-09-12; narrowed from catch(Exception) in the
                // 2026-09-13 DeviceKeyManager audit — the broad catch also
                // swallowed genuinely transient/corrupt failures and
                // silently replaced an otherwise-valid, already-pinned
                // device key, which is exactly what device_auth_failed
                // looks like from the server's side.
                System.err.println("DeviceKeyManager: stored device_priv encrypted under a different SMK (${e.message}) — generating a new one")
            }
        }

        // Unconditional wrapBytes() here, unlike Android's generate-while-
        // locked Base64 fallback + lazy re-wrap-on-unlock — intentional
        // platform difference, not a gap: traced every call site that can
        // reach this branch (WebSocketClient.getOrCreateKeyPair() is only
        // ever invoked from the "handshake_ok" register-packet build, which
        // both LoginScreen.kt and RegisterScreen.kt call strictly AFTER
        // StorageKeyManager.setup()/unlockWithPassword()/unlockWithKeystore()
        // has already returned — there is no Desktop code path that starts
        // a connection before the SMK is unlocked, so this line provably
        // never runs while locked. Adding an unused plaintext-fallback
        // branch here would itself be an unnecessary storage downgrade with
        // no reachable caller to justify it. Found in the 2026-09-13
        // DeviceKeyManager audit.
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        DesktopStorage.put(KEY_PRIV, StorageKeyManager.wrapBytes(kp.private.encoded))
        DesktopStorage.put(KEY_PUB, Base64.getEncoder().encodeToString(kp.public.encoded))
        println("DeviceKeyManager: device EC keypair generated")
        return kp
    }

    /** Wipes the device keypair — call ONLY when intentionally starting a
     *  genuinely new local identity (`BackupManager.resetCompromisedIdentity()`),
     *  mirroring Android's `DeviceKeyManager.clear()` exactly. Not strictly
     *  load-bearing today — `getOrCreateKeyPair()`'s `AEADBadTagException`
     *  handling above already self-heals if a leftover `device_priv` turns
     *  out to be wrapped under a since-replaced SMK — but proactively
     *  clearing on identity reset is more robust than relying solely on a
     *  decrypt-failure fallback, and keeps this in parity with Android
     *  rather than silently diverging. Found missing 2026-09-25 while
     *  auditing OPEN-9 (`docs/KNOWN_SECURITY_ISSUES.md`) against actual
     *  code — the device-signing side of device-gated TOTP was already
     *  fully implemented on Desktop, contrary to what OPEN-9 claimed; this
     *  cleanup call was the one genuinely missing piece. */
    fun clear() {
        DesktopStorage.remove(KEY_PRIV)
        DesktopStorage.remove(KEY_PUB)
    }

    /** X.509 SubjectPublicKeyInfo DER, base64 — same encoding
     *  DesktopCryptoManager uses for the identity key, and what server.py's
     *  cryptography.hazmat load_der_public_key() expects directly. */
    fun getPublicKeyString(): String =
        Base64.getEncoder().encodeToString(getOrCreateKeyPair().public.encoded)

    /** Signs SUBROSA_DEVICE_V1 || challenge || username || device_id with
     *  the device private key — called on EVERY register(), not just first
     *  enrollment (challenge is fresh per-connection, so this also doubles
     *  as replay protection). `username` here is the identity fingerprint
     *  (uppercase hex), not a human-chosen display name. */
    fun signDeviceChallenge(challenge: ByteArray, username: String, deviceId: String): String {
        val kp = getOrCreateKeyPair()
        val signedData = SIGN_PREFIX.toByteArray(Charsets.US_ASCII) +
            challenge +
            username.toByteArray(Charsets.UTF_8) +
            deviceId.toByteArray(Charsets.UTF_8)
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(kp.private)
        signature.update(signedData)
        return Base64.getEncoder().encodeToString(signature.sign())
    }
}
