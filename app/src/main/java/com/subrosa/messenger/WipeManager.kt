package com.subrosa.messenger

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import java.io.File

/**
 * Every destructive path in the app funnels through [eraseEverything] here.
 *
 * It used to be three near-identical copies — `hardWipe`,
 * `wipeForDecoyKeepAlive` and `MessengerService.performEmergencyWipe` — and
 * they had already drifted in ways that made one route a strictly weaker wipe
 * than another route to the same outcome:
 *
 *  - `performEmergencyWipe` (the 5-volume-press trigger) did not delete the
 *    `beacon_smk_wrap` Keystore alias that the other two did, leaving the
 *    Keystore-wrapped copy of the Storage Master Key behind.
 *  - `performEmergencyWipe` did not call `StorageKeyManager.lock()`, despite
 *    docs/SECURITY.md and SECURITY_INVARIANTS.md #22 both stating the SMK is
 *    zeroed as the very first operation of *any* wipe. The key stayed live in
 *    process memory for the whole deletion pass.
 *  - Only `wipe()` dismissed the panic notification, so the four routes that
 *    call `hardWipe` directly left an ongoing "Subrosa — Экстренный вайп"
 *    notification, with a working DESTROY action, in the shade afterwards.
 *
 * Divergence between copies is the failure mode this file is now shaped to
 * prevent: there is one implementation, and the callers differ only in whether
 * they keep the process alive.
 */
object WipeManager {

    enum class Level { HARD, NUCLEAR }

    private val KEYSTORE_ALIASES = listOf(
        "_androidx_security_master_key",
        "_androidx_security_crypto_master_key_",
        "beacon_smk_wrap"
    )

    fun wipe(context: Context, level: Level, withDecoy: Boolean = false) {
        when (level) {
            Level.HARD    -> hardWipe(context, withDecoy)
            Level.NUCLEAR -> nuclearWipe(context, withDecoy)
        }
    }

    /** Full wipe, then kill the process. */
    fun hardWipe(context: Context, withDecoy: Boolean = false) {
        try {
            eraseEverything(context, keepDecoyProfile = withDecoy)
        } catch (e: Exception) {
            android.util.Log.e("WipeManager", "Ошибка hard wipe: ${e.message}", e)
        } finally {
            android.os.Process.killProcess(android.os.Process.myPid())
        }
    }

    /**
     * Identical erasure, but the process keeps running so the decoy can stay on
     * screen in front of whoever triggered it. Used by the panic-password path
     * (MainActivity.onPanicMode) and the panic notification's decoy variant
     * (WipeReceiver) — both of which are showing a fake inbox at the moment
     * this runs, so an abrupt process death would itself be the giveaway.
     */
    fun wipeForDecoyKeepAlive(context: Context) {
        try {
            eraseEverything(context, keepDecoyProfile = true)
        } catch (e: Exception) {
            android.util.Log.e("WipeManager", "Ошибка decoy wipe: ${e.message}", e)
        }
    }

    /**
     * The single destructive implementation.
     *
     * Order matters and is deliberate:
     *  1. Overwrite the SMK in memory (documented invariant — before anything
     *     else). `lock()` routes through [SecureMemory], so the buffer is
     *     overwritten rather than merely unreferenced, and the overwrite
     *     cannot be dropped as a dead store — see SecureMemory's class doc for
     *     why that, and not the number of passes, is the part that matters.
     *     In-process key material is scrubbed again in step 4
     *     (`deleteAllSessions` overwrites chain keys, ratchet privates and the
     *     ML-KEM private key). The complete answer for HARD/NUCLEAR is still
     *     process death at the end of [hardWipe] — scrubbing is what carries
     *     [wipeForDecoyKeepAlive], where the heap deliberately survives.
     *  2. Dismiss the panic notification, which outlives the process.
     *  3. Read out the decoy profile fields *before* the storage holding them
     *     is destroyed.
     *  4. Destroy keys, then files.
     *  5. Re-establish the decoy profile last, into freshly created encrypted
     *     storage.
     */
    private fun eraseEverything(context: Context, keepDecoyProfile: Boolean) {
        StorageKeyManager.lock()
        PanicNotificationManager.dismiss(context)

        var savedPasswordHash: String? = null
        var savedUsername: String? = null
        var savedUserId: String? = null
        var savedCalcDisguise = false
        var savedCalcUnlockResult: Float? = null
        try {
            val enc = EncryptedStorage.getEncryptedPrefs(context, "user_prefs")
            // Only carry the disguise forward if its unlock code survives with
            // it — the code lives in this same (about-to-be-wiped) encrypted
            // prefs file, so restoring disguise=true with no code would
            // permanently lock the user out of their own restored profile.
            if (enc.getBoolean("calculator_disguise", false) && enc.contains("calculator_unlock_result")) {
                savedCalcDisguise = true
                savedCalcUnlockResult = enc.getFloat("calculator_unlock_result", 0f)
            }
            if (keepDecoyProfile) {
                savedPasswordHash = enc.getString("password_hash", null)
                savedUsername     = enc.getString("username",      null)
                savedUserId       = enc.getString("user_id",       null)
            }
        } catch (_: Exception) {}

        SessionKeyManager.deleteAllSessions()
        CryptoManager.deleteKeys()

        try {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            KEYSTORE_ALIASES.filter { ks.containsAlias(it) }.forEach { ks.deleteEntry(it) }
        } catch (_: Exception) {}

        val dataDir = context.applicationInfo.dataDir
        File(dataDir, "shared_prefs").deleteRecursively()
        context.filesDir.deleteRecursively()
        context.cacheDir.deleteRecursively()
        context.externalCacheDir?.deleteRecursively()
        File(dataDir, "databases").deleteRecursively()
        File(dataDir, "app_webview").deleteRecursively()
        File(dataDir, "no_backup").deleteRecursively()
        context.getExternalFilesDir(null)?.parentFile?.deleteRecursively()

        context.stopService(Intent(context, MessengerService::class.java))

        // Straight back into encrypted prefs (a fresh master key and a fresh
        // file, since both were just destroyed) rather than the old plaintext
        // `beacon_recovery` hand-off — see UserStorage.reestablishDecoyProfile.
        UserStorage.reestablishDecoyProfile(
            context = context,
            username = savedUsername,
            userId = savedUserId,
            passwordHash = savedPasswordHash,
            calcDisguise = savedCalcDisguise,
            calcUnlockResult = savedCalcUnlockResult
        )
    }

    /**
     * `clearApplicationUserData()` hands the erase to the framework, which
     * destroys the entire data directory — including anything we could have
     * written to carry a decoy profile forward. So NUCLEAR and decoy survival
     * are mutually exclusive by construction, and [withDecoy] only applies to
     * the fallback below, for when the framework call is unavailable or fails.
     * Stated explicitly because the parameter previously looked as though it
     * worked here and silently did nothing.
     */
    private fun nuclearWipe(context: Context, withDecoy: Boolean = false) {
        StorageKeyManager.lock()
        PanicNotificationManager.dismiss(context)

        try {
            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()
            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                KEYSTORE_ALIASES.filter { ks.containsAlias(it) }.forEach { ks.deleteEntry(it) }
            } catch (_: Exception) {}
        } catch (_: Exception) {}

        try {
            val am = context.getSystemService(ActivityManager::class.java)
            am.clearApplicationUserData()
        } catch (_: Exception) {
            hardWipe(context, withDecoy)
        }
    }
}
