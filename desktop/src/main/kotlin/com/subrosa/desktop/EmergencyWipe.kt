package com.subrosa.desktop

import java.io.File

/** "Это не я" — duress panic wipe, mirrors Android's WipeManager.hardWipe()
 *  (the plain, non-decoy path — Desktop has no calculator-disguise mode to
 *  preserve). Unconditionally destroys every local trace of this identity:
 *  chat storage, the SMK/password material, AND the identity keypair itself
 *  (the PKCS12 keystore + its DPAPI-protected password seed on Windows) —
 *  unlike BackupManager.resetCompromisedIdentity()'s "Меня
 *  скомпрометировали", which deliberately preserves device-level settings
 *  for a clean re-registration. There is no screen left to safely fall back
 *  to with this much gone, so the process exits immediately after — same
 *  effect as Android's Process.killProcess(), the user relaunches to see a
 *  fresh RegisterScreen. Was entirely missing from Desktop before this fix
 *  (found in the 2026-09-12 full-logic audit — Desktop's ProfileScreen had
 *  no duress-wipe button at all). */
object EmergencyWipe {
    fun wipeEverythingAndExit(): Nothing {
        try {
            StorageKeyManager.lock()
            val dataDir = DesktopStorage.resolveDataDir()
            DesktopStorage.secureWipeAll()
            DesktopStorage.secureDelete(File(dataDir, "BEACON.p12"))
            DesktopStorage.secureDelete(File(dataDir, "BEACON.seed.dpapi"))
        } catch (_: Exception) {
        } finally {
            kotlin.system.exitProcess(0)
        }
    }

    /** Panic-password path — mirrors Android's WipeManager.wipeForDecoyKeepAlive():
     *  destroys every real trace (chat storage, identity keypair, SMK/password
     *  material via the same wipe as hardWipe()'s destructive core) but does
     *  NOT exit the process. Unlike the plain "Это не я" wipe above, the
     *  original username/userId/password hash are deliberately preserved and
     *  written back after the wipe, together with decoy_mode=true — so this
     *  device's real password keeps "working" forever afterward, just always
     *  landing on the fake messenger instead of the real one, with nothing
     *  left to distinguish a wiped device from one that was never real to
     *  begin with. Was entirely missing before this fix — Desktop had no
     *  panic-password/decoy feature at all. */
    fun wipeForDecoyKeepAlive() {
        val savedUsername = DesktopStorage.get("username")
        val savedUserId    = DesktopStorage.get("user_id")
        val savedPasswordHash = DesktopStorage.get("password_hash")

        try {
            StorageKeyManager.lock()
            SessionKeyManager.deleteAllSessions()
            CryptoManager.deleteKeys()
            val dataDir = DesktopStorage.resolveDataDir()
            DesktopStorage.secureWipeAll()
            DesktopStorage.secureDelete(File(dataDir, "BEACON.p12"))
            DesktopStorage.secureDelete(File(dataDir, "BEACON.seed.dpapi"))
        } catch (_: Exception) {
        }

        try {
            // secureWipeAll() clears DesktopStorage's in-memory map and its
            // AES key reference — re-init to get a fresh (empty) store
            // backed by the same machine-bound keystore, since that file
            // wasn't touched above (only storage.enc + the identity keys were).
            DesktopStorage.init()
            if (savedUsername != null && savedPasswordHash != null) {
                DesktopStorage.put("username", savedUsername)
                DesktopStorage.put("user_id", savedUserId ?: "")
                DesktopStorage.put("password_hash", savedPasswordHash)
            }
            DesktopStorage.putBoolean("decoy_mode", true)
        } catch (_: Exception) {
        }
    }
}
