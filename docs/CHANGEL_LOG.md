# Engineering Change Log (ECL)

**Project:** [Project Name]
**Format:** Problem $\to$ Implementation $\to$ Commit Reference

---

## [Date: 2023-10-27]

### 1. Feature/Bug: Anti-Debugging Implementation
*   **Problem:** Vulnerability to runtime analysis via JDWP (Java Debug Wire Protocol) and presence of debug flags.
*   **Implementation:** Integrated `android.os.Debug.isDebuggerConnected()` checks and `android_os.Debug.unwrap()` logic into the application startup lifecycle.
*   **Commit:** `feat: implement anti-debugging detection logic`

### 2. Feature/Bug: Screen Capture Protection
*   **Problem:** Information leakage via screenshot-taking and screen recording applications.
*   **Implementation:** Applied `WindowManager.LayoutParams.FLAG_SECURE` to the main activity window to prevent window content from appearing in screenshots.
*   **Commit:** `fix: prevent screen capture and recording`

### 3. Feature/Bug: Root Detection (Basic)
*   **Problem:** Compromised device integrity (Root/Magisk) allows bypassing security constraints.
*   **Implementation:** Added checks for common binaries (`su`, `busybox`, `magisk`) in the system PATH.
*   **Commit:** `feat: add basic root detection module`

---

## [Date: 2026-04-26]

### 1. Fix: Main Thread Blocking in onResume() Security Checks
*   **Problem:** `IntrusionDetector.scan()` and `HoneyTokenManager.checkIntegrity()` were called synchronously on the Android Main Thread inside `onResume()`, causing potential ANR (Application Not Responding) jank and violating the strict-mode threading rules.
*   **Implementation:** Wrapped the entire Paranoid Mode security check block (`RootDetector.checkResult()`, `IntrusionDetector.scan()`, `HoneyTokenManager.checkIntegrity()`) inside `lifecycleScope.launch { withContext(Dispatchers.IO) { … } }`. Blocking IO operations now run off the Main Thread; UI reactions (`finishAffinity()`, `handleThreat()`) remain on the Main dispatcher via coroutine resume.
*   **Files:** `MainActivity.kt`
*   **Commit:** `fix: move onResume security checks to Dispatchers.IO`

### 2. Fix: Raw Thread in sendAlert() Replaced with Coroutine Scope
*   **Problem:** `ParanoidMode.sendAlert()` spawned a raw `Thread { }.start()` for the HTTP alert POST, which bypasses structured concurrency and leaks resources if the object is never garbage-collected.
*   **Implementation:** Added `private val alertScope = CoroutineScope(Dispatchers.IO + SupervisorJob())` to `ParanoidMode` object. Replaced `Thread { }.start()` with `alertScope.launch { … }`, inheriting cancellation and lifecycle management.
*   **Files:** `ParanoidMode.kt`
*   **Commit:** `fix: replace raw Thread with coroutine scope in sendAlert`

### 3. Feature: Double Encryption — Storage Master Key (SMK) Layer
*   **Problem:** At-rest data on the device (messages, EC identity key, group keys) was protected only by EncryptedSharedPreferences backed by AndroidKeyStore. An attacker with root access or an offline filesystem image could potentially compromise the AndroidKeyStore software key and read all stored data without knowing the user's application password.
*   **Implementation:** Introduced a second encryption layer via `StorageKeyManager` (new file). A 256-bit Storage Master Key (SMK) is generated on registration and stored in two forms: (1) `enc_smk_pwd` — AES-256-GCM encrypted with a key derived via PBKDF2-SHA256 (300 000 iterations) from the user's login password; (2) `enc_smk_ks` — AES-256-GCM encrypted with a dedicated AndroidKeyStore AES-256 key for fast biometric/re-lock recovery. The SMK lives in memory only and is zeroed on lock or wipe. A transparent migration scheme prefixes all SMK-protected values with `"smk1:"`, ensuring legacy unencrypted values continue to be read without modification.
*   **Protected assets:**
    *   EC secp256r1 identity private key (`CryptoManager`, `beacon_ec_keys_enc` prefs) — eager re-wrap on first read.
    *   Per-group AES-256 keys (`GroupManager`, `"groups"` prefs) — wrapped at serialization.
    *   Per-chat message JSON blobs (`ChatStorage`, `"chat_storage_encrypted"` prefs) — whole array encrypted/decrypted via `loadJsonArray()` / `saveJsonArray()` helpers.
*   **Not protected by SMK** (required at cold-start before login): SPK/OPK private keys, Double Ratchet session states.
*   **Lifecycle hooks added:**
    *   `RegisterScreen` — `StorageKeyManager.setup(context, password)` after first registration.
    *   `LoginScreen` — `unlockWithPassword(context, password)` on password login; `unlockWithKeystore(context)` on biometric success.
    *   `MainActivity` app-lock screen — `unlockWithPassword` / `unlockWithKeystore` mirrored for re-lock flow; `lock()` called before setting `isAppLocked = true` (screen-off and timeout paths).
    *   `WipeManager.wipe()` — `StorageKeyManager.lock()` called as first operation before any data deletion.
*   **Files:** `StorageKeyManager.kt` (new), `CryptoManager.kt`, `GroupManager.kt`, `ChatStorage.kt`, `LoginScreen.kt`, `RegisterScreen.kt`, `MainActivity.kt`, `WipeManager.kt`
*   **Commit:** `feat: add SMK double-encryption layer for at-rest data protection`