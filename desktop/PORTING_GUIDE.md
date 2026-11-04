# Beacon Desktop — Porting Guide

## Project layout

```
D:\TEST2\
├── app\              ← original Android project (DO NOT TOUCH)
└── desktop\          ← this desktop project
    ├── settings.gradle.kts
    ├── build.gradle.kts
    └── src\main\kotlin\com\bcon\desktop\
        ├── main.kt
        ├── AppNavigation.kt
        ├── platform\
        │   ├── DesktopStorage.kt      ← replaces EncryptedSharedPreferences
        │   ├── DesktopKeyStore.kt     ← replaces AndroidKeyStore (PKCS12)
        │   └── DesktopCryptoManager.kt ← replaces CryptoManager (stub)
        ├── network\
        │   └── WebSocketClient.kt    ← replaces MessengerService (WS only)
        └── ui\
            ├── LoginScreen.kt
            ├── RegisterScreen.kt
            ├── ChatsScreen.kt
            └── ChatScreen.kt          ← geo opens OSM in browser
```

---

## Android API → Desktop replacement table

| Android class / import               | Desktop replacement                              |
|--------------------------------------|--------------------------------------------------|
| `android.util.Base64`                | `java.util.Base64` (same API, different class)  |
| `android.util.Log.d/e`              | `println()` / `System.err.println()`            |
| `android.content.Context`           | Remove — not needed; use `DesktopStorage`        |
| `EncryptedSharedPreferences`         | `DesktopStorage` (`get/put/remove/contains`)     |
| `AndroidKeyStore`                    | `DesktopKeyStore` (PKCS12 file)                 |
| `android.security.keystore.*`        | Standard `java.security.*`                       |
| `android.graphics.Bitmap`           | `org.jetbrains.skia.Image` / `ImageBitmap`      |
| `android.graphics.BitmapFactory`    | `org.jetbrains.skia.Image.makeFromEncoded()`    |
| `org.json.JSONObject`               | `org.json.JSONObject` (same — on JVM classpath) |
| `ContextCompat.startForegroundService` | Remove — no services on desktop              |
| `NotificationManager`               | Desktop system tray / AWT notification           |
| osmdroid `MapView`                  | `Desktop.getDesktop().browse(URI(...))` to OSM  |

---

## Files to copy directly (zero Android deps)

Copy these files verbatim from `D:\TEST2\app\src\main\java\com\example\test\`
to `D:\TEST2\desktop\src\main\kotlin\com\bcon\desktop\`:

| File                    | Notes                                                     |
|-------------------------|-----------------------------------------------------------|
| `SecureMemory.kt`       | Pure JVM — `ByteArray` zeroing. No changes needed.       |
| `EmojiFingerprint.kt`   | Pure Kotlin. No Android deps.                             |
| `ProtocolVersion.kt`    | Constants only.                                           |
| `GroupManager.kt`       | Replace `android.util.Base64` → `java.util.Base64`       |
|                         | Replace `android.util.Log` → println                     |
|                         | Replace `EncryptedStorage.getEncryptedPrefs(ctx, …)`     |
|                         |   → `DesktopStorage.get/put(…)`                          |

---

## Files to adapt (moderate effort)

### CryptoManager.kt → DesktopCryptoManager.kt  (stub already created)

Changes required:
1. Remove `android.content.Context` parameter from `init()`
2. Replace every `Base64.encode(bytes, Base64.NO_WRAP)` → `java.util.Base64.getEncoder().encodeToString(bytes)`
3. Replace every `Base64.decode(str, Base64.NO_WRAP)` → `java.util.Base64.getDecoder().decode(str)`
4. Replace `EncryptedStorage.getEncryptedPrefs(ctx, SW_KEY_PREFS_ENC)` → `DesktopStorage`
5. Replace `StorageKeyManager.wrapBytes/unwrapBytes` → copy as-is (pure JVM)
6. Replace `android.util.Log.*` → println / System.err

### ChatStorage.kt → DesktopChatStorage.kt  (not yet created)

Changes required:
1. Remove `Context` from all public functions
2. Replace `EncryptedStorage.getEncryptedPrefs(ctx, …)` → `DesktopStorage.get/put(…)`
   - Messages are JSON-serialized strings; the key scheme stays the same
3. Replace `android.util.Base64` → `java.util.Base64`
4. Image blobs: instead of saving to `context.filesDir`, save to
   `File(DesktopStorage.resolveDataDir(), "images/$id.jpg.enc")`

### UserStorage.kt → DesktopUserStorage.kt  (not yet created)

Changes required:
1. Remove all `Context` parameters
2. Replace every `context.getSharedPreferences(PREFS_NAME, …)` call with
   `DesktopStorage.get/put/getBoolean/putBoolean(…)` directly
3. Keep `hashPasswordV2` / `verifyPassword` unchanged (pure JVM)
4. Remove `getCalculatorDisguise`, `getDecoyMode`, `isEmergencyWipeEnabled` — not relevant on desktop

---

## SessionKeyManager.kt / StorageKeyManager.kt

Both are pure JVM (no Android deps at all) — copy verbatim, change only:
- `android.util.Base64` → `java.util.Base64`
- `android.util.Log`    → println

---

## Map / geo coordinates

Android used an embedded osmdroid MapView.
Desktop: `GeoRow` composable in `ChatScreen.kt` opens
`https://www.openstreetmap.org/?mlat=LAT&mlon=LON&zoom=17`
in the system default browser via `java.awt.Desktop.getDesktop().browse(URI(...))`.

No additional dependencies needed.

---

## Building

```bash
cd D:\TEST2\desktop
.\gradlew run           # run from source
.\gradlew packageMsi    # build Windows installer
.\gradlew packageDeb    # build Linux .deb
```

Requires JDK 17+ and Gradle 8.x (wrapper not yet committed — add with `gradle wrapper`).

---

## Known TODOs before first compile

1. `DesktopCryptoManager.init()` calls `DesktopStorage.resolveDataDir()` — make sure
   `DesktopStorage.init()` is called first in `main.kt` (already done).
2. `DesktopChatStorage` and `DesktopUserStorage` need to be created (see adapt section).
3. `ChatsScreen` contact list must be wired to `DesktopChatStorage.getContacts()`.
4. `LoginScreen` password verify TODO comment needs implementing.
5. `SessionKeyManager` must be ported for end-to-end encryption to work.
