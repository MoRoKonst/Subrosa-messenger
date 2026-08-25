# Architecture

*Last verified against commit: `4486682` (2026-08-23). This project changes quickly — if you're reading this much later than that date, treat specific claims as needing a fresh code check, not as guaranteed-current.*

This document describes the system design, module structure, and data flows of Subrosa Messenger.

> **Note:** The Channels feature (broadcast channels: `ChannelManager`, `ChannelFeedScreen`, `channel_*` message types and DB tables referenced below) is currently **disabled at the UI layer** on both clients — it didn't fit the product's purpose as a resilient private communication tool rather than a broadcast/social tool, and its metadata wasn't anonymized. The underlying code is left in place, unreachable, in case it's revisited later.

---

## Table of Contents

- [High-Level Overview](#high-level-overview)
- [Client Architecture](#client-architecture)
  - [Layer Model](#layer-model)
  - [Navigation](#navigation)
  - [Module Reference](#module-reference)
- [Desktop Client Architecture](#desktop-client-architecture)
  - [Module Reference (Desktop)](#module-reference-desktop)
  - [Tor Support](#tor-support)
  - [Machine-Bound Keystore](#machine-bound-keystore)
- [Server Architecture](#server-architecture)
  - [State Model](#state-model)
  - [Message Protocol](#message-protocol)
  - [Rate Limiting](#rate-limiting)
- [Data Flows](#data-flows)
  - [Registration](#registration)
  - [One-to-One Messaging](#one-to-one-messaging)
  - [Group Messaging](#group-messaging)
  - [File Transfer](#file-transfer)
  - [WebRTC Calls](#webrtc-calls)
  - [Authentication Handshake](#authentication-handshake)
- [Storage Design](#storage-design)
- [Dependencies](#dependencies)

---

## High-Level Overview

```
┌─────────────────────────────────────┐
│          Android Client             │
│  ┌──────────┐   ┌────────────────┐  │
│  │ Compose  │   │MessengerService│  │
│  │   UI     │◄──│  (background)  │  │
│  └──────────┘   └───────┬────────┘  │
│                         │ WSS       │
└─────────────────────────┼───────────┘
                          │
               ┌──────────▼──────────┐
               │   Python WebSocket  │
               │       Server        │
               │  (relay + signaling)│
               └──────────┬──────────┘
                          │ WebRTC
               ┌──────────▼──────────┐
               │    TURN Server      │
               │    (coturn)         │
               └─────────────────────┘
```

The server is a message relay. It never possesses plaintext content: all messages are encrypted on the sender device before transmission and decrypted only on the recipient device. Call media is peer-to-peer (TURN is used only when direct UDP is blocked).

---

## Client Architecture

### Layer Model

```
┌────────────────────────────────────────────────┐
│  UI Layer (Jetpack Compose screens)             │
│  LoginScreen, ChatsScreen, ChatScreen,          │
│  GroupChatScreen, ChannelFeedScreen,            │
│  ActiveCallScreen, ProfileScreen, ...           │
├────────────────────────────────────────────────┤
│  Application / ViewModel Layer                  │
│  MainActivity (navigation state)                │
│  MessengerService (WebSocket, notifications)    │
│  CallManager (WebRTC)                           │
├────────────────────────────────────────────────┤
│  Domain / Manager Layer                         │
│  CryptoManager    — EC keys, ECDH, ECDSA        │
│  GroupManager     — group keys, membership      │
│  ChannelManager   — broadcast channels          │
│  SessionKeyManager — Double Ratchet sessions    │
│  BackupManager    — export / import             │
│  DeadMansSwitchManager — DMS timer              │
│  IntrusionDetector — threat scanning            │
│  RootDetector     — device integrity            │
│  HoneyTokenManager — tamper detection           │
│  WipeManager      — secure data destruction     │
│  ParanoidMode     — anti-forensics mode         │
│  StorageKeyManager — at-rest SMK layer          │
│  InviteCodeManager — signed invite URLs         │
├────────────────────────────────────────────────┤
│  Storage Layer                                  │
│  UserStorage      — credentials, device prefs  │
│  ChatStorage      — 1-on-1 messages, contacts  │
│  GroupManager     — group messages              │
│  ChannelManager   — channel posts               │
│  SecureFileStorage — encrypted file blobs       │
│  EncryptedStorage — EncryptedSharedPreferences  │
├────────────────────────────────────────────────┤
│  Platform Layer                                 │
│  AndroidKeyStore  — key wrapping                │
│  BiometricPrompt  — biometric authentication    │
│  NotificationManager — system notifications     │
│  ConnectivityManager — network state            │
└────────────────────────────────────────────────┘
```

### Navigation

Navigation is managed entirely in `MainActivity` via a single Compose `mutableStateOf<String>` variable named `screen`. The root composable `AppNavigation()` renders the appropriate screen using a `when` expression:

```
"login"          → LoginScreen
"register"       → RegisterScreen
"chats"          → ChatsScreen       (main hub)
"chat"           → ChatScreen
"group_chat"     → GroupChatScreen
"channel_feed"   → ChannelFeedScreen
"call"           → ActiveCallScreen
"incoming_call"  → IncomingCallScreen
"profile"        → ProfileScreen
"backup"         → BackupScreen
"wipe_settings"  → WipeSettingsScreen
"verify_key"     → VerifyKeyScreen
"servers"        → ServersScreen
"security_diag"  → SecurityDiagnosticsScreen
"decoy"          → DecoyScreen
```

The manifest still registers intent filters for `beacon://invite` and `beacon://channel`, but neither is currently functional: there is no `beacon://invite` handling code anywhere (the invite exchange flow is the `bc:<base64url>` blob, pasted/scanned into a dedicated add-contact screen, not a URI intent), and `handleChannelDeepLink()` (`MainActivity.kt`) is entirely commented out, consistent with Channels being disabled at the UI layer (see `SECURITY.md`, Known Limitations item 12). Treat both deep link schemes as vestigial until either is re-wired.

---

### Module Reference

#### `MessengerService.kt`
Background `Service` (foreground, `dataSync` type). Owns the WebSocket connection lifecycle. All outgoing messages go through this service (via `Intent` extras or direct binder call). All incoming WebSocket messages are dispatched here and persisted or forwarded to the UI via `SharedFlow` / broadcast.

Responsibilities:
- WebSocket connect / reconnect (exponential backoff)
- Heartbeat keepalive
- Chunked file upload and reassembly
- Notification creation (message, call, channel update)
- Session conflict handling
- Outer packet-size padding: `addPadding(packet: JSONObject)` rounds every outgoing WebSocket JSON envelope up to the next multiple of 512 bytes (random string in a `_p` field) right before `sendWs(...)` — see [SECURITY.md](SECURITY.md#traffic-analysis-resistance-padding)

#### `CryptoManager.kt`
Stateless singleton for all EC cryptography. Keys are stored in `EncryptedSharedPreferences("beacon_ec_keys_enc")` — never in `AndroidKeyStore` directly, to allow software export and key rotation.

| Operation | Algorithm |
|---|---|
| Key pair | EC P-256 (secp256r1) |
| ECDH | `KeyAgreement("ECDH")` |
| Symmetric encryption | AES-256-GCM, 12-byte IV, 128-bit tag |
| Digital signature | ECDSA with SHA-256 |
| Key derivation | HKDF-style HMAC-SHA256 |

The private key is stored wrapped with the Storage Master Key (SMK) when the user is logged in (see `StorageKeyManager`).

Also applies content-level padding before encryption — 128–512 random bytes for text (`addPadding`/`removePadding`), 1024–4096 for files/images (`addFilePadding`/`removeFilePadding`) — so ciphertext length doesn't reveal how much real content a message carries. See [SECURITY.md](SECURITY.md#traffic-analysis-resistance-padding) for how this stacks with the packet-level padding above.

#### `SessionKeyManager.kt`
Manages per-contact Double Ratchet session states. Initialized at app start (before login) from persisted state. Handles:
- Hybrid X3DH initial key agreement: classical ECDH (identity key + signed prekey + one-time prekeys) combined with an ML-KEM-768 (`PqCrypto.kt`) encapsulation over HKDF, so the derived root key resists a future quantum adversary even if session transcripts are harvested today
- Ratchet step on each message send/receive
- Session state serialization
- Publishing an anonymous **bootstrap token** (from `AnonTokenManager`'s pool) alongside the prekey bundle, letting a fetcher's `session_init` reply be delivered via `anon_message` instead of direct fingerprint addressing (see [SECURITY.md](SECURITY.md) item 11)

> SPK, OPK, PQ (ML-KEM) private keys, and Double Ratchet session state are SMK-wrapped (`SessionKeyManager.wrapKeyBytes()`/`saveSession()`, see [SECURITY.md](SECURITY.md)). The cold-start case (background service resumed before the user unlocks) is handled without leaving keys unwrapped: `tryUnwrapKeyBytes()` returns `null` rather than throwing when the SMK isn't available yet, callers treat that as "not available yet" and skip gracefully, and `wrapKeyBytes()` falls back to plain Base64 only for writes made while locked (so incoming-traffic-triggered saves still work) — reads of already-wrapped values while locked stay unavailable until unlock, they aren't silently stored unwrapped.

#### `GroupManager.kt`
Manages encrypted group state.

Key lifecycle:
1. Group creator calls `generateGroupKey()` → 32-byte random AES key
2. For each member: `encryptGroupKeyForMember(groupKey, memberPublicKey)` using ECDH + AES-GCM
3. Encrypted key blobs sent to server; server distributes to members
4. On receipt: `decryptGroupKey(encryptedBlob, myPrivateKey)`
5. Group key stored wrapped with SMK in `"groups"` prefs

Message encryption: `AES/GCM/NoPadding`, 12-byte IV prepended.

Key rotation is triggered on member removal.

#### `StorageKeyManager.kt`
Second encryption layer for at-rest data. The Storage Master Key (SMK) is a 256-bit random key that lives in memory only and is zeroed on lock or wipe.

Two copies of the SMK are persisted in `EncryptedSharedPreferences("smk_config")`:

| Key | Protection | Purpose |
|---|---|---|
| `enc_smk_pwd` | PBKDF2-SHA256(password, salt, 300 000 iter) → AES-256-GCM | Offline extraction protection |
| `enc_smk_ks` | AndroidKeyStore AES-256 → AES-256-GCM | Biometric / fast re-lock recovery |

Values protected by the SMK are prefixed with `"smk1:"` to enable transparent backward-compatible migration. See [SECURITY.md](SECURITY.md) for details.

#### `WipeManager.kt`
Two-level data destruction (a third, `SOFT`, existed briefly but was removed — it was never wired to any trigger while still being shown to the user in `WipeSettingsScreen.kt` as a working option, misleading in a security-critical screen):

| Level | Action |
|---|---|
| `HARD` | Delete all keys, prefs, files, WebView data, databases; optional decoy state creation |
| `NUCLEAR` | `HARD` + `ActivityManager.clearApplicationUserData()` (atomic system wipe, process killed) |

Decoy mode: before HARD wipe, saves `username`, `password_hash`, `user_id` to a temporary plaintext file. On next launch, the app appears to have a legitimate account with fake chats — deniability of what's on screen against a coercing party, not undetectability of the wipe itself against a forensic device examination (see `SECURITY.md`, Known Limitations item 7).

#### `IntrusionDetector.kt`
Scans for active interception at runtime. Called on `onResume()` in Paranoid Mode (off-Main-Thread via `Dispatchers.IO`).

| Threat | Detection Method |
|---|---|
| `PROXY` | `System.getProperty("http.proxyHost")` |
| `USER_CA` | AndroidCAStore aliases starting with `"user:"` |
| `VPN` | `ConnectivityManager.TRANSPORT_VPN` |
| `ADB` | `Settings.Global.ADB_ENABLED` |
| `DEV_OPTIONS` | `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` |

PROXY + USER_CA together constitute a critical-severity threat (likely MITM).

#### `ParanoidMode.kt`
Anti-forensics mode toggle. When enabled:
- Suppresses all `Log.d / .i / .w` output via `BLog` wrapper
- Clears logcat buffer on activation
- On threat detection: fires HTTP POST to user-configured alert URL, then triggers wipe or stealth (decoy) mode

HTTP alerts run in `CoroutineScope(Dispatchers.IO + SupervisorJob())` — fire-and-forget, structured concurrency.

#### `HoneyTokenManager.kt`
Tamper detection via canary values. A HMAC of a known set of values is stored at setup time. On each `checkIntegrity()` call, the HMAC is recomputed. A mismatch indicates that underlying storage was modified outside the application.

#### `DeadMansSwitchManager.kt`
Scheduled wipe if the user fails to check in within a configured interval. Uses `AlarmManager.setExactAndAllowWhileIdle`. On alarm fire, `WipeReceiver` triggers `WipeManager.wipe()`.

#### `InviteCodeManager.kt`
Generates and verifies ECDSA-signed contact invitations as a binary blob, prefixed `bc:` and Base64url-encoded — not a URL with individually encoded fields. See [SECURITY.md](SECURITY.md) "Invite Codes" for the exact byte layout. Signature covers the whole pre-signature payload. TTL: 7 days from `ts`. Current format version is `0x03` (adds the mailbox tag field); the older `0x02` format is **rejected outright** on parse (`parseInviteCode` returns `null` for any version mismatch) — it used to fall back to a direct, server-visible lookup, which silently dropped the anonymous-mailbox guarantee with no warning to the user. Desktop and Android share this exact binary format byte-for-byte.

#### `BackupManager.kt`
Exports all user data to an encrypted binary blob:
- Key derivation: **Argon2id** (BouncyCastle `Argon2BytesGenerator`) — 64 MB memory, 3 iterations, parallelism 1
- Encryption: AES-256-GCM
- Includes: messages, contacts, group keys, channel subscriptions, settings

> Not to be confused with `UserStorage`'s login password hash (PBKDF2-SHA256, 100 000 iterations) or `StorageKeyManager`'s SMK wrapping (PBKDF2-SHA256, 300 000 iterations) below — three different KDFs for three different purposes. Backup export specifically uses Argon2id, chosen for its memory-hardness against GPU/ASIC brute-force on a file an attacker could copy and attack offline indefinitely.

#### `CallManager.kt`
WebRTC wrapper around `stream-webrtc-android:1.3.10`:
- `Camera1Enumerator(false)` — YUV/NV21 capture (MIUI compatible)
- `DefaultVideoEncoderFactory(eglBase, false, false)` — VP8 + H264 Baseline HW
- `SurfaceViewRenderer` with shared EGL context
- All remote track and call-end callbacks dispatched to Main thread via `Handler(Looper.getMainLooper()).post{}` to avoid `IllegalStateException` from native WebRTC threads writing Compose state

#### `EncryptedStorage.kt`
Thin wrapper around `EncryptedSharedPreferences`. Returns a named prefs instance backed by an `AndroidKeyStore` master key. All persistent application state except the plaintext recovery blob goes through this.

#### `UserStorage.kt`
Stores user credentials and device settings in `EncryptedSharedPreferences("user_prefs")`.

Password hashing:
- Legacy: `SHA-256(password)` (read-only, migrated on login)
- Current: `"v2:<saltB64>:<hashB64>"` — PBKDF2-SHA256, 16-byte salt, 100 000 iterations
- Panic password uses the same scheme; matching panic password on login triggers wipe

---

## Desktop Client Architecture

The desktop client (`desktop/src/main/kotlin/com/bcon/desktop/`) is a Compose Multiplatform / Compose Desktop port of the Android app, sharing the same wire protocol, cryptographic scheme, and package/module naming pattern (everything lives under `com.bcon.desktop`, including files physically under a `ui/`, `network/`, or `platform/` subfolder). It talks to the same server over the same JSON-over-WebSocket protocol — an Android client and a Desktop client can message each other directly.

It is not built or distributed alongside the Android app; the `desktop/` folder is excluded from the published repository until it is release-ready.

Where Android and Desktop diverge architecturally:

| Concern | Android | Desktop |
|---|---|---|
| Persistent storage | `EncryptedSharedPreferences` (AndroidKeyStore-backed) | `DesktopStorage.kt` — a single AES-256-GCM encrypted JSON blob at `%APPDATA%\BeaconMessenger\storage.enc` |
| Key storage | `AndroidKeyStore` | `DesktopKeyStore.kt` — a PKCS12 keystore (`BEACON.p12`), password machine-derived (see [Machine-Bound Keystore](#machine-bound-keystore)) |
| Anonymity network | Orbot (system-level Tor VPN) | `DesktopTorManager.kt` — local SOCKS5 proxy detection, no VPN (see [Tor Support](#tor-support)) |
| WebRTC | `stream-webrtc-android` | `webrtc-java` (JNI wrapper around native libwebrtc), Windows-only native binaries currently bundled |
| Screen-capture / anti-forensics | OS-level `FLAG_SECURE`, root/ADB detection | `NativeProtection.kt` (JNA): `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` on Windows, `VirtualLock`/`VirtualUnlock` for non-pageable SMK storage; Linux/macOS support is partial |

Cryptography, X3DH/Double-Ratchet session logic, the hybrid ML-KEM-768 post-quantum layer, group encryption, and the invite-code/anonymous-token-routing/mailbox metadata protections are the same design on both platforms — `SessionKeyManager.kt`, `GroupManager.kt`, `AnonTokenManager.kt`, `InviteCodeManager.kt`, and `PqCrypto.kt` are independent ports with matching wire-level behavior, not shared code (Kotlin/JVM allows near-identical source but Android and Desktop are separate Gradle modules with no common module today).

### Module Reference (Desktop)

**Entry & navigation**
- `main.kt` — process entry point; initializes `NativeProtection`, `DesktopStorage`, `DesktopKeyStore`, `CryptoManager`, `SessionKeyManager`, then launches the Compose window via `AppNavigation`.
- `AppNavigation.kt` — Compose router (Material3), analogous to Android's `MainActivity` `screen` state machine.

**Storage & keys**
- `DesktopStorage.kt` — AES-256-GCM encrypted JSON key-value store; Desktop's equivalent of `EncryptedSharedPreferences`.
- `DesktopKeyStore.kt` — PKCS12 keystore (`BEACON.p12`), machine-bound password (see [Machine-Bound Keystore](#machine-bound-keystore)); stores the storage key and the EC identity keypair.
- `StorageKeyManager.kt` — the same SMK (Storage Master Key) at-rest double-encryption layer as Android, ported: PBKDF2(password, 300k) + keystore-wrapped copy, locked native buffer where the platform allows it.
- `UserStorage.kt`, `ChatStorage.kt`, `GroupManager.kt`, `ChannelManager.kt` — same responsibilities as their Android namesakes (credentials/settings, 1:1 messages, groups, channels — channels disabled at the UI layer, same as Android).

**Cryptography**
- `DesktopCryptoManager.kt` — EC P-256 identity keypair, ECDH, peer-public-key cache, image/file encryption; Desktop's `CryptoManager` equivalent.
- `PqCrypto.kt` — ML-KEM-768 wrapper (BouncyCastle 1.79+): `generateKeyPair()` / `encapsulate()` / `decapsulate()`, combined with classical ECDH via HKDF in `SessionKeyManager.kt` for hybrid post-quantum X3DH — identical design to Android's `PqCrypto.kt`.
- `SecureMemory.kt` — zeroing helpers for `ByteArray`/`CharArray` key material (no `String` equivalent exists — the JVM string intern pool and JIT can retain copies outside the caller's control).

**Anonymity & invites**
- `AnonTokenManager.kt` — Desktop port of Android's anonymous token-routing pool (register ~50 tokens with the server, refill at a low-watermark, share with contacts for `anon_message` delivery).
- `InviteCodeManager.kt` — binary `bc:<base64url>` invite-code format, byte-for-byte identical to Android (see [SECURITY.md](SECURITY.md) "Invite Codes").
- `DesktopTorManager.kt` — see [Tor Support](#tor-support).

**Calls**
- `network/WebSocketClient.kt` — OkHttp-based WebSocket client: handshake, message routing (direct + `anon_message`/batched-fetch anonymization), reconnect, Tor-aware client selection.
- `network/DesktopCallManager.kt` — 1:1 audio/video signaling (`call_offer`/`call_answer`/`call_ice`/`call_end`) over the same WebSocket relay as Android, using `webrtc-java`. Group (mesh) calls are not implemented on Desktop yet.

**Security & diagnostics**
- `NativeProtection.kt` — JNA bindings for OS-level anti-forensics: Windows screen-capture exclusion and non-pageable memory locking; degrades to a warning (no enforcement) on platforms without an equivalent API.
- `SecurityDiagnostics.kt` — startup debugger/instrumentation detection (JDWP, Frida argument signatures); can be configured to abort startup if triggered.

**UI** (`ui/`)
- `LoginScreen.kt`, `RegisterScreen.kt`, `ChatsScreen.kt`, `ChatScreen.kt`, `GroupChatScreen.kt`, `ChannelFeedScreen.kt`, `CallScreen.kt`, `ProfileScreen.kt` — Compose screens mirroring the Android screen set (Channels UI present but unreachable, same as Android).
- `SecureTextField.kt` — password-entry field pairing with the on-screen keyboard described in [SECURITY.md](SECURITY.md) item 8.

**Testing**
- `IntegrationSmokeTest.kt` — headless two-process integration test (no GUI): runs the real `WebSocketClient`/`SessionKeyManager`/`CryptoManager` stack end-to-end (connect → register → publish hybrid-PQ prekey bundle → X3DH → Double-Ratchet round trip) with file-based identity exchange instead of the invite-code UI. Invoked via the `smokeTest` Gradle task; `printRuntimeClasspath` supports running it as two separate `java -cp` processes with distinct `APPDATA` for isolated identities. This exists because none of this project's wire-format or crypto work had ever been exercised against a second real process before it was added — compiling successfully is not the same as two independent clients actually completing a handshake.

### Tor Support

Android reaches Tor via Orbot, a system-level VPN that transparently routes all app traffic — no in-app SOCKS handling needed. Desktop has no VPN layer available, so it implements SOCKS5 proxying directly in `WebSocketClient.kt`:

- `DesktopTorManager.detectSocksPort()` probes `127.0.0.1:9050` (standalone Tor) and `127.0.0.1:9150` (Tor Browser's bundled Tor) and returns whichever is listening.
- When the configured server URL is a `.onion` address, `WebSocketClient` builds a second OkHttp client (`torClient`) whose socket factory routes through `Proxy(Proxy.Type.SOCKS, ...)` using a raw `Socket(proxy).connect(InetSocketAddress.createUnresolved(host, port), ...)` — deliberately using the *unresolved* address form so hostname resolution (including the `.onion` address itself) happens inside the Tor circuit, never via the local/system DNS resolver.
- If no local Tor SOCKS proxy is found for a `.onion` server URL, the connection attempt fails fast with a clear error rather than silently falling back to a direct (non-anonymized) connection.
- Non-`.onion` server URLs use the regular direct OkHttp client; Tor is opt-in per configured server, not a global toggle.

### Machine-Bound Keystore

`DesktopKeyStore.kt` stores the storage key and EC identity keypair in a PKCS12 file (`BEACON.p12`), protected by a password that is *derived*, not user-chosen — the same purpose AndroidKeyStore serves on Android (a hardware/OS-backed secret the app never has to ask the user for), adapted to a desktop OS with no equivalent hardware-backed keystore API:

- **Windows**: a random 32-byte seed is generated once and protected with DPAPI (`CryptProtectData`, machine or user scope depending on configuration) via JNA's `Crypt32Util`; the PKCS12 password is `SHA-256(seed)`.
- **Linux**: `SHA-256("BEACON-ks-v2:" + /etc/machine-id)` (falling back to `/var/lib/dbus/machine-id`) — stable across reboots and reinstalls of the app, but tied to that specific machine's OS installation.

This means the PKCS12 file cannot be decrypted if copied to a different machine (Windows: DPAPI-protected seed doesn't unwrap without the original machine/user context; Linux: the machine-id won't match) — a deliberate anti-exfiltration property, at the cost of there being no built-in way to migrate an identity to new hardware other than the normal backup/restore flow (see `BackupManager.kt`).

---

## Server Architecture

### State Model

**This section previously said the server keeps no database and loses all
state on restart — that was wrong.** `Server/server.py` uses a SQLite
file (`DB_PATH`, `messages.db` by default) for anything that needs to
survive a restart, and plain in-memory dicts/sets for everything that's
inherently tied to a live connection. The database file can optionally be
encrypted at rest via SQLCipher (`DB_ENCRYPTION_KEY_HEX` env var, off by
default) — see `SECURITY.md`, Known Limitations item 27, for what that
does and doesn't protect against.

**Persistent (SQLite)** — survives a server restart:

```
pending_messages:        offline-queue fallback for direct (non-anon) messages, 30-day TTL
prekey_bundles_db:       published prekey bundles (OPK pools)
registered_fingerprints: every identity ever registered — backs the access-code
                         gate and the (optional) MAX_REGISTERED_USERS cap
revoked_fingerprints:    identities revoked via "I've been compromised" / DMS —
                         register() rejects a match here regardless of a valid
                         challenge-response
user_totp:               per-account TOTP secrets (device-gated registration)
totp_recovery_codes:     one-time recovery codes for the above
server_access_codes:     invite-style codes for SERVER_ACCESS_PROTECTED deployments
```

**In-memory only** — lost on restart, by design (tied to a live connection
or deliberately short-lived):

```
authenticated_users: {ws → username}
clients:            {username → {ws, name, public_key}}
token_to_ws:         {anon_token → ws}                 — anonymous routing table
token_pending:       {anon_token → [queued anon_delivery]} — TTL 24h, watchdog-swept
known_tokens:        {anon_token}                      — registered-but-not-yet-routed
active_calls:        {username → {peer, call_id}}
rate_limits:         {username → {message, reaction, typing, prekey_fetch, ...}}
banned_ips:          {ip → ban_expiry}
```

A server restart therefore does **not** wipe identities, TOTP protection,
revocations, or the access-code allowlist — but it does drop live
WebSocket connections (clients reconnect automatically) and any
anonymous-routing state in flight (queued `anon_message` deliveries not
yet acknowledged, which is bounded to 24h by a watchdog, not indefinite).

### Message Protocol

All messages are JSON objects over WebSocket. Every message has a `type` field.

**Client → Server (selected types):**

| Type | Description |
|---|---|
| `register` | Initial authentication with ECDSA handshake response |
| `message` | Encrypted 1-on-1 message |
| `group_message` | Encrypted group message |
| `channel_post` | Admin post to channel |
| `call_invite` | WebRTC offer to peer |
| `call_answer` | WebRTC answer |
| `ice_candidate` | WebRTC ICE candidate |
| `call_end` | Terminate call |
| `fetch_prekey_bundle` | Request OPK bundle for X3DH |
| `get_prekey_bundles_batch` | Anonymized prekey fetch: real target padded with decoy fingerprints (own contacts) so the server can't tell which one is real; see [SECURITY.md](SECURITY.md) item 11 |
| `upload_prekeys` | Push new OPK bundle to server |
| `typing` | Typing indicator |
| `reaction` | Message reaction |
| `checkin` | Dead Man's Switch check-in |
| `subscribe_tokens` | Register the client's pool of ~50 anonymous single-use tokens against this connection |
| `anon_message` | Anything routed anonymously (1:1 text, typing, read receipts, reactions, edits, deletes, file/voice/video chunks, call signaling) wrapped in `{token, payload}` instead of being fingerprint-addressed — this is the actual carrier for most client→client traffic, not the `message`/`typing`/`reaction` rows above (those apply when a message is sent to a group or otherwise can't go anonymous) |
| `anon_delivery_ack` | Recipient confirms it actually processed an `anon_delivery` payload — only after this does the server drop its fallback copy; see [SECURITY.md](SECURITY.md) item 18 |
| `revoke_identity` | Authenticated client asks the server to mark its own fingerprint as revoked (persisted, survives restart) |

**Server → Client (selected types):**

| Type | Description |
|---|---|
| `challenge` | Random bytes for ECDSA handshake |
| `handshake_ok` | Signature verified — client may now send `register` |
| *(none)* | An invalid `challenge_response` signature isn't answered with a distinct rejection type — the server just drops the connection |
| `totp_required` / `access_code_required` | `register` rejected — device-gated TOTP or access-code allowlist gate not satisfied, see [SECURITY.md](SECURITY.md#device-gated-totp--recovery-codes) |
| `message` | Relayed encrypted message |
| `group_message` | Relayed group message |
| `channel_update` | New channel post |
| `call_request_audio` / `call_request_video` | Incoming call ping from peer (two-phase call flow) |
| `turn_config` | TURN credentials (post-auth) |
| `session_conflict` | New login from another device |
| `prekey_bundle_response` / `prekey_bundles_batch_response` | Prekey bundle(s) for X3DH |
| `prekey_bundle_request` | Server asks this client to republish its OPK pool (running low) |
| `anon_delivery` | The other side of `anon_message` — payload delivered to whichever connection currently owns the token, without the sender's fingerprint ever appearing |
| `registration_full` | `register` rejected — `MAX_REGISTERED_USERS` cap reached (optional, off by default) |
| `pow_required` | `register` rejected — this fingerprint's first-ever registration needs a `pow_nonce` solved against the handshake challenge (optional, off by default) |
| `identity_revoked` | `register` rejected — this fingerprint was revoked (via `revoke_identity` or Dead Man's Switch) |

### Rate Limiting

Per-user rate limits are enforced server-side:

| Action | Limit |
|---|---|
| Messages | Configurable per-minute burst |
| Reactions | Configurable |
| Typing indicators | Configurable |
| Prekey fetches | Configurable |

Violations result in temporary suspension.

---

## Data Flows

### Registration

```
Client                              Server
  │                                   │
  │──── connect (WSS) ───────────────►│
  │◄─── challenge {bytes} ────────────│
  │                                   │
  │  1. Generate EC key pair (P-256)  │
  │  2. ECDSA sign(challenge)         │
  │  3. PBKDF2 hash(password)         │
  │  4. Generate OPK bundle           │
  │  5. StorageKeyManager.setup()     │
  │                                   │
  │──── challenge_response            │
  │      {public_key, signature} ───► │
  │◄─── handshake_ok ─────────────────│
  │                                   │
  │──── register {name, public_key,   │
  │      device_id, totp_code?,       │
  │      access_code?} ─────────────► │
  │◄─── turn_config ──────────────────│
```

`register`'s `public_key` must match exactly the key just proven in `challenge_response` — mismatches are rejected. `totp_code`/`access_code` are optional, only checked by the server under the conditions in [SECURITY.md](SECURITY.md#device-gated-totp--recovery-codes) (new device_id on an account with TOTP enabled; a private/business server with the access-code allowlist on).

For a fingerprint's very first-ever registration, two more (optional, off by default) checks can apply before any of the above: `MAX_REGISTERED_USERS` (a hard cap on total identities ever registered — rejects with `registration_full` above the cap) and `POW_DIFFICULTY_BITS` (proof-of-work — rejects with `pow_required`, client solves it against the handshake challenge and resends `register` with a `pow_nonce`). Neither ever applies to a reconnect of an already-known fingerprint. See [SECURITY.md](SECURITY.md) item 26.

### One-to-One Messaging

**First message (X3DH key agreement):**

```
Sender                              Server                  Recipient
  │                                   │                         │
  │── fetch_prekey_bundle(recipient) ►│                         │
  │◄─ prekey_bundle {IK, SPK, OPK} ──│                         │
  │                                   │                         │
  │  1. ECDH(mySK, recipientIK)       │                         │
  │  2. ECDH(ephemeral, recipientSPK) │                         │
  │  3. ECDH(ephemeral, recipientOPK) │                         │
  │  4. KDF → session key             │                         │
  │  5. AES-256-GCM(plaintext)        │                         │
  │                                   │                         │
  │── message {ciphertext, ephPub} ──►│── message ─────────────►│
  │                                   │                         │
  │                                   │         1. Recover key  │
  │                                   │         2. AES-256-GCM  │
  │                                   │            decrypt      │
```

**Subsequent messages:** Double Ratchet advances session key. Each message uses a new symmetric key derived from the ratchet state.

### Group Messaging

```
Creator                             Server               Member N
  │                                   │                      │
  │  1. generateGroupKey() → 32B key  │                      │
  │  2. For each member:              │                      │
  │     encryptGroupKeyForMember()    │                      │
  │  3. Create group object           │                      │
  │                                   │                      │
  │── create_group {members,          │                      │
  │     encKeyForEachMember} ────────►│── group_invite ─────►│
  │                                   │                      │
  │                              (member stores decrypted groupKey)
  │                                   │                      │
  │  encryptGroupMessage(text, key)   │                      │
  │── group_message {groupId, ct} ───►│── group_message ────►│
  │                                   │     (broadcast)      │
```

### File Transfer

Files are split into chunks (max 6 MB per packet). Each chunk is sent as a `file_chunk` message. The receiver reassembles chunks in order and decrypts the complete file.

```
Sender                          Server                    Recipient
  │                               │                           │
  │  1. AES-256-GCM encrypt file  │                           │
  │  2. Split into chunks         │                           │
  │                               │                           │
  │─ file_chunk {id, n, total, data} ─►│─ file_chunk ────────►│
  │  (repeat for each chunk)      │                           │
  │                               │                           │
  │                               │          1. Reassemble    │
  │                               │          2. Decrypt       │
```

### WebRTC Calls

```
Caller              Server              Callee
  │                   │                   │
  │── call_invite ───►│── call_invite ───►│
  │◄── call_answer ───│◄── call_answer ───│
  │── ice_candidate ─►│── ice_candidate ─►│
  │◄─ ice_candidate ──│◄─ ice_candidate ──│
  │                   │                   │
  │◄═══════ P2P media (WebRTC) ══════════►│
  │         (via TURN if direct UDP blocked)
```

TURN credentials are delivered by the server after authentication (`turn_config` message). Media never passes through the signaling server.

### Authentication Handshake

```
Client                          Server
  │                               │
  │── connect ───────────────────►│
  │◄── challenge {32 random bytes}│
  │                               │
  │  ECDSA.sign(challenge,        │
  │             privateKey)       │
  │                               │
  │── challenge_response          │
  │   {public_key, signature} ───►│
  │                               │
  │                    ECDSA.verify(
  │                      signature,
  │                      challenge,
  │                      public_key)
  │                               │
  │◄── handshake_ok ──────────────│
  │                               │
  │── register {name, public_key, │
  │   device_id, ...} ───────────►│
```

Timeout: 15 seconds. If authentication is not completed in time (or the signature fails verification), the server closes the connection without sending a distinct rejection message. `register` is a separate step from `challenge_response` — see the Registration flow above for what happens there (device-gating, access-code allowlist, session_conflict).

---

## Storage Design

All persistent data is stored in `EncryptedSharedPreferences` instances backed by Android Keystore. Each logical domain uses a separate named prefs file.

| Prefs File | Owner | Contents |
|---|---|---|
| `user_prefs` | `UserStorage` | Username, password hash, device_id, settings |
| `beacon_ec_keys_enc` | `CryptoManager` | EC identity key pair |
| `chat_storage_encrypted` | `ChatStorage` | Messages, contacts, keys, avatars |
| `groups` | `GroupManager` | Group metadata and keys |
| `group_messages_*` | `GroupManager` | Per-group message history |
| `subscribed_channels` | `ChannelManager` | Channel list |
| `ch_posts_*` | `ChannelManager` | Per-channel post history |
| `smk_config` | `StorageKeyManager` | Encrypted SMK copies |
| `dms_prefs` | `DeadMansSwitchManager` | DMS interval and last check-in |
| `honey_prefs` | `HoneyTokenManager` | Canary HMAC |

Backup files are binary blobs (AES-256-GCM) shared via the system file picker. They are not stored in any cloud.

---

## Dependencies

### Android Client

| Library | Version | Purpose |
|---|---|---|
| Jetpack Compose BOM | 2024.x | UI framework |
| AndroidX Security Crypto | 1.1.0-alpha06 | EncryptedSharedPreferences |
| AndroidX Biometric | 1.1.0 | Fingerprint/face unlock |
| OkHttp3 | 4.12.0 | WebSocket client |
| Kotlin Coroutines | 1.7.3 | Async/IO |
| stream-webrtc-android | 1.3.10 | WebRTC |
| Firebase Messaging | latest | Push notifications |
| CameraX | 1.3.4 | Camera preview |
| osmdroid | 6.1.18 | Map view |
| ZXing | 3.5.1 | QR code generation |
| Play Services Location | 21.2.0 | GPS |

### Server

| Library | Purpose |
|---|---|
| `websockets` | Async WebSocket server |
| `cryptography` | ECDSA verification |
