# Architecture

This document describes the system design, module structure, and data flows of Beacon Messenger.

---

## Table of Contents

- [High-Level Overview](#high-level-overview)
- [Client Architecture](#client-architecture)
  - [Layer Model](#layer-model)
  - [Navigation](#navigation)
  - [Module Reference](#module-reference)
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

Deep links (`beacon://invite`, `beacon://channel`) are processed in `handleDeepLink()` before routing.

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

#### `SessionKeyManager.kt`
Manages per-contact Double Ratchet session states. Initialized at app start (before login) from persisted state. Handles:
- X3DH initial key agreement using identity key + signed prekey + one-time prekeys (OPKs)
- Ratchet step on each message send/receive
- Session state serialization

> SPK and OPK private keys are intentionally **not** wrapped by the SMK layer because they are needed at cold start before the user logs in.

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
Three-level data destruction:

| Level | Action |
|---|---|
| `SOFT` | Clear in-memory sessions and caches only |
| `HARD` | Delete all keys, prefs, files, WebView data, databases; optional decoy state creation |
| `NUCLEAR` | `HARD` + `ActivityManager.clearApplicationUserData()` (atomic system wipe, process killed) |

Decoy mode: before HARD wipe, saves `username`, `password_hash`, `user_id` to a temporary plaintext file. On next launch, the app appears to have a legitimate account with fake chats, providing plausible deniability under coercion.

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
Generates and verifies ECDSA-signed contact invitation deep links:
```
beacon://invite?key=<pubKeyB64>&fp=<fingerprint>&nonce=<nonce>&name=<nameB64>&ts=<timestamp>&sig=<sigB64>
```
Signature covers all fields. TTL: 7 days from `ts`. Backward compatible with unsigned codes (no `ts` field).

#### `BackupManager.kt`
Exports all user data to an encrypted binary blob:
- Key derivation: PBKDF2-SHA256, 100 000 iterations
- Encryption: AES-256-GCM
- Includes: messages, contacts, group keys, channel subscriptions, settings

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

## Server Architecture

### State Model

The server maintains in-memory state (no database). All state is lost on restart.

```
authenticated_users: {ws → username}
clients:            {username → {ws, name, public_key}}
prekey_bundles:     {username → [OPK bundles]}
active_calls:       {username → {peer, call_id}}
pending_messages:   {username → [message]}
rate_limits:        {username → {message, reaction, typing, prekey_fetch, ...}}
banned_users:       {username → ban_info}
banned_ips:         {ip → ban_info}
channels:           {channel_id → {name, avatar, admin_id, posts: [...]}}
channel_subscribers: {channel_id → {username}}
```

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
| `upload_prekeys` | Push new OPK bundle to server |
| `typing` | Typing indicator |
| `reaction` | Message reaction |
| `checkin` | Dead Man's Switch check-in |

**Server → Client (selected types):**

| Type | Description |
|---|---|
| `challenge` | Random bytes for ECDSA handshake |
| `auth_ok` | Authentication confirmed |
| `auth_fail` | Authentication rejected |
| `message` | Relayed encrypted message |
| `group_message` | Relayed group message |
| `channel_update` | New channel post |
| `call_invite` | Incoming call from peer |
| `turn_config` | TURN credentials (post-auth) |
| `session_conflict` | New login from another device |
| `prekey_bundle` | OPK bundle for X3DH |
| `opk_low` | Reminder to upload more OPKs |

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
  │──── register {username, pubkey,   │
  │              signature, opks} ───►│
  │◄─── auth_ok ──────────────────────│
  │◄─── turn_config ──────────────────│
```

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
  │── register/login {username,   │
  │     pubKey, signature} ──────►│
  │                               │
  │                    ECDSA.verify(
  │                      signature,
  │                      challenge,
  │                      pubKey)
  │                               │
  │◄── auth_ok ───────────────────│
```

Timeout: 15 seconds. If authentication is not completed in time, the server closes the connection.

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
