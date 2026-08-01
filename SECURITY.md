# Security Model

This document describes the threat model, cryptographic design, and anti-forensics mechanisms of Beacon Messenger.

---

## Table of Contents

- [Threat Model](#threat-model)
- [Cryptographic Design](#cryptographic-design)
  - [Key Hierarchy](#key-hierarchy)
  - [Identity Keys](#identity-keys)
  - [Message Encryption](#message-encryption)
  - [Forward Secrecy](#forward-secrecy)
  - [Group Key Exchange](#group-key-exchange)
  - [Double Encryption at Rest (SMK)](#double-encryption-at-rest-smk)
  - [Password Hashing](#password-hashing)
  - [Backup Encryption](#backup-encryption)
- [Authentication](#authentication)
  - [Server Handshake](#server-handshake)
  - [Invite Codes](#invite-codes)
- [Anti-Forensics](#anti-forensics)
  - [Paranoid Mode](#paranoid-mode)
  - [Screen Protection](#screen-protection)
  - [Anti-Debugging](#anti-debugging)
  - [Root Detection](#root-detection)
  - [Intrusion Detection](#intrusion-detection)
  - [Certificate Pinning](#certificate-pinning)
- [Emergency Mechanisms](#emergency-mechanisms)
  - [Wipe Levels](#wipe-levels)
  - [Panic Password](#panic-password)
  - [Dead Man's Switch](#dead-mans-switch)
  - [Decoy Mode](#decoy-mode)
- [Session Security](#session-security)
- [Known Limitations](#known-limitations)

---

## Threat Model

Beacon is designed to protect against the following adversaries:

### In scope

| Adversary | Capability | Mitigation |
|---|---|---|
| Network attacker | Intercept and modify traffic | TLS + certificate pinning + E2EE |
| MITM with forged CA | Install user CA, proxy TLS | Intrusion detection (USER_CA + PROXY) |
| Server compromise | Server operator reads DB | E2EE; server stores no plaintext |
| Physical device theft | Offline extraction of filesystem | EncryptedSharedPreferences + SMK layer |
| Forensic examination | Cold-boot, JTAG, software extraction | SMK requires password; decoy mode |
| Coercion (legal demand) | Compelled decryption | Panic password, wipe, decoy mode |
| Shoulder surfing | Screen visibility | `FLAG_SECURE` screen protection |
| Debugging / dynamic analysis | Attach JDWP, logcat | Anti-debugging checks, Paranoid Mode log suppression |
| Rooted device attacker | Read prefs as root, bypass keystore | SMK PBKDF2 layer; root detection warning |

### Out of scope

| Scenario | Reason |
|---|---|
| Endpoint compromise (full device root + live RAM dump) | SMK in memory while unlocked; key unavoidable |
| Server-side traffic correlation | Timing and metadata on the wire |
| Coercion of the recipient | Recipient device not controlled |
| Supply-chain attack (malicious build) | Requires independent APK verification |

---

## Cryptographic Design

### Key Hierarchy

```
User Password
    │
    ▼ PBKDF2-SHA256 (300 000 iter, 32B salt)
Password-derived Key (PDK)
    │
    ▼ AES-256-GCM
enc_smk_pwd  ──────────────────────────────────┐
                                               │ decrypt
AndroidKeyStore AES-256 ("beacon_smk_wrap")    │
    │                                          │
    ▼ AES-256-GCM                              ▼
enc_smk_ks  ──────────────────────► Storage Master Key (SMK)  [in memory]
                                               │
                    ┌──────────────────────────┼─────────────────────┐
                    ▼                          ▼                     ▼
           EC identity privkey          Group AES keys       Chat message blobs
         (beacon_ec_keys_enc)              (groups)         (chat_storage_encrypted)
```

### Identity Keys

Each user has one EC key pair on the P-256 (secp256r1) curve. This key pair serves as:
- The long-term identity key in X3DH (sender and recipient)
- The signing key for invite codes and authentication challenges

The private key is stored in `EncryptedSharedPreferences("beacon_ec_keys_enc")` under the key `"ec_priv"`. The stored value is:
- `"smk1:" + Base64(iv[12] + AES-256-GCM(privKey.encoded, smk))` when SMK is set up
- `Base64(privKey.encoded)` for legacy entries (migrated on next read when SMK is unlocked)

The public key is stored as plain Base64 and transmitted to the server on registration.

### Message Encryption

One-to-one messages are encrypted with AES-256-GCM:

```
plaintext
    │
    ▼ AES/GCM/NoPadding
    │  key:  session key (from Double Ratchet)
    │  iv:   12 random bytes (from Cipher.init)
    │  tag:  128-bit authentication tag (appended)
    ▼
iv[12] || ciphertext || tag[16]
```

The ciphertext blob is transmitted inside the `"data"` field of the JSON message, encoded as Base64.

### Forward Secrecy

X3DH-style initial key agreement:

1. Recipient publishes on server: `IK_B` (identity key), `SPK_B` (signed prekey), `OPK_B` (one-time prekey).
2. Sender fetches the bundle and computes:
   ```
   DH1 = ECDH(IK_A, SPK_B)
   DH2 = ECDH(EK_A, IK_B)       ← EK_A: ephemeral key, discarded after send
   DH3 = ECDH(EK_A, SPK_B)
   DH4 = ECDH(EK_A, OPK_B)      ← OPK_B: one-time, deleted by server after fetch
   master_secret = KDF(DH1 || DH2 || DH3 || DH4)
   ```
3. `master_secret` seeds the Double Ratchet.

Each subsequent message ratchets forward. Compromise of a session key does not compromise past or future session keys.

The server is notified when OPK supply drops below the watermark (`OPK_LOW_WATERMARK = 5`) and prompts the client to upload more bundles.

### Group Key Exchange

Each group has a 256-bit random AES key (`groupKey`). It is distributed out-of-band to each member individually:

1. Admin calls `generateGroupKey()` → `SecureRandom().nextBytes(32)`.
2. For each member M:
   ```
   shared = ECDH(adminPriv, memberPub)
   encKey = AES-256-GCM(groupKey, KDF(shared))
   ```
3. `{memberId, encKey}` pairs are sent to the server in the `create_group` message; the server delivers each `encKey` only to the corresponding member.
4. Member calls `decryptGroupKey(encKey, myPriv)` → `groupKey`.

Group messages:
```
plaintext
    │
    ▼ AES/GCM/NoPadding (key = groupKey, iv = random 12B)
iv[12] || ciphertext || tag[16]
```

On member removal, the admin generates a new `groupKey` and redistributes it to remaining members.

When stored locally, `groupKey` is wrapped with the SMK (`"smk1:"` prefix) if unlocked, otherwise stored as plain Base64.

### Double Encryption at Rest (SMK)

All sensitive at-rest values receive a second encryption layer on top of `EncryptedSharedPreferences`.

#### SMK Generation

On first registration:
```kotlin
val smk  = SecureRandom().nextBytes(32)   // 256-bit random key
val salt = SecureRandom().nextBytes(32)   // 256-bit random salt

enc_smk_pwd = AES-256-GCM(smk, PBKDF2(password, salt, 300_000, 256))
enc_smk_ks  = AES-256-GCM(smk, keystoreKey)   // AndroidKeyStore AES-256
```

Both ciphertexts are stored in `EncryptedSharedPreferences("smk_config")`.

#### SMK Unlock Paths

| Path | How | When |
|---|---|---|
| Password login | PBKDF2(password, salt, 300 000) → decrypt `enc_smk_pwd` | Every login |
| Biometric login | AndroidKeyStore key → decrypt `enc_smk_ks` | Biometric success |
| App re-lock unlock | Same two paths | After timeout / screen-off lock |

PBKDF2 operations run on `Dispatchers.IO` — never on the Main thread.

#### SMK Lock

`StorageKeyManager.lock()` fills the in-memory `smk` byte array with zeros and sets it to `null`. Called:
- Before `isAppLocked = true` (screen-off, auto-lock timeout)
- As the first operation in `WipeManager.wipe()`

#### Value Wrapping

```
wrapBytes(bytes):
    iv = random 12 bytes
    ct = AES-256-GCM(bytes, smk, iv)
    return "smk1:" + Base64(iv || ct || tag)

unwrapBytes(stored):
    if not stored.startsWith("smk1:"):
        return Base64.decode(stored)      # legacy fallback
    blob = Base64.decode(stored[5:])
    iv = blob[0:12]
    ct = blob[12:]
    return AES-256-GCM-decrypt(ct, smk, iv)
```

Transparent migration: existing unprotected values are read as legacy Base64 without error. On next write, the value is wrapped. The EC private key uses eager re-wrap: if `StorageKeyManager.isUnlocked` but the stored value has no `"smk1:"` prefix, it is immediately re-wrapped on the first read.

#### What is NOT wrapped by SMK

| Data | Reason |
|---|---|
| SPK / OPK private keys | Needed at cold start before login |
| Double Ratchet session states | Needed at cold start before login |

### Password Hashing

Application passwords are hashed before storage:

```
v2:<saltB64>:<hashB64>
  salt = SecureRandom().nextBytes(16)
  hash = PBKDF2WithHmacSHA256(password, salt, iterations=100_000, keyLen=256)
```

On login, the stored hash is compared to the freshly derived hash. Auto-migration from legacy `SHA-256(password)` (format without `"v2:"` prefix) is performed on the first successful login.

### Backup Encryption

Backup files use the same pattern with a user-supplied backup password:

```
salt    = SecureRandom().nextBytes(16)
key     = PBKDF2-SHA256(backupPassword, salt, 100_000, 256)
iv      = SecureRandom().nextBytes(12)
payload = AES-256-GCM(serialized_data, key, iv)
file    = salt[16] || iv[12] || payload
```

---

## Authentication

### Server Handshake

Authentication is challenge-response via ECDSA. The server never stores or transmits the password:

1. Client connects; server sends `{type: "challenge", data: "<32 random bytes base64>"}`.
2. Client signs the challenge bytes with its EC private key (SHA256withECDSA).
3. Client sends `{type: "register", username, public_key, signature, ...}`.
4. Server verifies the signature against the public key.
5. On success: `{type: "auth_ok"}` + `{type: "turn_config", ...}`.

Handshake timeout: 15 seconds.

Session conflict: when a second device authenticates for the same username, the server sends `{type: "session_conflict"}` to the existing session. The existing client disconnects and notifies the user.

### Invite Codes

Invite codes are ECDSA-signed deep links:

```
beacon://invite?key=<pubKeyB64>&fp=<fp8B>&nonce=<16chars>&name=<nameB64>&ts=<unix>&sig=<sigB64>
```

Signed payload: `key|fp|nonce|name|ts` (pipe-separated).
Signature algorithm: SHA256withECDSA with the inviter's identity key.
TTL: 7 days from `ts`.

Verification:
1. Decode `key` → EC public key.
2. Recompute `fp` = first 8 bytes of SHA-256(encoded public key), compare.
3. Check `ts` + 7 days > now.
4. Verify ECDSA signature.

---

## Anti-Forensics

### Paranoid Mode

When enabled:
- All `Log.d`, `Log.i`, `Log.w` calls are suppressed (via `BLog` wrapper that checks `ParanoidMode.isEnabled`).
- `logcat -c` is executed to clear the current process logcat buffer.
- `IntrusionDetector.scan()` is run on every `onResume()` (on `Dispatchers.IO`).
- On threat detection (`handleThreat()`):
  1. Logcat cleared again.
  2. HTTP POST to user-configured alert URL (fire-and-forget coroutine).
  3. If "wipe on breach" enabled: `WipeManager.wipe(level)`.
  4. Otherwise: stealth mode (show `DecoyScreen`).

### Screen Protection

`WindowManager.LayoutParams.FLAG_SECURE` is applied to the main activity window. This prevents:
- Screenshots via the system screenshot shortcut.
- Screen recording apps capturing the window content.
- The app thumbnail appearing in the Recents screen.

### Anti-Debugging

Checked at startup:
- `android.os.Debug.isDebuggerConnected()` — detects attached JDWP debugger.
- JDWP port check via socket probe.

These checks run before the UI is shown. If a debugger is detected, the app can terminate or suppress sensitive operations.

### Root Detection

Scans for indicators of device compromise:
- Common binaries in PATH: `su`, `busybox`, `magisk`, `daemonsu`.
- Known superuser APK package names.
- Writable paths that should be read-only on stock firmware.
- `RootBeer`-style heuristics.

A detected root is treated as a warning; the user is informed but is not forced to exit. In Paranoid Mode, root detection triggers `handleThreat()`.

### Intrusion Detection

`IntrusionDetector.scan()` returns a `ScanResult` with a list of active threats:

| Threat | Severity | Description |
|---|---|---|
| `PROXY` | Medium | System HTTP proxy configured |
| `USER_CA` | Medium | User-installed root CA present |
| `PROXY + USER_CA` | Critical | Almost certain MITM proxy in place |
| `VPN` | Low | VPN connection active |
| `ADB` | Medium | Android Debug Bridge enabled |
| `DEV_OPTIONS` | Low | Developer options enabled |

In Paranoid Mode, a critical-severity scan result triggers `handleThreat()`.

### Certificate Pinning

`CertificatePinner` (OkHttp3) pins the server's TLS certificate or public key. A connection that presents an unexpected certificate is rejected even if it is signed by a trusted CA. This mitigates attacks that install a custom root CA.

---

## Emergency Mechanisms

### Wipe Levels

| Level | Operations | Use case |
|---|---|---|
| `SOFT` | Zero in-memory keys and session states | Temporary screen lock |
| `HARD` | Delete all prefs, files, databases, WebView data, AndroidKeyStore keys | Threat detected, border crossing |
| `NUCLEAR` | `HARD` + `ActivityManager.clearApplicationUserData()` | Maximum urgency; process is killed by system |

`StorageKeyManager.lock()` is called as the very first operation of any wipe, ensuring the SMK is zeroed from memory before any other destructive step.

### Panic Password

The user can configure a secondary "panic password" in settings. If this password is entered in the login screen instead of the real password, the app:
1. Begins `WipeManager.wipe(HARD)` in the background.
2. May display a fake loading screen to buy time.

This allows inconspicuous triggering of wipe while appearing to log in normally.

### Dead Man's Switch

A scheduled alarm (`AlarmManager.setExactAndAllowWhileIdle`) fires if the user has not performed a check-in within the configured interval (hours or days). On alarm:
1. `WipeReceiver` receives `DMS_FIRE`.
2. `WipeManager.wipe()` is triggered.

Normal check-in: user opens the app (automatic) or taps the manual check-in button. The last check-in timestamp is stored in `EncryptedSharedPreferences`.

`BootReceiver` restores the DMS alarm after device reboot.

### Decoy Mode

When `HARD` wipe is triggered with "post-wipe decoy" enabled:

1. Before deletion, saves to `beacon_recovery` (plaintext file):
   - `username`
   - `password_hash` (the hash, not the password)
   - `user_id`
   - A random selection of contact names

2. Performs full HARD wipe.

3. On next app launch, `beacon_recovery` is detected:
   - A fake account is created using the saved credentials.
   - Fake chat entries are populated.
   - The app appears normal to a cursory inspection.

The decoy account cannot decrypt any real messages (all keys were destroyed). It provides plausible deniability when a coercing party demands to see the device.

---

## Session Security

- One active session per device per username.
- `device_id` is a UUID generated once per installation and transmitted on every authentication.
- If two devices authenticate with the same username, the server sends `session_conflict` to the older session, which then disconnects and alerts the user.
- Session tokens are not stored; full ECDSA re-authentication occurs on each WebSocket connection.

---

## Known Limitations

1. **Server metadata**: The server knows who communicates with whom (social graph) and message timestamps. It does not know message content. Traffic analysis resistance is not provided.

2. **SMK in memory**: While the app is unlocked and in the foreground, the SMK lives in memory. A full RAM dump from a rooted or exploited device could extract it.

3. **AndroidKeyStore software keys**: On devices without a hardware-backed Secure Element, AndroidKeyStore keys are stored as software keys in the TEE or in `/data`. An attacker with deep OS-level access may be able to extract them, bypassing the `enc_smk_ks` path. The `enc_smk_pwd` path (PBKDF2 300K) provides protection independent of the Keystore.

4. **OPK exhaustion**: If a user's OPK supply is exhausted and the client is offline, the server may serve the same OPK to multiple senders. Clients should upload new OPK bundles proactively.

5. **Group key distribution**: Group keys are distributed through the server. A compromised server could refuse to deliver a new group key to a member after rotation, effectively excluding them silently. Out-of-band verification of group membership is recommended for high-security use cases.

6. **Backup password**: The backup password is not stored anywhere. If it is lost, the backup cannot be decrypted. There is no recovery mechanism.

7. **Decoy mode forensics**: A sophisticated forensic examiner may detect evidence of a prior wipe (filesystem timestamps, journal entries, wear-leveling patterns on flash storage). Decoy mode provides social/legal cover, not technical undetectability.

8. **Desktop keystroke interception**: Unlike Android's `FLAG_SECURE` (a real OS-enforced guarantee for that app's window), there is no userspace defense against a hardware keylogger (inline USB device) or an OS-level low-level keyboard hook (e.g. Windows `WH_KEYBOARD_LL`) — these intercept key-press events before any application, including this one, ever receives them. The desktop client mitigates this with an on-screen keyboard, available both for password fields (login, registration, backup, change-password, auto-lock unlock) and for regular chat message composition, with a layout randomized on each open, so text can be entered via mouse clicks without generating a single keystroke. This closes the most common real-world keylogger class (hardware/driver-level keyboard capture). It is complemented by screen-capture exclusion (`WDA_EXCLUDEFROMCAPTURE` on Windows, `NSWindowSharingNone` on macOS) so the on-screen keyboard and message content are not readable via screenshots or screen recording either, and by clipboard hygiene (auto-clear after 30s, exclusion from Windows Clipboard History and Cloud Clipboard sync) for copied message text. None of this defends against memory-scraping malware with kernel-level access, or against the Windows Accessibility/UI Automation API, which can read on-screen control text programmatically — bypassing pixel-level capture protection entirely; there is no cross-toolkit way to opt a window out of this without also breaking legitimate assistive-technology users. Physical typing remains available and is not blocked outside of password fields, so the on-screen keyboard is opt-in per message. On macOS specifically, a stronger mechanism exists (`EnableSecureEventInput()`, the same API Terminal and 1Password use for password prompts) but is not yet wired up.

9. **Desktop swap/hibernation exposure beyond the SMK**: The Storage Master Key is held in a locked, non-pageable native buffer (`VirtualLock`/`mlock`) and message keys are zeroed after use, but the JVM heap as a whole (including transient decrypted message text held by the UI) is not, and cannot practically be, locked against paging by an application running without elevated privileges. On a machine without full-disk encryption (BitLocker/FileVault/LUKS), plaintext could theoretically be recovered from the swap file or a hibernation image. Enabling OS-level full-disk encryption is a deployment recommendation, not something the app can enforce.

10. **Desktop attachment temp files**: Opening a received file attachment decrypts it to a temporary file so the OS can hand it to an external viewer. The temp file is overwritten with `secureDelete` (3-pass) on a timer and on JVM shutdown, rather than left for a plain OS delete — but a hard crash or `kill -9` before either fires can still leave recoverable plaintext in the OS temp directory. The external viewer application may also retain its own reference to the path (e.g. an MRU/recent-files list) outside this app's control.

11. **Prekey-bundle fetch reveals a fingerprint pair to the server**: To establish forward secrecy with a contact for the first time (X3DH), a client asks the server for that contact's prekey bundle by fingerprint (`get_prekey_bundle`) — this is a structural requirement of using a central server for bundle distribution, and the server necessarily learns "A requested B's bundle" at that moment. This is the same limitation Signal's own server has; it is not solved by anonymous token routing (tokens don't exist yet at this point) and is accepted as a floor for this architecture. It's bypassed only when an anonymous-mailbox invite (see below) already carried a token pool before this step becomes necessary.

12. **Anonymous routing coverage is not yet complete**: 1:1 text, typing, read receipts, reactions, edits, deletes, image/file/video chunks, group messages, and call signaling are anonymized via token routing once a token pool exists for that contact (falling back to fingerprint addressing only until then). `channel_post` and `group_message_delete` are not yet covered — the server can see who posts to a channel and who receives a group-delete instruction — and channel subscriber lists are inherently visible to the server today. This is a known, scoped gap, not an oversight; anonymizing channel distribution requires a mailbox-based subscriber-token exchange that hasn't been built yet.

13. ~~Android and Desktop invite codes are mutually incompatible~~ — **fixed**: Desktop's `InviteCodeManager` was rewritten to use the same binary `bc:<...>` wire format as Android (byte layout, DER↔raw ECDSA signature conversion, and EC-point reconstruction mirrored field-for-field), replacing its previous incompatible `beacon://invite?key=...` URL format. This was done as a code-level port without a live cross-platform test — an actual Android↔Desktop invite exchange still needs to be run once to confirm the byte-for-byte port is correct (see `desktop/SECURITY_TEST_PLAN.md`, section 14).
