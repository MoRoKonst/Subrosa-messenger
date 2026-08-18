# Security Model

This document describes the threat model, cryptographic design, and anti-forensics mechanisms of Subrosa Messenger.

---

## Table of Contents

- [Threat Model](#threat-model)
- [Cryptographic Design](#cryptographic-design)
  - [Key Hierarchy](#key-hierarchy)
  - [Identity Keys](#identity-keys)
  - [Message Encryption](#message-encryption)
  - [Traffic Analysis Resistance (Padding)](#traffic-analysis-resistance-padding)
  - [Forward Secrecy](#forward-secrecy)
  - [Group Key Exchange](#group-key-exchange)
  - [Double Encryption at Rest (SMK)](#double-encryption-at-rest-smk)
  - [Password Hashing](#password-hashing)
  - [Backup Encryption](#backup-encryption)
- [Authentication](#authentication)
  - [Server Handshake](#server-handshake)
  - [Device-Gated TOTP + Recovery Codes](#device-gated-totp--recovery-codes)
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

Subrosa is designed to protect against the following adversaries:

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
| Stolen private key (via backup theft, or raw extraction from a compromised device bypassing the backup flow entirely) | Register a new device under the victim's fingerprint, hijack their live session | Mandatory device-gated TOTP — see [Device-Gated TOTP](#device-gated-totp--recovery-codes) |

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

### Traffic Analysis Resistance (Padding)

Even with the content fully encrypted, the *size* of a ciphertext leaks information: a server (or anyone observing the connection) can often guess message content from length alone — a 40-byte ciphertext is very unlikely to be anything but "ok" or "hi", a 2KB one is probably a paragraph, a photo-sized one is obviously a photo. Two independent, stacked padding layers close this:

1. **Content-level padding** (`CryptoManager.kt`, `addPadding`/`removePadding` for text, `addFilePadding`/`removeFilePadding` for files): before encryption, 128–512 random bytes (1024–4096 for files/images) are prepended to the plaintext, with a short length prefix so the real content can be recovered exactly after decryption. This runs inside `aesEncrypt`/`aesDecrypt` and `encryptFile`/`decryptFile`, so every 1:1 message, file, and image gets it automatically — there is no code path that skips it.
2. **Packet-level bucketing** (`MessengerService.kt`, `addPadding(packet: JSONObject)`): independently of the above, the *entire outgoing WebSocket JSON envelope* (ciphertext plus all the surrounding protocol fields) is padded with a random string in a `_p` field up to the next multiple of 512 bytes, right before every `sendWs(...)` call — direct messages, anon-routed messages, and cover-traffic noise packets alike.

The two layers serve different purposes: layer 1 hides how much *content* a message actually contains (a one-word reply and a full paragraph become indistinguishable in ciphertext length once padded to the same bucket), while layer 2 hides the *packet* size on the wire, including protocol overhead, so an eavesdropper watching raw WebSocket frames without any awareness of the JSON structure still can't fingerprint message types by size. Both were self-verified with dedicated checks in `CryptoManager.kt`'s test routines, surfaced in Security Diagnostics.

This defends against **length-based** traffic analysis. It does not defend against **timing-based** correlation (see cover traffic under item 12 in Known Limitations) or the **social-graph** metadata the server inherently sees (item 1).

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

### Post-Quantum Hybrid Key Agreement

X3DH's `master_secret` above is classical ECDH (secp256r1), which is vulnerable to a future quantum computer running Shor's algorithm — and more urgently, to **harvest-now-decrypt-later**: an adversary recording today's traffic could decrypt it retroactively once quantum computers mature. This matters for privileged/legal communication with a decades-long confidentiality requirement.

To close this, the prekey bundle also carries an **ML-KEM-768** public key (FIPS 203, NIST-standardized), signed with the same ECDSA identity key as the SPK and rotated on the same 7-day cadence:

```
pq_shared_secret = ML-KEM-Decapsulate(pq_private_key, pq_ciphertext)
master_secret     = KDF(DH1 || DH2 || DH3 || [DH4] || pq_shared_secret)
```

Only the *initial* X3DH root key needs this hardening — every subsequent Double Ratchet root key is `HKDF(dhOutput, salt=previousRootKey)`, so deriving it requires the actual secret previous root key, not just breaking that step's classical DH. A quantum adversary who breaks every individual ratchet-step DH still cannot advance the chain without the root, and the root is only recoverable by breaking **both** the classical and the ML-KEM component. This is the same reasoning behind Signal's PQXDH.

The same hybrid treatment is applied everywhere else a shared secret is derived via one-shot ephemeral ECDH outside the ratchet chain: the pre-session/legacy message fallback, `edit`, group key distribution, and image/file/voice encryption. A bundle or handshake missing the PQ component is rejected outright rather than silently accepted as classical-only, to close the obvious downgrade attack (a malicious server stripping the field).

**Known limitations:**
- Sessions established *before* this upgrade have a purely classical root key that cannot be hardened retroactively — only a fresh handshake protects a conversation going forward. See the migration note in `SessionKeyManager`.
- The anonymous-mailbox first-contact bootstrap message (see [README.md](README.md#privacy-architecture)) stays classical-only — an invite code carrying a ~1.2 KB ML-KEM key would make invite links/QR codes impractically large. The Double Ratchet session established immediately after it is full PQ-hybrid.

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

#### SPK / OPK private keys and Double Ratchet session state — now wrapped too

**Previously not wrapped**, on the stated reasoning "needed at cold start before login." That reasoning didn't hold up against how the EC identity key already worked: the identity key faces the exact same requirement (it's needed to process incoming X3DH the moment a message arrives, possibly before the user has opened the app) and was already wrapped — the SPK/OPK/session-state omission was an inconsistency, not a deliberate design call, and was closed in `SessionKeyManager.kt`.

The key realization: none of this material is re-read from disk on every message. It's loaded once into memory at `SessionKeyManager.initialize()` (current SPK, the OPK pool, all session states) and kept resident in the running process from then on — locking `StorageKeyManager` only zeros the in-memory SMK, it doesn't touch anything `SessionKeyManager` already loaded. So wrapping this data only matters at the *narrow* moment of a genuine process cold start (device reboot, or the OS killing the background service under memory pressure) that happens to land before the user has unlocked in that new process — not "every message while locked," which would have been a real regression.

Implementation, mirroring the existing EC-identity-key pattern exactly:
- **SPK, previous-SPK, current/previous PQ KEM private keys, OPK pool entries**: each wrapped individually via `StorageKeyManager.wrapBytes()`/`unwrapBytes()` when writing/reading the Base64 string stored in `EncryptedSharedPreferences("session_keys_secure")`, same as `CryptoManager`'s identity key.
- **Double Ratchet session state** (`SessionState` — chain keys, root key, ratchet keypair, skipped-message keys): the whole per-contact JSON blob is wrapped as one unit (`"smk1:"` + `Base64(AES-256-GCM(json_bytes))`) rather than field-by-field, since it's already persisted as a single JSON string per contact.
- **The cold-start-while-locked case is handled explicitly, not left to throw**: a new `tryUnwrapKeyBytes()` helper catches the "SMK is locked" exception and returns null instead of propagating it, so a process cold start before unlock degrades to "this particular SPK/OPK/session isn't available yet" (logged, skipped) rather than crashing `SessionKeyManager.initialize()` outright — regenerating a fresh SPK in that situation was considered and rejected, since the real key is still on disk and just temporarily inaccessible; regenerating would gratuitously invalidate an already-published bundle.
- **`SessionKeyManager.reloadSessionsIfNeeded()`**, called from `StorageKeyManager.unlockWithPassword()`/`unlockWithKeystore()` right after a successful unlock, re-attempts anything that came up unavailable during the locked cold-start window. Idempotent and cheap to call on every unlock, including the common case where everything already loaded fine.

**Desktop had the identical gap, checked and fixed the same day**: Desktop's `SessionKeyManager.kt` mirrors Android's almost line-for-line (same SPK/OPK/PQ-KEM/session-state persistence shape, just via `DesktopStorage.get/put` instead of `EncryptedSharedPreferences`), and Desktop's own `StorageKeyManager` already had the identical `wrapBytes`/`unwrapBytes`/`isUnlocked` primitives — already used for group keys (`GroupManager.kt`) and messages (`ChatStorage.kt`), just never extended to session keys, same oversight as Android. Fixed with the same approach: `wrapKeyBytes`/`tryUnwrapKeyBytes` helpers, wrapped SPK/prev-SPK/PQ-KEM/prev-PQ-KEM/OPK-pool entries and the whole per-contact session-state JSON blob, and `reloadSessionsIfNeeded()` wired into both `StorageKeyManager.unlockWithPassword()`/`unlockWithKeystore()`. Compiles clean.

Note: unlike Android, Desktop's own identity key (`CryptoManager.kt`) is *not* SMK-wrapped — it uses a separate protection mechanism instead (`DesktopKeyStore`, a machine-bound PKCS12 keystore), an intentionally different design already in place before this pass, not part of this gap.

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

Authentication is challenge-response via ECDSA. The server never stores or transmits the password — the password only ever protects local storage (SMK), it is never part of the network protocol at all:

1. Client connects; server sends `{type: "challenge", data: "<32 random bytes base64>"}`.
2. Client signs the challenge bytes with its EC private key (SHA256withECDSA) and replies `{type: "challenge_response", public_key, signature}`.
3. Server verifies the signature against the supplied public key and, on success, replies `{type: "handshake_ok"}`, remembering the verified key bytes for the next step.
4. Client sends a separate `{type: "register", name, public_key, device_id, ...}` — `public_key` here is checked to match exactly the key that was just proven in step 2/3 (identity-binding fix, see Known Limitations item 14); a mismatch is rejected outright, closing the connection.
5. The server derives the fingerprint (`SHA-256(public_key)[:8]`), which is also the username, and applies any additional gates before accepting the registration — in order: optional one-time access-code allowlist for private/business deployments (`access_code_required` on failure), then device-gated TOTP if the account has it enabled (`totp_required` on failure — see [Device-Gated TOTP](#device-gated-totp--recovery-codes) below). Only once these pass does the server accept the connection, resolve `session_conflict` if another device is already registered under this fingerprint, and later send `{type: "turn_config", ...}` for call signaling.

Handshake timeout: 15 seconds.

Session conflict: when a second `device_id` registers for the same fingerprint, the server sends `{type: "session_conflict", ts}` to the existing session (and a push notification via FCM if the old session isn't live to receive the WebSocket message). The existing client disconnects and notifies the user. The server's `connect()` reconnect loop on both clients does not currently distinguish `session_conflict` from an ordinary network disconnect, so both devices can end up in a "reconnect war" alternately displacing each other — device-gated TOTP (below) prevents this for any device the fingerprint hasn't registered with a valid code, but does not resolve the race for two device_ids the account has already registered.

### Device-Gated TOTP + Recovery Codes

Since 2026-08-10, TOTP is a **mandatory** step immediately after registration, not opt-in — the client won't proceed to the chat list until it's set up. It serves two purposes with the same secret:

- **Backup import gate**: `BackupManager.importBackup()` requires a valid current TOTP code if the backup being restored has `totp_enabled=true` — closes the "file + password alone is enough to hijack the identity" gap for anyone who also enabled this. Also required to *export* a new backup at all (`BackupScreen.kt`/Desktop equivalent won't produce a new file without TOTP enabled first).
- **Device-gated server registration**: the server (`user_totp_secrets`, `server.py`) requires a valid TOTP code in `register()` whenever `device_id` is new for that fingerprint — exactly the condition that would otherwise open the reconnect-war/session-hijack window described above. A reconnect from an already-known `device_id` never needs a code, so this doesn't affect ordinary mobile-network reconnect churn.

The secret is generated client-side, shown once with an `otpauth://` URI for any standard authenticator app, and is never included in the backup file itself (only the boolean `totp_enabled` flag is) — deliberately, so a stolen backup + password alone can't also recover the TOTP secret.

**Recovery codes**: 8 one-time codes are generated and shown once when TOTP is enabled (`totp_setup_ok.recovery_codes`), the same model as GitHub/Google 2FA. The server stores only their SHA-256 hashes (`totp_recovery_codes` table). A recovery code can substitute for a TOTP code in `register()` if the authenticator is lost; redeeming one is atomic (`UPDATE ... WHERE used = 0`, so two simultaneous redemption attempts of the same code can't both succeed) and immediately revokes the account's TOTP secret and all other recovery codes — the account returns to "no TOTP" and requires a deliberate fresh setup from the now-trusted device, rather than leaving stale credentials usable by whoever else might have seen them.

**Known limitation**: accounts created before 2026-08-10 were not migrated to mandatory TOTP retroactively — this only applies to registrations after that date. There is currently no recovery path if both the TOTP secret *and* all recovery codes are lost (by design, same rationale as the backup password having no recovery mechanism below) — the account's fingerprint becomes permanently unable to register a new `device_id` until an operator manually clears its `user_totp_secrets` row.

### Invite Codes

Invite codes are ECDSA-signed binary blobs, prefixed and Base64url-encoded (no padding):

```
bc:<base64url(payload)>
```

Payload layout (current format, version `0x03`):

```
version(1B) | ts(4B) | nonce(8B) | mailboxTag(16B) | fp(8B) | ecPoint(65B) | nameLen(1B) | name(nameLen B) | rawSig(64B)
```

- `ecPoint` is the raw 65-byte uncompressed EC point (X9.62 `0x04 || X || Y`); the P-256 X.509 SPKI header is reconstructed on parse rather than carried in the invite.
- `rawSig` is the raw `r || s` ECDSA signature (32 bytes each, sign-corrected), not DER — converted to/from DER only around the JCA `Signature` API.
- Version `0x02` (legacy, no `mailboxTag` field) is **rejected outright** on parse — it used to be accepted for backward compatibility, with a client-side fallback to a direct, server-visible `get_key` lookup naming the target fingerprint when no mailbox tag was present. That fallback silently dropped the anonymous-mailbox guarantee with no warning to the user; found while building `SCENARIOS.md`'s "First contact" scenario as a branching tree and cut entirely the same day, on both platforms (Desktop's version of the bug was worse — it called the direct lookup unconditionally, on every contact add, not only when a tag was missing). A code in the old format now just fails to parse, same as any other invalid code.

Signed payload (everything before `rawSig`): `version | ts | nonce | [mailboxTag] | fp | ecPoint | nameLen | name`.
Signature algorithm: SHA256withECDSA with the inviter's identity key.
TTL: 7 days from `ts`.

Verification:
1. Reconstruct the EC public key from `ecPoint` (prepend the fixed X.509 header).
2. Recompute `fp` = first 8 bytes of SHA-256(X.509-encoded public key), compare.
3. Check `ts` + 7 days > now.
4. Verify ECDSA signature over the signed payload.

Desktop and Android share this exact binary format (byte-for-byte, including the DER↔raw signature conversion and EC-point reconstruction) — see item 13 below for the history of that port.

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
| `HARD` | Delete all prefs, files, databases, WebView data, AndroidKeyStore keys | Threat detected, border crossing |
| `NUCLEAR` | `HARD` + `ActivityManager.clearApplicationUserData()` | Maximum urgency; process is killed by system |

A `SOFT` level existed briefly but was removed (`WipeManager.kt`) — it was never wired to any trigger, yet was shown to the user in `WipeSettingsScreen.kt` as if it were a working option ("Мягкий (SOFT)" / "Очищает кеш и оперативную память"), which was misleading in a security-critical settings screen rather than merely dead code. `HARD`/`NUCLEAR` were not affected by the removal.

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

- One active session per device per username (fingerprint).
- `device_id` is a UUID generated once per installation and transmitted on every authentication.
- If a second, previously-unseen `device_id` registers for the same fingerprint, the server sends `session_conflict` to the older session, which then disconnects and alerts the user — see [Device-Gated TOTP](#device-gated-totp--recovery-codes) for what gates that new `device_id` from registering in the first place.
- Session tokens are not stored; full ECDSA re-authentication occurs on each WebSocket connection.

---

## Known Limitations

1. **Server metadata**: The server knows who communicates with whom (social graph) and message timestamps. It does not know message content. **Length-based** traffic analysis is mitigated by the two-layer padding scheme (see [Traffic Analysis Resistance](#traffic-analysis-resistance-padding)), but **timing-based** correlation and the social graph itself are not addressed by padding — see item 12 for what anon-token routing does and does not cover.

2. **SMK in memory**: While the app is unlocked and in the foreground, the SMK lives in memory. A full RAM dump from a rooted or exploited device could extract it.

3. **AndroidKeyStore software keys**: On devices without a hardware-backed Secure Element, AndroidKeyStore keys are stored as software keys in the TEE or in `/data`. An attacker with deep OS-level access may be able to extract them, bypassing the `enc_smk_ks` path. The `enc_smk_pwd` path (PBKDF2 300K) provides protection independent of the Keystore.

4. ~~OPK exhaustion: the server may serve the same OPK to multiple senders~~ — **re-verified 2026-08-10, does not happen under concurrent requests**: OPK issuance (`get_prekey_bundle`/`federated_get_bundle` in `server.py`) reads-and-pops the OPK list inside the same global `asyncio.Lock()`, with no `await` in the critical section — genuinely atomic under asyncio's single-threaded model, a second simultaneous request gets the next OPK, never the same one. The one real (much narrower) residual case: `db_save_bundle()`'s SQLite write happens *after* the lock is released, as a fire-and-forget task — a server crash in that specific window could theoretically let an already-issued OPK be handed out again after restart. Even then, the client already catches it: `SessionKeyManager.consumeOpk()` returns `null` for an OPK already consumed locally, `receiveSession()` throws a synchronous `SecurityException` right at handshake time (not a delayed decrypt failure), and the caller (`processSessionInit()`) already self-heals — requests a fresh bundle and sends `session_reset` to the sender. If a user's OPK supply runs low, the server proactively asks the client to republish (`prekey_bundle_request`, low-watermark 5 of a 10-key pool) rather than silently degrading.

5. **Group key distribution**: Group keys are distributed through the server. A compromised server could refuse to deliver a new group key to a member after rotation, effectively excluding them silently. Out-of-band verification of group membership is recommended for high-security use cases.

6. **Backup password**: The backup password is not stored anywhere. If it is lost, the backup cannot be decrypted. There is no recovery mechanism.

7. **Decoy mode forensics**: A sophisticated forensic examiner may detect evidence of a prior wipe (filesystem timestamps, journal entries, wear-leveling patterns on flash storage). Decoy mode provides social/legal cover, not technical undetectability.

8. **Desktop keystroke interception**: Unlike Android's `FLAG_SECURE` (a real OS-enforced guarantee for that app's window), there is no userspace defense against a hardware keylogger (inline USB device) or an OS-level low-level keyboard hook (e.g. Windows `WH_KEYBOARD_LL`) — these intercept key-press events before any application, including this one, ever receives them. The desktop client mitigates this with an on-screen keyboard, available both for password fields (login, registration, backup, change-password, auto-lock unlock) and for regular chat message composition, with a layout randomized on each open, so text can be entered via mouse clicks without generating a single keystroke. This closes the most common real-world keylogger class (hardware/driver-level keyboard capture). It is complemented by screen-capture exclusion (`WDA_EXCLUDEFROMCAPTURE` on Windows, `NSWindowSharingNone` on macOS) so the on-screen keyboard and message content are not readable via screenshots or screen recording either, and by clipboard hygiene (auto-clear after 30s, exclusion from Windows Clipboard History and Cloud Clipboard sync) for copied message text. None of this defends against memory-scraping malware with kernel-level access, or against the Windows Accessibility/UI Automation API, which can read on-screen control text programmatically — bypassing pixel-level capture protection entirely; there is no cross-toolkit way to opt a window out of this without also breaking legitimate assistive-technology users. Physical typing remains available and is not blocked outside of password fields, so the on-screen keyboard is opt-in per message. On macOS specifically, a stronger mechanism exists (`EnableSecureEventInput()`, the same API Terminal and 1Password use for password prompts) but is not yet wired up.

9. **Desktop swap/hibernation exposure beyond the SMK**: The Storage Master Key is held in a locked, non-pageable native buffer (`VirtualLock`/`mlock`) and message keys are zeroed after use, but the JVM heap as a whole (including transient decrypted message text held by the UI) is not, and cannot practically be, locked against paging by an application running without elevated privileges. On a machine without full-disk encryption (BitLocker/FileVault/LUKS), plaintext could theoretically be recovered from the swap file or a hibernation image. Enabling OS-level full-disk encryption is a deployment recommendation, not something the app can enforce.

10. **Desktop attachment temp files**: Opening a received file attachment decrypts it to a temporary file so the OS can hand it to an external viewer. The temp file is overwritten with `secureDelete` (3-pass) on a timer and on JVM shutdown, rather than left for a plain OS delete — but a hard crash or `kill -9` before either fires can still leave recoverable plaintext in the OS temp directory. The external viewer application may also retain its own reference to the path (e.g. an MRU/recent-files list) outside this app's control.

11. ~~Prekey-bundle fetch reveals a fingerprint pair to the server~~ — **partially mitigated, with known residual leaks**: `get_prekey_bundle` used to tell the server directly "A wants B's bundle" — the same limitation Signal's own server has. This is now reduced two ways, both reusing existing primitives rather than new cryptography: (a) **batched anonymous fetch** (`get_prekey_bundles_batch`) — the real target is padded with decoy targets drawn from the requester's own existing contacts (mirroring the anonymous-mailbox fake-tag pattern; decoys must be *real* fingerprints here, unlike mailbox tags, or the server would trivially spot the one genuine request among fakes — self-created "ghost" accounts were considered and rejected as decoys, since an account that never carries real traffic becomes distinguishable and excludable over time), never consuming a decoy's one-time prekey; falls back to the old single-target fetch when the requester has no contacts to use as cover (a batch of size 1 provides none). (b) **Bootstrap token** — every bundle the server hands out (batched or direct) is now also stamped, at serve time, with one of the bundle owner's currently-registered anonymous tokens (from the pool already maintained by `AnonTokenManager`/`subscribe_tokens`), letting the resulting `session_init` be delivered via `anon_message` instead of directly addressed — closing the follow-on leak where batching only the fetch would still be undone by a directly-addressed `session_init` moments later.

    **Residual gaps found during self-audit, not yet closed:** (i) because decoys are drawn from the requester's *real* contact list, a single batch hands the server that requester's entire contact list in cleartext — the mechanism trades "which fingerprint is the real target" for "here is my full contact graph," which is a real cost, not a free anonymization; (ii) batch size shrinks below `MAX_BATCH_BUNDLE_TARGETS` when the requester has fewer contacts than that, leaking an approximate contact-list size; (iii) if the target's bundle-serving code path never had a registered anon token to attach (or a malicious server simply omits `bootstrap_token` every time), the client silently falls back to direct fingerprint addressing for `session_init` with no user-visible warning that anonymization degraded — a passive server can force this downgrade unconditionally and the client has no way to detect it happened. None of these break message confidentiality (the E2EE payload itself is unaffected), but they meaningfully limit the anonymity property this mechanism was built for.

    **This mitigation (unlike the ML-KEM/X3DH crypto elsewhere in this document) is original protocol-design work, not an implementation of an independently peer-reviewed anonymity standard** — the same honest caveat that already applies to the anon-token-routing/mailbox/cover-traffic system it extends. It has not been independently audited.

12. **Anonymous routing coverage is not yet complete**: 1:1 text, typing, read receipts, reactions, edits, deletes, image/file/video chunks, group messages, group-message deletion, and (as of item 18 below) 1:1 call signaling are anonymized via token routing. There is no fingerprint-addressed fallback for any of these — if no anon token is available for a contact, the message queues locally and retries via anon-token refill / mailbox bootstrap rather than sending in the clear (see the "cut the direct fallback" decision this was changed to). Group-call signaling (`call_group_*`) is deliberately **excluded** — see item 18 below. `channel_post` is not covered — the server could see who posts and channel subscriber lists are inherently visible — but the Channels feature is currently disabled at the UI layer on both clients (see `ARCHITECTURE.md`), so this gap has no live attack surface today. If channels are ever re-enabled, anonymizing distribution needs the same mailbox-based subscriber-token exchange described when that decision was made.

13. ~~Android and Desktop invite codes are mutually incompatible~~ — **fixed**: Desktop's `InviteCodeManager` was rewritten to use the same binary `bc:<...>` wire format as Android (byte layout, DER↔raw ECDSA signature conversion, and EC-point reconstruction mirrored field-for-field), replacing its previous incompatible `Subrosa://invite?key=...` URL format. This was done as a code-level port without a live cross-platform test — an actual Android↔Desktop invite exchange still needs to be run once to confirm the byte-for-byte port is correct (see `desktop/SECURITY_TEST_PLAN.md`, section 14).

14. ~~Server never bound a client's `register` identity to the key proven in the handshake~~ — **fixed**: `challenge_response` proved a client owned *some* keypair, but the subsequent `register` message read a completely separate, client-supplied `public_key` field to derive the username (`SHA-256(public_key)[:8]`), with no check that it matched the key that passed the handshake. In practice this let anyone who knew a victim's *public* key (public by design — it's their identity key) register under the victim's fingerprint without owning the victim's private key at all: the real device gets kicked via `session_conflict`, and messages addressed to that fingerprint arrive at the attacker's connection instead. This did **not** allow decrypting the victim's traffic or forging a valid session — `SessionKeyManager.initiateSession()`/`receiveSession()` verify the SPK and PQ-key signatures against the claimed identity key before using a bundle, and the attacker cannot produce a valid signature without the victim's private key — so the impact was availability/connection-hijacking and metadata exposure (timing, size of incoming traffic), not confidentiality or authenticity of message content. Fixed in `ForEXP/server.py`: the public key bytes verified during `challenge_response` are now captured and `register` is rejected unless its `public_key` matches exactly (federation peers, which authenticate via a separate HMAC scheme, are exempt from this specific check).

15. ~~Group-key rotation on member removal could deliver the new key to the removed member~~ — **fixed**: In `GroupInfoScreen.kt`, removing a member read the pre-removal Compose state (`group!!.members`) to build the post-rotation recipient list, and `MessengerService.rotateGroupKey()` only ever excluded the *caller* (`it != username`), never the specific member being removed. The net effect: the freshly-rotated AES-256 group key was sent directly to the account that had just been kicked, defeating the entire purpose of rotating on removal. Fixed by reloading the group's member list from storage after removal completes, and explicitly filtering out the removed member id as a second layer of defense at the call site. Confirmed the Desktop client does not share this bug — its `rotateGroupKey()` re-reads group state from storage internally, after removal has already persisted.

16. ~~Several server message types bypassed rate limiting entirely~~ — **fixed**: `rate_limit_check()`'s `default_limits` table was missing entries for `anon_message` and `mailbox_put`, so those types silently resolved to "no limit" (the function returns `True` unconditionally when `max_count` is falsy) despite looking rate-limited in the code that calls it. `register_bundle`, `channel_create`, `subscribe_tokens`, and `profile_update` never called `rate_limit_check()` at all, and `register_bundle` additionally had no size cap (unlike the equivalent `publish_prekey_bundle` path), making it a cheap memory/disk-growth vector for any client willing to self-register a throwaway identity. All five now have explicit per-type limits and `register_bundle` enforces the same `MAX_BUNDLE_SIZE_BYTES` cap as the primary bundle-publish path.

17. ~~Self-hosted relay ("son") servers were hardcoded to federate with the operator's public server~~ — **fixed**: `ForEXP/start-son-server.bat` unconditionally wrote `FEDERATION_PEERS=wss://api.beacon-app.org` into the generated `.env` on first run, regardless of user intent — anyone using the quick-start script to build an entirely private, self-contained federation among their own nodes would still have that node attempt to connect to the operator's infrastructure. There was no data-confidentiality impact (the server only ever relays ciphertext, and federation itself requires a shared `FEDERATION_SECRET` the operator's server wouldn't have), but it was an unwanted, undisclosed network connection and a real independence concern for anyone deploying a fully private mesh. The script now asks explicitly at setup time whether to join the public federation, connect to a custom primary server, or run with no primary at all (self-contained, the default choice) — see [self-hosting guide](self-hosting.html) for the current flow.

18. ~~Call signaling was never anonymized, to avoid a reliability bug~~ — **fixed via a two-phase request/response flow** (1:1 calls only; `call_group_*` group-call signaling is unaffected by this item and still always goes out directly, see below). The original problem: routing `call_offer`/`call_ice`/etc. through `anon_message` meant a recipient who was even momentarily offline (a brief reconnect, a network blip) got the message silently queued instead of delivered live — no live-delivery guarantee, and no missed-call/FCM-wake fallback for anon-routed traffic (that only exists on the server's *direct* call-relay path). A late-delivered `call_offer` is useless once the caller has already timed out, and a queued `call_end` could leave the other side's call UI hanging. This was reproduced live via matched client/server logs (`[ANON] Токен ... офлайн, сообщение в очереди` at the exact moment a call attempt silently failed) and initially "fixed" by routing all call signaling direct — closing the reliability bug but reopening the metadata leak (server sees who calls whom and when).

    The two-phase flow splits a call into two steps: a lightweight `call_request_audio`/`call_request_video` ping is sent first (anon-routed, tolerant of a queued/delayed delivery — if the recipient reconnects within the existing 45s ring timeout, the server's `token_pending` queue flushes to them the moment they resubscribe to their tokens, which happens automatically on every reconnect). The recipient's `call_response(accepted=true)` goes back the same anonymized way. A genuinely offline recipient (no reconnect within 45s) simply produces a clean "no answer" on the caller's side, the same as a real phone call.

    **The first version of this fix also anonymized the real SDP/ICE signaling** (`call_offer`/`answer`/`ice`/`end`) that follows acceptance, reasoning that liveness confirmed a second earlier meant subsequent sends would also land live. **Live testing on a real phone disproved this**: even after a confirmed `call_response`, the phone's WebSocket connection could blip for a fraction of a second in the middle of the SDP/ICE exchange — long enough for the server to momentarily see that token as offline and queue one specific packet (an ICE candidate, or the answer itself) instead of delivering it live, confirmed via server logs showing a mix of `[ANON] Доставлено по токену` and `[ANON] Токен ... офлайн, сообщение в очереди` within the same call attempt. SDP/ICE negotiation can't tolerate even a few seconds of delay on a single packet — unlike the request phase, there's no forgiving timeout here. Real SDP/ICE signaling was reverted to direct addressing as a stopgap at that point in the project. Group calls (`call_group_invite`/`call_group_join`/`call_group_answer`/`call_group_ice`/`call_group_leave`) were never brought into the two-phase flow at all — they remain always direct, unaffected by anything in this item.

    **Current state (this stopgap no longer applies)**: `call_offer`/`answer`/`ice`/`end` route through the same `sendAnonOrDirect()` path as every other 1:1 message type — no call-signaling-specific direct-only carve-out remains in the code. Two changes made this safe to reintroduce: `call_end` gained a P2P DataChannel "bye" as its true primary path (server-routed `call_end` is now only the fallback for when that channel isn't open yet), removing the specific failure mode where a queued hangup could leave the other side's call UI stuck; and, separately, `sendAnonOrDirect` itself no longer has an unconditional direct-fallback for *any* message type it's used for (see the "cut the direct fallback" decision — when no anon token is available, the packet queues and retries via the anon-token-refill/mailbox path instead of sending in the clear). The original packet-loss failure mode this item documents was real and reproduced live; it just isn't the current architecture's behavior anymore.

19. ~~A contact's anonymous-token pool could permanently fail to bootstrap, silently pinning that conversation to direct/legacy addressing forever~~ — **fixed**: sharing tokens with a contact (`sendAnonTokensTo`) itself requires wrapping the token payload in `anon_message`, which requires *already having* a token from that contact — a token they can only ever give you the same way. The one path that breaks this circularity is the anonymous mailbox (it needs only the invite-code-derived tag and the contact's public key, not a pre-existing token) — but the client's mailbox branch for sending a real message is gated on `!SessionKeyManager.hasSession(to)`, so once a session was established some other way (e.g. both sides independently fetched each other's prekey bundle in a race, or any first message succeeded via the ordinary X3DH path instead of mailbox), mailbox stopped being tried for that contact at all. With no other bootstrap path available, that pair's token pool could never be seeded — not "hasn't happened yet" but structurally unable to happen — leaving every message between them on direct or legacy addressing permanently, with the server seeing the real fingerprint pair on every send. Fixed by giving `sendAnonTokensTo` its own mailbox fallback, independent of session state: when no anon token is available to wrap the token-sharing message, and a mailbox tag for that contact still exists, it deposits the token payload via `mailbox_put` directly instead of giving up. (While implementing this on Desktop, also found and fixed a related gap in `handleMailboxResult`: unlike Android, it had no check to keep non-message mailbox payloads — like this new token-only bootstrap deposit — from being surfaced to the UI as a literal chat bubble.)

20. ~~Revisiting your own Profile screen could silently orphan an in-progress mailbox exchange, permanently pinning a contact's channel to "establishing" forever~~ — **fixed**: the invite code shown in Profile (and the anonymous-mailbox tag embedded in it) was regenerated on every visit to the screen, immediately removing the previous tag from "tags I poll for" and replacing it with a brand-new one nobody else knew about. If a contact had already been given the old invite code and was mid-exchange (or hadn't gotten around to using it yet), their deposits kept landing under the old, now-abandoned tag while the local client polled for the new one — a permanent mismatch, not a transient one. Root-caused via live server-side instrumentation (temporary debug logging added to `mailbox_put`/`mailbox_fetch`): server logs showed deposits accumulating successfully under a tag that the depositing contact's *own* fetch requests never queried for, while the other side's mailbox held tags neither party was polling. Fixed by persisting the invite code once generated and reusing it on subsequent visits, only regenerating when it actually hits the existing 7-day TTL — the code (and its mailbox tag) now stays stable for as long as it's valid, instead of rotating on every screen view. (Desktop had a related but less severe version of the same bug — it never removed the old tag, so exchanges didn't get invalidated, but "tags I poll for" grew unbounded on every visit, which would eventually crowd out the decoy-tag padding in `buildFetchTagList` once real tags exceeded the batch size, weakening the anonymity that padding provides. Fixed the same way: persist and reuse.)

    **Follow-up bug found in this fix itself, same day**: the first version only called `addMyMailboxTag` in the "generate a fresh code" branch — reusing an already-persisted code (the normal, common case after this fix) skipped it entirely. If the invite-code text (`UserStorage`) and "my mailbox tags" (`AnonTokenManager`, a separate encrypted prefs file) ever fell out of sync — e.g. a partial data reset that clears one file but not the other, observed in practice across repeated test reinstalls — the reused code's tag would silently never be registered, leaving `pollMailbox()` with zero real tags to check for indefinitely (confirmed live: zero `pollMailbox` log lines fired for an entire session). Fixed by making tag registration unconditional on every call — `addMyMailboxTag` is idempotent, so re-registering an already-known tag is a no-op.

    **A second, more fundamental gap found the same day**: both of the fixes above only ran when the user's own Profile screen was actually composed (Android) or `generateInviteLink()` was actually called (Desktop) — both are lazy, UI-triggered paths. A user who added contacts purely through the "add contact" dialog, without ever opening their own Profile screen first, never registered a mailbox tag for themselves at all, in any session, regardless of the fixes above. Confirmed live on a fresh install that only used "add contact": `pollMailbox: 20 тегов (0 реальных)` indefinitely — the device could deposit tokens for contacts (it had *their* tag from redeeming *their* invite code) but had nothing of its own for contacts to deposit into. Fixed by moving tag registration out of the UI entirely: Android now ensures it in `MessengerService.onCreate()` (`ensureMyMailboxTagRegistered()`, mirroring ProfileScreen's reuse-until-TTL logic), and Desktop in `WebSocketClient.connect()` — both run unconditionally as soon as the account is usable, independent of whether the user ever visits their own Profile screen.

21. ~~A mailbox deposit auto-added the sender as a contact and surfaced their message even if the recipient never added the sender back~~ — **fixed**: possessing someone's invite code is enough to compute their mailbox tag and deposit into it — but the product's intended anti-spam contract is that a message never reaches a user unless *that user* independently added the sender first (mutual/reciprocal add), not merely that the sender knows how to reach the recipient's mailbox. The mailbox-deposit handler auto-created a contact entry and displayed any real message unconditionally, so anyone in possession of a user's invite code (shared out-of-band, screenshotted, forwarded, leaked) could make themselves appear as a contact and have a first message shown, without the recipient ever choosing to add them. Fixed by gating all mailbox-deposit processing (token import, contact creation, name, message display) on `getContactMailboxTag(from) != null` — a value only ever set when *this* user's own client redeemed *that* sender's invite code, i.e. proof the add was reciprocal. A deposit failing this check is dropped outright, matching the original "add me first or it doesn't arrive" design. (While implementing the mutual-add gate, also closed a related gap: mailbox deposits never carried the sender's display name, so a contact auto-created by an earlier, now-removed unconditional add showed up nameless until separately redeemed via invite code. The deposit payload now includes the sender's display name, applied only if the recipient hasn't already set one — harmless now that deposits are gated, but keeps things tidy for the legitimate mutual-add case.)

22. ~~Photos and files silently failed to send whenever the recipient's PQ public key wasn't already cached in memory, with no retry~~ — **fixed**: `sendImage`/`sendFile` use a one-shot hybrid encrypt (`CryptoManager.encrypt`/`encryptFile`) that needs both the recipient's classical *and* PQ public key cached locally — unlike text, which rides the already-established Double Ratchet session and needs neither. The PQ key is only ever populated by actually fetching a prekey bundle; a passively-received `session_init` only ever carried the sender's classical key (`sender_ik`), never their PQ key, so a recipient who never independently fetched the sender's bundle had no PQ key cached for them at all — and unlike the equivalent gap in `sendFile`/`sendVideoCircle` (which already requested a bundle on a miss), `sendImage` didn't even do that, just logged a warning and gave up. Confirmed live: `sendImage: нет ключа для ...` with text messages to the same contact delivering normally seconds apart. Fixed by giving both functions the same queue-and-retry pattern `sendVideoCircle` already had (`pendingVideoCircles`/`flushPendingVideoCircles`): a failed send is queued (`pendingImages`/`pendingFileSends`) and replayed once a prekey-bundle response actually populates the PQ key, on both platforms.

    ~~**Related, not yet fixed**: `sendVoice` queues a failed send into `pendingSessionMessages`...~~ — **re-verified 2026-08-10, already fixed**: every flush site for `pendingSessionMessages` (`MessengerService.kt`, several call sites including `handleFetchedPrekeyBundle`) checks for the `"__voice__|"` prefix and reconstructs the voice message via `sendVoice()` before falling through to the plain-text retry path — a failed voice send no longer surfaces as garbled placeholder text. The design is still a little fragile (the check is duplicated at each flush site rather than living in one dedicated `pendingVoiceSends` queue, so a future flush path could forget it), but the originally reported bug does not currently reproduce.

23. **Self-audit sweep for forgotten/undocumented mechanisms — two gaps found, both fixed**: prompted by discovering the padding described above had gone undocumented, the Android client (`app/src/main/java/com/example/test/`) was swept specifically for other security-relevant code that might exist but be forgotten or unwired. No orphaned/dead security classes were found (searched for canary/tripwire/sentinel/watchdog/scramble/mimic-style naming patterns); no `TODO`/`FIXME` markers anywhere in the app module.

    **EXIF/GPS stripping — gap found, fixed**: photos picked through the dedicated photo picker were already safe as an architectural side effect — that path decodes to a `Bitmap` and re-encodes to WebP (`compressImageForSend`), and `Bitmap` is pixel data only, carrying no EXIF forward regardless of whether any code explicitly strips it. The actual gap was the generic **"attach as file" picker**: selecting a photo through it read and sent the original file bytes untouched, GPS coordinates and all, since that path has no decode/re-encode step. Fixed by adding `stripExif()` (`ChatScreen.kt`, using `androidx.exifinterface`), applied only when the attached file's MIME type starts with `image/`: writes the bytes to a temp file, clears all GPS tags plus device-identifying tags (make/model/software/serial numbers) and capture timestamps, keeps `TAG_ORIENTATION` so the image doesn't display sideways, saves back and deletes the temp file. Falls back to the original bytes on any failure (e.g. a format `ExifInterface` doesn't support) rather than blocking the send. Added `androidx.exifinterface:exifinterface:1.3.7` as a new dependency. Compiles clean.

    **Desktop had the same gap, and worse — checked and fixed the same day**: Desktop's single attach dialog routes by extension rather than having a separate "photo" vs. "file" picker like Android, and unlike Android's photo path it never decoded/re-encoded the image at all — so **every** image sent from Desktop (not just ones sent as a generic file) shipped the original bytes, EXIF included, straight from disk. Fixed with `stripImageMetadata()` in `ChatScreen.kt` (Desktop): decodes via `javax.imageio.ImageIO` and re-encodes in the same format (jpg/png/bmp/gif), which drops EXIF the same way Android's Bitmap round-trip does — no per-tag clearing needed since the re-encoded pixel buffer never carried metadata to begin with. `webp` isn't writable by the JDK's built-in `ImageIO` (no bundled plugin) and is sent unmodified, same fallback behavior as any decode/encode failure. No new dependency needed (`ImageIO` is part of the JDK).

    **Filename/storage-path obfuscation — gap found, fixed**: received-attachment filenames on disk were predictable and type-revealing (`image_<uuid>.jpg.enc`, `voice_<id>.3gp.enc`, `videos/<id>.mp4.enc`, `files/<id>/<real-filename>.enc`) — so browsing the app's private storage without decrypting anything (e.g. an ADB backup extract, or a rooted device before the EncryptedFile/SMK key is compromised) revealed attachment *type* by filename/directory alone, and for the `files/` case, the **real original filename** was in the path verbatim. The Desktop client had the same issue and it was worse there: file attachments were stored as `<fileId>-<original filename>.enc`, putting the sender's actual filename (potentially itself sensitive — `client_lawsuit_draft.pdf`, say) directly on disk in the clear as a path component. Fixed on both platforms by consolidating all attachment types into a single flat directory (`blobs/` on Android under `filesDir`/`cacheDir`, `blobs/` on Desktop under the data dir) with opaque `<id>.enc` naming and no type prefix, no subdirectory-per-type, and no embedded original filename — the real filename remains available to the UI exactly as before, since it was already tracked as separate message metadata (`ChatStorage.fileName`/`StoredMessage.fileName`) independent of the on-disk path, so nothing was lost by making the path itself meaningless. Compiles clean on both platforms.

24. ~~A single-use anonymous token could be spent twice on a send failure~~ — **fixed**: the "restore the token to the local pool if `sendWs()` returns false" mechanism assumed that signal reliably meant "the frame definitely never left the device." Found live: under real network stress (specifically, a video call — WebRTC competing with the WebSocket connection itself for CPU and bandwidth), `sendWs()` can report failure locally while the packet still reaches the server and gets an `anon_delivery_ack`. The token, already "restored" for reuse by that point, ends up spent twice — the second message sent with it goes nowhere (the server already cleared that token's route after the first delivery), while the sender believes it succeeded (`sendWs=true` on the second, doomed attempt). Fixed by disabling the restore-to-pool mechanism at all three call sites. The message itself is still queued for retry — only the token's fate changes, from "might be reused and double-spent" to "simply lost on failure." Closing this gap completely isn't possible without a reliable way to know a byte's fate on the wire at the moment of a local failure, which doesn't exist.

25. ~~`server.py`'s port (9000) was directly reachable from the internet, bypassing Cloudflare and nginx entirely~~ — **fixed**: nginx is configured to accept incoming traffic only from Cloudflare's IP ranges (`allow <cloudflare>; deny all;`), but `server.py` itself listens on `0.0.0.0:9000` — and the production server's firewall (`ufw`) turned out to be **inactive** (`ufw status` → `inactive`), meaning the "Cloudflare-only" protection had never actually been enforced in practice: port 9000 was open to everyone, bypassing Cloudflare, nginx, and any IP-based restriction. Found via a Python traceback in the server log (`websockets.exceptions.InvalidUpgrade: invalid Connection header: keep-alive`) — a telltale sign of a connection arriving directly, not through nginx. Fixed by enabling `ufw` (after auditing existing rules to avoid losing SSH access), explicitly denying port 9000 externally, and confirming it's unreachable from outside (`curl` from a different host → timeout). Lesson: an `allow`/`deny` rule existing in the ruleset means nothing if the firewall itself isn't active — worth periodically checking `ufw status`, not just the rule list.

26. **No protection against mass registration of new identities (Sybil flood) — added**: `rate_limit_check()` is keyed on `username`, i.e. on identity — and identity is free to mint, a new ECDSA keypair per connection. An attacker with many devices/IPs trivially defeats any IP-based limit by minting a new identity instead of one. Added `MAX_REGISTERED_USERS` (a hard cap on the total number of identities ever registered, unlimited by default — a per-deployment setting) and `POW_DIFFICULTY_BITS` (proof-of-work on each fingerprint's very first registration — the cost is real device CPU time, not an IP address an attacker with many devices can swap for free). Both apply only to brand-new identities, never to a reconnect of an already-known one, and both are off by default (`0` = disabled).
