# Security Model

*Last verified against commit: `2ae787a` (2026-08-28) — re-verified end-to-end against an external documentation-level review of this exact file (see `docs/KNOWN_SECURITY_ISSUES.md` § S5 for what changed and why). This project changes quickly — if you're reading this much later than that date, treat specific claims as needing a fresh code check, not as guaranteed-current.*

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
| Endpoint compromise (full device root + live RAM dump) | Key material resident in the running process — SMK while unlocked, and separately, SPK/OPK/PQ private keys/Double Ratchet session state for the lifetime of the process regardless of app-lock state (see "SPK / OPK private keys and Double Ratchet session state" below) — unavoidable for either without killing the process entirely |
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

Each subsequent message ratchets forward. Precisely (external review 2026-08-28, CRYPTO-09 — the
previous "does not compromise past or future" phrasing was too absolute, per the Double Ratchet
spec's own compromise model): compromising the current ratchet state does not reveal *already-
deleted* past message keys (those are wiped after use — see `SecureMemory.wipe` calls throughout
`CryptoManager.kt`/`SessionKeyManager.kt`). Future confidentiality is *not* immediate or
unconditional — an attacker holding the current chain key can compute upcoming message keys until
an uncompromised Diffie-Hellman ratchet step introduces new secret entropy the attacker doesn't
have. This is standard Double Ratchet behavior, not a bug, but "future keys are also safe" as a
blanket claim overstated the model.

The server is notified when OPK supply drops below the watermark (`OPK_LOW_WATERMARK = 5`) and prompts the client to upload more bundles.

### Post-Quantum Hybrid Key Agreement

X3DH's `master_secret` above is classical ECDH (secp256r1), which is vulnerable to a future quantum computer running Shor's algorithm — and more urgently, to **harvest-now-decrypt-later**: an adversary recording today's traffic could decrypt it retroactively once quantum computers mature. This matters for privileged/legal communication with a decades-long confidentiality requirement.

To close this, the prekey bundle also carries an **ML-KEM-768** public key (FIPS 203, NIST-standardized), signed with the same ECDSA identity key as the SPK and rotated on the same 7-day cadence:

```
pq_shared_secret = ML-KEM-Decapsulate(pq_private_key, pq_ciphertext)
master_secret     = KDF(DH1 || DH2 || DH3 || [DH4] || pq_shared_secret)
```

Only the *initial* X3DH root key needs this hardening — every subsequent Double Ratchet root key is `HKDF(dhOutput, salt=previousRootKey)`, so deriving it requires the actual secret previous root key, not just breaking that step's classical DH. A quantum adversary who breaks every individual ratchet-step DH still cannot advance the chain without the root, and the root is only recoverable by breaking **both** the classical and the ML-KEM component. This is the same reasoning behind Signal's PQXDH.

**Scope of this guarantee, stated precisely (external review 2026-08-28, CRYPTO-07 — the previous
phrasing implied a stronger, general property than the design actually provides):** this protects
against harvest-now-decrypt-later for a *passive* adversary who only records ciphertext traffic and
never compromises either endpoint or the session's root key. It is **not** a general continuous
post-quantum post-compromise security property. If an adversary compromises a device or its root
key *now* (by any means — not necessarily quantum) and continues recording that session's traffic,
a future quantum computer does not need to break ML-KEM at all — it already has everything a
classical attacker with the same compromise would have. Continuous protection against a
compromise-now-decrypt-later scenario (as opposed to harvest-now) would require a full
post-quantum ratchet construction (e.g. Signal's own PQ ratchet extensions), which this project
does not implement. ML-KEM-768 itself is a sound, NIST-standardized (FIPS 203) primitive choice —
the caveat above is about the boundary of what the *protocol construction* guarantees, not about
the primitive.

The same hybrid treatment is applied everywhere else a shared secret is derived via one-shot ephemeral ECDH outside the ratchet chain: the pre-session/legacy message fallback, `edit`, group key distribution, and image/file/voice encryption. A bundle or handshake missing the PQ component is rejected outright rather than silently accepted as classical-only, to close the obvious downgrade attack (a malicious server stripping the field).

**Known limitations:**
- Sessions established *before* this upgrade have a purely classical root key that cannot be hardened retroactively — only a fresh handshake protects a conversation going forward. See the migration note in `SessionKeyManager`.
- The anonymous-mailbox first-contact bootstrap message (see [README.md](README.md#privacy-architecture)) stays classical-only — an invite code carrying a ~1.2 KB ML-KEM key would make invite links/QR codes impractically large. The Double Ratchet session established immediately after it is full PQ-hybrid.

### Group Key Exchange

*Corrected 2026-08-28 (external review, CRYPTO-04): this section previously described a
classical-only `ECDH → AES-GCM(groupKey, KDF(shared))` wrap, contradicting the Post-Quantum Hybrid
section above, which claims group key distribution gets the same hybrid treatment as everything
else. Checked against the actual code — `GroupManager.encryptGroupKeyForMember()` calls
`CryptoManager.encrypt()`, the same one-shot hybrid function `sendImage`/`sendFile` use. The
Post-Quantum Hybrid section's claim was correct; this section's pseudocode was stale.*

Each group has a 256-bit random AES key (`groupKey`). It is distributed out-of-band to each member
individually, using the same hybrid ECDH+ML-KEM one-shot encryption as file/image transfer:

1. Admin calls `generateGroupKey()` → `SecureRandom().nextBytes(32)`.
2. For each member M, `GroupManager.encryptGroupKeyForMember()` calls `CryptoManager.encrypt()`:
   ```
   ephemeralKeyPair = generate fresh EC keypair
   classicalSecret  = ECDH(ephemeralKeyPair.private, M.identityPublicKey)
   (pqCiphertext, pqSharedSecret) = ML-KEM-768-Encapsulate(M.pqPublicKey)
   combinedSecret   = classicalSecret || pqSharedSecret
   aesKey           = HKDF-Extract-then-Expand(combinedSecret, info="BeaconECDHpq")
   encKey           = AES-256-GCM(groupKey, aesKey)
   wire format       = [ephemeralPublicKey][pqCiphertext][iv || encKey || tag]
   ```
   Breaking either the classical ECDH or the ML-KEM component alone does not recover `groupKey` —
   same reasoning as the Post-Quantum Hybrid section above, applied to group-key wrapping instead
   of message content.
3. `{memberId, encKey}` pairs are sent to the server in the `group_create`/`group_member_added`
   message; the server delivers each `encKey` only to the corresponding member (it cannot decrypt
   any of them — it never has any member's private key).
4. Member calls `GroupManager.decryptGroupKey(encKey)` → `CryptoManager.decrypt()` (the matching
   hybrid decrypt, using the member's own identity + PQ private keys) → `groupKey`.

Group messages:
```
plaintext
    │
    ▼ AES/GCM/NoPadding (key = groupKey, iv = random 12B)
iv[12] || ciphertext || tag[16]
```

Group message **authenticity is separate from the AES-GCM encryption**: since every member shares
the same symmetric `groupKey`, AES-GCM alone only proves *some* group member produced the
ciphertext, not *which* one. Every `group_message`/`group_reaction`/`group_key_rotation`/etc. is
additionally signed with the sender's own ECDSA identity key (`CryptoManager.sign`), verified
against their known identity public key on receipt before the message is trusted — a member cannot
forge a message under another member's name, even knowing the shared `groupKey`. (External review
2026-08-28, CRYPTO-05, confirmed by reading the code — this was already implemented, just not
documented here.)

**Key rotation happens on member *removal* only, not on member addition** (external review
2026-08-28, CRYPTO-08 — the previous wording, "rotated on membership change," was ambiguous about
this and has been corrected). On removal, the admin generates a fresh `groupKey` and redistributes
it to the remaining members, with the removed member explicitly excluded from the redistribution
list (see [Known Limitations #15](#known-limitations) for the bug this closed, and
[THREAT_MODEL.md § C](THREAT_MODEL.md#c-removed-group-member) for the regression test covering it).
Adding a member does **not** rotate the key — a newly-added member receives the group's *current*
key and can decrypt any historical ciphertext they separately obtain (e.g. from another member's
device, or if the server ever logged group message payloads) from before they joined. This is a
genuine backward-secrecy gap, not yet decided as accepted-tradeoff-vs-needs-fixing — see
[KNOWN_SECURITY_ISSUES.md OPEN-7](KNOWN_SECURITY_ISSUES.md).

When stored locally, `groupKey` is wrapped with the SMK (`"smk1:"` prefix) if unlocked, otherwise
stored as plain Base64 (still inside `EncryptedSharedPreferences`/Keystore-backed storage — see the
[Double Encryption at Rest](#double-encryption-at-rest-smk) section for exactly what this fallback
does and doesn't lose).

### Double Encryption at Rest (SMK)

Sensitive at-rest values receive a second encryption layer on top of `EncryptedSharedPreferences`
**when the SMK is unlocked**. Corrected 2026-08-28 (external review, CRYPTO-02 — the previous
"all sensitive values" phrasing directly contradicted this same document's own Group Key Exchange
and SPK/OPK/session-state sections a few paragraphs down, both of which describe a plain-Base64
fallback for writes made while locked): the SMK layer is the normal case, not an unconditional
guarantee. See "Value Wrapping" below for exactly when the fallback applies and what it does and
doesn't lose — the fallback value is still inside `EncryptedSharedPreferences`/AndroidKeyStore-backed
storage, so this is "single-layer instead of double-layer protection" for that value until the next
unlock triggers the documented self-healing re-wrap, not plaintext-on-disk.

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

Backup files use a deliberately different, memory-hard KDF from the password hash above — Argon2id, not PBKDF2 — since a backup file is something an attacker who obtains a copy can brute-force offline indefinitely, with no rate limiting and no device involved at all:

```
salt    = SecureRandom().nextBytes(32)
key     = Argon2id(backupPassword, salt, memoryKB=65_536, iterations=3, parallelism=1, keyLen=32)
iv      = SecureRandom().nextBytes(12)
payload = AES-256-GCM(serialized_data, key, iv)   // 128-bit tag
file    = base64(salt[32] || iv[12] || payload)
```

---

## Authentication

### Server Handshake

Authentication is challenge-response via ECDSA. The server never stores or transmits the password — the password only ever protects local storage (SMK), it is never part of the network protocol at all:

1. Client connects; server sends `{type: "challenge", data: "<32 random bytes base64>"}`.
2. Client signs the challenge bytes with its EC private key (SHA256withECDSA) and replies `{type: "challenge_response", public_key, signature}`.
3. Server verifies the signature against the supplied public key and, on success, replies `{type: "handshake_ok"}`, remembering the verified key bytes for the next step.
4. Client sends a separate `{type: "register", name, public_key, device_id, ...}` — `public_key` here is checked to match exactly the key that was just proven in step 2/3 (identity-binding fix, see [SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md) item 14); a mismatch is rejected outright, closing the connection.
5. The server derives the fingerprint (`SHA-256(public_key)[:8]`), which is also the username, and applies any additional gates before accepting the registration — in order: optional one-time access-code allowlist for private/business deployments (`access_code_required` on failure), then device-gated TOTP if the account has it enabled (`totp_required` on failure — see [Device-Gated TOTP](#device-gated-totp--recovery-codes) below). Only once these pass does the server accept the connection, resolve `session_conflict` if another device is already registered under this fingerprint, and later send `{type: "turn_config", ...}` for call signaling.

**Fingerprint length, analyzed (external review 2026-08-28, AUTH-01):** 8 bytes = 64 bits. Targeted
preimage (find a keypair matching one specific victim's fingerprint) stays infeasible at 2^64.
Birthday-bound *collision* resistance is the relevant number for a shared identity-namespace,
though: ~2^32 (about 4.3 billion) registered fingerprints before an accidental collision becomes
likely. That's far beyond this product's realistic scale, so not a practical concern today. Worth
noting as a real (if currently theoretical) scaling ceiling: `register()` stores/overwrites
`clients[fingerprint]`'s public key on every registration with no check against a previously-seen
public key for that fingerprint, and `registered_fingerprints.fingerprint` is a SQLite `PRIMARY KEY`
— so a genuine collision (two different keypairs hashing to the same 8 bytes) would let the second
key silently overwrite/impersonate the first in `clients` (in-memory), while the DB insert would
just no-op (`INSERT OR IGNORE`) rather than surface the collision at all. Not fixed, since it isn't
reachable at realistic scale — flagged for the record, not treated as an active vulnerability.

Handshake timeout: 15 seconds.

Session conflict: when a second `device_id` registers for the same fingerprint, the server sends `{type: "session_conflict", ts}` to the existing session (and a push notification via FCM if the old session isn't live to receive the WebSocket message). The existing client disconnects and notifies the user. The server's `connect()` reconnect loop on both clients does not currently distinguish `session_conflict` from an ordinary network disconnect, so both devices can end up in a "reconnect war" alternately displacing each other — device-gated TOTP (below) prevents this for any device the fingerprint hasn't registered with a valid code, but does not resolve the race for two device_ids the account has already registered.

### Device-Gated TOTP + Recovery Codes

Since 2026-08-10, TOTP is a **mandatory** step immediately after registration, not opt-in — the client won't proceed to the chat list until it's set up. It serves two purposes with the same secret:

- **Backup import gate**: `BackupManager.importBackup()` requires a valid current TOTP code if the backup being restored has `totp_enabled=true` — closes the "file + password alone is enough to hijack the identity" gap for anyone who also enabled this. Also required to *export* a new backup at all (`BackupScreen.kt`/Desktop equivalent won't produce a new file without TOTP enabled first).
- **Device-gated server registration**: the server (`user_totp_secrets`, `server.py`) requires a valid TOTP code in `register()` whenever `device_id` is new for that fingerprint — exactly the condition that would otherwise open the reconnect-war/session-hijack window described above. A reconnect from an already-known `device_id` never needs a code, so this doesn't affect ordinary mobile-network reconnect churn.

The secret is generated client-side, shown once with an `otpauth://` URI for any standard authenticator app, and is never included in the backup file itself (only the boolean `totp_enabled` flag is) — deliberately, so a stolen backup + password alone can't also recover the TOTP secret.

**Recovery codes**: 8 one-time codes are generated and shown once when TOTP is enabled (`totp_setup_ok.recovery_codes`), the same model as GitHub/Google 2FA. Format and entropy, stated explicitly (external review 2026-08-28, AUTH-02 — this section previously said only "the server stores SHA-256 hashes," without specifying the code's own entropy, which is what actually determines offline brute-force resistance against a stolen copy of those hashes): each code is `secrets.token_hex(10)` — **80 bits**, formatted as four 5-hex-character groups (`XXXXX-XXXXX-XXXXX-XXXXX`) for readability. Bumped from an original 40 bits (`secrets.token_hex(5)`) after this same external review flagged that 40 bits against a single unsalted SHA-256 hash is crackable offline in well under a minute on one consumer GPU — a real, live weakness given a stolen/unencrypted server DB (`totp_recovery_codes` table) exposes exactly these hashes; see the composite-attack discussion in [THREAT_MODEL.md § F](THREAT_MODEL.md#f-attacker-with-offline-access-to-the-servers-database-stolen-disk-backup-hosting-provider-access). The server stores only the SHA-256 hash of each code (`totp_recovery_codes` table) — a single unsalted hash is an acceptable choice for an 80-bit *server-generated* random token (not a user-chosen low-entropy password), since the entropy itself, not hash cost, is what needs to resist brute force here. A recovery code can substitute for a TOTP code in `register()` if the authenticator is lost; redeeming one is atomic (`UPDATE ... WHERE used = 0`, so two simultaneous redemption attempts of the same code can't both succeed — regression-tested, `test_recovery_code_consumed_exactly_once_under_concurrency`) and immediately revokes the account's TOTP secret and all other recovery codes — the account returns to "no TOTP" and requires a deliberate fresh setup from the now-trusted device, rather than leaving stale credentials usable by whoever else might have seen them.

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

Desktop and Android share this exact binary format (byte-for-byte, including the DER↔raw signature conversion and EC-point reconstruction) — see [SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md) item 13 for the history of that port.

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

**Scope, stated explicitly (external review 2026-08-28):** the pin (`NetworkConfig.CERT_PIN`) is
tied to exactly one hardcoded hostname (`NetworkConfig.SERVER_HOSTNAME` — the project's own official
server) and is applied conditionally, only when both are non-empty at build time. **A self-hosted
server a user adds at runtime is a different hostname and receives no pinning at all** — it's
validated through the normal system CA trust store instead. Deliberate scope, not a gap: there's no
mechanism today to pre-pin an arbitrary self-hosted deployment's certificate (would need some
out-of-band provisioning step — TOFU, QR-code-carried pin, etc. — none of which exist yet).

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

The decoy account cannot decrypt any real messages (all keys were destroyed). It provides plausible deniability against a cursory inspection or a coercing party demanding to see the device's *contents* — not against a forensic examination of the *device itself*: a sophisticated examiner may still find filesystem timestamps, journal entries, or flash wear-leveling patterns indicating a prior wipe occurred (see Known Limitations item 7). Deniability of what's on screen, not undetectability of the wipe.

---

## Session Security

- One active session per device per username (fingerprint).
- `device_id` is a UUID generated once per installation and transmitted on every authentication.
- If a second, previously-unseen `device_id` registers for the same fingerprint, the server sends `session_conflict` to the older session, which then disconnects and alerts the user — see [Device-Gated TOTP](#device-gated-totp--recovery-codes) for what gates that new `device_id` from registering in the first place.
- Session tokens are not stored; full ECDSA re-authentication occurs on each WebSocket connection.

---

## Known Limitations

*Fully resolved items are not listed here — see [SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md).
Numbering below has gaps where an item moved there; numbers are preserved rather than
renumbered so existing cross-references (this repo's own docs, `docs/KNOWN_SECURITY_ISSUES.md`'s
`KL-N` IDs) stay valid.*

1. **Server metadata**: The server sees message timestamps and, for anything still routed outside anon-token coverage, who communicates with whom. As of item 30, the `anon_message` payload itself no longer hands the server the sender/recipient pair in plaintext for the message types listed in item 12 — but the server could still reconstruct it by deliberately correlating token-subscription records (which account registered a given token) against token usage, so this is "no longer handed over for free," not "cryptographically impossible for the operator to reconstruct." It does not know message content. **Length-based** traffic analysis is mitigated by the two-layer padding scheme (see [Traffic Analysis Resistance](#traffic-analysis-resistance-padding)), but **timing-based** correlation is not addressed by padding — see item 12 for what anon-token routing does and does not cover.

2. **SMK in memory**: While the app is unlocked and in the foreground, the SMK lives in memory. A full RAM dump from a rooted or exploited device could extract it.

3. **AndroidKeyStore software keys**: On devices without a hardware-backed Secure Element, AndroidKeyStore keys are stored as software keys in the TEE or in `/data`. An attacker with deep OS-level access may be able to extract them, bypassing the `enc_smk_ks` path. The `enc_smk_pwd` path (PBKDF2 300K) provides protection independent of the Keystore.

5. **Group key distribution**: Group keys are distributed through the server. A compromised server could refuse to deliver a new group key to a member after rotation, effectively excluding them silently. Out-of-band verification of group membership is recommended for high-security use cases.

6. **Backup password**: The backup password is not stored anywhere. If it is lost, the backup cannot be decrypted. There is no recovery mechanism.

7. **Decoy mode forensics**: A sophisticated forensic examiner may detect evidence of a prior wipe (filesystem timestamps, journal entries, wear-leveling patterns on flash storage). Decoy mode provides social/legal cover, not technical undetectability.

8. **Desktop keystroke interception**: Unlike Android's `FLAG_SECURE` (a real OS-enforced guarantee for that app's window), there is no userspace defense against a hardware keylogger (inline USB device) or an OS-level low-level keyboard hook (e.g. Windows `WH_KEYBOARD_LL`) — these intercept key-press events before any application, including this one, ever receives them. The desktop client mitigates this with an on-screen keyboard, available both for password fields (login, registration, backup, change-password, auto-lock unlock) and for regular chat message composition, with a layout randomized on each open, so text can be entered via mouse clicks without generating a single keystroke. This closes the most common real-world keylogger class (hardware/driver-level keyboard capture). It is complemented by screen-capture exclusion (`WDA_EXCLUDEFROMCAPTURE` on Windows, `NSWindowSharingNone` on macOS) so the on-screen keyboard and message content are not readable via screenshots or screen recording either, and by clipboard hygiene (auto-clear after 30s, exclusion from Windows Clipboard History and Cloud Clipboard sync) for copied message text. None of this defends against memory-scraping malware with kernel-level access, or against the Windows Accessibility/UI Automation API, which can read on-screen control text programmatically — bypassing pixel-level capture protection entirely; there is no cross-toolkit way to opt a window out of this without also breaking legitimate assistive-technology users. Physical typing remains available and is not blocked outside of password fields, so the on-screen keyboard is opt-in per message. On macOS specifically, a stronger mechanism exists (`EnableSecureEventInput()`, the same API Terminal and 1Password use for password prompts) but is not yet wired up.

9. **Desktop swap/hibernation exposure beyond the SMK**: The Storage Master Key is held in a locked, non-pageable native buffer (`VirtualLock`/`mlock`) and message keys are zeroed after use, but the JVM heap as a whole (including transient decrypted message text held by the UI) is not, and cannot practically be, locked against paging by an application running without elevated privileges. On a machine without full-disk encryption (BitLocker/FileVault/LUKS), plaintext could theoretically be recovered from the swap file or a hibernation image. Enabling OS-level full-disk encryption is a deployment recommendation, not something the app can enforce.

10. **Desktop attachment temp files**: Opening a received file attachment decrypts it to a temporary file so the OS can hand it to an external viewer. The temp file is overwritten with `secureDelete` (3-pass) on a timer and on JVM shutdown, rather than left for a plain OS delete — but a hard crash or `kill -9` before either fires can still leave recoverable plaintext in the OS temp directory. The external viewer application may also retain its own reference to the path (e.g. an MRU/recent-files list) outside this app's control.

11. ~~Prekey-bundle fetch reveals a fingerprint pair to the server~~ — **partially mitigated, with known residual leaks**: `get_prekey_bundle` used to tell the server directly "A wants B's bundle" — the same limitation Signal's own server has. This is now reduced two ways, both reusing existing primitives rather than new cryptography: (a) **batched anonymous fetch** (`get_prekey_bundles_batch`) — the real target is padded with decoy targets drawn from the requester's own existing contacts (mirroring the anonymous-mailbox fake-tag pattern; decoys must be *real* fingerprints here, unlike mailbox tags, or the server would trivially spot the one genuine request among fakes — self-created "ghost" accounts were considered and rejected as decoys, since an account that never carries real traffic becomes distinguishable and excludable over time), never consuming a decoy's one-time prekey; falls back to the old single-target fetch when the requester has no contacts to use as cover (a batch of size 1 provides none). (b) **Bootstrap token** — every bundle the server hands out (batched or direct) is now also stamped, at serve time, with one of the bundle owner's currently-registered anonymous tokens (from the pool already maintained by `AnonTokenManager`/`subscribe_tokens`), letting the resulting `session_init` be delivered via `anon_message` instead of directly addressed — closing the follow-on leak where batching only the fetch would still be undone by a directly-addressed `session_init` moments later.

    **Residual gaps found during self-audit, not yet closed:** (i) because decoys are drawn from the requester's *real* contact list, a single batch hands the server that requester's entire contact list in cleartext — the mechanism trades "which fingerprint is the real target" for "here is my full contact graph," which is a real cost, not a free anonymization; (ii) batch size shrinks below `MAX_BATCH_BUNDLE_TARGETS` when the requester has fewer contacts than that, leaking an approximate contact-list size; (iii) if the target's bundle-serving code path never had a registered anon token to attach (or a malicious server simply omits `bootstrap_token` every time), the client silently falls back to direct fingerprint addressing for `session_init` with no user-visible warning that anonymization degraded — a passive server can force this downgrade unconditionally and the client has no way to detect it happened. None of these break message confidentiality (the E2EE payload itself is unaffected), but they meaningfully limit the anonymity property this mechanism was built for.

    **This mitigation (unlike the ML-KEM/X3DH crypto elsewhere in this document) is original protocol-design work, not an implementation of an independently peer-reviewed anonymity standard** — the same honest caveat that already applies to the anon-token-routing/mailbox/cover-traffic system it extends. It has not been independently audited.

12. **Anonymous routing coverage is not yet complete**: 1:1 text, typing, read receipts, reactions, edits, deletes, image/file/video chunks, group messages, group-message deletion, and (per [SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md) item 18) 1:1 call signaling are anonymized via token routing. There is no fingerprint-addressed fallback for any of these — if no anon token is available for a contact, the message queues locally and retries via anon-token refill / mailbox bootstrap rather than sending in the clear (see the "cut the direct fallback" decision this was changed to). Group-call signaling (`call_group_*`) is deliberately **excluded** — see [SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md) item 18. `channel_post` is not covered — the server could see who posts and channel subscriber lists are inherently visible — but the Channels feature is currently disabled at the UI layer on both clients (see `ARCHITECTURE.md`), so this gap has no live attack surface today. If channels are ever re-enabled, anonymizing distribution needs the same mailbox-based subscriber-token exchange described when that decision was made.

26. **No protection against mass registration of new identities (Sybil flood) — added**: `rate_limit_check()` is keyed on `username`, i.e. on identity — and identity is free to mint, a new ECDSA keypair per connection. An attacker with many devices/IPs trivially defeats any IP-based limit by minting a new identity instead of one. Added `MAX_REGISTERED_USERS` (a hard cap on the total number of identities ever registered, unlimited by default — a per-deployment setting) and `POW_DIFFICULTY_BITS` (proof-of-work on each fingerprint's very first registration — the cost is real device CPU time, not an IP address an attacker with many devices can swap for free). Both apply only to brand-new identities, never to a reconnect of an already-known one, and both are off by default (`0` = disabled).

27. **No protection against offline access to the server's message database — mitigated, opt-in**: `server.py`'s SQLite database (`messages.db`) was always stored unencrypted on disk — a stolen disk, an unencrypted backup, or a hosting provider with filesystem access could read it directly, including the permanent `registered_fingerprints`/`revoked_fingerprints` tables and (unless `TOTP_SECRET_ENCRYPTION_KEY` is also set) plaintext TOTP secrets. Added optional SQLCipher-backed encryption at rest, enabled by setting `DB_ENCRYPTION_KEY_HEX` (a 32-byte hex key) in the server's environment; off by default, so existing deployments are unaffected until an operator opts in. **This defends only against offline/at-rest access** — a root-level attacker on the *live* process can still read the key from the environment, same limitation as `TOTP_SECRET_ENCRYPTION_KEY`. Relayed message payloads themselves are opaque ciphertext either way (server never has the E2EE keys), so this closes a metadata gap, not a content one. Enabling it on an existing deployment requires starting from an empty database — SQLCipher cannot open a file that was written in plain SQLite format.

29. **Only one invite-code mailbox tag can be "live" per device at a time**: each invite code embeds a one-time anonymous-mailbox tag (see [Invite Codes](#invite-codes)), and generating a fresh code (tapping Copy/Share/Show-QR in Profile) replaces the single tag the device is currently polling for. If a code has already been given to someone who hasn't redeemed it yet, and a second code is then generated for a different person, the first code still looks structurally valid (signature and TTL both check out) but its mailbox deposit is never picked up — the first person's connection attempt fails silently, with no error on either side. This is a deliberate tradeoff, not an oversight: minting additional tags increases the number of distinct tags the anonymous-mailbox/cover-traffic system has to carry, which is a cost for every user's traffic-analysis resistance, not just the person generating them — supporting multiple simultaneously-live tags per device was considered and rejected on that basis. The UI (Profile screen and the in-app security guide) now warns explicitly not to regenerate a code until its recipient has connected.

30. **Invariant: `server.py` must never read a client's real IP address.** The application layer has no legitimate use for it — routing is entirely token-based (see item 12) — so `server.py` only ever calls `websocket.remote_address`, which is always the reverse proxy's own loopback address in a normal deployment, and never parses `X-Forwarded-For`/`X-Real-IP` from request headers. This held by accident rather than by design until 2026-08-29: the Docker deployment config (`deploy/nginx.conf`) was actively setting `proxy_set_header X-Real-IP`/`X-Forwarded-For` toward the backend (the production `docs/nginx-subrosamessenger.conf.snippet` config was not), meaning the headers were sitting there, unread only because no code happened to parse them yet — one well-intentioned "let's improve rate-limiting" change away from silently exposing every client's IP to the application layer and its logs/DB. `deploy/nginx.conf` no longer forwards either header to the backend. **This is now a hard invariant, not an implementation detail**: any future change that makes `server.py` read a client IP from anything other than a federation peer's own handshake (federation peers are a different trust model — they're pre-shared-secret-authenticated servers, not anonymous end users) should be treated as a regression.

    This says nothing about IP visibility elsewhere in the stack — nginx itself, and the hosting/CDN provider, still see it, and that's a separate, expected part of operating a TLS-terminating reverse proxy. The production config additionally restricts inbound traffic to Cloudflare's IP ranges, which meant (before 2026-08-29) nginx's own `access_log` recorded Cloudflare's edge IP rather than the actual client, making the operator's own IP-based abuse mitigation (fail2ban etc.) look at the wrong address entirely. Added `set_real_ip_from`/`real_ip_header CF-Connecting-IP` (trusting only the same Cloudflare ranges already allow-listed, so it can't be spoofed by a client claiming to be Cloudflare) so nginx's own logging is accurate for the operator's use — this is orthogonal to, and does not weaken, the invariant above: the recovered real IP still stops at nginx and is never forwarded to `server.py`.

31. **`anon_message` payloads carried the sender/recipient pair in plaintext — fixed 2026-08-29.** An oversight, not a deliberate design choice: federation was implemented before anonymous token routing, and `from`/`to` were never moved out of the plaintext envelope when token routing was added later. Only the `text` field was ever encrypted (via the recipient's Double Ratchet session); `from` and `to` sat in the same JSON object as plain strings. The token protects *routing* — the server never needs to know from/to to deliver by token, `token_to_ws.get(token)` is enough — but the payload it actually holds during that lookup was fully readable by anyone with access to the server process at that moment, and the federation fallback path (`payload.get("to")`, used when a token isn't known locally) explicitly read it. Fixed by having `sendAnonOrDirect()` and `sendWithForwardSecrecy()` seal the entire packet (from/to included) with one more layer of hybrid asymmetric encryption keyed to the recipient's own identity key (`sealPacketForRecipient()`), the same mechanism `sendAnonTokensTo()` already used for `__beacon_tokens__` — the recipient decrypts with their own private key, which doesn't require knowing who sent it first (unlike the Double Ratchet session itself, which does need "from" to pick the right session before decryption). Covers every message type routed through those two functions — the list in item 12. Mailbox-deposited messages (`depositTokensViaMailbox`/`depositSessionInitViaMailbox`) were never affected by this gap; that path already encrypts the entire inner structure, from/to included, as one opaque blob. **Deliberate trade-off accepted with the operator**: federation's by-fingerprint fallback routing no longer works for anything sent this way, since the server can no longer read `to` to forward it. Backward compatible on receipt (an absent `blob` field falls back to the old unsealed shape), but a new client talking to an un-updated peer breaks in the new→old direction (the old code doesn't know to look for `blob`) — both sides need the update together.
