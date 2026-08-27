# Known Security Issues Register

*ID/severity/status view of what [SECURITY.md](SECURITY.md)'s "Known Limitations" section and
[docs/ANDROID_AUDIT.md](ANDROID_AUDIT.md) already document in full prose — this file is an index
for an auditor scanning for "what's already known," not a replacement for the detail in either.
Every item below links to where the real writeup is.*

Status legend: **Fixed** (closed, code changed), **Mitigated** (reduced, not eliminated — usually
opt-in or partial), **Open/by-design** (accepted tradeoff, explicit non-goal or product decision,
not expected to change), **Open/undecided** (a real gap someone still needs to make a call on).

## SECURITY.md Known Limitations (items 1–29)

| ID | Summary | Severity (estimate) | Status | Regression test |
|---|---|---|---|---|
| KL-1 | Server sees social graph + timestamps (metadata, not content) | Medium | Open/by-design | — |
| KL-2 | SMK resident in memory while app unlocked | Medium | Open/by-design (see [SECURITY_MODEL.md](SECURITY_MODEL.md) non-goals) | — |
| KL-3 | AndroidKeyStore software-key fallback on non-SE devices | Low–Medium | Open/by-design | — |
| KL-4 | OPK exhaustion under concurrent requests | Medium | Fixed, re-verified 2026-08-10 | — |
| KL-5 | Malicious server can refuse group-key delivery to a member | Low (availability, not confidentiality) | Open/by-design | — |
| KL-6 | Backup password has no recovery mechanism | Informational | Open/by-design | — |
| KL-7 | Decoy mode: no undetectability of the wipe event itself | Low | Open/by-design | — |
| KL-8 | Desktop: no defense vs. hardware/OS-level keylogger | Medium (Desktop only) | Mitigated (on-screen keyboard, opt-in) | — |
| KL-9 | Desktop: swap/hibernation may expose plaintext without full-disk encryption | Low | Open/by-design | — |
| KL-10 | Desktop: attachment temp files may survive a hard crash before secure-delete | Low | Mitigated | — |
| KL-11 | Prekey-bundle fetch metadata leak (contact-list size/membership to server) | Medium | Mitigated, residual gaps documented | — |
| KL-12 | Anonymous-routing coverage incomplete for some message types | Medium | Open/documented | — |
| KL-13 | Android/Desktop invite-code format was incompatible | Medium | Fixed (code-level; live cross-platform test still not run — `docs/TODO.md`) | — |
| KL-14 | Server didn't bind `register` identity to the handshake-proven key | High | Fixed | — |
| KL-15 | Group-key rotation could deliver the new key to the just-removed member | High | Fixed | **Yes** — `GroupManagerTest.kt` |
| KL-16 | Several message types bypassed rate limiting entirely | Medium | Fixed | — |
| KL-17 | Self-hosted relay servers hardcoded federation to the operator's server | Low (independence/undisclosed connection, not confidentiality) | Fixed | — |
| KL-18 | Call signaling anonymization vs. reliability (multi-iteration fix) | Medium | Fixed | — |
| KL-19 | A contact's anon-token pool could permanently fail to bootstrap | Medium | Fixed | — |
| KL-20 | Profile-screen invite regeneration could orphan an in-progress mailbox exchange | Medium | Fixed | — |
| KL-21 | Mailbox deposit could auto-add a contact without reciprocal consent | Medium–High | Fixed | — |
| KL-22 | Photo/file send silently failed without a cached PQ key, no retry | Low (reliability) | Fixed | — |
| KL-23 | EXIF/GPS not stripped on "attach as file"; predictable attachment filenames/paths | Medium (metadata/privacy leak) | Fixed | — |
| KL-24 | Anonymous token could be double-spent on a local send-failure false negative | Medium | Fixed | — |
| KL-25 | Server port 9000 directly reachable, bypassing Cloudflare (`ufw` inactive) | Critical (infra, not code) | Fixed | — |
| KL-26 | No protection against Sybil-style mass identity registration | Medium | Mitigated (opt-in cap + PoW) | **Yes** — `test_registration_cap_atomic_under_concurrent_new_fingerprints` |
| KL-27 | No protection against offline access to the server's database | Medium | Mitigated (opt-in SQLCipher) | — |
| KL-28 | Calculator-disguise hardcoded unlock code; wipe/restore could lose the code | Medium (disguise) / High (data loss) | Fixed | — |
| KL-29 | Only one invite-code mailbox tag can be "live" per device | Low | Open/by-design tradeoff | — |

Full writeups: [SECURITY.md § Known Limitations](SECURITY.md#known-limitations).

## 2026-08-23 audit session (`docs/ANDROID_AUDIT.md`)

Full line-by-line audit of `AnonTokenManager.kt`, `SessionKeyManager.kt`, `MessengerService.kt`
(ACK semantics), `BackupManager.kt`/`TotpManager.kt`, `GroupManager.kt`, `Server/server.py` —
external-review claims verified against actual code, confirmed issues fixed, inaccurate claims
explicitly declined with reasoning (see that file for both directions).

| ID | Summary | Severity | Status | Regression test |
|---|---|---|---|---|
| AA-1 | `server.py`: `db_connect()` had a self-inflicted infinite-recursion bug | High (server unusable) | Fixed | — (caught live, not by a test) |
| AA-2 | `server.py`: recovery-code redemption had a TOCTOU race (SELECT+UPDATE, not atomic) | High | Fixed | **Yes** — `test_recovery_code_consumed_exactly_once_under_concurrency` |
| AA-3 | `server.py`: new-fingerprint registration cap had the same TOCTOU race | Medium | Fixed | **Yes** — `test_registration_cap_atomic_under_concurrent_new_fingerprints` |
| AA-4 | `server.py`: access-code redemption had the same TOCTOU race | Medium | Fixed | **Yes** — `test_access_code_atomic_under_concurrent_redemption` |
| AA-5 | `server.py`: `anon_delivery_ack` didn't verify the acking connection owned the token | High | Fixed | **Yes** — `test_ack_ownership_wrong_connection_cannot_confirm_someone_elses_token` |
| AA-6 | `server.py`: spent anonymous tokens weren't rejected on replay | Medium | Fixed | **Yes** — `test_spent_token_replay_rejected` |
| AA-7 | `MessengerService.kt`: several handlers `return`ed instead of `throw`ing on signature failure, leaving ambiguous state | Medium | Fixed | — |
| AA-8 | `GroupManager.kt`: `addMember`/`removeMember`/`promoteToAdmin` raced under concurrent calls (lost update) | Medium | Fixed | **Yes** — `` `concurrent removals of two different members do not lose an update` `` |
| AA-9 | `AnonTokenManager.kt`: `addContactTokens()` could store duplicate tokens | Low | Fixed | — |
| AA-10 | `AnonTokenManager.kt`: dead/dangerous `restoreContactToken()` function | Low (dead code, not reachable) | Fixed (removed) | — |

Full writeup: [docs/ANDROID_AUDIT.md](ANDROID_AUDIT.md).

## This session (2026-08-27) — CI/SAST + GroupManager authorization

| ID | Summary | Severity | Status | Regression test |
|---|---|---|---|---|
| S3-1 | `GroupManager` mutators had no internal authorization check (relied entirely on caller) | Medium (defense-in-depth gap, no known live bypass — every call site already checked) | Fixed | **Yes** — `GroupManagerTest.kt` (9 tests) |
| S3-2 | 5 CI/build issues found only via live GitHub Actions runs (google-services.json plugin, stale codeql-action pin, CodeQL Autobuild/JDK mismatch, Semgrep false positive, first-ever lint run) | Low (tooling, not product security) | Fixed | **Yes** — `test_recovery_code_has_sufficient_entropy` |
| S3-3 | Recovery-code entropy was 40 bits — single unsalted SHA-256 hash crackable offline in under a minute on one GPU given a stolen DB (composite with KL-27) | **High** | Fixed (bumped to 80 bits) | **Yes** — `test_recovery_code_has_sufficient_entropy` |

Found by an external *documentation-level* review of the six audit-package files (not a code
review) — flagged the "metadata exposure, not credential compromise" framing in an earlier
`THREAT_MODEL.md` draft as underselling what a stolen DB actually exposes; checking the code behind
that framing surfaced the actual 40-bit weakness, which was real and unrelated to the wording
issue itself. Documentation review finding real code bugs, not just prose problems, is worth noting
for its own sake.

## Open, undecided (not yet a "fix", a product decision still needed)

| ID | Summary | Where |
|---|---|---|
| OPEN-1 | Recovery-code takeover window — TOTP disabled account-wide after any successful recovery-code redemption, no time bound | [THREAT_MODEL.md § D](THREAT_MODEL.md#d-stolen-or-compromised-device--stolen-backup), `docs/TODO.md` |
| OPEN-3 | No fuzzing/negative-input test suite for the server's protocol handlers | `docs/TODO.md`, `docs/AUDIT_PREPARATION_NEXT_STEPS.md` §15–16 |
| OPEN-4 | Desktop client — no static audit yet performed (same bug classes as Android, not yet checked) | `docs/TODO.md` |
| OPEN-5 | Sender gets no notification when a `token_pending` entry silently expires (24h TTL) without ever reaching the recipient — found while writing the token_pending lifecycle contract, not previously documented anywhere | [MESSAGE_DELIVERY.md](MESSAGE_DELIVERY.md) |
| OPEN-6 | Federation (`forward_to_peers`) interaction with anonymous-token ownership/ACK semantics not traced end-to-end — flagged for explicit auditor attention, not asserted safe or unsafe | [MESSAGE_DELIVERY.md](MESSAGE_DELIVERY.md) |
| OPEN-7 | Adding a member to a group does not rotate the group key — new member gets the current key and can decrypt any historical ciphertext they separately obtain from before they joined. Genuine backward-secrecy gap, not yet decided as accepted-tradeoff-vs-needs-fixing | [SECURITY.md § Group Key Exchange](SECURITY.md#group-key-exchange) |
| OPEN-8 | `spent_tokens`/`known_tokens` are plain in-memory sets, reset on every server restart — a token spent before a restart is no longer recognized as spent after one, reopening a narrow replay window (practically limited to the server operator, who already sees all token values by nature of routing them) | [MESSAGE_DELIVERY.md](MESSAGE_DELIVERY.md) |

## S4 (2026-08-27/28) — closing OPEN-2

Checking `message_delete`/`disappear_timer`/`group_message_delete` for the AA-7 pattern found the
first two matched exactly (return-not-throw), but `group_message_delete` was worse than the pattern
predicted:

| ID | Summary | Severity | Status | Regression test |
|---|---|---|---|---|
| S4-1 | `message_delete`/`disappear_timer`: bad-signature check `return`ed instead of `throw`ing, same class as AA-7 | Medium | Fixed | — |
| S4-2 | `group_message_delete`: **no signature was ever sent or checked, and no check that the deleter was the message's original author or even a group member** — any group member's modified client could silently delete any other member's group message on every recipient's device | **High** | Fixed — now requires a signature over `groupId:messageId` and verifies `from` matches the stored message's `senderId` | — |
| S4-3 | The same return-not-throw pattern was also present in `message`, `voice`, `group_create` (×4 sites), `group_message` (×3), `group_reaction`, `group_member_removed`, `group_member_added`, `group_key_rotation`, `group_invite_accepted`, `video_chunk`/`processVideoChunk` — far more handlers than OPEN-2 named, found while verifying CRYPTO-05 | Medium | Fixed (all sites) | — |

## S5 (2026-08-28) — SECURITY.md/ARCHITECTURE.md cryptography-documentation review

A second external review, this time of the actual crypto-design docs (`SECURITY.md`/
`ARCHITECTURE.md`) rather than just the six audit-package files, per the same "verify against code,
don't just trust the prose" standard applied all session. Findings below; documentation-only ones
list "Documentation" as fix type, code fixes list the actual change.

| ID | Summary | Severity | Fix type | Status |
|---|---|---|---|---|
| CRYPTO-01 | `SECURITY.md`/`ARCHITECTURE.md`'s "Last verified against commit" stamps predated `audit-2026-08` | High | Documentation | Fixed — see stamps at top of both files |
| CRYPTO-02 | "All sensitive at-rest values receive a second [SMK] encryption layer" contradicted the same document's own SPK/OPK/group-key fallback sections | High | Documentation (behavior was already correct/reasoned, claim was overstated) | Fixed |
| CRYPTO-03 | App-lock only zeros the SMK; SPK/OPK/PQ private keys/Double Ratchet session state stay resident in the process regardless of lock state — threat-model non-goal said "while unlocked," understating the real exposure window | High | Documentation | Fixed — non-goal now says "including after lock" |
| CRYPTO-04 | "Group Key Exchange" section described plain classical ECDH, contradicting the Post-Quantum Hybrid section's own claim that group-key distribution gets the same hybrid treatment | High | Documentation (code was already hybrid via `CryptoManager.encrypt()`) | Fixed |
| CRYPTO-05 | Group sender authenticity wasn't documented — could a member forge another member's group message? | High (as a question) | Verified in code: **not a vulnerability** — group messages are ECDSA-signed per-sender, verified on receipt | Fixed (documented) |
| CRYPTO-06 | No AES-GCM associated data (AAD) anywhere; context (group_id, sender, etc.) lives in unauthenticated plaintext JSON around the ciphertext | **High** for `group_key_rotation` specifically (decrypts via the recipient's own identity key regardless of group_id — a malicious server could relabel a real rotation for group X as group Y, silently corrupting Y's key), lower elsewhere (wrong-key decryption just fails) | **Code fix** for `group_key_rotation` (signature now covers `groupId:encryptedNewKey`); documented as lower-severity residual for other types | Fixed (group_key_rotation); others tracked, not fixed |
| CRYPTO-07 | PQ/HNDL claim implied a general continuous post-quantum post-compromise property; the actual guarantee is narrower (passive harvest-now-decrypt-later only, not compromise-now-decrypt-later) | High | Documentation | Fixed |
| CRYPTO-08 | "Rotated on membership change" was ambiguous about add vs. remove — checked code: **only removal rotates**, addition does not (backward-secrecy gap) | Medium–High | Documentation + tracked as [OPEN-7](#open-undecided-not-yet-a-fix-a-product-decision-still-needed) | Documented; not fixed (product decision) |
| CRYPTO-09 | "Compromise does not affect past or future session keys" was too absolute per the Double Ratchet spec's own compromise model | Medium | Documentation | Fixed |
| CRYPTO-10 | KDF described only as "HKDF-style HMAC-SHA256" — insufficient for an auditor | Medium–High | Documentation (full Extract/Expand spec, salt, and per-context `info` strings added) | Fixed |
| PROTO-01 | `token_pending` lost on server restart, contradicting an implied "kept until real ACK" guarantee | Medium | Documentation (already covered in [MESSAGE_DELIVERY.md](MESSAGE_DELIVERY.md), confirmed accurate) | Already documented |
| PROTO-02 | `spent_tokens`/`known_tokens` also reset on restart, reopening a token-replay window | Medium–High | Documentation | Documented as [OPEN-8](#open-undecided-not-yet-a-fix-a-product-decision-still-needed); not fixed |
| SCOPE-01 | Channels server-side handlers (`channel_create`/`channel_post`/etc.) were fully live and reachable by any custom WebSocket client, despite being "disabled" only at the Android/Desktop UI layer — `SECURITY.md`'s claim of "no live attack surface today" was wrong | **Medium–High** (live, reachable, unauthenticated-by-anon-routing attack surface for a feature believed dead) | **Code fix** — removed from `server.py`'s `ALLOWED_TYPES`, now actually rejected server-side, not just hidden in the UI | Fixed |
| AUTH-01 | 64-bit fingerprint (`SHA-256(public_key)[:8]`) — collision/preimage analysis requested | Medium | Documentation (analyzed: ~2^32 registrations before birthday-bound collision risk, far beyond realistic scale; not fixed since not practically reachable) | Documented, no fix needed at current scale |
| AUTH-02 | Recovery-code format/entropy wasn't specified in `SECURITY.md` | Medium | Documentation (code was already fixed earlier this session — see S3-3 above; this closes the doc gap) | Fixed |
| — | Certificate pinning vs. runtime self-hosted server selection | Informational | Documentation | Resolved — see below |

**Certificate pinning, resolved:** checked `NetworkConfig.kt` and `MessengerService.kt`'s
`buildOkHttpClient()`. Pinning is scoped to exactly one hardcoded hostname
(`NetworkConfig.SERVER_HOSTNAME`, the project's own official server) via a compile-time
`NetworkConfig.CERT_PIN` constant, and is applied conditionally
(`if (CERT_PIN.isNotEmpty() && SERVER_HOSTNAME.isNotEmpty())`) — OkHttp's `CertificatePinner` only
enforces the pin for connections to that specific hostname. **A self-hosted server the user adds at
runtime is a different hostname and gets no pinning at all** — it's validated through the normal
system CA trust store, same as any other HTTPS connection. This is a reasonable, deliberate scope
(there's no way to pre-pin an arbitrary self-hosted deployment's certificate without some
out-of-band provisioning step, which doesn't exist today) — not a bug, but worth stating plainly
rather than leaving "certificate pinning" as an unqualified claim that a reader might assume covers
every server a user connects to.
