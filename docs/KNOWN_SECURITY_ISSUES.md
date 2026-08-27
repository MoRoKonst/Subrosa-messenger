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
| S3-2 | 5 CI/build issues found only via live GitHub Actions runs (google-services.json plugin, stale codeql-action pin, CodeQL Autobuild/JDK mismatch, Semgrep false positive, first-ever lint run) | Low (tooling, not product security) | Fixed | CI itself is the regression test |

## Open, undecided (not yet a "fix", a product decision still needed)

| ID | Summary | Where |
|---|---|---|
| OPEN-1 | Recovery-code takeover window — TOTP disabled account-wide after any successful recovery-code redemption, no time bound | [THREAT_MODEL.md § D](THREAT_MODEL.md#d-stolen-or-compromised-device--stolen-backup), `docs/TODO.md` |
| OPEN-2 | `message_delete`/`disappear_timer`/`group_message_delete` — not yet checked for the same return-vs-throw signature-failure pattern as AA-7 | `docs/TODO.md` |
| OPEN-3 | No fuzzing/negative-input test suite for the server's protocol handlers | `docs/TODO.md`, `docs/AUDIT_PREPARATION_NEXT_STEPS.md` §15–16 |
| OPEN-4 | Desktop client — no static audit yet performed (same bug classes as Android, not yet checked) | `docs/TODO.md` |
