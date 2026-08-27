# Security Model

*Companion to [SECURITY.md](SECURITY.md) and [ARCHITECTURE.md](ARCHITECTURE.md), which contain the
implementation detail (algorithms, key formats, wire protocol). This document exists for an
external reviewer/auditor to answer one question first, before reading code: **what is this
system actually trying to guarantee, and what is it explicitly not trying to guarantee?***

Last verified against commit: see `git log -1` at review time — this file describes intent, not
a specific commit's bug state, so it should stay accurate across normal development; re-check if
a change alters what's listed here as protected or as a non-goal.

---

## What this system protects (assets)

| Asset | How | Detail |
|---|---|---|
| 1:1 message content | E2EE — X3DH + PQ-hybrid (ML-KEM-768) initial agreement, Double Ratchet forward secrecy | [SECURITY.md § Forward Secrecy](SECURITY.md#forward-secrecy) |
| Group message content | Per-group AES-256 key, ECDH-wrapped per member, rotated on membership change | [SECURITY.md § Group Key Exchange](SECURITY.md#group-key-exchange) |
| Attachments (image/file/video/voice) | Same AEAD as messages; EXIF/GPS stripped; opaque on-disk filenames (no type/name leak from a filesystem-only view) | [SECURITY.md Known Limitations #23](SECURITY.md#known-limitations) |
| Message *size* (not just content) | Two independent padding layers — content-level and packet-level | [SECURITY.md § Traffic Analysis Resistance](SECURITY.md#traffic-analysis-resistance-padding) |
| Cryptographic keys at rest on device | Double encryption (AndroidKeyStore/DPAPI-equivalent + password-derived SMK wrap) | [SECURITY.md § Double Encryption at Rest](SECURITY.md#double-encryption-at-rest-smk) |
| Device/session hijack via stolen key material | Challenge-response identity binding + mandatory device-gated TOTP on any new `device_id` | [SECURITY.md § Device-Gated TOTP](SECURITY.md#device-gated-totp--recovery-codes) |
| Recovery from lost authenticator | One-time recovery codes, atomically single-use | [SECURITY.md § Device-Gated TOTP](SECURITY.md#device-gated-totp--recovery-codes) |
| Some routing metadata (who-messages-whom, partially) | Anonymous token routing + blind mailbox for first contact | [SECURITY.md Known Limitations #11–12](SECURITY.md#known-limitations) — **partial, with documented residual leaks, see below** |
| Data under device seizure / coercion | Panic password, HARD/NUCLEAR wipe, decoy mode, dead man's switch | [SECURITY.md § Emergency Mechanisms](SECURITY.md#emergency-mechanisms) |
| On-screen content visibility | `FLAG_SECURE` (Android) / capture-exclusion (Desktop) — no screenshots, no Recents thumbnail | [SECURITY.md § Screen Protection](SECURITY.md#screen-protection) |

## Explicit non-goals

Stating these plainly matters more than the asset list above — an auditor (or a user) who assumes
one of these is covered and finds out otherwise later is a trust failure this document exists to
prevent.

| Non-goal | Why | Reference |
|---|---|---|
| Hiding the user's IP address from the server | No default Tor/mixnet routing — the server sees the connecting IP on every WebSocket connection. Optional Tor routing exists (`TorManager.kt`) but is opt-in, not the default posture. | — |
| Full social-graph anonymity from the server | Anonymous token routing reduces *some* directly-addressed traffic, but has documented residual leaks (batch-fetch reveals contact list to the server, decoy fallback can silently downgrade to direct addressing with no user warning). This is metadata reduction, not a strong anonymity guarantee. | [SECURITY.md Known Limitations #11–12](SECURITY.md#known-limitations) |
| Protection against a fully compromised endpoint with live process-memory access — **including after the app is locked, not only while unlocked** | Corrected 2026-08-28 (external review, CRYPTO-03 — the previous wording said "while the app is unlocked," which understated the actual exposure window). Locking `StorageKeyManager` only zeros the in-memory SMK; it does not touch what `SessionKeyManager` already loaded into memory (current SPK, the OPK pool, all Double Ratchet session states) — those stay resident in the running process for as long as the process itself lives, regardless of app-lock state. A live RAM read on a rooted/compromised device can recover this material whether the app shows as locked or unlocked in the UI. Full cold-start (process killed and relaunched) does still require unlocking before this material reloads. | [SECURITY.md § Double Encryption at Rest](SECURITY.md#double-encryption-at-rest-smk), [SECURITY.md § Threat Model, Out of scope](SECURITY.md#threat-model) |
| Timing-based traffic correlation | Padding defends against length-based analysis, not against an adversary correlating connection timing across the network. | [SECURITY.md § Traffic Analysis Resistance](SECURITY.md#traffic-analysis-resistance-padding) |
| Coercion of the message recipient | The recipient's device is not this project's to defend — only the sender/local user's device and its emergency mechanisms are in scope. | — |
| Supply-chain integrity of a downloaded APK | No reproducible-build/signature-transparency mechanism yet — a user must trust the build they installed came from the real source. | — |
| Undetectability that a wipe occurred | Decoy mode provides deniability of *content* shown on screen, not forensic undetectability of the wipe event itself (filesystem timestamps, flash wear-leveling can still show evidence). | [SECURITY.md Known Limitations #7](SECURITY.md#known-limitations) |
| Defense against a malicious/coerced group-key-serving server | A compromised server can refuse to deliver a rotated group key to a member, silently excluding them; it cannot forge message content, but availability of the group channel to specific members is not cryptographically guaranteed. | [SECURITY.md Known Limitations #5](SECURITY.md#known-limitations) |
| Defense against a hardware keylogger or OS-level keyboard hook (Desktop) | These intercept keystrokes before any userspace application, including this one, ever sees them. Mitigated (on-screen keyboard, opt-in), not eliminated. | [SECURITY.md Known Limitations #8](SECURITY.md#known-limitations) |

## Reading this alongside a threat model

This file answers "what are we defending and what aren't we." [THREAT_MODEL.md](THREAT_MODEL.md)
answers "against which specific attackers, with which specific capabilities, and what's the
residual risk after mitigation" — read that next for the adversary-by-adversary breakdown.
