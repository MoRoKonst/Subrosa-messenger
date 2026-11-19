# Open work

This file is the list of what is **open**, and why. It is assembled only from what the other documents
already say — every item links to its source, and nothing here is a wish list. If an item is not in
another document, it is not here. The authoritative record, with severities and how each item was
verified, is `KNOWN_SECURITY_ISSUES.md` (rows `KL-*`, `OPEN-*`, `S*-*`).

**No external security audit has been done.** An F-Droid listing is not one.

*Not to be confused with `docs/TODO.md`, which several documents here cite: that is the maintainer's internal working file, deliberately not published (see `.gitignore`, "Внутренние документы"). This file is the public list, and it carries only items that another published document already states.*

## 1. Open, with work or a decision attached

- **OPEN-4** — Desktop client — no static audit yet performed (same bug classes as Android, not yet checked) ([KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md), row `OPEN-4`)
- **OPEN-5** — Sender gets no notification when a `token_pending` entry silently expires (24h TTL) without ever reaching the recipient. ([KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md), row `OPEN-5`)
- **OPEN-12** — S6-24's `federation_host_allowed()` DNS check and `websockets.connect()`'s own later resolution are not atomic — a host under active… ([KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md), row `OPEN-12`)
- **OPEN-13** — `hideIpDuringCalls` defaults to `false` on both platforms — an ordinary call by default does P2P ICE (both peers learn each other's real… ([KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md), row `OPEN-13`)
- **S15-1** — logging in the desktop client; **S15-3** — attachment temp files not covered by secure-delete; see the "Session S15" table in [KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md) (`OPEN-4` stays open).
- **S10-9** — a backup carries message text only (no attachments) — open, surfaced not fixed. ([KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md))
- **S12-5 / S12-6** — the `security@` mailbox and private vulnerability reporting are actions for the maintainer, not code. ([KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md))

## 2. Live checks that have not been run

- **KL-13** — Android ↔ Desktop invite exchange: both parsers pass the same shared vectors (`testdata/invite-vectors.tsv`), but a live first-contact run between the two clients has not been done. ([KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md), row `KL-13`)
- **S13-1 regression check on a device** — `RELEASE_CHECKLIST.md` §7: not performed.
- Further server stress that was explicitly left out when `OPEN-3` was closed (registration/PoW load, offline-queue and prekey stress, federation stress, event-loop lag, DB-restart recovery, memory-leak detection, failure injection): `Server/stress/README.md`, "Not implemented in this pass".

## 3. Known limits of what we ship (from `RELEASE_CHECKLIST.md`)

- The Windows installer is **not code-signed** (SmartScreen will warn).
- Builds are **not reproducible**; CI installers are unsigned.
- No external security audit (see the top of this file).

## 4. Open by design / inherent — not planned to change, and why

Each is recorded with its reasoning in [KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md); they are listed so nobody mistakes them for forgotten bugs.

- **KL-2** — SMK resident in memory while app unlocked — *Open/by-design (see [SECURITY_MODEL.md](SECURITY_MODEL.md) non-goals)*
- **KL-3** — AndroidKeyStore software-key fallback on non-SE devices — *Open/by-design*
- **KL-5** — Malicious server can refuse group-key delivery to a member — *Open/by-design*
- **KL-6** — Backup password has no recovery mechanism — *Open/by-design*
- **KL-7** — Decoy mode: no undetectability of the wipe event itself — *Open/by-design*
- **KL-9** — Desktop: swap/hibernation may expose plaintext without full-disk encryption — *Open/by-design*
- **KL-12** — Anonymous-routing coverage incomplete for some message types — *Open/documented*
- **KL-29** — Only one invite-code mailbox tag can be "live" per device — *Open/by-design tradeoff*
- **KL-30** — `server.py` must never read a client's real IP address (formal invariant) — *Open/by-design (invariant now enforced — `deploy/nginx.conf` no longer forwards…*
- **S7-10** — Decoy seed is Keystore-backed, not password-backed — *Open/by-design — an attacker with live root on an unlocked device can read the seed and,…*
- **S7-11** — In the decoy, the profile avatar, the "+" create button, the attach button, the two call buttons and the message long-press menu are inert — *Open/undecided — parity means either replicating `ProfileScreen.kt` (85KB) and…*
- **S9-3** — `TotpManager.verifyCode()` compares the generated and supplied codes with `String.equals` (not constant-time), across a ±1 step drift window — *Open/by-design — the comparison is local, and an attacker holding the device can…*
- **S9-5** — `AnonTokenManager` shuffles its real+decoy token list with `java.util.Random(rng.nextLong())` seeded from a `SecureRandom`, rather than… — *Open/by-design — the seed has 64 bits of real entropy and the shuffle only orders cover…*
- **S10-4** — `SecureMemory.wipe(String)` reaches `String.value` by reflection. On ART this is a blocked non-SDK member from API 28 and is expected to… — *Open by design, now documented in-code — the real fix is for secrets never to be `String`…*
- **S10-5** — Copies made inside the JCA cannot be reached: `SecretKeySpec` clones its input and AOSP does not implement its `destroy()`, and the… — *Open, inherent — mitigated by the fact that the primary defence is…*
- **S11-7** — A v8 export interrupted mid-write leaves a file that looks like a backup and fails when it is needed. It cannot be rolled back through the… — *Open, surfaced not fixed — the error message states plainly that the file is incomplete…*
- **S11-8** — Frame sizes are visible to anyone holding the file, leaking the number of attachments and their approximate sizes — *Open, inherent — v7 already leaks total size, and padding multi-gigabyte media to a fixed…*
- **S11-9** — v8 cannot be read by the Desktop client, so a user who ticks the box and relies on it for cross-platform recovery is stuck — *Open, mitigated — the option is off by default, the checkbox subtitle states the…*

## 5. Mitigated, with a residual gap that is documented

- **KL-1** — Server sees social graph + timestamps (metadata, not content) — *Mitigated (2026-08-29 — sender side no longer identity-bound on the server for…*
- **KL-8** — Desktop: no defense vs. hardware/OS-level keylogger — *Mitigated (on-screen keyboard, opt-in)*
- **KL-10** — Desktop: attachment temp files may survive a hard crash before secure-delete — *Mitigated*
- **KL-11** — Prekey-bundle fetch metadata leak (contact-list size/membership to server) — *Mitigated, residual gaps documented*
- **KL-26** — No protection against Sybil-style mass identity registration — *Mitigated (opt-in cap + PoW)*
- **KL-27** — No protection against offline access to the server's database — *Mitigated (opt-in SQLCipher)*
- **KL-32** — Server could identify `anon_message` sender via the authenticated connection that submitted it — *Mitigated (2026-08-29 — sender cert + de-identified `anon_channel`; recipient side,…*
