# Threat Model

*Read [SECURITY_MODEL.md](SECURITY_MODEL.md) first — it defines what this project is and isn't
trying to protect. This document works through specific attacker classes against that backdrop:
what each one can do, what stops them today, and what's left over after mitigation. Detail on
individual mechanisms lives in [SECURITY.md](SECURITY.md) and [ARCHITECTURE.md](ARCHITECTURE.md);
this file links out rather than re-deriving it.*

Format per threat, matching common external-audit convention: **Asset / Attacker / Capability /
Threat / Mitigation / Residual risk.**

---

## A. External network attacker (unauthenticated)

- **Asset:** server availability, connection integrity, anonymous-token pool.
- **Attacker:** anyone who can reach the WebSocket endpoint. No account, no valid keypair required
  to *attempt* a connection.
- **Capability:** open connections, send arbitrary/malformed JSON, replay previously-observed
  frames, open many connections in parallel, attempt to exceed rate limits.
- **Threat:** connection-flood DoS; replay of an already-spent anonymous token to re-trigger
  delivery or probe token validity; malformed-payload crash; unbounded memory growth from
  unauthenticated input.
- **Mitigation:**
  - TLS + certificate pinning on the client side; `ufw` restricts the raw WebSocket port to
    Cloudflare's ranges in production (found and fixed live after this exact gap was open —
    [SECURITY.md #25](SECURITY.md#known-limitations)).
  - `MAX_PACKET_SIZE_BYTES` frame-size cap; oversized frames get the sender's IP banned.
  - Per-type rate limiting (`rate_limit_check()`) — every message type is covered after
    [SECURITY.md #16](SECURITY.md#known-limitations) closed the types that had silently bypassed it.
  - Spent/replayed anonymous tokens are rejected identically to unknown/decoy ones (`spent_tokens`
    set, `Server/tests/test_security_invariants.py::test_spent_token_replay_rejected`).
  - `MAX_REGISTERED_USERS` + `POW_DIFFICULTY_BITS` bound Sybil-style mass identity minting
    ([SECURITY.md #26](SECURITY.md#known-limitations)) — **opt-in, off by default** (`0` =
    disabled for both); see [AUDIT_SETUP.md § Profile B](AUDIT_SETUP.md#2b-server--profile-b-production-equivalent-hardened-environment)
    for the default-vs-hardened distinction across every opt-in control in this document.
- **Residual risk:** no fuzzing/property-based testing of the malformed-input surface yet exists
  (`docs/TODO.md`, "Протокольное тестирование сервера"). Negative-input coverage (missing field,
  wrong type, oversized field, invalid signature, wrong enum) has not been systematically driven
  against every handler — only the invariants already covered by
  `Server/tests/test_security_invariants.py`.

---

## B. Compromised or maliciously modified ordinary client

- **Asset:** other users' message delivery integrity, session/token ownership.
- **Attacker:** a real, registered user (or someone who compiled their own client) sending
  hand-crafted protocol messages instead of what the real client would send.
- **Capability:** send any well-formed message the server accepts, using their own valid
  authenticated connection; replay their own past ACKs; attempt to claim ownership of routing
  state that isn't theirs.
- **Threat:** confirm delivery of a message that was never actually received (fake ACK), forge a
  session-establishment message under a false signature, tamper with locally-held state and
  re-upload it as if legitimate.
- **Mitigation:**
  - `anon_delivery_ack` is only honored if `token_to_ws.get(token) is <this connection>` — closed
    this session's audit, verified by
    `test_ack_ownership_wrong_connection_cannot_confirm_someone_elses_token`.
  - Every handler that processes signed protocol state (`session_init`, `edit`, `reaction`,
    `file_chunk`/`image_chunk`/`video_chunk_batch`) now `throw`s on signature failure instead of
    silently `return`ing and leaving ambiguous local state — closed same session, documented in
    `docs/ANDROID_AUDIT.md`.
  - `SessionKeyManager` verifies the SPK/PQ-key signature against the claimed identity key before
    trusting a bundle; an attacker without the victim's private key cannot produce a valid one
    ([SECURITY.md #14](SECURITY.md#known-limitations)).
  - **Fixed:** `GroupManager`'s mutators (`addMember`/`removeMember`/`promoteToAdmin`) now verify
    the caller (`actorId`) is an admin *inside the manager itself*, not only at UI call sites —
    `removeMember` keeps a self-removal exception. Regression-tested in
    `app/src/test/java/com/example/test/GroupManagerTest.kt` (Robolectric).
- **Residual risk:** the `GroupManager` authorization gap specifically is closed and tested (was
  the highest-priority open item under this threat). Broader than that one fix, though: several
  security-sensitive handlers remain unreviewed for the same signature-failure /
  state-transition class this threat covers, identified in `AA-7`
  (`docs/ANDROID_AUDIT.md`) but not yet checked exhaustively —
  `message_delete`/`disappear_timer`/`group_message_delete` specifically
  ([KNOWN_SECURITY_ISSUES.md OPEN-2](KNOWN_SECURITY_ISSUES.md#open-undecided-not-yet-a-fix-a-product-decision-still-needed)).
  Until OPEN-2 is checked, this threat should not be read as fully closed — external review
  correctly flagged an earlier draft's "none currently known" here as overstated (2026-08-27).

---

## C. Removed group member

- **Asset:** confidentiality of a group's messages after a member is removed.
- **Attacker:** a former group member who still has the pre-removal group key.
- **Capability:** decrypt any message encrypted with the group key they already hold.
- **Threat:** continued read access after removal if the group key is not rotated, or if rotation
  accidentally still delivers the new key to them.
- **Key property:** *a removed member must never receive the rotated key.*
- **Mitigation:** group-key rotation on removal reloads the member list from persistent storage
  (not stale in-memory Compose state) and explicitly filters the removed member id as a second
  layer — this was a real, found-and-fixed bug
  ([SECURITY.md #15](SECURITY.md#known-limitations): the original code sent the freshly-rotated
  key directly to the account just kicked).
- **Residual risk:** the exact invariant `rotateGroupKey`'s recipient list depends on — that a
  removed member's id is actually gone from persisted `Group.members` immediately after
  `GroupManager.removeMember()` — is now regression-tested
  (`GroupManagerTest.kt`, `` `admin can remove another member, and the removed id is actually gone
  from persisted state` ``). `GroupManager`'s authorization gap (threat B) is also closed. What's
  *not* tested: the full `rotateGroupKey()` network distribution path itself (it lives in
  `MessengerService`, an Android `Service` with WebSocket I/O, not practically unit-testable
  without a running client-server pair) — the tested invariant is the state it reads from, which
  is the part that was actually buggy historically.

---

## D. Stolen or compromised device / stolen backup

- **Asset:** identity private key, message history, ability to impersonate the real owner.
- **Attacker:** someone with physical possession of a device, or a copy of its encrypted backup
  file.
- **Capability:** attempt offline brute-force of the backup password; attempt to register a new
  `device_id` under the stolen identity key if raw key material is extracted.
- **Threat:** account takeover via a new device registration, or backup decryption, without the
  real owner's cooperation.
- **Mitigation:**
  - Backup encryption uses Argon2id (memory-hard, 64MB/3 iter) specifically because an offline
    brute-force attempt against a stolen file has no rate limiting and no device involvement
    ([SECURITY.md § Backup Encryption](SECURITY.md#backup-encryption)).
  - Device-gated TOTP: any `device_id` the fingerprint hasn't registered before requires a valid
    TOTP code, closing "stolen key alone is enough to hijack the live session"
    ([SECURITY.md § Device-Gated TOTP](SECURITY.md#device-gated-totp--recovery-codes)).
  - Backup import itself requires a valid TOTP code if the backup has `totp_enabled=true`, and the
    secret is deliberately never included in the backup file.
### Recovery state machine (external review 2026-08-27: this needed to be one explicit diagram, not reconstructed across three documents)

```
TOTP_ENABLED (normal state)
     │
     │  new device_id + valid recovery code presented to register()
     ▼
RECOVERY_CODE_CONSUMED
     │  (atomic: UPDATE ... WHERE used=0, only one concurrent
     │   redemption of the same code can ever succeed --
     │   test_recovery_code_consumed_exactly_once_under_concurrency)
     ▼
ALL_RECOVERY_CODES_FOR_ACCOUNT_INVALIDATED  +  TOTP_SECRET_DELETED
     │
     ▼
TOTP_DISABLED  ◄── account sits here with NO device-gating at all,
     │              indefinitely, until:
     │
     │  user manually re-enables from the now-trusted device
     ▼
TOTP_ENABLED (new secret, new recovery codes)
```

**What protects the account between `TOTP_DISABLED` and re-enrollment?** Nothing beyond the
identity private key itself. This is the residual risk below, not a hidden gap — the state machine
above makes explicit exactly what "the recovery-code takeover window" means and why it has no time
bound today.

- **Residual risk — the recovery-code takeover window (open product decision, not a bug, but a
  question a first audit should weigh in on, not just note):** once *any* concurrent recovery-code
  redemption attempt succeeds, TOTP protection is disabled for the account entirely, permanently,
  per the state machine above, until the legitimate owner manually re-enables it from the
  now-trusted device. A stolen backup combined with a leaked/observed recovery code (both are
  physically bundled if the owner wrote them down together) defeats the gate with no time bound —
  and see Threat F's composite-attack note for the DB-theft variant of this same class of problem.
  See `docs/TODO.md` — a proposed `RECOVERY_PENDING_REENROLLMENT` state has not been decided on.
  **This should be treated as one of the primary open questions for the first audit**, not deferred
  as a routine product-backlog item — external review's assessment, and this document agrees.

---

## E. Compromised or malicious server operator

- **Asset:** message confidentiality (should hold regardless), metadata (partially exposed by
  design), group membership integrity.
- **Attacker:** whoever controls the server process — the deployment operator, or anyone who
  compromises it.
- **Capability:** read everything the server persists or sees in transit; refuse to relay
  messages; attempt to answer prekey-bundle/key-distribution requests dishonestly.
- **Threat — confidentiality:** the server never holds any E2EE key material and cannot decrypt
  message content — this is the core guarantee and does not depend on trusting the operator.
- **Threat — integrity/availability:** a malicious server *can*:
  - see the fingerprint pair and timing of any directly-addressed message (not anon-token-routed);
  - see full group membership (it delivers per-member wrapped keys);
  - refuse to deliver a rotated group key to a specific member, silently excluding them
    ([SECURITY.md #5](SECURITY.md#known-limitations)) — an availability attack, not a
    confidentiality break;
  - omit the `bootstrap_token` field when serving a prekey bundle, silently forcing the requesting
    client to fall back to direct fingerprint addressing for `session_init` — degrading anonymity
    with **no client-visible warning that this happened**
    ([SECURITY.md #11, residual gap iii](SECURITY.md#known-limitations)).
- **Mitigation:** anonymous token routing + blind mailbox reduce (not eliminate) directly-addressed
  traffic for most 1:1/group message types; batched prekey-bundle fetches pad the real target with
  decoys drawn from the requester's real contacts.
- **Residual risk:** documented and explicit, not swept under the rug —
  [SECURITY.md #11's residual-gaps list](SECURITY.md#known-limitations) states plainly that batch
  decoys leak the requester's contact-list size and membership, and that anon-routing coverage
  isn't complete for every message type. This is original, unaudited protocol design, not an
  implementation of a peer-reviewed anonymity standard — stated as such in SECURITY.md itself.

---

## F. Attacker with offline access to the server's database (stolen disk, backup, hosting-provider access)

- **Asset:** stored message queue (already opaque ciphertext regardless), registered/revoked
  fingerprint lists, TOTP secrets, recovery-code hashes.
- **Attacker:** anyone who obtains a copy of `messages.db` outside the live process — stolen disk,
  unencrypted backup, or a hosting provider with filesystem access.
- **Capability:** read the SQLite file directly, offline, with no rate limit and no need to touch
  the live server.
- **Threat:** relayed message payloads are opaque ciphertext either way (no E2EE key ever touches
  the server) — but this is **not just a metadata exposure**. TOTP secrets (unless
  `TOTP_SECRET_ENCRYPTION_KEY` is set) are stored plaintext, and TOTP secrets are an
  *authentication credential*, not metadata: possessing one lets the attacker generate valid
  device-gating codes for that account going forward. Recovery-code hashes are also in this table
  — see the composite-attack note below.
- **Mitigation:** optional SQLCipher-backed encryption at rest
  (`DB_ENCRYPTION_KEY_HEX` — [SECURITY.md #27](SECURITY.md#known-limitations)); optional separate
  `TOTP_SECRET_ENCRYPTION_KEY` for the TOTP-secret column specifically. Recovery codes are stored
  hashed (`_hash_recovery_code`, single unsalted SHA-256) at 80 bits of entropy — bumped from 40
  bits after external review found the original length crackable offline by a single GPU in well
  under a minute given just the hash (fixed 2026-08-27; see the commit and
  `Server/tests/test_security_invariants.py::test_recovery_code_has_sufficient_entropy`).
- **Composite attack — DB theft is not independent of Threat D:** stolen/leaked identity key
  material (Threat D) plus a stolen, unencrypted server DB (this threat) together can defeat
  device-gated TOTP entirely: the attacker gets both the identity credential *and* — if
  `TOTP_SECRET_ENCRYPTION_KEY` wasn't set — a live, usable TOTP secret for the same account, from
  two independently-obtained sources. Neither threat's mitigation alone accounts for the other's
  failure mode; this composite path is why `TOTP_SECRET_ENCRYPTION_KEY` and `DB_ENCRYPTION_KEY_HEX`
  matter together, not as independent checkboxes.
- **Residual risk:** both `DB_ENCRYPTION_KEY_HEX` and `TOTP_SECRET_ENCRYPTION_KEY` are **opt-in,
  off by default** — an operator who doesn't explicitly configure them ships an unencrypted
  database with plaintext TOTP secrets (see
  [AUDIT_SETUP.md § Profile B](AUDIT_SETUP.md#2b-server--profile-b-production-equivalent-hardened-environment)
  for how to run with both enabled). Neither defends against a root-level attacker on the *live*
  process (the decryption key sits in the process environment) — this matches the explicit
  non-goal in [SECURITY_MODEL.md](SECURITY_MODEL.md) ("full endpoint compromise") applied to the
  server side rather than the client.

---

## G. Passive traffic observer / server-side traffic analyst

*Added 2026-08-27 — external review correctly noted that [SECURITY_MODEL.md](SECURITY_MODEL.md)
claims message-size protection as a defended asset, but no attacker class here previously covered
it explicitly.*

- **Asset:** message size, timing, and connection-pattern metadata (not content — content
  confidentiality is covered under Threats A–F, this is specifically about what a size/timing-only
  observer learns).
- **Attacker:** the server operator, or anyone with a vantage point on the connection (network
  position, or the server itself) who is *not* actively tampering with traffic, just observing it.
- **Capability:** measure ciphertext sizes, connection timing, message frequency per user.
- **Threat:** infer message type/content-length from raw ciphertext size; correlate two users'
  online/typing patterns to infer a conversation is happening even without seeing addressing.
- **Mitigation:** two independent padding layers —
  content-level (128–512 random bytes prepended before encryption, 1024–4096 for files/images) and
  packet-level (whole outgoing envelope padded to the next 512-byte bucket). See
  [SECURITY.md § Traffic Analysis Resistance](SECURITY.md#traffic-analysis-resistance-padding).
- **Residual risk:** explicitly **not** covered — this defends against *length*-based analysis
  only. Timing-based correlation (e.g. noticing two users are always online/active within seconds
  of each other) is an explicit non-goal, stated in
  [SECURITY_MODEL.md](SECURITY_MODEL.md#explicit-non-goals). No cover-traffic/dummy-message
  scheme exists to mask *when* real traffic occurs, only how big it looks.

## H. Physical device seizure / coercion

*Added 2026-08-27 — [SECURITY_MODEL.md](SECURITY_MODEL.md) lists "data under device
seizure/coercion" as a protected asset (panic password, wipe, decoy mode, dead man's switch) but
this attacker class wasn't previously broken out on its own.*

- **Asset:** message history, identity keys, and the fact of the app's real purpose, under a
  scenario where the attacker has physical, sustained access to an unlocked or soon-to-be-unlocked
  device and can compel the user (border search, legal demand, physical coercion).
- **Attacker:** anyone with legal authority or physical leverage to compel the device owner to
  unlock/decrypt, or to seize the device outright.
- **Capability:** demand the passcode/biometric; physically retain the device; observe what's
  shown on screen once unlocked (with or without the owner's willing cooperation).
- **Threat:** compelled disclosure of real message content and identity; forced unlock revealing
  the app is a secure messenger at all (which can itself be incriminating in some threat models).
- **Mitigation:** panic password triggers a background `HARD` wipe while appearing to log in
  normally; decoy mode populates a plausible fake account/chat history after a wipe; dead man's
  switch wipes automatically after a missed check-in interval, covering the case where the user
  cannot act (detained, incapacitated). See
  [SECURITY.md § Emergency Mechanisms](SECURITY.md#emergency-mechanisms).
- **Residual risk:** decoy mode provides deniability of *screen content*, not forensic
  undetectability of the wipe event — a sophisticated examiner may find filesystem/wear-leveling
  evidence a wipe occurred ([SECURITY.md #7](SECURITY.md#known-limitations)). Coercion of the
  *recipient's* device is out of scope entirely (not this project's device to defend). A dead
  man's switch is itself a risk if misconfigured (accidental wipe from a missed check-in) —
  that's a usability/support-burden tradeoff, not a security gap, but worth an auditor's attention
  for how the interval/warning UX is implemented.

## I. Local malicious app / shoulder-surfing / screen-capture on the user's own device

*Added 2026-08-27 — the third asset from [SECURITY_MODEL.md](SECURITY_MODEL.md) without a
dedicated attacker class: screen visibility protection (`FLAG_SECURE`).*

- **Asset:** on-screen message content, visible to anyone who can see the screen or capture it
  programmatically.
- **Attacker:** someone physically near the unlocked device (shoulder surfing), or another app on
  the same device attempting to capture this app's window (screenshot, screen recording,
  Recents-screen thumbnail).
- **Capability:** look at the screen directly; on Android, without `FLAG_SECURE`, capture a
  screenshot/recording of the window or read its Recents thumbnail.
- **Threat:** casual or automated visual exfiltration of message content without ever touching
  the app's storage or keys.
- **Mitigation:** `WindowManager.LayoutParams.FLAG_SECURE` on the main activity window — blocks
  the system screenshot shortcut, screen-recording apps, and the Recents thumbnail. See
  [SECURITY.md § Screen Protection](SECURITY.md#screen-protection).
- **Residual risk:** `FLAG_SECURE` is an OS-enforced guarantee on Android but has no equivalent on
  the Desktop client beyond capture-exclusion APIs (`WDA_EXCLUDEFROMCAPTURE`/`NSWindowSharingNone`)
  — see [SECURITY.md #8](SECURITY.md#known-limitations) for what Desktop does and does not defend
  against (notably: the Windows Accessibility/UI Automation API can still read on-screen control
  text programmatically, bypassing pixel-level capture protection). Shoulder-surfing itself has no
  technical mitigation beyond user awareness — this is a physical-environment risk, not a
  software one.

---

## Priority for external audit

Per the ordering this threat model implies (highest-leverage first, matching
`docs/AUDIT_PREPARATION_NEXT_STEPS.md`'s own conclusion): **C (group-key rotation invariant) and
B (GroupManager's internal authorization check)** were the two highest-value open items identified
when this document was first written — both are now fixed and regression-tested
(`GroupManagerTest.kt`). Threat B's broader scope (OPEN-2) is not yet closed — see that section.

G/H/I were added 2026-08-27 to close a gap where [SECURITY_MODEL.md](SECURITY_MODEL.md) claimed
assets (message-size protection, coercion resistance, screen-visibility protection) with no
corresponding attacker class analyzed here. None of the three surfaced a new *undocumented*
weakness — their mitigations and residual risks were already described in `SECURITY.md`, just not
organized by attacker before. They're lower priority for a first audit than A–F (nothing here
depends on original, unaudited protocol design the way anonymous routing does — see
[SCOPE.md](SCOPE.md) priority item 11), but should still be in scope, not skipped.
