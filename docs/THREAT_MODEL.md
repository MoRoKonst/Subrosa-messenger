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
    ([SECURITY.md #26](SECURITY.md#known-limitations)).
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
- **Residual risk:** `GroupManager`'s own mutators (`addMember`/`removeMember`/`promoteToAdmin`)
  do not verify the *caller* is an admin inside the manager itself — that check currently lives
  only in the UI call sites. A caller that reaches the manager directly (a future bug, not a known
  live exploit today) would not be stopped by the manager. Open in `docs/TODO.md`.

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
- **Residual risk:** no automated regression test currently exercises "removed member does not
  receive the rotated key" end-to-end (unlike the ACK-ownership and token-replay invariants, which
  do have tests). This is the highest-value untested invariant flagged in
  `docs/AUDIT_PREPARATION_NEXT_STEPS.md`'s priority list. Also unresolved: `GroupManager`'s
  authorization gap (see threat B above) means a bug elsewhere in the call chain could in
  principle call the mutators without an admin check.

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
- **Residual risk — the recovery-code takeover window (open product decision, not a bug):** once
  *any* concurrent recovery-code redemption attempt succeeds, TOTP protection is disabled for the
  account entirely, permanently, until the legitimate owner manually re-enables it from the
  now-trusted device. A stolen backup combined with a leaked/observed recovery code (both are
  physically bundled if the owner wrote them down together) defeats the gate with no time bound.
  See `docs/TODO.md` — a proposed `RECOVERY_PENDING_REENROLLMENT` state has not been decided on.

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
  the server), so this is a *metadata* exposure, not a content one — but registered-fingerprint
  history, revocation records, and (unless separately configured) plaintext TOTP secrets are
  readable.
- **Mitigation:** optional SQLCipher-backed encryption at rest
  (`DB_ENCRYPTION_KEY_HEX` — [SECURITY.md #27](SECURITY.md#known-limitations)); optional separate
  `TOTP_SECRET_ENCRYPTION_KEY` for the TOTP-secret column specifically.
- **Residual risk:** both are **opt-in, off by default** — an operator who doesn't explicitly
  configure them ships an unencrypted database. Neither defends against a root-level attacker on
  the *live* process (the decryption key sits in the process environment) — this matches the
  explicit non-goal in [SECURITY_MODEL.md](SECURITY_MODEL.md) ("full endpoint compromise") applied
  to the server side rather than the client.

---

## Priority for external audit

Per the ordering this threat model implies (highest-leverage first, matching
`docs/AUDIT_PREPARATION_NEXT_STEPS.md`'s own conclusion): **C (group-key rotation invariant,
currently untested) and B (GroupManager's missing internal authorization check)** are the two
highest-value open items — everything else in this file already has either a fix, a passing
regression test, or an explicit, honestly-documented residual-risk statement.
