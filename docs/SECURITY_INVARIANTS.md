# Security Invariants

*Created 2026-08-30. This is not a new set of rules — every invariant below is already
implemented and described in prose somewhere in `SECURITY.md`/`ARCHITECTURE.md`. The point of
this document is to make them checkable in isolation: a future auditor (or a future change) can
walk this list and verify each line directly against the code, without first reconstructing which
paragraph of `SECURITY.md` it came from. When code and this list disagree, treat it as a
regression until proven otherwise — file location references are best-effort and may drift; if a
reference is stale, that alone is not evidence the invariant itself no longer holds — check the
code.*

Format: **Invariant** — what must always be true. **Why** — what breaks if it isn't. **Where
enforced** — the code that's responsible for holding it.

---

## Server metadata / anonymity

1. **`server.py` must never read a client's real IP address for ordinary (non-federation)
   traffic.** The application layer has no legitimate use for it — routing is entirely
   token-based.
   Why: an IP is a direct, involuntary deanonymization channel that bypasses every other
   anonymity mechanism in this document at once.
   Where: `server.py` only calls `websocket.remote_address` (always the reverse proxy's loopback
   address); `deploy/nginx.conf` does not forward `X-Real-IP`/`X-Forwarded-For` to the backend.
   See `SECURITY.md` item 30.

2. **The connection that submits an `anon_message` must never be identity-bound.** The
   `anon_channel` WebSocket skips the challenge/signature handshake entirely and the server never
   learns a `username` for it.
   Why: this is the entire point of sealed sender — if the submitting socket is identity-bound,
   an operator (compelled or malicious) can read the sender straight off `clients[username]` in
   real time, no logs needed.
   Where: `server.py`'s `hs_type == "anon_channel"` branch; hard-restricted to the single message
   type `anon_message` (anything else closes the connection). See `SECURITY.md` item 32.

3. **`anon_channel` must never share network-layer state (TLS session cache, connection-open
   timing) with the main identified socket.**
   Why: even without reading `username` directly, a shared `OkHttpClient`/TLS session ticket or a
   fixed, predictable delay between the two sockets opening lets an observer pair them anyway —
   defeating invariant 2 through a side channel instead of the front door.
   Where: `MessengerService.kt` — separate `anonWsClient`/`anonWsTorClient` instances; randomized
   0–3s delay in `connectAnonChannel()` before the socket actually opens.

4. **There must be no fallback path from the de-identified `anon_channel` to the identified main
   socket for `anon_message` traffic**, except the one documented, deliberate exception
   (`sendAnonTokensToLocked()`, which needs single-connection ordering against its own
   `subscribe_tokens` call).
   Why: a silent "anonymous → identified" fail-open defeats sealed sender exactly when the
   anonymous channel is briefly unavailable — the worst possible time for it to fail open instead
   of closed.
   Where: `sendOnAnonChannelNow()` queues into `anonChannelPendingQueue` and waits for
   `anon_channel_ok` rather than falling back to `sendWs()`.

5. **`anon_message` payloads must never carry `from`/`to` in plaintext.**
   Why: the token protects *routing* (server never needs from/to to deliver by token), but a
   plaintext payload sitting in server memory during the `token_to_ws` lookup is fully readable by
   anyone with access to the live process at that moment.
   Where: `sealPacketForRecipient()`, used by `sendAnonOrDirect()`, `sendWithForwardSecrecy()` and
   — since 2026-11-03 — `sendAnonTokensToLocked()`. See `SECURITY.md` item 31.
   **Audit note (2026-11-03): this invariant was VIOLATED and this list did not catch it.**
   `sendAnonTokensToLocked()` (token resupply, routine traffic) assembled its payload by hand with
   `from`/`to` as plain strings and never called `sealPacketForRecipient()` at all, while item 31
   asserted the opposite. Found by grepping the call sites of `sealPacketForRecipient()` — there
   were exactly two, and that path was not one of them. **How to re-check this invariant rather
   than trust it:** enumerate every producer of an `anon_message` packet and confirm each one is a
   caller of `sealPacketForRecipient()`. "The documentation says it is sealed" is not evidence.

6. **A locally-blocked contact must never trigger any side effect (key save, session
   establishment, network request) from an incoming `session_init`, checked before any other
   processing.**
   Why: even with tokens revoked, a compromised contact can still reach out cold via a fresh
   `session_init` — the block check must be the literal first line, not the last, or the
   "harmless" cryptographic/state work has already happened by the time content is dropped.
   Where: `processSessionInit()` — `ChatStorage.isBlocked(from)` is the first check after reading
   `from`, before `saveContactPublicKey`/`SessionKeyManager.receiveSession`/
   `requestPrekeyBundle`.

7. **The block list is local-only and must never be reported to the server.**
   Why: a server-side block list requires the client to explicitly tell the server "I know and am
   blocking fingerprint X" — a direct, permanent, voluntary admission of a relationship, strictly
   worse than the leak sealed sender exists to close.
   Where: `ChatStorage.blockContact()`/`isBlocked()` — `SharedPreferences` only, no network call.

8. **A stale/evicted anon token must never be silently dropped from a device's own pool while
   still outstanding (given to a contact, unspent).** Pool size may only shrink through actual
   spending.
   Why: blind position-based truncation (`.take(POOL_SIZE)`/`.takeLast(POOL_SIZE)`) can evict a
   token a contact is still holding, producing a permanent "offline, message queued" state that
   never self-heals, since the owner never re-subscribes that exact value again.
   Where: `AnonTokenManager.freshTokensToShare()`/`addContactTokens()` — trim only at
   `MAX_POOL_HARD_CAP` (a safety valve, not a routine operation), with a warning log if it ever
   fires.

## Cryptography

9. **A handshake or key bundle missing the post-quantum (ML-KEM) component must be rejected
   outright, never silently accepted as classical-only.**
   Why: silently accepting closes to a downgrade attack — a malicious server stripping the PQ
   field would otherwise be invisible and would quietly remove the harvest-now-decrypt-later
   protection for that session.
   Where: `CryptoManager`'s hybrid encrypt/decrypt paths (session establishment, `edit`, group key
   distribution, image/file/voice encryption).

10. **Group message authenticity must be proven per-sender, not just per-group.** AES-GCM under
    the shared `groupKey` alone only proves *some* member sent a message — every
    `group_message`/`group_reaction`/`group_key_rotation`/etc. carries an additional ECDSA
    signature from the sender's own identity key, verified against their known public key before
    the message is trusted.
    Why: without this, any group member can forge a message under any other member's name.
    Where: `CryptoManager.sign`/`verify` calls around each group message handler in
    `MessengerService.kt` — verified 2026-11-03 to be present in **all 12** group handlers, with
    no gap.
    **Extended 2026-11-03 — a signature must also bind its ENVELOPE, not just its payload.** A
    signature over the payload alone proves who produced that payload but not which message or
    group it belongs to, so a captured signature can be relocated. Audited: the hardened handlers
    already bind it (`"SUBROSA_GROUP_MESSAGE_DELETE_V1:$groupId:$messageId"`,
    `"SUBROSA_VOICE_V1:$voiceId:$duration:$encryptedData"`, `"$groupId:$encryptedNewKey"`,
    `"$groupId:add:$newMember"`, `"$groupId:$removedMember"`, `"$groupId:$newMember"`), but three
    did not. Worst was `group_reaction`, which signed the **bare plaintext emoji** — making one
    captured signature a universally reusable token attachable to any `message_id` in any
    `group_id`, by anyone who had observed that sender react once, **including the relaying
    server**; the signed alphabet is small enough to tabulate. Now bound:
    `"SUBROSA_GROUP_REACTION_V1:$groupId:$messageId:$emoji"` and
    `"SUBROSA_REACTION_V1:$messageId:$encryptedEmoji"`. **Still unbound, deliberately deferred:**
    `group_message` signs only `encryptedText`. It cannot be moved between groups (the ciphertext
    would not decrypt under another group's key) but can be re-attributed to a different
    `message_id` within its own group. Left for a coordinated release because it is core traffic —
    a transcript mismatch there breaks all group chat between versions, whereas a broken reaction
    is cosmetic.

11. **A message-signature verification failure in an incoming protocol message must `throw`, not
    silently `return`.**
    Why: a plain `return` can let a caller's ACK/side-effect logic proceed as if the message had
    been legitimately processed and rejected, rather than rejected outright — same bug class
    across multiple handlers historically.
    Where: `session_init`, `reaction`, `file_chunk`, `message_delete`, `disappear_timer`,
    `group_message_delete` in `MessengerService.kt` all raise `SecurityException` on bad/missing
    signature.

12. **`GroupManager`'s membership mutators (`addMember`/`removeMember`/`promoteToAdmin`) must
    verify the acting user is an admin of that specific group themselves**, not rely solely on
    the caller (UI, remote-message handler) having already checked.
    Why: defense in depth — a future caller that forgets its own gate should not silently become
    a privilege-escalation path.
    Where: BOTH platforms' `GroupManager.kt` — each mutator takes `actorId` and calls `isAdmin()`
    internally before mutating; `removeMember` carries an explicit self-removal exception.
    `isAdmin()` itself also requires current membership (a creator removed from the group must
    stop being treated as admin). Desktop's `GroupManager` had none of this until S6-60 (2026-09-08)
    — no `actorId` parameter existed at all, so a remote-message handler was the only thing
    standing between an unauthorized caller and a mutation, exactly the case this invariant exists
    to not depend on.

13. **Group key rotation must happen on member removal**, with the removed member excluded from
    the redistribution list, **and only an admin's signed rotation request may be honored, for the
    specific group_id the rotation claims to be for.**
    Why: without exclusion, a removed member retains read access to future messages; without
    signature+admin verification, any group member could force an unauthorized rotation; without
    `group_id` bound into the signed transcript, a validly-signed rotation for one group can be
    relabeled and replayed against a different group the same admin also administers.
    Where: `MessengerService.kt`'s (Android) and `WebSocketClient.kt`'s (Desktop)
    `group_key_rotation` handlers — signature check over `"$groupId:$encryptedNewKey"`, then
    `GroupManager.isAdmin(from)` check, both before `GroupManager.saveGroup()`. Desktop signed only
    bare `encrypted_new_key` (no `group_id` binding) until S6-60 (2026-09-08) — the same class of
    gap Android's own CRYPTO-06 fix closed earlier, never ported to Desktop.

14. **A Double Ratchet DH-ratchet step must never be re-applied using a public key from an
    already-superseded epoch.**
    Why: `server.py`'s `token_pending` fallback (§2 of `PROTOCOL_STATE_MACHINE.md`) deliberately
    redelivers anything not yet acked — including, for a non-skipped (in-order-processed)
    message, an old epoch's key after the session has already moved on. Re-stepping with it rolls
    the live session's root/chain keys and ratchet keypair backward, corrupting a healthy session
    instead of safely no-opping on a duplicate.
    Where: `SessionKeyManager.nextRecvKey()` checks `dhKeyB64` against
    `SessionState.previousRecvRatchetPubs` (last 5 epochs) before calling
    `performDHRatchetStep()`; a match throws `DuplicateOrStaleMessage` untouched. See
    `PROTOCOL_STATE_MACHINE.md` §7.

15. **A backup export must include the current SPK+PQ prekey material, not just the identity
    key — and must fail loudly (throw), never silently omit it.**
    Why: without it, every restore is an unplanned, ungraced key rotation (the old prekey was
    physically deleted by the wipe that precedes a restore) — contacts with an already-cached
    bundle for this identity fail to decrypt until they separately re-fetch one, and a backup
    silently missing this material gives no warning that restore will degrade delivery.
    Where: `BackupManager.exportBackup()` calls `SessionKeyManager.exportCurrentPrekeyForBackup()`
    and throws `IllegalStateException` if null; `importBackup()` restores it via
    `restorePrekeyFromBackup()` before `SessionKeyManager.initialize()` runs. Backup format
    version 7+.

16. **One-time prekeys (OPKs) must never be restored from a backup as key material — only the
    issuance counter may carry forward, and only forward (never backward).**
    Why: OPKs are single-use by protocol design; restoring a frozen keypair from a backup file
    risks reissuing an id that was already consumed for real between export and a later restore
    of the same file — silently deriving X3DH from a key material that both a legitimate
    contact's prior session AND this restored session now believe is theirs alone.
    Where: `SessionKeyManager.exportOpkCounterForBackup()`/`restoreOpkCounterFromBackup()` —
    counter-only, combined via `maxOf()` with whatever counter the device already has.

## Authentication

*Renumbered 2026-09-03: this section previously restarted at 14, colliding with the Cryptography
section's own items 14–16 above (a pre-existing documentation bug, not intentional — unlike the
deliberate numbering gaps in `SECURITY_CHANGELOG.md`). Checked first that nothing elsewhere
references these by number (only #8/#9/#13 are cross-referenced, all outside this section) before
renumbering — safe to do here.*

17. **A new (previously-unseen) `device_id` registering under an existing fingerprint must
    require a valid TOTP code (or one-time recovery code), verified together with a device-local
    signature — and neither the fingerprint nor the device's authorization may be durably recorded
    until AFTER that verification succeeds.** A reconnect from an already-known, already
    signature-verified `device_id` never requires a TOTP code.
    Why: this is what closes the "stolen private key → hijack live session" window — without it,
    anyone who obtains the identity private key (backup theft, raw extraction) can register a new
    device and take over the account outright. Two historical failure modes, both closed by this
    wording specifically: (a) an early version derived "is this a new device" from the live
    in-memory `clients` dict, so the check silently disappeared the moment the real owner's
    session wasn't live (app closed, server restarted) — durable `authorized_devices` closes this;
    (b) an even earlier version durably recorded the fingerprint/device *before* PoW/access-code/
    TOTP had actually passed, so a failed gate still left a permanent, exploitable side effect —
    see `PROTOCOL_STATE_MACHINE.md` §8 for the full ordering fix.
    Where: `server.py`'s `register()` — PoW checked before any DB write; `db_admit_new_fingerprint()`
    (cap+access-code+insert, one transaction) only runs after PoW passes; `authorized_devices`
    checked/written via `db_get_authorized_device()`/`db_bind_device_pubkey()`, only after TOTP/
    recovery succeeds for a device with no pinned key yet.

18. **A device's `device_id` string alone must never be sufficient to skip the TOTP gate — it
    must be backed by a device-local cryptographic keypair, proven live on every single
    `register()`, and once a `device_pubkey` is pinned to a `(username, device_id)` pair, it must
    never be replaced by any code path.**
    Why: `device_id` is a client-supplied string, sent in the clear on every registration —
    nothing about it is secret. Durable authorization alone (invariant 17) closes the
    live-session-only gap but not this one: an attacker with the stolen identity key who also
    learns a legitimate `device_id` (easy — it's an identifier, not a secret) could present that
    same string and be treated as the already-authorized device. Requiring a signature over a
    fresh per-connection challenge means the string alone is worthless without the matching
    private key, which never leaves the original device and is deliberately excluded from the
    identity backup — so a stolen *backup* (identity key + password) still cannot forge a device
    signature for a device it was never on. The never-replace rule specifically prevents an
    attacker who successfully compromises TOTP/recovery from then re-pinning a victim's own
    `device_id` to a key the attacker controls.
    Where: `server.py`'s `register()` — signature verified over `SUBROSA_DEVICE_V1 || challenge ||
    username || device_id` using ECDSA/P-256/SHA-256 (same curve/algorithm as the identity key),
    checked on every registration attempt where TOTP is configured, not just first enrollment;
    `db_bind_device_pubkey()`'s `WHERE device_pubkey IS NULL` guard plus `register()`'s own
    pubkey-match-or-refuse check (belt-and-suspenders, both independently enforce this). Android:
    `DeviceKeyManager.kt`, keypair stored in its own `EncryptedSharedPreferences` file, never
    touched by `BackupManager.exportBackup()`. Desktop: its own `DeviceKeyManager.kt`, same
    keypair-generation/signing shape, wired into `WebSocketClient.register()` — **corrected
    2026-09-25**, this line previously said Desktop didn't implement the device-keypair side yet;
    that was true when written but went stale once Desktop's port shipped without this note being
    updated — see `PROTOCOL_STATE_MACHINE.md` §8's "Deployment status" note.

19. **`register()`'s `public_key` must match exactly the key already proven in the preceding
    challenge/response step.**
    Why: without this binding, a client could complete the challenge with one key and then
    register a different one, defeating the entire point of challenge-response authentication.
    Where: `server.py`'s `register()` handler, checked against the key remembered from
    `challenge_response`.

20. **Recovery-code redemption must be atomic** — two concurrent redemption attempts of the same
    code must not both succeed.
    Why: without atomicity, a race could let a code be used twice, e.g. by two attackers who both
    obtained a copy of it.
    Where: `server.py` — `UPDATE ... WHERE used = 0`; regression-tested
    (`test_recovery_code_consumed_exactly_once_under_concurrency`).

## At-rest storage

21. **The password must never be transmitted to the server, in any form**, at any protocol step.
    Why: the password's only job is protecting local storage (the SMK) — sending it anywhere
    turns a local-compromise-only secret into a network-interceptable or server-compromise-
    recoverable one.
    Where: server handshake is challenge-response ECDSA only (`SECURITY.md` § Server Handshake) —
    no field in any message type carries the password.

22. **`StorageKeyManager.lock()` (zeroing the in-memory SMK) must be the first operation of any
    wipe**, before any other destructive step.
    Why: if a wipe is interrupted partway (killed process, power loss) after other steps but
    before this one, the SMK could still be recoverable from memory even though files were
    already deleted — worse than either outcome alone.
    Where: `WipeManager.wipe()`.

23. **The TOTP secret must never be included in a backup file.** Only the boolean
    `totp_enabled` flag is.
    Why: a stolen backup + password should not also be sufficient to defeat the TOTP gate that
    backup restoration itself depends on — that would make the gate circular.
    Where: `BackupManager` backup serialization — secret is generated and held client-side/
    server-side only, never serialized into the exported file.

## Anonymous token durability (added 2026-09-03)

*See `PROTOCOL_STATE_MACHINE.md` §1/§2 for the full state machine these invariants describe; the
entries below state the same facts in checkable, standalone form, per this document's own
convention.*

24. **A token's ownership and lifecycle state (ACTIVE/IN_FLIGHT/SPENT/REVOKED) must be durable —
    a server restart must never reset either.**
    Why: an in-memory-only model (`token_owner`/`spent_tokens`/`known_tokens` as plain dicts/sets)
    reset on every restart, reopening two separate windows at once: a token's ownership could be
    silently re-claimed by a different account before the real owner reconnected, and a token
    already spent before the restart looked unspent again afterward, reopening replay.
    Where: SQLite `anon_token_state` table, `owner`/`state` columns; RAM dicts/sets remain but are
    documented and enforced as caches in front of it, never the record of truth themselves.

25. **A token may be claimed by at most one owner, decided atomically — first claim wins, and it
    is permanent.**
    Why: without an atomic check-and-claim, two connections racing to `subscribe_tokens` to the
    same never-before-seen token could both believe they own it.
    Where: `db_claim_anon_tokens()` — `BEGIN IMMEDIATE` transaction, `INSERT` for a new token, plain
    read (not overwrite) for an already-claimed one.

26. **A token may be committed to a pending delivery (`token_pending`) by at most one
    `anon_message` before it is acknowledged — "first write wins," not "whichever send happened to
    run last."**
    Why: without this, the sender (who knows the token) could send twice before the first delivery
    was ever acked, silently discarding the first message's fallback copy in favor of the second's
    — a real "one token, one message" violation, not just "one token, one ACK."
    Where: `db_mark_anon_token_inflight()` — atomic `UPDATE ... WHERE state = 'ACTIVE'`; only a
    caller that actually wins this transition may write `token_pending`.

27. **A token's lifecycle state in `anon_token_state_cache` must never move backwards along
    ACTIVE → IN_FLIGHT → {SPENT, REVOKED} — not just "never revert out of terminal," the full
    ordering.**
    Why: (a) in SQLite, an earlier version of the terminalize function returned success even when
    the token was already terminal and no write actually happened, letting a caller stamp a stale
    state into the RAM cache that disagreed with the DB; (b) in RAM, a concurrent `anon_message`
    racing a terminalizing call (ack/revoke/TTL-sweep) could read a stale non-terminal cache entry
    and re-commit `token_pending`/`IN_FLIGHT` after the terminal write had already happened
    elsewhere, resurrecting a token the rest of the server already considered dead; (c) found
    2026-09-04, one rank down from (b): `subscribe_tokens`'s own claim-resolution loop only ever
    checked "is the cached state terminal" before overwriting — a stale ACTIVE claim (this token's
    state before a concurrent `anon_message` won ACTIVE→IN_FLIGHT while this coroutine was
    suspended on `db_claim_anon_tokens()`) could still stamp a freshly-written IN_FLIGHT cache
    entry back to ACTIVE, which never legitimately happens (invariant 28: IN_FLIGHT is
    force-closed to SPENT, never silently returned to ACTIVE). Every atomic DB transition this
    cache fronts (`db_mark_anon_token_inflight()`, `db_terminalize_anon_token()`) still
    independently re-validates against the real SQLite state before acting, so (c) was a
    cache-consistency gap, not a demonstrated double-spend — but the cache no longer accurately
    reflecting reality was exactly the kind of drift this invariant exists to rule out.
    Where: `db_terminalize_anon_token()` — single conditional `UPDATE` with the terminal-state
    guard in the `WHERE` clause, `rowcount` is the only success signal; every writer of
    `anon_token_state_cache` (`anon_message`, `anon_delivery_ack`, `unsubscribe_tokens`, the TTL
    watchdog, and `subscribe_tokens`'s own claim-resolution loop) checks the current cached state
    under the same `lock` it writes under. `subscribe_tokens` specifically compares by
    `ANON_TOKEN_STATE_RANK` (`ACTIVE=0 < IN_FLIGHT=1 < {SPENT,REVOKED}=2`) rather than only
    checking for a terminal cached state, so a stale claim can never move the cached rank
    backwards, at any step of the lifecycle, not just out of a terminal one.

28. **A token still IN_FLIGHT when the server restarts, or when its 24h `token_pending` TTL
    expires, must be force-closed to SPENT — never left IN_FLIGHT, never silently reverted to
    ACTIVE.**
    Why: `token_pending` (the queued payload) is RAM-only and always empty after a restart, so an
    IN_FLIGHT token at that point can never be delivered/acked again regardless of what its SQLite
    state says. Leaving it ACTIVE-again would let the same token be spent a second time for
    nothing gained; leaving it IN_FLIGHT forever zombies it (the server refuses further sends on
    it, but the owning client has no signal to stop treating it as spendable). Security priority
    (a capability never outlives the one message it was claimed for) is chosen deliberately over
    reliability (that one message is lost either way).
    Where: `_db_setup_sync()`'s fail-closed startup sweep (`UPDATE ... SET state='SPENT' WHERE
    state='IN_FLIGHT'`, run before `anon_token_state_cache` loads); `token_pending_watchdog()`'s
    hourly TTL sweep, which now calls `db_terminalize_anon_token()` instead of only clearing RAM.

29. **A bootstrap-token reservation (`pick_bootstrap_token`) must be durable, per-(target,
    requester), and must never be re-issuable while the underlying token is still live.**
    Why: RAM-only reservation forgot itself on disconnect (routine) or restart, letting the same
    token be handed to a second requester while the first might still use it. A durable but
    *global* "is this reserved by someone" flag was still exploitable: one authenticated account
    could repeatedly fetch a target's prekey bundle and mint a brand-new reservation each call,
    exhausting that target's entire token pool in minutes without ever sending a real message — a
    pure availability attack against the target's ability to receive a bootstrap from anyone else.
    Where: `anon_token_state.bootstrap_reserved`/`bootstrap_reserved_by` columns;
    `db_resolve_bootstrap_token()` returns the requester's own existing reservation unchanged
    (idempotent repeat fetches) rather than minting a new one, and refuses a second concurrently
    outstanding reservation for the same pair while the first is IN_FLIGHT;
    `db_terminalize_anon_token()` clears both columns in the same statement as the state
    transition, so a terminal token can never still look reserved.

## TOTP setup/disable durability (added 2026-09-04)

30. **`totp_setup_ok`/`totp_disable_ok` must never be sent until every durable write behind that
    reply has actually committed — enrollment/disablement of TOTP is never "probably fine,
    finishing in the background."**
    Why: `totp_setup` used to update RAM and reply immediately, then fire two independent,
    unawaited `create_task()`s to persist the secret and the recovery codes — two separate writes,
    neither awaited, both racing a reply the client had already acted on. `totp_disable` had the
    mirror bug on the delete path. A crash in that window left either an account the client
    believes is TOTP-protected with no `user_totp` row at all (silent downgrade to disabled), a
    secret with no matching recovery codes (unrecoverable if the authenticator is later lost), or
    the two tables disagreeing about whether TOTP is on at all.
    Where: `server.py` — `_db_commit_totp_setup_sync()`/`_db_commit_totp_disable_sync()`, one
    `BEGIN IMMEDIATE` transaction each covering both `user_totp` and `totp_recovery_codes`;
    `totp_setup`/`totp_disable` `await` the commit and only then touch `user_totp_secrets` (RAM)
    or send the `_ok` reply.

## Federation isolation (added 2026-09-04)

31. **A federation peer (`is_fed=True`) must never reach the identified-client message loop —
    `register`, or any other type in `ALLOWED_TYPES`.** Immediately after the `federation_auth`
    handshake succeeds, the connection must be handed to `handle_federation_peer_incoming()` and
    nothing else, for its entire lifetime.
    Why: `register()` deliberately skips the identity proof-of-possession check for `is_fed`
    connections (`if not is_fed and (... key_bytes != verified_public_key)`), since federation
    forwarding was never meant to prove a *user's* private key. An `is_fed` connection that could
    reach `register` at all could therefore submit any victim's `public_key` with no private key
    and take over that victim's fingerprint — anyone holding `FEDERATION_SECRET` (a server-to-server
    credential, not a user secret) would have a full identity-takeover primitive.
    Where: `server.py`'s per-connection handler — `is_fed` branches to
    `handle_federation_peer_incoming()` and `return`s immediately after the handshake dispatch,
    before the `async for raw_message in websocket:` client loop. (Previously this dispatch sat
    *after* that loop, which only exits on disconnect — so it never actually ran while the
    connection was open; the peer was processed by the full client protocol instead. Fixed
    2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-16.)

32. **A stored TOTP secret that cannot be decrypted at startup must abort server startup
    entirely — never be silently treated as "this account has no TOTP secret."**
    Why: `register()`'s TOTP gate is driven purely by `username in user_totp_secrets`. A secret
    that fails to decrypt (missing/wrong `TOTP_SECRET_ENCRYPTION_KEY` at this boot, or a corrupted
    row) used to be dropped from that dict — indistinguishable from an account that never enabled
    TOTP at all. A stolen identity private key was then sufficient again to register a new device
    for that account, exactly the attack device-gated TOTP exists to stop; `totp_setup` would also
    have let a caller re-provision a fresh secret with no proof of the old one. The previous code's
    own comment claimed this failed closed — it did not; this is the same "fail-open despite
    fail-closed comment" bug class as the earlier federation dispatch issue (invariant 31), found
    the same review pass.
    Where: `server.py` — `_totp_decrypt_from_storage()` raises `RuntimeError` instead of returning
    `""` for both "encrypted row present, no/invalid `TOTP_SECRET_ENCRYPTION_KEY`" and "decryption
    failed"; `_db_load_totp_sync()` (called synchronously from `start_server()`, before anything
    binds/serves) re-raises rather than skipping the row — the whole process refuses to start.

33. **A second-factor proof attempt (TOTP code or recovery code, at any of the three sites that
    check one) must be durably rate-limited, and the attempt must be spent BEFORE the code is
    checked — a correct code must never retroactively "un-spend" it.**
    Why: a 6-digit TOTP code is a 10⁶-space online-guessable secret unless something durably caps
    attempts. `totp_verify_and_consume()`'s own anti-replay only rejects an already-used counter —
    a wrong guess costs nothing and consumes nothing, so an unknown device could try indefinitely.
    `rate_limit_check()` doesn't cover `register`/`totp_setup`/`totp_disable` at all, and is
    RAM-only where it applies elsewhere (reset by restart, not shared across workers).
    Where: `server.py` — durable `second_factor_guard` table, `db_take_second_factor_attempt()`:
    atomic `BEGIN IMMEDIATE`, 5 attempts per rolling 5-minute window then a 15-minute lock, keyed
    on the fingerprint (`username`). Called before the code/recovery-code check in `register()`'s
    unknown-device path, `totp_setup` re-enrollment, and `totp_disable` — all three sites that
    accept a TOTP or recovery-code proof. Recovery codes are routed through the same gate despite
    their own entropy (80 bits) not being realistically brute-forceable, so the endpoint doesn't
    become a lower-friction alternate auth path or a free DB-DoS surface.

34. **The server-wide `async with lock:` must never `await` a blocking DB call or network I/O
    while held — only RAM reads/writes, and `asyncio.create_task(...)` (which schedules, not
    awaits).**
    Why: `asyncio.Lock()` doesn't block the event loop itself, but every OTHER coroutine anywhere
    in the server that needs this SAME lock — nearly everything, it's the one server-wide lock —
    has to wait for whatever's currently holding it. `register()` used to `await`
    `totp_verify_and_consume()`/`db_check_and_consume_recovery_code()`/`db_bind_device_pubkey()`/
    `db_authorize_device()` (all SQLite calls via an executor thread) from inside the lock — a
    purely per-connection proof check (one account's TOTP code) became a server-wide availability
    bottleneck under SQLite contention, serializing every other connection's `lock`-needing
    operation behind it for as long as that one DB call took.
    Where: `server.py`'s `register()` — split into Phase 1 (every security/DB proof: TOTP/recovery
    check, `db_bind_device_pubkey()`/`db_authorize_device()`, all `await`ed with NO lock held) and
    Phase 2 (`async with lock:`, RAM-only: `clients`/`authenticated_users` commit, session-conflict
    eviction via `asyncio.create_task()`). Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-19.

## Federation TLS peer authentication (added 2026-09-04)

35. **Every outgoing federation connection must be real, peer-verified TLS (`wss://`, certificate
    chain verified, hostname checked) — TLS encryption alone, without peer authentication, is
    never acceptable for federation, no matter what the application-layer handshake does on top
    of it.**
    Why: the `FEDERATION_SECRET` HMAC handshake authenticates each endpoint's knowledge of the
    shared secret, not the TLS *channel* they're talking through. With `ssl.CERT_NONE`/
    `check_hostname = False` (the previous, unconditional setting for every outgoing federation
    connection), a MITM that can intercept the TCP connection — compromised network, coerced
    upstream, DNS/BGP hijack of the peer hostname — terminates its own TLS session with each real
    endpoint and simply relays the challenge and the HMAC response verbatim between them. The MITM
    never needs to know `FEDERATION_SECRET` at all; both real endpoints see a valid
    `federation_auth` exchange with *each other*. Federation frames past that point carry no
    per-message MAC or channel binding, so the MITM reads and modifies every frame on the link
    indefinitely — `CERT_NONE` converts a relay-proof HMAC handshake into a fully relayable one.
    Where: `server.py` — `build_federation_ssl_context()` sets `verify_mode = ssl.CERT_REQUIRED`
    and `check_hostname = True` unconditionally (optionally verifying against a private
    `FEDERATION_CA_FILE` CA for self-signed peer deployments, never `CERT_NONE`); `main()` requires
    every static `FEDERATION_PEERS` entry to be `wss://`, raising `RuntimeError` at startup
    otherwise; `peer_announce`/`peer_roster` handlers reject any non-`wss://` dynamically-discovered
    peer URL before it's added to `dynamic_peer_urls` or reaches `federation_connect_to_peer()`.
    Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-21/S6-22.

36. **The number of gossip-discovered federation peers, and the number a single `peer_roster`
    message can introduce, must both be bounded — and every dynamic peer's persistent reconnect
    loop must be individually cancellable, not just removable from bookkeeping.**
    Why: `peer_roster` previously admitted an unlimited number of URLs from a single message, each
    becoming a permanent `dynamic_peer_urls` entry AND its own infinite-reconnect
    `asyncio.Task` (`federation_connect_to_peer()`'s own `while True`) — a malicious/compromised
    peer sending one `peer_roster` with thousands of URLs could mint thousands of these, each
    costing memory, sockets, DNS/TLS CPU, and outbound traffic indefinitely. Separately,
    `federation_watchdog()`'s eviction (after `DYNAMIC_PEER_MAX_STRIKES` failures) only ever
    removed a URL from `dynamic_peer_urls`/`dynamic_peer_strikes`/`federation_ws` — the Task actually
    running that peer's reconnect loop was never tracked anywhere, so eviction never stopped it; an
    evicted peer kept reconnecting forever in the background, invisibly.
    Where: `server.py` — `MAX_DYNAMIC_PEERS` caps the total dynamic roster; `MAX_ROSTER_PEERS`
    caps how many URLs one `peer_roster` message can introduce (list truncated before iterating);
    `MAX_PEER_URL_LEN` bounds a single URL's length before it's parsed. `start_dynamic_peer()` is
    the sole entry point for admitting a gossip-discovered peer — enforces the cap, de-duplicates,
    and records the created Task in `dynamic_peer_tasks`. `federation_watchdog()`'s eviction now
    cancels that Task and closes the peer's websocket, not just removing bookkeeping.
    `federation_connect_to_peer(dynamic=True)` additionally self-terminates once its own URL is no
    longer in `dynamic_peer_urls`, so a lost/failed cancellation still can't resurrect an evicted
    peer on its own next reconnect attempt. Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-23.
    **Not yet addressed by this fix, tracked separately**: `wss://` alone doesn't restrict which
    *hosts* an authorized peer can direct this server to open outbound TLS connections to — an
    address-range/host allowlist policy (and whether federation should be permitted to target LAN
    addresses at all) is a distinct SSRF/egress question, deliberately deferred — see
    `KNOWN_SECURITY_ISSUES.md` OPEN-11, closed by invariant 37 below.

37. **Dynamic federation gossip must never grant arbitrary network egress. Every announced peer
    must pass URL policy and destination-address policy before any DNS/TCP/TLS connection is
    attempted. Private, loopback, link-local, reserved, and unspecified destinations are
    fail-closed unless explicitly allowlisted.**
    Why: `wss://` + `CERT_REQUIRED` (invariant 35) authenticates WHO a peer's certificate says it
    is, but nothing about WHERE this server is being told to connect — a compromised/malicious
    federation peer could announce an internal hostname or IP (a LAN admin panel, a cloud metadata
    endpoint, a localhost-bound service on this same machine) via `peer_announce`/`peer_roster` and
    get this server to open an outbound TLS connection to it. TLS/certificate verification does not
    defend against this at all, since the malicious "peer" IS the actual destination in that
    scenario, not a MITM intercepting a connection to somewhere else.
    Where: `server.py` — three gates, in order, before `start_dynamic_peer()` ever runs for a
    gossip-discovered URL: (1) `parse_federation_url()` — strict syntax (`wss` scheme exactly, a
    real hostname, no embedded `user:pass@` credentials); (2) `federation_host_allowed()` —
    resolves the hostname via `getaddrinfo()` and requires EVERY returned address to pass
    `_federation_ip_allowed()` (fail-closed on any disallowed address, a DNS failure, or an empty
    result); (3) `_federation_ip_allowed()` itself rejects any loopback/private/link-local/
    multicast/unspecified/reserved address unless it falls inside an operator-configured
    `FEDERATION_ALLOWED_PRIVATE_CIDRS` range (empty by default — no private destination is ever
    allowed for a gossip-discovered peer out of the box). Static, operator-configured
    `FEDERATION_PEERS` are explicit operator trust and are NOT filtered by this — the threat model
    is a peer already inside the mesh directing this server elsewhere, not the operator's own
    configuration.
    **Known, explicitly accepted residual gap — DNS TOCTOU/rebinding**: `federation_host_allowed()`
    resolves the hostname once for this check; `websockets.connect()` resolves it again,
    independently, moments later when the connection actually opens. The two resolutions are not
    atomic — an attacker with DNS-cache-poisoning reach, or a host they fully control, could serve
    a public address to the check and a private one to the real connection. This raises the bar
    (requires active DNS control at exactly the right moment, not a static malicious record) but is
    not a complete fix. A fully rebinding-proof design needs either network-layer egress policy
    (firewall/container rules restricting the federation process to known peer CIDRs/ports —
    recommended for genuinely strict deployments) or resolving once and connecting directly to the
    verified IP while keeping the hostname only for SNI/certificate verification — neither is
    implemented here. Fixed 2026-09-04 (the three-gate check itself), residual gap tracked at
    `KNOWN_SECURITY_ISSUES.md` OPEN-12, see S6-24.

## Prekey bundle admission and serving (added 2026-09-04)

38. **Every prekey bundle enters one canonical representation. Every single-target prekey fetch
    goes through one canonical serving path.**
    Why: two message types wrote `prekey_bundles` with DIFFERENT shapes for the same underlying
    X3DH bundle — `register_bundle` (legacy, but still Android's only prekey-registration call,
    sent unconditionally on every connect) stored it raw; `publish_prekey_bundle` (canonical)
    wrapped it as `{"bundle": ..., "updated_at": ...}`. `get_prekey_bundle`'s OPK-consumption logic
    (`bundle_data.get("bundle", {}).get("opks")`) only recognizes the wrapped shape — a bundle
    registered via the raw legacy path fell through to a "serve the whole thing, nothing popped"
    branch, silently voiding the one-time-prekey guarantee for whichever bundle actually arrived
    that way (in practice, most Android connections). Separately, a THIRD message type,
    `request_prekey`, served `prekey_bundles[target]` completely as-is over its own code path —
    no `opks.pop(0)`, no persisted consumed-OPK state, no `bootstrap_token`, no `revoked` flag — a
    weaker, parallel route to the identical data that bypassed every guarantee the canonical
    `get_prekey_bundle`/`get_prekey_bundles_batch` path enforces.
    Where: `server.py` — `request_prekey` removed entirely (dead client-side; grepped both Android
    and Desktop source trees, zero callers) — handler and its `ALLOWED_TYPES` entry both deleted,
    not hardened, since nothing calls it. `store_prekey_bundle()` is now the SOLE write path for
    `prekey_bundles`, called by both `register_bundle` (kept as a thin adapter — Android still
    depends on it) and `publish_prekey_bundle` — one function, one shape, so the two message types
    can no longer disagree about what a stored bundle looks like. `get_prekey_bundle`/
    `get_prekey_bundles_batch` remain the only bundle-serving paths.
    **Correction, 2026-09-04 (same day, later pass)**: this invariant's first version additionally
    claimed OPK consumption was already atomic at this point (`opks.pop(0)` under the global
    `lock`, persisted via a fire-and-forget `db_save_bundle()`). That was an overclaim — RAM-lock
    exclusivity is not the same thing as a durable commit, and the persistence itself was never
    awaited, let alone atomic with the pop. See invariant 39 below, which replaces that claim with
    what's actually true now.

39. **An OPK may be exposed to a requester only after its removal from the available pool is
    durably committed. All OPK issuance paths share one canonical durable consume operation.**
    Why: `get_prekey_bundle` used to pop the OPK from the RAM cache under `lock`, THEN
    `asyncio.create_task()` a fire-and-forget `db_save_bundle()` afterward — a crash in that
    window (or the process simply dying before that scheduled task ever ran) meant the SAME OPK
    could be handed out again after a restart, or to a second concurrent requester racing the
    first, defeating the one-time-use guarantee X3DH's forward secrecy for that handshake depends
    on. The incoming-federation path (`federated_get_bundle`) was worse: it popped the OPK from
    RAM under `lock` with NO persistence at all, not even a fire-and-forget save — a federation
    peer re-requesting the same target's bundle (after any restart, or simply racing a second
    request) could receive the identical OPK every time. Both also violated invariant 34 (DB
    awaits forbidden under the global `lock`) implicitly, since the RAM mutation and the (absent
    or fire-and-forget) persistence were never actually part of one atomic operation to begin with.
    Where: `server.py` — `_db_consume_prekey_opk_sync()`: one `BEGIN IMMEDIATE` transaction
    covering the SELECT, the JSON parse, `opks.pop(0)`, and the UPDATE writing the bundle back;
    rolls back and re-raises on any failure, never returning as if an OPK was consumed when the
    write didn't commit. `consume_prekey_bundle_for_serve()` is the sole canonical caller both
    `get_prekey_bundle` and `federated_get_bundle` now use: acquires a narrow per-target
    `prekey_mutation_locks[target]` (separate from the global `lock` — DB awaits are allowed while
    holding this one), awaits the durable consume, and only AFTER that commit succeeds briefly
    takes the global `lock` to sync `prekey_bundles[target]`'s RAM cache to match — DB first,
    RAM-sync second, never the reverse, and no network I/O while holding either lock.
    `store_prekey_bundle()` (publish) shares the SAME per-target lock and the same DB-then-RAM
    ordering, so a concurrent publish and a concurrent consumption for the same target can never
    interleave — one always fully precedes the other. `get_prekey_bundles_batch` is unaffected
    (unchanged): it never consumes an OPK, always returning `opks: []` for every target, decoys
    included. Regression-tested: `Server/tests/test_security_invariants.py`'s durable-OPK-consumption
    section (direct fetch, federation fetch, restart/reload non-reissuance, concurrent-fetch
    non-collision, concurrent publish-vs-consume consistency, simulated DB-failure leaves no
    trace, batch fetch still consumes zero). Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md`
    S6-26.

40. **All client-triggerable prekey-bundle publication aliases share ONE rate-limit bucket, and
    rate limiting/size validation occur before any durable prekey mutation.**
    Why: `register_bundle` and `publish_prekey_bundle` are two message-type aliases for the exact
    same durable operation — both reach `store_prekey_bundle()`, a real SQLite write, a per-target
    `prekey_mutation_locks[username]` acquisition, and executor-thread work (invariant 39). Before
    this fix `register_bundle` alone was rate-limited (a bucket keyed on its own message-type
    string, 20/60s) and `publish_prekey_bundle` had no rate limit at all — an authenticated client
    could spam `publish_prekey_bundle` to force unbounded SQLite writes. Even after adding a limit
    to `publish_prekey_bundle`, keying the two message types on separate buckets would still let a
    client double its effective write rate by alternating between them.
    Where: `server.py` — `rate_limit_check(username, "prekey_publish")`, the SAME bucket name,
    called by both `register_bundle` and `publish_prekey_bundle`, in each case before any bundle
    size validation, before `store_prekey_bundle()`, and therefore before any `prekey_mutation_locks`
    acquisition or SQLite write. The old `"register_bundle"`-keyed bucket was removed (nothing else
    referenced it) rather than left as an unused, misleadingly-named entry. No internal/startup
    code path calls `store_prekey_bundle()` — grepped all callers, only these two message handlers
    — so there is no risk of an internal caller accidentally consuming a user's rate-limit
    allowance. Regression-tested: `Server/tests/test_security_invariants.py`'s shared-prekey-
    rate-limit section (20 combined requests succeed, the 21st is rejected regardless of which of
    the two message types it is, filling the bucket with one type immediately rejects the other,
    a rejected request never reaches `store_prekey_bundle()`, an oversized bundle never reaches
    SQLite, a normal publish still persists to both RAM and disk). Fixed 2026-09-04, see
    `KNOWN_SECURITY_ISSUES.md` S6-27.

41. **Client-triggerable prekey publication is bounded by both a per-identity quota and an
    aggregate server-process quota before any durable mutation.**
    Why: invariant 40's per-user `"prekey_publish"` bucket gives fairness between accounts, but
    does not bound TOTAL write load under open registration — an attacker can mint many valid
    identities (subject only to `POW_DIFFICULTY_BITS`/`MAX_REGISTERED_USERS`, if configured at
    all) and get a fresh 20/60s allowance per identity, multiplying the aggregate durable SQLite
    write rate linearly with the number of identities minted. Each accepted publish is
    intentionally expensive since invariants 38/39 (`store_prekey_bundle()`'s durable DB-first
    write, a per-target `prekey_mutation_locks` acquisition, executor-thread work) — a Sybil flood
    of otherwise individually-compliant requests could still force unbounded aggregate DB load.
    Where: `server.py` — `global_prekey_publish_rate_ok()`, a single process-local counter
    (`global_prekey_publish_rate`), checked by both `register_bundle` and `publish_prekey_bundle`
    immediately after the per-user check and still before any bundle-size validation or
    `store_prekey_bundle()` call. Deliberately RAM-only, not SQLite-backed — implementing an
    "avoid excess SQLite writes" guard as a SQLite write itself would defeat much of its own
    purpose. No `await` inside the check-and-increment, so it's atomic with respect to every other
    coroutine on this single asyncio event loop with no explicit lock needed. Both rejections (the
    per-user bucket and this aggregate one) return the identical generic `"Rate limit exceeded"`
    error — a caller cannot distinguish which bucket was exhausted.
    **Explicitly process-local, not cross-process durable**: this RAM counter is correct and
    sufficient for this deployment's CURRENT shape — one single asyncio process. If ever run as
    multiple replicas/processes behind a load balancer, each process gets its OWN independent
    `PREKEY_PUBLISH_GLOBAL_LIMIT` allowance, so the real aggregate write rate across the whole
    deployment becomes `(configured limit × replica count)`, not the configured limit itself. A
    genuinely multi-process deployment needs a SHARED external limiter (Redis, a gateway/sidecar
    rate limit, etc.) — this mechanism does not provide that and is not meant to.
    `PREKEY_PUBLISH_GLOBAL_LIMIT` (env-configurable, default 200/60s) treats exactly `0` as
    "explicitly disabled"; a negative value refuses to start the server rather than being
    silently, ambiguously coerced into some guessed behavior.
    Regression-tested: `Server/tests/test_security_invariants.py`'s server-wide prekey-publish
    budget section (per-user limit unaffected by the new check, many distinct identities
    collectively exhaust the aggregate quota, a fresh under-its-own-limit identity is still
    rejected once the aggregate is exhausted, a rejected request never reaches
    `store_prekey_bundle()`, the window reset restores quota, both message-type aliases consume
    the same aggregate counter, an oversized bundle still never reaches SQLite after both
    limiters). Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-28.

42. **Anonymous mailbox state has real global expiry and hard process-wide byte and entry bounds.
    Every mailbox/counter mutation is serialized under the same RAM lock; no network/DB await
    occurs under that lock.**
    Why: `MAILBOX_TTL` (48h) was previously enforced only LAZILY, at the exact moment the SAME tag
    was next touched by `mailbox_put`/`mailbox_fetch` — a tag that's never touched again (the
    normal case for a one-shot first-contact bootstrap tag whose intended recipient never fetches
    it) stayed in the `mailbox` dict FOREVER, well past its supposedly-48h lifetime, since nothing
    ever swept it. The existing per-tag cap (5) does nothing against this: a fresh, distinct,
    otherwise-valid random tag on every `mailbox_put` never approaches that limit. At the existing
    rate limit (20/min) and `MAILBOX_MAX_BLOB` (8 KiB), one authenticated identity could add
    roughly 225 MiB of RAM-resident payload per day that nothing reclaimed short of a restart;
    Sybil identities multiply that without bound. TTL alone (even made globally real) only bounds
    *average-case* growth, not worst-case burst growth within one TTL window — a hard capacity
    bound is needed on top, independent of TTL.
    Where: `server.py` — `mailbox_watchdog()` (fires every `MAILBOX_CLEANUP_INTERVAL_SEC`, 300s by
    default) calls `_mailbox_cleanup_expired_locked()` under `lock`, sweeping the WHOLE `mailbox`
    dict and decrementing `mailbox_total_bytes`/`mailbox_total_blobs` for everything it removes —
    this is the real, unconditional global expiry. `mailbox_put`'s own fast path only ever cleans
    the ONE tag it's about to write to (`_mailbox_cleanup_tag_expired_locked()`, shared logic with
    the watchdog's per-tag step) — deliberately never a full scan per request, which would itself
    be an O(n) cost on every single put; `MAILBOX_MAX_TOTAL_BYTES`/`MAILBOX_MAX_TOTAL_BLOBS` are
    what keep the watchdog's own periodic full scan bounded regardless of how large `mailbox` is
    allowed to get between sweeps. Both hard caps are checked BEFORE appending, in `mailbox_put`,
    after the per-tag cap and before any mutation — exceeding either is rejected the same
    externally-indistinguishable way as every other `mailbox_put` failure (invalid tag/blob,
    per-tag cap), so remaining capacity can't be probed from outside. `mailbox_fetch`'s existing
    delete-on-fetch semantics are unchanged (a separate, deliberately out-of-scope question); it
    now also decrements the counters for the FULL set of entries removed by that delete, not just
    the still-live subset returned to the caller, so an already-expired entry sharing a tag with a
    live one is still counted out. Every mutation of `mailbox`/`mailbox_total_bytes`/
    `mailbox_total_blobs` happens under the same `lock`, with no `await` inside any of those
    critical sections.
    **Deliberately does not persist sender identity/owner per entry** to implement a per-user
    occupancy quota instead of (or alongside) this global one — the server already sees the
    authenticated `mailbox_put` request, but retaining a sender→tag mapping for 48h would be a
    strictly worse metadata-retention posture than this blind, sender-less storage already has;
    mailbox entries stay exactly as blind as before this fix.
    **Explicitly process-local, not cross-replica durable** — same caveat as invariant 41's
    aggregate prekey-publish budget: these RAM counters, and `mailbox` itself, are correct and
    sufficient for this deployment's current single-process shape only. A future
    horizontally-replicated deployment sharing one logical mailbox needs shared, bounded external
    storage for it, not an assumption that these counters somehow aggregate across processes.
    Both caps default to strictly positive values and refuse to start the server if configured
    `<= 0` — a hard, always-on process-protection bound, not an optional knob a deployment might
    reasonably disable (unlike `PREKEY_PUBLISH_GLOBAL_LIMIT` in invariant 41, where `0` is a valid
    explicit-disable).
    Regression-tested: `Server/tests/test_security_invariants.py`'s anonymous-mailbox section
    (expired blob on an untouched tag removed by the watchdog helper, a non-expired blob survives
    cleanup, an emptied tag key is removed rather than left as `[]`, byte/blob counters increment
    and decrement exactly on put/fetch, the byte cap and the blob-count cap each reject an
    otherwise-valid put without altering existing state, the per-tag cap of 5 still works, a
    cleanup sweep frees capacity for a later put, and many unique tags collectively cannot exceed
    either global cap). Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-29.

43. **Anonymous pending-delivery RAM is bounded by hard process-wide byte and item caps. Capacity
    is reserved before the durable ACTIVE→IN_FLIGHT transition, and every pending
    mutation/removal uses canonical accounting under the same RAM lock.**
    Why: `TOKEN_PENDING_TTL_SEC` (24h) bounds how LONG a single `token_pending` entry can sit in
    RAM, but nothing previously bounded how MUCH RAM the whole of `token_pending` could hold at
    once — a valid, authenticated subscriber's token can hold one potentially-large
    `anon_delivery` in RAM from the moment a sender fires `anon_message` until either
    `anon_delivery_ack` or the TTL sweep. Many valid, simultaneously-live tokens therefore produce
    bounded retention TIME per entry but UNBOUNDED PEAK RAM in aggregate — the same class of gap
    invariant 42 (mailbox) closed, applied here to anonymous-token pending delivery. This is a
    patch-level resource bound, not a protocol redesign: the one-token/one-message semantics, the
    24h TTL, ACK semantics, RAM-only (never persisted) payload retention, the sealed-payload wire
    format, and `anon_channel`'s identity-less authentication model are all unchanged.
    Where: `server.py` — `TOKEN_PENDING_MAX_TOTAL_BYTES` (128 MiB default) and
    `TOKEN_PENDING_MAX_TOTAL_ITEMS` (5000 default), both required strictly positive (refuse to
    start otherwise, same posture as invariant 42's mailbox caps). Four canonical, lock-only
    helpers own every mutation of `token_pending`/`token_pending_created`/`token_pending_sizes`/
    the byte-item counters: `_token_pending_try_reserve_locked()` (admission check against
    committed totals PLUS any concurrently in-flight reservations, so two racing admissions can
    never both believe they got the last slot), `_token_pending_commit_reserved_locked()`
    (converts a reservation into a real entry), `_token_pending_release_reservation_locked()`
    (releases a reservation without committing it), and `_token_pending_remove_locked()` (the sole
    removal path — every direct `token_pending.pop(...)` in `anon_delivery_ack`,
    `unsubscribe_tokens`, and `token_pending_watchdog`'s tick was replaced with a call to this,
    since a bare pop correctly removed the entry but never decremented the committed totals,
    silently drifting the accounting from reality with every ACK/revoke/expiry).
    **Ordering is the security-relevant part**: `anon_message` reserves RAM capacity FIRST,
    atomically, and only calls `db_mark_anon_token_inflight()` (the durable ACTIVE→IN_FLIGHT
    claim) if that reservation succeeds — a capacity-full rejection therefore never burns an
    otherwise-still-ACTIVE token; the token is left untouched, still spendable by a retry, rather
    than being transitioned to IN_FLIGHT with nowhere to actually queue the payload. The
    reservation is released (never committed) if the DB claim fails, or if the existing
    terminal-state race check (invariant 27) finds the token was concurrently terminalized —
    resolved via `try`/`finally` bookkeeping so an exception or cancellation while a reservation is
    held cannot leak it, and never resolved (committed or released) twice.
    `subscribe_tokens`' redelivery of an already-queued entry is a pure read
    (`token_pending.get(...)`) and never re-increments the counters — the same entry stays pending
    until a real `anon_delivery_ack`, exactly as before this fix.
    **Explicitly process-local**, same caveat as invariant 42's mailbox caps — `token_pending`
    itself is already intentionally process-local (no sealed-payload persistence across restarts,
    a deliberate trade-off predating this fix), so these RAM counters inherit that same scope; a
    replicated deployment would need shared bounded storage for pending deliveries, not an
    assumption these counters aggregate across processes.
    Regression-tested: `Server/tests/test_security_invariants.py`'s token_pending RAM-cap section
    (commit/ACK/unsubscribe/watchdog-expiry each increment or decrement exactly once, redelivery
    on resubscribe does not double-count, the byte cap and the item cap each reject before
    `db_mark_anon_token_inflight()` is ever called, concurrent reservations collectively respect
    the cap, a DB-claim failure and a post-claim terminal-state race both release the reservation
    rather than committing it, an exception mid-claim does not leak the reservation, removing a
    nonexistent token never underflows the counters, and many unique tokens collectively cannot
    exceed the configured cap). Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-30.

44. **Durable offline-message storage has hard row/byte/per-payload bounds. Capacity accounting
    changes atomically with insert/delete/expiry, and a sender is never ACKed for offline
    persistence unless the message is already durably present.**
    Why: `MSG_TTL_SEC` bounded how LONG a `pending_messages` row could live, not how MUCH it could
    grow while still within that window — the same class of gap invariants 42/43 (mailbox,
    token_pending) closed, applied here to the durable SQLite offline queue. Worse than either of
    those two: the TTL sweep itself only ever ran ONCE, at server startup — a long-running process
    never re-swept expired rows at all. An attacker who keeps a single recipient permanently
    offline (trivial — simply never connect that fingerprint) could persist an unbounded number of
    rows for the full TTL, across every relay path reaching `db_store()` (`message`, `session_init`,
    `edit`, `reaction`, `voice`, `group_*`, `missed_call`, ...) — several of which, `voice` in
    particular, have no per-message-type rate limit of their own at all. Separately,
    `_db_store_sync()` swallowed every DB-layer exception (`except Exception: pass`), and
    `message`/`session_init` sent their delivery `ack` UNCONDITIONALLY, regardless of whether
    `db_store()` actually persisted anything — a sender could be told a message was "delivered"
    for a message that was never durably queued at all, a false-delivery-ACK bug independent of
    the capacity question.
    Where: `server.py` — schema: `pending_messages` gained a `payload_bytes` column (migrated via
    `PRAGMA table_info()`, not exception-probing, so `DB_ENCRYPTION_KEY_HEX`/SQLCipher mode
    migrates correctly too; legacy rows backfilled via `length(CAST(payload AS BLOB))`, SQLite's
    actual byte count, not `length()`'s character count for TEXT) plus a singleton
    `pending_messages_meta(total_rows, total_bytes)` row, reconciled from the real table
    (`COUNT(*)`/`SUM(payload_bytes)`) once at every startup, after the TTL sweep — cheap
    transactional bookkeeping so a capacity check never needs to re-scan the whole table.
    `PENDING_MESSAGES_MAX_TOTAL_BYTES` (512 MiB default) / `PENDING_MESSAGES_MAX_TOTAL_ROWS`
    (200000 default) / `PENDING_MESSAGE_MAX_BYTES` (defaults to `MAX_PACKET_SIZE_BYTES`, the same
    ceiling the websocket layer itself already enforces on any single incoming frame — a payload
    legitimately accepted live must also be storable offline) are all required strictly positive,
    refusing to start otherwise, same posture as invariants 42/43's hard caps.
    `_db_store_sync()` rejects an over-`PENDING_MESSAGE_MAX_BYTES` payload before `BEGIN IMMEDIATE`
    is even issued (`"TOO_LARGE"`, no DB connection touched at all); one `BEGIN IMMEDIATE`
    transaction then covers reading the meta counters, the row/byte cap check against them
    (`"FULL"` if exceeded), the `INSERT OR IGNORE`, and — only when `cur.rowcount == 1` (a
    genuinely new row) — the meta increment, all committed or rolled back together. A `msg_id`
    conflict (`rowcount == 0`) is never assumed to be a harmless resend: the existing row is looked
    up and compared by recipient AND payload before being reported `"DUPLICATE"` (safe to ACK,
    same as `"STORED"`); a mismatch on either is reported `"CONFLICT"` instead (never treated as
    success). Any DB-layer exception rolls back and RE-RAISES — the old swallow-everything
    behavior this replaces is exactly the false-delivery-ACK failure mode described above.
    `_db_flush_sync()` keeps its existing delete-on-flush semantics unchanged (the separate
    delete-before-send reliability gap is explicitly out of scope for this fix) but now decrements
    `total_rows`/`total_bytes` in the SAME transaction as the delete. A new
    `pending_messages_watchdog()` (every `PENDING_MESSAGES_CLEANUP_INTERVAL_SEC`, 300s default)
    is what makes the TTL sweep actually periodic instead of startup-only; its tick
    (`_pending_messages_watchdog_tick()`, factored out for direct testing, same split as
    `mailbox_watchdog()`/`token_pending_watchdog()`) runs in bounded
    `PENDING_MESSAGES_CLEANUP_BATCH_SIZE`-row batches (`_pending_messages_cleanup_batch_sync()`),
    each its own short `BEGIN IMMEDIATE` transaction pairing the DELETE with the meta decrement —
    a large expired backlog can never hold the SQLite write lock for one unbounded stretch, which
    would otherwise block every concurrent `db_store()`/`db_flush()`.
    A new process-local `OFFLINE_STORE_GLOBAL_LIMIT` (300/60s default; `0` explicitly disables,
    negative refuses to start) rejects excess write ATTEMPTS in `db_store()` BEFORE the
    executor/SQLite hop at all — once the hard caps above are actually exhausted, every further
    call would otherwise still pay a full `BEGIN IMMEDIATE` transaction just to be told `"FULL"`.
    Deliberately RAM-only, not SQLite-backed, and with no `await` in its check-and-increment (same
    single-event-loop atomicity argument as invariant 41's `global_prekey_publish_rate_ok()`) —
    forcing a SQLite write merely to reject SQLite-write DoS would defeat much of the point.
    **Explicitly process-local, not cross-process durable**, same caveat as invariants 41/42/43 —
    a multi-process/replica deployment gets one independent `OFFLINE_STORE_GLOBAL_LIMIT` budget
    PER PROCESS, not one shared budget across the deployment; a genuinely multi-process deployment
    needs a shared external limiter, not this mechanism.
    The critical ACK rule: `message`/`session_init` now gate their delivery `ack` on `db_store()`'s
    actual returned status — only `"STORED"`/`"DUPLICATE"` (the message IS durably present either
    way) send `ack`; every other status (`"FULL"`, `"TOO_LARGE"`, `"CONFLICT"`,
    `"RATE_LIMITED"`) sends a generic `"Storage unavailable, please retry"` error instead, and the
    FCM wakeup push is likewise only fired once the message is somewhere it can actually be
    delivered from (forwarded via federation, or durably stored) — never on a failed store with
    nothing to wake up for. Every other `db_store()` callsite was grepped: none of them ever
    claimed persistence succeeded via any wire-level signal in the first place (they were already
    fire-and-forget before this fix), so none needed a corresponding change.
    Regression-tested: `Server/tests/test_security_invariants.py`'s bounded-durable-offline-queue
    section (the row cap and the byte cap each reject an otherwise-valid insert without altering
    existing DB/meta state, the per-payload cap rejects before any DB connection is even opened, a
    successful insert increments both counters exactly, a duplicate `msg_id` does not double-count,
    a conflicting duplicate is reported `CONFLICT` rather than treated as success, flush and TTL
    cleanup each decrement counters exactly, a restart-time reconciliation repairs deliberately
    corrupted meta counters back to the real table's totals, the global write-attempt budget
    rejects before the executor/SQLite is ever touched, a real DB exception propagates rather than
    being swallowed, `message`/`session_init` never ACK a failed offline store, a genuine
    duplicate resend still ACKs, and many concurrent large payloads collectively can never push the
    real on-disk totals past the configured caps). Fixed 2026-09-04, see
    `KNOWN_SECURITY_ISSUES.md` S6-31.

45. **Live TOTP state transitions and registration decisions for one fingerprint are serialized by
    the same account-scoped state lock. A register operation never observes an intermediate
    durable-vs-RAM TOTP state.**
    Why: TOTP enable/disable is durable in SQLite (`db_commit_totp_setup()`/
    `db_commit_totp_disable()`), but `register()`'s device-gating decision reads the RAM cache —
    `username in user_totp_secrets` — and `totp_setup`/`totp_disable` each correctly `await` their
    durable commit BEFORE updating that same RAM cache (deliberately: RAM must never race ahead of
    a commit that might still roll back). That `await` is itself a scheduling window on this single
    event loop — a concurrent `register()` for the SAME fingerprint, interleaved while the commit
    is in flight, could previously observe "already durably committed in SQLite" and "still the OLD
    state in `user_totp_secrets`" simultaneously, and act on the stale RAM read rather than either
    the old or the new state consistently. For `totp_setup` specifically, this meant a concurrent
    `register()` could take the no-TOTP device-admission path — silently authorizing a brand-new
    device with zero proof at all — for a fingerprint whose owner was, at that exact moment,
    enabling TOTP specifically to close that path.
    Where: `server.py` — `totp_state_locks` (a plain `dict` of `asyncio.Lock`, one per fingerprint
    that has ever reached a TOTP-state-dependent path) and `get_totp_state_lock(username)` (creates
    the lock for `username` on first use). Deliberately NOT the global RAM `lock` (invariant 34) —
    this is narrow and per-account: fingerprint A's TOTP transition never blocks fingerprint B's
    `register()`, and DB `await`s are explicitly allowed while holding it, unlike the global `lock`.
    `register()` acquires `get_totp_state_lock(username)` before the FIRST decision derived from
    `username in user_totp_secrets` and holds it through the complete security-dependent device-
    admission phase — device-pubkey read/verify, the second-factor-attempt gate
    (`db_take_second_factor_attempt()`), TOTP/recovery-code verify-and-consume
    (`totp_verify_and_consume()`/`db_check_and_consume_recovery_code()`), and the final
    `db_bind_device_pubkey()` or `db_authorize_device()` commit — releasing it BEFORE Phase 2's
    global `lock` (invariant for that RAM-only/no-DB-await split) ever acquires. Lock ordering is
    never inverted and the two locks are never held at the same time: `totp_state_lock` → release →
    global `lock`, only in that direction. `totp_setup`/`totp_disable` each wrap their ENTIRE
    state-dependent operation — the re-check of the current TOTP state, re-enrollment/disable
    authorization (proof of the old code or a recovery code), validation of the new secret/code,
    the durable commit, and the matching RAM write (`user_totp_secrets[username] = secret` /
    `.pop(username, None)`) — in the same lock, with the RAM write happening before the lock is
    released. If the durable commit raises, the exception propagates out of the handler (caught by
    `handle_client`'s own top-level try/except, same as every other DB-layer exception since S6-31)
    and the RAM write is never reached — `async with`'s `__aexit__` still releases the lock
    regardless, so a failed attempt never leaves it stuck held. `totp_verify_and_consume()` itself
    deliberately does NOT acquire this lock internally — every caller (`register()`/`totp_setup`/
    `totp_disable`) already holds it for the whole surrounding transition; acquiring it a second
    time from inside would self-deadlock, since `asyncio.Lock` is not reentrant.
    **Explicitly process-local**: `totp_state_locks` is correct and sufficient for this deployment's
    current single-process shape. If multiple worker processes are ever introduced,
    `user_totp_secrets` itself can no longer be the sole authoritative live state across all of
    them, and this invariant would need to move to shared transactional state (e.g. a durable,
    lock-free read of the committed SQLite row at decision time, or an external distributed lock) —
    not simply a bigger version of this same in-process RAM lock.
    Regression-tested: `Server/tests/test_security_invariants.py`'s account-scoped TOTP-state-lock
    section (a `register()` paused mid-flight cannot observe the transient DB-committed/RAM-stale
    window during a concurrent `totp_setup`, a waiting `register()` correctly sees TOTP enabled once
    `totp_setup` fully completes, a failed `totp_setup`/`totp_disable` leaves RAM exactly unchanged
    and does not deadlock a later attempt, a concurrent `totp_disable` and `register()` serialize
    rather than racing, two concurrent re-enrollment attempts against the same single-use recovery
    code never leave RAM and SQLite disagreeing about which secret is live, and the global `lock`
    is never acquired while a `totp_state_lock` is held during a real TOTP-gated `register()` flow).
    Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-32.

46. **Authorization of TOTP replacement and validation of the newly enrolled secret are distinct
    proofs. A failed new-secret validation never consumes the existing second-factor credential.**
    Why: `totp_setup` used to read `message["code"]` for TWO unrelated roles at once — proof of
    possession of the CURRENT secret (the re-enrollment authorization check, when TOTP was already
    enabled) AND validation of the NEW secret being enrolled. These are two independent TOTP
    secrets; a single 6-digit value validating against BOTH at the same moment is roughly a 1-in-10⁶
    coincidence, so current-TOTP-authorized re-enrollment was practically unusable — inspecting the
    Android client (`TotpSettingsScreen.kt`/`MessengerService.kt`) confirmed it has no UI field for
    a distinct current-secret code at all; only the `recovery_code` fallback ever actually worked.
    Worse, the OLD ordering attempted the dual-purpose field against the CURRENT secret FIRST,
    before ever validating it against the NEW one — a coincidental match (or an attacker
    deliberately probing the ±1 time-step drift window `totp_code_matches()` allows) could consume
    the current TOTP counter even though setup was about to fail validating the new secret anyway,
    burning a genuine second-factor auth window on an attempt that could never have succeeded.
    Where: `server.py`, `totp_setup` handler (inside the existing per-account `totp_state_lock`,
    invariant 45) — three distinct wire fields, never conflated: `new_code` (proof for the NEW
    `secret`, always required), `current_code` (proof for the EXISTING secret, read only when
    `username in user_totp_secrets`), `recovery_code` (unchanged, an alternative proof for the
    existing account). `new_code` falls back to the legacy `code` field for clients not yet updated
    to send it explicitly — Android's `sendTotpSetup()` now sends `new_code` (a straight rename; its
    UI already only ever offered recovery-code re-enrollment, so this has no user-visible behavior
    change). Ordering is the security-relevant part: the NEW secret/`new_code` is validated FIRST,
    via pure `totp_code_matches()` — no DB write, no counter or recovery-code consumption — and an
    invalid `new_code` is rejected immediately, `"invalid_code"`, before `current_code`/
    `recovery_code` is ever looked at. Only once `new_code` validates does the (already-enrolled-
    only) re-enrollment-authorization check run: `db_take_second_factor_attempt()`'s existing guard,
    then `totp_verify_and_consume(username, current_code)`, then `db_check_and_consume_recovery_code()`
    as a fallback — a valid `new_code` alone, with no valid `current_code`/`recovery_code`, still
    correctly fails as `"already_enabled"` and never replaces the durable secret. `last_counter`
    resetting to -1 on a successful replacement is unchanged — `_db_commit_totp_setup_sync()`'s
    `INSERT OR REPLACE` already did this before this fix and still does.
    Regression-tested: `Server/tests/test_security_invariants.py`'s current_code-vs-new_code section
    (first-time setup succeeds with just `new_code`, re-enrollment succeeds with a genuinely
    DIFFERENT `current_code` and `new_code`, recovery-authorized re-enrollment still works, an
    invalid `new_code` consumes neither the current TOTP counter nor a recovery code — verified by
    reusing the exact same proof successfully afterward, a valid `new_code` with an invalid
    current-secret proof never replaces the durable secret, a successful replacement resets
    `last_counter` to -1, and two concurrent re-enrollments racing the same `current_code` remain
    fully serialized by the existing `totp_state_lock`, landing on exactly one of the two proposed
    secrets with RAM and SQLite never disagreeing). Fixed 2026-09-04, see
    `KNOWN_SECURITY_ISSUES.md` S6-33.

47. **Incoming federation forwarding is bounded before delivery work. Federation dedup state has
    hard delivered/in-flight bounds, and an ID becomes durably deduplicated only after the
    corresponding local handoff actually succeeded.**
    Why: `federated_forward` had no dedicated rate limit at all — any authenticated peer could
    forward as fast as it could write to the socket — and its dedup structure (`delivered_msg_ids`)
    had a TTL but no hard entry cap: a flood of UNIQUE msg_ids within the 5-minute TTL grew it
    without bound. Its cleanup made this worse, not just slower — it rescanned the ENTIRE dict on
    EVERY incoming message (`[k for k, v in list(delivered_msg_ids.items()) if now - v > 300]`),
    O(N) work per message, so a sustained flood of unique IDs was O(N²) total CPU while ALSO
    growing RAM — a genuine DoS via a connection that's merely authenticated, not trusted not to
    flood. Independently: a msg_id used to be marked delivered BEFORE delivery/storage actually
    succeeded — a failed `send_safe()`, or a `db_store()` status other than `STORED`/`DUPLICATE`
    (S6-31's `FULL`/`TOO_LARGE`/`CONFLICT`/`RATE_LIMITED`), incorrectly suppressed a legitimate
    retransmission for the full TTL on a message that was never actually delivered anywhere. Simply
    moving the mark to after delivery, naively, opens a second gap: two concurrent peer connections
    forwarding the identical msg_id could both pass a "not yet delivered" check and both proceed to
    deliver. Finally, malformed frames — non-dict top-level JSON, a non-dict `payload`, an
    unhashable (list/dict) or absurdly long `msg_id` — could raise straight into the handler's outer
    `except`, tearing down the WHOLE peer connection's message loop over one bad frame, not just
    rejecting it.
    Where: `server.py`, `handle_federation_peer_incoming()`'s `federated_forward` branch. Validation
    first, before any other work: the top-level `msg` must be a `dict` (checked once, protecting
    every message type this handler processes, not just `federated_forward`); `to` must be a
    non-empty string `<= FED_MAX_TO_LEN` chars; `payload` must be a `dict`; `payload["id"]`, if
    present, must be a non-empty string `<= FED_DEDUP_MAX_MSG_ID_LEN` chars, or the whole frame is
    rejected (`continue`) rather than silently treated as "no msg_id" — a crafted oversized/
    malformed id specifically to dodge dedup is exactly what this closes. Two new process-local rate
    limiters — `fed_forward_rate_per_ip_ok()` (`FED_FORWARD_PER_IP_LIMIT`, default 120/60s) and
    `fed_forward_rate_global_ok()` (`FED_FORWARD_GLOBAL_LIMIT`, default 1000/60s, layered on top,
    same two-tier per-identity/aggregate reasoning as invariants 40/41) — are checked BEFORE any of
    the validation/dedup/DB/client-send work above, and apply even to malformed or no-`msg_id`
    frames (which have no dedup layer to fall back on at all). Both follow the same `0` = explicitly
    disabled, negative = refuse to start convention as `PREKEY_PUBLISH_GLOBAL_LIMIT`/
    `OFFLINE_STORE_GLOBAL_LIMIT` — an authenticated peer is not automatically a trusted one.
    `delivered_msg_ids` is now an `OrderedDict`, hard-capped at `FED_DEDUP_MAX_IDS` (default 20000,
    required strictly positive — a process-protection bound, not an optional knob); a NEW,
    equally-hard-capped (`FED_DEDUP_MAX_INFLIGHT`, default 2000) `federation_delivery_inflight` set
    tracks msg_ids currently mid-handoff — a SEPARATE structure from `delivered_msg_ids`, not a flag
    inside it, specifically so a concurrent duplicate arriving on a DIFFERENT peer connection can be
    recognized and dropped WHILE the first copy is still being delivered, not only after it durably
    lands. Both structures are protected by a dedicated `federation_dedup_lock` — explicitly NOT the
    global server-wide `lock` (invariant 34's "no DB/network await under the global lock" rule would
    otherwise be violated by Phase B below) — never held across a network or DB call. Three-phase
    flow: **Phase A** (`federation_dedup_lock` held) runs `_federation_dedup_cleanup_locked()`, then
    checks `delivered_msg_ids` AND `federation_delivery_inflight` for a duplicate, then (if under
    `FED_DEDUP_MAX_INFLIGHT`) reserves the msg_id in the in-flight set. **Phase B** (lock released)
    does the actual handoff — `send_safe()` if the recipient is online, `db_store()` otherwise —
    computing `success` from the real outcome (a truthy `send_safe()` return, or a `db_store()`
    status of `"STORED"`/`"DUPLICATE"`) rather than assuming it. **Phase C** (inside a `finally`, so
    a cancellation or an exception from Phase B still runs it) re-acquires the lock, unconditionally
    discards the in-flight reservation, and ONLY IF `success` is true commits `delivered_msg_ids[
    msg_id] = now`, evicting the oldest tombstone if `FED_DEDUP_MAX_IDS` is now exceeded. A failed
    Phase B therefore never durably deduplicates anything — the next retransmission of that exact
    msg_id is free to actually succeed. `_federation_dedup_cleanup_locked()` itself replaces the old
    O(N) full rescan: because `delivered_msg_ids` is insertion-ordered and every entry is appended
    once, at delivery time, never reordered, the OLDEST entry is always first — repeatedly peeking
    and popping just that one, stopping the instant it isn't expired yet, does the identical job in
    O(1) amortized per message instead of O(N). Evicting the oldest dedup tombstone under capacity
    pressure is an accepted, bounded trade-off (documented, not silently lossy) — it may let an
    unusually old duplicate through once in a while, but the rate limiters above already bound how
    much duplicate work that could cost, and it never fails NEW federation traffic outright just
    because the cache happens to be full. Included in the same patch: the previous unnamed
    `MAX_PACKET_SIZE_BYTES * 2` federation frame ceiling is now the independently-configurable
    `FEDERATION_MAX_PACKET_SIZE_BYTES` (same numeric value, just named).
    **Both new rate counters (`fed_forward_rate_per_ip`/`fed_forward_rate_global`) are explicitly
    process-local**, same caveat as every other RAM-only limiter in this file — a multi-process/
    replica deployment gets one independent budget PER PROCESS, not one shared budget across the
    deployment; a genuinely multi-process deployment needs a shared external limiter instead.
    Regression-tested: `Server/tests/test_security_invariants.py`'s bounded-federation-forward-dedup
    section (a malformed non-dict top-level frame doesn't kill the handler loop, a non-dict payload
    and an unhashable/oversized msg_id are each rejected without crashing, a repeated msg_id after a
    real successful online delivery or durable offline store is only ever acted on once, a failed
    `send_safe()` or a non-STORED/DUPLICATE `db_store()` status never poisons dedup and a retry can
    still succeed, two concurrent peer connections forwarding the identical msg_id produce exactly
    one real handoff, a cancellation mid-handoff still releases the in-flight reservation, the dedup
    cache and the in-flight set each respect their hard caps under real pressure, expiry only ever
    inspects the oldest entries rather than rescanning, the per-IP limit rejects a flood from one
    peer while leaving a different peer unaffected, the aggregate limit bounds many distinct peer
    IPs collectively even though each is individually under its own per-IP limit, and a payload with
    no msg_id at all is still fully rate-limited). Fixed 2026-09-04, see
    `KNOWN_SECURITY_ISSUES.md` S6-34.

48. **Prekey mutation serialization uses one shared lock per target only while that target has
    active holders/waiters; keyed-lock entries are reference-counted and self-pruning, and all
    prekey target identifiers are validated as canonical fingerprints before registry/DB/federation
    work.**
    Why: `prekey_mutation_locks` was a `defaultdict(asyncio.Lock)` — a lock, once created for a
    given key, was kept for the rest of the process's life, no matter how briefly it was ever
    needed. `consume_prekey_bundle_for_serve(target)` acquires this lock for `target` before
    knowing whether `target` is even a real account or has a bundle at all, and `get_prekey_bundle`'s
    handler read `target = message.get("target")` with no shape validation whatsoever. Put together:
    any authenticated client — no elevated privilege, just the ability to register — could mint one
    permanent, RAM-resident lock (plus its retained dict key, unbounded in length since a websocket
    frame may be up to `MAX_PACKET_SIZE_BYTES`) for every unique garbage string it felt like sending
    as `target`, at up to the existing `prekey_fetch` rate limit (10/min) — a straightforward,
    unbounded RAM DoS with no special access required. The incoming federation `federated_get_bundle`
    handler reached the identical `consume_prekey_bundle_for_serve()` call with a peer-controlled
    `target` and had the same exposure.
    Where: `server.py` — two independent fixes, addressing input validation and resource lifetime
    separately (fixing only one would leave the other exploitable on its own).
    **Validation**: `is_valid_fingerprint(value)` — `register()` derives every real username as
    exactly `sha256(key_bytes).digest()[:8].hex().upper()`: a `str`, length 16, every character in
    `"0123456789ABCDEF"`. Deliberately does not normalize (lowercase, strip, truncate) — every real
    fingerprint this server has ever minted is already exactly this shape, so silently coercing a
    near-miss into something valid-looking would just relocate the validation gap, not close it.
    Checked BEFORE any DB lookup, lock-registry lookup, federation fan-out, or cache lookup, at
    every place a prekey API takes a fingerprint-shaped target: the local `get_prekey_bundle`
    handler (after the existing per-user `prekey_fetch` rate limit, before
    `consume_prekey_bundle_for_serve()`), `get_prekey_bundles_batch` (filters the whole `targets`
    list to canonical fingerprints before any `prekey_bundles`/bootstrap-token work, `MAX_BATCH_
    BUNDLE_TARGETS` still applied to the filtered list), the outgoing `federated_get_bundle()`
    function itself (defense-in-depth — refuses before ever creating a `fed_pending` future or
    sending anything to any connected peer), and the incoming `federated_get_bundle` handler (after
    the existing per-IP `fed_bundle_rate_ok()` check, before `consume_prekey_bundle_for_serve()` —
    an invalid target gets silently dropped, never echoed back into a federation response).
    `store_prekey_bundle()`/`consume_prekey_bundle_for_serve()` themselves do NOT additionally
    validate — `store_prekey_bundle()`'s `username` is always the calling connection's own proven
    identity, never attacker-chosen, and `consume_prekey_bundle_for_serve()`'s `target` is validated
    by every one of its callers before it's ever reached, per the four call-sites above.
    **Resource lifetime**: `prekey_mutation_locks` is now a plain `dict`, and
    `prekey_mutation_guard(target)` (an `@asynccontextmanager`) replaces every bare
    `async with prekey_mutation_locks[key]:`. Each registry entry is `{"lock": asyncio.Lock(),
    "refs": <int>}`; `refs` is incremented the INSTANT the entry is created or found — before the
    `await` on `.acquire()` — and this whole sequence (dict lookup/create, increment) has no
    `await` in it, so it's atomic with respect to every other coroutine on this single event loop,
    needing no separate lock to protect the registry dict itself. `refs` is decremented in a
    `finally` that wraps BOTH the wait-to-acquire step and the critical section, so a normal exit,
    a cancellation while still waiting to acquire, and a cancellation while holding the lock all
    decrement exactly once; the entry is popped only when `refs` reaches 0 AND the dict still maps
    the key to that exact same entry object (guards a pop-then-recreate double-free, which the
    ordering here shouldn't allow but costs nothing to check for anyway).
    **`refs` counting WAITERS, not just the current holder, is the entire correctness argument**:
    decrementing (and potentially pruning) on ENTERING the critical section instead of on truly
    leaving it reopens exactly the split-lock race invariant #39 exists to prevent — coroutine A
    holds lock L1 for `target`, coroutine B is already queued behind it, A finishes and (wrongly)
    the registry prunes `target` while B is STILL waiting, coroutine C then calls this for the same
    `target`, finds no entry, and creates a brand-new lock L2; B's queued acquire on L1 and C's
    acquire on L2 can now both succeed at once — two coroutines inside a "target" critical section
    simultaneously, the exact interleaving per-target serialization exists to rule out (a concurrent
    publish and a concurrent OPK consumption for one target could interleave again). Counting
    waiters closes this: the entry (and its lock) stays alive as long as anyone, holder or waiter,
    still references it.
    `store_prekey_bundle()` and `consume_prekey_bundle_for_serve()` use `prekey_mutation_guard(...)`
    in place of the old bare lock access; the protected critical sections themselves, the DB-first-
    then-RAM-sync ordering, and the durable single-use-OPK guarantee (invariant #39) are completely
    unchanged — this fix changes only the lock's own lifetime management and the input validation
    gating access to it, not prekey protocol semantics, X3DH, bundle publication, or federation
    behavior.
    Two approaches explicitly rejected: capping `target`'s length alone (closes the oversized-key
    amplification but still leaves permanent growth from unlimited unique valid-*looking* 16-hex
    strings) and periodically clearing the registry (would itself reopen the same split-lock race
    the refcount exists to prevent, if a clear ever raced a live holder/waiter).
    Regression-tested: `Server/tests/test_security_invariants.py`'s canonical-fingerprint-validation-
    and-self-pruning-registry section (`is_valid_fingerprint()` rejects every malformed shape
    tested directly; `None`/list/dict/int targets and an overlong target are each rejected before
    `consume_prekey_bundle_for_serve()`/any registry mutation is ever reached; a genuinely valid
    16-char fingerprint still works end to end; 300 sequential unique valid-looking nonexistent
    targets leave the registry empty afterward; a finished publish and a finished consume each
    leave no registry entry; two concurrent consumes of the SAME target are proven to share the
    exact same registry entry object and remain serialized to two different OPKs; a publish racing
    a consume for the same target likewise shares one entry; two different targets proceed fully
    concurrently, unblocked by each other; cancellation while waiting for the lock decrements refs
    without leaking, verified via a live refcount assertion mid-wait; cancellation while HOLDING
    the lock releases it and removes the entry, verified by a fresh consume succeeding immediately
    after; an invalid target on the incoming federation handler never reaches
    `consume_prekey_bundle_for_serve()`; an invalid target on the outgoing `federated_get_bundle()`
    creates no `fed_pending` future and sends nothing to any peer; and a batch fetch filters out
    every malformed target before any cache/DB work, leaving only the canonical one in the result).
    Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-35.

49. **Serving a one-time prekey is independently abuse-bounded per requester/target, per target,
    and process-wide. A throttled bundle lookup remains usable via the no-OPK fallback and never
    consumes or re-serves an OPK.**
    Why: invariant #39 (S6-26) made OPK consumption durable and single-use, and invariant #48
    (S6-35) bounded the lock registry serializing it — but neither stopped an otherwise-fully-
    authorized caller from repeatedly draining a target's OPK pool. A single authenticated local
    account, still within its own `prekey_fetch` allowance, could repeatedly call
    `consume_prekey_bundle_for_serve(target)` and consume a fresh OPK every time; an authenticated
    federation peer, still within `FED_BUNDLE_LIMIT`, could do the same via the incoming
    `federated_get_bundle` handler. No `session_init` or actual X3DH handshake was ever required —
    this was pure OPK-ISSUANCE abuse, a different problem than the existing bundle-fetch-VOLUME
    limits already cover. `get_prekey_bundles_batch` was already safe (`opks: []` unconditionally)
    and is unaffected.
    Where: `server.py` — `consume_prekey_bundle_for_serve(target, requester_scope)` gained a second
    parameter (`username` for a local caller, `"fed:" + ip` for an incoming federation peer — never
    put on the wire; the federation identity is only shared-secret/IP-scoped, not a cryptographic
    peer identity, so this is a best-effort fairness key, and the per-target/global budgets below
    are the real backstop if a peer reconnects under a new source address).
    After acquiring `prekey_mutation_guard(target)` (invariant #48), the function first peeks the
    RAM-cached bundle (safe: the guard is held for the whole span, so nothing else can mutate
    `prekey_bundles[target]` concurrently). A nonexistent target returns `(None, 0)` immediately; a
    target whose pool is already empty returns the normal bundle with `opks: []` immediately —
    NEITHER case ever reaches the guards below or creates any limiter state, matching invariant
    #48's own posture on attacker-controlled growth. Only for a target with a real, available OPK
    are three independent, process-local guards evaluated, synchronously and with no `await`
    between check and update (atomic on this single event loop): a per-`(requester_scope, target)`
    cooldown (`OPK_PAIR_COOLDOWN_SEC`, default 300s — an immediate same-scope repeat gets `opks: []`,
    never the same OPK re-served), a per-target aggregate issuance budget
    (`OPK_TARGET_MAX_PER_WINDOW`/`OPK_TARGET_WINDOW_SEC`, default 5/60s — bounds how fast ONE
    target's pool drains no matter how many distinct requester_scopes are used, closing the Sybil-
    username/reconnecting-federation-peer amplification path), and a server-wide aggregate budget
    (`OPK_GLOBAL_MAX_PER_WINDOW`/`OPK_GLOBAL_WINDOW_SEC`, default 300/60s — bounds aggregate SQLite-
    write amplification across many different targets, layered on top of the per-target budget the
    same way invariant 41's `global_prekey_publish_rate_ok()` layers on `"prekey_publish"`). Only a
    request admitted by ALL THREE guards reaches `db_consume_prekey_opk()`; target/global budgets
    are reserved (incremented) the instant a request is admitted and are deliberately NOT refunded
    if the subsequent durable consume raises — same fail-closed convention as
    `OFFLINE_STORE_GLOBAL_LIMIT`/`global_prekey_publish_rate_ok()`. The pair-cooldown entry itself
    (`opk_pair_last_issued`, an `OrderedDict`) is recorded ONLY after `db_consume_prekey_opk()`
    actually reports a popped OPK — never on a denied attempt — and is lazily self-pruned
    (`_opk_pair_cleanup()`, the same oldest-entry-only O(1)-amortized trick invariant 47's
    `_federation_dedup_cleanup_locked()` uses) rather than kept as an unbounded permanent dict; its
    live size is bounded in practice by the global budget times the cooldown window, regardless of
    how many distinct requester_scopes or targets are involved.
    Any guard denial returns the otherwise-normal bundle with `opks: []` — never `None`, never a
    distinguishable error, and no SQLite mutation of any kind — so the existing no-OPK X3DH fallback
    remains available; this is abuse containment, not a new protocol failure mode. Defaults were
    chosen after inspecting Android's actual OPK pool (`SessionKeyManager.refillOpkPool`, target
    size 10, low-watermark republish nudge at `OPK_LOW_WATERMARK` = 5) so the guard is never the
    reason a legitimate burst of brand-new contacts (each needing exactly one real OPK) gets
    throttled. All five constants (`OPK_PAIR_COOLDOWN_SEC`, `OPK_TARGET_WINDOW_SEC`,
    `OPK_TARGET_MAX_PER_WINDOW`, `OPK_GLOBAL_WINDOW_SEC`, `OPK_GLOBAL_MAX_PER_WINDOW`) are env-
    configurable with explicit validation: the two budgets and the cooldown treat `0` as explicitly
    disabled and a negative value as a refuse-to-start misconfiguration; the two window widths have
    no sensible "disabled" meaning and must simply be strictly positive.
    The protected critical section itself — `prekey_mutation_guard(target)` serialization, DB-first-
    then-RAM-sync ordering, the durable single-use-OPK guarantee (invariant #39) — is completely
    unchanged; this fix changes only what gates reaching it. **These OPK-issuance guards are
    explicitly process-local**, same caveat as every other RAM-only limiter in this file — a future
    multi-worker deployment sharing the same prekey database needs shared issuance accounting across
    workers, not a bigger version of these same RAM structures.
    Regression-tested: `Server/tests/test_security_invariants.py`'s OPK-issuance-abuse-guards section
    (a first fetch consumes a real OPK and an immediate same-scope repeat gets the normal bundle
    shape with `opks: []`, never a stale or previously-issued key; a different requester_scope can
    still consume while the target budget allows even though the first requester is on cooldown;
    pair-cooldown expiry permits a later fresh OPK for the same pair; many Sybil requester_scopes
    against one target are capped at the per-target budget regardless of how many distinct scopes
    are used, and never issue the same OPK twice; a target-budget denial and a global-budget denial
    each perform zero SQLite mutation; the global budget bounds total issuance across many different
    targets even though each stays under its own per-target budget; a nonexistent target and a
    target whose pool is already empty each create zero limiter state; an incoming federation peer
    repeating a target request hits the same pair guard a local requester would; a federation
    source-address change bypasses the pair guard (as expected, since it's not a cryptographic
    identity) but not the per-target budget; a batch fetch still consumes zero OPKs with every guard
    active and never even enters the issuance path; a denied request is proven to never re-serve an
    already-issued OPK across repeated attempts; a publish racing an admitted consumption remains
    serialized by the same `prekey_mutation_guard` entry; an admitted consumption still durably
    commits to SQLite before ever being reported to the caller; and limiter state is proven to
    self-prune after expiry rather than growing permanently). Fixed 2026-09-04, see
    `KNOWN_SECURITY_ISSUES.md` S6-36.

50. **Device identifiers and device-authentication material are protocol-bounded before expensive
    processing or persistence. Durable device-key enrollment is atomically capped per fingerprint,
    and TOTP-disabled connections do not create trust-less permanent device rows.**
    Why: `register()` took `device_id = message.get("device_id")` with no length/format bound at
    all — bounded only by the multi-megabyte websocket frame ceiling — and `device_public_key`/
    `device_signature` were base64-decoded and DER-parsed with no protocol-specific size limit
    either. Separately, whenever TOTP wasn't configured for an account, `register()` durably
    INSERTed a NULL-`device_pubkey` row into `authorized_devices` on every reconnect with a fresh
    `device_id` — a NULL row confers no trust by itself (`db_get_authorized_device()`'s own logic
    treats "no row" and "row exists, pubkey NULL" identically: both still require TOTP/recovery-
    proof plus a valid device signature before `db_bind_device_pubkey()` ever pins anything), so one
    authenticated fingerprint could reconnect repeatedly with a fresh device_id every time and
    permanently grow the table for zero security benefit, paying registration PoW only on its
    first-ever registration. Even after removing that path, an account that legitimately keeps
    re-proving TOTP for brand-new device_ids (each reinstall/phone change generates a fresh one)
    could still durably enroll an unbounded number of pinned device keys over its lifetime.
    Where: `server.py` — four independent fixes.
    **Canonical device_id validation**: both Android (`UserStorage.getDeviceId()`) and Desktop
    (its own `UserStorage.getDeviceId()`) generate `device_id` exactly once per install via
    `UUID.randomUUID().toString()` and persist it indefinitely — a standard RFC-4122 textual UUID,
    always exactly 36 characters. `is_valid_device_id(value)` checks this exact shape, checked
    BEFORE any device DB lookup/write and before even the identity-key checks in `register()`,
    since it has nothing to do with which fingerprint is registering. Only a device_id that was
    actually PROVIDED and doesn't match this shape is rejected — an absent/empty device_id is
    "missing", not "invalid", and falls through unchanged into the pre-existing TOTP-required
    fail-closed check. Deliberately never truncated or normalized: `device_id` participates
    byte-for-byte in the signed data (`SUBROSA_DEVICE_V1 || challenge || username || device_id`),
    so rewriting it server-side would change what the client actually signed.
    **Bounded crypto-field lengths**: `MAX_DEVICE_PUBKEY_B64_LEN` (512) and `MAX_DEVICE_SIGNATURE_
    B64_LEN` (256) are checked as plain string-length comparisons BEFORE `base64.b64decode()`/
    `load_der_public_key()` ever runs. `device_public_key` is a DER X.509 SubjectPublicKeyInfo for a
    secp256r1 (P-256) public key — a fixed 91 raw bytes, 124 base64 characters; `device_signature`
    is a DER-encoded ECDSA signature over the same curve — variable but typically 70-72 raw bytes,
    roughly 96-100 base64 characters. Both bounds are deliberately generous relative to those real
    sizes while remaining tiny relative to `MAX_PACKET_SIZE_BYTES` — these fields carry a single EC
    key or signature, never megabytes of legitimate data. `base64.b64decode(..., validate=True)`
    additionally rejects non-alphabet input instead of silently ignoring it.
    **TOTP-disabled admission no longer persists anything**: the branch that used to run
    `db_authorize_device(username, device_id)` whenever `username not in user_totp_secrets` is
    removed entirely — confirmed via grep and `db_get_authorized_device()`'s own logic that a
    NULL-pubkey row carries no independent trust, so removing its only creation path is security-
    semantics-neutral. `db_authorize_device()`/`_db_authorize_device_sync()` deleted as dead code
    (this was their only caller). `clients[username]["device_id"]` (RAM-only, Phase 2) already
    tracks the live session's device_id for session-conflict purposes — nothing durable was ever
    needed for the TOTP-disabled case.
    **Atomic per-account device cap**: `MAX_AUTHORIZED_DEVICES_PER_ACCOUNT` (32, required strictly
    positive — refuses to start otherwise) is enforced INSIDE `db_bind_device_pubkey()`'s existing
    `BEGIN IMMEDIATE` transaction — a `SELECT COUNT(*)` for the account and the conditional `INSERT`
    share the SAME transaction, so two concurrent enrollments can never both observe "under cap" and
    both insert (a separate count-then-insert-in-a-later-transaction would allow exactly that race).
    An EXISTING row — already pinned and matching, already pinned and mismatched, or a legacy row
    whose pubkey is still NULL — is never blocked by the cap; only a genuinely NEW device_id row is,
    since claiming existing state is not new durable growth. `db_bind_device_pubkey()` changed from
    a bare bool to explicit `"BOUND"`/`"ALREADY_MATCHED"`/`"CONFLICT"`/`"FULL"` statuses; register()
    sends a distinct `device_limit_reached` reply for `"FULL"`, and the generic `device_auth_failed`
    for every other non-success status (the same unreachable-in-practice safety net the old bool
    return provided). A one-time-in-effect startup migration (`DELETE FROM authorized_devices WHERE
    device_pubkey IS NULL`) reclaims whatever the removed TOTP-disabled path left behind historically
    — safe to run unconditionally on every restart, since no code path creates a new NULL-pubkey row
    anymore, so it becomes a costless no-op once the initial backlog is gone. Never touches a row
    with a pinned (non-NULL) pubkey.
    None of this changes device-auth semantics: device-key signatures, TOTP/recovery-code
    requirements, the never-overwrite-a-pinned-key invariant, and live session behavior are all
    unchanged — this is resource/input hardening only.
    Regression-tested: `Server/tests/test_security_invariants.py`'s bounded-authorized-devices-
    growth section (an oversized device_id is rejected before any `authorized_devices` DB call; a
    malformed non-UUID-shaped device_id is rejected; a genuinely canonical UUID device_id still
    registers normally; an oversized `device_public_key`/`device_signature` is each rejected before
    base64/DER parsing ever runs; TOTP-disabled reconnects with many distinct device_ids create zero
    new rows; enabling TOTP afterward still lets a legitimate device bind; new pinned devices can be
    added while under the account cap; the first device attempted above the cap is rejected with no
    INSERT ever happening; two concurrent enrollments racing for the last available slot are proven
    to admit exactly one, never both, via the same real atomic transaction; an already-pinned
    device's reconnect still works even while the account is already at the cap; a pre-existing
    legacy NULL row can still be claimed even while over the cap; a different key can never overwrite
    an already-pinned device_id; and invalid input at every validated field is proven to never reach
    `db_bind_device_pubkey()`'s write transaction at all). Fixed 2026-09-04, see
    `KNOWN_SECURITY_ISSUES.md` S6-37.

51. **Federation forwarding is a dedicated protocol surface, not the general client protocol
    surface. Both outbound and inbound federated_forward payloads are restricted to an explicit
    allowlist derived from legitimate federation producers, with canonical sender/destination
    identifiers validated before deduplication, delivery, or persistence.**
    Why: invariant 47 (S6-34) bounded and rate-limited the OUTER `federated_forward` envelope, but
    the INNER `payload["type"]` was still handed straight to a local client (`send_safe()`) or the
    offline queue (`db_store()`) with no check that this server would ever have produced that
    payload type through federation itself. An authenticated federation peer — trusted only to know
    `FEDERATION_SECRET`, not to only ever send legitimate federation traffic — could supply an
    ARBITRARY `payload["type"]` inside `federated_forward`: `session_conflict` (force a local client
    into believing a session eviction happened), any `totp_*` control message, `identity_revoked`/
    `identity_revoked_ack`, `prekey_bundle_request`/`prekey_bundle_response`, `subscribe_tokens_
    result`, `anon_delivery_ack_ok`, or any other privileged/control client-protocol message this
    server itself has never once sent across a federation link. `ALLOWED_TYPES` is the wrong
    allowlist to reuse here — it describes what an authenticated CLIENT may send TO its own server,
    a much larger trust surface than what one federation server is actually supposed to relay to
    another on that client's behalf.
    Where: `server.py`.
    **`FEDERATED_FORWARD_ALLOWED_TYPES`**: a `frozenset`, derived by grepping every CURRENT
    `forward_to_peers()` call site rather than assumed — `read`, `delivered`, `typing`, `edit`,
    `session_init`, `message`, `reaction`, `group_reaction`, `voice`, `group_create`,
    `group_message`, `group_member_removed`, `group_key_rotation`, `group_invite_accepted`,
    `message_delete`, `disappear_timer`, `group_message_delete`. (`typing` in particular was absent
    from an initially-proposed list and only surfaced by grepping actual call sites instead of
    trusting a hand-written guess — the exact class of drift this invariant exists to prevent.)
    Deliberately does NOT include `session_conflict`, `identity_revoked`/`identity_revoked_ack`, any
    `totp_*` type, any device-auth/control response, `register`/`register_bundle`, prekey publish/
    get control messages, subscribe/unsubscribe token control, `anon_delivery_ack`, mailbox control,
    federation protocol messages themselves (`peer_announce`/`peer_roster`/`federated_get_bundle`/
    `federated_bundle_response`/`federated_forward` itself), challenge/handshake messages, or any
    other current/future `ALLOWED_TYPES` entry — none of these has a real `forward_to_peers()`
    producer today. This is intentionally an allowlist, not a denylist: a new federated payload type
    added later requires deliberately adding it here, so a forgotten exclusion can never silently
    become forwardable.
    **`validate_federated_forward_payload(payload)`**: `payload` must be a dict, `payload.get("type")`
    must be a member of the allowlist above, and `payload.get("from")` must satisfy
    `is_valid_fingerprint()`. Every currently-federated payload type has its `from` set SERVER-SIDE
    by the originating server to the connection's own proven fingerprint before `forward_to_peers()`
    is ever called (verified by grepping every call site — each constructs `"from": username` or
    mutates `message["from"] = username` from the authenticated sender's own identity, never
    client-supplied), so this one check is meaningful for every current type with no per-type
    exception needed. Does not normalize or invent `from`.
    **Enforced on BOTH the inbound and outbound surfaces, deliberately kept from drifting apart**:
    - Inbound (`handle_federation_peer_incoming()`'s `federated_forward` branch): AFTER the existing
      S6-34 per-IP and global rate limits and the existing cheap outer `to`/`payload` shape checks,
      `is_valid_fingerprint(to)` (not merely length-bounded — a junk recipient "namespace" must
      never reach `clients[]`/SQLite) and `validate_federated_forward_payload(payload)` are both
      required BEFORE msg_id shape validation, the Phase-A dedup reservation, and any
      `send_safe()`/`db_store()` call. A frame that fails either check performs no DB work, no local
      send, creates no `federation_delivery_inflight`/`delivered_msg_ids` entry, and does not
      terminate the peer connection — it is simply dropped, exactly like any other malformed frame
      this handler already tolerates.
    - Outbound (`forward_to_peers(to, payload)`): runs the identical `is_valid_fingerprint(to)` and
      `validate_federated_forward_payload(payload)` checks before ever serializing or sending
      anything, failing closed (logging what looks like a programming/protocol error) rather than
      silently relaying. Every current call site already only ever passes an allowed type, so this
      is deliberately redundant today — the point is a FUTURE local handler that accidentally calls
      `forward_to_peers()` with a local-only privileged/control payload fails closed immediately
      instead of silently leaking a control message to every connected peer until someone notices.
    **Explicit residual limitation this patch does NOT solve**: a canonical-shaped `from` only
    proves SYNTAX, not origin. With today's shared federation secret and no per-user origin
    signature at the federation layer, this server cannot cryptographically prove the sending peer
    actually owns or serves the fingerprint it claims — a compromised/malicious peer can still lie
    about `from` for an otherwise-ALLOWED type (e.g. forge a `message` that appears to come from any
    fingerprint it chooses). Closing that requires cryptographic remote-user/server ownership
    binding or another federation-origin design; that is an architecture/protocol change, explicitly
    out of scope for this patch, and must be tracked separately if ever undertaken.
    Regression-tested: `Server/tests/test_security_invariants.py`'s federated-forwarding-restricted-
    to-legitimate-producers section (every current `FEDERATED_FORWARD_ALLOWED_TYPES` member passes
    the validator; a normal federated message still reaches an online recipient and still reaches
    `db_store()` when the recipient is offline; an injected `session_conflict`, `totp_setup_ok`/
    `totp_required`, `identity_revoked`/`identity_revoked_ack`, `prekey_bundle_request`/
    `prekey_bundle_response`, `subscribe_tokens_result`/`anon_delivery_ack_ok`, a nested
    `federated_forward` payload, and an arbitrary unknown type are each rejected; a payload with no
    `type` at all and a missing/`None`/malformed/wrong-typed `from` are each rejected; a
    non-canonical `to` is rejected; a rejected payload is proven to reserve no dedup state
    (`delivered_msg_ids`/`federation_delivery_inflight`) and to call neither `send_safe()` nor
    `db_store()`; a malformed/rejected frame only drops that one frame, with a subsequent legitimate
    frame on the SAME connection still succeeding; `forward_to_peers()` itself refuses a
    non-allowlisted payload and an invalid destination before ever touching a fake peer socket; and
    every current `forward_to_peers()` call site is exercised end-to-end and proven to emit only
    allowlisted types). Fixed 2026-09-04, see `KNOWN_SECURITY_ISSUES.md` S6-38.

52. **Handshake key possession and successful registration are distinct authorization states. A
    fingerprint becomes the connection's application identity only in the successful Phase-2 commit
    after every admission, revocation, TOTP, and device-authentication gate has passed. Ordinary
    client protocol messages require that committed registration state.**
    Why: `register()` derived `username = fingerprint` immediately after deriving the fingerprint
    from the handshake-proven key — BEFORE the registration/admission/security gates below it had
    run at all. Every one of those gates rejects with a bare `continue` (stays on the same
    connection, never closes it), so a REJECTED candidate identity — bad PoW, server full, wrong/
    absent access code, revoked identity, missing/failed TOTP, invalid device signature, device-cap
    reached, or any other gate failure — still left `username` populated with that fingerprint for
    the rest of the connection's lifetime, even though Phase 2 (`clients[username] = ...`,
    `authenticated_users[websocket] = username`) never ran. A subsequent ordinary message on the
    SAME socket was then processed using that uncommitted candidate fingerprint, bypassing every
    gate the failed `register()` was supposed to enforce — e.g. a connection holding a stolen
    identity private key that failed TOTP could still call `request_sender_cert` and receive a
    validly-signed sender certificate for that fingerprint, send `message`/`session_init` under it,
    claim `subscribe_tokens` for it, or even `revoke_identity` on it — all without ever actually
    proving TOTP or device possession. Handshake key possession is NOT registration authorization;
    treating them as interchangeable was the entire bug.
    Where: `server.py` — `handle_client()` and `register()`, three independent fixes.
    **Candidate/committed separation**: the connection-scope `username` (declared `None` at
    function entry, before the handshake even completes) is never assigned anywhere inside
    `register()`'s gates. A new local, `candidate_username`, is used for every security/admission
    operation instead: `db_is_fingerprint_registered()`, PoW logging, `db_admit_new_fingerprint()`,
    `db_is_fingerprint_revoked()`, `get_totp_state_lock()`, the `user_totp_secrets` membership check,
    `db_get_authorized_device()`, `db_take_second_factor_attempt()`, `totp_verify_and_consume()`,
    the recovery-code consume, `db_bind_device_pubkey()`, and — critically — the device-signature
    `signed_data` construction (`SUBROSA_DEVICE_V1 || challenge || candidate_username ||
    device_id`), which must continue signing over the fingerprint actually BEING registered
    regardless of whether registration ultimately succeeds. `username = candidate_username` happens
    in exactly ONE place: inside Phase 2's successful `async with lock:` commit, atomically with
    `clients[candidate_username] = {...}` and `authenticated_users[websocket] = candidate_username`
    — by construction, every gate above has already passed by the time this line runs. A rejected
    candidate therefore leaves `username` exactly `None`, indistinguishable from a connection that
    never attempted `register()` at all.
    **Hard authorization boundary**: defense in depth on top of the refactor above, so a future
    change to `register()`'s many failure paths accidentally reintroducing an early assignment
    can't reopen this bug silently. Before processing ANY message other than `register` (or the one
    documented exception below), the ordinary client loop now requires
    `authenticated_users.get(websocket)` to be non-`None`, closing the connection with a generic
    `"Registration required"` error otherwise. This checks the ONE authoritative live mapping that
    only Phase 2's successful commit ever writes to — it doesn't trust the local `username` variable
    at all. `is_anon_channel` connections are exempt (they intentionally never register or enter
    `authenticated_users`, and are already restricted to exactly `anon_message` by the block above
    this one, so `msg_type` here is always `anon_message` whenever `is_anon_channel` is true).
    Federation peers never reach this loop in the first place (`is_fed` returns straight into
    `handle_federation_peer_incoming()` earlier). `register_bundle` is ALSO exempted — verified
    against CURRENT client behavior, not assumed: Android's `MessengerService.kt` `handshake_ok`
    handler sends `register_bundle` synchronously on one coroutine, while the SEPARATE coroutine
    that sends `register` only notices the handshake completed via a 100ms poll loop
    (`while (!handshakeDone) delay(100)`), with no happens-before relationship between the two —
    Android can and does genuinely deliver `register_bundle` before `register` completes on a fast
    connection (this is the same behavior the pre-existing comment on that handler already
    documented: "still sent by Android unconditionally on every connect... right after handshake").
    Desktop's handshake sequence has no such race (checked against that client tree too). The
    `register_bundle` handler itself now has an explicit `if not username: continue` guard so an
    uncommitted-identity delivery is safely dropped (no durable write under a bogus `None` key)
    instead of either crashing or being rejected outright — the connection stays open and the
    client's own subsequent `register` still proceeds normally. No other message type has any
    provable pre-register need on either client; anything else arriving before a completed
    `register` closes the connection.
    **Disconnect cleanup requires no code change**: the existing `finally` block's account-specific
    cleanup (`clients.pop`, `authenticated_users.pop`, `rate_limits`, `active_calls`,
    `ws_to_tokens`/`token_to_ws`) is already gated on the local `username` — which, after this fix,
    can only ever be the actual committed identity or `None`. A failed candidate registration
    therefore automatically never mutates another account's live session, exactly as if the failed
    connection had never attempted `register()` at all.
    Explicitly NOT a conceptual change: challenge-response still proves identity-key possession, and
    `register()` still performs the exact same gates in the exact same order — this patch only
    prevents a REJECTED candidate identity from ever crossing the authorization boundary into
    `authenticated_users`/`clients`/the connection's own `username`.
    Regression-tested: `Server/tests/test_security_invariants.py`'s candidate-identity-vs-committed-
    session section (a failed TOTP register leaves `username` uncommitted, and every one of
    `request_sender_cert`/`message`/`subscribe_tokens`/`revoke_identity` is proven impossible
    afterward on that same socket; the same "impossible afterward" property is proven for a revoked
    fingerprint, denied access code, bad PoW, a full server, `device_auth_failed`, and
    `device_limit_reached`; a challenge_response client sending `message` or `request_sender_cert`
    BEFORE any register attempt is rejected/closed; a successful register is proven to set
    `username`/`authenticated_users[websocket]`/`clients[username]["ws"]` consistently, and every
    normal handler still works afterward; `anon_channel` still sends `anon_message` with no register
    at all; federation still goes straight to its dedicated handler, unaffected; a cancellation
    during Phase 1 and a forced failure immediately before Phase 2 each leave `username`
    uncommitted; a failed registration attempt for an account with an ALREADY-live legitimate
    session is proven to leave that existing session's `clients`/`authenticated_users` entries
    completely untouched; and one explicit invariant-style test asserts, across multiple distinct
    rejection scenarios, that the connection never appears in `authenticated_users`/`clients` after
    a rejected register attempt). Fixed 2026-09-05, see `KNOWN_SECURITY_ISSUES.md` S6-39.

53. **Account-scoped client startup traffic is released only after that exact websocket generation
    has completed server-side registration. The server has no ordinary pre-registration message
    exceptions.**
    Why: invariant 52 (S6-39) added a hard authorization boundary requiring `authenticated_users.
    get(websocket)` to be non-`None` before processing any non-`register` message — but it briefly
    carried one exception, for `register_bundle`, because Android's `MessengerService.kt` genuinely
    could deliver it before `register`. The client's `handshake_ok` handler ran in a coroutine
    spawned independently per incoming message and sent `register_bundle` the instant the handshake
    completed; the SEPARATE coroutine actually responsible for sending `register` only noticed the
    handshake was done via a polled Boolean (`while (!handshakeDone) delay(100)`), with no
    happens-before relationship between the two. On a fast connection, `register_bundle` could reach
    this server first. The exception (`register_bundle` exempted from the boundary, guarded instead
    by an inner `if not username: continue` so it couldn't durably write under a bogus key) kept this
    from being an authorization bypass, but it was still an unnecessary weakening of an otherwise-
    strict rule, and a legitimate bundle publication racing this way could be silently dropped.
    Where: `app/src/main/java/com/example/test/MessengerService.kt` (the actual fix) and `server.py`
    (removing the now-unneeded exception).
    **Fixed at the source, not by further loosening the server.** Android's polled `handshakeDone`
    Boolean is replaced by a `CompletableDeferred<Unit>` pair — `handshakeReady` and
    `registrationReady` — created FRESH for every websocket generation (every `connect()` loop
    iteration) and captured directly by that attempt's own `WebSocketListener` closures. This is the
    load-bearing property for correctness: a callback firing late, after this generation has already
    been abandoned in favor of a new connection attempt, can only ever complete the pair it was
    closed over at creation time — never a replacement socket's synchronization objects, since a
    fresh pair is always created before any new listener/socket is built. `connect()`'s startup
    sequence is now purely event-driven: `handshakeReady.await()` (completed by the `handshake_ok`
    handler, or by `onFailure`/`onClosed`/a "challenge" parse failure on outright handshake failure)
    → send `register` → `registrationReady.await()` → only then send `register_bundle`,
    `publish_prekey_bundle`, `request_sender_cert`, `subscribe_tokens`, `register_fcm`, and
    `flushQueue()`. `registrationReady` completes successfully on a NEW, explicit server
    acknowledgment, `register_ok` — added to `server.py`'s Phase 2 commit specifically to give the
    client one authoritative signal, since previously there was no wire message at all marking
    registration success; the client could only infer it from the absence of an error. It completes
    EXCEPTIONALLY (so the client's wait ends immediately rather than idling out the full timeout) on
    any of the definitive registration-failure responses — `totp_required`, `access_code_required`,
    `registration_full`, `device_auth_failed`, `identity_revoked`, and the two the Android client had
    never previously handled at all, `device_limit_reached` (S6-37) and `second_factor_rate_limited`
    (S6-18) — as well as on `session_conflict` or outright socket teardown. `pow_required`
    deliberately does NOT complete it: that response triggers an automatic same-socket retry of
    `register` with a solved proof-of-work nonce, not a terminal outcome for this generation: the
    same `await` simply keeps waiting for whatever the retried attempt eventually returns.
    `register_bundle` itself moved out of the racy `handshake_ok` handler entirely, into `connect()`'s
    own sequential flow immediately after the new gate — no polling, no arbitrary sleep, no retry
    loop anywhere in the new mechanism.
    **Desktop was inspected and needed no change.** `WebSocketClient.kt`'s `register`,
    `publish_prekey_bundle`, `subscribe_tokens`, and `request_sender_cert` sends all happen
    synchronously, in program order, within the single `handshake_ok` handler — no second coroutine
    ever competes to send any of them. Combined with this server processing one connection's
    incoming frames strictly in the order received (the `async for` loop `await`s each message's
    full handler, including `register()`'s complete Phase 1/Phase 2, before ever reading the next
    frame), Desktop's ordering was already correct by construction — TCP preserves send order on one
    connection, and the server never starts processing frame N+1 until frame N's handler has fully
    returned — not merely correct by lucky timing that a future change could quietly break.
    **Server cleanup**: with Android's ordering now deterministic, the temporary exception is
    removed. `handle_client()`'s hard boundary is back to its original, unconditional form — `if not
    is_anon_channel and msg_type != "register":` — with no `register_bundle` special case, and the
    `register_bundle` handler's `if not username: continue` guard (which existed only because the
    exception could let it through pre-registration) is deleted along with it. `register_bundle` is
    reachable only from an already-committed registered connection again, exactly like every other
    message type; its own rate limits, size validation, and the canonical `store_prekey_bundle()`
    path are all unchanged.
    Regression-tested: `Server/tests/test_security_invariants.py`'s deterministic-registration-
    ordering section (`register_bundle` sent before any `register` attempt is rejected and the
    connection closed exactly like any other ordinary pre-registration message, with no special
    case; a failed register followed by `register_bundle` never reaches `store_prekey_bundle()`; a
    successful register followed by `register_bundle` still works end-to-end, storing the bundle
    correctly; and a successful registration is proven to actually receive the new `register_ok`
    acknowledgment) — plus every existing S6-39 test and every prekey-publication/rate-limit test
    re-run unmodified, confirming the tightened boundary and the `register_ok` addition introduced no
    regression. Fixed 2026-09-05, see `KNOWN_SECURITY_ISSUES.md` S6-40.

54. **Server access codes are high-entropy one-time bearer credentials. Only their cryptographic
    hashes are stored, malformed credentials are rejected before SQLite, and a denied access-code
    admission terminates that handshake so one PoW solution cannot be amortized across credential
    guesses.**
    Why: `SERVER_ACCESS_PROTECTED` codes were `secrets.token_hex(4).upper()` — only 32 bits, cheaply
    guessable online since no dedicated attempt limiter existed for this specific credential at all.
    Worse, a wrong guess left `register()`'s handling as a bare `continue`, not a connection close —
    and the websocket handshake's `challenge` never changes across multiple `register()` attempts on
    the SAME connection, so a single solved proof-of-work nonce could be reused for unlimited further
    access-code guesses at zero additional PoW cost, with every guess still reaching a real `BEGIN
    IMMEDIATE` SQLite transaction. Unused codes were also stored in `server_access_codes` as
    plaintext, so a stolen offline copy of the database handed out immediately-usable server
    invitations with no further work at all.
    Where: `server.py` (the fix), `Server/admin_gen_codes.py` (the standalone admin generator, kept
    in sync), Android/Desktop (inspected, confirmed to need no change).
    **Entropy**: `ACCESS_CODE_RANDOM_BYTES` (16) / `ACCESS_CODE_HEX_LEN` (32) — a code is now
    `secrets.token_hex(16).upper()`, 128 bits of randomness encoded as exactly 32 uppercase hex
    characters, the same `secrets.token_hex(N).upper()` shape and dedicated-validator pattern used
    elsewhere in this file (`is_valid_fingerprint()`, `is_valid_device_id()`). `is_valid_access_code
    (value)` checks this exact shape. Neither Android nor Desktop assume any fixed access-code
    length anywhere — the QR-payload parser and the manual "add server" entry field on both clients
    carry through an arbitrary-length string unchanged (checked against both client trees) — so this
    is a pure server/generator-side change with no client update required.
    **Storage**: `ACCESS_CODE_HASH_PREFIX` (`"sha256:"`) + `_hash_access_code(raw)`. `_db_gen_access_
    codes_sync()` generates fresh raw codes, durably stores only `_hash_access_code(raw)` for each
    (the `code TEXT PRIMARY KEY` column's shape is unchanged — no migration risk — it just now holds
    a prefixed hash instead of plaintext), and returns the raw values to the caller so they can be
    printed/QR-encoded; the raw values are never themselves written to SQLite or logged anywhere.
    Unsalted SHA-256 is appropriate here for the same reason it already is for
    `totp_recovery_codes`/anon-token hashes elsewhere in this file: these are server-generated,
    uniformly random 128-bit values, not low-entropy user secrets a rainbow table could meaningfully
    target. `_db_admit_new_fingerprint_sync()` receives the canonical RAW code from its caller (which
    already validated its shape — see below) and hashes it exactly once, inside the SAME `BEGIN
    IMMEDIATE` transaction as the cap-check and the fingerprint `INSERT`, comparing against the
    stored hash via the same `UPDATE ... WHERE code = ? AND used = 0` first-write-wins pattern as
    before — the atomicity guarantee (a second concurrent racer for the same code blocks until the
    first's transaction fully commits or rolls back) is completely unchanged.
    **Fail-closed on legacy low-entropy codes**: `_db_has_legacy_unused_access_codes_sync()` returns
    true if any row with `used = 0` is not the current `sha256:<64 hex>` shape. `start_server()` now
    refuses to start at all with `SERVER_ACCESS_PROTECTED` enabled while any such row exists —
    hashing an already-generated 32-bit-entropy code retroactively would not make it safe, only turn
    online guessing into offline hashing of at most 2^32 values, so silently accepting old unused
    codes would defeat the entire point of this fix. USED legacy rows are deliberately exempt from
    this check: a spent code can never grant access again regardless of its original format, so it's
    harmless historical/audit state, not a live credential. `Server/admin_gen_codes.py` — intentionally
    standalone, no `import server` — duplicates the same canonical constants/hash logic (kept
    explicitly in sync by comment) and gained a `--purge-legacy` flag that deletes unused non-v2 rows
    before generating fresh 128-bit ones.
    **One denied guess per handshake**: `register()`'s `access_denied` branch now sends
    `access_code_required` and closes the connection outright (`await websocket.close(); return`, not
    `continue`) — a new guess therefore requires a brand-new connection, which means a fresh random
    `challenge` and a freshly-solved PoW nonce, closing the PoW-amortization/cheap-SQLite-hammering
    angle independent of the credential's own entropy. Every other registration outcome (successful
    admission, `registration_full`, revoked identity, TOTP/device gates) is completely unchanged.
    **Bounded input before SQLite**: `is_valid_access_code()` is checked BEFORE
    `db_admit_new_fingerprint()` is ever invoked for a new fingerprint under `SERVER_ACCESS_
    PROTECTED` — missing, wrong-type, wrong-length, or non-hex input never opens the `BEGIN IMMEDIATE`
    admission transaction at all, and gets the EXACT SAME generic `access_code_required` response and
    connection close as a well-formed-but-wrong code; a caller can never distinguish malformed from
    wrong from nonexistent from this response alone.
    **Process-wide pre-SQLite attempt budget**: `ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT`/`ACCESS_CODE_
    GLOBAL_WINDOW_SEC` (default 60 per 60s) and `access_code_global_rate_ok()` — checked only for
    syntactically-valid guesses (so malformed junk can't burn it for free), after the shape check and
    before `db_admit_new_fingerprint()`, with no `await` in the check-and-increment (atomic on this
    single event loop, same as every other RAM-only aggregate budget in this file). This is
    explicitly NOT the credential's security boundary — even at this budget's ceiling, guessing a
    128-bit code online remains computationally hopeless; its only job is bounding the resource cost
    of a flood of syntactically-plausible attempts before they ever reach SQLite, the same role
    `global_prekey_publish_rate_ok()`/`OFFLINE_STORE_GLOBAL_LIMIT` play for their own respective
    write paths. **Explicitly process-local**: a multi-worker deployment gets one independent budget
    per process, not one shared budget deployment-wide — but the credential itself remains secure
    regardless of process topology, since it is 128-bit and atomically consumed via `BEGIN IMMEDIATE`
    in SQLite (first-write-wins holds across any number of workers sharing one DB file); a
    multi-process deployment would only need a shared/gateway attempt limiter for aggregate resource
    protection at that point, never for credential security.
    Regression-tested: `Server/tests/test_security_invariants.py`'s hardened-access-code section (a
    generated code is proven to be exactly 32 uppercase hex characters/128 bits with no accidental
    duplicates in a batch; the raw code is proven to never appear anywhere in SQLite, only its hash;
    a correct code is accepted exactly once and rejected on any reuse, including under concurrent
    racing for the same code — updated, not new, since this atomicity property already had a
    dedicated test); malformed, missing, and oversized access-code values are each proven to never
    reach `db_admit_new_fingerprint()` at all; a well-formed-but-wrong code closes the connection
    outright, and that same socket is proven unable to make a second guess; a fresh connection is
    proven to receive a genuinely different handshake challenge; the global attempt budget is proven
    to reject purely in RAM before ever reaching the DB; the legacy-code startup check is proven to
    flag an unused old-format row and to NOT flag (or block on) a used one, and a used legacy row is
    further proven unable to grant access if replayed; the updated admin generator is proven, via an
    actual subprocess invocation, to store only the hash while still displaying the raw code; a
    successful protected registration is proven to durably consume the code and register the
    fingerprint together; a failed/full registration is proven to never touch a valid code; and
    `SERVER_ACCESS_PROTECTED=false` behavior is proven unchanged — plus every existing S6-39/S6-40
    test re-run unmodified (one, the access-code-denial ordinary-message test, updated to match the
    new outright-close behavior instead of the old continue-then-boundary-closes behavior). Fixed
    2026-09-05, see `KNOWN_SECURITY_ISSUES.md` S6-41.

55. **Every durable offline-message recipient is a canonical account fingerprint, and every
    separately stored message identifier is protocol-bounded before executor/SQLite work. The
    offline queue's unaccounted per-row metadata is therefore strictly bounded and cannot be used
    to bypass its byte cap.**
    Why: `pending_messages_meta.total_bytes` (S6-31's durable byte cap) only ever accounted for
    `len(payload_json.encode("utf-8"))` — but `recipient` and `msg_id` are each their own
    separately-stored SQLite TEXT column, and neither had any shape/length bound of its own at
    `db_store()`'s boundary. Nearly every relay handler (`message`, `session_init`, `edit`,
    `reaction`, `voice` — which has no message-type rate limit of its own — `group_*`,
    `missed_call`, ...) did `to = message.get("to")` then `db_store(to, ...)` with no canonical-
    shape check on `to` at all. A websocket frame can be almost `MAX_PACKET_SIZE_BYTES` (6 MiB), so
    an attacker could make `to` several MiB long while keeping the actual JSON payload tiny — the
    giant `recipient` was written to SQLite but contributed ZERO bytes to the tracked
    `total_bytes`, an orders-of-magnitude bypass of the advertised durable byte cap. Such
    junk-recipient rows also could never legitimately flush (`db_flush()` looks up by exact
    recipient, and no genuine fingerprint will ever equal attacker-chosen garbage), so they'd sit
    until `MSG_TTL_SEC` expiry.
    Where: `server.py`'s `db_store()`/`_db_store_sync()` and every handler whose `to` means a real
    account.
    **Recipient validation at the `db_store()` boundary**: every legitimate recipient in this table
    is an `is_valid_fingerprint()` shape — exactly 16 uppercase hex characters, always (register()
    derives it that way, same canonical shape already relied on by prekey/device-auth/access-code
    validation elsewhere in this file). `db_store()` now checks `is_valid_fingerprint(recipient)`
    FIRST — before `global_offline_store_rate_ok()`, `json.dumps()`, or the executor hop — returning
    `"INVALID_RECIPIENT"` immediately, so a malformed recipient consumes neither the aggregate
    write-attempt budget nor any executor/SQLite work. `_db_store_sync()` re-checks the identical
    condition as defense-in-depth, before `BEGIN IMMEDIATE`, in case a future internal caller ever
    bypasses `db_store()`. Neither function normalizes (lowercase, strip, truncate) — same
    philosophy as `is_valid_fingerprint()`'s own comment: coercing a near-miss into a valid-looking
    key would just move the validation gap somewhere subtler.
    **msg_id bounded too**: `OFFLINE_MSG_ID_MAX_LEN` (128) + `is_valid_offline_msg_id()` — msg_id is
    another separately-stored TEXT column not represented by `payload_bytes` at all, so leaving it
    unbounded would simply reopen the same class of gap one column over. When not `None`, msg_id
    must be a string of length 1–128; a list/dict (which would raise `TypeError` at SQLite parameter
    binding) or an oversized string is rejected as `"INVALID_MSG_ID"` before either function's
    executor/SQLite work. 128 is not an arbitrary guess: every msg_id either client has ever sent is
    `UUID.randomUUID().toString()` (grepped both Android's and Desktop's message-send paths) — always
    exactly 36 characters — so this is a generous compatibility margin. `msg_id=None` remains fully
    supported: most `db_store()` callers (delivered/edit/reaction/voice/group_reaction/group_create/
    group_member_removed/group_key_rotation/group_invite_accepted/missed_call/message_delete/
    disappear_timer/group_message_delete) legitimately never pass one at all.
    **Handler-layer validation, ahead of the backstop**: every handler where `to` means an ACCOUNT
    fingerprint — `read`, `delivered`, `typing`, `session_reset`, `edit`, `session_init`, `message`,
    `reaction`, `group_reaction`, `voice`, `group_create`, `group_message`, `group_member_removed`,
    `group_key_rotation`, `group_invite_accepted`, every `CALL_RELAY_TYPES` entry, and
    `message_delete`/`disappear_timer`/`group_message_delete` — now validates
    `is_valid_fingerprint(to)` BEFORE `clients.get()`, `forward_to_peers()`, `db_store()`, or
    `send_fcm_wakeup()` are ever reached. Fire-and-forget relay types simply drop a malformed `to`
    silently, same treatment as any other malformed protocol input in this file (e.g.
    `get_prekey_bundle`'s own `target` check); `message`/`session_init` — which already have an
    ack/error contract the sender is waiting on — reply with an explicit
    `{"type": "error", "reason": "Invalid recipient"}` instead, so a false "ack" for a message that
    was never actually routable can never happen. Every `group_*` handler validates `to` (the
    per-member account fingerprint a payload is being relayed to for THIS specific member), never
    `group_id`/`channel_id`/token/mailbox tag — those are separate namespaces and deliberately never
    passed through `is_valid_fingerprint()`. `db_store()`'s own `INVALID_RECIPIENT`/`INVALID_MSG_ID`
    checks remain a genuine backstop, not dead code: `message`/`session_init`'s existing critical-ACK
    rule (`delivered = store_status in ("STORED", "DUPLICATE")`, S6-31) already treats any status
    other than those two as failure, so it required no change to correctly treat the two new
    statuses as failures too. The incoming `federated_forward` path already validated
    `is_valid_fingerprint(to)` before ever reaching `db_store()` (S6-38) — confirmed by inspection,
    not re-fixed, since it was already safe.
    **S6-31 capacity semantics, still coherent**: `PENDING_MESSAGES_MAX_TOTAL_BYTES` continues to
    bound serialized payload bytes only; `PENDING_MESSAGES_MAX_TOTAL_ROWS`, together with the now-
    canonical 16-byte `recipient` and the now-bounded `msg_id`, bound the remaining per-row metadata
    that `payload_bytes` never tracked. No new exact-row-byte-accounting migration was added for
    this — once every non-payload TEXT column is itself strictly bounded, one would add complexity
    without materially changing the server's actual worst-case disk growth.
    Regression-tested: `Server/tests/test_security_invariants.py`'s recipient/msg_id-bounding
    section proves a ~6 MiB recipient is rejected before the global offline-store limiter is ever
    touched; an oversized recipient never reaches the executor/SQLite at all; lowercase/non-hex/
    15-char/17-char recipient shapes are all rejected while the canonical 16-uppercase-hex shape
    still stores normally; `_db_store_sync()`'s own defense-in-depth rejects a bad recipient before
    `BEGIN IMMEDIATE`; a list/dict or oversized msg_id is rejected before SQLite parameter binding
    while `msg_id=None` remains fully supported; an invalid recipient or msg_id never increments
    `pending_messages_meta`; `message`/`session_init` with an invalid `to` receive an explicit error
    and no ack; `voice` (the motivating no-rate-limit example) and every other direct-user relay
    type with a giant/invalid `to` can never create a durable row; an invalid local `to` never
    reaches `forward_to_peers()` or `send_fcm_wakeup()`; canonical direct (online) delivery and
    canonical offline store-then-flush both remain fully functional; and a flood of tiny-payload
    requests carrying a maximally-invalid recipient is proven, concurrently, to leave
    `pending_messages` completely unchanged — plus every existing S6-31 pending-queue test (updated
    to use `canonical_fingerprint()` recipients, since the plain descriptive strings they used
    before this fix are no longer accepted) and every existing S6-38 federation-destination test,
    re-run unmodified. Fixed 2026-09-05, see `KNOWN_SECURITY_ISSUES.md` S6-42.

56. **TOTP at-rest encryption has three explicit configuration states: unconfigured permits legacy
    plaintext mode, valid configuration enables Fernet storage, and invalid explicit configuration
    refuses startup. Explicit encryption intent never silently falls back to plaintext.**
    Why: the module-level `TOTP_SECRET_ENCRYPTION_KEY` init used to construct `Fernet` inside a
    bare `try`/`except`, and on failure just printed a warning and continued with
    `_totp_fernet = None` — silently downgrading to plaintext-at-rest despite the operator having
    explicitly opted into encryption. `_db_load_totp_sync()`'s own fail-closed check (raises when a
    stored `fernet1:`-prefixed row can't be decrypted — see its own comment) does NOT catch this on
    a fresh DB, a DB with no TOTP accounts enrolled yet, or a DB containing only legacy plaintext
    rows: none of those have an encrypted row to trip that check. `totp_setup` on any of those
    would then durably write brand-new secrets as plaintext, and the operator would have no
    indication anything was wrong — the server started normally, logged nothing alarming, and just
    quietly ignored the configured key.
    Where: `server.py`'s module-level `TOTP_SECRET_ENCRYPTION_KEY`/`_totp_fernet` initialization
    block, right before `_totp_encrypt_for_storage()`/`_totp_decrypt_from_storage()`.
    A NONEMPTY `TOTP_SECRET_ENCRYPTION_KEY` is now a hard requirement to actually construct a
    working `Fernet` instance — covering both an invalid key value and the `cryptography` package
    being unavailable at all (the `from cryptography.fernet import Fernet` is a local import inside
    this `if` block, not a top-of-file one, specifically so an UNSET key still works without that
    dependency installed at all). Either failure now prints a `[FATAL]` message and calls
    `sys.exit(1)` — aborting the entire process at module import time, before `_db_setup_sync()`,
    `_db_load_totp_sync()`, or any other DB work has even begun. An ABSENT or empty (including
    whitespace-only, since the value is `.strip()`ped first) key is completely unaffected by this
    fix: `_totp_fernet` stays `None`, legacy plaintext-at-rest mode continues exactly as before —
    this is deliberate, permanent backward compatibility for deployments that never opted into
    encryption at all, not a gap. No key is silently generated, repaired, or normalized to "fix" an
    invalid supplied value, and plaintext is never used as a silent fallback for a broken explicit
    configuration — the only three outcomes are: not configured → plaintext allowed; configured and
    valid → Fernet mode; configured and invalid → refuse to start.
    Regression-tested: `Server/tests/test_security_invariants.py`'s TOTP-at-rest-encryption-
    configuration section (each test spawns a real subprocess with `TOTP_SECRET_ENCRYPTION_KEY` set
    exactly as needed, since this is module-level initialization code the already-imported test
    session can't re-trigger by mutating `os.environ`) proves: an absent key and a whitespace-only
    key both keep `_totp_fernet is None`; a valid key initializes `_totp_fernet`; an invalid nonempty
    key aborts at `import server` with `[FATAL]` and a nonzero exit code; a configured key with the
    `cryptography` import itself blocked (simulating the dependency being unavailable) aborts the
    same way; a fresh DB and a DB containing only legacy plaintext TOTP rows both still abort given
    an invalid key (proving the crash happens at import, before DB state could ever matter — this is
    exactly the scenario the old code let through); a DB with a genuinely encrypted row and a
    syntactically-valid-but-WRONG key still fails closed via the pre-existing, unmodified
    `_db_load_totp_sync()` path; a valid key durably stores a newly-enrolled secret with the
    `fernet1:` prefix and decrypts back correctly; an unset key stores a newly-enrolled secret as
    plaintext exactly as legacy behavior always has — plus the full existing TOTP/device-gating test
    suite re-run unmodified. Fixed 2026-09-05, see `KNOWN_SECURITY_ISSUES.md` S6-43.

57. **Anonymous-token state creation is independently bounded per account, per issuance window,
    and process-wide, with a hard durable row ceiling. Existing token capabilities continue to
    resolve and terminalize even when creation capacity is exhausted, and the live routing set per
    account is bounded.**
    Why: `subscribe_tokens` was purely additive with no cap at all on how many DISTINCT never-
    before-seen tokens one authenticated account could turn into permanent `anon_token_state` rows.
    The per-message call-count limit alone was never a meaningful bound on this (and, as of
    2026-09-20, isn't even charged for a purely idempotent resubscribe) — the real ceiling on new-row
    creation is the four independent, content-aware limits enforced atomically inside
    `_db_claim_anon_tokens_sync()`/`db_claim_anon_tokens()`: `MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT`,
    `ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW` (durable, per-account, time-windowed), the process-wide
    `ANON_TOKEN_GLOBAL_CLAIM_LIMIT`, and the table-wide `ANON_TOKEN_STATE_MAX_TOTAL_ROWS` hard
    backstop. `anon_token_state_cache` mirrors the ENTIRE table in RAM (a deliberate, separate DoS
    defense for the unauthenticated `anon_channel` hot path — see that cache's own comment, untouched
    by this fix), so unbounded durable growth on disk is also unbounded startup/live RAM growth.
    Repeated additive `subscribe_tokens` calls on one live connection also had no cap on how large
    that connection's own `ws_to_tokens` routing set could grow.
    Where: `server.py`'s `_db_claim_anon_tokens_sync()`/`db_claim_anon_tokens()` and the
    `subscribe_tokens` handler.
    **Client pool sizing inspected first**, not guessed: Android's and Desktop's `AnonTokenManager.kt`
    both maintain exactly ONE "my tokens" pool per installation, target size 50 (`POOL_SIZE`), with a
    client-side safety-valve ceiling of 100 (`MAX_POOL_HARD_CAP`) chosen specifically so a full pool
    still fits in one `subscribe_tokens` call (`MAX_TOKENS_PER_SUBSCRIBE`) — both clients' own
    comments cite that exact server constant. Multiple authorized devices per account are a real,
    separately supported flow (`MAX_AUTHORIZED_DEVICES_PER_ACCOUNT`=32, S6-37) sharing one account
    fingerprint, each keeping its own local pool.
    **`MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT`** (default 5000) bounds one account's INSTANTANEOUS
    footprint — the maximum number of non-terminal (ACTIVE/IN_FLIGHT) rows it may own at once,
    generous even for a heavily multi-device account.
    **`_db_claim_anon_tokens_sync()` rewritten**: EXISTING tokens (any row already present, any
    state, any owner) are resolved FIRST, unconditionally, before capacity is even considered — this
    is what keeps every already-issued capability (ownership lookup, reconnect, terminalization,
    unsubscribe, IN_FLIGHT reconciliation) working even when every limit below is simultaneously
    exhausted. Only inserting a genuinely NEW `token_hash` draws against capacity. Three limits are
    checked together, in the SAME `BEGIN IMMEDIATE` transaction as the resolve + INSERTs, so
    count-then-admit can never race a concurrent claim: the owner's own active-row headroom, the
    owner's durable new-claim issuance quota, and the table-wide hard ceiling — `admit_count =
    min(len(new_tokens), active_room, quota_room, total_room)`, so a batch may be admitted PARTIALLY.
    A refused new token's result entry is `(None, "NEW_CLAIM_LIMIT")` — `owner=None` is the signal
    that this token has NO backing row in the DB at all, so `subscribe_tokens` never writes it into
    `anon_token_state_cache` (a strict mirror of the DB's actual contents) and never touches
    `token_to_ws`/`known_tokens`/`token_owner`/`ws_to_tokens` for it.
    **`ANON_TOKEN_NEW_CLAIM_WINDOW_SEC`/`MAX_PER_WINDOW`** (600s/300, new `anon_token_claim_guard`
    table, one row per account that has ever created a new token) closes the gap the active cap
    alone leaves open: claim→unsubscribe(REVOKED)→reclaim cycling frees active capacity every time
    but still mints a fresh permanent tombstone, so the active cap alone cannot bound an account's
    SUSTAINED issuance rate. Re-subscribing an already-existing owned token costs zero quota.
    **`ANON_TOKEN_GLOBAL_CLAIM_LIMIT`/`WINDOW_SEC`** (300/60s, mirrors
    `OFFLINE_STORE_GLOBAL_LIMIT`'s own pattern) is a process-wide pre-SQLite request budget in
    `db_claim_anon_tokens()`, defeating Sybil accounts each individually under their own quota —
    classified against `anon_token_state_cache` first: a request whose tokens are ALL already cached
    never even checks this budget (an ordinary reconnect resubscribing an already-owned pool must
    never be throttled by a budget that exists only to bound genuine new-row creation), and if the
    budget IS exhausted, only the genuinely-potential-new tokens in a mixed batch are refused —
    already-cached tokens in that SAME batch still resolve, from the cache, with zero DB/executor
    work. A cache miss does not guarantee an INSERT will actually happen; the DB-level limits above
    remain the real authority — this is a request/work budget, not exact durable accounting.
    **`ANON_TOKEN_STATE_MAX_TOTAL_ROWS`** (2,000,000) is the final hard backstop on the WHOLE table,
    independent of account count (closing the Sybil-many-under-quota-accounts angle the per-owner
    quota alone can't). Because `anon_token_state_cache` mirrors this entire table, this cap is also
    a real upper bound on startup/live RAM consumed by that cache. A cheap `SELECT COUNT(*)` startup
    sanity check (`start_server()`, after schema setup, before the full-table RAM load) refuses to
    start — never auto-deletes — if the table is already over this configured cap.
    **Live routing-set cap**: independently of all durable state, `subscribe_tokens` now also
    enforces `len(ws_to_tokens[websocket]) <= MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT` under `lock` —
    bounds how large repeated additive calls can grow ONE connection's own live routing set; a token
    already in that connection's set never consumes another slot.
    No backward token-state transition was introduced by this fix, and no automatic expiry of
    ACTIVE/IN_FLIGHT/SPENT/REVOKED was added — see this invariant's own residual-limitation note
    below and `KNOWN_SECURITY_ISSUES.md` S6-44's own copy of it.
    **Explicit residual limitation — SPENT/REVOKED tombstones are intentionally never deleted by
    this fix.** They are what prevents a previously-known raw capability token from being claimed
    again as if brand-new (the DB layer sees a deleted tombstone's token exactly like a genuinely
    fresh one). The hard total-row ceiling therefore guarantees BOUNDED resources, not
    infinite-lifetime garbage collection — a deployment that eventually approaches the configured
    ceiling needs a separately designed, safe tombstone-retention/expiry scheme (a real
    token-expiry/protocol-semantics question, or another durable replay-prevention structure) before
    any row can ever be safely compacted. This invariant does not claim to solve that long-term
    lifecycle question.
    Regression-tested: `Server/tests/test_security_invariants.py`'s anon-token resource-hardening
    section proves the client pool hard cap stays below the active cap; reconnect/resubscribe of
    existing tokens succeeds even exactly at the active cap; a new token below the cap inserts
    normally while the first token above it does not, including under concurrent claims that must
    not atomically exceed the cap combined; the live `ws_to_tokens` set cannot be grown past the cap
    by repeated additive calls, and a rejected token never partially mutates
    `token_to_ws`/`known_tokens`/`token_owner`; an existing SPENT or IN_FLIGHT token still resolves
    while the active cap is completely full; a token owned by another user remains correctly
    attributed; unsubscribe frees active capacity while leaving a durable REVOKED tombstone; new
    issuance after unsubscribe is bounded by the durable claim quota (not the now-empty active cap),
    including across many repeated claim→revoke cycles; the claim-guard quota is proven durable (a
    direct SQLite read, not any RAM structure) and unaffected by re-subscribing existing tokens; the
    global claim-request budget is proven to reject before ever reaching the executor/SQLite, while
    an all-cache-hit reconnect is proven to skip that budget check entirely; the total-row hard cap
    rejects a genuinely new token while still allowing an existing token's reconnect and
    terminalization; startup is proven to refuse over the configured hard row cap and to proceed
    normally exactly at it; a rejected new claim is proven to never appear in
    `anon_token_state_cache`, while a successful one still updates it exactly as before; and a
    dedicated attack-simulation regression proves that repeated new-token-flood-and-revoke cycling
    can never exceed the active cap, the durable issuance quota, or the hard total-row ceiling,
    regardless of how many cycles are attempted — plus the full existing anon_delivery_ack/
    token_pending/bootstrap-token test suite re-run unmodified. Fixed 2026-09-05, see
    `KNOWN_SECURITY_ISSUES.md` S6-44.

58. **Pre-authentication handshake input has a dedicated small frame ceiling and protocol-specific
    cryptographic-field bounds. JSON container shape and base64 syntax are validated before padding
    removal, DER parsing, or signature/HMAC processing; the larger application frame ceiling is
    never inherited by the authentication surface.**
    Why: the handshake reused `MAX_PACKET_SIZE_BYTES` (6 MiB — needed for legitimate post-auth
    media traffic) as its own frame ceiling, then ran attacker-controlled `json.loads()`/
    `base64.b64decode()`/`load_der_public_key()`/signature verification with no handshake-specific
    field bounds at all. An unauthenticated attacker therefore got a multi-megabyte parsing/decode
    surface per connection for fields (`public_key`, `signature`, federation `mac`) whose real
    representation is a few hundred bytes at most. Separately, a syntactically-valid non-dict JSON
    value (`[]`/`"str"`/`123`/`null`) reached `strip_padding()`'s unconditional
    `.pop("_p", None)`, which assumes a dict.
    Where: `server.py`'s `handle_client()` handshake section, the ordinary post-auth message loop
    (defense-in-depth only), `register()`, and the federation `mac` check.
    **`HANDSHAKE_MAX_PACKET_SIZE_BYTES`** (default 8 KiB) is checked against the actual encoded
    UTF-8 byte count (not Python's character-count `len()`, which undercounts for non-ASCII
    content) BEFORE `json.loads()` ever runs. Chosen after inspecting both shipped clients: neither
    Android's nor Desktop's packet-padding helper (`addPadding()`/`_p`) is ever applied to
    `challenge_response`, `anon_channel`, or any other handshake message — only to post-auth
    traffic — so a real handshake frame is on the order of 250-300 bytes; even a hypothetically
    padded one (simulated in tests using the clients' own 512-byte-boundary algorithm) stays far
    under 8 KiB. `MAX_PACKET_SIZE_BYTES` and `websockets.serve(... max_size=MAX_PACKET_SIZE_BYTES)`
    are completely untouched — still the ceiling for every post-handshake application frame
    (image/video/file/voice/message payloads).
    **JSON container shape**: `isinstance(hs_msg, dict)` is required before `strip_padding()` is
    ever called on the handshake message; the identical cheap defense-in-depth check was added to
    the ordinary post-auth message loop too (not the main finding, just consistency — a malformed
    container there was already otherwise harmless, just would have raised).
    **Canonical identity-crypto bounds**: new `decode_identity_public_key()`/
    `decode_identity_signature()` helpers (`MAX_IDENTITY_PUBKEY_B64_LEN`/
    `MAX_IDENTITY_SIGNATURE_B64_LEN`, 512/256 — mirroring S6-37's `MAX_DEVICE_PUBKEY_B64_LEN`/
    `MAX_DEVICE_SIGNATURE_B64_LEN` exactly, since both shipped clients use the IDENTICAL
    secp256r1/`SHA256withECDSA`/X.509-SubjectPublicKeyInfo-DER algorithm for the long-lived identity
    key as for a per-device one) bound length and require strict base64 (`validate=True`) BEFORE
    `base64.b64decode()`/`load_der_public_key()` ever run. After DER parsing, the actual EC
    algorithm is now enforced: `isinstance(public_key, ec.EllipticCurvePublicKey) and
    isinstance(public_key.curve, ec.SECP256R1)` — confirmed P-256 as the sole protocol-wide identity
    curve on both clients (by grep) before adding this restriction, since `load_der_public_key()`
    alone happily parses any EC curve's DER blob, or even a non-EC key type entirely. Fingerprint
    semantics are completely unchanged: still SHA-256 over the exact same canonical DER bytes.
    **One shared helper, not two hardening passes**: the SAME `decode_identity_public_key()` is used
    by both the handshake's `challenge_response` AND `register()` — before this fix, `register()`
    re-decoded `public_key` with a bare, non-strict `base64.b64decode()` and no bounds at all, so an
    already-"authenticated" connection (past the handshake) could still force the same expensive
    base64/DER work merely by sending a giant `register` `public_key`, even though the PROVEN
    handshake key was tiny. The exact S6-39 proof-of-possession property is preserved unchanged:
    `key_bytes == verified_public_key`, no alternate key or canonicalization ever accepted.
    **Federation `mac` bounds**: `MAX_FEDERATION_MAC_B64_LEN` (128) is checked before base64 decode
    (`validate=True`); the DECODED length is then explicitly compared to
    `hashlib.sha256().digest_size` (32) before `hmac.compare_digest()` ever runs —
    `compare_digest()` doesn't require equal-length inputs, so a malformed/wrong-size value needed
    an explicit length check rather than an implicit compare-and-fail. The HMAC construction itself
    is completely unchanged.
    **PoW nonce bound (defense-in-depth, not the core pre-auth finding)**: `MAX_POW_NONCE_LEN` (64)
    reflects Android's actual `counter.toString()` representation (a signed 64-bit counter, at most
    ~20 decimal digits; Desktop doesn't send PoW yet). A non-string or oversized `pow_nonce` is
    simply treated as an empty one — exactly as unable to satisfy the difficulty check as any other
    wrong guess, never hashed as attacker-controlled megabytes.
    Regression-tested: `Server/tests/test_security_invariants.py`'s pre-auth handshake hardening
    section proves the official challenge_response shape (and a hypothetically-padded variant using
    the clients' own padding algorithm) fits comfortably under the handshake ceiling; a near-6-MiB
    handshake is rejected before `json.loads()` is ever called; a JSON list/string/int/null
    handshake is rejected cleanly without disturbing the server's ability to accept further
    connections; an oversized public_key/signature is rejected before `base64.b64decode()` is ever
    reached for that specific value, while a malformed-base64 value of either is rejected too; a
    valid official identity key still verifies end to end; a non-EC (RSA) key and a wrong EC curve
    (secp384r1) are both rejected; an oversized/malformed-base64/wrong-decoded-length federation MAC
    is each rejected at its respective layer, while the correct HMAC still authenticates; `register()`
    rejects an oversized public_key before DER parsing and still rejects a genuine key mismatch,
    in both cases leaving the connection alive for a subsequent legitimate registration; a malformed
    ordinary JSON container never kills the client handler; a substantial post-handshake frame
    remains governed by the normal (not handshake) ceiling end-to-end; and a non-string/oversized
    PoW nonce both fail safely (oversized proven never actually hashed) while the official client's
    own nonce representation still completes registration — plus the full existing S6-39/S6-40
    registration and federation-auth test suites re-run unmodified. Fixed 2026-09-05, see
    `KNOWN_SECURITY_ISSUES.md` S6-45.

59. **A federated prekey response can resolve a pending lookup only when its correlation data
    matches the exact pending target, its size/shape are protocol-bounded, and the identity public
    key carried by the bundle cryptographically derives to that target fingerprint. Invalid peer
    responses are ignored without poisoning the pending lookup.**
    Why: `fed_pending` was `req_id → asyncio.Future` — `federated_get_bundle()` broadcasts the
    identical `{type, target, req_id}` request to every connected peer, so ANY peer receiving it
    necessarily learns a valid `req_id` for that in-flight lookup. `handle_federation_response()`
    resolved the Future on the FIRST `federated_bundle_response` carrying that `req_id` with a
    non-null `bundle`, from any authenticated peer, with no check that the bundle's cryptographic
    identity actually matched the fingerprint originally requested. A malicious or compromised peer
    could therefore win the first-response race with arbitrary bundle content for a target it does
    not own — classic response poisoning, made worse by first-response-wins semantics. The incoming
    serve side had the matching gap in reverse: it attached the LOCALLY-TRUSTED requested `target`
    to whatever bundle it sent back, with no field correlating the response to the specific request
    that produced it.
    Where: `server.py`'s `fed_pending`, `federated_get_bundle()`, `handle_federation_response()`,
    the incoming `federated_get_bundle` message handler, and `federation_connect_to_peer()`.
    `fed_pending` is now `req_id → {"future", "target", "created_at"}` — every response is checked
    against the target THIS specific lookup was created for, per this server's own records, never
    against a target the responding peer supplies. `handle_federation_response(msg, peer_url="")`
    (peer_url threaded through from `federation_connect_to_peer()`'s read loop, for bounded security
    logging only — federation has no cryptographic peer-authority mapping to build a real trust
    input from) requires, in order, before ever resolving the Future: (1) `is_valid_fed_req_id()` —
    canonical 16-lowercase-hex shape (exactly what `secrets.token_hex(8)` always produces) plus a
    live `fed_pending` lookup, so a malformed/random/unknown `req_id` is an O(1) reject that can
    never itself create pending state; (2) a real (non-null) `bundle` — a legitimate "I don't have
    this user" null response from one peer still leaves the Future pending for another to answer,
    unchanged from before this fix; (3) `response["target"] == pending["target"]`, both
    `is_valid_fingerprint`-shaped — correlation/defense-in-depth ONLY, explicitly not treated as
    proof, since any peer that received the original request already knows `target` too and can
    trivially echo it back; (4) `isinstance(bundle, dict)` and its exact UTF-8-encoded serialized
    size within `MAX_BUNDLE_SIZE_BYTES` — checked BEFORE any base64/DER/crypto work, so a malicious
    response can never buy a bigger parsing budget than a genuine local `register_bundle`/
    `publish_prekey_bundle` gets; (5) the actual cryptographic proof —
    `decode_identity_public_key(bundle.get("identity_key"))` (S6-45's canonical decoder), then
    `hashlib.sha256(key_bytes).digest()[:8].hex().upper() == pending["target"]`, the SAME
    fingerprint computation `register()` uses for every real account. A rejection at any step
    leaves the Future genuinely pending — never resolved, never errored, never cancelled — so a
    malicious peer's invalid FIRST response can never suppress a legitimate peer's valid LATER
    response for the same lookup. The incoming-serve handler now also validates
    `is_valid_fed_req_id(req_id)` before ever reflecting it back into a response (previously
    unvalidated), and echoes `"target": target` in its `federated_bundle_response` — again
    correlation only, never authentication. `FED_PENDING_MAX` (default 2000, required strictly
    positive) is a new hard process-wide ceiling on concurrently outstanding lookups, on top of the
    existing per-user `prekey_fetch` rate limit (10/min) and each entry's unchanged ~3s self-expiry.
    Client defense-in-depth (Android's and Desktop's `SessionKeyManager.initiateSession()`,
    byte-identical logic): both now compute the received bundle's own identity-key fingerprint the
    same way and require it to equal the requested contact before trusting the SPK/PQ signatures,
    consuming an OPK, or creating a session — closing the matching client-side gap this same review
    found (neither client previously checked this at all).
    Regression-tested: `Server/tests/test_security_invariants.py`'s federated response-poisoning
    section proves a normal matching-target response resolves; a response missing `target`, with a
    non-canonical or mismatched `target`, with a malformed or oversized `req_id`, with a non-dict or
    oversized `bundle`, or with an identity key that decodes to the wrong fingerprint (or doesn't
    decode at all) is each ignored while leaving the Future pending, not errored; a random unknown
    `req_id` creates no state; a late response after cleanup and a cancelled in-flight lookup both
    leave `fed_pending` correctly empty; a malicious peer's invalid first response is proven unable
    to suppress a legitimate peer's valid later response for the same lookup; the outgoing path is
    proven to create a correctly-shaped target-aware pending entry and to refuse before contacting
    any peer once `FED_PENDING_MAX` is reached; and the incoming handler is proven to echo `target`
    and to reject a malformed `req_id` before ever calling `consume_prekey_bundle_for_serve()` — plus
    the full existing S6-35/S6-36/S6-38 federation-bundle test suites re-run unmodified. Fixed
    2026-09-05, see `KNOWN_SECURITY_ISSUES.md` S6-46.

60. **Persistent channel content is protocol-bounded before storage and subject to independent
    per-account, process-wide, per-row, and durable aggregate capacity limits. A channel post
    becomes visible in RAM or to subscribers only after its durable admission succeeds, and
    duplicate identifiers cannot create or broadcast conflicting content.**
    Why: `channel_post` had no `rate_limit_check()` call at all, `image_data` was bounded at
    `len(image_data) > 5 * 1024 * 1024` (base64 CHARACTERS, not decoded bytes, and never rejecting
    a non-str value), `text`/`channel_description`/`channel_avatar` had no bound at all, and every
    accepted post was persisted forever via a bare `INSERT OR IGNORE` — the RAM-only
    `if len(ch["posts"]) > 200: ...` bounded the in-memory list but did nothing to the underlying
    `channel_posts` SQLite rows, so disk usage grew without bound regardless of how little history
    the application ever actually surfaced. `channel_create` had only a rate (5/min), never a
    lifetime cap, on a table with no deletion feature, so one account could durably create channels
    forever. Note: the Channels feature is currently dormant in production — `channel_create`/
    `channel_post`/etc. were already removed from `ALLOWED_TYPES` by an earlier fix (external review
    2026-08-28, SCOPE-01) — but the handler code and DB tables were deliberately left in place
    rather than deleted, so this invariant applies to that code regardless of current reachability:
    unreachable today is not the same guarantee as deleted.
    Where: `server.py`'s `channel_create`/`channel_post`/`channel_subscribe`/`channel_unsubscribe`
    handlers, `_db_store_channel_post_sync()`, `_db_create_channel_sync()`, `channel_posts_meta`.
    Field bounds derived from actual client behavior: `CHANNEL_ID_MAX_LEN`/`CHANNEL_POST_ID_MAX_LEN`
    cover both server-generated `secrets.token_urlsafe(16)` values and client
    `UUID.randomUUID().toString()` ids (same precedent as S6-42's `OFFLINE_MSG_ID_MAX_LEN`);
    `CHANNEL_NAME_MAX_CHARS` formalizes the pre-existing 100-char check; `CHANNEL_DESCRIPTION_MAX_CHARS`/
    `CHANNEL_AVATAR_MAX_CHARS` are newly bounded; `CHANNEL_POST_TEXT_MAX_CHARS` reflects that channel
    text is plaintext the server actually reads/re-broadcasts, unlike E2E-encrypted ordinary
    messages. `image_data` (confirmed base64 — Android's `Base64.encodeToString(..., NO_WRAP)`,
    Desktop never sends this field) is bounded BEFORE decode (`CHANNEL_POST_IMAGE_B64_MAX_LEN`),
    strictly base64-validated, then bounded again on the DECODED byte length
    (`CHANNEL_POST_IMAGE_MAX_BYTES`) — the real image-size ceiling. `CHANNEL_POST_RATE_LIMIT` (10/min,
    per-user) plus `CHANNEL_POST_GLOBAL_LIMIT`/`WINDOW_SEC` (process-local pre-executor budget,
    mirroring `global_prekey_publish_rate_ok()`/`global_offline_store_rate_ok()` exactly) bound write
    attempts; `channel_posts.storage_bytes` (exact UTF-8 bytes of every attacker-controlled variable
    field in the row) plus a `channel_posts_meta` running-totals singleton — migrated/backfilled and
    reconciled once at startup, same `pending_messages_meta` pattern (S6-31) — let
    `_db_store_channel_post_sync()` enforce `CHANNEL_POST_MAX_BYTES` (one post)/
    `CHANNEL_POSTS_MAX_TOTAL_BYTES`/`CHANNEL_POSTS_MAX_TOTAL_ROWS` (process-wide) from a cheap running
    total rather than a `COUNT(*)`/`SUM()` on every write. That same ONE `BEGIN IMMEDIATE`
    transaction also covers the duplicate/conflict check (`post_id` is UNIQUE globally, not
    per-channel — a reused id is `"DUPLICATE"` only if `channel_id`/`text`/`author_id`/
    `author_name`/`image_data` all match the existing row exactly, otherwise `"CONFLICT"`, never
    silently treated as success) and an atomic per-channel retention prune
    (`CHANNEL_POSTS_MAX_PER_CHANNEL`=200 — the server already only loads/RAM-keeps the most recent
    200 posts per channel and no current client has any older-history pagination API, confirmed by
    grep, so rows beyond that are already unobservable; existing DBs are retroactively pruned once
    at startup too). Handler ordering: `channel_post` now snapshots channel/admin state and
    subscribers under the short global `lock`, then calls the durable store WITHOUT holding that
    lock across the `await` (invariant #34), and only appends to RAM / broadcasts to subscribers
    when the store result is `"STORED"` — a `"DUPLICATE"`, `"CONFLICT"`, `"FULL"`, `"TOO_LARGE"`, or
    rate-limited result never mutates RAM and never broadcasts, closing a prior ordering bug where
    `ch["posts"].append()` ran BEFORE the durable write, so RAM/broadcast could reflect a post whose
    insert had actually failed or been rejected. `channel_create` mirrors this: `_db_create_channel_sync()`
    enforces `MAX_CHANNELS_PER_OWNER`/`CHANNELS_MAX_TOTAL_ROWS` atomically inside the SAME transaction
    as the INSERT (same race S6-37's `db_bind_device_pubkey()` closed for `authorized_devices`), and
    RAM (`channels[channel_id]`) is only populated after the row durably exists.
    Regression-tested: `Server/tests/test_security_invariants.py`'s channel-persistence-hardening
    section (29 tests) proves the dedicated per-user and process-wide rate limits both reject before
    reaching SQLite; a wrong-type/oversized image, oversized text/description/avatar/post_id/channel_id
    are each rejected before any DB work while a valid normal post/channel still works end to end; a
    post above the single-post byte ceiling, the total-row cap, and the total-byte cap are each
    proven to leave `channel_posts_meta` and the durable table completely unchanged; a successful
    insert increments both counters exactly; a duplicate identical post neither increments counters
    nor is appended/broadcast a second time, while a conflicting reused `post_id` is rejected; a DB
    failure and a `FULL` result both produce no RAM post and no subscriber broadcast; restart
    reconciliation repairs deliberately-corrupted meta counters; the storage_bytes migration
    correctly backfills a pre-S6-47-shaped legacy row; concurrent writers at the final row slot are
    proven unable to jointly exceed the cap; a 201st post to one channel is proven to leave exactly
    200 durable rows with meta matching; normal channel creation still works while oversized metadata
    creates no RAM/DB channel; the per-owner and process-wide channel-count caps are both proven
    unraceable under concurrency; and a dedicated attack-simulation regression (500 max-size post
    attempts against a small configured cap) proves durable bytes/rows never exceed the configured
    hard ceiling regardless of how many attempts are made — this is the first automated test
    coverage the Channels feature has ever had. Fixed 2026-09-05, see `KNOWN_SECURITY_ISSUES.md`
    S6-47.

61. **TOTP secrets and proof credentials are protocol-bounded before decoding, hashing,
    comparison, or persistence. First-time enrollment has independent per-account and aggregate
    work limits, and persisted TOTP secrets are validated fail-closed before entering the live
    verifier cache.**
    Why: `totp_setup` accepted client-controlled `secret`/`new_code`/`current_code`/
    `recovery_code` with no protocol-specific bounds. `SECOND_FACTOR_GUARD_*` only protects proof
    of an EXISTING factor — before TOTP is enabled for an account, `totp_setup` never reaches
    `db_take_second_factor_attempt()` at all, so an authenticated account with no TOTP configured
    could repeatedly send large `secret` values, each reaching `totp_code_matches(secret, new_code)`
    → `_totp_code_at_counter()` → `secret.strip().upper()` → padding/copies → `base64.b32decode()`,
    up to the ordinary multi-megabyte websocket frame ceiling, with no dedicated rate limit. Worse,
    if an attacker's huge secret ever validated against a supplied code, the server durably
    persisted it, and `_db_load_totp_sync()` loads every stored secret fully into
    `user_totp_secrets` on every future startup — one oversized frame became permanent SQLite
    growth plus startup/live-RAM retention.
    Where: `server.py`'s `decode_totp_secret()`, `is_valid_totp_code()`, `is_valid_recovery_code()`,
    `totp_code_matches()`, `totp_setup`/`totp_disable` handlers, `register()`'s device-gating TOTP
    path, `_db_commit_totp_setup_sync()`, `_db_load_totp_sync()`.
    Client secret format confirmed by inspection, not guessed: both Android's and Desktop's
    `TotpManager.generateSecret()` produce `ByteArray(20)` + `SecureRandom`, Base32-encoded with a
    hand-rolled uppercase-only encoder that never emits padding — byte-identical on both platforms,
    unchanged in git history since TOTP was introduced, with no "import an external secret" path on
    either client. **`decode_totp_secret(value)`** requires this ONE canonical format exactly, not a
    compatibility range: cheap type/length/alphabet checks (`TOTP_SECRET_B32_MAX_LEN`=40
    pre-normalization gate) BEFORE `base64.b32decode()` ever runs, `TOTP_SECRET_B32_LEN`=32 required
    after the SAME `strip().upper()` normalization `_totp_code_at_counter()` already applied (no new
    leniency), then the DECODED byte length required to be exactly `TOTP_SECRET_DECODED_BYTES`=20;
    returns the normalized secret on success, `None` on any failure. **`is_valid_totp_code(value)`**
    requires exactly 6 ASCII decimal digits after the same pre-existing `strip()`.
    **`is_valid_recovery_code(value)`** requires the canonical `XXXXX-XXXXX-XXXXX-XXXXX` shape (20
    hex characters + dashes) after the same `strip().upper()` `_hash_recovery_code()` already
    applies. **`totp_code_matches()` validates BOTH arguments** via the two functions above before
    any Base32/HMAC work runs — the single chokepoint every proof path (`register()`'s
    device-gating code, `totp_setup`'s `new_code`/`current_code`, `totp_disable`'s `code`) already
    routes through, closing the gap everywhere at once; `is_valid_recovery_code()` is additionally
    checked at each of the three `recovery_code` call sites directly, since
    `db_check_and_consume_recovery_code()` has no internal guard of its own. **Independent
    enrollment-work limits**: `TOTP_SETUP_RATE_LIMIT`=5/min (new `rate_limit_check()` bucket) applies
    at the TOP of `totp_setup` regardless of whether TOTP is already enabled — the actual
    first-enrollment gap, independent of and not a replacement for `SECOND_FACTOR_GUARD_*` (which
    remains the durable brute-force boundary for an already-enrolled account's re-enrollment
    proof); `TOTP_SETUP_GLOBAL_LIMIT`/`WINDOW_SEC` (60/60s, process-local RAM-only, mirroring
    `global_prekey_publish_rate_ok()`) bounds aggregate Sybil-account setup-work, checked AFTER
    cheap shape validation but BEFORE `totp_code_matches()`, so malformed/oversized input never
    consumes it. **Persistence defense-in-depth**: `_db_commit_totp_setup_sync()` independently
    refuses (raises) a non-`decode_totp_secret()`-shaped secret BEFORE
    `_totp_encrypt_for_storage()`/`BEGIN IMMEDIATE`/INSERT. **Startup fail-closed**:
    `_db_load_totp_sync()` validates each decrypted secret with `decode_totp_secret()` before ever
    populating `user_totp_secrets` — a malformed/oversized stored secret refuses the ENTIRE
    startup, same posture as the adjacent S6-43 decrypt-failure check, never silently skipped/
    treated-as-disabled/truncated. Migration-safety confirmed before enabling this: git history of
    both clients' `TotpManager.kt` shows `ByteArray(20)` unchanged since TOTP was introduced, and no
    server-side tool generates a secret in any other shape.
    Regression-tested: `Server/tests/test_security_invariants.py`'s TOTP-input-hardening section
    proves official Android/Desktop-shaped secrets (and this suite's own canonical fixtures) pass; a
    multi-megabyte or wrong-type secret is rejected before `base64.b32decode()` is ever called; an
    invalid-alphabet canonical-length secret is rejected cleanly; a maximum-length genuine secret
    still verifies; a huge `new_code` is rejected before `totp_code_matches()`; non-6-digit codes are
    rejected while a canonical one still works; a huge `recovery_code` is proven to never reach
    `db_check_and_consume_recovery_code()` at all; a malformed recovery-code shape is rejected while
    an officially-generated one still works; a TOTP-disabled account is still subject to the
    per-user setup rate limit; Sybil accounts are proven unable to exceed the shared global
    setup-work budget; malformed giant input is proven to never consume that budget; a valid
    first-time setup still commits correctly; `_db_commit_totp_setup_sync()` is proven to reject an
    oversized secret directly, both before it ever reaches SQLite and before it ever enters
    `user_totp_secrets`; startup is proven to refuse a malformed/oversized stored secret and to
    accept every legitimate historical shape; plus a dedicated attack-simulation regression (a flood
    of near-frame-limit secrets from one account) proves none reaches `base64.b32decode()`, none
    reaches SQLite, retained RAM never grows, and the rate/global guards bound accepted work — plus
    the full existing TOTP replay, durable second-factor, S6-33 re-enrollment, and S6-43
    encryption/fail-closed test suites re-run unmodified. Fixed 2026-09-05, see
    `KNOWN_SECURITY_ISSUES.md` S6-48.

62. **Direct attachment chunks are protocol-bounded before relay and are subject to bounded
    sender, aggregate, and recipient transfer budgets. Chunk ACKs prove successful relay only;
    malformed or over-budget chunks cannot create unbounded server or recipient assembly state.**
    Why: `image_chunk`/`video_chunk`/`file_chunk` relayed `message.get("data")` verbatim to
    `clients.get(to)` with no `is_valid_fingerprint(to)` check (these never queue offline, so S6-42
    never reached them), no protocol-specific bounds on `chunk_index`/`total_chunks`/`data`/
    `signature`/`file_name`, and no chunk-specific rate/byte limit — an authenticated client could
    use the chunk protocol as an unrestricted high-bandwidth relay to any online fingerprint, up to
    `MAX_PACKET_SIZE_BYTES` (6 MiB) per frame. Confirmed by inspection that neither shipped client
    currently sends these three bare types directly — both always route through
    `sendAnonOrDirect()`, which always wraps delivery in `anon_message` — but the handlers remain
    live `ALLOWED_TYPES`, reachable by any custom/legacy client, and are hardened anyway (same
    "dormant is not deleted" posture as S6-47's Channels invariant). Separately, both clients'
    receive-side chunk-reassembly accumulators had no bounds at all — no range check on
    `chunk_index`/`total_chunks`, no cap on simultaneous transfers, no expiry for an abandoned one —
    and Android's `file_chunk` accumulator was a plain list that appended every arrival instead of
    de-duplicating by index, so a duplicate/replayed chunk grew it forever and could corrupt
    reassembly with duplicate data.
    Where: `server.py`'s `_validate_media_chunk_envelope()`, the `image_chunk`/`video_chunk`/
    `file_chunk` handlers, `MEDIA_CHUNK_*` budgets; Android's `MessengerService.kt`
    (`imageChunks`/`imageTotals`/`fileChunks`, `processVideoChunk()`); Desktop's
    `WebSocketClient.kt` (`imageChunks`/`fileChunks`).
    Server protocol shape confirmed from CURRENT client code: chunks are
    `packedData.chunked(120_000)` (120,000 base64 chars, ~90 KB decoded), transfer ids are
    `UUID.randomUUID().toString()` (36 chars), signatures are SHA256withECDSA over
    `transferId‖chunkIndex‖chunkData`, DER, base64. `_validate_media_chunk_envelope()` (shared by
    all three handlers) requires `is_valid_fingerprint(to)`, a bounded transfer id
    (`MEDIA_CHUNK_ID_MAX_LEN`=128), a real non-bool `chunk_index >= 0`, a real non-bool
    `total_chunks` in `1..MEDIA_CHUNK_MAX_TOTAL_CHUNKS` (20,000), `chunk_index < total_chunks`, a
    bounded non-empty `data` (`MEDIA_CHUNK_DATA_MAX_LEN`=130,000), and a bounded optional
    `signature` (`MEDIA_CHUNK_SIGNATURE_MAX_LEN`=256) — all checked BEFORE `clients.get()`/
    `json.dumps()`/`send_safe()`, never coerced. `file_chunk` forwards both `file_name` and
    `encrypted_file_name` (each bounded, `MEDIA_CHUNK_FILENAME_MAX_LEN`=512) — the field CURRENT
    `sendFile()` actually sends on both clients, confirmed by grep, not the stale legacy-only field
    the old relay list forwarded. Ordering: cheap envelope validation → a cheap per-user chunk-
    ATTEMPT counter (`MEDIA_CHUNK_ATTEMPT_LIMIT`=1000/10s, independent of size, bounds inbound-
    parsing cost even against an offline/nonexistent target) → resolve online-recipient status →
    only if online: per-user (`MEDIA_CHUNK_USER_MAX_BYTES`=50 MiB/10s), process-wide
    (`MEDIA_CHUNK_GLOBAL_MAX_BYTES`=500 MiB/10s), and per-recipient
    (`MEDIA_CHUNK_RECIPIENT_MAX_BYTES`=100 MiB/10s) byte budgets — all windowed RAM-only counters
    mirroring `global_prekey_publish_rate_ok()`'s pattern — → relay via `send_safe()` → `chunk_ack`
    only on success. An offline/nonexistent recipient never consumes any byte budget (no egress
    ever happens) but is still bounded by the attempt counter; the per-recipient budget is keyed
    only by a genuinely-online username (bounded the same way `rate_limits` already is), never an
    attacker-controlled arbitrary string — not the pre-S6-35 unbounded-registry anti-pattern. A
    rejected chunk gets `{"status": "rate_limited"}` or the existing `"offline"` reply, never a
    `chunk_ack` — both clients only act on `status == "offline"`, so the new value is safely
    ignored by current official apps. Client receive-assembly (both platforms, fixed identically):
    `chunk_index`/`total_chunks` range-checked before touching any accumulator; a new
    `pruneAndAdmitTransfer()` helper lazily sweeps any transfer idle past 5 minutes then caps
    simultaneous transfers at 20 per accumulator; Android's file accumulator changed from a list to
    a map keyed by index so a repeated `chunk_index` overwrites its own slot instead of appending a
    duplicate (Desktop's accumulators were already map-based). `MAX_PACKET_SIZE_BYTES` is completely
    untouched — these are protocol-specific ceilings layered on top of it, not a replacement.
    Regression-tested: `Server/tests/test_security_invariants.py`'s media-chunk-relay-hardening
    section proves official image/video/file chunks still relay and ack correctly; a non-canonical
    `to` never reaches `clients.get()`; oversized/wrong-type `data`, oversized transfer ids/
    signatures, negative/bool/out-of-range `chunk_index`, zero/negative/absurd `total_chunks`, and
    oversized `file_name`/`encrypted_file_name` are all rejected before relay; a `chunk_ack` is
    proven to follow `send_safe()` success only, and a rejected chunk is proven to produce no ack at
    all; per-user, process-wide, and per-recipient byte budgets each independently bound their
    target; the per-user limiter is proven to reset after its window and stay keyed only by real
    accounts; an offline/nonexistent target is proven bounded by the attempt counter without ever
    touching the byte budgets; a normal multi-chunk transfer fits comfortably within the configured
    limits; and `MAX_PACKET_SIZE_BYTES` is proven unchanged. Client receive-assembly hardening
    confirmed by source inspection (not exercised by a Kotlin build/test harness in this repo) —
    both clients' bare-direct-type sending paths were confirmed dormant (always anon_message-wrapped
    in practice), so this is defense-in-depth against a remote authenticated sender the device
    already trusts enough to have cached a public key for. Fixed 2026-09-05, see
    `KNOWN_SECURITY_ISSUES.md` S6-49.

    **Follow-up (2026-09-06):** the receive-side hardening above bounded chunk_index/total_chunks/
    concurrent-transfer count but not one transfer's TOTAL accumulated size, and never validated an
    incoming chunk's own `data` length against anything client-side (relying entirely on the
    server's own validator, which a compromised/malicious server does not have to honor). Both
    clients now reject any incoming chunk whose `data` exceeds the server's own
    `MEDIA_CHUNK_DATA_MAX_LEN` (130,000 chars) before storing it, and enforce a new
    `MEDIA_TRANSFER_MAX_BYTES` (64 MiB) hard ceiling on one transfer's total accumulated wire bytes,
    delta-accounted per chunk index so a replayed index never re-inflates the total but a
    differently-sized replacement is accounted correctly rather than silently ignored (the gap this
    follow-up specifically found: without delta-accounting, a validly-signed contact could replay
    every already-admitted index with a larger chunk and inflate real retained memory far past the
    accounted total, since "duplicate index" was treated as a pure no-op). Exceeding the ceiling
    cancels the whole transfer (every tracking map cleared, no ack) rather than truncating.
    `pruneAndAdmitTransfer()`'s own stale-transfer sweep was extended to also clear the new byte-
    accounting maps for the same stale keys — previously an abandoned transfer swept out of the
    content map by an unrelated later transfer's admission check left its byte-accounting entry
    orphaned forever. `group_image_batch`/`group_file_batch` (sharing the same accumulators)
    received the identical chunk_index/total_chunks/data-length/byte-ceiling bounds, closing a
    pre-existing gap where they had none of this invariant's guards at all; their remaining lack of
    `pruneAndAdmitTransfer()` concurrency-cap coverage is tracked as a separate, narrower follow-up.
    Verified by a clean `.\gradlew.bat :app:compileDebugKotlin` (Android) and
    `.\gradlew.bat compileKotlin` (Desktop), and by a standalone executable Kotlin harness — an
    exact copy of the shared `pruneAndAdmitTransfer()`/`accountChunkBytes()` algorithm, run via
    `java -cp` and then deleted, not part of the shipped app — proving all of: max legitimate
    transfer succeeds; first byte over the ceiling is rejected; duplicate index doesn't increase
    accounting; sparse unique chunks can't exceed the ceiling; 20 concurrent transfers are each
    still capped; abandoned-transfer cleanup releases every tracking map; completion releases every
    tracking map; oversized data is rejected before retention; group-batch transfers share the
    identical ceiling; a normal small transfer still completes. Server-side S6-49 tests are
    unaffected by this client-only follow-up (372/372 still pass).

63. **Avatar data is protocol-bounded before decode/storage, all avatar mutations share one
    admission path, unchanged reconnect values are no-ops, durable state commits before RAM/fanout,
    and aggregate retained avatar bytes plus avatar egress are bounded independently of account
    count.**
    Why: successful `register()` accepted an `avatar` field with only an independent
    `len(...) < 200_000` check and NO `rate_limit_check()` call at all, completely bypassing
    `profile_update`'s own `"profile_update"` rate bucket — and Android includes `avatar` in EVERY
    `register()` call (first registration AND every reconnect), so a repeatedly-reconnecting account
    could durably write/broadcast its avatar at unlimited rate. Every successful register/reconnect
    also received the server's ENTIRE `user_avatars` directory unconditionally, so one reconnect's
    egress scaled with total account count, and `user_avatars` loaded fully into RAM at startup with
    no aggregate byte/row ceiling while `MAX_REGISTERED_USERS` defaults unlimited.
    Where: `server.py`'s `is_valid_avatar()`, `apply_avatar_mutation()`, `_db_upsert_avatar_sync()`,
    `get_avatar_mutation_lock()`, the `register`/`profile_update`/`get_key` handlers,
    `AVATARS_MAX_TOTAL_BYTES`/`ROWS`, `AVATAR_UPDATE_GLOBAL_LIMIT`, `AVATAR_SYNC_MAX_COUNT`/
    `MAX_TOTAL_BYTES`.
    `is_valid_avatar()` (mirrors `validate_channel_post_image()`'s exact shape) requires a `str`,
    bounds the encoded length BEFORE decode (`AVATAR_MAX_B64_LEN`, the base64 expansion of
    `AVATAR_MAX_DECODED_BYTES`=64 KiB — a generous multiple of Android's real 128×128 JPEG q85
    format, confirmed by inspection of `ProfileScreen.kt`, not an attempt to prove
    128×128/JPEG-ness, which would need decoding an untrusted image format server-side), strictly
    base64-decodes, then bounds the DECODED byte length. `apply_avatar_mutation(username,
    avatar_value)` is the ONE canonical admission path both `register()`'s avatar field and
    `profile_update` call — register has no independent rate bucket, both share
    `rate_limit_check(username, "profile_update")`. Ordering deliberately checks "byte-for-byte
    identical to the currently-stored avatar" BEFORE any rate/budget admission — the normal
    reconnect case costs nothing: no rate consumption, no SQLite write, no broadcast. Only a genuine
    change is rate-admitted AND checked against a new process-local `AVATAR_UPDATE_GLOBAL_LIMIT`
    (60/60s, mirrors `channel_post_global_rate_ok()`) BEFORE the durable write.
    `get_avatar_mutation_lock()` (mirrors `get_totp_state_lock()`'s exact reasoning — bounded key
    space of real authenticated usernames) serializes concurrent mutations for the same fingerprint
    across the DB `await` so RAM and durable state can never disagree after a race — never holding
    the global `lock` across that `await` (invariant #34). `_db_upsert_avatar_sync()` computes the
    byte DELTA (new − old) for a replace inside ONE `BEGIN IMMEDIATE` transaction with the capacity
    check against a new `user_avatars_meta` singleton (reconciled at startup, same
    `pending_messages_meta`/`channel_posts_meta` pattern), returning `"STORED"`/`"FULL"` — never
    silently treating a rejected write as success. Hard strictly-positive
    `AVATARS_MAX_TOTAL_BYTES`=256 MiB/`AVATARS_MAX_TOTAL_ROWS`=1,000,000 bound aggregate persisted
    avatar bytes independently of account count; a startup fail-closed check (same posture as
    S6-44's `anon_token_state` check) refuses to start if the DB is already over either cap, never
    auto-deleting rows. The unconditional full-directory reconnect sync is now a bounded snapshot
    (`AVATAR_SYNC_MAX_COUNT`=500/`AVATAR_SYNC_MAX_TOTAL_BYTES`=8 MiB) rather than removed outright —
    both clients inspected first: Android already restores contacts' avatars from its own local
    cache on every reconnect and separately fetches a specific contact's avatar on demand via
    `get_key()` when that contact's public key isn't cached, so the bulk sync is a compatibility
    fallback, not the only path. `get_key` (this protocol's only avatar-adjacent retrieval path —
    there is no dedicated `get_avatar` message type) now requires `is_valid_fingerprint(target)`
    (silently dropped if malformed, same posture as every other account-fingerprint handler, S6-42)
    and a new `rate_limit_check(username, "get_key")` bucket (30/min) — previously entirely
    unrate-limited and shape-unchecked. Regression-tested: `Server/tests/test_security_invariants.py`'s
    avatar-persistence-hardening section proves official Android avatars pass the validator;
    wrong-type/oversized-encoded/invalid-base64/oversized-decoded avatars are all rejected before
    RAM/SQLite/broadcast; register and profile_update share the same validator and the same rate
    bucket (proven over the real wire protocol, alternating between both message types); an
    unchanged reconnect avatar causes no SQLite write, no broadcast, and does not consume the global
    mutation budget; a genuinely changed avatar does consume it; a DB failure leaves RAM and any
    broadcast completely untouched; concurrent mutations for one account leave DB and RAM agreeing;
    the aggregate byte cap rejects growth above it while a shrink-then-grow sequence correctly frees
    logical capacity via delta accounting; a rejected FULL update leaves the old avatar intact;
    startup refuses a DB already over the cap and loads a bounded one normally; one reconnect's
    avatar-directory sync is provably bounded; repeated reconnects with an unchanged avatar cannot
    fan out more than once; `get_key` requires a canonical target and is rate-limited; and a genuine
    avatar update remains visible to a legitimate observing client. Two attack-simulation
    regressions: repeated reconnection with the same maximum-size avatar produces zero repeated
    writes/broadcasts and bounded egress; Sybil accounts each creating a maximum avatar never push
    aggregate persisted bytes past the configured cap. This patch does not claim avatars are private
    metadata — the protocol still deliberately broadcasts a changed avatar to every online account,
    unchanged from before; this is resource/lifecycle hardening, not a confidentiality change. Fixed
    2026-09-06, see `KNOWN_SECURITY_ISSUES.md` S6-50.

64. **WebRTC signaling is a small schema-defined protocol: every signaling field and total sanitized
    payload are bounded before relay/state mutation, arbitrary caller fields are never reflected,
    signaling has sender/global/recipient byte budgets in addition to count limits, and network sends
    cannot accumulate an unbounded number of background tasks.**
    Why: the call-signaling relay forwarded the caller's ENTIRE arbitrary JSON dict
    (`message["from"] = username; asyncio.create_task(send_safe(target_ws, json.dumps(message)))`),
    bounded only by count limits sized for small WebRTC messages (`call_ice`: 300/min) under the
    shared `MAX_PACKET_SIZE_BYTES` (6 MiB) frame ceiling — 300 × ~6 MiB is ~1.8 GiB/minute of
    potential relay input from one account before Sybils, and a small legitimate candidate plus
    megabytes of unrelated JSON in the same frame would have been relayed intact. `call_offer`/
    `call_answer` also copied an unvalidated `call_id` into `active_calls`, and every relay used
    fire-and-forget `asyncio.create_task()` rather than awaiting the send.
    Where: `server.py`'s `is_valid_call_uuid()`, `_sanitize_call_signal()`, `_call_signal_ceiling_bytes()`,
    `call_signal_user_rate_ok()`/`global_rate_ok()`/`recipient_rate_ok()`, the `CALL_RELAY_TYPES`
    handler; Android's `CallManager.kt`; Desktop's `DesktopCallManager.kt`.
    Schemas derived from both clients' actual code, not guessed: `call_id`/`group_id` are always
    `UUID.randomUUID().toString()` (group calls are Android-only); SDP is a few KB (both clients use
    trickle ICE, no embedded candidates); one ICE candidate line is well under 300 bytes; `reason`
    strings are a small enumerable set. `is_valid_call_uuid()` requires the exact canonical UUID
    shape — a dedicated validator, decoupled from the unrelated `is_valid_device_id()` despite the
    identical regex. Per-type envelope ceilings (`CALL_SIGNAL_SDP_MAX_PACKET_SIZE_BYTES`=96 KiB,
    `..._ICE_...`=4 KiB, `..._PEER_LIST_...`=8 KiB, `..._CONTROL_...`=2 KiB — all far below
    `MAX_PACKET_SIZE_BYTES`, which is untouched) are checked against the ACTUAL received UTF-8 frame
    before active_calls mutation, clients lookup, or field-level work. `_sanitize_call_signal()` is
    the ONE construction path for every relayed message: a BRAND NEW dict with only `type`/
    `from`(server-controlled, never spoofable)/`to`/`call_id` plus whatever fields THIS EXACT message
    type's protocol defines (`sdp` ≤`CALL_SDP_MAX_LEN`=64 KiB; `candidate` ≤1024/`sdp_mid` ≤64 chars/
    `sdp_m_line_index` a real non-bool int 0-255; `is_video`/`is_group`/`accepted` real non-coerced
    booleans; `reason` restricted to the exact enumerated set either client or this server ever
    sends; `peers` ≤50 entries, every one `is_valid_fingerprint()`-shaped) — any unrelated extra
    field is discarded, never reflected. `active_calls` is populated only from this validated
    `call_id`, and only once byte-budget admission has also cleared — malformed and over-budget
    signaling leave `active_calls` equally untouched. New process-local byte budgets
    (`CALL_SIGNAL_USER_MAX_BYTES`=2 MiB/`GLOBAL_MAX_BYTES`=20 MiB/`RECIPIENT_MAX_BYTES`=8 MiB, all
    /10s, mirroring `media_chunk_*_rate_ok()` from S6-49) sit alongside the unchanged existing count
    limits, accounted once from the exact sanitized relay payload, charged only when a message is
    about to reach an ONLINE recipient. The relay now `await`s `send_safe()` directly instead of
    scheduling it via `asyncio.create_task()` — one bounded packet per relay gives the sender's own
    message loop backpressure instead of letting pending send Tasks accumulate against a slow
    recipient. Offline `call_offer` behavior is unchanged (only the small server-created
    `missed_call` is stored, through `db_store()`'s pre-existing `global_offline_store_rate_ok()`
    budget); `send_fcm_wakeup()`'s own missing recipient/global push budget is a pre-existing gap
    shared by every FCM-wake call site in this file, deliberately not expanded here (tracked
    separately). Client-side (a compromised/malicious server is not either client's memory-safety
    boundary): both `CallManager.kt` and `DesktopCallManager.kt` independently bound `call_id`/
    `group_id`, SDP, ICE candidate/`sdp_mid`, and the group peer list before ever calling
    `setRemoteDescription()`/`addIceCandidate()`/spinning up a `PeerConnection` per peer, mirroring
    the server's own bounds; the previously-unbounded pending-ICE-candidate queue is now capped at
    500 entries per peer. Regression-tested: `Server/tests/test_security_invariants.py`'s call-
    signaling-hardening section proves official Android/Desktop offers, answers, ICE bursts, ICE
    restarts, and every group-call type all still pass; a noncanonical `to`, oversized `call_id`,
    oversized SDP, oversized ICE candidate, malformed/oversized/invalid-entry peer lists are all
    rejected before relay/state mutation; an enormous arbitrary extra field is never relayed and the
    sanitized output contains only schema fields; `from` cannot be spoofed; the existing `call_ice`
    count limiter still fires; per-user/global/recipient byte budgets each independently bound their
    target; malformed AND over-budget signaling both leave `active_calls` untouched while valid
    signaling populates it correctly and `call_end`/disconnect both clear it; the relay awaits
    `send_safe()` rather than scheduling it; offline `call_offer` still stores only `missed_call` and
    still triggers the FCM wakeup; `MAX_PACKET_SIZE_BYTES` is unchanged. Client-side validation
    confirmed by source inspection and a clean compile on both platforms, not exercised by the Python
    suite (no cross-language harness exists) — this is the first automated test coverage call
    signaling has ever had. Fixed 2026-09-06, see `KNOWN_SECURITY_ISSUES.md` S6-51.

65. **External push work is admitted synchronously before task/executor creation: FCM tokens are
    protocol-bounded, silent wakeups are coalesced per recipient, sender/recipient/global push rates
    and simultaneous Firebase calls are bounded, and failure of optional wakeup delivery never
    changes the durability truth of the underlying E2EE message.**
    Why: STEP-1 investigation confirmed `fcm_token` lives ONLY in `clients[username]["fcm_token"]`
    — wiped on disconnect, never carried into the fresh dict `register()` builds on every reconnect
    — so every wakeup call site (which only ever fires when the target is confirmed NOT in
    `clients`) was reading a token that could never be there; the "wake a disconnected client" path
    was already functionally dead. That does not make the surrounding surface safe: `register_fcm`
    accepted an unbounded opaque token with no rate limit at all; every call site did
    `asyncio.create_task(send_fcm_wakeup(target))` unconditionally, allocating and scheduling a Task
    BEFORE the coroutine's own dead token-lookup ever ran, so a Sybil flood of offline
    messages/missed-calls still cost unbounded Task-creation overhead; `send_fcm_session_conflict()`
    — the one push path that genuinely CAN reach Firebase, since it reads a token from a still-live
    connection at the exact moment of eviction — had none of `register_fcm`'s bounds, no rate limit,
    no concurrent-send cap. Separately, `missed_call`/`message_delete`/`disappear_timer`/
    `group_message_delete` requested a wakeup unconditionally after `db_store()`, without checking
    whether the store actually succeeded, unlike `message`/`session_init`'s already-correct
    `delivered` gating.
    Where: `server.py`'s `register_fcm` handler, `schedule_fcm_wakeup()`/`_run_fcm_wakeup()`,
    `schedule_fcm_session_conflict()`/`_run_fcm_session_conflict()`, `_invalidate_fcm_token_if_unregistered()`.
    `FCM_TOKEN_MAX_LEN`=4096 bounds `register_fcm`'s token before it ever touches `clients` RAM (no
    invented regex on content — Firebase documents no exact format). Identical-token
    re-registration is a no-op BEFORE the new `"register_fcm"` rate bucket (10/min) — mirrors S6-50's
    avatar-mutation ordering. `schedule_fcm_wakeup(target, source, reason) -> bool` is fully
    synchronous — every cheap RAM admission check (fingerprint shape, per-recipient in-flight dedup,
    `FCM_WAKEUP_RECIPIENT_COOLDOWN_SEC`=5s coalescing, failure backoff, `FCM_WAKEUP_SOURCE_LIMIT`=20/min,
    `FCM_WAKEUP_RECIPIENT_LIMIT`=10/min, `FCM_PUSH_GLOBAL_LIMIT`=120/min, the hard
    `FCM_MAX_INFLIGHT_SENDS`=50 concurrent-sends cap) happens and is decided BEFORE
    `asyncio.create_task()` ever runs — only an admitted push allocates a Task. The hard inflight cap
    is reserved synchronously (increment-then-`create_task`, decrement in the worker's `finally`),
    not an `asyncio.Semaphore` awaited from inside an already-created Task (which would still leave
    unbounded Tasks in memory even while "bounded"). `FCM_WAKEUP_FAILURE_BACKOFF_SEC`=30s applies
    after a Firebase send exception — no immediate/indefinite retry storm; recipient cooldown commits
    only after a genuinely successful send. `firebase_admin.messaging.UnregisteredError` specifically
    (the one documented "token no longer registered" condition, distinct from timeout/generic/quota
    errors) invalidates the RAM-only token, only if it still matches what was actually sent.
    `schedule_fcm_session_conflict()` mirrors the same structure with its OWN separate cooldown/
    in-flight/backoff state (deliberately not shared with silent-wakeup coalescing — a real session
    takeover must still promptly notify the displaced device) while sharing the global budget and
    hard in-flight cap. `message_delete`/`disappear_timer`/`group_message_delete`/`missed_call` now
    only request a wakeup after `forward_to_peers()` succeeded or `db_store()` returned
    `"STORED"`/`"DUPLICATE"`, matching `message`/`session_init`'s pre-existing correct gating. All
    limiter dicts are keyed only by real `is_valid_fingerprint()`-shaped usernames (or the
    connection's own proven identity for `source`) — same bounded-key-space posture as
    `rate_limits`/`totp_state_locks`/`avatar_mutation_locks` elsewhere in this file. Message
    durability/ACK semantics are completely independent of push admission — a successfully queued
    message's ACK is never retracted because a push was denied or Firebase is unavailable.
    Regression-tested: `Server/tests/test_security_invariants.py`'s FCM-hardening section proves a
    normal token is accepted; wrong-type/oversized tokens are rejected before RAM mutation; identical
    re-registration is a no-op that doesn't consume the rate budget; the rate budget itself is
    bounded; a malformed target creates no limiter state; the first legitimate wakeup is admitted and
    repeated immediate wakeups to the same recipient are coalesced with only one ever in flight; a
    successful send commits recipient cooldown while a failed send releases in-flight state and
    applies bounded backoff (not a tight retry loop); one sender cannot exceed the source budget;
    Sybil senders cannot exceed the recipient budget against one victim; many recipients cannot
    exceed the global budget; the hard inflight cap cannot be raced above its limit; a denied wakeup
    creates no Task, never calls `_init_firebase()`, and never reaches the Firebase send; limiter
    state resets after its window; a queued message's ACK remains success even when FCM scheduling is
    denied; a failed offline store creates no FCM request at all; missed-call/session_init wakeups and
    the session_conflict notification all remain functional; session_conflict shares the global/
    inflight limits; a transient Firebase error never deletes the token while a confirmed
    `UnregisteredError` does; and — proving the STEP-1 finding directly rather than assuming it —
    disconnect removes the `clients` entry and its token, and a wakeup attempt against a genuinely
    disconnected target never even reaches `_init_firebase()`. Attack-simulation regression: many
    authenticated accounts targeting one FCM-enabled recipient with traffic that legitimately reaches
    the wakeup path stay bounded by the recipient/global limits and the inflight cap, while every
    message's durable-delivery ACK remains correct throughout. No client changes: Android's
    `register_fcm` producer is unchanged, and Desktop has no FCM integration to touch. Fixed
    2026-09-06, see `KNOWN_SECURITY_ISSUES.md` S6-52.

66. **Chat-control relay messages are small schema-defined objects. The server constructs a fresh
    payload containing only validated protocol fields and its authenticated sender identity; arbitrary
    caller fields are never reflected, control traffic is count/byte bounded per sender/recipient/
    process, and one-recipient relay is backpressured rather than accumulated as unbounded background
    Tasks. The same schema bounds apply to federated control input.**
    Why: `message_delete`/`disappear_timer`/`group_message_delete` relayed the caller's ENTIRE raw
    JSON object verbatim — `message["from"] = username` was the only server-side mutation before
    `asyncio.create_task(send_safe(target_ws, json.dumps(message)))` (online) /
    `forward_to_peers(target, message)` / `db_store(target, message)` (offline) — no schema
    reconstruction (unlike call signaling's `_sanitize_call_signal()`, S6-51), no dedicated envelope
    ceiling, and no type-specific `rate_limit_check()` bucket at all. An authenticated client could
    attach an arbitrary `"junk": "A"*several_megabytes` field to an otherwise-legitimate delete/timer
    command, under the shared ~6 MiB `MAX_PACKET_SIZE_BYTES` ceiling, repeatable with no admission
    control — an authenticated high-bandwidth/task-amplification relay. All 3 types are also in
    `FEDERATED_FORWARD_ALLOWED_TYPES`, and `validate_federated_forward_payload()` only checks
    container shape/type-allowlist/`from`-fingerprint-shape (S6-38) — no per-type field validation —
    so a malicious/compromised federation peer could bypass the same hardening via a wrapped
    `federated_forward`.
    Where: `server.py`'s `sanitize_chat_control()`, `is_valid_chat_control_id()`/
    `is_valid_chat_control_signature()`, `CHAT_CONTROL_MAX_PACKET_SIZE_BYTES`,
    `chat_control_user_rate_ok()`/`global_rate_ok()`/`recipient_rate_ok()`, the chat-control relay
    handler block, and the incoming `federated_forward` handler's Phase B; Android's
    `MessengerService.kt`; Desktop's `WebSocketClient.kt`.
    Schemas derived from both clients' actual code, not guessed: `message_id`/`group_id` are always
    `UUID.randomUUID().toString()`; Android's `message_delete`/`group_message_delete` send
    `message_id`, Desktop's send `id` instead (and omit `signature` entirely, a pre-existing
    cross-client wire-format inconsistency this patch preserves rather than "fixes" — both spellings
    are accepted as aliases so neither client's existing behavior is further broken); `seconds` is one
    of exactly 4 values ChatScreen's disappear dialog offers (0/3600/86400/604800); `signature` is
    `SHA256withECDSA`/P-256, DER-encoded, base64'd, same shape as every other identity signature in
    this protocol. `sanitize_chat_control(msg_type, message, from_user, target)` is the ONE
    construction path for every relayed chat-control message, local or federated: a BRAND NEW dict
    with server-controlled `type`/`from`/`to` plus only the fields THIS EXACT type's protocol defines
    (`message_id`/`id` each independently bounded to `CHAT_CONTROL_ID_MAX_LEN`=128 when present, at
    least one required; `group_id` validated via `is_valid_call_uuid()` — the same canonical-UUID
    space call signaling already treats this identifier as, reused rather than duplicated;`seconds`
    checked against the exact allowlist, with `bool` explicitly rejected before the `int` check since
    `bool` is an `int` subclass in Python; `signature`, optional, bounded to
    `CHAT_CONTROL_SIGNATURE_MAX_LEN`=256) — any unrelated extra field is discarded, never reflected.
    `from_user` is dual-purpose by design: the authenticated connection's own username for a locally
    originated message (mandatory, never caller-suppliable), or the federation peer's already
    fingerprint-shape-validated `from` for an incoming `federated_forward` payload, passed through
    UNCHANGED — this does NOT solve `validate_federated_forward_payload()`'s own documented residual
    `from`-spoofing limitation (S6-38), only closes the unsanitized-field gap. `CHAT_CONTROL_MAX_
    PACKET_SIZE_BYTES`=2 KiB (far below `MAX_PACKET_SIZE_BYTES`, which is untouched) is checked
    against the ACTUAL received UTF-8 frame before any clients lookup/limiter-key creation/field-level
    work. A shared `"chat_control"` `rate_limit_check()` bucket (60/min) covers all 3 types together —
    alternating `message_delete`/`disappear_timer` would otherwise double the effective allowance for
    the same abuse resource. New process-local byte budgets (`CHAT_CONTROL_USER_MAX_BYTES`=256 KiB/
    `GLOBAL_MAX_BYTES`=2 MiB/`RECIPIENT_MAX_BYTES`=128 KiB, all /10s — scaled down from S6-51's call-
    signaling budgets for a much smaller envelope, headroomed for a `group_message_delete` fanout of
    up to `CALL_GROUP_PEER_LIST_MAX_COUNT`=50 members) are accounted once from the exact sanitized
    relay payload, charged only when a message is about to reach an ONLINE recipient — rejected before
    any offline store/forward path runs, so malformed AND over-budget control traffic leave exactly as
    much state behind: none. The relay now `await`s `send_safe()` directly instead of scheduling it
    via `asyncio.create_task()` — one bounded control packet per relay gives the sender's own message
    loop backpressure instead of letting pending send Tasks accumulate against a slow recipient, and no
    failed online send is queued for retry in RAM. The offline path passes ONLY the sanitized payload
    to `forward_to_peers()`/`db_store()`; S6-52's `schedule_fcm_wakeup()` gating (only on `STORED`/
    `DUPLICATE`/forwarded success) is preserved unchanged — it remains the ONLY FCM admission path for
    these 3 types. The incoming `federated_forward` handler re-runs `sanitize_chat_control()` on these
    3 payload types right after `validate_federated_forward_payload()` succeeds, BEFORE `msg_id`
    extraction/dedup reservation (S6-34's two-phase dedup machinery is otherwise completely untouched)
    — a malformed federated chat-control payload reserves nothing and is dropped like any other
    malformed frame.
    Client-side (a compromised server/federation peer must not make the client rely solely on
    server-side validation): Android already verified a signature over `message_id`/`seconds`/
    `"$groupId:$messageId"` for all 3 types (plus author-match against the stored message's own
    `senderId` for `group_message_delete`) before this patch — no missing-authorization gap found
    there, per this patch's own STEP-11 review. Android now ALSO bounds `message_id`/`group_id` length
    (`CHAT_CONTROL_ID_MAX_LEN`=128) and checks `seconds` against the same exact allowlist, both BEFORE
    the existing signature verification, since a genuinely-authenticated malicious contact can still
    produce a validly-signed message over any content they choose — signature verification proves
    origin, not protocol sanity. Desktop bounds `id`/`group_id`/`message_id` length the same way.
    Desktop's OWN pre-existing, separate gap — `message_delete`/`group_message_delete` are sent and
    received with **no signature at all** on that platform (`sendDelete()`/`sendGroupDeleteMessage()`
    never produce one; the receive handlers apply the command unconditionally once IDs are non-empty)
    — is reported here as a distinct missing-authorization issue, intentionally NOT fixed as part of
    this patch (patch-level scope, per this row's own STEP-11 finding).
    Regression-tested: `Server/tests/test_security_invariants.py`'s chat-control-hardening section
    proves official Android (`message_id`+`signature`) and Desktop (`id`, no `signature`)
    `message_delete`, `disappear_timer`, and `group_message_delete` all still pass; a noncanonical
    `to` is rejected before any limiter-key creation; oversized `message_id`/`group_id`/`signature` are
    rejected; a malformed (wrong-type/bool) or out-of-range `seconds` is rejected; a multi-megabyte raw
    frame exceeds the chat-control envelope and an enormous `junk` field is never relayed; the sanitized
    payload contains only defined fields and `from` cannot be spoofed; the shared count bucket and the
    sender/recipient/global byte budgets each independently bound their target; online relay is an
    awaited send, never a background Task, and a failed online send never falls back to an offline
    store; the offline store and federation-outbound call both receive the sanitized payload only; a
    failed offline store schedules no FCM wakeup while `STORED`/`DUPLICATE` still does, through the
    same `schedule_fcm_wakeup()` path for all 3 types; a valid federated `message_delete` still works,
    federated `junk` is stripped, an oversized federated field and a malformed federated timer are
    both rejected, the federated peer's `from` is preserved exactly as supplied, and this patch does
    not reopen S6-38's privileged-type federation injection gap. Attack-simulation regression: repeated
    near-envelope junk-stuffed `message_delete` frames against an online victim are never relayed, and
    background-Task count does not scale with request count. Fixed 2026-09-06, see
    `KNOWN_SECURITY_ISSUES.md` S6-53.

67. **A delete-for-everyone command is applied only after cryptographic authentication of a
    domain-separated transcript and local authorization against the referenced message. For direct
    messages the authorized deleter is the message author; for group messages the author, or an
    explicitly supported locally-proven administrator, is required. Knowledge of a message ID or
    possession of an unrelated valid account key never grants deletion authority.**
    Why: S6-53's own STEP-11 review found that a valid signature over a delete command proves only
    "this identity requested this deletion," never "this identity is authorized to delete THIS
    message" — and that Desktop sent/verified no signature at all for `message_delete`/
    `group_message_delete`, while Android's `message_delete` receiver had a signature check but NO
    author-authorization check (`group_message_delete`'s own `existing.senderId != from` check was
    already correct). Both platforms' pre-existing transcripts were also unversioned and not
    domain-separated: `message_delete` signed the bare `messageId`, and `group_message_delete`'s
    `"$groupId:$messageId"` transcript is the same two-colon-joined shape `group_member_removed`'s
    `"$groupId:$removedMember"` already uses elsewhere in this protocol — risking a signature computed
    for one operation verifying for another if their signed values ever coincide.
    Where: Android's `MessengerService.kt` (`sendDeleteMessage()`/`sendGroupDeleteMessage()`, the
    `"message_delete"`/`"group_message_delete"` receive handlers); Desktop's `WebSocketClient.kt`
    (`sendDelete()`/`sendGroupDeleteMessage()`, the same two receive handlers) and `ChatScreen.kt`
    (`ContextMenuDialog`); `server.py`'s `sanitize_chat_control()`.
    Both transcripts are now versioned and domain-separated, identical on both platforms:
    `"SUBROSA_MESSAGE_DELETE_V1:" + messageId` and `"SUBROSA_GROUP_MESSAGE_DELETE_V1:" + groupId +
    ":" + messageId` — chosen so neither can verify as the other or as any other signed operation in
    this protocol, and the group transcript binds BOTH `groupId` and `messageId` so a signature can't
    be replayed against a different group referencing the same message id. Desktop now signs both
    with `CryptoManager.sign()` (confirmed identical `SHA256withECDSA`/UTF-8/standard-base64-no-wrap
    primitives to Android's own — the existing basis `edit`/`group_message` signatures already
    interoperate on) and verifies before ever calling `GroupManager.deleteGroupMessage()`/invoking
    `onMessageDeleted`, using the same `peerPublicKeys`/`DesktopCryptoManager.getPeerPublicKey()`
    lookup already used elsewhere in that file. Authorization — the part a signature alone cannot
    prove — is now checked for `message_delete` on BOTH platforms: a direct 1:1 conversation has
    exactly two possible authors, so the locally stored message's own `isOwn`/`fromMe` flag tells us
    which; if the referenced message is the LOCAL user's own, the remote `from` is rejected regardless
    of signature validity. An unknown/nonexistent message id remains a safe no-op. `group_message_
    delete`'s existing author-only check (`existing.senderId != from`) is preserved as-is on both
    platforms — this product has no admin-delete-others'-messages feature (`GroupManager.isAdmin()`
    exists only for member add/remove/promote), so author-only remains the correct policy, not
    something to replace with an invented admin-delete capability. Desktop's delete-for-everyone
    dialog also now hides its "delete for everyone" option unless the message is the local user's own,
    matching Android — UI-side hygiene only, never the security control, since a custom client can
    construct arbitrary protocol messages regardless of what any official client's UI shows.
    Server-side, `sanitize_chat_control()` now REQUIRES a nonempty bounded `signature` for
    `message_delete`/`group_message_delete` specifically (unchanged for `disappear_timer`), for both
    local relay and incoming `federated_forward` payloads of these 2 types — defense-in-depth against
    official infrastructure ever relaying/storing a command no up-to-date official client would
    produce, explicitly NOT the authorization boundary itself: this server has no reliable
    E2EE-message-author semantics to verify a signer against, only each client's own local storage
    does. `disappear_timer` was inspected and left unchanged — a 1:1 conversation has no third-party-
    authorship concern the way message deletion does, and Desktop has no `disappear_timer` feature at
    all to have a missing-signature gap in the first place.
    Verified with a temporary cross-platform vector harness (Desktop's real `CryptoManager.sign()`/
    `verify()`, deleted after use, since no Android instrumentation is available in this environment):
    both transcripts sign/verify round-trip correctly, a `message_delete` signature does not verify as
    a `group_message_delete` transcript or vice versa, and changing either `messageId` or `groupId`
    breaks verification — domain separation and binding both hold in practice, not merely in the
    string-construction source. Regression-tested (server-side; client-side signing/verification/
    authorization is not exercised by the Python suite, confirmed instead by source inspection, a
    clean compile on both platforms, and the vector harness above — same posture as S6-51's own
    client-side coverage): an unsigned `message_delete`/`group_message_delete` is relayed neither
    online nor stored offline; an empty-string or wrong-typed `signature` is rejected the same as a
    missing one; a validly-shaped signed command still relays with no regression; federation cannot
    strip the signature and still reach a local client or durable storage; `disappear_timer`'s
    signature remains optional, unchanged by this patch. Fixed 2026-09-06, see
    `KNOWN_SECURITY_ISSUES.md` S6-54.

68. **Offline messages remain durable until their individual websocket handoff succeeds. Flush is
    FIFO and bounded-batch; a failed or interrupted send leaves the current and subsequent rows in
    SQLite, and per-row deletion updates durable row/byte accounting atomically. The queue provides
    at-least-once handoff, not exactly-once application delivery.**
    Why: `_db_flush_sync()` predated `pending_messages_meta` (S6-31) and was never revisited for its
    own delete-before-send shape once that landed — it `SELECT`ed and `DELETE`d every pending row for
    a reconnecting recipient in ONE transaction, then handed the payloads back to the caller to send
    one at a time over the websocket. A disconnect any time after that transaction committed — before
    the first send, mid-batch, or on the last row — silently destroyed every message that hadn't
    actually reached the client yet, with no durable trace left to redeliver on the next reconnect.
    Where: `server.py`'s `_db_flush_sync()`/`db_flush()` (replaced) and the reconnect delivery block
    in the `register` handler (`pending = await db_flush(username); for payload_str in pending: ...`).
    Replaced with two primitives: `db_peek_pending(recipient, limit)` is a plain bounded read — no
    transaction, no mutation of `pending_messages` or `pending_messages_meta`, safe to call repeatedly
    or concurrently with anything else — and `db_delete_pending_row(recipient, row_id)` deletes
    exactly one row (verifying it still belongs to `recipient` first) and decrements
    `pending_messages_meta` in the SAME `BEGIN IMMEDIATE` transaction, returning `"DELETED"` or
    `"NOT_FOUND"`; meta is never decremented for a `"NOT_FOUND"`. The reconnect loop now peeks a
    `PENDING_MESSAGES_FLUSH_BATCH_SIZE`-bounded batch, and for each row calls `send_safe()` THEN —
    only if that returned `True` — `db_delete_pending_row()` for that exact row; the first `False`
    (or an exception) stops the loop immediately, leaving that row and every later row (in this batch
    and the rest of the backlog) durable for the next reconnect. No single call ever materializes an
    account's entire backlog into RAM, and a message stored for a recipient mid-flush (by a sender
    racing the flush) is never lost, since each batch is a fresh bounded read, not a stale snapshot.
    Concurrency: `get_pending_flush_lock(username)` (a plain per-account `asyncio.Lock`, same
    always-resident keyed-lock shape as `avatar_mutation_locks`/`totp_state_locks` — `username` here
    is always this connection's own already-authenticated identity, never an attacker-chosen string,
    so this is not the ref-counted self-pruning shape `prekey_mutation_locks` needs) narrows the
    window where a session-conflict-evicted connection's own still-running flush loop could interleave
    with a brand new connection's flush loop for the same account. Even without that lock, correctness
    holds: two concurrent deletes of the same row resolve to one `"DELETED"` and one `"NOT_FOUND"`,
    never a double-decrement; a TTL-watchdog sweep racing a flush's delete-after-send resolves the same
    way, benignly. The accepted, explicitly-documented remaining gap: `send_safe()` returning `True`
    followed by a crash before `db_delete_pending_row()` commits leaves that exact row still durable,
    so the next reconnect redelivers it — a genuine duplicate, never silent loss. Regression-tested:
    peek/delete primitive semantics (FIFO order, no mutation on peek, exact meta decrement, `NOT_FOUND`
    never touching meta, cross-recipient rejection), partial-batch-failure delivery (only the delivered
    prefix is removed, the rest survives verbatim, a later reconnect delivers the remainder in original
    order), bounded batching (a backlog larger than the batch size is still delivered in full, one
    bounded peek never returns more than the cap), the crash-window duplicate simulated directly
    (send without delete, then redelivered on a fresh flush), concurrent-delete/watchdog-race/store-
    delete-race meta correctness, a real two-connection session-conflict eviction never corrupting
    `pending_messages_meta`, and an end-to-end attack simulation (N queued rows, a websocket that
    accepts exactly K then dies mid-batch, asserting rows `1..K` gone and `K+1..N` durable, then a
    clean reconnect delivering the remainder FIFO). Fixed 2026-09-06, see `KNOWN_SECURITY_ISSUES.md`
    S6-55.

69. **New-account creation always has a finite durable safety ceiling independent of deployment
    policy. An operator may disable the smaller deployment-specific account cap, but cannot make
    the persistent account registry unbounded; capacity admission is atomic with registration/
    access-code consumption and does not block existing identities from reconnecting.**
    Why: STEP-1 of this fix's own review established the actual shipped default: `.env.example`
    explicitly tells personal-server operators to leave `SERVER_ACCESS_PROTECTED` off, neither it
    nor `MAX_REGISTERED_USERS` is set by `start-son-server.bat`, and `MAX_REGISTERED_USERS=0` was
    treated as literally unlimited — no ceiling of any kind. `POW_DIFFICULTY_BITS` defaults to 18
    (real friction) but is itself an operator-disableable setting (`=0` removes it entirely), so it
    can never be the durable-resource boundary. A remote client that completes the handshake could
    therefore mint an unbounded number of permanent `registered_fingerprints` rows from the default
    deployment alone — the same class of gap S6-31/S6-44/S6-50/S6-47 already closed for the offline
    queue/anonymous tokens/avatars/channels, just never applied to the root account registry itself.
    Where: `server.py`'s `MAX_REGISTERED_USERS`, `_db_admit_new_fingerprint_sync()`, and the
    `register` handler's new-fingerprint admission block.
    `REGISTERED_ACCOUNTS_HARD_MAX_ROWS` (default 1,000,000 — same value as the existing
    `AVATARS_MAX_TOTAL_ROWS` one-row-per-account precedent, not a guess) is now an always-on safety
    ceiling. `effective_registration_cap()` folds it in alongside the operator's own
    `MAX_REGISTERED_USERS`: `min(MAX_REGISTERED_USERS, HARD_MAX)` when the operator set a smaller
    cap, otherwise `HARD_MAX` — `MAX_REGISTERED_USERS=0`/unset now means "no smaller operator cap,"
    never "no ceiling at all." Enforced inside the SAME atomic `_db_admit_new_fingerprint_sync()`
    transaction, unchanged — only the `max_users` value the register handler passes in changed, so
    the existing exists → cap-check → access-code-consume → insert ordering, and the pre-existing
    guarantee that a "full" rejection never touches the access code, both hold exactly as before.
    Applies ONLY to a brand-new fingerprint: an already-registered identity's reconnect, device
    authentication, and TOTP checks are entirely unaffected even with the account table sitting
    exactly at the hard cap, and a new device for an existing account remains governed by S6-37's
    own per-account device cap, never by this new-account count. A new process-wide
    `NEW_ACCOUNT_GLOBAL_LIMIT`/`NEW_ACCOUNT_GLOBAL_WINDOW_SEC` budget — independent of PoW, since PoW
    is itself disableable — rejects excess brand-new-fingerprint attempts before the executor/SQLite
    hop; charged only to `is_new_fingerprint` attempts, never to an ordinary reconnect. Startup now
    logs the actual registered-account count against both the operator and hard caps on every run:
    `registered_fingerprints` is never bulk-loaded into RAM at startup (unlike `user_avatars`/
    `anon_token_state`, confirmed by inspection — every lookup against it is a per-row query), so
    there is no "refuse to start before an unbounded RAM load" case here the way those two tables
    have; the atomic per-request cap check above already disables new registration on its own once
    the table is at or past the hard cap. A table already over the hard cap is reported prominently
    at startup rather than only surfacing as unexplained `registration_full` responses later, and
    rows are never auto-deleted to force the count back under a lowered cap — an operator who
    intentionally raised real usage past a newly-lowered value needs to raise the cap back, not have
    accounts silently removed. Audited (STEP 7): every other per-account table this multiplies —
    `authorized_devices`, `prekey_bundles_db`, `user_totp`, `totp_recovery_codes`, `user_avatars` —
    was already bounded per-account by prior fixes (S6-37/S6-36/S6-50); no additional field-level fix
    was needed to make bounded-bytes-per-account × bounded-total-accounts hold. Regression-tested:
    hard-cap semantics (below/at/above the cap, operator cap lower/equal/higher than the hard cap
    never raising the effective limit), existing users never blocked (reconnect/device-auth/TOTP at
    the hard cap, a reconnect never counted as a new admission or charged against the new-account
    budget), concurrency (two distinct fingerprints racing the one remaining slot — exactly one
    succeeds, durable row count never exceeds the cap; the same fingerprint racing itself resolves to
    one `"ok"` and every other `"exists"`), access-code interaction (a losing/full rejection never
    consumes an access code; the winning last-slot registration consumes it exactly once), the global
    budget (Sybil attempts across distinct fingerprints hit it, an existing reconnect bypasses it
    entirely), startup accounting (below/at/above the hard cap, never auto-deleting), and an
    end-to-end attack simulation with `MAX_REGISTERED_USERS=0` + `POW_DIFFICULTY_BITS=0` + open
    registration and the hard cap monkeypatched small: more distinct identities attempt registration
    than the cap allows, exactly the cap's worth are admitted, every admitted account can still
    reconnect afterward, and no access code or per-account/global accounting is left inconsistent.
    Fixed 2026-09-06, see `KNOWN_SECURITY_ISSUES.md` S6-56.

70. **Voice messages are a finite protocol: wire data, identifiers, signatures, duration and
    decrypted audio size are bounded before expensive processing or retention; voice traffic has
    sender/recipient/process admission limits, and the same schema applies to local and federated
    relay.**
    Why: the `voice` handler relayed `voice_id`/`voice_data`/`signature`/`duration` verbatim with no
    protocol-specific size bound of any kind, and `"voice"` had no entry at all in
    `rate_limit_check()`'s `default_limits` — the multi-megabyte `MAX_PACKET_SIZE_BYTES` application
    frame ceiling was the ONLY thing standing between an authenticated sender and using encrypted
    voice blobs as a high-bandwidth relay, forcing signature-verification/decryption/audio-decode
    work onto recipients regardless of how large the blob was. Neither shipping client capped
    recording duration either, so nothing on the sending side even discouraged an unbounded
    recording from being created in the first place.
    Where: `server.py`'s `voice` handler and the `federated_forward` Phase B per-type dispatch;
    Android's `AudioHelper.kt`/`MessengerService.kt` (`sendVoice()`, the `"voice"` receive handler,
    `ChatScreen.kt`'s recording UI); Desktop's `VoiceRecorder.kt`/`WebSocketClient.kt` (`sendVoice()`,
    the `"voice"` receive handler, `ChatScreen.kt`'s recording UI).
    Numbers are derived, not guessed, from both clients' actual voice implementations: Android
    records AMR-NB/3GPP (empirically ~2000 bytes/sec of encoded audio); Desktop records
    UNCOMPRESSED 16 kHz/16-bit mono PCM WAV (32,000 bytes/sec of raw audio) — the dominant/worst
    case every bound below is actually sized against. Both clients' `voice_id` is always
    `UUID.randomUUID().toString()`. Wire expansion on both clients is identical: raw audio → base64
    (~4/3) → that string is the plaintext for the hybrid encrypt (~1.2 KB fixed overhead: ephemeral
    EC pubkey + ML-KEM-768 ciphertext + GCM IV/tag) → the combined blob is base64-encoded again for
    the wire `voice_data` field (~4/3) — roughly 1.78x the raw audio bytes end to end. A new
    `MAX_VOICE_DURATION_SECONDS` (60) is the finite product maximum this patch establishes; at that
    duration Desktop's worst-case wire `voice_data` is ~3.26 MiB, and `VOICE_DATA_MAX_LEN` (4 MiB)
    gives real headroom above that while `VOICE_MAX_PACKET_SIZE_BYTES` (4.5 MiB) stays meaningfully
    below `MAX_PACKET_SIZE_BYTES` (6 MiB) rather than silently re-permitting the full application
    frame ceiling for this message type.
    `sanitize_voice_payload()` is now the ONE canonical construction path for a relayed voice
    message — a brand-new dict containing only `type`/`from`/`to`/`voice_id`/`voice_data`/
    `signature`/`duration`, each validated (canonical-UUID `voice_id`, nonempty bounded
    `voice_data`/`signature`, a non-bool int `duration` in `[0, MAX_VOICE_DURATION_SECONDS]`) —
    never the caller's arbitrary dict forwarded verbatim. The raw frame is checked against
    `VOICE_MAX_PACKET_SIZE_BYTES` before any parsing; a new `"voice"` count-rate bucket (60/min,
    previously absent) and per-sender/global/per-recipient byte budgets (mirroring S6-49's media-
    chunk and S6-51's call-signaling precedent exactly) are charged only for a message actually
    relayed to an online recipient — an offline target is federated/queued instead, governed by
    S6-31's own separate global offline-queue caps, never double-charged. Federated inbound `voice`
    payloads pass through this SAME sanitizer before local relay or offline storage (mirrors S6-53's
    own per-type federation-parity pattern) — a federation peer can no longer bypass local voice
    limits with an oversized `voice_data` field. Only the sanitized payload ever reaches
    `db_store()`.
    Both clients now independently bound `voice_data`/`signature`/`voice_id`/`duration` BEFORE
    signature verification, decryption, or base64/audio decoding — the server must never be either
    client's own memory-safety boundary. Beyond wire-size bounds, both also bound the DECRYPTED
    payload length (the base64 audio string `CryptoManager.decrypt()` returns) and the post-base64-
    decode raw-audio byte count before ever writing a file: Android's `AudioHelper.decodeAndSave()`
    now returns `null` (no file retained, no partial state) for anything malformed or oversized, and
    Desktop's equivalent inline decode path gained the identical checks. Both clients also now cap
    recording duration at 60 seconds — auto-stopping and sending exactly at the cap, matching the
    server's own product maximum — so a user can no longer create a voice message the server will
    later reject.
    Two things were found and are explicitly reported rather than silently fixed in this resource-
    bounding patch: (1) both clients sign only the encrypted `voice_data`, never `voice_id` or
    `duration` — a compromised server could in principle relabel those fields on an otherwise-
    validly-signed payload without invalidating the signature; `duration` is UI-metadata-only, but
    `voice_id` doubles as a local storage/file-naming key on both clients, so this is a follow-up
    semantic-authentication candidate, not addressed here. (2) group voice messages ride inside
    `group_message`'s own already-encrypted `text` field (`"VOICE:$duration:$base64"`), a separate
    code path this patch did not add server-side size bounds to (that's `group_message`'s own
    protocol, out of scope for a `voice`-message patch) — the shared client-side decode-helper
    hardening still protects that path's own decode step as a side effect.
    Regression-tested: maximum-legitimate-payload acceptance for both clients' own codecs, field-
    validation rejections (oversized/wrong-type `voice_data`, oversized/non-canonical `voice_id`,
    oversized `signature`, negative/bool/over-max `duration`), junk-field stripping, `from`-spoofing
    rejection, count-rate and all three byte budgets, offline-store sanitization, federated-inbound
    parity (oversized dropped, valid relayed sanitized), `MAX_PACKET_SIZE_BYTES` left unchanged, and
    an attack simulation confirming an over-ceiling `voice_data` is rejected before ever reaching a
    recipient and that repeated near-maximum-size sends are bounded by the sender/global/recipient
    budgets with no unbounded server-side retained state. Fixed 2026-09-06, see
    `KNOWN_SECURITY_ISSUES.md` S6-57.

71. **A voice message's end-to-end signature is domain separated and binds the authenticated audio
    payload to its canonical message identifier and security-relevant metadata. Relays may transport
    those fields but cannot change or rebind them without recipient-side signature failure.**
    Why: both platforms signed only the encrypted `voice_data` bytes via `CryptoManager.sign()`, with
    no domain separator and no binding of `voice_id`/`duration`/protocol type into the signed content
    — S6-57 bounded the SHAPE of every voice field but not its end-to-end authenticity. STEP-1 of this
    fix's own investigation found the concrete consequence, not a theoretical one: Android's
    `ChatStorage.saveOrUpdateMessage()` matches purely on `message.id`, so a relay relabeling `voice_id`
    to an EXISTING message id in that conversation (any type, including the user's own previously-sent
    message — `isOwn` plays no part in the match) silently overwrites that message's stored text and
    attachment paths; separately, both platforms derive their on-disk blob filename directly from the
    wire `voice_id` (`SecureFileStorage.blobFile(id)` on Android, `"$id.enc"` under a shared `blobs`
    directory on Desktop — the SAME naming scheme every attachment type uses) with an unconditional
    overwrite-on-write, so a relabeled `voice_id` colliding with ANY existing attachment id destroys and
    replaces that attachment's encrypted file content on both platforms, independent of any ChatStorage
    effect. This promotes the finding from the initially-assumed Medium to High. A related, distinct
    observation: multiple message types (message/edit/voice) all signed bare ciphertext with the same
    primitive and no domain separator, so a legitimately-produced signature for one type was, before
    this fix, trivially replayable as a voice signature for the same sender.
    Where: Android's `MessengerService.kt` (`sendVoice()`, the `"voice"` receive handler,
    `voiceSignatureTranscript()`); Desktop's `WebSocketClient.kt` (`sendVoice()`, the `"voice"` receive
    handler, `voiceSignatureTranscript()`) and `ChatScreen.kt` (`onFileReceived`'s voice-id-as-message-id
    fix); `server.py`'s `sanitize_voice_payload()` (inspected, confirmed to need no change).
    Both platforms now sign/verify a versioned, domain-separated V1 transcript —
    `"SUBROSA_VOICE_V1:" + voiceId + ":" + duration + ":" + encryptedData` — instead of bare ciphertext,
    using the same `SHA256withECDSA` primitive and no new keys. Delimiter concatenation is proven
    unambiguous rather than assumed: `voiceId` is validated as a canonical UUID (hex digits and hyphens
    only) before this is ever called, `duration` is rendered as a plain decimal integer, and
    `encryptedData` is standard-alphabet base64 (`CryptoManager.encrypt()`'s own output) — none of the
    three can ever contain `:`. Sender identity is already bound implicitly by which contact's public
    key verification selects (unchanged, same reasoning as every other signed control type in this
    file, e.g. `message_delete`); recipient identity is already bound implicitly by
    `CryptoManager.encrypt()`'s own per-recipient hybrid ECDH+ML-KEM encryption — decrypting with any
    OTHER recipient's private key already fails at the AES-GCM tag-check step regardless of this
    signature — so neither field was added to the transcript itself; both omissions are deliberate and
    documented at the transcript's own definition, not silent gaps. This is a hard cutover: there is NO
    legacy-signature fallback path, since a fallback would preserve exactly the vulnerability this fixes
    (a malicious relay simply presenting a legacy-shaped frame). Any voice message signed by a pre-S6-58
    client and still offline-queued server-side at upgrade time will fail verification on receipt and be
    dropped, identically to any other signature failure — an accepted, explicit tradeoff, not an
    oversight. Server-side, `sanitize_voice_payload()` required no change at all: `signature` was
    already relayed as an opaque, format-agnostic bounded string, and the server has no ability to
    verify an E2EE signature regardless of its shape (same reasoning as every other E2EE signature type
    in this protocol). A related finding surfaced and fixed along the way (STEP 9): once `voice_id` is
    authenticated, an exact replay of a genuinely valid signed voice frame must remain idempotent or
    otherwise bounded — Desktop's voice receive path previously generated a FRESH random UUID as its
    local message id on every single receive (only the on-disk blob filename used the wire `voice_id`),
    so a replayed authentic frame created an unbounded string of duplicate message entries; it now uses
    the (now-authenticated) `voice_id` directly as the local message id, exactly matching Android's own
    storage key, so a replay updates the same row in place instead of duplicating it. Both platforms now
    dedupe by `voice_id`, but deliberately checked AFTER signature verification succeeds rather than
    before (Desktop's own usual convention for `message`/`session_init`) — checking beforehand would let
    an attacker pre-emptively "burn" a legitimate `voice_id` with an unsigned or invalidly-signed frame,
    silently suppressing the real sender's later legitimate message as a false duplicate.
    Verified with a temporary cross-platform vector harness (Desktop's real `CryptoManager.sign()`/
    `verify()`, deleted after use, mirroring S6-54's identical harness pattern): the exact fixed test
    vector verifies; tampering `voice_id`, `duration`, or `voice_data` independently invalidates the
    signature; a legacy bare-ciphertext signature does not verify as a V1 transcript and a V1-transcript
    signature does not verify as legacy bare ciphertext (domain separation confirmed to hold in
    practice, not merely in the string-construction source); and the transcript construction matches the
    documented literal formula exactly. Regression-tested by inspection and a clean compile on both
    platforms (`compileDebugKotlin`/`compileKotlin`) — client-side signing/verification is not exercised
    by the Python suite, same posture as S6-54's own client-side coverage. Fixed 2026-09-06, see
    `KNOWN_SECURITY_ISSUES.md` S6-58.

72. **Anonymous delivery is a bounded transport, not an escape hatch from protocol validation. Its
    outer payload and aggregate/recipient traffic are hard-bounded before token consumption, and
    nested protocol data receives the same field and client-side validation as its direct
    equivalent without revealing or injecting the sender's authenticated identity.**
    Why: STEP-1's routing-matrix audit found that both official clients route essentially ALL
    bounded 1:1 protocol traffic — `message`, `session_init`, `reaction`, `edit`, `read`,
    `delivered`, `typing`, `message_delete`, `disappear_timer`, `group_message_delete`, `voice`,
    media chunks, and every 1:1 `call_*` signal — through the generic, opaque, sealed
    `anon_message`/`anon_delivery` transport (only Android's group calls bypass it, via a direct
    `sendWs()`). Anonymous token delivery was a generic multi-megabyte relay envelope with no
    protocol awareness of its own: real traffic routed through it bypassed S6-49/S6-51/S6-53/S6-57's
    own per-type sanitizers and resource bounds entirely, and per-connection byte counting alone did
    not bound aggregate anonymous traffic sent to one victim across many connections — promoted to
    High per the same "real traffic, not a theoretical edge case" criterion used for
    S6-56/S6-57/S6-58.
    Where: `server.py`'s `anon_message` handler (the `ANON_PAYLOAD_MAX_BYTES`/
    `ANON_DELIVERY_MAX_PACKET_SIZE_BYTES`/`ANON_PAYLOAD_ALLOWED_TYPES` constants and the rewritten
    handler block), `validate_voice_fields()`/`sanitize_voice_payload()` and
    `validate_chat_control_fields()`/`sanitize_chat_control()` (split into field-only + identity-
    adding halves), `anon_relay_conn_rate`/`anon_relay_global_rate`/`anon_relay_recipient_rate` and
    their `_rate_ok()` helpers; Android's `MessengerService.kt` (`ANON_DELIVERY_BLOB_MAX_LEN`, the
    `"anon_delivery"` branch of `handleMessage()`); Desktop's `WebSocketClient.kt`
    (`ANON_DELIVERY_BLOB_MAX_LEN`, the `"anon_delivery"` branch of `onMessage`).
    New `ANON_PAYLOAD_MAX_BYTES` (5.5 MiB) and `ANON_DELIVERY_MAX_PACKET_SIZE_BYTES` bound the outer
    envelope — derived from first-principles byte-math on a max-length sealed voice message's own
    hybrid-encrypt expansion, deliberately a distinct, smaller constant from the generic
    `MAX_PACKET_SIZE_BYTES` application ceiling rather than reusing it. A new
    `ANON_PAYLOAD_ALLOWED_TYPES` allowlist rejects any unrecognized visible type before token
    consumption. `sanitize_voice_payload()` and `sanitize_chat_control()` were split into field-only
    `validate_voice_fields()`/`validate_chat_control_fields()` halves (no `from`/`to`/`type`
    knowledge) plus the existing identity-adding wrapper, so the rare visible-type case (Desktop's
    seal-failure fallback, `sendAnonTokensTo`'s beacon-token shape) can reuse the SAME field
    validation the direct handlers use — including S6-54's required-signature rule for delete types
    — without the anonymous path ever learning or injecting a sender identity; call-signaling and
    media-chunk field reuse were deliberately left out of scope, since the generic envelope/byte
    bounds already close the actual bypass for those types and neither has an S6-54-style
    correctness rule whose absence matters on the anon path specifically. New per-connection
    (`anon_relay_conn_rate`, keyed by websocket object since `anon_channel` connections are
    identity-less by design), global (`anon_relay_global_rate`), and per-resolved-recipient
    (`anon_relay_recipient_rate`, keyed only after a token durably resolves to a real owner via
    `anon_token_state_cache` — never on a raw attacker-supplied token string) byte budgets layer on
    top of the existing per-connection limiter, closing the multi-connection bypass a single
    per-connection counter alone could not. Ordering was chosen deliberately so every new rejection
    — including the recipient-budget check — happens BEFORE `db_mark_anon_token_inflight()`'s
    durable claim, so a rejected oversized or over-budget send never burns the recipient's one-time
    token; this was made possible by using `anon_token_state_cache` (populated at claim time
    regardless of which RAM-cache path made the token known) rather than `token_owner` (populated
    only on the restart-restore and revoke paths) to resolve the recipient's identity for the budget
    check. Every new rejection path reuses the SAME externally-indistinguishable fake ack
    (`{"type": "ack", "id": msg_id}` if present, else silent) as every pre-existing `anon_message`
    rejection path, so none of this adds a new signal an attacker could use to distinguish why a
    send was rejected — anonymous semantics are unchanged. Client-side, Android's `handleMessage()`
    was confirmed by inspection to already be the single canonical dispatcher for both direct and
    anon-delivered payloads — no legacy alternate handler existed to consolidate — and Desktop's
    `anon_delivery` branch was confirmed to call the same `handleMessage(payload.toString())` used
    for direct dispatch; both platforms gained a new `ANON_DELIVERY_BLOB_MAX_LEN` (6 MiB) ceiling on
    the sealed `blob` string itself, checked before `CryptoManager.decrypt()` ever runs, so a
    compromised server handing a device an arbitrarily large sealed blob is rejected before any
    crypto work — a compromised server must never be this client's own memory-safety boundary, the
    same posture S6-57's `VOICE_WIRE_MAX_LEN` already established one layer in.
    Regression-tested (`test_s659_*`, 24 tests): routing-matrix regression, envelope size/allowlist
    bounds (acceptance at the exact ceiling, rejection one byte over), connection/global/recipient
    byte budgets (including self-pruning after the window and garbage tokens creating no recipient
    limiter state), token-lifecycle-safe rejection ordering (an oversized or over-budget send leaves
    the token ACTIVE, never burned), protocol-field-reuse bypass regressions (oversized visible
    voice data, tampered duration, unsigned visible delete — all rejected via field reuse or the
    envelope bound), and a many-channels/many-tokens/one-victim attack simulation confirming the
    recipient budget bounds aggregate traffic regardless of connection count. Client-side dispatcher
    consolidation and the blob-length bound were verified by source inspection and a clean compile
    on both platforms (`compileDebugKotlin`/`compileKotlin`), same posture as S6-54/S6-57/S6-58's
    own client-side coverage. Fixed 2026-09-08, see `KNOWN_SECURITY_ISSUES.md` S6-59.

73. **Applying a group-membership mutation from a remote message requires both a valid signature
    AND local authorization for the specific mutation being applied — never signature alone, and
    never `from`-blind self-attestation.** `group_invite_accepted`'s signature proves only that the
    named `new_member` consented to join; it is not proof that any admin invited them. A receiving
    device may apply it only if THAT DEVICE is itself the group's current admin (mirrors invariant
    12's own `actorId`/`isAdmin()` gate) — never unconditionally for any device that merely has the
    group locally.
    Why: Desktop applied `group_invite_accepted` unconditionally on any receiving device with no
    `from` check and no admin check at all — any attacker with a real account could self-sign
    `"$groupId:$theirOwnFingerprint"` and inject themselves into a target's local roster for any
    group_id they could name, with no invitation from an actual admin ever required. Impact wasn't
    cosmetic: a poisoned `members` list feeds `rotateGroupKey()`'s real fan-out, so a subsequent
    legitimate rotation on a poisoned-roster admin device would hand the real group AES key to the
    attacker's real identity key.
    Where: `WebSocketClient.kt`'s (Desktop) `handleGroupInviteAccepted()` — now calls
    `GroupManager.addMember(groupId, myFingerprint, newMember)`, letting `addMember()`'s own
    `isAdmin()` gate (invariant 12) reject the call unless the local device is admin. Matches
    Android's `MessengerService.kt`, which already used `actorId = username` (self) for exactly
    this reason. Existing (non-admin) members instead learn about a post-creation join via the
    authenticated `group_member_added` broadcast (signed by the actual admin, `groupId:add:newMember`),
    which had to be added to Desktop's dispatcher (it previously had none) and to the server's
    `ALLOWED_TYPES` (it wasn't relayable at all — the broadcast was silently dropped on every send,
    on every platform, despite `SECURITY.md` documenting it as the mechanism existing members learn
    a new member's key through). Separately, the server was found to silently drop the `signature`
    field when relaying `group_member_removed`/`group_invite_accepted` (unlike `group_key_rotation`,
    which always kept it) — both official clients require one on receive, so this broke the
    legitimate path end-to-end (fails closed, not a bypass, but the client-side checks above never
    got exercised by real relayed traffic before this fix).
    Regression-tested server-side (8 tests: unsigned-not-relayed/not-stored for both types, signed
    relays with signature preserved, `group_member_added` now relays / rejects unsigned). Client-side
    actor-gating and dispatcher changes verified by source inspection and a clean compile on both
    platforms (`compileDebugKotlin`/`compileKotlin`), same posture as S6-54/S6-57/S6-58/S6-59's own
    client-side coverage. Fixed 2026-09-08, see `KNOWN_SECURITY_ISSUES.md` S6-60.

74. **A cross-user `active_calls` mutation (writing/erasing someone ELSE's entry) must only
    happen if that entry currently, reciprocally, correlates with the exact peer + call_id being
    referenced.** A user's own entry remains freely writable by that user at any time.
    Why: `call_answer`/`call_end`/disconnect wrote/erased `active_calls[target]`/`active_calls[peer]`
    unconditionally — an unrelated authenticated account could name any victim as `to` and corrupt
    that victim's real bookkeeping, misdirecting the auto-call_end-on-disconnect notification.
    Where: `active_call_matches(user, peer, call_id)` in `server.py`, called under `lock` before
    every cross-user write in the `call_answer`/`call_end`/`call_group_leave`/disconnect paths.
    Fixed 2026-09-08, see `KNOWN_SECURITY_ISSUES.md` S6-61.

75. **`federated_forward` admission must bound aggregate BYTES, not just message count.**
    Why: `FED_FORWARD_PER_IP_LIMIT`/`GLOBAL_LIMIT` bounded frame count only — a compromised
    authenticated peer could send many near-`FEDERATION_MAX_PACKET_SIZE_BYTES` (12 MiB) frames,
    forcing unbounded `json.loads()`/reserialization/relay/store work per window.
    Where: `FED_FORWARD_MAX_PAYLOAD_BYTES` (hard per-payload cap) plus
    `fed_forward_byte_rate_per_ip_ok()`/`_global_ok()`/`_recipient_ok()` in `server.py`, checked
    once the inner payload is serialized, before dedup reservation/clients lookup/send_safe/db_store.
    Fixed 2026-09-09, see `KNOWN_SECURITY_ISSUES.md` S6-62.

76. **Database upgrades preserve anonymous-token ownership and lifecycle state**: legacy
    `anon_token_state` schemas are transactionally migrated to the current state machine before
    serving traffic, without deleting or resetting token state.
    Why: `CREATE TABLE IF NOT EXISTS` doesn't widen an existing CHECK constraint — a pre-IN_FLIGHT
    database silently kept rejecting ACTIVE→IN_FLIGHT forever, an upgrade/reliability gap the old
    code only documented in a comment, never closed.
    Where: `_migrate_anon_token_state_check_constraint()` in `server.py`, called first thing inside
    `_db_setup_sync()`. Detects the legacy CHECK via `sqlite_master.sql`, rebuilds
    create-copy-validate-drop-rename, and raises (crashing startup) rather than proceeding on any
    row-count or state-value mismatch.
    Fixed 2026-09-09, see `KNOWN_SECURITY_ISSUES.md` S6-63.

77. **`group_create`'s signature must bind `group_id`, `group_name`, and `group_avatar`, not just
    the encrypted key blob.**
    Why: a signature over `encrypted_group_key` alone let a relay relabel `group_id`/name/avatar on
    an otherwise-validly-signed invitation, durably creating a spoofed/duplicated local group
    attributed to a real sender (existing-group overwrite was already independently blocked by the
    `getGroup(groupId) != null` no-op on both platforms).
    Where: `groupCreatePayload()` on both platforms — `"SUBROSA_GROUP_CREATE_V1:groupId:len(name):
    name:len(avatar):avatar:encryptedGroupKey"`, length-prefixing the two free-text fields so no two
    (name, avatar) pairs can collide to the same transcript. No legacy fallback.
    Fixed 2026-09-09, see `KNOWN_SECURITY_ISSUES.md` S6-64.

78. **`group_create`'s signed member/admin roster must actually reach the recipient**, not be
    dropped in transit — the server relays/bounds it but never cryptographically verifies it
    (that stays each client's job, against its own `roster_signature` check).
    Why: the server previously stripped `members`/`admins`/`roster_signature` on every relay path,
    so every recipient silently fell back to an unauthenticated `[from, self]` guess — any group
    >2 people had a permanently wrong roster on every non-admin invitee.
    Where: `validate_group_roster()` in `server.py`, gating the shared online/offline/federated-
    outbound `group_create` payload and the `federated_forward` incoming dispatch. Both clients
    now require the roster — no unsigned fallback for a current-version `group_create`.
    Fixed 2026-09-09, see `KNOWN_SECURITY_ISSUES.md` S6-65.

79. **A sealed `anon_delivery` inner message with no independent per-message signature of its own
    must not be dispatched unless its sender_cert verifies** — cert-check failure/absence must
    reject, not merely log.
    Why: `session_reset`/call signaling/`contact_ping`/`pq_bundle_refresh` carry no signature of
    their own; the sender_cert check was log-only, so any anon-token holder could claim any `from`
    and, e.g., delete a victim's session with an arbitrary third party.
    Where: `ANON_DELIVERY_REQUIRES_IDENTITY_SIGNATURE` in `MessengerService.kt`/
    `WebSocketClient.kt`, checked before `handleMessage()`. Originally required a verified
    `sender_cert`, replaced by an end-to-end identity signature (`controlEnvelopeTranscript()`,
    the sender's own long-term key) — a per-server signing-key pin is not a valid trust anchor for
    arbitrary self-hosted servers, and was still an unconfigured placeholder besides.
    Fixed 2026-09-09, see `KNOWN_SECURITY_ISSUES.md` S6-66.

80. **Anonymous-token lifecycle state is strictly node-local. No federation connection or
    federated payload may invoke or influence token claim (ACTIVE), the ACTIVE→IN_FLIGHT
    transition, delivery ACK, SPENT/REVOKED terminalization, `token_pending`, or token ownership
    mappings (`token_to_ws`/`ws_to_tokens`).**
    Why: allowing a federation peer to confirm or mutate token lifecycle would let possession of
    `FEDERATION_SECRET` (a server-to-server credential) substitute for actual recipient possession
    of a token — a compromised/malicious peer could then forge delivery confirmation (falsely
    terminalize a real token to SPENT before the real recipient ever saw the message), double-spend
    a token across two nodes, corrupt ownership, or clear a legitimate fallback copy out from under
    its real owner. This is invariant 51 applied to one specific, previously-unverified boundary —
    resolves `KNOWN_SECURITY_ISSUES.md` OPEN-6, which asked whether this had ever actually been
    traced end-to-end against the code (it had not, until 2026-09-25).
    Where enforced: `FEDERATED_FORWARD_ALLOWED_TYPES` (invariant 51) excludes every anon-token wire
    type — `anon_message`, `anon_delivery`, `anon_delivery_ack`, `anon_delivery_ack_ok`,
    `subscribe_tokens`, `subscribe_tokens_result`, `unsubscribe_tokens` — so
    `validate_federated_forward_payload()` drops any of them wrapped as a `federated_forward` inner
    payload before any dedup/delivery/DB work runs. Separately, none of `anon_message`/
    `anon_delivery_ack`/`subscribe_tokens`/`unsubscribe_tokens`'s own handlers ever call
    `forward_to_peers()` at all (grepped every call site in `server.py`) — the exclusion is
    structural on both the outbound and inbound surface, not merely a single allowlist check that
    could be bypassed by a different code path. `handle_federation_peer_incoming()`'s own dispatch
    is a closed `if`/`elif` chain over exactly three types (`federated_forward`, `peer_announce`,
    `federated_get_bundle`) with no fallback into the general `ALLOWED_TYPES` client loop, so a
    federation-authenticated connection (`is_fed=True`) cannot reach `db_claim_anon_tokens()`/
    `db_mark_anon_token_inflight()`/`db_terminalize_anon_token()` by any route, direct or nested.
    `anon_delivery_ack`'s own ownership check (`token_to_ws.get(token) is <this connection>`,
    invariant 2's connection-identity-binding requirement) is therefore never reachable from a
    federation-authenticated connection in the first place — the local check and the federation
    exclusion are independent, redundant layers, not a single point of failure.
    Regression-tested: `Server/tests/test_security_invariants.py`'s OPEN-6 section —
    `ANON_TOKEN_FEDERATION_FORBIDDEN_TYPES` disjoint from `FEDERATED_FORWARD_ALLOWED_TYPES`;
    `anon_message`/`anon_delivery_ack`/`subscribe_tokens`/`unsubscribe_tokens` never call
    `forward_to_peers()` during a real send/ack/claim/revoke cycle; each of the seven forbidden
    types, wrapped as a `federated_forward` inner payload, is dropped before reaching a local
    client or `db_store()`; a real ACTIVE token's state is provably unchanged after a malicious
    peer tries to smuggle an `anon_message` claim for it; a real IN_FLIGHT token's state (and its
    `token_pending` entry) is provably unchanged after a malicious peer tries to smuggle an
    `anon_delivery_ack`, and the real local owner's ACK still works correctly afterward; a real
    ACTIVE token cannot be revoked via a smuggled `unsubscribe_tokens`; a federation peer sending
    an anon-token type directly as its own connection's `type` (unwrapped) is a no-op that doesn't
    disturb the connection's normal federation traffic afterward. Fixed by verification/tests only
    2026-09-25 — no production code changed, because the trace found no reachable gap to close.
    Separate, already-tracked residual risk this invariant does NOT close: invariant 51's own
    documented `from`-spoofing limitation (a canonical-shaped `from` on an otherwise-ALLOWED
    federated type proves syntax, not that the sending peer actually owns/serves that fingerprint)
    — unrelated to anonymous-token lifecycle, since none of the anon-token types are
    federation-allowed to begin with.

---

*Maintenance note: when a fix in this codebase closes a gap that reads like "X must always/never
happen," consider whether it belongs here as a new invariant, not just as a changelog entry in
`SECURITY_CHANGELOG.md`/`KNOWN_SECURITY_ISSUES.md`. Changelog entries describe what changed;
invariants describe what a reviewer should be able to check right now, independent of history.*
