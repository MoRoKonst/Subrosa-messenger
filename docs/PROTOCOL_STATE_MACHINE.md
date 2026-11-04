# Protocol State Machine

*Created 2026-08-30, extended 2026-09-03 with §7 (Double Ratchet epoch handling) and, later the
same day, §8 (registration gates) plus a full rewrite of §1/§2 (anonymous-token durability). This
document exists because the actual bug history of this project (recorded across
`SECURITY_CHANGELOG.md`, `KNOWN_SECURITY_ISSUES.md`, `TODO.md`, `ISSUE_backup_identity_hijack.md`)
is dominated by state-consistency bugs — token lifecycle, mailbox, retry/ack, bootstrap, Double
Ratchet epoch/backup-restore interaction, and (as of §8) registration/device-authentication gate
ordering — not the underlying primitives (AES-GCM, HKDF, Argon2id) themselves, which have had
comparatively few issues. An auditor reconstructing this state machine from `server.py`/client
prose and scattered comments is exactly the failure mode this document is meant to prevent. States
and transitions below are transcribed from the actual code (file:line references given where
stable); if a reference has drifted, that is a documentation bug, not evidence the described
behavior no longer holds — check the code.*

This describes **server-observable state** — what `server.py` tracks, not client-internal state
(the client has its own bookkeeping in `AnonTokenManager.kt`/`ChatStorage.kt` that mirrors parts
of this from the client's perspective, deliberately without the server ever seeing it — see
`SECURITY.md` item 33 for why some of this state is intentionally *not* mirrored server-side).

---

## 1. Anonymous token lifecycle

Anonymous tokens are the routing primitive that lets `anon_message` reach a recipient without the
server needing to know the recipient's identity — see `SECURITY.md` items 12/31/32 for why this
exists.

**Rewritten 2026-09-03** (external review, six-round chain of findings) — the entire durability
model changed. The original design (`known_tokens`/`token_to_ws`/`token_pending`/`spent_tokens` as
plain in-memory dicts/sets, "lost on restart by design") is what `MESSAGE_DELIVERY.md`'s PROTO-02
and `KNOWN_SECURITY_ISSUES.md`'s OPEN-8 flagged as a real replay/hijack window: a server restart
reset ownership and spent-state at once, so (a) a token's *ownership* could be silently
re-claimed by a different account after a restart before the real owner reconnected, and (b) a
token already spent before the restart looked unspent again afterward, reopening replay. Both are
now closed by making the durable SQLite table below, not RAM, the source of truth — the RAM
dicts/sets that remain are fast caches in front of it, not the record of state itself.

### States (per token value)

```
                    ┌─────────────┐
                    │  (no row)   │  never claimed by anyone
                    └──────┬──────┘
                           │ subscribe_tokens — first-claim-wins, atomic
                           │ (db_claim_anon_tokens, BEGIN IMMEDIATE: two
                           │  connections racing to claim the same
                           │  never-before-seen token, only one becomes
                           │  its durable owner)
                           ▼
                    ┌─────────────┐
        ┌───────────┤   ACTIVE    │◄──────────────┐
        │           │ (routable,  │                │
        │           │  owner durable) │             │
        │           └──────┬──────┘                │
        │                  │ anon_message accepted —│ subscribe_tokens
        │                  │ atomic ACTIVE→IN_FLIGHT│ (re-registers after
        │                  │ (db_mark_anon_token_    │  reconnect — owner
        │                  │  inflight); a SECOND    │  is read from SQLite,
        │                  │ anon_message on the     │  not re-derived from
        │                  │ same token, before ack, │  whichever connection
        │                  │ gets the same           │  happens to be live)
        │                  │ indistinguishable        │
        │                  │ fake-ack as unknown/     │
        │                  │ spent — first-write-wins │
        │                  ▼                          │
        │           ┌─────────────┐                  │
        │           │  IN_FLIGHT  │──────────────────┘
        │           │ (durable —  │
        │           │  survives   │
        │           │  restart)   │
        │           └──────┬──────┘
        │        ┌─────────┼─────────────────┐
        │  anon_delivery_ack   24h TTL expiry   server restart while
        │  (owner acks)        (watchdog)       still IN_FLIGHT — the
        │        │                 │            queued payload (RAM-only
        │        ▼                 ▼            token_pending) is gone
        │   ┌─────────┐      ┌─────────┐        either way; fail-closed
        │   │  SPENT  │      │  SPENT  │        startup sweep forces
        │   └─────────┘      └─────────┘        IN_FLIGHT → SPENT rather
        │                                       than leaving a token that
        │                                       looks ACTIVE again with no
        │                                       hope of ever being acked
        │
        │ unsubscribe_tokens (owner explicitly revokes,
        │ from ACTIVE or IN_FLIGHT — e.g. contact
        │ compromised, SECURITY.md item 33; no longer
        │ gated on this connection's live routing state,
        │ see below)
        ▼
   ┌─────────┐
   │ REVOKED │   (SPENT and REVOKED are both terminal;
   └─────────┘    a terminal state is never re-opened)
```

### Durable source of truth (`server.py`, SQLite `anon_token_state` table)

```sql
CREATE TABLE anon_token_state (
    token_hash          BLOB PRIMARY KEY,   -- SHA-256(token); the raw token is
                                             -- never stored, only enough to recognize
                                             -- one presented later
    owner                TEXT NOT NULL,
    state                TEXT NOT NULL CHECK(state IN ('ACTIVE','IN_FLIGHT','SPENT','REVOKED')),
    bootstrap_reserved    INTEGER NOT NULL DEFAULT 0,
    bootstrap_reserved_by TEXT,             -- see § "Bootstrap token reservation" below
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
)
```

Every write to this table is a single atomic statement, not a separate SELECT-then-UPDATE:

- **`db_claim_anon_tokens()`** — first-claim-wins ownership, `BEGIN IMMEDIATE` + `INSERT` for a
  never-seen token, plain read for an already-claimed one. Called from `subscribe_tokens`.
- **`db_mark_anon_token_inflight()`** — `UPDATE ... WHERE state = 'ACTIVE'`, rowcount tells the
  caller whether *this* call actually won the transition. Called from `anon_message`, before the
  message is ever queued into `token_pending`.
- **`db_terminalize_anon_token()`** — the single function both `anon_delivery_ack` (→ SPENT) and
  `unsubscribe_tokens` (→ REVOKED) call, plus the TTL watchdog (→ SPENT). One conditional `UPDATE
  ... WHERE owner = ? AND state IN ('ACTIVE','IN_FLIGHT')`, `rowcount == 1` is the only signal of
  success — an earlier version read state first and only conditionally wrote, which returned
  `True` even when the token was already terminal and nothing actually changed, letting a stale
  RAM-cache write silently stamp a state that never happened in the DB (e.g. a TTL-watchdog SPENT
  racing a genuinely-just-happened REVOKED). Also clears `bootstrap_reserved`/
  `bootstrap_reserved_by` in the same statement.

**Node-local, never federated** (traced end-to-end 2026-09-25, closing `KNOWN_SECURITY_ISSUES.md`
OPEN-6): none of these three functions, and none of the four wire types that drive them
(`subscribe_tokens`, `anon_message`, `anon_delivery_ack`, `unsubscribe_tokens`), are reachable from
a federation-authenticated connection — see `SECURITY_INVARIANTS.md` #80 for the full trace and the
regression tests that enforce it. A federation deployment therefore has one authoritative
`anon_token_state` table per node, with no cross-node claim/ACK/revoke traffic at all.

**RAM caches remain, but are just caches now**: `token_owner`/`spent_tokens`/
`anon_token_state_cache` (a full `{token_hash: (owner, state)}` mirror, loaded once at startup so
the unauthenticated `anon_channel` hot path never needs a per-token DB round-trip — see the DoS
note below) exist purely so `subscribe_tokens`/`anon_message` don't pay a DB round-trip for every
already-resolved token. **Invariant, enforced everywhere this cache is written**: a terminal
(SPENT/REVOKED) entry is never overwritten by a fresher-looking non-terminal write — every writer
(`anon_message`'s IN_FLIGHT commit, `anon_delivery_ack`, `unsubscribe_tokens`, the TTL watchdog,
and `subscribe_tokens`'s own claim-resolution loop) checks the current cached state under the same
`lock` it writes under, and refuses to downgrade a terminal state back to IN_FLIGHT/ACTIVE. See
`SECURITY_INVARIANTS.md` for this stated as a standalone invariant.

**Why the cache isn't a per-token DB lookup instead**: an earlier version of this fix used a
per-unknown-token `SELECT` as a RAM-cache-miss fallback in `anon_message` — reasonable-looking,
but `anon_channel` connections are unauthenticated with only a per-connection rate limit
(`ANON_CHANNEL_MAX_PER_MINUTE`), so a flood of fake/decoy tokens (indistinguishable from cover
traffic by design) would each trigger a real DB round-trip. Loading the full table into RAM once
at startup, and keeping it in sync on every write, keeps the "is this even a real token" check
O(1) in memory regardless of how many decoys arrive.

**Fail-closed restart sweep**: on startup, `_db_setup_sync()` forces every still-IN_FLIGHT row to
SPENT, *before* `anon_token_state_cache` is loaded. `token_pending` (the queued payload) is
RAM-only and always empty right after a restart — a token that was IN_FLIGHT when the process
died has no path to ever being delivered/acked again regardless of what its SQLite state says, so
leaving it ACTIVE-again would let it be spent a second time for nothing, and leaving it IN_FLIGHT
forever would zombie it (server refuses a new send, owner's client has no signal to stop treating
it as spendable). Forcing it to SPENT closes both: the security priority (a token capability never
outlives the one message it was claimed for) is chosen over the reliability one (that one message
is lost) — an accepted, explicit trade-off, not an oversight.

**TTL watchdog now durably closes what it sweeps, not just RAM**: `token_pending_watchdog()`
(hourly, `TOKEN_PENDING_TTL_SEC = 24h`) used to just pop the RAM `token_pending` entry. Since a
`token_pending` entry only ever exists for a token that's IN_FLIGHT, leaving the token's SQLite
state untouched after this sweep was the exact same restart-sweep zombie case above, just
triggered by TTL instead of a process restart. The watchdog now calls the same
`db_terminalize_anon_token()` → SPENT path, and — best-effort, if the owner happens to be online —
sends `subscribe_tokens_result: {"spent": [token]}` immediately so the owning client can drop it
without waiting for its next reconnect's reconciliation.

### `unsubscribe_tokens` — durable ownership is the gate, not live connection routing

**Changed 2026-09-03**: revocation used to require `t in ws_to_tokens[websocket]` — the token had
to currently be routed to *this exact connection*. That's an artifact of when ownership itself was
RAM-only; now that `db_claim_anon_tokens()` makes SQLite ownership authoritative, gating revocation
on live routing was an unnecessary restriction with a real gap — right after a reconnect, before
the next `subscribe_tokens` re-establishes routing, an owner temporarily couldn't revoke their own
token. `unsubscribe_tokens` now attempts every token the client claims and lets
`db_terminalize_anon_token()`'s own `owner = ?` check be the actual authorization: a stranger's
token still can't be revoked (rowcount 0), but the authenticated owner can revoke a token
regardless of which connection currently has it routed.

### Bootstrap token reservation (`pick_bootstrap_token`)

A separate but related durability/DoS story, evolved over several rounds the same day — see
`SECURITY.md` item 11's "Bootstrap token" mechanism for what this is for. Final shape:

- **Durable, not RAM-only**: `bootstrap_reserved`/`bootstrap_reserved_by` (columns on the same
  `anon_token_state` row) survive both disconnect and restart — an earlier RAM-only version
  forgot a reservation on disconnect (routine, frequent) or restart, letting the exact same token
  be handed to a second requester while the first might still use it.
- **Per-(target, requester), not global**: a bare "is this token reserved by *someone*" flag let
  one authenticated account repeatedly call `get_prekey_bundle(target)`/
  `get_prekey_bundles_batch` and mint a *new* reservation each time — reserving a target's entire
  token pool in minutes without ever sending one real message, a pure-DoS exhaustion of that
  target's ability to receive a bootstrap from anyone else. `db_resolve_bootstrap_token()` now
  looks up the specific `(target, requester)` pair first: an existing ACTIVE reservation returns
  the *same* token again (repeated fetches become `T1 → T1 → T1`, not `T1 → T2 → T3`); an existing
  IN_FLIGHT one (a real send already in flight) returns nothing rather than a second concurrently
  outstanding token for the same pair; only with no existing reservation does it atomically claim
  a fresh one.
- **Never re-reserves once terminal**: `db_terminalize_anon_token()` clears both bootstrap columns
  in the same statement as the state transition — a token that's SPENT/REVOKED can't still look
  reserved.
- **Cost of durability, stated plainly**: an unused bootstrap reservation is never automatically
  returned to the pool — the old requester might still use it. The only way a reservation clears
  is the underlying token itself reaching a terminal state. Bounded because tokens are finite and
  eventually terminalize (ACK, TTL, restart sweep, or revoke), not because reservations expire on
  their own.

### Client-side pool discipline (not server-visible)

The client (`AnonTokenManager.kt`) maintains its own pool of ~50 unspent tokens
(`ensureMyTokenPool()`, additive-only) and shares batches of 20 with contacts on resupply
(`freshTokensToShare()`). **Invariant** (see `SECURITY_INVARIANTS.md` #8): the pool may only
shrink through actual spend, never through blind position-based truncation — a 2026-08-30 fix
closed exactly this bug class, where `.take(POOL_SIZE)` could silently evict a still-outstanding
token a contact was holding, producing a permanent "offline, message queued" state with no
self-healing path (distinct from a genuine race, which self-heals via `token_pending`
flush-on-resubscribe within seconds).

---

## 2. `anon_message` delivery / retry / ack

**Rewritten 2026-09-03** alongside § 1 above — the commit into `token_pending` is now gated by
the same durable ACTIVE→IN_FLIGHT transition described there, not a RAM-only check.

```
Sender                                Server                              Recipient
  │                                     │                                     │
  │── anon_message{token,payload} ────►│                                     │
  │                                     │ RAM/cache fast-path: is this a      │
  │                                     │ known, non-terminal token at all?   │
  │                                     │   NO → fake ack (indistinguishable  │
  │                                     │        from a real send/from a      │
  │                                     │        cover-traffic decoy)         │
  │                                     │   YES → continue                    │
  │                                     │                                     │
  │                                     │ db_mark_anon_token_inflight(token)  │
  │                                     │ — atomic ACTIVE→IN_FLIGHT, durable  │
  │                                     │   None → same fake ack (already     │
  │                                     │   IN_FLIGHT/SPENT/REVOKED, or a      │
  │                                     │   race lost to a concurrent send —   │
  │                                     │   this IS the first-write-wins       │
  │                                     │   enforcement: a token can be        │
  │                                     │   committed to token_pending by AT   │
  │                                     │   MOST one anon_message before it's  │
  │                                     │   acked, not "whichever send         │
  │                                     │   happened to run last")             │
  │                                     │   owner → continue, commit to        │
  │                                     │   token_pending under `lock`,        │
  │                                     │   never overwriting an ALREADY       │
  │                                     │   terminal cache entry a concurrent  │
  │                                     │   ack/revoke/TTL-sweep may have      │
  │                                     │   written in the same window         │
  │                                     │                                     │
  │                                     │ target_ws = token_to_ws.get(token)  │
  │                                     │                                     │
  │                          ┌──────────┴──────────┐                         │
  │                          │  target_ws is live?  │                         │
  │                          └──────────┬──────────┘                         │
  │                    YES ─────────────┤───────────── NO                    │
  │                     ▼                              ▼                     │
  │         send immediately              store in token_pending[token],     │
  │         AND store in                  wait for owner's next              │
  │         token_pending (fallback       subscribe_tokens (flush) or        │
  │         copy — see note below)        24h TTL sweep (durably SPENDS      │
  │                                       the token, not just a drop —       │
  │                                       see § 1's watchdog note)           │
  │                                     │                                     │
  │                                     │── anon_delivery{payload} ─────────►│
  │                                     │                                     │
  │                                     │◄── anon_delivery_ack{token} ───────│
  │                                     │                                     │
  │                                     │ token_to_ws.get(token) is this ws?  │
  │                                     │   NO → ignored, logged (stale ack   │
  │                                     │   from a superseded connection)     │
  │                                     │   YES → db_terminalize_anon_token   │
  │                                     │   (token, owner, "SPENT") — durable │
  │                                     │   BEFORE any RAM cleanup; only on   │
  │                                     │   success does token_pending/       │
  │                                     │   token_to_ws/spent_tokens/cache    │
  │                                     │   actually clear, all under one     │
  │                                     │   `lock` alongside the cache write  │
  │◄── anon_delivery_ack_ok ───────────│                                     │
```

**Why a live delivery also writes a `token_pending` fallback copy**: if the recipient's
connection drops between delivery and ack (network flap mid-message), the message must not be
lost — the fallback copy is what a reconnect-triggered `subscribe_tokens` flushes. This is the
same "queue rather than lose" principle applied elsewhere in this protocol (see § 4 below).

**Ack requirement, not just delivery**: `anon_delivery_ack` is what actually retires a token to
SPENT — a message that reaches the client but crashes before the client acks it is still
retryable (`SECURITY_CHANGELOG.md` item 18's "fake ack" fallback-copy mechanism exists for
exactly this).

**`anon_delivery_ack_ok` reconciliation**: if the ack itself lands durably (SQLite already says
SPENT) but this final confirmation is what gets lost — a real possibility, it's sent over the same
network as everything else — the client would otherwise wait forever for a delivery its recipient
already durably has. `subscribe_tokens_result: {"spent": [...]}` closes this: any token the client
resubscribes to that the server already durably considers terminal is reported back explicitly,
so the client's own ACK_PENDING bookkeeping (`AnonTokenManager.markMyTokenAckPending`/
`confirmMyTokenAcked`) can resolve on the next reconnect even if the direct confirmation never
arrived. The same mechanism is what makes the TTL-watchdog's SPENT transition (§ 1) visible to the
token's owner without a separate notification channel.

---

## 3. `anon_channel` — de-identified submission connection

State machine for the *connection itself*, distinct from the per-token states above. See
`ARCHITECTURE.md`'s `anon_channel` subsection and `SECURITY.md` item 32 for the full rationale.

```
        ┌───────────────┐
        │  DISCONNECTED │
        └───────┬───────┘
                │ main socket reaches handshake_ok/register
                │ (client schedules connectAnonChannel() after
                │  a randomized 0–3s delay — deliberately not
                │  immediate, see ARCHITECTURE.md)
                ▼
        ┌───────────────┐
        │  CONNECTING   │
        └───────┬───────┘
                │ server responds `challenge`
                │ client replies {"type":"anon_channel"} — no
                │ public key, no signature
                ▼
        ┌───────────────┐
        │  is_anon_channel│  (server never assigns username;
        │  = true, awaiting│  restricted to exactly one message
        │  anon_channel_ok │  type for the rest of the connection's
        └───────┬───────┘  life: anon_message — anything else
                │            closes the connection immediately)
                │ server sends anon_channel_ok
                ▼
        ┌───────────────┐
        │     READY     │──── anon_message sends flow through
        └───────┬───────┘     directly (paced, AGGRESSIVE mode
                │              queue — real traffic and decoys
                │              indistinguishable by timing)
                │ connection drops (network flap, server restart)
                ▼
        ┌───────────────┐
        │  DISCONNECTED │──── back to top; client-side sends attempted
        └───────────────┘     during the gap queue into
                               anonChannelPendingQueue and flush once
                               READY again — there is NO fallback to
                               the identified main socket (removed
                               2026-08-29, see SECURITY.md item 32's
                               "No identified-socket fallback" bullet)
```

**Anti-abuse without identity**: this connection has no `username` to key `rate_limit_check()`
on, so abuse containment is a per-connection counter (`anon_channel_count`,
`ANON_CHANNEL_MAX_PER_MINUTE`, reset every 60s) plus the pre-existing cheap `is_known`/`is_spent`
rejection from § 2 above — a flood of garbage tokens over this channel is no cheaper to mount
than over the main socket.

---

## 4. Anonymous-mailbox first-contact bootstrap

This is the "cold outreach" path — before any token relationship exists between two parties, and
before a shared secret exists to derive one from.

```
Alice (inviter)                                      Bob (invitee)
  │                                                       │
  │  1. Generate invite code: ECDSA-signed blob            │
  │     containing a one-time mailbox tag                  │
  │     (InviteCodeManager — see SECURITY.md               │
  │     "Invite Codes")                                    │
  │                                                       │
  │  2. Alice polls the mailbox tag for a deposit           │
  │     (client-side polling, not server push — the         │
  │     server has no reason to know Alice cares            │
  │     about this specific tag ahead of time)               │
  │                                                       │
  │──── (out-of-band: code shared with Bob) ─────────────►│
  │                                                       │
  │                                    3. Bob parses code, verifies
  │                                       signature+TTL (7 days from ts),
  │                                       extracts mailbox tag + Alice's
  │                                       identity key
  │                                                       │
  │                                    4. Bob deposits a session_init
  │                                       (his own identity key + a
  │                                       hybrid-encrypted bootstrap
  │                                       payload) tagged with Alice's
  │                                       mailbox tag — this deposit
  │                                       call IS identified (Bob's own
  │                                       username), see gap below
  │                                                       │
  │◄─── Alice's poll picks up the deposit ────────────────│
  │                                                       │
  │  5. Alice decrypts, calls processSessionInit() —       │
  │     ChatStorage.isBlocked(from) checked FIRST, before  │
  │     any side effect (SECURITY.md item 33)              │
  │                                                       │
  │  6. If not blocked: saveContactPublicKey,               │
  │     SessionKeyManager.receiveSession,                   │
  │     requestPrekeyBundle → establishes Double Ratchet    │
  │     session, hybrid PQ (SECURITY.md's Post-Quantum       │
  │     Hybrid section)                                     │
```

**Known gap, not closed by sealed sender**: unlike § 2/§ 3 above, this bootstrap path remains
identified in both directions — `get_prekey_bundle`/`get_prekey_bundles_batch`
run over the normal authenticated socket, so both Alice's and Bob's `username` are known to the
server for this exchange. See `SECURITY.md` item 11's residual-gaps note. This is a genuinely
open problem, not an oversight — establishing a relationship from nothing requires *some* way for
the server to route the first message, and no anonymous-mailbox-only mechanism for that currently
exists in this protocol.

### Prekey-batching (partial mitigation of the bootstrap identification above)

```
Requester                                          Server
  │                                                   │
  │── get_prekey_bundles_batch                        │
  │   {targets: [real_target, decoy1, decoy2, ...]} ─►│
  │                                                   │  decoys drawn from requester's
  │                                                   │  OWN existing contacts (must be
  │                                                   │  real fingerprints — a self-created
  │                                                   │  "ghost" decoy would be
  │                                                   │  distinguishable over time by
  │                                                   │  never carrying real traffic)
  │◄── prekey_bundles_batch_response                  │
  │    {bundle per target, each stamped with           │
  │     a bootstrap_token from that target's           │
  │     own anon-token pool} ──────────────────────────│
```

**Residual gaps** (see `SECURITY.md` item 11 for full detail, not repeated here): decoys leak the
requester's real contact list to the server; batch size below `MAX_BATCH_BUNDLE_TARGETS` leaks an
approximate contact-list size; and a requester with **no other contacts to use as decoys** falls
back to a plain `get_prekey_bundle` naming the real target, which is server-visible and silent
(`requestPrekeyBundle()` states this openly — a batch of size 1 provides no cover, so it does not
pretend otherwise). That last one is the live gap listed as item 5 in § 6 below.

**Corrected 2026-11-03**: this list previously ended with "if the target's bundle-serving path has
no bootstrap token to attach, the client silently downgrades to direct fingerprint addressing with
no user-visible warning." **That fallback no longer exists.** On a first message with no bootstrap
token and no anon token, the client routes through the anonymous mailbox
(`depositSessionInitViaMailbox`, carrying the full `session_init` sub-packet so the recipient's
session state ends up identical to a direct delivery), and if no mailbox tag/key is cached either
it queues into `pendingSessionMessages` and retries via `requestPrekeyBundle` — it never falls
back to fingerprint addressing. That direct `sendWs()` fallback was removed 2026-08-23 precisely
because it contradicted `SECURITY.md`'s "no fingerprint-addressed fallback" claim for the
first-contact case, and § 6 item 2 below already records its removal. The stale sentence mattered
because it sat in the "Residual gaps" block — where a reviewer looks for what is still open — and
described a dead gap in wording close enough to be confused with the live one above it.

---

## 5. Group key rotation

**Corrected 2026-09-25**: this section used to show only the removal-triggered path and call
addition-without-rotation a "known gap, accepted trade-off" (`KNOWN_SECURITY_ISSUES.md` OPEN-7).
That gap is now closed — addition rotates too, reusing the same wire message and per-member-encrypt
mechanism. Both trigger paths:

```
Admin                                Server                          Members
  │                                    │                                │
  │  removeMember(actor=admin,          │                                │
  │  target=X) — verified admin,        │                                │
  │  X excluded from what follows       │                                │
  │        — OR —                       │                                │
  │  addMember(actor=admin, target=N)   │                                │
  │  — new member N added to roster     │                                │
  │  first, THEN excluded from the      │                                │
  │  rotation recipient list below      │                                │
  │  (N gets the fresh key a different  │                                │
  │  way, see below — not by receiving  │                                │
  │  a group_key_rotation of its own)   │                                │
  │                                    │                                │
  │  generateGroupKey() → fresh key     │                                │
  │  For each member M that should      │                                │
  │  already hold the key (all          │                                │
  │  remaining members on removal; all  │                                │
  │  PRE-existing members on addition,  │                                │
  │  i.e. not the brand-new N):         │                                │
  │    encryptGroupKeyForMember(M)      │                                │
  │    (hybrid ECDH+ML-KEM, per-member  │                                │
  │    ciphertext — server can't        │                                │
  │    decrypt any of them)             │                                │
  │                                    │                                │
  │── group_key_rotation                │                                │
  │   {group_id, encrypted_new_key,     │                                │
  │    signature} (per member) ────────►│── group_key_rotation ─────────►│
  │                                    │  (on removal: X is not in the    │
  │                                    │   recipient list — never sent    │
  │                                    │   the new key)                   │
  │                                    │                                │
  │                     Recipient side: verify signature over
  │                     "$groupId:$encryptedNewKey", THEN verify
  │                     GroupManager.isAdmin(from) — both required
  │                     before decrypting/saving (SECURITY_INVARIANTS.md #13)
```

**On addition specifically**: the admin saves the fresh key locally *before* sending the new
member's own `group_create` invite, which independently re-reads `group.groupKey` from storage at
send time — so the new member receives the fresh key through their normal join invite, never through
a `group_key_rotation` message of their own (they have no prior key to rotate away from). Every
other, pre-existing member receives the fresh key via `group_key_rotation`, identically to the
removal path. Implementation: `GroupInfoScreen.kt`'s add-member handler (Android);
`WebSocketClient.addGroupMember()` plus a `sendGroupKeyRotation()` helper extracted from the existing
`rotateGroupKey()` (Desktop). A newly-added member can therefore no longer decrypt group ciphertext
from before they joined — the backward-secrecy gap this section used to describe is closed.

---

## 6. Downgrade paths — what this protocol refuses to do silently

A recurring theme worth stating as a single list, since each of these was a real fix, not a
hypothetical:

- **No PQ→classical downgrade**: a handshake/bundle missing the ML-KEM component is rejected
  outright, never silently accepted as classical-only (`SECURITY_INVARIANTS.md` #9).
- **No anonymous→identified fallback** for `anon_message`: removed 2026-08-29; a not-yet-ready
  `anon_channel` queues rather than falling back to the main socket (§ 3 above).
- **No blind token-pool eviction**: fixed 2026-08-30; pool only shrinks by actual spend
  (`SECURITY_INVARIANTS.md` #8).
- **No invite-code format downgrade**: legacy version `0x02` (no mailbox tag) is rejected
  outright at parse time, not accepted with a silent fallback to a direct, server-visible lookup
  (that fallback used to exist and was cut entirely — `SECURITY.md` "Invite Codes" section).
- **Prekey-batch downgrade IS silent, and this is a known, not-yet-closed gap** (§ 4 above) — the
  one place in this list where the protocol currently does degrade without a user-visible signal.
  Listed here deliberately, as the counter-example to the pattern above, not to imply it's fixed.

---

## 7. Double Ratchet session — epoch tracking and backup-restore continuity

This is **client-internal** state (`SessionKeyManager.kt`'s `SessionState`, one per contact,
persisted SMK-wrapped) — the server never sees any of it, only the resulting ciphertext and a
`dh`/`counter` header. Added here because the 2026-09 debugging saga (`ISSUE_backup_identity_hijack.md`)
found three real bugs in this exact layer, contradicting this document's original framing of it as
comparatively low-risk — see the note at the top of this file.

### Per-message ratchet state

```
                         ┌────────────────────┐
                         │  X3DH established   │  rootKey, sendChainKey,
                         │  (initiateSession/   │  recvChainKey, sendRatchetPriv/Pub,
                         │  receiveSession)      │  recvRatchetPub = peer's first key
                         └──────────┬───────────┘
                                    │
                    every send: nextSendKey()          every receive: nextRecvKey()
                    ratchetStep(sendChainKey),          (see epoch handling below)
                    sendCounter++, no DH step —
                    the DH keypair only changes
                    in response to a RECEIVED
                    new peer key (see below)
                                    │
                                    ▼
                         ┌────────────────────┐
                         │  steady-state turn   │  symmetric-only ratchet advances
                         │  (one side sends N    │  (ratchetStep/ratchetAdvance,
                         │  messages in a row)   │  HMAC-SHA256-based) — no DH
                         └────────────────────┘  work happens per message
```

### `nextRecvKey(contactId, expectedCounter, dhKeyB64)` — decision order

This function's decision order is itself the fix history — each step exists because an earlier
ordering was wrong in production:

```
1. Expire skipped keys older than SKIPPED_KEY_TTL_MS (7 days) — lost forever past this point,
   accepted trade-off vs. unbounded storage growth.
2. Look up (epoch, counter) in the skipped-key buffer (MAX_SKIPPED_KEYS = 100) — an
   out-of-order message we already gap-filled a key for. If found, return it; done.
3. Is dhKeyB64 present AND different from the currently-tracked recvRatchetPub? → candidate
   DH step.
     3a. Is dhKeyB64 in previousRecvRatchetPubs (last 5 epochs already stepped past)?
         → this is a REPLAY of an old epoch (e.g. server.py's token_pending fallback
           redelivering an already-processed, non-skipped message) — NOT a genuine forward
           step. Throw DuplicateOrStaleMessage, touch nothing. (Fixed 2026-09-03 — see
           SECURITY_INVARIANTS.md.)
     3b. Otherwise: genuinely new epoch. performDHRatchetStep() — resets sendCounter/
         recvCounter to 0, derives fresh rootKey/chainKeys, generates a new send keypair,
         records the OLD recvRatchetPub into previousRecvRatchetPubs. (Reordered
         2026-09-02 to run BEFORE the counter comparison below — see step 4's note.)
4. expectedCounter < recvCounter (now correctly the CURRENT epoch's counter, post-step) →
   genuine same-epoch duplicate. Throw DuplicateOrStaleMessage, touch nothing.
5. expectedCounter > recvCounter → gap within the current epoch: derive and cache each
   intermediate key as skipped, return the requested one.
6. expectedCounter == recvCounter → normal in-order derivation.
```

**Why step 3 had to move before step 4** (found live 2026-09-02, "новые сообщения после бэкапа
и видеозвонка не доходят"): `performDHRatchetStep()` always resets both counters to 0, so a new
epoch's first message carries a low counter unrelated to the old epoch's `recvCounter`. Running
the old counter comparison first meant a legitimate new-epoch message could look "stale" against
the old epoch's accumulated counter and get thrown away — and since that throw is deliberately
side-effect-free, the session stayed wedged on the old epoch forever, failing every subsequent
message from the new epoch identically.

**Why step 3a exists** (found live 2026-09-03, immediately after fixing step 3's ordering):
making the DH step unconditional and first removed an *accidental* safeguard the old code had —
an old-epoch replay used to often land in step 4 and get rejected before ever reaching the step
logic, simply because old-epoch counters tend to be numerically lower. Nothing actually verified
"is this epoch newer", only "is this epoch different" — so a redelivered old-epoch message could
force a real DH step with a stale key, rolling the live session's root/chain keys and ratchet
keypair backward. `previousRecvRatchetPubs` closes this the same way `spent_tokens` closes replay
at the token layer (§1 above): remember what's already been consumed, reject a repeat cheaply
instead of reprocessing it.

### SPK/PQ prekey rotation and backup-restore continuity

```
generateOrRotateSpk()                    Backup export/import
  │                                         │
  │ every SPK_ROTATION_INTERVAL_MS          │ exportCurrentPrekeyForBackup() —
  │ (7 days): mint new SPK+PQ keypair,      │ current SPK+PQ keypair only
  │ demote current → previous               │ (not OPKs — see below)
  │ (kept valid SPK_GRACE_PERIOD_MS,        │
  │  14 days, for contacts with a           │ restorePrekeyFromBackup() — writes
  │  stale cached bundle)                   │ directly into session_keys(_secure)
  │                                         │ prefs + in-memory state, BEFORE
  │                                         │ initialize() runs on the fresh
  │                                         │ install, so generateOrRotateSpk()
  │                                         │ treats the restored key as an
  │                                         │ ordinary scheduled rotation
  │                                         │ (correctly graced) instead of an
  │                                         │ unplanned one with no grace period
  ▼                                         ▼
previous SPK wiped after grace          contacts' cached bundle for this
period elapses (SecureMemory.wipe)      identity keeps decrypting — no
                                         re-handshake needed post-restore
```

**OPKs are handled differently on backup**: they're single-use by protocol design
(`receiveSession()`'s `consumeOpk()`), so restoring frozen key material risks reissuing an id
already consumed for real between export and restore. Only `opkIdCounter` carries forward
(`exportOpkCounterForBackup()`/`restoreOpkCounterFromBackup()`, monotonic via `maxOf` — never
moves backward even if this device's own post-wipe pool is already ahead). The pool itself is
left for the ordinary `refillOpkPool()` top-up path to repopulate with brand-new keys.

---

## 8. `register()` — admission gates and device authentication

Added 2026-09-03 (external review). Two separate gates, both with the same underlying bug class:
a durable record used to be written *before* the gate protecting it had actually passed, so a
failed gate still left a permanent, exploitable side effect.

### Fingerprint admission — PoW / access-code / registration-cap ordering

```
register(public_key, device_id, ...)
        │
        ▼
is_new_fingerprint = NOT db_is_fingerprint_registered(username)
        │
        │ (only for a brand-new fingerprint — a reconnect skips straight
        │  past all of the following)
        ▼
POW_DIFFICULTY_BITS > 0?  → verify pow_nonce (pure computation, no DB
        │                    write — nothing to make atomic here)
        │ fail → pow_required, NOTHING durable has happened yet
        ▼ pass
db_admit_new_fingerprint(username, MAX_REGISTERED_USERS, access_code,
                          SERVER_ACCESS_PROTECTED)
        │  ONE atomic transaction (BEGIN IMMEDIATE):
        │    exists already? → "exists" (a concurrent registration of the
        │      SAME identity won the race first — proceed, nothing charged)
        │    cap reached?    → "full", ROLLED BACK — access_code (if any)
        │      untouched, not wasted on a server that was full anyway
        │    access_code required & doesn't match unused row? → "access_denied", ROLLED BACK
        │    otherwise: consume access_code + INSERT registered_fingerprints,
        │      all together → "ok"
        ▼
only "ok"/"exists" proceeds to session setup; "full"/"access_denied" reject
```

**Bug this replaced**: the previous ordering INSERTed the fingerprint (cap-checked, but
unconditional otherwise) *before* PoW was ever checked. A fingerprint that then failed PoW — or,
further down, the access-code check — was still durably in `registered_fingerprints`.
`db_is_fingerprint_registered()` then reported it as already-registered on any later attempt, so
`is_new_fingerprint` came out `False` for good and **neither gate was ever checked again** for
that identity. One connection attempt with a bogus PoW nonce (or no access code at all) was enough
to permanently mint a "registered" identity — and with `MAX_REGISTERED_USERS` active, an attacker
could burn through the cap with fingerprints that never actually passed either gate. A related bug
in the same code: access-code consumption used to happen as a separate step from the cap check, so
a real code could be consumed and *then* the server turns out to be full — burned for nothing. Both
close together once cap-check + access-code-consume + insert became one transaction.

### Device authentication — durable authorization + cryptographic device binding

Two rounds of the same underlying issue, both in the TOTP device-gate (`SECURITY.md` § Device-Gated
TOTP + Recovery Codes has the auditor-facing summary; this is the state-machine view).

**Round 1 — device authorization must be durable, not tied to a live session.** The original gate
computed "is this a new device" from `clients.get(username)`, purely in-memory — gone the instant
the real owner's app closed, or the server restarted. A stolen identity private key was then enough
to `register()` with any `device_id` and skip TOTP outright, any time `clients[username]` happened
to be empty — which meant TOTP was really only ever protecting against a *second* device connecting
while the real owner's session was still live, not the stolen-key scenario it exists to defend.
Fixed with a durable `authorized_devices(username, device_id, device_pubkey, added_at)` table —
see below for what `device_pubkey` adds — checked instead of the live `clients` dict, with the same
insert-only-after-the-gate-passes ordering as fingerprint admission above.

**Round 2 — `device_id` alone is a bearer token, not proof of anything.** Even durable,
`authorized_devices` only recorded a client-supplied *string* — sent in the clear on every
`register()`, nothing about it secret. An attacker holding a stolen identity private key who also
learned a legitimate `device_id` (not hard: it's an identifier, not a secret) could present that
same string and have the durable check answer "already authorized," skipping TOTP again. Closed by
making `device_id` require an actual credential behind it — a second, device-local EC keypair,
generated on-device and deliberately excluded from the identity backup (`DeviceKeyManager.kt`,
Android; separate SharedPreferences file never touched by `BackupManager.exportBackup()`), which
signs a fresh, per-connection challenge on **every** `register()`, not just first enrollment:

```
register() now also carries device_public_key (DER, base64), device_signature (base64)

signed message = "SUBROSA_DEVICE_V1" || challenge || username || device_id
  (challenge is the same per-connection random 32 bytes already used for the
   identity-key challenge_response — fresh every connection, so this also
   doubles as replay protection: a captured signature from a past connection
   is worthless against a new one)

server-side (register(), only when username in user_totp_secrets):
        │
        ▼
db_get_authorized_device(username, device_id)
        │
   ┌────┴─────────────────────────┐
   row exists, pubkey PINNED       row doesn't exist, OR exists with
   │                               pubkey still NULL (legacy row from
   │                               before this column, or from a
   │                               TOTP-not-configured registration)
   ▼                               ▼
supplied pubkey MUST match         verify signature with the SUPPLIED
stored pubkey exactly, or          pubkey; TOTP/recovery required
device_auth_failed — NEVER         regardless (first-time binding);
falls through to "unknown          only on TOTP/recovery success:
device, please prove TOTP"         db_bind_device_pubkey() — atomic
(that would let a TOTP/            INSERT or claim-the-NULL-row,
recovery-code compromise           NEVER overwrites an already-pinned
re-pin someone else's              pubkey (checked again here even
device_id to an attacker's         though register()'s own check above
key)                                already refused a mismatch —
   │                               belt-and-suspenders against a TOCTOU)
   ▼                                       │
verify signature with the                  │
STORED pubkey; TOTP skipped                │
if it verifies                             │
   └───────────────┬────────────────────────┘
                    ▼
        register() proceeds (or session_conflict/reconnect as usual)
```

**Critical invariant**: once `(username, device_id)` has a pinned `device_pubkey`, it is never
replaced by any code path — enforced both by `register()`'s own pubkey-match check (refuses
outright on mismatch, doesn't fall through to a re-provable path) and, redundantly, inside
`db_bind_device_pubkey()` itself. A device that lost its local keypair (e.g. app reinstall) is
expected to generate a fresh `device_id` and go through the brand-new-device TOTP flow again, not
reclaim the old one.

**Deployment status**: server-side, Android, and Desktop are all live — Desktop's
`DeviceKeyManager.kt` (dated 2026-09-11/13 in its own comments) ports the same keypair/signing
scheme, wired into `WebSocketClient.kt`'s `register()` build. This section previously said Desktop
didn't send `device_public_key`/`device_signature` at all; that was true when written but went
stale once the port landed — corrected 2026-09-25 (`docs/KNOWN_SECURITY_ISSUES.md` OPEN-9, now
closed as a documentation-drift instance, not a live gap).

## 9. `totp_setup` / `totp_disable` — atomic commit before reply

Same class of bug as fingerprint admission (§8 above): a handler telling the client an operation
succeeded *before* every durable write behind it had actually landed. Found live 2026-09-03.

**The bug.** `totp_setup` used to update `user_totp_secrets` (RAM) and send `totp_setup_ok`
immediately, then fire two independent, unawaited `create_task()`s to persist the secret
(`user_totp` row) and the freshly-generated recovery codes (`totp_recovery_codes` rows) — two
separate SQLite writes, neither awaited, both racing the reply already in flight. `totp_disable`
had the mirror-image bug: reply first, then two independent fire-and-forget `DELETE`s. A process
crash in the window between "client got the `_ok` reply" and either write completing left one of:

- `user_totp` with no row at all — the client believes TOTP is now protecting the account; the
  server, on restart, has never heard of it. Silent downgrade back to disabled.
- A freshly-enrolled secret with zero matching recovery codes — the account is protected, but the
  one documented lost-authenticator recovery path (`SECURITY.md` § Device-Gated TOTP) is a no-op
  for it forever.
- (disable path) A `user_totp` row that survives despite the client believing TOTP is off, or vice
  versa for `totp_recovery_codes` — the two tables silently disagreeing about whether the account
  is protected.

**The fix.** `_db_commit_totp_setup_sync()` / `_db_commit_totp_disable_sync()` — one
`BEGIN IMMEDIATE` transaction each, covering both `user_totp` and `totp_recovery_codes` together:

```
totp_setup:
    validate proof-of-current-secret (if re-enrolling) / new-secret code
        │
        ▼
    await db_commit_totp_setup(username, secret, recovery_codes)
        (ONE transaction: INSERT OR REPLACE user_totp (…, last_counter=-1)
                           DELETE + re-INSERT totp_recovery_codes)
        │
        ▼  only after the commit returns
    user_totp_secrets[username] = secret   (RAM, now safe to trust)
    send totp_setup_ok

totp_disable:
    validate current TOTP code / recovery code
        │
        ▼
    await db_commit_totp_disable(username)
        (ONE transaction: DELETE user_totp, DELETE totp_recovery_codes)
        │
        ▼  only after the commit returns
    del user_totp_secrets[username]
    send totp_disable_ok
```

`last_counter` needs no separate reset on re-enrollment — the `INSERT OR REPLACE` inside the
transaction recreates the whole `user_totp` row, so it gets the column's `DEFAULT -1` automatically
(same mechanic `db_consume_totp_counter()`'s own comment already documents). The two previously
separate async helpers this replaced (`db_save_totp`/`db_delete_totp`/`db_save_recovery_codes`/
`db_delete_recovery_codes`, and their `_sync` counterparts) were removed entirely — nothing else
called them.

---

*Maintenance note: when a new message type or connection mode is added, add its state machine
here alongside the existing ones, not just as prose in `ARCHITECTURE.md`'s protocol table. The
table says what a message type does; this document says what states a stream of them can be in
and in what order — the two are complementary, not duplicates.*
