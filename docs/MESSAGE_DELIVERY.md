# Message Delivery — `token_pending` Lifecycle Contract

*Added 2026-08-27 in response to external review (DOC-10): [SCOPE.md](SCOPE.md) names
`token_pending` lifecycle as priority item 4, and [AUDIT_SETUP.md](AUDIT_SETUP.md) exercises "token
survives disconnect," but neither previously spelled out the actual contract — TTL, cleanup,
restart behavior, retry, and what the sender does or doesn't learn. Every fact below is read
directly from `Server/server.py`, not reconstructed from memory.*

*Updated 2026-09-03 (external review): the restart-clears-everything behavior this document
originally described for token ownership/spent-state (flagged here as PROTO-02, tracked as
`KNOWN_SECURITY_ISSUES.md` OPEN-8) is now fixed — token state is durable in SQLite, not
in-memory-only. `token_pending` itself (the queued payload) remains intentionally RAM-only — see
the durability section below for why that specific piece is a deliberate, still-current trade-off,
not an oversight. See `PROTOCOL_STATE_MACHINE.md` §1/§2 for the full state-machine detail this
file's table summarizes.*

## What it is

`token_pending: dict[str, list[dict]]` (plus `token_pending_created: dict[str, float]` for TTL
tracking) is the server's fallback queue for anonymous-token-routed messages
(`anon_message`/`anon_delivery_ack` handlers). It exists because a successful `sendWs()` write to a
live socket doesn't guarantee the recipient's app actually processed the frame — the queued copy
is the safety net for that gap.

## State transitions

```
subscribe_tokens (first-claim-wins, atomic, durable — db_claim_anon_tokens)
        │
        ▼
token durably ACTIVE, owner recorded in SQLite (anon_token_state)
        │
        ▼
anon_message arrives — atomic ACTIVE→IN_FLIGHT (db_mark_anon_token_inflight,
durable); a SECOND anon_message on the same token before ack gets the same
indistinguishable fake-ack as an unknown/spent token — first-write-wins,
enforced by this same atomic transition, not a RAM-only check
        │
        ▼
token_pending[token] = [payload]     ← RAM-only (see "Deliberate RAM-only
        │                              exception" below); always a 1-item
        │                              list, since only one anon_message can
        │                              ever win the IN_FLIGHT transition
        ▼
   ┌────┴─────┐
   │          │
live delivery  no live socket (offline) / delivery attempted regardless
attempted      │
   │          │
   ▼          ▼
(either way, the queued copy stays until a REAL ack — a successful sendWs()
 does NOT clear it; see the anon_message handler's own comment on why)
        │
        ▼
recipient (re)subscribes to their tokens (subscribe_tokens)
        │
        ▼
queued copy is resent (asyncio.create_task(send_safe(...))) — but NOT
cleared here; resubscribing redelivers, it doesn't confirm delivery
        │
        ▼
recipient's client sends anon_delivery_ack for the token
        │
        ▼
ownership check: token_to_ws.get(token) is this connection?
        │
   ┌────┴────┐
   NO         YES
   │           │
ignored,    db_terminalize_anon_token(token, owner, "SPENT") — durable,
logged      BEFORE any RAM cleanup; only on success does token_pending.pop()
            + spent_tokens.add() + anon_token_state_cache update happen,
            all under one lock — token permanently unusable, survives restart
```

**What also durably closes IN_FLIGHT, besides a real ack** — both now call the same
`db_terminalize_anon_token()` path, not just a RAM pop:

- **24h TTL** (`token_pending_watchdog`) — durably transitions to SPENT, then best-effort notifies
  the owner (`subscribe_tokens_result: {"spent": [token]}`) if they're online.
- **Server restart while still IN_FLIGHT** — a fail-closed startup sweep (`_db_setup_sync()`)
  force-closes any IN_FLIGHT row to SPENT before the cache loads. See "Deliberate RAM-only
  exception" below for why this can't instead resurrect the queued message.
- **`unsubscribe_tokens`** — owner-initiated revoke, from ACTIVE or IN_FLIGHT, to REVOKED (also
  terminal). No longer requires the token to be currently routed to the revoking connection — see
  `PROTOCOL_STATE_MACHINE.md` §1's "unsubscribe_tokens" note.

## Contract details

| Property | Value | Source |
|---|---|---|
| **Persistence — token ownership/state** | **Durable.** `anon_token_state` (SQLite): `owner`, `state` (ACTIVE/IN_FLIGHT/SPENT/REVOKED), survives restart. Fixed 2026-09-03 — see "Fixed: the restart-replay gap" below. | `db_claim_anon_tokens()`/`db_mark_anon_token_inflight()`/`db_terminalize_anon_token()` |
| **Persistence — `token_pending` (the queued payload itself)** | **Still RAM-only, deliberately.** See "Deliberate RAM-only exception" below — this is the one piece of state this document originally flagged as non-durable that remains non-durable, on purpose. | `token_pending: dict`, no DB table |
| **TTL** | 24 hours per entry (`TOKEN_PENDING_TTL_SEC = 24 * 3600`) | `server.py` |
| **Cleanup** | Watchdog task (`token_pending_watchdog`) wakes every hour; entries older than the TTL are now durably closed to SPENT (not just RAM-popped) — see "What also durably closes IN_FLIGHT" above | `token_pending_watchdog()` |
| **Max entries / per-token cap** | Process-wide hard cap (added S6-30, 2026-09-04 — **corrected 2026-09-25**, this row previously said no such cap existed, which went stale the day after it was written): `TOKEN_PENDING_MAX_TOTAL_BYTES` (default 128 MiB) and `TOKEN_PENDING_MAX_TOTAL_ITEMS` (default 5000), both required strictly positive at startup, enforced via a reservation system before a new entry is admitted. Per-token: exactly 0 or 1 entries, enforced atomically (`db_mark_anon_token_inflight`'s `WHERE state = 'ACTIVE'`), not just by convention. | `anon_message` handler; `SECURITY_INVARIANTS.md` #43 |
| **Retry schedule** | No periodic re-push. Redelivery happens exactly once per event: when the recipient calls `subscribe_tokens` again (e.g. on reconnect). There is no background retry loop beyond that. | `subscribe_tokens` handler |
| **What happens after TTL** | The token is durably closed to SPENT; the *original sender* still gets no notification (see below), but the *token's owner* now does, best-effort, via `subscribe_tokens_result`. | `token_pending_watchdog` |
| **Does the sender learn about expiry?** | **No — decided 2026-09-25, `KNOWN_SECURITY_ISSUES.md`'s "Decided: accepted tradeoffs" table, not left as an open question anymore.** A sender has no signal that a message sat in `token_pending` for 24h and was dropped without ever reaching the recipient — TTL expiry closes the *token's* lifecycle (so the owner's client stops treating it as spendable), it does not notify the party who sent the now-lost message. The only way to fix this would be for the server to learn who the sender is, directly against sealed-sender's whole point — explicitly rejected in favor of preserving anonymity. The sender's only signal is the same ambiguous "stuck on single checkmark" every E2EE messenger gives for a long-offline contact, plus the existing cause-agnostic manual resend action — assessed as low real-world impact, since the common case (recipient reconnects within 24h) redelivers automatically and transparently. |
| **Federation ACK semantics** | **Resolved by verification 2026-09-25 — traced end-to-end, `KNOWN_SECURITY_ISSUES.md` OPEN-6 closed.** `anon_delivery_ack`'s ownership check (`token_to_ws.get(token) is <this connection>`) IS purely local, but that's fine: anonymous-token lifecycle (claim/ACTIVE, ACTIVE→IN_FLIGHT, delivery ACK/SPENT, revoke/REVOKED, `token_pending`, `token_to_ws`/`ws_to_tokens`) never crosses federation at all, by construction — none of `anon_message`/`anon_delivery_ack`/`subscribe_tokens`/`unsubscribe_tokens` ever call `forward_to_peers()`, none of their four wire types are in `FEDERATED_FORWARD_ALLOWED_TYPES`, and a federation-authenticated connection's dispatch loop has no path into any anon-token handler at all (see `SECURITY_INVARIANTS.md` #80 for the full trace and enforcement points). A federation peer therefore cannot claim, terminalize, revoke, or otherwise mutate another node's anonymous-token lifecycle — there's no multi-server ownership question to answer because ownership never leaves the node that issued it. |
| **`spent_tokens`/`known_tokens`/ownership persistence across restart** | **Fixed 2026-09-03 (was PROTO-02/`KNOWN_SECURITY_ISSUES.md` OPEN-8).** See "Fixed: the restart-replay gap" below for the full before/after. |

### Fixed: the restart-replay gap (was PROTO-02 / OPEN-8)

**Original gap** (external review 2026-08-28): `spent_tokens`/`known_tokens`/`token_owner` were
plain in-memory sets/dicts, reset to empty on every server restart. A token legitimately spent
before a restart was no longer recognized as spent afterward — a replayed `anon_message` using
that old token would be accepted as if new — and separately, ownership itself could be re-claimed
by a different account after a restart, before the real owner reconnected.

**Fix**: `anon_token_state` (SQLite) is now the source of truth for both ownership and lifecycle
state; the RAM structures are fast caches kept in sync on every write, never the record of state
itself. See `PROTOCOL_STATE_MACHINE.md` §1 for the full table schema and the atomic-write
functions (`db_claim_anon_tokens`/`db_mark_anon_token_inflight`/`db_terminalize_anon_token`), and
`SECURITY_INVARIANTS.md` #24–29 for this stated as standalone, checkable invariants.

### Deliberate RAM-only exception: the queued payload itself

Token *state* is now durable, but the actual queued ciphertext (`token_pending[token]`) is not,
and this is an explicit, accepted trade-off, not an oversight or a remaining TODO. Persisting
sealed message payloads to disk would be a real retention/privacy trade-off of its own (ciphertext
sitting in the database beyond the moment it's needed, for a system whose whole design elsewhere
minimizes what the server retains) — not revisited as part of this fix. The consequence, stated
plainly: **if the server process dies after a message has been accepted into IN_FLIGHT but before
it's ever delivered/acked, that specific message is lost.** The token itself is not put at risk by
this — the fail-closed restart sweep (above) burns it to SPENT rather than leaving it spendable
again — so the failure mode is "one message lost," never "one token reused." This is the same
security-over-reliability trade-off stated in `PROTOCOL_STATE_MACHINE.md` §1's restart-sweep note.

## Regression test coverage

`Server/tests/test_security_invariants.py::test_token_pending_survives_disconnect_until_real_ack`
covers: entry persists across a disconnect, resubscribe redelivers without clearing it, and only a
real `anon_delivery_ack` from the owning connection clears it (moving to `spent_tokens`). The
federation-ACK boundary is now covered too, as of 2026-09-25 — see the same test file's OPEN-6
section (`SECURITY_INVARIANTS.md` #80 lists the exact tests).

**Inventory corrected 2026-11-03.** Two items this section listed as uncovered have since been
covered, and leaving them listed is its own small harm — it invites writing a test that already
exists, and an auditor working from `SCOPE.md` (which points at `Server/tests/` for what is
already regression-tested) would record a closed gap as open.

Now covered:
- **The TTL watchdog itself** — `test_token_pending_watchdog_tick_decrements_counters_exactly_once`
  backdates `token_pending_created` past `TOKEN_PENDING_TTL_SEC`, calls
  `_token_pending_watchdog_tick()`, and asserts the entry is gone and both counters are zeroed.
- **First-write-wins under a concurrent double `anon_message`** —
  `test_protocol_concurrency.py::test_concurrent_anon_message_only_one_wins_inflight` fires two
  senders at the same ACTIVE token, asserts exactly one delivery wins, and checks the loser
  receives the same indistinguishable fake ack a decoy would.

Still **not** covered by an automated test:
- The TTL watchdog's **durable** terminalize. The watchdog test above asserts RAM state only; it
  never checks that the token was moved to SPENT in SQLite. This is a genuinely different claim
  from "the watchdog is covered".
- The fail-closed IN_FLIGHT→SPENT **startup sweep**.
- Ownership/state surviving a simulated restart.
- Per-(target, requester) **bootstrap-token reservation**.
- The **no-notification-on-expiry** gap (a sender gets no signal that its message expired).

Those five were verified by code review, not by a regression suite — still the natural next
addition to `Server/tests/`.
