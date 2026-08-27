# Message Delivery — `token_pending` Lifecycle Contract

*Added 2026-08-27 in response to external review (DOC-10): [SCOPE.md](SCOPE.md) names
`token_pending` lifecycle as priority item 4, and [AUDIT_SETUP.md](AUDIT_SETUP.md) exercises "token
survives disconnect," but neither previously spelled out the actual contract — TTL, cleanup,
restart behavior, retry, and what the sender does or doesn't learn. Every fact below is read
directly from `Server/server.py`, not reconstructed from memory.*

## What it is

`token_pending: dict[str, list[dict]]` (plus `token_pending_created: dict[str, float]` for TTL
tracking) is the server's fallback queue for anonymous-token-routed messages
(`anon_message`/`anon_delivery_ack` handlers). It exists because a successful `sendWs()` write to a
live socket doesn't guarantee the recipient's app actually processed the frame — the queued copy
is the safety net for that gap.

## State transitions

```
anon_message arrives for a known, unspent token
        │
        ▼
token_pending[token] = [payload]     ← always a 1-item list: single-use tokens mean at
        │                              most one entry is ever queued per token, so this
        │                              is a plain overwrite, never an append
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
ignored,    token_pending.pop(token)  +  spent_tokens.add(token)
logged      (cleared for real, token now permanently unusable —
             replay of this same token is rejected from here on)
```

## Contract details

| Property | Value | Source |
|---|---|---|
| **Persistence** | None — pure in-memory dict. A server restart clears the entire queue silently. | `token_pending` declared as a plain `dict`, no DB table |
| **TTL** | 24 hours per entry (`TOKEN_PENDING_TTL_SEC = 24 * 3600`) | `server.py:62` |
| **Cleanup** | Watchdog task (`token_pending_watchdog`) wakes every hour, deletes any entry older than the TTL | `server.py:3070` |
| **Max entries / per-token cap** | No explicit cap on total queue size. Per-token: exactly 0 or 1 entries — single-use tokens mean a second `anon_message` for an already-pending token overwrites, never appends. | comment in the `anon_message` handler |
| **Retry schedule** | No periodic re-push. Redelivery happens exactly once per event: when the recipient calls `subscribe_tokens` again (e.g. on reconnect). There is no background retry loop beyond that. | `subscribe_tokens` handler |
| **What happens after TTL** | The entry is silently deleted. No message is sent to the original sender informing them the delivery expired. | `token_pending_watchdog` — no notification code path exists there |
| **Does the sender learn about expiry?** | **No.** This is a real, previously-undocumented gap surfaced while writing this file, not a "residual risk" line borrowed from elsewhere — a sender has no signal that a message sat in `token_pending` for 24h and was dropped without ever reaching the recipient. Distinguishing this from a message that *was* delivered live requires the sender to infer it from an absent read receipt or ACK, over whatever timeout the client UI uses, if any. |
| **Federation ACK semantics** | `anon_delivery_ack`'s ownership check (`token_to_ws.get(token) is <this connection>`) is a purely local, in-process dict lookup — not verified end-to-end against how `forward_to_peers`/federation interacts with anonymous token ownership across a multi-server deployment in this pass. **Flagged for explicit auditor attention, not asserted as safe or unsafe.** |

## Regression test coverage

`Server/tests/test_security_invariants.py::test_token_pending_survives_disconnect_until_real_ack`
covers: entry persists across a disconnect, resubscribe redelivers without clearing it, and only a
real `anon_delivery_ack` from the owning connection clears it (moving to `spent_tokens`). The TTL
watchdog itself, the no-notification-on-expiry gap, and the federation-ACK interaction above are
**not** covered by an automated test — noted as open items.
