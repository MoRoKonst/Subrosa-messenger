"""
Concurrency/race tests for every operation whose security depends on
atomicity or first-write-wins — built with asyncio.gather so both sides of
a race actually hit the server at (as close to) the same time as this
process can arrange, rather than depending on artificial sleeps/timing.

Each test targets an invariant server.py's own comments explicitly call
out as a fixed race (see the cited line ranges) — this suite exists to
keep proving those fixes hold, under a real subprocess and real
concurrent connections, not just the in-process single-event-loop
scheduling test_security_invariants.py already covers extensively.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol_harness as ph

pytestmark = pytest.mark.asyncio


async def test_concurrent_anon_message_only_one_wins_inflight(managed_server: ph.ManagedServer):
    """Two different senders fire anon_message for the SAME ACTIVE token at
    (as close to) the same instant. server.py's db_mark_anon_token_inflight
    atomic ACTIVE->IN_FLIGHT claim (~11396) guarantees at most one of them
    can ever win real delivery -- the loser gets the same indistinguishable
    fake ack a decoy/spent token would (~11311/11411)."""
    owner_ws, owner_fp, _, _ = await ph.connect_and_register(managed_server.url, device_id="raceowner1")
    s1_ws, s1_fp, _, _ = await ph.connect_and_register(managed_server.url, device_id="racesender1")
    s2_ws, s2_fp, _, _ = await ph.connect_and_register(managed_server.url, device_id="racesender2")
    try:
        token = ph.rand_token()
        await owner_ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await owner_ws.send(json.dumps({"type": "ping"}))
        assert await ph.drain_until(owner_ws, "pong", timeout=3.0) is not None

        async def send(ws, msg_id):
            await ws.send(json.dumps({
                "type": "anon_message", "token": token,
                "payload": {"id": msg_id, "blob": "aGVsbG8="},
            }))

        await asyncio.gather(send(s1_ws, "race-a"), send(s2_ws, "race-b"))

        owner_msgs = await ph.drain_all(owner_ws, quiet_for=1.0, max_total=3.0)
        deliveries = [m for m in owner_msgs if isinstance(m, dict) and m.get("type") == "anon_delivery"]
        assert len(deliveries) == 1, f"expected exactly one delivery to win the race, got {len(deliveries)}: {owner_msgs}"
        winning_id = deliveries[0]["payload"]["id"]
        assert winning_id in ("race-a", "race-b")

        s1_msgs = await ph.drain_all(s1_ws, quiet_for=0.5, max_total=2.0)
        s2_msgs = await ph.drain_all(s2_ws, quiet_for=0.5, max_total=2.0)
        losing_id = "race-b" if winning_id == "race-a" else "race-a"
        loser_msgs = s2_msgs if losing_id == "race-b" else s1_msgs
        assert {"type": "ack", "id": losing_id} in loser_msgs, \
            f"loser of the race should get the indistinguishable fake ack, got {loser_msgs}"
    finally:
        await owner_ws.close()
        await s1_ws.close()
        await s2_ws.close()


async def test_concurrent_subscribe_tokens_first_claim_wins(managed_server: ph.ManagedServer):
    """Two different accounts subscribe_tokens the SAME brand-new token at
    (as close to) the same instant. db_claim_anon_tokens()'s BEGIN
    IMMEDIATE transaction guarantees exactly one becomes the durable owner
    -- proven here by having each side subsequently send anon_message with
    the token and checking exactly one of them observes a self-delivered
    anon_delivery (only the actual token_to_ws owner ever gets routed a
    message it sends to that same token, in this single-owner setup)."""
    a_ws, a_fp, _, _ = await ph.connect_and_register(managed_server.url, device_id="raceclaimA")
    b_ws, b_fp, _, _ = await ph.connect_and_register(managed_server.url, device_id="raceclaimB")
    try:
        token = ph.rand_token()

        async def claim(ws):
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))

        await asyncio.gather(claim(a_ws), claim(b_ws))
        await a_ws.send(json.dumps({"type": "ping"}))
        await b_ws.send(json.dumps({"type": "ping"}))
        assert await ph.drain_until(a_ws, "pong", timeout=3.0) is not None
        assert await ph.drain_until(b_ws, "pong", timeout=3.0) is not None

        await a_ws.send(json.dumps({"type": "anon_message", "token": token, "payload": {"id": "a1", "blob": "aGVsbG8="}}))
        a_msgs = await ph.drain_all(a_ws, quiet_for=0.7, max_total=2.0)
        a_won = any(m.get("type") == "anon_delivery" for m in a_msgs if isinstance(m, dict))

        await b_ws.send(json.dumps({"type": "anon_message", "token": token, "payload": {"id": "b1", "blob": "aGVsbG8="}}))
        b_msgs = await ph.drain_all(b_ws, quiet_for=0.7, max_total=2.0)
        b_won = any(m.get("type") == "anon_delivery" for m in b_msgs if isinstance(m, dict))

        assert a_won != b_won, f"exactly one side must win ownership -- a_won={a_won} b_won={b_won} (a_msgs={a_msgs}, b_msgs={b_msgs})"
    finally:
        await a_ws.close()
        await b_ws.close()


async def test_concurrent_ack_and_revoke_no_corruption(managed_server: ph.ManagedServer):
    """anon_delivery_ack (-> SPENT) and unsubscribe_tokens (-> REVOKED),
    sent back-to-back for the same IN_FLIGHT token.

    NOTE on what this test does and doesn't prove: a genuine two-socket
    race was attempted while building this test, but registering a SECOND
    connection with the same identity/keypair turned out to kick the FIRST
    one off (confirmed empirically -- a real, if incidental, discovery
    about session handling, not this test's main subject). handle_client()
    processes one connection's messages strictly sequentially (the `async
    for raw_message in websocket:` loop awaits each handler fully before
    reading the next frame), so two sends on ONE socket can never actually
    execute concurrently server-side regardless of asyncio.gather() on the
    client side -- this is really a same-connection ORDERING test, not a
    true race. It still meaningfully exercises
    db_terminalize_anon_token()'s atomic "state IN (ACTIVE, IN_FLIGHT)"
    guard (~5468): whichever message the server happens to process first
    wins, the second's UPDATE matches zero rows, and the token ends in a
    single consistent terminal state either way -- the connection survives,
    and a replay of anon_message with this token gets the same
    indistinguishable fake ack every terminal/decoy token gets, never a
    fresh delivery. The genuinely-concurrent, cross-connection version of
    this race (e.g. the TTL watchdog background task racing a live client
    ACK) is not covered here -- see docs/KNOWN_SECURITY_ISSUES.md's OPEN-3
    status note."""
    ws, fp, _, _ = await ph.connect_and_register(managed_server.url, device_id="raceackrevoke1")
    try:
        token = ph.rand_token()
        await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await ws.send(json.dumps({"type": "anon_message", "token": token, "payload": {"id": "m1", "blob": "aGVsbG8="}}))
        assert await ph.drain_until(ws, "anon_delivery", timeout=3.0) is not None

        await asyncio.gather(
            ws.send(json.dumps({"type": "anon_delivery_ack", "token": token})),
            ws.send(json.dumps({"type": "unsubscribe_tokens", "tokens": [token]})),
        )
        await ws.send(json.dumps({"type": "ping"}))
        assert await ph.drain_until(ws, "pong", timeout=3.0) is not None

        await ws.send(json.dumps({"type": "anon_message", "token": token, "payload": {"id": "m2", "blob": "aGVsbG8="}}))
        msgs = await ph.drain_all(ws, quiet_for=1.0, max_total=2.0)
        types = [m.get("type") for m in msgs if isinstance(m, dict)]
        assert "anon_delivery" not in types, f"terminal token was delivered again after ack/revoke race: {msgs}"
    finally:
        await ws.close()


@pytest.fixture
def capped_managed_server():
    """A DEDICATED server (function-scoped, not the shared module fixture)
    with MAX_REGISTERED_USERS=3 -- needed to reliably exhaust the cap with
    a small number of concurrent registrations rather than requiring
    hundreds of real accounts."""
    srv = ph.ManagedServer(max_registered_users="3")
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()


async def test_concurrent_registration_respects_cap_exactly(capped_managed_server: ph.ManagedServer):
    """MAX_REGISTERED_USERS=3, 8 brand-new identities register concurrently
    -- effective_registration_cap()'s DB-backed accounting must admit
    EXACTLY 3, never more (a race letting the count overshoot would be a
    real cap-bypass bug), regardless of how the 8 attempts interleave."""
    url = capped_managed_server.url
    n = 8

    async def attempt(i):
        import websockets
        priv, pub_der = ph.gen_keypair()
        ws = await websockets.connect(url)
        try:
            await ph.handshake(ws, priv, pub_der)
            await ph.register(ws, pub_der, f"caprace{i}")
            msgs = await ph.drain_all(ws, quiet_for=1.0, max_total=4.0)
            return any(m.get("type") == "register_ok" for m in msgs if isinstance(m, dict))
        finally:
            try:
                await ws.close()
            except Exception:
                pass

    results = await asyncio.gather(*(attempt(i) for i in range(n)))
    successes = sum(1 for r in results if r)
    assert successes == 3, f"MAX_REGISTERED_USERS=3 but {successes}/{n} concurrent registrations succeeded"
