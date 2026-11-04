"""
State-machine abuse: valid-shaped packets sent in an invalid connection
state or invalid protocol order. Every scenario here is derived directly
from server.py's own state-gating code (handle_client()'s
authenticated_users boundary, is_anon_channel restriction, the anon-token
ACTIVE/IN_FLIGHT/SPENT/REVOKED transitions) — see each test's own
docstring for the exact line-level behavior it's proving.

test_security_invariants.py already exhaustively covers most of these
invariants in-process; this file's marginal value is the ones that are
naturally about WIRE-LEVEL/connection-lifecycle behavior (does the
connection actually get closed, does a real subprocess reconnect see
durable state) rather than in-process function-level assertions.
"""
from __future__ import annotations

import json
import os
import sys

import pytest
import websockets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol_harness as ph

pytestmark = pytest.mark.asyncio


async def test_message_before_register_is_rejected_and_closes(managed_server: ph.ManagedServer):
    """handle_client()'s hard authorization boundary (server.py ~8444):
    any ALLOWED_TYPES message except `register` from a connection that
    hasn't completed registration gets an explicit `error` reply and the
    connection is closed."""
    priv, pub_der = ph.gen_keypair()
    ws = await websockets.connect(managed_server.url)
    try:
        await ph.handshake(ws, priv, pub_der)
        await ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await ws.recv())
        assert msg["type"] == "error"
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await ws.recv()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


async def test_anon_channel_restricted_to_anon_message_only(managed_server: ph.ManagedServer):
    """handle_client() ~8393: an anon_channel connection sending anything
    other than anon_message gets the connection closed outright (not just
    the message dropped)."""
    ws = await websockets.connect(managed_server.url)
    try:
        await ph.anon_channel_handshake(ws)
        await ws.send(json.dumps({"type": "ping"}))
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await ws.recv()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


async def test_anon_channel_cannot_register(managed_server: ph.ManagedServer):
    """An anon_channel connection never proved (or claimed) an identity —
    register must be rejected exactly like any other non-anon_message type
    on this connection kind."""
    ws = await websockets.connect(managed_server.url)
    try:
        await ph.anon_channel_handshake(ws)
        priv, pub_der = ph.gen_keypair()
        await ph.register(ws, pub_der, "anonchanreg1")
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await ws.recv()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


async def test_federation_only_type_from_ordinary_client_is_unknown_type(managed_server: ph.ManagedServer):
    """peer_roster/federated_forward/federated_get_bundle/peer_announce/
    federated_bundle_response are handled exclusively inside
    handle_federation_peer_incoming(), never in ALLOWED_TYPES -- an
    ordinary authenticated client sending one hits the same "неизвестный
    тип" silent-drop path as any other unrecognized type, and the
    connection is NOT dropped (compare the pre-register/anon_channel tests
    above, where the SAME-shaped wrong-type traffic DOES close the
    connection -- the difference is entirely about connection state, not
    the message itself)."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="fedtypeclient1")
    try:
        for t in ("peer_roster", "federated_forward", "federated_get_bundle",
                  "peer_announce", "federated_bundle_response"):
            await ws.send(json.dumps({"type": t, "junk": "data"}))
        await ws.send(json.dumps({"type": "ping"}))
        pong = await ph.drain_until(ws, "pong", timeout=3.0)
        assert pong is not None
    finally:
        await ws.close()


async def test_dormant_channel_types_are_unreachable(managed_server: ph.ManagedServer):
    """channel_create/channel_subscribe/channel_unsubscribe/channel_post/
    channel_get_info handlers still exist in server.py but were removed
    from ALLOWED_TYPES (external review 2026-08-28, SCOPE-01) -- this is a
    regression test for that removal staying in effect, not a new
    finding."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="dormantchannel1")
    try:
        for t in ("channel_create", "channel_subscribe", "channel_unsubscribe",
                  "channel_post", "channel_get_info"):
            await ws.send(json.dumps({"type": t, "channel_id": "x"}))
        await ws.send(json.dumps({"type": "ping"}))
        pong = await ph.drain_until(ws, "pong", timeout=3.0)
        assert pong is not None
    finally:
        await ws.close()


async def test_ack_for_never_subscribed_token_is_silent_noop(managed_server: ph.ManagedServer):
    """anon_delivery_ack for a token nobody ever subscribed to must not be
    honored -- token_to_ws has no entry, so `is_current_owner` is False for
    any connection, and no anon_delivery_ack_ok is ever sent."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="ackneverclaimed1")
    try:
        token = ph.rand_token()
        await ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        msgs = await ph.drain_all(ws, quiet_for=1.0, max_total=2.0)
        assert not any(m.get("type") == "anon_delivery_ack_ok" for m in msgs if isinstance(m, dict))
    finally:
        await ws.close()


async def test_duplicate_ack_second_is_noop(managed_server: ph.ManagedServer):
    """Once a token is durably SPENT and its token_to_ws routing entry
    popped (server.py's anon_delivery_ack handler), a second ACK for the
    SAME token from the SAME connection must NOT get a second
    anon_delivery_ack_ok -- token_to_ws.get(token) is now None, so
    is_current_owner is False the second time."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="dupack1")
    try:
        token = ph.rand_token()
        await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await ws.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "m1", "blob": "aGVsbG8="},
        }))
        assert await ph.drain_until(ws, "anon_delivery", timeout=3.0) is not None

        await ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        assert await ph.drain_until(ws, "anon_delivery_ack_ok", timeout=3.0) is not None

        await ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        msgs = await ph.drain_all(ws, quiet_for=1.0, max_total=2.0)
        assert not any(m.get("type") == "anon_delivery_ack_ok" for m in msgs if isinstance(m, dict)), \
            f"second ACK for an already-SPENT token was honored again: {msgs}"
    finally:
        await ws.close()


async def test_ack_from_wrong_connection_is_rejected(managed_server: ph.ManagedServer):
    """Only the connection currently routed in token_to_ws for a token may
    ACK it (server.py ~11845 ownership check) -- a DIFFERENT registered
    identity trying to ACK someone else's in-flight token must be ignored,
    and the real owner's ACK must still work afterward."""
    owner_ws, owner_fp, _, _ = await ph.connect_and_register(managed_server.url, device_id="ackowner1")
    stranger_ws, stranger_fp, _, _ = await ph.connect_and_register(managed_server.url, device_id="ackstranger1")
    try:
        token = ph.rand_token()
        await owner_ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await owner_ws.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "m1", "blob": "aGVsbG8="},
        }))
        assert await ph.drain_until(owner_ws, "anon_delivery", timeout=3.0) is not None

        await stranger_ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        msgs = await ph.drain_all(stranger_ws, quiet_for=1.0, max_total=2.0)
        assert not any(m.get("type") == "anon_delivery_ack_ok" for m in msgs if isinstance(m, dict))

        await owner_ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        assert await ph.drain_until(owner_ws, "anon_delivery_ack_ok", timeout=3.0) is not None
    finally:
        await owner_ws.close()
        await stranger_ws.close()


async def test_replay_of_spent_token_gets_indistinguishable_fake_ack(managed_server: ph.ManagedServer):
    """After a token is SPENT, resending anon_message with it must NOT
    deliver again -- it gets the SAME externally-indistinguishable
    {"type": "ack", "id": msg_id} a decoy/unknown token would get
    (server.py ~11311), never a second 'anon_delivery'."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="replayspent1")
    try:
        token = ph.rand_token()
        await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await ws.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "m1", "blob": "aGVsbG8="},
        }))
        assert await ph.drain_until(ws, "anon_delivery", timeout=3.0) is not None
        await ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        assert await ph.drain_until(ws, "anon_delivery_ack_ok", timeout=3.0) is not None

        # Replay with the now-SPENT token.
        await ws.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "m2", "blob": "aGVsbG8="},
        }))
        msgs = await ph.drain_all(ws, quiet_for=1.0, max_total=2.0)
        types = [m.get("type") for m in msgs if isinstance(m, dict)]
        assert "anon_delivery" not in types, f"a SPENT token was delivered again: {msgs}"
        assert {"type": "ack", "id": "m2"} in msgs, f"expected the indistinguishable fake ack, got: {msgs}"
    finally:
        await ws.close()


async def test_replay_of_revoked_token_gets_indistinguishable_fake_ack(managed_server: ph.ManagedServer):
    """Same as the SPENT case, but via unsubscribe_tokens (REVOKED) instead
    of a real delivery+ACK cycle."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="replayrevoked1")
    try:
        token = ph.rand_token()
        await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await ws.send(json.dumps({"type": "unsubscribe_tokens", "tokens": [token]}))
        await ws.send(json.dumps({"type": "ping"}))
        assert await ph.drain_until(ws, "pong", timeout=3.0) is not None

        await ws.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "m1", "blob": "aGVsbG8="},
        }))
        msgs = await ph.drain_all(ws, quiet_for=1.0, max_total=2.0)
        types = [m.get("type") for m in msgs if isinstance(m, dict)]
        assert "anon_delivery" not in types, f"a REVOKED token was delivered: {msgs}"
        assert {"type": "ack", "id": "m1"} in msgs, f"expected the indistinguishable fake ack, got: {msgs}"
    finally:
        await ws.close()


async def test_unknown_decoy_token_gets_same_fake_ack_as_spent(managed_server: ph.ManagedServer):
    """A random 32-char string nobody ever subscribed to must be
    indistinguishable, on the wire, from a real-but-spent token -- both
    get exactly {"type": "ack", "id": msg_id} and nothing else."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="decoytoken1")
    try:
        decoy = ph.rand_token()
        await ws.send(json.dumps({
            "type": "anon_message", "token": decoy,
            "payload": {"id": "m1", "blob": "aGVsbG8="},
        }))
        msgs = await ph.drain_all(ws, quiet_for=1.0, max_total=2.0)
        assert msgs == [{"type": "ack", "id": "m1"}], f"decoy token got a distinguishable response: {msgs}"
    finally:
        await ws.close()


async def test_revoke_identity_closes_connection_and_further_traffic_fails(managed_server: ph.ManagedServer):
    """revoke_identity (server.py ~9646) closes the connection on success.
    A subsequent register attempt with the SAME (now-revoked) key must be
    refused."""
    priv, pub_der = ph.gen_keypair()
    ws = await websockets.connect(managed_server.url)
    await ph.handshake(ws, priv, pub_der)
    await ph.register(ws, pub_der, "revokedid1")
    await ph.drain_until(ws, "register_ok", timeout=3.0)
    await ws.send(json.dumps({"type": "revoke_identity"}))
    assert await ph.drain_until(ws, "identity_revoked_ack", timeout=3.0) is not None
    with pytest.raises(websockets.exceptions.ConnectionClosed):
        await ws.recv()

    ws2 = await websockets.connect(managed_server.url)
    try:
        await ph.handshake(ws2, priv, pub_der)
        await ph.register(ws2, pub_der, "revokedid1")
        msgs = await ph.drain_all(ws2, quiet_for=1.0, max_total=3.0)
        assert not any(m.get("type") == "register_ok" for m in msgs if isinstance(m, dict)), \
            f"a revoked identity was allowed to re-register: {msgs}"
    finally:
        await ws2.close()
