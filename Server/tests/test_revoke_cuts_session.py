"""
N1: revoking an identity (here via the operator tool, which writes straight into
SQLite and cannot talk to the server process) must cut that identity's LIVE
session — not just refuse its next register(). Real server subprocess, real
websocket client, isolated loopback port + temp DB (protocol_harness.ManagedServer).
"""
import asyncio
import json
import os
import subprocess
import sys
import time

import pytest
import websockets

import protocol_harness as ph

pytestmark = pytest.mark.asyncio

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "admin_users.py")
INTERVAL = 1  # seconds, via REVOKED_SESSION_SWEEP_INTERVAL_SEC


def revoke_with_tool(db_path, fingerprint):
    env = dict(os.environ, DB_PATH=str(db_path))
    env.pop("DB_ENCRYPTION_KEY_HEX", None)
    r = subprocess.run([sys.executable, TOOL, "revoke", fingerprint, "--yes"], env=env,
                       capture_output=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr


async def recv_until_closed(ws, timeout):
    """Collect frames until the server closes the socket. Returns (frames, seconds)."""
    t0 = time.monotonic()
    frames = []
    try:
        while time.monotonic() - t0 < timeout:
            frames.append(json.loads(await asyncio.wait_for(ws.recv(), timeout)))
    except websockets.ConnectionClosed:
        return frames, time.monotonic() - t0
    except asyncio.TimeoutError:
        pass
    return frames, None


async def test_live_session_of_revoked_identity_is_cut_and_cannot_return():
    with ph.ManagedServer(extra_env={"REVOKED_SESSION_SWEEP_INTERVAL_SEC": str(INTERVAL)}) as srv:
        victim, victim_fp, v_priv, v_pub = await ph.connect_and_register(srv.url, "victim")
        bystander, _, *_ = await ph.connect_and_register(srv.url, "bystander")

        revoke_with_tool(srv.db_path, victim_fp)          # server process is NOT told
        frames, took = await recv_until_closed(victim, timeout=INTERVAL * 6 + 5)

        assert took is not None, "revoked identity's live session was NOT closed"
        assert any(f.get("type") == "identity_revoked" for f in frames), frames
        assert took < INTERVAL * 3 + 5, f"cut after {took:.1f}s with a {INTERVAL}s sweep"

        # the bystander is untouched: still connected, still answers a ping
        await bystander.send(json.dumps({"type": "ping"}))
        assert bystander.state.name == "OPEN"

        # and the victim cannot come back (register() refuses with identity_revoked)
        again = await websockets.connect(srv.url, max_size=ph.CLIENT_MAX_SIZE)
        await ph.handshake(again, v_priv, v_pub)
        await ph.register(again, v_pub, "victim")
        refused = json.loads(await asyncio.wait_for(again.recv(), 5))
        assert refused.get("type") == "identity_revoked", refused
        await again.close()
        await bystander.close()


async def test_no_revocations_means_nobody_is_cut():
    with ph.ManagedServer(extra_env={"REVOKED_SESSION_SWEEP_INTERVAL_SEC": str(INTERVAL)}) as srv:
        ws, *_ = await ph.connect_and_register(srv.url, "alone")
        frames, took = await recv_until_closed(ws, timeout=INTERVAL * 3 + 1)
        assert took is None and ws.state.name == "OPEN"
        await ws.close()
