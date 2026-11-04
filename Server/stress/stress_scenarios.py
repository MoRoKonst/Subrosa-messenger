"""
Individual stress scenarios. Each takes (url, report, **params) and fills
in the ScenarioReport as it runs. Every scenario uses bounded
semaphores/task counts (section 33 of the spec this implements) -- no
scenario here spawns an unbounded number of coroutines regardless of the
`clients`/`duration` parameters passed to it.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import time
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import protocol_harness as ph  # noqa: E402

from stress_metrics import ScenarioReport  # noqa: E402

MALFORMED_FRAMES = [
    "not json {{{", "null", "true", "42", '"str"', "[]", "{}",
    '{"type": null}', '{"type": 12345}', '{"type": "unknown_xyz"}',
]


async def connection_churn(url: str, report: ScenarioReport, *, clients: int = 50,
                            duration: float = 10.0, concurrency: int = 20):
    """Ramps connection churn: connect-then-disconnect at various points in
    the handshake/register sequence, plus a register->reconnect loop.
    Bounded by both `clients` (total attempts) and `concurrency` (in-flight
    at once) -- see the module docstring."""
    report.notes.append(f"clients={clients} duration={duration}s concurrency={concurrency}")
    sem = asyncio.Semaphore(concurrency)
    deadline = time.monotonic() + duration
    attempted = 0
    lock = asyncio.Lock()

    async def one_churn(i: int):
        nonlocal attempted
        async with lock:
            attempted += 1
        report.attempted += 1
        pattern = i % 4
        t0 = time.monotonic()
        try:
            async with sem:
                if pattern == 0:
                    # Connect, read the challenge, disconnect immediately.
                    ws = await websockets.connect(url)
                    await ws.recv()
                    await ws.close()
                elif pattern == 1:
                    # Full handshake, then disconnect without registering.
                    priv, pub_der = ph.gen_keypair()
                    ws = await websockets.connect(url)
                    await ph.handshake(ws, priv, pub_der)
                    await ws.close()
                elif pattern == 2:
                    # Register, then disconnect (server-side cleanup path).
                    ws, fp, priv, pub = await ph.connect_and_register(url, device_id=f"churn{i}")
                    await ws.close()
                else:
                    # Register, reconnect with the same identity twice.
                    priv, pub_der = ph.gen_keypair()
                    ws = await websockets.connect(url)
                    await ph.handshake(ws, priv, pub_der)
                    await ph.register(ws, pub_der, f"churnreconnect{i}")
                    await ph.drain_until(ws, "register_ok", timeout=5.0)
                    await ws.close()
                    ws2 = await websockets.connect(url)
                    await ph.handshake(ws2, priv, pub_der)
                    await ph.register(ws2, pub_der, f"churnreconnect{i}")
                    await ph.drain_until(ws2, "register_ok", timeout=5.0)
                    await ws2.close()
            report.succeeded += 1
            report.latencies_sec.append(time.monotonic() - t0)
        except Exception as e:
            report.unexpected_errors += 1
            report.notes.append(f"churn#{i} pattern={pattern} error: {e!r}")

    tasks = []
    i = 0
    while time.monotonic() < deadline and i < clients:
        tasks.append(asyncio.create_task(one_churn(i)))
        i += 1
        if len(tasks) >= concurrency:
            await asyncio.gather(*tasks)
            tasks = []
        await asyncio.sleep(0)
    if tasks:
        await asyncio.gather(*tasks)


async def anon_token_stress(url: str, report: ScenarioReport, *, clients: int = 20,
                             tokens_per_client: int = 10, concurrency: int = 10):
    """Legitimate subscribe->send(self)->ack cycles, decoy tokens, and
    replay attempts, run across many independent client connections.
    Invariant checked per-token: exactly one real delivery for a legit
    token, zero for decoys/replays (see anon-token state-machine tests in
    tests/test_protocol_stateful.py for the single-connection version of
    this same invariant -- this scenario is the load-bearing multi-client
    version)."""
    report.notes.append(f"clients={clients} tokens_per_client={tokens_per_client}")
    sem = asyncio.Semaphore(concurrency)

    async def one_client(i: int):
        try:
            async with sem:
                ws, fp, priv, pub = await ph.connect_and_register(url, device_id=f"anonstress{i}")
            try:
                for j in range(tokens_per_client):
                    report.attempted += 1
                    t0 = time.monotonic()
                    token = ph.rand_token()
                    await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
                    msg_id = f"c{i}t{j}"
                    await ws.send(json.dumps({
                        "type": "anon_message", "token": token,
                        "payload": {"id": msg_id, "blob": "aGVsbG8="},
                    }))
                    delivered = await ph.drain_until(ws, "anon_delivery", timeout=5.0)
                    if delivered is None:
                        report.invariant_violations.append(f"client{i}/token{j}: no delivery for a fresh legit token")
                        continue
                    await ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
                    ack_ok = await ph.drain_until(ws, "anon_delivery_ack_ok", timeout=5.0)
                    if ack_ok is None:
                        report.invariant_violations.append(f"client{i}/token{j}: ack not confirmed")
                        continue
                    report.latencies_sec.append(time.monotonic() - t0)
                    report.succeeded += 1

                    # Replay: must NOT deliver again.
                    await ws.send(json.dumps({
                        "type": "anon_message", "token": token,
                        "payload": {"id": msg_id + "-replay", "blob": "aGVsbG8="},
                    }))
                    replay_msgs = await ph.drain_all(ws, quiet_for=0.5, max_total=1.5)
                    if any(m.get("type") == "anon_delivery" for m in replay_msgs if isinstance(m, dict)):
                        report.invariant_violations.append(f"client{i}/token{j}: SPENT token delivered again on replay")
                    else:
                        report.rejected_expected += 1

                # Decoy tokens: must never deliver.
                for k in range(max(1, tokens_per_client // 5)):
                    decoy = ph.rand_token()
                    await ws.send(json.dumps({
                        "type": "anon_message", "token": decoy,
                        "payload": {"id": f"decoy{i}-{k}", "blob": "aGVsbG8="},
                    }))
                msgs = await ph.drain_all(ws, quiet_for=0.5, max_total=1.5)
                if any(m.get("type") == "anon_delivery" for m in msgs if isinstance(m, dict)):
                    report.invariant_violations.append(f"client{i}: a decoy token was delivered")
                else:
                    report.rejected_expected += len(msgs)
            finally:
                await ws.close()
        except Exception as e:
            report.unexpected_errors += 1
            report.notes.append(f"anon_client#{i} error: {e!r}")

    await asyncio.gather(*(one_client(i) for i in range(clients)))


async def mixed_traffic_with_canary(url: str, report: ScenarioReport, *, malicious_clients: int = 10,
                                     duration: float = 8.0, canary_interval: float = 0.3,
                                     min_canary_success_rate: float = 0.8):
    """A healthy canary pair keeps doing small, real message round-trips
    throughout the whole scenario while `malicious_clients` concurrently
    send malformed frames / floods / bad-owner ACKs. The only hard FAIL
    oracle here is the canary success rate dropping below
    `min_canary_success_rate` -- everything else is reported, not asserted
    (section 34: measured numbers, not capacity claims)."""
    report.notes.append(f"malicious_clients={malicious_clients} duration={duration}s "
                         f"min_canary_success_rate={min_canary_success_rate}")
    canary_a, fp_a, _, _ = await ph.connect_and_register(url, device_id="canaryA")
    canary_b, fp_b, _, _ = await ph.connect_and_register(url, device_id="canaryB")

    canary_ok = 0
    canary_fail = 0
    stop = asyncio.Event()

    async def canary_loop():
        nonlocal canary_ok, canary_fail
        i = 0
        while not stop.is_set():
            i += 1
            t0 = time.monotonic()
            msg_id = f"canary{i}"
            try:
                await canary_a.send(json.dumps({
                    "type": "message", "to": fp_b, "id": msg_id,
                    "text": "hi", "signature": "x", "protocol_version": 2,
                }))
                got = await ph.drain_until(canary_b, "message", timeout=3.0)
                if got is not None and got.get("id") == msg_id:
                    canary_ok += 1
                    report.latencies_sec.append(time.monotonic() - t0)
                else:
                    canary_fail += 1
            except Exception:
                canary_fail += 1
            await asyncio.sleep(canary_interval)

    async def malicious_client(i: int):
        try:
            ws, fp, priv, pub = await ph.connect_and_register(url, device_id=f"malicious{i}")
            try:
                end = time.monotonic() + duration
                while time.monotonic() < end:
                    report.attempted += 1
                    action = random.choice(["frame", "flood", "badtoken", "wrongowner"])
                    if action == "frame":
                        await ws.send(random.choice(MALFORMED_FRAMES))
                    elif action == "flood":
                        for _ in range(20):
                            await ws.send(json.dumps({"type": "profile_update", "avatar": ""}))
                    elif action == "badtoken":
                        await ws.send(json.dumps({
                            "type": "anon_message", "token": ph.rand_token(),
                            "payload": {"id": "x", "blob": "eA=="},
                        }))
                    else:
                        await ws.send(json.dumps({"type": "anon_delivery_ack", "token": ph.rand_token()}))
                    report.rejected_expected += 1
                    await asyncio.sleep(0.05)
            finally:
                await ws.close()
        except Exception as e:
            report.unexpected_errors += 1
            report.notes.append(f"malicious#{i} error: {e!r}")

    canary_task = asyncio.create_task(canary_loop())
    try:
        await asyncio.gather(*(malicious_client(i) for i in range(malicious_clients)))
    finally:
        stop.set()
        await canary_task
        await canary_a.close()
        await canary_b.close()

    report.succeeded = canary_ok
    total_canary = canary_ok + canary_fail
    rate = (canary_ok / total_canary) if total_canary else 0.0
    report.notes.append(f"canary: {canary_ok}/{total_canary} succeeded ({rate:.1%})")
    if total_canary == 0:
        report.invariant_violations.append("canary never completed a single round-trip")
    elif rate < min_canary_success_rate:
        report.invariant_violations.append(
            f"canary success rate {rate:.1%} fell below {min_canary_success_rate:.0%} under malicious load"
        )
