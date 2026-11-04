#!/usr/bin/env python3
"""
Performance benchmark for the Subrosa server -- throughput (msg/s), latency
percentiles, and event-loop lag under aggregate client load.

Why this is separate from the three systems in README.md: `stress_server.py`
answers "does the server stay correct and non-starved under adversarial
load" (pass/fail oracles on invariants). This file answers "how many
messages per second does it actually relay, and where does the time go"
(numbers, no oracles). Mixing a perf regression number into a security
scenario's FAIL condition would make both worse -- a slow machine would
start failing security tests.

SAFETY: identical model to stress_server.py -- always starts its own
`server.py` subprocess via protocol_harness.ManagedServer (loopback-only,
temp-DB-only, minimal child env). No --host/--target flag exists.

IMPORTANT, read before believing any number this prints
--------------------------------------------------------
server.py enforces PER-USER rate limits (`rate_limit_check`):
`anon_message` 500/60s (8.3/s per user), `message` 50/60s (0.83/s per
user). A single client therefore CANNOT saturate the server -- it saturates
its own bucket first. Aggregate server capacity is only observable across
many concurrent clients, which is what every scenario here does. Any
benchmark of this server that uses one or two connections is measuring the
rate limiter, not the server.

Usage:
    python bench_throughput.py --profile quick
    python bench_throughput.py --profile full --json before.json
    python bench_throughput.py --scenario anon_relay --clients 40
"""
from __future__ import annotations

import argparse
import asyncio
import json
import platform
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import protocol_harness as ph  # noqa: E402

# `subscribe_tokens` sends NO reply on the ordinary success path -- verified
# empirically against a live server, then confirmed in server.py: the only
# reply, `subscribe_tokens_result`, is sent exclusively `if already_spent`
# (i.e. when some submitted token was already SPENT/REVOKED). A benchmark
# that waits for a subscription acknowledgement therefore hangs forever on
# the happy path; that is how this was found.
#
# `ping` -> `pong` is used instead as a sync barrier. It is the only
# request/response pair in the protocol with no rate limit and no durable
# write, and because one WebSocket's frames are processed sequentially by a
# single `async for` loop in handle_client, a `pong` proves every frame sent
# before the `ping` has already been fully processed.
async def _barrier(ws, timeout: float = 30.0):
    await ws.send(json.dumps({"type": "ping"}))
    return await ph.drain_until(ws, "pong", timeout=timeout)


# ─── Result model ──────────────────────────────────────────────────────────

@dataclass
class BenchResult:
    name: str
    ops: int = 0
    errors: int = 0
    wall_sec: float = 0.0
    latencies_sec: list = field(default_factory=list)
    loop_lag_sec: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    peak_rss_mb: float | None = None
    peak_cpu_pct: float | None = None

    @property
    def ops_per_sec(self) -> float:
        return (self.ops / self.wall_sec) if self.wall_sec > 0 else 0.0

    def summary(self) -> dict:
        lat = ph.percentiles(self.latencies_sec) if self.latencies_sec else {}
        lag = ph.percentiles(self.loop_lag_sec) if self.loop_lag_sec else {}
        return {
            "name": self.name,
            "ops": self.ops,
            "errors": self.errors,
            "wall_sec": round(self.wall_sec, 3),
            "ops_per_sec": round(self.ops_per_sec, 1),
            "latency_ms": lat,
            "client_loop_lag_ms": lag,
            "peak_rss_mb": self.peak_rss_mb,
            "peak_cpu_pct": self.peak_cpu_pct,
            "notes": self.notes,
        }

    def print(self):
        s = self.summary()
        print(f"\n=== {self.name} ===")
        print(f"  ops              : {s['ops']}  (errors {s['errors']})")
        print(f"  wall             : {s['wall_sec']}s")
        print(f"  THROUGHPUT       : {s['ops_per_sec']} ops/sec")
        if s["latency_ms"]:
            lm = s["latency_ms"]
            print(f"  latency ms       : p50={lm.get('p50')} p95={lm.get('p95')} "
                  f"p99={lm.get('p99')} max={lm.get('max')}")
        if s["client_loop_lag_ms"]:
            lg = s["client_loop_lag_ms"]
            print(f"  client loop lag  : p50={lg.get('p50')} p99={lg.get('p99')} max={lg.get('max')}")
        if s["peak_rss_mb"] is not None:
            print(f"  server peak RSS  : {s['peak_rss_mb']} MB   peak CPU {s['peak_cpu_pct']}%")
        for n in s["notes"]:
            print(f"  note: {n}")


# ─── Client-side event-loop lag probe ──────────────────────────────────────
# Measures how late a 10ms sleep actually fires in THIS process. It is a
# proxy for "is the benchmark client itself the bottleneck" -- if client lag
# is high, the throughput number below is a client artifact, not a server
# limit. Deliberately measured and printed rather than assumed away.

async def _loop_lag_probe(result: BenchResult, stop: asyncio.Event, interval: float = 0.01):
    while not stop.is_set():
        t0 = time.perf_counter()
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
        result.loop_lag_sec.append(max(0.0, (time.perf_counter() - t0) - interval))


# ─── Scenario 1: anonymous relay, online recipient (pure RAM path) ─────────

async def bench_anon_relay(url: str, *, clients: int, msgs_per_client: int,
                            payload_bytes: int = 256) -> BenchResult:
    """The hot path of the whole product: anon_message -> token_to_ws lookup
    -> relay to an ONLINE socket -> anon_delivery_ack.

    This path performs TWO durable SQLite transactions per round trip even
    though the recipient is online and the payload itself is never persisted:
    `db_mark_anon_token_inflight()` (server.py, ACTIVE->IN_FLIGHT) on the send
    and `db_terminalize_anon_token()` (->SPENT) on the ack. Both are required
    by the token single-use invariants, so this scenario measures the combined
    relay+durability cost and is the one most sensitive to SQLite
    configuration. Compare against `direct_message`, which relays through the
    same machinery with NO durable write, to separate the two.

    Each client is an independent registered identity (own rate-limit
    bucket) that subscribes its own tokens and sends to itself -- the server
    does the identical relay work as a cross-client send (same
    `token_to_ws` lookup, same send_safe), while keeping the measurement
    free of cross-client scheduling noise.
    """
    r = BenchResult(name=f"anon_relay(clients={clients}, msgs={msgs_per_client}, payload={payload_bytes}B)")
    blob = "A" * payload_bytes

    # Rate limit reality check: anon_message is 500/60s per user.
    if msgs_per_client > 480:
        r.notes.append(
            f"msgs_per_client={msgs_per_client} exceeds the per-user anon_message "
            f"rate limit (500/60s) -- numbers will include throttled/dropped sends"
        )

    conns = []
    try:
        for i in range(clients):
            ws, fp, priv, pub = await ph.connect_and_register(url, device_id=f"bench_anon{i}")
            conns.append(ws)

        async def one_client(ws, idx: int) -> tuple[int, int, list]:
            ok = 0
            err = 0
            lats = []
            tokens = [ph.rand_token() for _ in range(msgs_per_client)]
            # Subscribe in ONE frame: subscribe_tokens is itself rate limited
            # and does a durable claim write, so per-message subscription
            # would benchmark the claim path instead of the relay path.
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": tokens}))
            await _barrier(ws)
            for j, tok in enumerate(tokens):
                t0 = time.perf_counter()
                try:
                    await ws.send(json.dumps({
                        "type": "anon_message", "token": tok,
                        "payload": {"id": f"b{idx}-{j}", "blob": blob},
                    }))
                    got = await ph.drain_until(ws, "anon_delivery", timeout=10.0)
                    if got is None:
                        err += 1
                        continue
                    await ws.send(json.dumps({"type": "anon_delivery_ack", "token": tok}))
                    await ph.drain_until(ws, "anon_delivery_ack_ok", timeout=10.0)
                    lats.append(time.perf_counter() - t0)
                    ok += 1
                except Exception:
                    err += 1
            return ok, err, lats

        stop = asyncio.Event()
        probe = asyncio.create_task(_loop_lag_probe(r, stop))
        t_start = time.perf_counter()
        results = await asyncio.gather(*(one_client(ws, i) for i, ws in enumerate(conns)),
                                        return_exceptions=True)
        r.wall_sec = time.perf_counter() - t_start
        stop.set()
        await probe

        for res in results:
            if isinstance(res, Exception):
                r.errors += 1
                r.notes.append(f"client-level exception: {res!r}")
                continue
            ok, err, lats = res
            r.ops += ok
            r.errors += err
            r.latencies_sec.extend(lats)
    finally:
        await asyncio.gather(*(c.close() for c in conns), return_exceptions=True)
    r.notes.append("2 durable SQLite tx per op (mark_inflight + terminalize) -- "
                   "disk-bound; compare with direct_message for the no-write path")
    return r


# ─── Scenario 2: direct message to an online peer ──────────────────────────

async def bench_direct_message(url: str, *, pairs: int, msgs_per_pair: int,
                                text_bytes: int = 256) -> BenchResult:
    """Fingerprint-addressed `message` to an ONLINE recipient. Same RAM
    relay path as anon_relay but through the non-anonymous dispatch branch,
    which sits much earlier in handle_client's if-chain -- useful as the
    control when measuring dispatch-order cost."""
    r = BenchResult(name=f"direct_message(pairs={pairs}, msgs={msgs_per_pair}, text={text_bytes}B)")
    text = "A" * text_bytes
    if msgs_per_pair > 48:
        r.notes.append(
            f"msgs_per_pair={msgs_per_pair} exceeds the per-user `message` rate "
            f"limit (50/60s) -- expect throttling in these numbers"
        )
    conns = []
    try:
        pair_list = []
        for i in range(pairs):
            a, fp_a, _, _ = await ph.connect_and_register(url, device_id=f"bench_dmA{i}")
            b, fp_b, _, _ = await ph.connect_and_register(url, device_id=f"bench_dmB{i}")
            conns += [a, b]
            pair_list.append((a, b, fp_b))

        async def one_pair(a, b, fp_b, idx: int):
            ok, err, lats = 0, 0, []
            for j in range(msgs_per_pair):
                mid = f"dm{idx}-{j}"
                t0 = time.perf_counter()
                try:
                    await a.send(json.dumps({
                        "type": "message", "to": fp_b, "id": mid,
                        "text": text, "signature": "x", "protocol_version": 2,
                    }))
                    got = await ph.drain_until(b, "message", timeout=10.0)
                    if got is None or got.get("id") != mid:
                        err += 1
                        continue
                    lats.append(time.perf_counter() - t0)
                    ok += 1
                except Exception:
                    err += 1
            return ok, err, lats

        stop = asyncio.Event()
        probe = asyncio.create_task(_loop_lag_probe(r, stop))
        t_start = time.perf_counter()
        results = await asyncio.gather(
            *(one_pair(a, b, fp, i) for i, (a, b, fp) in enumerate(pair_list)),
            return_exceptions=True)
        r.wall_sec = time.perf_counter() - t_start
        stop.set()
        await probe

        for res in results:
            if isinstance(res, Exception):
                r.errors += 1
                r.notes.append(f"pair-level exception: {res!r}")
                continue
            ok, err, lats = res
            r.ops += ok
            r.errors += err
            r.latencies_sec.extend(lats)
    finally:
        await asyncio.gather(*(c.close() for c in conns), return_exceptions=True)
    return r


# ─── Scenario 3: token subscription (durable claim write per token) ─────────

async def bench_subscribe_tokens(url: str, *, clients: int, tokens_per_batch: int,
                                  batches: int) -> BenchResult:
    """`subscribe_tokens` -> db_claim_anon_tokens -> a real SQLite write
    transaction per batch. This is the DISK-bound counterpart to
    bench_anon_relay, and the scenario where SQLite journal/synchronous
    configuration dominates the result."""
    r = BenchResult(name=f"subscribe_tokens(clients={clients}, {tokens_per_batch}tok x {batches} batches)")
    conns = []
    try:
        for i in range(clients):
            ws, fp, priv, pub = await ph.connect_and_register(url, device_id=f"bench_sub{i}")
            conns.append(ws)

        async def one_client(ws, idx: int):
            ok, err, lats = 0, 0, []
            for b in range(batches):
                tokens = [ph.rand_token() for _ in range(tokens_per_batch)]
                t0 = time.perf_counter()
                try:
                    await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": tokens}))
                    # No success reply exists -- a ping/pong barrier is what
                    # proves the claim transaction actually committed.
                    if await _barrier(ws) is None:
                        err += 1
                        continue
                    lats.append(time.perf_counter() - t0)
                    ok += tokens_per_batch
                except Exception:
                    err += 1
            return ok, err, lats

        stop = asyncio.Event()
        probe = asyncio.create_task(_loop_lag_probe(r, stop))
        t_start = time.perf_counter()
        results = await asyncio.gather(*(one_client(ws, i) for i, ws in enumerate(conns)),
                                        return_exceptions=True)
        r.wall_sec = time.perf_counter() - t_start
        stop.set()
        await probe

        for res in results:
            if isinstance(res, Exception):
                r.errors += 1
                r.notes.append(f"client-level exception: {res!r}")
                continue
            ok, err, lats = res
            r.ops += ok
            r.errors += err
            r.latencies_sec.extend(lats)
    finally:
        await asyncio.gather(*(c.close() for c in conns), return_exceptions=True)
    r.notes.append("ops counts TOKENS claimed; latency is per-BATCH (one SQLite tx per batch)")
    return r


# ─── Scenario 4: call signaling, alone and under contention ───────────────

async def bench_call_signaling(url: str, *, pairs: int, ice_per_call: int,
                                contend_clients: int = 0,
                                contend_msgs: int = 0) -> BenchResult:
    """`call_offer` -> `call_answer` -> a stream of `call_ice`, relayed
    between two registered peers. Call signaling is the most
    latency-sensitive traffic in the product and it carries no durable
    write, so on its own it should look like `direct_message`.

    The question this scenario exists to answer is the interesting one:
    does OTHER traffic measurably hurt call-signaling tail latency? Pass
    `contend_clients`/`contend_msgs` to run the durable-write `anon_message`
    load concurrently in the background while the calls are measured. That
    is the evidence needed before deciding whether call signaling deserves
    its own process -- without it, "move calls to a sub-server" is an
    architectural preference, not a measured requirement.

    Latency is measured per signaling message (offer, answer, and each ICE
    candidate), as seen by the receiving peer.
    """
    label = f"call_signaling(pairs={pairs}, ice={ice_per_call}"
    if contend_clients:
        label += f", contention={contend_clients}x{contend_msgs} anon_message"
    label += ")"
    r = BenchResult(name=label)

    # call_offer is rate limited to 20/60s and call_ice to 300/60s per user
    # (server.py rate_limit_check defaults) -- one call per pair plus
    # ice_per_call candidates stays well inside both.
    if ice_per_call > 280:
        r.notes.append(f"ice_per_call={ice_per_call} approaches the call_ice limit (300/60s)")

    sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n" + ("a=x\r\n" * 40)
    candidate = "candidate:1 1 UDP 2130706431 192.0.2.1 50000 typ host"

    conns = []
    contend_conns = []
    contend_tasks = []
    stop_contention = asyncio.Event()
    contention_ops = 0

    try:
        pair_list = []
        for i in range(pairs):
            a, fp_a, _, _ = await ph.connect_and_register(url, device_id=f"bench_callA{i}")
            b, fp_b, _, _ = await ph.connect_and_register(url, device_id=f"bench_callB{i}")
            conns += [a, b]
            pair_list.append((a, fp_a, b, fp_b))

        # ── background durable-write load, if requested ──
        async def contender(idx: int):
            nonlocal contention_ops
            try:
                ws, fp, _, _ = await ph.connect_and_register(url, device_id=f"bench_callbg{idx}")
                contend_conns.append(ws)
                tokens = [ph.rand_token() for _ in range(contend_msgs)]
                await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": tokens}))
                await _barrier(ws)
                for tok in tokens:
                    if stop_contention.is_set():
                        return
                    await ws.send(json.dumps({
                        "type": "anon_message", "token": tok,
                        "payload": {"id": tok[:8], "blob": "A" * 256},
                    }))
                    if await ph.drain_until(ws, "anon_delivery", timeout=10.0) is None:
                        continue
                    await ws.send(json.dumps({"type": "anon_delivery_ack", "token": tok}))
                    await ph.drain_until(ws, "anon_delivery_ack_ok", timeout=10.0)
                    contention_ops += 1
            except Exception:
                pass

        contend_tasks = [asyncio.create_task(contender(i)) for i in range(contend_clients)]
        if contend_tasks:
            # Let the background load actually get going before measuring,
            # otherwise the first calls are measured against an idle server
            # and the contention number means nothing.
            await asyncio.sleep(1.0)

        async def one_call(a, fp_a, b, fp_b, idx: int):
            ok, err, lats = 0, 0, []
            call_id = str(uuid.uuid4())
            try:
                # offer: A -> B
                t0 = time.perf_counter()
                await a.send(json.dumps({
                    "type": "call_offer", "to": fp_b, "call_id": call_id,
                    "sdp": sdp, "is_video": False, "is_group": False,
                }))
                if await ph.drain_until(b, "call_offer", timeout=10.0) is None:
                    return 0, 1, []
                lats.append(time.perf_counter() - t0)
                ok += 1

                # answer: B -> A
                t0 = time.perf_counter()
                await b.send(json.dumps({
                    "type": "call_answer", "to": fp_a, "call_id": call_id, "sdp": sdp,
                }))
                if await ph.drain_until(a, "call_answer", timeout=10.0) is None:
                    return ok, 1, lats
                lats.append(time.perf_counter() - t0)
                ok += 1

                # ICE candidates, alternating direction like a real negotiation
                for j in range(ice_per_call):
                    src, dst, dst_fp = (a, b, fp_b) if j % 2 == 0 else (b, a, fp_a)
                    t0 = time.perf_counter()
                    await src.send(json.dumps({
                        "type": "call_ice", "to": dst_fp, "call_id": call_id,
                        "candidate": candidate, "sdp_m_line_index": 0,
                        "sdp_mid": "0",
                    }))
                    if await ph.drain_until(dst, "call_ice", timeout=10.0) is None:
                        err += 1
                        continue
                    lats.append(time.perf_counter() - t0)
                    ok += 1
            except Exception:
                err += 1
            return ok, err, lats

        stop = asyncio.Event()
        probe = asyncio.create_task(_loop_lag_probe(r, stop))
        t_start = time.perf_counter()
        results = await asyncio.gather(
            *(one_call(a, fa, b, fb, i) for i, (a, fa, b, fb) in enumerate(pair_list)),
            return_exceptions=True)
        r.wall_sec = time.perf_counter() - t_start
        stop.set()
        await probe

        for res in results:
            if isinstance(res, Exception):
                r.errors += 1
                r.notes.append(f"call-level exception: {res!r}")
                continue
            ok, err, lats = res
            r.ops += ok
            r.errors += err
            r.latencies_sec.extend(lats)
    finally:
        stop_contention.set()
        for t in contend_tasks:
            t.cancel()
        if contend_tasks:
            await asyncio.gather(*contend_tasks, return_exceptions=True)
        await asyncio.gather(*(c.close() for c in conns + contend_conns),
                             return_exceptions=True)

    r.notes.append("no durable SQLite write on this path -- pure relay, "
                   "like direct_message")
    if contend_clients:
        r.notes.append(f"background anon_message round trips completed during "
                       f"measurement: {contention_ops}")
    return r


# ─── Scenario 5: registration (BEGIN IMMEDIATE transaction per op) ─────────

async def bench_register(url: str, *, clients: int) -> BenchResult:
    """Full connect + ECDSA challenge-response handshake + register. Each
    registration takes the registration-cap transaction (BEGIN IMMEDIATE),
    so this is the most write-serialized path in the server."""
    r = BenchResult(name=f"register(clients={clients})")

    # `NEW_ACCOUNT_GLOBAL_LIMIT` defaults to 60 per 60s (server.py:2467) and
    # is a SERVER-WIDE aggregate, not per-user -- so more than ~60 clients in
    # one run measures that limiter, not registration capacity. Found
    # empirically: 80 clients produced exactly 60 successes and 20 errors.
    # Raise it deliberately when you want the real number:
    #   --server-env NEW_ACCOUNT_GLOBAL_LIMIT=1000
    if clients > 55:
        r.notes.append(
            f"clients={clients} is at/above NEW_ACCOUNT_GLOBAL_LIMIT (default 60/60s, "
            f"server-wide) -- errors here are that limiter doing its job, not failures. "
            f"Re-run with --server-env NEW_ACCOUNT_GLOBAL_LIMIT=1000 for capacity."
        )

    async def one(i: int):
        t0 = time.perf_counter()
        try:
            ws, fp, priv, pub = await ph.connect_and_register(url, device_id=f"bench_reg{i}")
            await ws.close()
            return True, time.perf_counter() - t0
        except Exception:
            return False, time.perf_counter() - t0

    stop = asyncio.Event()
    probe = asyncio.create_task(_loop_lag_probe(r, stop))
    t_start = time.perf_counter()
    results = await asyncio.gather(*(one(i) for i in range(clients)), return_exceptions=True)
    r.wall_sec = time.perf_counter() - t_start
    stop.set()
    await probe

    for res in results:
        if isinstance(res, Exception):
            r.errors += 1
            continue
        ok, lat = res
        if ok:
            r.ops += 1
            r.latencies_sec.append(lat)
        else:
            r.errors += 1
    r.notes.append("includes client-side ECDSA keygen+sign, which is NOT server cost")
    return r


# ─── Runner ────────────────────────────────────────────────────────────────

PROFILES = {
    "quick": {
        "anon_relay":       dict(clients=10, msgs_per_client=20),
        "direct_message":   dict(pairs=5, msgs_per_pair=20),
        "subscribe_tokens": dict(clients=5, tokens_per_batch=20, batches=5),
        "call_signaling":   dict(pairs=5, ice_per_call=20),
        "call_contended":   dict(pairs=5, ice_per_call=20,
                                 contend_clients=10, contend_msgs=40),
        "register":         dict(clients=20),
    },
    "full": {
        "anon_relay":       dict(clients=40, msgs_per_client=100),
        "direct_message":   dict(pairs=20, msgs_per_pair=40),
        "subscribe_tokens": dict(clients=20, tokens_per_batch=20, batches=10),
        "call_signaling":   dict(pairs=15, ice_per_call=60),
        "call_contended":   dict(pairs=15, ice_per_call=60,
                                 contend_clients=30, contend_msgs=100),
        "register":         dict(clients=80),
    },
}

SCENARIOS = {
    "anon_relay": bench_anon_relay,
    "direct_message": bench_direct_message,
    "subscribe_tokens": bench_subscribe_tokens,
    # Same function twice, deliberately: `call_signaling` is the clean
    # baseline and `call_contended` is the same measurement with durable-write
    # load running behind it. The pair is the whole point -- a single number
    # for call latency says nothing about whether other traffic hurts it.
    "call_signaling": bench_call_signaling,
    "call_contended": bench_call_signaling,
    "register": bench_register,
}


def env_banner() -> dict:
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "websockets": getattr(websockets, "__version__", "?"),
    }


async def run(profile: str, only: str | None, overrides: dict, json_out: str | None,
              server_env: dict) -> int:
    params = PROFILES[profile]
    print(f"[*] env: {env_banner()}")
    print(f"[*] starting isolated loopback server (profile={profile}, extra_env={server_env or '{}'})")
    srv = ph.ManagedServer(pow_difficulty_bits="0", max_registered_users="0",
                           extra_env=server_env)
    srv.start()
    print(f"[*] server up: {srv.url} (pid={srv.pid})")
    print(f"[*] db: {srv.db_path}")

    results: list[BenchResult] = []
    try:
        for name, fn in SCENARIOS.items():
            if only and name != only:
                continue
            kwargs = dict(params[name])
            kwargs.update({k: v for k, v in overrides.items() if k in kwargs})
            stop_sampler = asyncio.Event()
            sampler = ph.ResourceSampler(srv.pid, interval=0.25)
            sampler_task = asyncio.create_task(sampler.run(stop_sampler))
            print(f"\n[*] running {name} {kwargs} ...")
            try:
                res = await fn(srv.url, **kwargs)
            except Exception as e:
                res = BenchResult(name=name)
                res.errors += 1
                res.notes.append(f"scenario-level exception: {e!r}")
            stop_sampler.set()
            await sampler_task
            s = sampler.summary()
            res.peak_rss_mb = s.get("peak_rss_mb")
            res.peak_cpu_pct = s.get("peak_cpu_pct")
            if not srv.is_alive():
                res.notes.append("SERVER PROCESS DIED during this scenario")
            res.print()
            results.append(res)
            if not srv.is_alive():
                break
    finally:
        tail = srv.stdout_tail(30)
        srv.stop()

    print("\n" + "=" * 70)
    print("SUMMARY (ops/sec, higher is better; latency ms, lower is better)")
    print("=" * 70)
    for res in results:
        s = res.summary()
        lm = s["latency_ms"] or {}
        print(f"  {res.name[:52]:<52} {s['ops_per_sec']:>9} op/s  "
              f"p50={lm.get('p50', '-')} p99={lm.get('p99', '-')}")

    if json_out:
        payload = {
            "env": env_banner(),
            "profile": profile,
            "server_env": server_env,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "results": [r.summary() for r in results],
        }
        Path(json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n[*] wrote {json_out}")

    if any("SERVER PROCESS DIED" in n for r in results for n in r.notes):
        print("\n[!] server died mid-run. Tail of its output:")
        print(tail)
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=list(PROFILES), default="quick")
    ap.add_argument("--scenario", choices=list(SCENARIOS), default=None)
    ap.add_argument("--clients", type=int, default=None)
    ap.add_argument("--msgs-per-client", type=int, default=None)
    ap.add_argument("--json", dest="json_out", default=None,
                    help="Write machine-readable results here (for before/after diffing).")
    ap.add_argument("--server-env", action="append", default=[], metavar="K=V",
                    help="Extra env var for the server subprocess (repeatable).")
    args = ap.parse_args()

    overrides = {}
    if args.clients is not None:
        overrides["clients"] = args.clients
        overrides["pairs"] = args.clients
    if args.msgs_per_client is not None:
        overrides["msgs_per_client"] = args.msgs_per_client
        overrides["msgs_per_pair"] = args.msgs_per_client

    server_env = {}
    for kv in args.server_env:
        if "=" not in kv:
            ap.error(f"--server-env expects K=V, got {kv!r}")
        k, v = kv.split("=", 1)
        server_env[k] = v

    sys.exit(asyncio.run(run(args.profile, args.scenario, overrides,
                              args.json_out, server_env)))


if __name__ == "__main__":
    main()
