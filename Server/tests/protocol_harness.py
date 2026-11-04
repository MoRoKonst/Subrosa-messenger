"""
Shared infrastructure for the adversarial fuzz/stress/state-machine test
suite (test_protocol_negative.py, test_protocol_stateful.py,
test_protocol_concurrency.py, and Server/stress/*).

This is a THIRD system, distinct from:
  - pentest_local_server.py  (human-readable manual attack demo against a
    server the operator starts themselves)
  - subrosa_doctor.py        (read-only deployment/config validation)
See Server/stress/README.md for the full three-way split.

Everything here is either:
  1. Safety machinery for starting/stopping a real `server.py` subprocess
     against an isolated loopback port + temp DB, with hard aborts if the
     target ever looks like it could be non-loopback or a real DB, or
  2. Protocol helpers (crypto, handshake, register, drain) intentionally
     kept in lock-step with the equivalent helpers in
     tests/test_security_invariants.py and pentest_local_server.py — small
     enough that a fourth near-duplicate copy is cheaper than a shared
     import across three independently-runnable entry points.

No test assertions live in this file — only setup/teardown/helpers.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SERVER_DIR = Path(__file__).resolve().parent.parent
SERVER_PY = SERVER_DIR / "server.py"

TOKEN_LEN = 32  # server.MAX_TOKEN_LEN — duplicated to avoid importing server.py into every caller


class SafetyViolation(RuntimeError):
    """Raised instead of ever starting/running adversarial traffic against
    something that isn't a throwaway local target. Fail closed, never warn
    and continue."""


# ─── Safety guards ─────────────────────────────────────────────────────────

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def assert_loopback_host(host: str) -> None:
    if host not in _ALLOWED_HOSTS:
        raise SafetyViolation(
            f"Refusing to target host={host!r} — adversarial/stress traffic "
            f"may only run against loopback ({sorted(_ALLOWED_HOSTS)})."
        )


def assert_temp_db_path(db_path: os.PathLike | str) -> None:
    """The DB path must resolve to somewhere under the OS temp root. This
    is the one mechanical check standing between "isolated throwaway db"
    and "oops, wrote destructive test data into messages.db" — deliberately
    strict (no allow-list override) rather than trusting a caller-supplied
    flag."""
    resolved = Path(db_path).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    try:
        resolved.relative_to(temp_root)
    except ValueError:
        raise SafetyViolation(
            f"Refusing to use DB path {resolved} — it is not under the OS "
            f"temp root ({temp_root}). Only ever point adversarial tests at "
            f"a tempfile-generated path."
        )
    name = resolved.name.lower()
    if name in ("messages.db", "beacon.db", "subrosa.db"):
        raise SafetyViolation(
            f"Refusing to use DB path {resolved} — filename matches a known "
            f"production default even though it's under temp; use an "
            f"unambiguous generated name instead."
        )


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


# ─── Managed server subprocess ─────────────────────────────────────────────

@dataclass
class ManagedServer:
    """Starts server.py --dev as a real subprocess bound to an isolated
    loopback port with a throwaway temp DB, and tears it down cleanly.

    Every destructive/adversarial test in this suite must go through this
    (or the `managed_server` pytest fixture in conftest.py) rather than
    hand-rolling subprocess.Popen — that's what keeps the loopback+temp-DB
    assertions from being something a future test can accidentally skip.
    """

    pow_difficulty_bits: str = "0"
    max_registered_users: str = "0"
    # Server-wide aggregate budgets, raised by default so a load profile is
    # not silently throttled into doing no work at all — see the long comment
    # at their use site in start(). Override via extra_env (or these fields)
    # in a test that is specifically exercising a budget.
    new_account_global_limit: str = "100000"
    anon_token_global_claim_limit: str = "100000"
    extra_env: dict = field(default_factory=dict)
    ready_timeout: float = 15.0
    host: str = "127.0.0.1"

    def __post_init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._tmpdir: Optional[tempfile.TemporaryDirectory] = None
        self._db_path: Optional[Path] = None
        self._port: Optional[int] = None
        self._stdout_lines: list[str] = []

    # -- lifecycle -----------------------------------------------------

    def start(self) -> "ManagedServer":
        assert_loopback_host(self.host)

        self._tmpdir = tempfile.TemporaryDirectory(prefix="subrosa_stress_")
        self._db_path = Path(self._tmpdir.name) / f"stress_{uuid.uuid4().hex}.db"
        assert_temp_db_path(self._db_path)

        self._port = _free_loopback_port()

        # Deliberately NOT os.environ.copy() — start from a minimal
        # allow-list so no production secret (FEDERATION_SECRET,
        # DB_ENCRYPTION_KEY_HEX, TOTP_SECRET_ENCRYPTION_KEY, Firebase
        # credentials, ...) that happens to be set in the parent shell can
        # ever leak into an adversarial-test child process, even by
        # accident. Only what's needed for Python + Windows subprocess
        # plumbing to work is carried over.
        env = {}
        for key in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "PATHEXT", "COMSPEC"):
            if key in os.environ:
                env[key] = os.environ[key]
        env.update({
            "DB_PATH": str(self._db_path),
            "SUBROSA_BIND_HOST": self.host,
            "SUBROSA_BIND_PORT": str(self._port),
            "POW_DIFFICULTY_BITS": self.pow_difficulty_bits,
            "MAX_REGISTERED_USERS": self.max_registered_users,
            "MSG_TTL_DAYS": "30",
            # ─── Aggregate budgets neutralised for stress/load runs ───────
            # Found 2026-11-03: `stress_server.py --profile deep` could not
            # run at all, and the two scenarios that silently did ZERO work
            # still let the suite print "RESULT: PASS (3/3)".
            #
            # Two separate server-wide budgets caused it, both deliberately
            # small in production and both far below what a load profile
            # legitimately needs:
            #
            #   NEW_ACCOUNT_GLOBAL_LIMIT     60 per 60s  (server.py)
            #     `deep` needs ~217 registrations in about two minutes (150
            #     churn + 40 anon + 25 malicious + 2 canary). Past the 60th
            #     the server replies `registration_full` and never sends
            #     `register_ok`, so every helper waiting on it times out
            #     after 5s. Churn failures began at attempt #122 — churn only
            #     registers on 2 of its 4 patterns, so ~61 registrations had
            #     happened by then, matching the limit exactly.
            #
            #   ANON_TOKEN_GLOBAL_CLAIM_LIMIT  300 per 60s  (server.py)
            #     `anon_token_stress` at `deep` asks for 40 clients x 25
            #     tokens = 1000 new-token claims and got exactly 300 through,
            #     then one timeout per client as the rest came back
            #     NEW_CLAIM_LIMIT. That looked like a latency bug and was
            #     mis-diagnosed as one before being traced here.
            #
            # These are raised rather than inherited from the parent shell on
            # purpose: this dict stays an explicit allow-list (see the comment
            # below on why `os.environ.copy()` is NOT used), so a test's
            # resource budget is visible here instead of depending on whoever
            # launched pytest. A test that specifically wants to exercise a
            # budget overrides it back via `extra_env`.
            "NEW_ACCOUNT_GLOBAL_LIMIT": self.new_account_global_limit,
            "ANON_TOKEN_GLOBAL_CLAIM_LIMIT": self.anon_token_global_claim_limit,
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
        })
        env.update(self.extra_env)

        # No FEDERATION_SECRET, no GOOGLE_APPLICATION_CREDENTIALS, no
        # DB_ENCRYPTION_KEY_HEX, no SERVER_ACCESS_PROTECTED unless a caller
        # explicitly opts in via extra_env — every one of those is simply
        # absent from `env` above, which is the safe default for all of
        # them (disabled/off).

        self._proc = subprocess.Popen(
            [sys.executable, str(SERVER_PY), "--dev"],
            cwd=str(SERVER_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        self._start_log_pump()

        if not _wait_for_port(self.host, self._port, self.ready_timeout):
            output = self.stdout_tail()
            self.stop()
            raise RuntimeError(
                f"server.py did not open {self.host}:{self._port} within "
                f"{self.ready_timeout}s. Captured output:\n{output}"
            )
        # Port accepting TCP doesn't guarantee handle_client's first
        # `await websocket.send(challenge)` path is warm yet on a cold
        # interpreter — give it one more short grace beat rather than
        # racing the very first real test connection against it.
        time.sleep(0.2)
        if self._proc.poll() is not None:
            raise RuntimeError(
                f"server.py exited immediately (code {self._proc.returncode}). "
                f"Captured output:\n{self.stdout_tail()}"
            )
        return self

    def _start_log_pump(self):
        import threading

        def pump():
            assert self._proc is not None and self._proc.stdout is not None
            for line in self._proc.stdout:
                self._stdout_lines.append(line)
                if len(self._stdout_lines) > 5000:
                    del self._stdout_lines[:1000]

        t = threading.Thread(target=pump, daemon=True)
        t.start()

    def stdout_tail(self, n: int = 80) -> str:
        return "".join(self._stdout_lines[-n:])

    def stop(self, timeout: float = 5.0) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=timeout)
        if self._tmpdir is not None:
            try:
                self._tmpdir.cleanup()
            except OSError:
                pass  # sqlite -wal/-shm files sometimes linger briefly on Windows

    def __enter__(self) -> "ManagedServer":
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # -- accessors -------------------------------------------------------

    @property
    def url(self) -> str:
        assert self._port is not None
        return f"ws://{self.host}:{self._port}"

    @property
    def port(self) -> int:
        assert self._port is not None
        return self._port

    @property
    def db_path(self) -> Path:
        assert self._db_path is not None
        return self._db_path

    @property
    def pid(self) -> int:
        assert self._proc is not None
        return self._proc.pid

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def psutil_process(self):
        import psutil
        return psutil.Process(self.pid)


# ─── Protocol helpers (kept in lock-step with test_security_invariants.py) ─

def rand_token() -> str:
    return secrets.token_hex(TOKEN_LEN // 2)


def gen_keypair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_der


def fingerprint_of(pub_der: bytes) -> str:
    return hashlib.sha256(pub_der).digest()[:8].hex().upper()


_DEVICE_ID_NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")


def canonical_device_id(label: str) -> str:
    import re
    if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", label):
        return label
    return str(uuid.uuid5(_DEVICE_ID_NAMESPACE, label))


def sign_device_challenge(device_priv, challenge: bytes, username: str, device_id: str) -> bytes:
    signed_data = b"SUBROSA_DEVICE_V1" + challenge + username.encode("utf-8") + device_id.encode("utf-8")
    return device_priv.sign(signed_data, ec.ECDSA(hashes.SHA256()))


async def handshake(ws, priv, pub_der) -> bytes:
    challenge_msg = json.loads(await ws.recv())
    assert challenge_msg["type"] == "challenge", challenge_msg
    challenge = base64.b64decode(challenge_msg["data"])
    signature = priv.sign(challenge, ec.ECDSA(hashes.SHA256()))
    await ws.send(json.dumps({
        "type": "challenge_response",
        "public_key": base64.b64encode(pub_der).decode(),
        "signature": base64.b64encode(signature).decode(),
    }))
    ok_msg = json.loads(await ws.recv())
    assert ok_msg["type"] == "handshake_ok", ok_msg
    return challenge


async def anon_channel_handshake(ws) -> None:
    challenge_msg = json.loads(await ws.recv())
    assert challenge_msg["type"] == "challenge", challenge_msg
    await ws.send(json.dumps({"type": "anon_channel"}))
    ok_msg = json.loads(await ws.recv())
    assert ok_msg["type"] == "anon_channel_ok", ok_msg


async def register(ws, pub_der, device_id, name="t", extra=None):
    device_id = canonical_device_id(device_id)
    msg = {
        "type": "register",
        "name": name,
        "public_key": base64.b64encode(pub_der).decode(),
        "device_id": device_id,
    }
    if extra:
        msg.update(extra)
    await ws.send(json.dumps(msg))
    return device_id


# websockets.connect()'s own default max_size (1 MiB) is well under
# server.py's actual MAX_PACKET_SIZE_BYTES (6 MiB) and several
# individually-large-but-in-spec fields (voice_data up to 4 MiB) -- a
# boundary/encoding test that legitimately sends a payload near the
# server's own documented ceiling would otherwise get its own TEST CLIENT
# killing the connection with a local "message too big" error before the
# server ever gets a chance to accept or reject it (found empirically
# while building the boundary-mutation suite, 2026-09-25: the very first
# run hit exactly this on voice_data's at-max-length case). Every
# websockets.connect() in this suite should use this, not the library
# default, to test what the SERVER's limits actually are.
CLIENT_MAX_SIZE = 8 * 1024 * 1024  # headroom above server.py's 6 MiB MAX_PACKET_SIZE_BYTES


async def connect_and_register(url, device_id="dev1", name="t", extra=None):
    import websockets
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(url, max_size=CLIENT_MAX_SIZE)
    await handshake(ws, priv, pub_der)
    await register(ws, pub_der, device_id, name, extra)
    await drain_until(ws, "register_ok")
    return ws, fingerprint_of(pub_der), priv, pub_der


async def drain_until(ws, msg_type, timeout=5.0):
    import asyncio
    async with asyncio.timeout(timeout):
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("type") == msg_type:
                return msg


async def drain_all(ws, quiet_for=0.3, max_total=5.0):
    """Collect every message currently in flight; stops once nothing new
    arrives for `quiet_for` seconds or `max_total` elapses. Useful for
    fuzz/state tests that just need to prove the connection is still alive
    and responsive rather than waiting for one specific type."""
    import asyncio
    out = []
    deadline = time.monotonic() + max_total
    while time.monotonic() < deadline:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=quiet_for)
        except asyncio.TimeoutError:
            break
        try:
            out.append(json.loads(raw))
        except Exception:
            out.append({"_raw": raw})
    return out


# ─── Metrics ────────────────────────────────────────────────────────────

class ResourceSampler:
    """Periodic RSS/CPU sampling of a server subprocess via psutil. Pure OS
    process metrics — no telemetry hooks added to server.py itself (see
    Server/stress/README.md's "why not instrument the server" note)."""

    def __init__(self, pid: int, interval: float = 0.5):
        import psutil
        self._proc = psutil.Process(pid)
        self.interval = interval
        self.samples: list[tuple[float, int, float]] = []  # (t, rss_bytes, cpu_pct)
        self._task = None

    async def run(self, stop_event):
        import asyncio
        self._proc.cpu_percent(None)  # prime the non-blocking counter
        while not stop_event.is_set():
            try:
                rss = self._proc.memory_info().rss
                cpu = self._proc.cpu_percent(None)
                self.samples.append((time.monotonic(), rss, cpu))
            except Exception:
                break
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass

    def summary(self) -> dict:
        if not self.samples:
            return {"peak_rss_mb": None, "peak_cpu_pct": None, "samples": 0}
        peak_rss = max(s[1] for s in self.samples)
        peak_cpu = max(s[2] for s in self.samples)
        return {
            "peak_rss_mb": round(peak_rss / (1024 * 1024), 1),
            "final_rss_mb": round(self.samples[-1][1] / (1024 * 1024), 1),
            "peak_cpu_pct": round(peak_cpu, 1),
            "samples": len(self.samples),
        }


def percentiles(values: list[float], pcts=(50, 95, 99)) -> dict:
    if not values:
        return {f"p{p}": None for p in pcts} | {"max": None, "count": 0}
    s = sorted(values)
    n = len(s)

    def pct(p):
        idx = min(n - 1, max(0, int(round(p / 100 * (n - 1)))))
        return s[idx]

    out = {f"p{p}": round(pct(p) * 1000, 2) for p in pcts}  # ms
    out["max"] = round(s[-1] * 1000, 2)
    out["count"] = n
    return out
