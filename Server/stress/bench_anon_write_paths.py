#!/usr/bin/env python3
"""
Decides ONE design question with numbers instead of reasoning: should the
`anon_message` hot-path writes be serialised behind the same application
lock as `subscribe_tokens`' claim (PERF-02), behind their own separate
lock, or not at all?

Why this needs measuring rather than arguing. There are three writers to
`anon_token_state`:

  claim        (_db_claim_anon_tokens_sync)      -- up to 100 tokens, the
                                                    longest transaction
  mark_inflight(_db_mark_anon_token_inflight_sync) -- 1 SELECT + 1 UPDATE
  terminalize  (_db_terminalize_anon_token_sync)   -- 1 UPDATE

SQLite's write lock is database-wide, so all three contend with each other
regardless of how the application arranges its own locks. That produces
two competing intuitions:

  * ONE shared lock eliminates busy-handler backoff entirely, but puts a
    message send behind a possibly-100-token claim (head-of-line blocking
    across two very different transaction sizes).
  * TWO separate locks keep the groups independent, but then a claim and a
    send can still collide at the SQLite level, so the busy handler still
    engages -- just with 2 contenders instead of N, which may be cheap
    enough that it does not matter.

Neither intuition is obviously right, and the `anon_message` path is the
hottest in the product, so this measures the mixed-load case directly:
claimers and senders running concurrently, with sender latency reported
separately from claimer latency, under all three arrangements.

Writes only to a tempfile. No server, no asyncio, no network.

Usage:
    python bench_anon_write_paths.py
    python bench_anon_write_paths.py --senders 30 --claimers 6 --rows 200000
"""
from __future__ import annotations

import argparse
import hashlib
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

BATCH = 100                     # MAX_TOKENS_PER_SUBSCRIBE -- worst-case claim size
MAX_ACTIVE_PER_ACCOUNT = 5000
NEW_CLAIM_MAX_PER_WINDOW = 300
MAX_TOTAL_ROWS = 2_000_000
NEW_CLAIM_WINDOW_SEC = 3600
ROWS_HINT_MARGIN = 10_000       # PERF-02's margin

PRAGMAS = ("journal_mode=WAL", "synchronous=FULL", "busy_timeout=5000")

SCHEMA = """
CREATE TABLE IF NOT EXISTS anon_token_state (
    token_hash  BLOB PRIMARY KEY,
    owner       TEXT NOT NULL,
    state       TEXT NOT NULL CHECK(state IN ('ACTIVE','IN_FLIGHT','SPENT','REVOKED')),
    bootstrap_reserved     INTEGER NOT NULL DEFAULT 0,
    bootstrap_reserved_by  TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_anon_token_owner_state ON anon_token_state(owner, state);
CREATE TABLE IF NOT EXISTS anon_token_claim_guard (
    username       TEXT PRIMARY KEY,
    window_started REAL NOT NULL,
    new_claims     INTEGER NOT NULL
);
"""


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def _connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db, timeout=30)
    for p in PRAGMAS:
        conn.execute(f"PRAGMA {p}")
    return conn


def _seed(db: Path, rows: int, sender_tokens: list[str], owners: int = 50):
    """Pre-creates `rows` filler rows plus one ACTIVE row per token the
    senders will spend, so mark_inflight/terminalize always find real work."""
    conn = _connect(db)
    conn.executescript(SCHEMA)
    conn.commit()
    now = time.time()
    conn.execute("BEGIN IMMEDIATE")
    conn.executemany(
        "INSERT OR IGNORE INTO anon_token_state "
        "(token_hash, owner, state, created_at, updated_at) VALUES (?,?,'ACTIVE',?,?)",
        [(_hash(f"filler{i}"), f"OWNER{i % owners:04X}", now, now) for i in range(rows)],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO anon_token_state "
        "(token_hash, owner, state, created_at, updated_at) VALUES (?,?,'ACTIVE',?,?)",
        [(_hash(t), "SENDOWNER", now, now) for t in sender_tokens],
    )
    conn.commit()
    conn.close()


# ─── The three transactions under test, replicated faithfully ──────────────

def tx_claim(conn, tokens, username, rows_hint):
    """_db_claim_anon_tokens_sync, post-PERF-02 (with the hint guard)."""
    now = time.time()
    conn.execute("BEGIN IMMEDIATE")
    try:
        new_tokens = []
        for token in tokens:
            row = conn.execute(
                "SELECT owner, state FROM anon_token_state WHERE token_hash = ?",
                (_hash(token),),
            ).fetchone()
            if row is None:
                new_tokens.append(token)
        if not new_tokens:
            conn.commit()
            return
        conn.execute(
            "SELECT COUNT(*) FROM anon_token_state WHERE owner = ? AND state IN ('ACTIVE','IN_FLIGHT')",
            (username,),
        ).fetchone()
        conn.execute(
            "SELECT window_started, new_claims FROM anon_token_claim_guard WHERE username = ?",
            (username,),
        ).fetchone()
        if not (rows_hint + len(new_tokens) + ROWS_HINT_MARGIN < MAX_TOTAL_ROWS):
            conn.execute("SELECT COUNT(*) FROM anon_token_state").fetchone()
        for token in new_tokens:
            conn.execute(
                "INSERT INTO anon_token_state (token_hash, owner, state, created_at, updated_at) "
                "VALUES (?,?,'ACTIVE',?,?)",
                (_hash(token), username, now, now),
            )
        conn.execute(
            "INSERT OR REPLACE INTO anon_token_claim_guard (username, window_started, new_claims) "
            "VALUES (?,?,?)",
            (username, now, len(new_tokens)),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def tx_mark_inflight(conn, token):
    """_db_mark_anon_token_inflight_sync."""
    token_hash = _hash(token)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT owner, state FROM anon_token_state WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None or row[1] != "ACTIVE":
            conn.rollback()
            return None
        conn.execute(
            "UPDATE anon_token_state SET state='IN_FLIGHT', updated_at=? "
            "WHERE token_hash=? AND state='ACTIVE'",
            (time.time(), token_hash),
        )
        conn.commit()
        return row[0]
    except Exception:
        conn.rollback()
        raise


def tx_terminalize(conn, token, owner):
    """_db_terminalize_anon_token_sync."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "UPDATE anon_token_state SET state=?, bootstrap_reserved=0, "
            "bootstrap_reserved_by=NULL, updated_at=? "
            "WHERE token_hash=? AND owner=? AND state IN ('ACTIVE','IN_FLIGHT')",
            ("SPENT", time.time(), _hash(token), owner),
        )
        conn.commit()
        return cur.rowcount == 1
    except Exception:
        conn.rollback()
        raise


# ─── Driver ────────────────────────────────────────────────────────────────

def pct(values, p):
    s = sorted(values)
    i = min(len(s) - 1, max(0, int(round(p / 100 * (len(s) - 1)))))
    return s[i] * 1000.0


def run(db: Path, *, senders: int, claimers: int, sends_each: int, claims_each: int,
        rows: int, send_lock, claim_lock, sender_tokens: list[str]):
    """One arrangement. `send_lock`/`claim_lock` may be None (no app lock),
    distinct Locks (two-lock variant), or the SAME object (shared variant)."""
    send_lats: list[float] = []
    claim_lats: list[float] = []
    errors = [0]
    agg = threading.Lock()
    tokens_iter = iter(sender_tokens)
    tokens_guard = threading.Lock()

    def next_token():
        with tokens_guard:
            return next(tokens_iter, None)

    def sender():
        conn = _connect(db)
        local = []
        try:
            for _ in range(sends_each):
                tok = next_token()
                if tok is None:
                    break
                t0 = time.perf_counter()
                try:
                    if send_lock is not None:
                        with send_lock:
                            owner = tx_mark_inflight(conn, tok)
                            if owner:
                                tx_terminalize(conn, tok, owner)
                    else:
                        owner = tx_mark_inflight(conn, tok)
                        if owner:
                            tx_terminalize(conn, tok, owner)
                    local.append(time.perf_counter() - t0)
                except Exception:
                    with agg:
                        errors[0] += 1
        finally:
            conn.close()
        with agg:
            send_lats.extend(local)

    def claimer(tid: int):
        conn = _connect(db)
        local = []
        try:
            for _ in range(claims_each):
                batch = [secrets.token_hex(16) for _ in range(BATCH)]
                t0 = time.perf_counter()
                try:
                    if claim_lock is not None:
                        with claim_lock:
                            tx_claim(conn, batch, f"CLAIMER{tid:04X}", rows)
                    else:
                        tx_claim(conn, batch, f"CLAIMER{tid:04X}", rows)
                    local.append(time.perf_counter() - t0)
                except Exception:
                    with agg:
                        errors[0] += 1
        finally:
            conn.close()
        with agg:
            claim_lats.extend(local)

    ts = [threading.Thread(target=sender) for _ in range(senders)]
    ts += [threading.Thread(target=claimer, args=(i,)) for i in range(claimers)]
    t_start = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    wall = time.perf_counter() - t_start
    return send_lats, claim_lats, wall, errors[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--senders", type=int, default=20)
    ap.add_argument("--claimers", type=int, default=4)
    ap.add_argument("--sends-each", type=int, default=25)
    ap.add_argument("--claims-each", type=int, default=5)
    ap.add_argument("--rows", type=int, default=200_000)
    ap.add_argument("--repeat", type=int, default=2)
    args = ap.parse_args()

    total_sends = args.senders * args.sends_each
    print(f"python {sys.version.split()[0]}  sqlite {sqlite3.sqlite_version}")
    print(f"senders={args.senders} x {args.sends_each} sends   "
          f"claimers={args.claimers} x {args.claims_each} claims of {BATCH} tokens")
    print(f"pre-existing rows={args.rows}   PRAGMAs: {', '.join(PRAGMAS)}   repeat={args.repeat}\n")
    print("The question: does serialising the SEND pair help or hurt, and should it share")
    print("the claim lock (head-of-line blocking) or have its own (2-way SQLite contention)?\n")

    hdr = (f"{'arrangement':<34} {'send/s':>8} {'s p50':>7} {'s p95':>8} {'s p99':>9} "
           f"{'s max':>9} {'clm p99':>9} {'err':>4}")
    print(hdr)
    print("-" * len(hdr))

    arrangements = [
        ("current: no app lock", "none"),
        ("PERF-02 only (claim lock, sends free)", "claim_only"),
        ("two locks (claim | sends)", "two"),
        ("one shared lock (all writes)", "shared"),
    ]

    for label, mode in arrangements:
        best = None
        for _ in range(args.repeat):
            with tempfile.TemporaryDirectory(prefix="subrosa_anonwrite_") as td:
                db = Path(td) / "aw.db"
                sender_tokens = [f"sendtok{i}" for i in range(total_sends)]
                _seed(db, args.rows, sender_tokens)
                if mode == "none":
                    sl, cl = None, None
                elif mode == "claim_only":
                    sl, cl = None, threading.Lock()
                elif mode == "two":
                    sl, cl = threading.Lock(), threading.Lock()
                else:
                    shared = threading.Lock()
                    sl, cl = shared, shared
                s, c, wall, errs = run(
                    db, senders=args.senders, claimers=args.claimers,
                    sends_each=args.sends_each, claims_each=args.claims_each,
                    rows=args.rows, send_lock=sl, claim_lock=cl,
                    sender_tokens=sender_tokens,
                )
                if not s:
                    continue
                rate = len(s) / wall
                if best is None or rate > best[0]:
                    best = (rate, s, c, errs)
        if best is None:
            print(f"{label:<34} {'all failed':>8}")
            continue
        rate, s, c, errs = best
        cp99 = f"{pct(c, 99):.1f}" if c else "-"
        print(f"{label:<34} {rate:>8.0f} {pct(s, 50):>7.2f} {pct(s, 95):>8.2f} "
              f"{pct(s, 99):>9.2f} {pct(s, 100):>9.2f} {cp99:>9} {errs:>4}")

    print()
    print("Decide on: send p99/max (the hot path's tail -- the thing being fixed),")
    print("send/s (must not regress), and clm p99 (head-of-line cost if the lock is shared).")


if __name__ == "__main__":
    main()
