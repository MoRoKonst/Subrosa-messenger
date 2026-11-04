#!/usr/bin/env python3
"""
Isolates WHY `subscribe_tokens` has the worst tail latency of anything
measured (p50 1.44 ms but p95 205 ms, p99 990 ms, max 1 208 ms at 20
clients x 10 batches -- see _scratch/PERF_FINDINGS_2026-11-02.md).

It replicates `_db_claim_anon_tokens_sync()`'s exact transaction shape
(server.py:5429) against a throwaway temp database -- no server, no
asyncio, no network -- so each suspected cause can be turned on and off
independently:

  A. BEGIN IMMEDIATE serialization. Every claim takes a DATABASE-WIDE
     write lock, including a batch where every token is already known and
     the transaction performs only SELECTs. Concurrent callers therefore
     queue behind each other even when none of them writes anything.

  B. `SELECT COUNT(*) FROM anon_token_state` (server.py:5504). An
     unfiltered count, inside the write transaction, on every batch
     containing at least one new token. ANON_TOKEN_STATE_MAX_TOTAL_ROWS
     defaults to 2 000 000, so this is O(table size) per batch.

  C. The per-token SELECT loop (server.py:5473-5478). One round trip per
     token rather than one query per batch.

Each is measured at several table sizes and concurrency levels, because
the point is specifically to find which one explains a TAIL rather than a
mean. Writes only to a tempfile; reads nothing from the repo.

Usage:
    python bench_token_claim.py
    python bench_token_claim.py --rows 200000 --threads 20
"""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

BATCH = 20                      # tokens per subscribe_tokens batch (bench default)
MAX_ACTIVE_PER_ACCOUNT = 5000   # server.py:1092
NEW_CLAIM_MAX_PER_WINDOW = 300  # server.py:1108
MAX_TOTAL_ROWS = 2_000_000      # server.py:1164
NEW_CLAIM_WINDOW_SEC = 3600


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS anon_token_state (
    token_hash  BLOB PRIMARY KEY,
    owner       TEXT NOT NULL,
    state       TEXT NOT NULL CHECK(state IN ('ACTIVE','IN_FLIGHT','SPENT','REVOKED')),
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_anon_token_owner_state ON anon_token_state(owner, state);
CREATE TABLE IF NOT EXISTS anon_token_claim_guard (
    username      TEXT PRIMARY KEY,
    window_started REAL NOT NULL,
    new_claims    INTEGER NOT NULL
);
"""

PRAGMAS = ("journal_mode=WAL", "synchronous=FULL", "busy_timeout=5000")


def _connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db, timeout=30)
    for p in PRAGMAS:
        conn.execute(f"PRAGMA {p}")
    return conn


def _seed(db: Path, rows: int, owners: int = 50):
    conn = _connect(db)
    conn.executescript(SCHEMA)
    conn.commit()
    existing = conn.execute("SELECT COUNT(*) FROM anon_token_state").fetchone()[0]
    todo = rows - existing
    if todo > 0:
        now = time.time()
        conn.execute("BEGIN IMMEDIATE")
        conn.executemany(
            "INSERT OR IGNORE INTO anon_token_state (token_hash, owner, state, created_at, updated_at) "
            "VALUES (?,?,'ACTIVE',?,?)",
            [(_hash(f"seed{i}"), f"OWNER{i % owners:04X}", now, now) for i in range(todo)],
        )
        conn.commit()
    conn.close()


# ─── The transaction under test, in four variants ──────────────────────────

def claim_current(conn, tokens, username, skip_total_count=False, batched_select=False):
    """Faithful replica of _db_claim_anon_tokens_sync()'s transaction.

    `skip_total_count` models fix B (replace the unfiltered COUNT(*) with a
    maintained counter). `batched_select` models fix C (one IN-query instead
    of a per-token loop).
    """
    result = {}
    now = time.time()
    conn.execute("BEGIN IMMEDIATE")
    try:
        new_tokens = []
        if batched_select:
            hashes = {t: _hash(t) for t in tokens}
            placeholders = ",".join("?" * len(tokens))
            found = {
                row[0]: (row[1], row[2])
                for row in conn.execute(
                    f"SELECT token_hash, owner, state FROM anon_token_state "
                    f"WHERE token_hash IN ({placeholders})",
                    list(hashes.values()),
                ).fetchall()
            }
            for t, h in hashes.items():
                if h in found:
                    result[t] = found[h]
                else:
                    new_tokens.append(t)
        else:
            for token in tokens:
                row = conn.execute(
                    "SELECT owner, state FROM anon_token_state WHERE token_hash = ?",
                    (_hash(token),),
                ).fetchone()
                if row is None:
                    new_tokens.append(token)
                else:
                    result[token] = (row[0], row[1])

        if not new_tokens:
            conn.commit()
            return result

        active_count = conn.execute(
            "SELECT COUNT(*) FROM anon_token_state WHERE owner = ? AND state IN ('ACTIVE','IN_FLIGHT')",
            (username,),
        ).fetchone()[0]
        active_room = max(0, MAX_ACTIVE_PER_ACCOUNT - active_count)

        guard_row = conn.execute(
            "SELECT window_started, new_claims FROM anon_token_claim_guard WHERE username = ?",
            (username,),
        ).fetchone()
        if guard_row is None or now - guard_row[0] >= NEW_CLAIM_WINDOW_SEC:
            window_started, claims_so_far = now, 0
        else:
            window_started, claims_so_far = guard_row
        quota_room = max(0, NEW_CLAIM_MAX_PER_WINDOW - claims_so_far)

        if skip_total_count:
            total_room = MAX_TOTAL_ROWS  # a maintained counter would be O(1)
        else:
            total_rows = conn.execute("SELECT COUNT(*) FROM anon_token_state").fetchone()[0]
            total_room = max(0, MAX_TOTAL_ROWS - total_rows)

        admit_count = min(len(new_tokens), active_room, quota_room, total_room)
        admitted, refused = new_tokens[:admit_count], new_tokens[admit_count:]

        for token in admitted:
            conn.execute(
                "INSERT INTO anon_token_state (token_hash, owner, state, created_at, updated_at) "
                "VALUES (?,?,'ACTIVE',?,?)",
                (_hash(token), username, now, now),
            )
            result[token] = (username, "ACTIVE")
        for token in refused:
            result[token] = (None, "NEW_CLAIM_LIMIT")

        if admitted:
            conn.execute(
                "INSERT OR REPLACE INTO anon_token_claim_guard (username, window_started, new_claims) "
                "VALUES (?,?,?)",
                (username, window_started, claims_so_far + len(admitted)),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return result


# ─── Drivers ───────────────────────────────────────────────────────────────

def pct(values, p):
    s = sorted(values)
    i = min(len(s) - 1, max(0, int(round(p / 100 * (len(s) - 1)))))
    return s[i] * 1000.0


def run_concurrent(db: Path, threads: int, batches: int, *, all_known: bool,
                   skip_total_count=False, batched_select=False,
                   app_lock: threading.Lock | None = None):
    """Each thread runs `batches` claim transactions on its own connection,
    mirroring the executor-thread-per-call shape the server has.

    `app_lock` models fix D: serialize claim transactions in the
    APPLICATION so that SQLite's own busy handler never engages. SQLite's
    default busy handler does not queue fairly -- it sleeps the loser on a
    fixed escalating schedule (1, 2, 5, 10, 15, 20, 25, 25, 25, 50, 50,
    100 ms, ...) and retries, so under N-way contention a thread can
    accumulate hundreds of milliseconds of SLEEP even when every
    transaction itself takes microseconds. A Python lock queues FIFO with
    no backoff, which is why this variant separates "lock contention" from
    "busy-handler backoff" -- two very different diagnoses with two very
    different fixes.
    """
    lats: list[float] = []
    lock = threading.Lock()
    errors = [0]

    known_tokens = [f"seed{i}" for i in range(BATCH)] if all_known else None

    def worker(tid: int):
        conn = _connect(db)
        local = []
        try:
            for b in range(batches):
                if all_known:
                    tokens = known_tokens
                else:
                    tokens = [secrets.token_hex(16) for _ in range(BATCH)]
                t0 = time.perf_counter()
                try:
                    if app_lock is not None:
                        with app_lock:
                            claim_current(conn, tokens, f"BENCH{tid:04X}",
                                          skip_total_count=skip_total_count,
                                          batched_select=batched_select)
                    else:
                        claim_current(conn, tokens, f"BENCH{tid:04X}",
                                      skip_total_count=skip_total_count,
                                      batched_select=batched_select)
                    local.append(time.perf_counter() - t0)
                except Exception:
                    with lock:
                        errors[0] += 1
        finally:
            conn.close()
        with lock:
            lats.extend(local)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    t_start = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    wall = time.perf_counter() - t_start
    return lats, wall, errors[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--threads", type=int, default=20, help="concurrent claimers")
    ap.add_argument("--batches", type=int, default=10, help="claim transactions per thread")
    ap.add_argument("--rows", type=int, nargs="*", default=[1000, 50_000, 200_000],
                    help="pre-existing anon_token_state row counts to test at")
    args = ap.parse_args()

    print(f"python {sys.version.split()[0]}  sqlite {sqlite3.sqlite_version}")
    print(f"threads={args.threads} batches/thread={args.batches} tokens/batch={BATCH}  "
          f"(= {args.threads * args.batches} write transactions per cell)")
    print("PRAGMAs: " + ", ".join(PRAGMAS) + "   (post-PERF-01 configuration)\n")

    hdr = (f"{'rows':>8} {'variant':<42} {'tx/s':>8} {'p50':>8} {'p95':>9} "
           f"{'p99':>9} {'max':>9} {'err':>4}")
    print(hdr)
    print("-" * len(hdr))

    for rows in args.rows:
        with tempfile.TemporaryDirectory(prefix="subrosa_claimbench_") as td:
            db = Path(td) / "claim.db"
            _seed(db, rows)

            variants = [
                ("current: all-new tokens", dict(all_known=False)),
                ("current: all-KNOWN tokens (pure-read tx)", dict(all_known=True)),
                ("fix B: no unfiltered COUNT(*)", dict(all_known=False, skip_total_count=True)),
                ("fix C: batched IN-select", dict(all_known=False, batched_select=True)),
                ("fix B+C together", dict(all_known=False, skip_total_count=True,
                                          batched_select=True)),
                ("fix D: app-level lock (no SQLite busy wait)",
                 dict(all_known=False, app_lock=threading.Lock())),
                ("fix B+D (no C) -- is C actually pulling weight?",
                 dict(all_known=False, skip_total_count=True,
                      app_lock=threading.Lock())),
                ("fix B+C+D together", dict(all_known=False, skip_total_count=True,
                                            batched_select=True,
                                            app_lock=threading.Lock())),
            ]
            for label, kw in variants:
                lats, wall, errs = run_concurrent(db, args.threads, args.batches, **kw)
                if not lats:
                    print(f"{rows:>8} {label:<42} {'-':>8} {'all failed':>8}")
                    continue
                print(f"{rows:>8} {label:<42} {len(lats) / wall:>8.0f} "
                      f"{pct(lats, 50):>8.2f} {pct(lats, 95):>9.2f} "
                      f"{pct(lats, 99):>9.2f} {pct(lats, 100):>9.2f} {errs:>4}")
        print()

    print("Reading this table:")
    print("  * 'all-KNOWN' vs 'all-new' isolates cause A. A pure-read transaction that")
    print("    is still slow under concurrency means BEGIN IMMEDIATE's database-wide")
    print("    write lock is the serializer, not the writing itself.")
    print("  * Watch how 'current: all-new' degrades as `rows` grows while 'fix B'")
    print("    stays flat -- that difference IS the unfiltered COUNT(*).")
    print("  * Compare p99/max, not just p50. The reported problem is a tail.")


if __name__ == "__main__":
    main()
