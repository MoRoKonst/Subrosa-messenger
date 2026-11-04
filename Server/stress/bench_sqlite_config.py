#!/usr/bin/env python3
"""
Isolated microbenchmark of the SQLite configuration server.py actually uses
versus the standard alternatives -- on THIS machine's disk, with no server,
no asyncio, and no network in the measurement.

Why this exists: `db_connect()` (server.py) opens a fresh connection per
operation and sets no PRAGMAs at all, so every durable write runs under
SQLite's defaults: `journal_mode=delete` (a rollback journal file created,
fsynced, and deleted per transaction) and `synchronous=FULL` (fsync on
every commit). That is a property of the *configuration*, not of Python --
so it must be measured without Python's own overhead in the frame, or the
result can be dismissed as "well, it's an interpreted language."

This benchmark answers exactly one question: how much of the server's
per-write cost is the journal/sync configuration, and how much would
survive a rewrite in another language?

Writes go to a temp file, never to any real DB. Read-only w.r.t. the repo.

Usage:
    python bench_sqlite_config.py
    python bench_sqlite_config.py --rows 500 --repeat 3
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import statistics
import sys
import tempfile
import time
from pathlib import Path

# Mirrors the real schema shape of the table on the hottest durable-write
# path (`pending_messages` offline store + `anon_token_state` claim): a
# small row, an index, one tx per logical operation.
SCHEMA = """
CREATE TABLE IF NOT EXISTS bench_rows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bench_recipient ON bench_rows(recipient);
"""

PAYLOAD = "A" * 512


# ─── Configurations under test ─────────────────────────────────────────────

CONFIGS = {
    "current (server.py: defaults, new conn per op)": {
        "pragmas": [],
        "reconnect_per_op": True,
    },
    "defaults, one persistent connection": {
        "pragmas": [],
        "reconnect_per_op": False,
    },
    "WAL + synchronous=NORMAL, new conn per op": {
        "pragmas": ["journal_mode=WAL", "synchronous=NORMAL", "busy_timeout=5000"],
        "reconnect_per_op": True,
    },
    "WAL + synchronous=NORMAL, persistent conn": {
        "pragmas": ["journal_mode=WAL", "synchronous=NORMAL", "busy_timeout=5000"],
        "reconnect_per_op": False,
    },
    "WAL + synchronous=FULL, persistent conn": {
        "pragmas": ["journal_mode=WAL", "synchronous=FULL", "busy_timeout=5000"],
        "reconnect_per_op": False,
    },
}


def _apply(conn: sqlite3.Connection, pragmas: list[str]):
    for p in pragmas:
        conn.execute(f"PRAGMA {p}")


def _bench_writes(db_path: Path, pragmas: list[str], reconnect_per_op: bool,
                  rows: int) -> tuple[float, list[float]]:
    """One durable INSERT per transaction -- the unit of work the server
    performs for each offline-stored message / claimed token batch."""
    lats: list[float] = []

    if reconnect_per_op:
        # Create schema once, then open/close around every single op, which
        # is literally what db_connect() + `with db_connect() as conn:` does
        # in server.py today.
        conn = sqlite3.connect(db_path)
        _apply(conn, pragmas)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

        t0 = time.perf_counter()
        for i in range(rows):
            t_op = time.perf_counter()
            c = sqlite3.connect(db_path)
            _apply(c, pragmas)
            c.execute("BEGIN IMMEDIATE")
            c.execute(
                "INSERT INTO bench_rows (recipient, payload, created_at) VALUES (?,?,?)",
                (f"FP{i % 64:08X}", PAYLOAD, time.time()),
            )
            c.commit()
            c.close()
            lats.append(time.perf_counter() - t_op)
        total = time.perf_counter() - t0
    else:
        conn = sqlite3.connect(db_path)
        _apply(conn, pragmas)
        conn.executescript(SCHEMA)
        conn.commit()
        t0 = time.perf_counter()
        for i in range(rows):
            t_op = time.perf_counter()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO bench_rows (recipient, payload, created_at) VALUES (?,?,?)",
                (f"FP{i % 64:08X}", PAYLOAD, time.time()),
            )
            conn.commit()
            lats.append(time.perf_counter() - t_op)
        total = time.perf_counter() - t0
        conn.close()

    return total, lats


def _bench_reads(db_path: Path, pragmas: list[str], reconnect_per_op: bool,
                 reads: int) -> tuple[float, list[float]]:
    """Indexed SELECT -- the read side (peek pending, token lookup). Shows
    the per-op connection-open cost separately from the fsync cost, since
    reads don't fsync at all."""
    lats: list[float] = []
    if reconnect_per_op:
        t0 = time.perf_counter()
        for i in range(reads):
            t_op = time.perf_counter()
            c = sqlite3.connect(db_path)
            _apply(c, pragmas)
            c.execute("SELECT id, payload FROM bench_rows WHERE recipient=? LIMIT 10",
                      (f"FP{i % 64:08X}",)).fetchall()
            c.close()
            lats.append(time.perf_counter() - t_op)
        total = time.perf_counter() - t0
    else:
        conn = sqlite3.connect(db_path)
        _apply(conn, pragmas)
        t0 = time.perf_counter()
        for i in range(reads):
            t_op = time.perf_counter()
            conn.execute("SELECT id, payload FROM bench_rows WHERE recipient=? LIMIT 10",
                         (f"FP{i % 64:08X}",)).fetchall()
            lats.append(time.perf_counter() - t_op)
        total = time.perf_counter() - t0
        conn.close()
    return total, lats


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round(p / 100 * (len(s) - 1)))))
    return s[idx] * 1000.0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rows", type=int, default=300, help="durable writes per config")
    ap.add_argument("--reads", type=int, default=2000, help="indexed reads per config")
    ap.add_argument("--repeat", type=int, default=2, help="repeat each config, keep best")
    args = ap.parse_args()

    print(f"python {sys.version.split()[0]}  sqlite {sqlite3.sqlite_version}")
    print(f"writes/config={args.rows}  reads/config={args.reads}  repeat={args.repeat}")
    print(f"temp dir: {tempfile.gettempdir()}")
    print()

    hdr = f"{'configuration':<48} {'writes/s':>9} {'w p50ms':>8} {'w p99ms':>8} {'reads/s':>9} {'r p50ms':>8}"
    print(hdr)
    print("-" * len(hdr))

    rows_out = []
    for name, cfg in CONFIGS.items():
        best_w = None
        best_r = None
        for _ in range(args.repeat):
            with tempfile.TemporaryDirectory(prefix="subrosa_sqlbench_") as td:
                db = Path(td) / "bench.db"
                w_total, w_lats = _bench_writes(db, cfg["pragmas"], cfg["reconnect_per_op"], args.rows)
                r_total, r_lats = _bench_reads(db, cfg["pragmas"], cfg["reconnect_per_op"], args.reads)
                w_rate = args.rows / w_total
                r_rate = args.reads / r_total
                if best_w is None or w_rate > best_w[0]:
                    best_w = (w_rate, w_lats)
                if best_r is None or r_rate > best_r[0]:
                    best_r = (r_rate, r_lats)
        w_rate, w_lats = best_w
        r_rate, r_lats = best_r
        print(f"{name:<48} {w_rate:>9.0f} {pct(w_lats, 50):>8.2f} {pct(w_lats, 99):>8.2f} "
              f"{r_rate:>9.0f} {pct(r_lats, 50):>8.3f}")
        rows_out.append((name, w_rate, r_rate))

    print()
    base = rows_out[0]
    print(f"Baseline = {base[0]!r}: {base[1]:.0f} writes/s, {base[2]:.0f} reads/s")
    for name, w, r in rows_out[1:]:
        print(f"  {name:<48} writes x{w / base[1]:.1f}   reads x{r / base[2]:.1f}")
    print()
    print("Read this as: any row that is faster than the baseline is a speedup")
    print("available WITHOUT changing programming language -- it is a SQLite")
    print("configuration change. Only the part of the gap that remains after")
    print("the best row here is attributable to the interpreter/runtime.")


if __name__ == "__main__":
    main()
