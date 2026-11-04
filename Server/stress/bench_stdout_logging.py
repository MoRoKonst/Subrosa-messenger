#!/usr/bin/env python3
"""
Isolated microbenchmark of the stdout configuration server.py uses for all
of its logging -- `line_buffering=True` (server.py:36-39) with 303 bare
`print()` calls, 125 of them inside handle_client, and no `logging` module
anywhere in the file.

What this measures and why it matters: with line buffering, every print()
is one write() syscall on the calling thread. In server.py that thread is
the asyncio event-loop thread, and under systemd stdout is a pipe to
journald. A pipe write blocks once the reader falls behind, which stalls
EVERY connection in the process, not just the one that logged. So the cost
of a log line is not "some CPU" -- it is a potential event-loop stall whose
duration is set by how fast the log consumer drains.

This runs as a parent that spawns itself as a child, so the child's stdout
is a real OS pipe -- the same shape as running under systemd/journald or
`python server.py | tee`. Measuring against a tty or a redirected file
would understate the problem, since those do not backpressure the same way.

Four configurations, each writing the same number of identical lines:

  line_buffered_pipe     -- what server.py does today
  block_buffered_pipe    -- same prints, 8 KiB buffering (one-line change)
  line_buffered_devnull  -- isolates syscall cost from pipe backpressure
  logging_block_pipe     -- stdlib logging at INFO over a block-buffered
                            stream, i.e. roughly the shape step 2 of
                            _scratch/REWRITE_FEASIBILITY.md proposes

Writes nothing to disk and touches no project file.

Usage:
    python bench_stdout_logging.py
    python bench_stdout_logging.py --lines 200000
"""
from __future__ import annotations

import argparse
import io
import logging
import os
import subprocess
import sys
import time

LINE = "[RATE_LIMIT] A1B2C3D4 превысил лимит anon_message"


def _run_child(mode: str, lines: int):
    """Executes inside the child process; its stdout is already a pipe (or
    devnull) set up by the parent."""
    if mode == "line_buffered_pipe" or mode == "line_buffered_devnull":
        stream = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace", line_buffering=True)
        t0 = time.perf_counter()
        for _ in range(lines):
            print(LINE, file=stream)
        stream.flush()
        elapsed = time.perf_counter() - t0

    elif mode == "block_buffered_pipe":
        stream = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace", line_buffering=False,
                                  write_through=False)
        t0 = time.perf_counter()
        for _ in range(lines):
            print(LINE, file=stream)
        stream.flush()
        elapsed = time.perf_counter() - t0

    elif mode == "logging_block_pipe":
        stream = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace", line_buffering=False)
        logger = logging.getLogger("bench")
        logger.setLevel(logging.INFO)
        h = logging.StreamHandler(stream)
        h.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(h)
        t0 = time.perf_counter()
        for _ in range(lines):
            logger.info(LINE)
        stream.flush()
        elapsed = time.perf_counter() - t0

    else:
        raise SystemExit(f"unknown mode {mode!r}")

    # Report on stderr so it cannot be confused with the measured stdout
    # traffic (and so the parent can read it without draining the pipe).
    print(f"__ELAPSED__ {elapsed:.6f}", file=sys.stderr, flush=True)


def _bench(mode: str, lines: int, reader_delay: float) -> float:
    """Spawns the child and returns its self-measured elapsed seconds.

    `reader_delay` models how fast the log consumer is:

      0.0  -- drain immediately and continuously: a healthy journald.
      > 0  -- sleep that long before draining at all, then drain normally.
              The 64 KiB pipe buffer fills in the meantime and the child
              BLOCKS in write(), which is exactly what a slow or stalled
              log consumer does to server.py's event-loop thread. The
              child's self-measured elapsed therefore includes the stall.

    Note: never "don't drain at all". The first version of this file did
    exactly that and deadlocked on the spot -- the child blocked forever at
    ~64 KiB of output while the parent blocked forever on the child's
    stderr, which the child only writes AFTER finishing. A slow reader
    reproduces the real backpressure; an absent reader just hangs.
    """
    import threading

    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    stdout_target = subprocess.DEVNULL if mode.endswith("devnull") else subprocess.PIPE
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--child", mode, "--lines", str(lines)],
        stdout=stdout_target, stderr=subprocess.PIPE, env=env,
    )

    drain_thread = None
    if stdout_target is subprocess.PIPE:
        def _drain(f, delay):
            if delay:
                time.sleep(delay)
            try:
                for _ in iter(lambda: f.read(65536), b""):
                    pass
            except Exception:
                pass

        drain_thread = threading.Thread(target=_drain, args=(proc.stdout, reader_delay),
                                        daemon=True)
        drain_thread.start()

    err = proc.stderr.read()
    proc.wait()
    if drain_thread is not None:
        drain_thread.join(timeout=10)

    for line in err.decode("utf-8", "replace").splitlines():
        if line.startswith("__ELAPSED__"):
            return float(line.split()[1])
    raise RuntimeError(f"child for mode={mode} did not report timing; stderr:\n{err!r}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--child", metavar="MODE", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--lines", type=int, default=100_000)
    args = ap.parse_args()

    if args.child:
        _run_child(args.child, args.lines)
        return

    n = args.lines
    print(f"python {sys.version.split()[0]}  lines per configuration: {n}")
    print("Child process writes to a real OS pipe (systemd/journald shape), "
          "except the devnull row.\n")

    cases = [
        ("line_buffered_pipe     (server.py today, fast reader)", "line_buffered_pipe", 0.0),
        ("line_buffered_pipe     (server.py today, reader stalls 2s)", "line_buffered_pipe", 2.0),
        ("block_buffered_pipe    (one-line change, fast reader)", "block_buffered_pipe", 0.0),
        ("block_buffered_pipe    (one-line change, reader stalls 2s)", "block_buffered_pipe", 2.0),
        ("line_buffered_devnull  (syscall cost only, no backpressure)", "line_buffered_devnull", 0.0),
        ("logging_block_pipe     (stdlib logging, fast reader)", "logging_block_pipe", 0.0),
    ]

    hdr = f"{'configuration':<62} {'sec':>8} {'lines/s':>12} {'us/line':>9}"
    print(hdr)
    print("-" * len(hdr))
    for label, mode, delay in cases:
        elapsed = _bench(mode, n, delay)
        rate = n / elapsed
        print(f"{label:<62} {elapsed:>8.3f} {rate:>12.0f} {elapsed / n * 1e6:>9.2f}")

    print()
    print("Interpretation: us/line is how long the EVENT-LOOP THREAD is blocked")
    print("per log line in server.py's current design. Multiply by the number of")
    print("print() calls on a hot path to get the per-message logging tax, and")
    print("compare each 'reader stalls 2s' row against its 'fast reader'")
    print("counterpart to see what a slow log consumer does to that tax.")
    print()
    print("The 2s stall rows include that 2s of blocked writes by construction,")
    print("so read them as 'the stall is paid by the writer', not as a rate.")


if __name__ == "__main__":
    main()
