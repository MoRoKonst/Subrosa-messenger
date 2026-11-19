"""The registration cap is two counters, not one number doing two jobs.

Before this, `MAX_REGISTERED_USERS` and `REGISTERED_ACCOUNTS_HARD_MAX_ROWS`
were folded into a single figure by `effective_registration_cap()` and checked
against `COUNT(*) FROM registered_fingerprints`. That conflated two different
things, and the Firm tier is where it showed: an operator who revoked a
departing employee did not get the seat back, because the revoked row still
counted. "Pay for a seat you can never reuse" is the opposite of what the tier
promises.

They are now checked separately, and these tests pin both halves:

  * the hard ceiling (S6-56, table growth) counts EVERY row, revoked included;
  * the operator cap (seats) counts only identities that can still connect.

The second half is the change; the first is the part that must not regress,
since weakening it would turn a safety ceiling into something an operator's
own revocations could erode.

Each case runs in a subprocess against a throwaway database, because
`server.py` reads `DB_PATH` once at import time -- same approach as
`test_admin_users.py`.
"""
import os
import subprocess
import sys

import pytest

SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Fingerprints are opaque to the code under test; any distinct strings do.
FPS = ["AAAA%04d" % i for i in range(10)]

SCRIPT = r"""
import json, os, sqlite3, sys, time
import server

server._db_setup_sync()

registered = json.loads(sys.argv[1])
revoked    = json.loads(sys.argv[2])
max_users  = int(sys.argv[3])
hard_max   = int(sys.argv[4])
candidate  = sys.argv[5]

conn = sqlite3.connect(os.environ["DB_PATH"])
now = time.time()
for fp in registered:
    conn.execute("INSERT INTO registered_fingerprints VALUES (?,?)", (fp, now - 86400))
for fp in revoked:
    conn.execute("INSERT OR IGNORE INTO revoked_fingerprints (fingerprint, revoked_at) VALUES (?,?)",
                 (fp, now))
conn.commit()
conn.close()

result = server._db_admit_new_fingerprint_sync(candidate, max_users, "", False, hard_max)
print("RESULT=" + result)
"""


_CASE = [0]


def admit(tmp_path, registered, revoked, max_users, hard_max, candidate="NEWCOMER01"):
    """Seed a database, then try to admit one more fingerprint. Returns the
    verdict string _db_admit_new_fingerprint_sync() produced.

    A fresh database file per call, not per test: a test that calls this twice
    must not have the second call seed on top of the first, or the seeding
    itself fails on the primary key and the failure looks like a cap result."""
    import json

    _CASE[0] += 1
    db = tmp_path / ("cap-%d.db" % _CASE[0])
    env = dict(os.environ, DB_PATH=str(db), POW_DIFFICULTY_BITS="0")
    env.pop("DB_ENCRYPTION_KEY_HEX", None)
    # Not read by the function under test (both limits arrive as arguments),
    # but set so a future reader does not think the env is what decides here.
    env["MAX_REGISTERED_USERS"] = str(max_users)
    run = subprocess.run(
        [sys.executable, "-c", SCRIPT,
         json.dumps(registered), json.dumps(revoked),
         str(max_users), str(hard_max), candidate],
        cwd=SERVER_DIR, env=env, capture_output=True, timeout=180,
    )
    out = run.stdout.decode("utf-8", "replace")
    assert run.returncode == 0, run.stderr.decode("utf-8", "replace")[-1500:]
    for line in out.splitlines():
        if line.startswith("RESULT="):
            return line.split("=", 1)[1].strip()
    raise AssertionError("no RESULT line in:\n" + out[-1500:])


def test_revoking_someone_returns_their_seat(tmp_path):
    """Two seats, two identities, one revoked -- the next person gets in.
    This is the Firm-tier promise, and before the split it failed."""
    assert admit(tmp_path, FPS[:2], [FPS[0]], max_users=2, hard_max=1000) == "ok"


def test_the_seat_cap_still_bites_when_nobody_is_revoked(tmp_path):
    """The same two seats, nobody revoked: full. Without this the test above
    would also pass with the cap check deleted entirely."""
    assert admit(tmp_path, FPS[:2], [], max_users=2, hard_max=1000) == "full"


def test_the_hard_ceiling_counts_revoked_rows_too(tmp_path):
    """S6-56 bounds the table, so a revoked row still occupies one. Both rows
    revoked, ceiling of 2: still full. An operator must not be able to grow the
    table past the ceiling by revoking."""
    assert admit(tmp_path, FPS[:2], FPS[:2], max_users=0, hard_max=2) == "full"


def test_the_hard_ceiling_outranks_a_larger_operator_cap(tmp_path):
    """A generous seat count cannot raise the safety ceiling."""
    assert admit(tmp_path, FPS[:2], [], max_users=100, hard_max=2) == "full"


def test_an_unset_operator_cap_is_not_an_absent_ceiling(tmp_path):
    """0/unset means "no seat cap of my own", never "no limit": the ceiling
    still applies. Three rows, ceiling of 3."""
    assert admit(tmp_path, FPS[:3], [], max_users=0, hard_max=3) == "full"
    assert admit(tmp_path, FPS[:2], [], max_users=0, hard_max=3) == "ok"


def test_room_under_both_limits_admits(tmp_path):
    assert admit(tmp_path, FPS[:2], [], max_users=5, hard_max=1000) == "ok"
