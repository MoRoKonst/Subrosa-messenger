"""
Schema migration: an OLD-schema database must be migrated by server startup
(`_db_setup_sync()`) with its data intact. There was no such test.

The "old" database is built by taking a database created by the current code
and removing, with ALTER TABLE ... DROP COLUMN, exactly the columns that
server.py adds later with ALTER TABLE ... ADD COLUMN — i.e. the shape a
database created before those columns existed has. Rows are inserted INTO the
old shape, then the real setup function runs in a subprocess on that file.

Also documents (does not fix) that no PRAGMA user_version stamp exists: an
older binary started on an already-migrated database is not refused.
"""
import os
import sqlite3
import subprocess
import sys
import time

import pytest

SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (table, column) pairs added after the first version of each table, per the
# ALTER TABLE ... ADD COLUMN blocks in server.py's _db_setup_sync().
LATE_COLUMNS = [
    ("pending_messages", "payload_bytes"),
    ("channel_posts", "image_data"),
    ("channel_posts", "storage_bytes"),
    ("user_avatars", "avatar_bytes"),
    ("user_totp", "last_counter"),
    ("authorized_devices", "device_pubkey"),
    ("anon_token_state", "bootstrap_reserved"),
    ("anon_token_state", "bootstrap_reserved_by"),
]
INDEXES_ON_LATE_COLUMNS = ["idx_anon_bootstrap_requester_target"]


def run_setup(db_path):
    env = dict(os.environ, DB_PATH=str(db_path), POW_DIFFICULTY_BITS="0")
    env.pop("DB_ENCRYPTION_KEY_HEX", None)
    r = subprocess.run([sys.executable, "-c", "import server; server._db_setup_sync()"],
                       cwd=SERVER_DIR, env=env, capture_output=True, timeout=180)
    return r.returncode, r.stderr.decode("utf-8", "replace")[-1500:]


def cols(conn, table):
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def sample_value(ctype, name):
    t = (ctype or "").upper()
    if "BLOB" in t:
        return b"\x01\x02\x03"
    if "INT" in t:
        return 1
    if "REAL" in t:
        return time.time()   # recent: startup purges expired rows, which must not be mistaken for data loss
    return f"x-{name}"


def insert_row(conn, table, overrides=None):
    """Insert one row filling every NOT-NULL-without-default column of the
    table's CURRENT shape; returns the dict inserted."""
    overrides = overrides or {}
    row = {}
    for _cid, name, ctype, notnull, default, _pk in conn.execute(f"PRAGMA table_info({table})"):
        if name in overrides:
            row[name] = overrides[name]
        elif notnull and default is None:
            row[name] = sample_value(ctype, name)
    names = ", ".join(row)
    conn.execute(f"INSERT INTO {table} ({names}) VALUES ({', '.join('?' for _ in row)})", list(row.values()))
    return row


@pytest.fixture(scope="module")
def current_db(tmp_path_factory):
    p = tmp_path_factory.mktemp("mig") / "current.db"
    rc, err = run_setup(p)
    assert rc == 0, err
    return p


def make_old_db(current_db, dest):
    dest.write_bytes(current_db.read_bytes())
    conn = sqlite3.connect(dest)
    for idx in INDEXES_ON_LATE_COLUMNS:
        conn.execute(f"DROP INDEX IF EXISTS {idx}")
    for table, col in LATE_COLUMNS:
        conn.execute(f"ALTER TABLE {table} DROP COLUMN {col}")
    conn.commit()
    return conn


def test_old_shape_really_lacks_the_late_columns(current_db, tmp_path):
    """Guards the test itself: if this passes vacuously, the rest proves nothing."""
    conn = make_old_db(current_db, tmp_path / "old.db")
    for table, col in LATE_COLUMNS:
        assert col not in cols(conn, table), f"{table}.{col} should be gone from the old-shape DB"
    conn.close()


def test_old_database_is_migrated_and_data_survives(current_db, tmp_path):
    old = tmp_path / "old.db"
    conn = make_old_db(current_db, old)
    seeded = {}
    for table in ("pending_messages", "channel_posts", "user_avatars", "user_totp",
                  "authorized_devices", "registered_fingerprints"):
        seeded[table] = insert_row(conn, table)
    seeded["anon_token_state"] = insert_row(conn, "anon_token_state", {"state": "SPENT"})
    conn.commit()
    conn.close()

    rc, err = run_setup(old)
    assert rc == 0, f"startup migration crashed on an old-schema DB:\n{err}"

    conn = sqlite3.connect(old)
    for table, col in LATE_COLUMNS:
        assert col in cols(conn, table), f"{table}.{col} was not added by migration"
    conn.row_factory = sqlite3.Row
    # By design (server.py "One-time-in-effect legacy cleanup", S6-37): an
    # authorized_devices row from before device_pubkey existed becomes
    # pubkey-NULL after the ADD COLUMN, confers no trust, and is deleted at
    # startup. So it must be GONE here, not preserved.
    assert conn.execute("SELECT COUNT(*) FROM authorized_devices").fetchone()[0] == 0
    seeded.pop("authorized_devices")
    for table, row in seeded.items():
        got = conn.execute(f"SELECT * FROM {table}").fetchall()
        assert len(got) == 1, f"{table}: expected 1 row after migration, got {len(got)}"
        for k, v in row.items():
            assert got[0][k] == v, f"{table}.{k} changed by migration: {v!r} -> {got[0][k]!r}"
    # the spent token must still be SPENT (invariants 24/27/28 — a migration must never revive it)
    assert conn.execute("SELECT state FROM anon_token_state").fetchone()[0] == "SPENT"
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    conn.close()


def test_migration_is_idempotent(current_db, tmp_path):
    old = tmp_path / "old.db"
    conn = make_old_db(current_db, old)
    insert_row(conn, "user_totp")
    conn.commit()
    conn.close()
    assert run_setup(old)[0] == 0
    c = sqlite3.connect(old)
    before = {t: cols(c, t) for t, _ in LATE_COLUMNS}
    n = c.execute("SELECT COUNT(*) FROM user_totp").fetchone()[0]
    c.close()
    assert run_setup(old)[0] == 0          # second start on the migrated DB
    c = sqlite3.connect(old)
    assert {t: cols(c, t) for t, _ in LATE_COLUMNS} == before
    assert c.execute("SELECT COUNT(*) FROM user_totp").fetchone()[0] == n
    c.close()


def user_version(path):
    c = sqlite3.connect(path)
    try:
        return c.execute("PRAGMA user_version").fetchone()[0]
    finally:
        c.close()


def run_setup_full(db_path):
    env = dict(os.environ, DB_PATH=str(db_path), POW_DIFFICULTY_BITS="0")
    env.pop("DB_ENCRYPTION_KEY_HEX", None)
    r = subprocess.run([sys.executable, "-c", "import server; server._db_setup_sync()"],
                       cwd=SERVER_DIR, env=env, capture_output=True, timeout=180)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def current_schema_version():
    r = subprocess.run([sys.executable, "-c", "import server; print(server.SCHEMA_VERSION)"], cwd=SERVER_DIR,
                       capture_output=True, timeout=120)
    return int(r.stdout.decode().strip().splitlines()[-1])


def test_setup_stamps_user_version(current_db):
    assert user_version(current_db) == current_schema_version() == 1


def test_unstamped_old_database_is_migrated_and_stamped(current_db, tmp_path):
    old = tmp_path / "old.db"
    conn = make_old_db(current_db, old)
    conn.execute("PRAGMA user_version = 0")      # a database from before the stamp existed
    insert_row(conn, "user_totp")
    conn.commit()
    conn.close()
    assert user_version(old) == 0
    rc, _out, err = run_setup_full(old)
    assert rc == 0, err
    assert user_version(old) == 1
    c = sqlite3.connect(old)
    assert c.execute("SELECT COUNT(*) FROM user_totp").fetchone()[0] == 1
    c.close()


def test_database_newer_than_the_server_is_refused_and_untouched(current_db, tmp_path):
    newer = tmp_path / "newer.db"
    newer.write_bytes(current_db.read_bytes())
    c = sqlite3.connect(newer)
    c.execute("PRAGMA user_version = 99")
    c.commit()
    c.close()
    before = newer.read_bytes()
    rc, _out, err = run_setup_full(newer)
    assert rc == 1, f"expected exit code 1, got {rc}: {err[-500:]}"
    assert "[FATAL] database schema v99 is newer than this server (v1)." in err
    assert "Restore the pre-update backup" in err
    assert user_version(newer) == 99               # not downgraded
    assert newer.read_bytes() == before            # nothing was touched


def test_database_older_than_the_server_still_works(current_db, tmp_path, monkeypatch):
    """The refusal is one-directional: an older stamp is the normal migration path.
    (Today SCHEMA_VERSION is 1, so 'older' means 0; covered above — this asserts the
    equal case too: a second start on an already-stamped database is fine.)"""
    db = tmp_path / "same.db"
    db.write_bytes(current_db.read_bytes())
    rc, _o, err = run_setup_full(db)
    assert rc == 0, err
    assert user_version(db) == 1
