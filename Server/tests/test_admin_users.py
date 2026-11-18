"""
admin_users.py — operator seat administration. The schema is created by
server.py's OWN setup function (in a subprocess, on a temp DB), so these
tests break if the tables the tool reads ever change shape.
"""
import os
import sqlite3
import subprocess
import sys
import time

import pytest

SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(SERVER_DIR, "admin_users.py")

FP_A = "AAAA1111BBBB2222"
FP_B = "CCCC3333DDDD4444"
FP_C = "AAAA1111EEEE5555"   # shares an 8-hex prefix with FP_A
SECRET_CODE_HASH = "sha256:" + "ab" * 32


def make_db(path):
    env = dict(os.environ, DB_PATH=str(path), POW_DIFFICULTY_BITS="0")
    env.pop("DB_ENCRYPTION_KEY_HEX", None)
    r = subprocess.run([sys.executable, "-c", "import server; server._db_setup_sync()"],
                       cwd=SERVER_DIR, env=env, capture_output=True, timeout=120)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-800:]


def seed(path):
    c = sqlite3.connect(path)
    now = time.time()
    for fp in (FP_A, FP_B, FP_C):
        c.execute("INSERT INTO registered_fingerprints VALUES (?,?)", (fp, now - 86400 * 30))
    c.execute("INSERT INTO authorized_devices (username, device_id, device_pubkey, added_at) VALUES (?,?,?,?)",
              (FP_A, "11111111-1111-4111-8111-111111111111", b"k1", now))
    c.execute("INSERT INTO authorized_devices (username, device_id, device_pubkey, added_at) VALUES (?,?,?,?)",
              (FP_A, "22222222-2222-4222-8222-222222222222", b"k2", now))
    c.execute("INSERT INTO authorized_devices (username, device_id, device_pubkey, added_at) VALUES (?,?,?,?)",
              (FP_B, "33333333-3333-4333-8333-333333333333", None, now))  # NULL pubkey: no trust, not counted
    c.execute("INSERT INTO user_totp (username, secret, created_at) VALUES (?,?,?)",
              (FP_A, "TOTP-SECRET-CANARY", now))
    c.execute("INSERT INTO server_access_codes (code, used, created_at) VALUES (?,0,?)", (SECRET_CODE_HASH, now))
    c.commit()
    c.close()


def tool(db, *args, extra_env=None):
    env = dict(os.environ, DB_PATH=str(db))
    env.pop("DB_ENCRYPTION_KEY_HEX", None)
    env.update(extra_env or {})
    p = subprocess.run([sys.executable, TOOL, *args], env=env, capture_output=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def revoked_rows(db):
    c = sqlite3.connect(db)
    try:
        return [r[0] for r in c.execute("SELECT fingerprint FROM revoked_fingerprints")]
    finally:
        c.close()


@pytest.fixture(scope="module")
def schema_db(tmp_path_factory):
    p = tmp_path_factory.mktemp("adm") / "schema.db"
    make_db(p)
    return p


@pytest.fixture
def empty_db(schema_db, tmp_path):
    p = tmp_path / "empty.db"
    p.write_bytes(schema_db.read_bytes())
    return p


@pytest.fixture
def seeded_db(empty_db):
    seed(empty_db)
    return empty_db


def test_list_on_empty_database(empty_db):
    rc, out = tool(empty_db, "list")
    assert rc == 0
    assert "No identities registered yet." in out
    assert "Identities ever registered: 0" in out


def test_list_is_default_command_and_truncates_fingerprints(seeded_db):
    rc, out = tool(seeded_db)
    assert rc == 0
    assert "AAAA…2222" in out and FP_A not in out
    assert "Identities ever registered: 3" in out
    assert "Active (registered, not revoked): 3" in out
    # two bound devices for A; B's NULL-pubkey row is not counted
    row_a = next(l for l in out.splitlines() if l.startswith("AAAA…2222"))
    row_b = next(l for l in out.splitlines() if l.startswith("CCCC…4444"))
    assert " 2  on" in row_a and " 0  off" in row_b
    assert "Access codes: 1 unused, 0 used" in out


def test_list_full_fingerprints(seeded_db):
    rc, out = tool(seeded_db, "list", "--full-fingerprints")
    assert FP_A in out and FP_B in out


def test_list_never_prints_secrets_and_is_read_only(seeded_db):
    before = seeded_db.read_bytes()
    rc, out = tool(seeded_db, "list", "--full-fingerprints")
    assert "TOTP-SECRET-CANARY" not in out
    assert SECRET_CODE_HASH not in out and "ab" * 32 not in out
    assert seeded_db.read_bytes() == before


def test_missing_database_is_not_created(tmp_path):
    ghost = tmp_path / "nope.db"
    rc, out = tool(ghost, "list")
    assert rc != 0 and "database not found" in out
    assert not ghost.exists()


def test_revoke_without_yes_changes_nothing(seeded_db):
    before = seeded_db.read_bytes()
    rc, out = tool(seeded_db, "revoke", FP_A)
    assert rc == 0 and "DRY RUN" in out
    assert "will NOT" in out and "free their seat" in out and "cut their live session" in out
    assert revoked_rows(seeded_db) == []
    assert seeded_db.read_bytes() == before


def test_revoke_with_yes_inserts_row_and_is_idempotent(seeded_db):
    rc, out = tool(seeded_db, "revoke", FP_B, "--yes")
    assert rc == 0 and "Done: revoked." in out
    assert revoked_rows(seeded_db) == [FP_B]
    rc, out = tool(seeded_db, "revoke", FP_B, "--yes")
    assert rc == 0 and "Already revoked" in out
    assert revoked_rows(seeded_db) == [FP_B]
    rc, out = tool(seeded_db, "list")
    assert "REVOKED" in out and "Revoked:                    1" in out
    assert "Active (registered, not revoked): 2" in out
    # seat is NOT freed: the registered row remains
    assert "Identities ever registered: 3" in out


def test_revoke_prefix_must_be_unambiguous(seeded_db):
    rc, out = tool(seeded_db, "revoke", "AAAA1111", "--yes")      # matches A and C
    assert rc != 0 and "ambiguous" in out
    assert revoked_rows(seeded_db) == []
    rc, out = tool(seeded_db, "revoke", "CCCC3333", "--yes")      # unique
    assert rc == 0 and revoked_rows(seeded_db) == [FP_B]


def test_revoke_rejects_garbage_and_unknown(seeded_db):
    assert tool(seeded_db, "revoke", "zzz", "--yes")[0] != 0
    assert tool(seeded_db, "revoke", "FFFFFFFFFFFFFFFF", "--yes")[0] != 0
    assert revoked_rows(seeded_db) == []


def test_revoked_row_matches_what_server_py_itself_writes(seeded_db):
    """Same table/columns as server.py's _db_revoke_fingerprint_sync."""
    tool(seeded_db, "revoke", FP_A, "--yes")
    env = dict(os.environ, DB_PATH=str(seeded_db), POW_DIFFICULTY_BITS="0")
    code = f"import server; print(server._db_is_fingerprint_revoked_sync('{FP_A}'), server._db_is_fingerprint_revoked_sync('{FP_B}'))"
    r = subprocess.run([sys.executable, "-c", code], cwd=SERVER_DIR, env=env, capture_output=True, timeout=120)
    assert r.stdout.decode().strip().splitlines()[-1] == "True False"


def codes_rows(db):
    c = sqlite3.connect(db)
    try:
        return [r[0] for r in c.execute("SELECT code FROM server_access_codes")]
    finally:
        c.close()


def test_codes_lists_prefix_only_never_the_full_hash(seeded_db):
    rc, out = tool(seeded_db, "codes")
    assert rc == 0 and "abababababab" in out
    assert SECRET_CODE_HASH not in out and "ab" * 32 not in out
    assert "Unused: 1" in out and "NOT recorded here" in out


def test_codes_delete_dry_run_then_yes(seeded_db):
    rc, out = tool(seeded_db, "codes", "--delete", "abababab")
    assert rc == 0 and "DRY RUN" in out and codes_rows(seeded_db) == [SECRET_CODE_HASH]
    rc, out = tool(seeded_db, "codes", "--delete", "abababab", "--yes")
    assert rc == 0 and "Deleted." in out and codes_rows(seeded_db) == []


def test_codes_never_deletes_a_used_code(seeded_db):
    c = sqlite3.connect(seeded_db)
    c.execute("UPDATE server_access_codes SET used = 1, used_by = ?", (FP_A,))
    c.commit(); c.close()
    rc, out = tool(seeded_db, "codes", "--delete", "abababab", "--yes")
    assert rc != 0 and "already USED" in out
    assert codes_rows(seeded_db) == [SECRET_CODE_HASH]


def test_codes_prefix_must_be_unambiguous_and_known(seeded_db):
    c = sqlite3.connect(seeded_db)
    c.execute("INSERT INTO server_access_codes (code, used, created_at) VALUES (?,0,?)", ("sha256:" + "ab" * 31 + "cd", time.time()))
    c.commit(); c.close()
    rc, out = tool(seeded_db, "codes", "--delete", "abab", "--yes")       # too short (<6)
    assert rc != 0
    rc, out = tool(seeded_db, "codes", "--delete", "ababab", "--yes")     # matches both
    assert rc != 0 and "ambiguous" in out and len(codes_rows(seeded_db)) == 2
    rc, out = tool(seeded_db, "codes", "--delete", "ffffff", "--yes")
    assert rc != 0 and "no code" in out
