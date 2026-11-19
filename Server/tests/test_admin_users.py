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


# ── revoke --purge ───────────────────────────────────────────────────────────

PURGE_TABLES = ["pending_messages", "prekey_bundles_db", "authorized_devices", "user_totp",
                "totp_recovery_codes", "user_avatars"]


def seed_purge_data(path):
    """Rows for FP_A (to be purged) and FP_B (must survive), with *_meta consistent, like a live server."""
    c = sqlite3.connect(path)
    now = time.time()
    for fp, n, size in ((FP_A, 3, 100), (FP_B, 2, 7)):
        for i in range(n):
            c.execute("INSERT INTO pending_messages (recipient, payload, created_at, msg_id, payload_bytes) VALUES (?,?,?,?,?)",
                      (fp, "x" * size, now, f"{fp}-{i}", size))
        c.execute("INSERT INTO prekey_bundles_db (username, bundle, updated_at) VALUES (?,?,?)", (fp, "{}", now))
        c.execute("INSERT INTO totp_recovery_codes (username, code_hash, used, created_at) VALUES (?,?,0,?)", (fp, "h-" + fp, now))
        c.execute("INSERT INTO user_avatars (username, avatar_b64, updated_at, avatar_bytes) VALUES (?,?,?,?)", (fp, "a" * 50, now, 50))
    c.execute("INSERT OR REPLACE INTO pending_messages_meta (id, total_rows, total_bytes) VALUES (1, 5, 314)")
    c.execute("INSERT OR REPLACE INTO user_avatars_meta (id, total_rows, total_bytes) VALUES (1, 2, 100)")
    c.commit(); c.close()


def row_counts(path):
    c = sqlite3.connect(path)
    try:
        out = {}
        for t in PURGE_TABLES:
            col = "recipient" if t == "pending_messages" else "username"
            out[t] = (c.execute(f"SELECT COUNT(*) FROM {t} WHERE {col} = ?", (FP_A,)).fetchone()[0],
                      c.execute(f"SELECT COUNT(*) FROM {t} WHERE {col} = ?", (FP_B,)).fetchone()[0])
        out["meta_p"] = c.execute("SELECT total_rows, total_bytes FROM pending_messages_meta").fetchone()
        out["meta_a"] = c.execute("SELECT total_rows, total_bytes FROM user_avatars_meta").fetchone()
        out["real_p"] = c.execute("SELECT COUNT(*), COALESCE(SUM(payload_bytes),0) FROM pending_messages").fetchone()
        out["real_a"] = c.execute("SELECT COUNT(*), COALESCE(SUM(avatar_bytes),0) FROM user_avatars").fetchone()
        return out
    finally:
        c.close()


@pytest.fixture
def purge_db(seeded_db):
    seed_purge_data(seeded_db)
    return seeded_db


def test_purge_dry_run_prints_counts_and_changes_nothing(purge_db):
    before = purge_db.read_bytes()
    rc, out = tool(purge_db, "revoke", FP_A, "--purge")
    assert rc == 0 and "DRY RUN" in out
    assert "pending_messages: 3 row(s)" in out and "user_avatars: 1 row(s)" in out
    assert "authorized_devices: 2 row(s)" in out and "user_totp: 1 row(s)" in out
    assert purge_db.read_bytes() == before and revoked_rows(purge_db) == []


def test_purge_deletes_every_named_table_for_that_identity_only(purge_db):
    rc, out = tool(purge_db, "revoke", FP_A, "--purge", "--yes")
    assert rc == 0 and "Purged:" in out, out
    c = row_counts(purge_db)
    for t in PURGE_TABLES:
        assert c[t][0] == 0, f"{t} still has rows for the purged identity"
    # the other identity keeps what it had (authorized_devices/user_totp: FP_B has the NULL-pubkey device only)
    assert c["pending_messages"][1] == 2 and c["prekey_bundles_db"][1] == 1 and c["user_avatars"][1] == 1
    assert c["authorized_devices"][1] == 1
    # the identity rows stay: registered AND revoked
    db = sqlite3.connect(purge_db)
    assert db.execute("SELECT COUNT(*) FROM registered_fingerprints WHERE fingerprint=?", (FP_A,)).fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM revoked_fingerprints WHERE fingerprint=?", (FP_A,)).fetchone()[0] == 1
    # access codes and everything else outside the list untouched
    assert db.execute("SELECT COUNT(*) FROM server_access_codes").fetchone()[0] == 1
    db.close()


def test_aggregates_match_a_recount_after_purge(purge_db):
    tool(purge_db, "revoke", FP_A, "--purge", "--yes")
    c = row_counts(purge_db)
    assert tuple(c["meta_p"]) == tuple(c["real_p"]) == (2, 14)
    assert tuple(c["meta_a"]) == tuple(c["real_a"]) == (1, 50)


def test_server_startup_reconcile_agrees_with_the_purged_database(purge_db):
    """What server.py itself recounts at startup must equal what purge wrote (S6-50 fail-closed check)."""
    tool(purge_db, "revoke", FP_A, "--purge", "--yes")
    before = row_counts(purge_db)
    make_db_setup = [sys.executable, "-c", "import server; server._db_setup_sync()"]
    env = dict(os.environ, DB_PATH=str(purge_db), POW_DIFFICULTY_BITS="0")
    env.pop("DB_ENCRYPTION_KEY_HEX", None)
    r = subprocess.run(make_db_setup, cwd=SERVER_DIR, env=env, capture_output=True, timeout=120)
    assert r.returncode == 0, r.stderr[-500:]
    after = row_counts(purge_db)
    assert before["meta_p"] == after["meta_p"] and before["meta_a"] == after["meta_a"]


def test_purge_is_idempotent_and_does_not_lift_the_revocation(purge_db):
    tool(purge_db, "revoke", FP_A, "--purge", "--yes")
    db = sqlite3.connect(purge_db)
    revoked_at = db.execute("SELECT revoked_at FROM revoked_fingerprints WHERE fingerprint=?", (FP_A,)).fetchone()[0]
    db.close()
    first = row_counts(purge_db)
    rc, out = tool(purge_db, "revoke", FP_A, "--purge", "--yes")
    assert rc == 0, out
    assert row_counts(purge_db) == first
    db = sqlite3.connect(purge_db)
    assert db.execute("SELECT revoked_at FROM revoked_fingerprints WHERE fingerprint=?", (FP_A,)).fetchone()[0] == revoked_at
    db.close()


def test_purge_works_on_an_already_revoked_identity(purge_db):
    tool(purge_db, "revoke", FP_A, "--yes")                 # revoke only, no purge
    assert row_counts(purge_db)["pending_messages"][0] == 3  # data still there
    rc, out = tool(purge_db, "revoke", FP_A, "--purge", "--yes")
    assert rc == 0 and "stays as it is" in out
    assert row_counts(purge_db)["pending_messages"][0] == 0


def test_without_purge_nothing_is_deleted(purge_db):
    rc, out = tool(purge_db, "revoke", FP_A, "--yes")
    assert rc == 0 and "add --purge" in out
    c = row_counts(purge_db)
    assert c["pending_messages"][0] == 3 and c["user_avatars"][0] == 1 and c["prekey_bundles_db"][0] == 1


def test_purge_is_one_transaction(purge_db):
    """If anything fails mid-way nothing is half-deleted: break the meta table and expect no change."""
    c = sqlite3.connect(purge_db)
    c.execute("DROP TABLE user_avatars_meta")
    c.execute("CREATE TABLE user_avatars_meta (id INTEGER PRIMARY KEY CHECK(id = 1), total_rows INTEGER NOT NULL, "
              "total_bytes INTEGER NOT NULL CHECK(total_bytes > 1000000))")   # recompute will violate this
    c.commit(); c.close()
    before = row_counts(purge_db)["pending_messages"]
    rc, out = tool(purge_db, "revoke", FP_A, "--purge", "--yes")
    assert rc != 0
    assert row_counts(purge_db)["pending_messages"] == before and revoked_rows(purge_db) == []
