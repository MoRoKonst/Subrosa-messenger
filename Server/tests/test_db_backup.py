"""deploy/db_backup.py — consistent backup of a live WAL database + read-back check,
and a measurement of why `cp` of the main file alone is not a backup."""
import os
import shutil
import sqlite3
import subprocess
import sys

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "deploy", "db_backup.py")


def make_live_wal_db(path):
    """A DB like the running server's: WAL mode, committed rows sitting in the -wal file,
    and the writer connection still OPEN (so no checkpoint has folded them in)."""
    w = sqlite3.connect(path)
    w.execute("PRAGMA journal_mode=WAL")
    w.execute("PRAGMA wal_autocheckpoint=0")          # never checkpoint on its own
    w.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    w.commit()
    w.executemany("INSERT INTO t (v) VALUES (?)", [(f"row{i}",) for i in range(200)])
    w.commit()
    return w


def count(path):
    c = sqlite3.connect(path)
    try:
        return c.execute("SELECT count(*) FROM t").fetchone()[0]
    finally:
        c.close()


def test_backup_of_live_wal_db_has_every_committed_row(tmp_path):
    db = tmp_path / "live.db"
    w = make_live_wal_db(db)
    assert os.path.getsize(str(db) + "-wal") > 0           # rows really are in the WAL
    r = subprocess.run([sys.executable, SCRIPT, str(db), str(tmp_path / "bk")], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "integrity_check=ok" in r.stdout
    path = r.stdout.strip().splitlines()[-1]
    assert count(path) == 200
    w.close()


def test_plain_cp_of_the_main_file_loses_the_wal_rows(tmp_path):
    """The measurement behind the 'never cp a live DB' rule in docs/DEPLOY.md."""
    db = tmp_path / "live.db"
    w = make_live_wal_db(db)
    cp = tmp_path / "copied.db"
    shutil.copyfile(db, cp)                                 # what `cp messages.db backup.db` does
    try:
        n = count(cp)
    except sqlite3.DatabaseError:
        n = -1
    assert n < 200, "cp unexpectedly captured every row; the WAL-loss premise needs re-checking"
    w.close()


def test_missing_db_is_an_error_and_creates_nothing(tmp_path):
    r = subprocess.run([sys.executable, SCRIPT, str(tmp_path / "nope.db"), str(tmp_path / "bk")], capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "not found" in r.stderr
    assert not (tmp_path / "bk").exists() or not os.listdir(tmp_path / "bk")


def test_non_sqlite_file_fails_cleanly(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not a database" * 100)
    r = subprocess.run([sys.executable, SCRIPT, str(bad), str(tmp_path / "bk")], capture_output=True, text=True, timeout=60)
    assert r.returncode != 0
    assert not [f for f in os.listdir(tmp_path / "bk")] if (tmp_path / "bk").exists() else True
