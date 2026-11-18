#!/usr/bin/env python3
"""
Consistent backup of a LIVE Subrosa SQLite database, then verification.

    python3 db_backup.py /app/data/messages.db /app/data/backups

Why not `cp`: server.py runs SQLite in WAL mode. Recent commits live in the
`-wal` file next to the database, not in the main file; copying only
`messages.db` of a running server silently loses them (and a copy taken while
a checkpoint runs can be internally inconsistent). The SQLite online-backup API
used here takes a consistent snapshot while the server keeps running.

After copying, the backup is opened and `PRAGMA integrity_check` must return
"ok", otherwise it is deleted and this exits non-zero — a backup nobody has
read back is a hope, not a backup.

Honors DB_ENCRYPTION_KEY_HEX (SQLCipher) like server.py; the backup is then
encrypted with the same key. Prints the backup path on the last line of stdout.
Never prints keys or data. Reads the script from stdin works too:
    docker compose exec -T <service> python - <src> <dest_dir> < deploy/db_backup.py
"""
import os
import sqlite3
import sys
import time


def connect(path, key):
    if key:
        try:
            import sqlcipher3 as driver
        except ImportError:
            sys.exit("error: DB_ENCRYPTION_KEY_HEX is set but sqlcipher3 is not installed")
        conn = driver.connect(path)
        conn.execute(f"PRAGMA key = \"x'{key}'\"")
        return conn
    return sqlite3.connect(path)


def main(argv):
    if len(argv) != 3:
        sys.exit("usage: db_backup.py <db-file> <backup-dir>")
    src, dest_dir = argv[1], argv[2]
    if not os.path.isfile(src):
        sys.exit(f"error: database not found: {src}")
    key = os.environ.get("DB_ENCRYPTION_KEY_HEX", "").strip()
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, time.strftime("messages-%Y%m%d-%H%M%S.db", time.gmtime()))
    if os.path.exists(dest):
        sys.exit(f"error: {dest} already exists")

    s = connect(src, key)
    try:
        s.execute("SELECT count(*) FROM sqlite_master").fetchone()   # wrong/missing key fails here
    except Exception:
        sys.exit("error: cannot read the source database (encrypted? DB_ENCRYPTION_KEY_HEX)")
    d = connect(dest, key)
    try:
        s.backup(d)
        d.commit()
    finally:
        d.close()
        s.close()
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass

    v = connect(dest, key)
    try:
        result = v.execute("PRAGMA integrity_check").fetchone()[0]
        tables = v.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    except Exception as e:
        result, tables = f"unreadable ({type(e).__name__})", 0
    finally:
        v.close()
    if result != "ok":
        os.remove(dest)
        sys.exit(f"error: backup failed integrity_check ({result}); backup deleted, nothing was changed on the server")
    print(f"backup verified: integrity_check=ok, {tables} tables")
    print(dest)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
