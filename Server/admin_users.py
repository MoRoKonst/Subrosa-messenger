#!/usr/bin/env python3
"""
Operator-side seat administration: who occupies a seat on this server, and how
to cut one off. Works directly on the same SQLite file server.py uses (path from
$DB_PATH), without restarting the server — same model as admin_gen_codes.py.

Usage:
    python3 admin_users.py                       # = `list`
    python3 admin_users.py list                  # truncated fingerprints
    python3 admin_users.py list --full-fingerprints
    python3 admin_users.py revoke 1A2B3C4D5E6F7A8B            # DRY RUN: prints what it would do
    python3 admin_users.py revoke 1A2B3C4D5E6F7A8B --yes      # actually does it
    python3 admin_users.py codes                              # unused access codes (by hash prefix)
    python3 admin_users.py codes --delete 1a2b3c4d            # dry run
    python3 admin_users.py codes --delete 1a2b3c4d --yes      # delete that UNUSED code
    DB_PATH=/app/data/messages.db python3 admin_users.py list # non-default database

`list` is strictly read-only (the database is opened with mode=ro and is never
created if missing). `revoke` is a separate command, does nothing without
`--yes`, and accepts either a full 16-hex fingerprint or an unambiguous prefix
of at least 8 hex characters of an already-registered one.

WHAT `revoke` DOES — exactly the mechanism a client already triggers with
"I have been compromised" (`revoke_identity` in server.py): one
`INSERT OR IGNORE INTO revoked_fingerprints`. Effects, read from server.py:
  * every future `register()` for that fingerprint is refused with
    `identity_revoked`, even though the challenge/response proves key possession;
  * prekey bundles of that fingerprint are flagged `revoked: true`;
  * a session that is open RIGHT NOW is cut by the server's revoked-sessions
    watchdog (revoked_sessions_watchdog in server.py): within
    REVOKED_SESSION_SWEEP_INTERVAL_SEC (default 30 s) the person receives
    `identity_revoked` and the socket is closed. This tool writes straight into
    SQLite and cannot talk to the server process, so the server finds the row on
    its next sweep.
WHAT IT DOES NOT DO:
  * (the seat IS freed: since the "revoking gives the seat back" change the server counts
    only non-revoked identities against MAX_REGISTERED_USERS; the registered_fingerprints
    row itself is kept so the fingerprint stays revoked);
  * it does NOT delete their stored data (queued messages, prekey bundle, device keys, TOTP
    secret/recovery codes, avatar) unless you ask with `--purge` — see below. Without it the
    data becomes unreachable, not erased;
  * it does NOT invalidate server access codes that were handed out and are
    still unused: someone holding one could register a brand-new identity.
    Use `codes` to see and delete unused codes. The server stores only the
    SHA-256 of each code, so this tool can show a code's hash prefix and age but
    never the code itself, and it deliberately does NOT record which code went
    to which person — that would be new data about people on the server. Keep
    that bookkeeping on your side (e.g. when you run admin_gen_codes.py, note
    who receives which link).

`revoke --purge` (separate flag, off by default; dry run without `--yes`) additionally deletes,
in the SAME transaction as the revocation, the rows keyed to that fingerprint in exactly these
tables and nothing else: pending_messages (recipient = fingerprint), prekey_bundles_db,
authorized_devices, user_totp, totp_recovery_codes, user_avatars. The aggregate tables the server
keeps for capacity limits (pending_messages_meta, user_avatars_meta) are recomputed from the tables
in the same transaction — the same recount server.py does at startup, so the S6-50 startup check
still agrees. NEVER deleted: the registered_fingerprints and revoked_fingerprints rows (the
fingerprint must stay revoked), access codes, anon token state, channel posts. Messages that this
person SENT sit in other people's queues and cannot be found: the server does not know senders.
A running server keeps copies of bundles/avatars/TOTP secrets in RAM; restart it to drop them.

WHAT THIS TOOL CANNOT KNOW, ON PURPOSE. The server never learns who sent an
`anon_message` and does not store who talks to whom: delivery runs on one-time
tokens that are not linked to identities. So this tool cannot show "who
contacted whom" or "what this person sent", and must not be extended to. That
absence is the property customers buy the product for. What it CAN show is
only what the server needs to authenticate a connection: the fingerprint, when
it first registered, how many devices are bound, whether TOTP is on, whether the
identity was revoked.

The output never includes access codes, key material, tokens or message content.
"""
import argparse
import io
import os
import pathlib
import re
import sqlite3
import sys
import time

FP_RE = re.compile(r"^[0-9A-F]{16}$")


def _utf8_stdout():
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)


def db_path() -> str:
    return os.environ.get("DB_PATH", "messages.db")


def open_db(path: str, writable: bool):
    """Open an EXISTING database; never create one. Honors DB_ENCRYPTION_KEY_HEX
    (SQLCipher) exactly as server.py does."""
    if not os.path.isfile(path):
        raise SystemExit(f"error: database not found: {path} (set DB_PATH to the file server.py uses)")
    key = os.environ.get("DB_ENCRYPTION_KEY_HEX", "").strip()
    uri = pathlib.Path(path).absolute().as_uri() + ("?mode=rw" if writable else "?mode=ro")
    if key:
        try:
            import sqlcipher3 as driver
        except ImportError:
            raise SystemExit("error: DB_ENCRYPTION_KEY_HEX is set but sqlcipher3 is not installed (pip install sqlcipher3-binary)")
        conn = driver.connect(uri, uri=True)
        conn.execute(f"PRAGMA key = \"x'{key}'\"")
    else:
        conn = sqlite3.connect(uri, uri=True)
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except Exception:
        raise SystemExit("error: cannot read the database (encrypted? set DB_ENCRYPTION_KEY_HEX; or not a SQLite file)")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def has_table(conn, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def fmt_fp(fp: str, full: bool) -> str:
    return fp if full or len(fp) <= 8 else fp[:4] + "…" + fp[-4:]


def fmt_ts(ts) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else "-"


def load_identities(conn):
    """List of dicts, one per known fingerprint (registered or revoked)."""
    def q(table, sql):
        return conn.execute(sql).fetchall() if has_table(conn, table) else []

    registered = dict(q("registered_fingerprints", "SELECT fingerprint, first_registered_at FROM registered_fingerprints"))
    revoked = dict(q("revoked_fingerprints", "SELECT fingerprint, revoked_at FROM revoked_fingerprints"))
    devices = dict(q("authorized_devices",
                     "SELECT username, COUNT(*) FROM authorized_devices WHERE device_pubkey IS NOT NULL GROUP BY username"))
    totp = {r[0] for r in q("user_totp", "SELECT username FROM user_totp")}
    out = []
    for fp in sorted(set(registered) | set(revoked), key=lambda f: (registered.get(f) or revoked.get(f) or 0, f)):
        out.append({
            "fp": fp,
            "registered_at": registered.get(fp),
            "devices": devices.get(fp, 0),
            "totp": fp in totp,
            "revoked_at": revoked.get(fp),
            "registered": fp in registered,
        })
    return out


def cmd_list(args) -> int:
    conn = open_db(db_path(), writable=False)
    ids = load_identities(conn)
    codes_unused = codes_used = None
    if has_table(conn, "server_access_codes"):
        codes_unused = conn.execute("SELECT COUNT(*) FROM server_access_codes WHERE used = 0").fetchone()[0]
        codes_used = conn.execute("SELECT COUNT(*) FROM server_access_codes WHERE used = 1").fetchone()[0]
    print(f"Database: {db_path()}  (read-only)")
    print()
    if not ids:
        print("No identities registered yet.")
    else:
        print(f"{'fingerprint':<18} {'registered':<11} {'devices':>7}  {'totp':<5} status")
        for i in ids:
            status = f"REVOKED {fmt_ts(i['revoked_at'])}" if i["revoked_at"] else "active"
            print(f"{fmt_fp(i['fp'], args.full_fingerprints):<18} {fmt_ts(i['registered_at']):<11} "
                  f"{i['devices']:>7}  {'on' if i['totp'] else 'off':<5} {status}")
    registered = sum(1 for i in ids if i["registered"])
    revoked = sum(1 for i in ids if i["revoked_at"])
    print()
    print(f"Identities ever registered: {registered}")
    print(f"Revoked:                    {revoked}")
    print(f"Active (registered, not revoked): {sum(1 for i in ids if i['registered'] and not i['revoked_at'])}")
    cap = os.environ.get("MAX_REGISTERED_USERS", "").strip()
    if cap and cap != "0":
        print(f"MAX_REGISTERED_USERS (from THIS shell's environment, may differ from the server's): {cap}"
              f" — the server counts all {registered} ever-registered, revoked ones included")
    if codes_unused is not None:
        print(f"Access codes: {codes_unused} unused, {codes_used} used (codes themselves are stored hashed and never shown)")
    print()
    print("Not shown, by design: who talks to whom, message content, who sent what — the server does not know.")
    return 0


def cmd_codes(args) -> int:
    conn = open_db(db_path(), writable=bool(args.delete and args.yes))
    if not has_table(conn, "server_access_codes"):
        print("No server_access_codes table (server never started with access codes).")
        return 0
    rows = conn.execute("SELECT code, used, created_at FROM server_access_codes ORDER BY created_at, code").fetchall()
    hashed = [(c, u, t) for c, u, t in rows if re.fullmatch(r"sha256:[0-9a-f]{64}", c)]
    legacy = sum(1 for c, u, t in rows if not re.fullmatch(r"sha256:[0-9a-f]{64}", c))
    if args.delete:
        want = args.delete.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{6,64}", want):
            raise SystemExit("error: give a hash prefix of at least 6 hex characters (see `codes`)")
        m = [(c, u, t) for c, u, t in hashed if c[len("sha256:"):].startswith(want)]
        if not m:
            raise SystemExit("error: no code with that prefix")
        if len(m) > 1:
            raise SystemExit(f"error: prefix is ambiguous ({len(m)} matches); give more characters")
        code, used, created = m[0]
        print(f"Code {code[len('sha256:'):][:12]}…  created {fmt_ts(created)}  {'USED' if used else 'unused'}")
        if used:
            print("This code is already USED: it grants nothing and its row is history. Not deleting.")
            return 1
        if not args.yes:
            print("DRY RUN — nothing was changed. Re-run with --yes to delete this unused code.")
            return 0
        cur = conn.execute("DELETE FROM server_access_codes WHERE code = ? AND used = 0", (code,))
        conn.commit()
        print("Deleted." if cur.rowcount == 1 else "Nothing deleted (it was used in the meantime).")
        return 0
    unused = [(c, t) for c, u, t in hashed if not u]
    print(f"Database: {db_path()}  (read-only)")
    print()
    print("unused access codes (SHA-256 prefix, created) — the codes themselves are not stored:")
    for c, t in unused:
        print(f"  {c[len('sha256:'):][:12]}…  {fmt_ts(t)}")
    if not unused:
        print("  (none)")
    print(f"\nUnused: {len(unused)}   Used: {sum(1 for c, u, t in hashed if u)}")
    if legacy:
        print(f"{legacy} legacy plaintext row(s) not shown — remove with admin_gen_codes.py --purge-legacy")
    print("Which person holds which code is NOT recorded here, by design.")
    return 0


def resolve(conn, token: str):
    token = token.strip().upper()
    if not re.fullmatch(r"[0-9A-F]{8,16}", token):
        raise SystemExit("error: give the 16-hex fingerprint (or an unambiguous prefix of at least 8 hex chars)")
    known = [i["fp"] for i in load_identities(conn)]
    matches = [f for f in known if f.startswith(token)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit("error: no such registered fingerprint in this database (run `list --full-fingerprints`)")
    raise SystemExit(f"error: prefix is ambiguous ({len(matches)} matches); give more characters")


PURGE_TABLES = [   # (table, key column) — the ONLY tables --purge may touch
    ("pending_messages", "recipient"),
    ("prekey_bundles_db", "username"),
    ("authorized_devices", "username"),
    ("user_totp", "username"),
    ("totp_recovery_codes", "username"),
    ("user_avatars", "username"),
]


def purge_plan(conn, fp):
    """[(table, rows)] for the tables that exist."""
    plan = []
    for table, col in PURGE_TABLES:
        if has_table(conn, table):
            plan.append((table, conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {col} = ?", (fp,)).fetchone()[0]))
    return plan


def recompute_meta(conn):
    """Same recount server.py does at startup (S6-50): the *_meta rows must match their tables."""
    if has_table(conn, "pending_messages_meta") and has_table(conn, "pending_messages"):
        r, b = conn.execute("SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM pending_messages").fetchone()
        conn.execute("INSERT OR REPLACE INTO pending_messages_meta (id, total_rows, total_bytes) VALUES (1, ?, ?)", (r, b))
    if has_table(conn, "user_avatars_meta") and has_table(conn, "user_avatars"):
        r, b = conn.execute("SELECT COUNT(*), COALESCE(SUM(avatar_bytes), 0) FROM user_avatars").fetchone()
        conn.execute("INSERT OR REPLACE INTO user_avatars_meta (id, total_rows, total_bytes) VALUES (1, ?, ?)", (r, b))


def cmd_revoke(args) -> int:
    conn = open_db(db_path(), writable=args.yes)
    fp = resolve(conn, args.fingerprint)
    if not has_table(conn, "revoked_fingerprints"):
        raise SystemExit("error: revoked_fingerprints table missing — start server.py once so it can create its schema")
    already = conn.execute("SELECT revoked_at FROM revoked_fingerprints WHERE fingerprint = ?", (fp,)).fetchone()
    print(f"Identity: {fp}")
    if already and not args.purge:
        print(f"Already revoked on {fmt_ts(already[0])} — nothing to do.")
        return 0
    if already:
        print(f"Already revoked on {fmt_ts(already[0])}; the revocation stays as it is.")
    else:
        print("This will:")
        print("  - add the fingerprint to revoked_fingerprints (same as the client's 'I have been compromised')")
        print("  - make every future connection attempt by this identity fail with identity_revoked")
        print("  - cut their live session within the server's sweep interval (default 30 s)")
        print("  - free their seat (the server counts only non-revoked identities against MAX_REGISTERED_USERS)")
    if args.purge:
        plan = purge_plan(conn, fp)
        print("--purge: delete the stored data of this identity, in the same transaction:")
        for table, n in plan:
            print(f"  - {table}: {n} row(s)")
        print("  - then recompute pending_messages_meta and user_avatars_meta from their tables")
        print("  never touched: registered_fingerprints / revoked_fingerprints rows, access codes, anon token state, channel posts")
        print("  not findable: messages this person SENT (the server does not know senders). A running server keeps")
        print("  bundle/avatar/TOTP copies in RAM — restart it to drop them.")
    print("This will NOT:")
    if not args.purge:
        print("  - delete queued messages, device keys or TOTP rows (add --purge to delete them)")
    print("  - cancel unused access codes they may hold (they could register a NEW identity with one: see `codes`)")
    if not args.yes:
        print()
        print("DRY RUN — nothing was changed. Re-run with --yes to do it.")
        return 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        if not already:
            conn.execute("INSERT OR IGNORE INTO revoked_fingerprints (fingerprint, revoked_at) VALUES (?, ?)", (fp, time.time()))
        deleted = []
        if args.purge:
            for table, col in PURGE_TABLES:
                if has_table(conn, table):
                    cur = conn.execute(f"DELETE FROM {table} WHERE {col} = ?", (fp,))
                    deleted.append((table, cur.rowcount))
            recompute_meta(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    print()
    print("Done: revoked." if not already else "Done.")
    if args.purge:
        print("Purged: " + ", ".join(f"{t} {n}" for t, n in deleted))
    return 0


def main(argv=None) -> int:
    _utf8_stdout()
    p = argparse.ArgumentParser(description="Subrosa seat administration (operator tool)")
    sub = p.add_subparsers(dest="cmd")
    pl = sub.add_parser("list", help="show identities and seat usage (read-only)")
    pl.add_argument("--full-fingerprints", action="store_true", help="print complete fingerprints")
    pr = sub.add_parser("revoke", help="revoke an identity (dry run unless --yes)")
    pr.add_argument("fingerprint")
    pr.add_argument("--purge", action="store_true", help="also delete this identity's stored data (queued messages, bundle, device keys, TOTP, avatar); dry run without --yes")
    pr.add_argument("--yes", action="store_true", help="actually perform the revocation")
    pc = sub.add_parser("codes", help="list / delete UNUSED access codes (by SHA-256 prefix)")
    pc.add_argument("--list", action="store_true", help="list unused codes (default)")
    pc.add_argument("--delete", metavar="PREFIX", help="delete the unused code whose hash starts with PREFIX (dry run unless --yes)")
    pc.add_argument("--yes", action="store_true", help="actually delete")
    args = p.parse_args(argv)
    if args.cmd == "codes":
        return cmd_codes(args)
    if args.cmd in (None, "list"):
        if args.cmd is None:
            args.full_fingerprints = False
        return cmd_list(args)
    return cmd_revoke(args)


if __name__ == "__main__":
    sys.exit(main())
