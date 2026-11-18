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
    DB_PATH=/app/data/messages.db python3 admin_users.py list # non-default database

`list` is strictly read-only (the database is opened with mode=ro and is never
created if missing). `revoke` is a separate command, does nothing without
`--yes`, and accepts either a full 16-hex fingerprint or an unambiguous prefix
of at least 8 hex characters of an already-registered one.

WHAT `revoke` DOES — exactly the mechanism a client already triggers with
"I have been compromised" (`revoke_identity` in server.py): one
`INSERT OR IGNORE INTO revoked_fingerprints`. Effects, read from server.py:
  * every future `register()` for that fingerprint is refused with
    `identity_revoked`, even though the challenge/response proves key possession
    (server.py, "if await db_is_fingerprint_revoked(candidate_username)");
  * prekey bundles of that fingerprint are flagged `revoked: true` for anyone
    starting a new session with it.
WHAT IT DOES NOT DO (so the operator is not surprised, and so a sales promise
is not made on the tool's behalf):
  * it does NOT disconnect a session that is open right now — server.py checks
    the revoked table only at `register()`, i.e. at connect time. The person is
    cut off when that connection ends (or when the server is restarted);
  * it does NOT free the seat: the `registered_fingerprints` row stays, and
    MAX_REGISTERED_USERS counts every fingerprint "ever registered";
  * it does NOT delete messages already queued for that fingerprint, nor
    remove their device keys / TOTP rows (they become unreachable, not erased);
  * it does NOT invalidate server access codes that were handed out and are
    still unused: someone holding one could register a brand-new identity
    (new fingerprint). Revoking a person means revoking their codes too — this
    tool does not track which code went to whom, and cannot.

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


def cmd_revoke(args) -> int:
    conn = open_db(db_path(), writable=args.yes)
    fp = resolve(conn, args.fingerprint)
    if not has_table(conn, "revoked_fingerprints"):
        raise SystemExit("error: revoked_fingerprints table missing — start server.py once so it can create its schema")
    already = conn.execute("SELECT revoked_at FROM revoked_fingerprints WHERE fingerprint = ?", (fp,)).fetchone()
    print(f"Identity: {fp}")
    if already:
        print(f"Already revoked on {fmt_ts(already[0])} — nothing to do.")
        return 0
    print("This will:")
    print("  - add the fingerprint to revoked_fingerprints (same as the client's 'I have been compromised')")
    print("  - make every future connection attempt by this identity fail with identity_revoked")
    print("This will NOT:")
    print("  - disconnect them if they are connected right now (they are cut off when that connection ends / on server restart)")
    print("  - free their seat (MAX_REGISTERED_USERS counts every fingerprint ever registered)")
    print("  - delete queued messages, device keys or TOTP rows")
    print("  - cancel unused access codes they may hold (they could register a NEW identity with one)")
    if not args.yes:
        print()
        print("DRY RUN — nothing was changed. Re-run with --yes to do it.")
        return 0
    conn.execute("INSERT OR IGNORE INTO revoked_fingerprints (fingerprint, revoked_at) VALUES (?, ?)", (fp, time.time()))
    conn.commit()
    print()
    print("Done: revoked.")
    return 0


def main(argv=None) -> int:
    _utf8_stdout()
    p = argparse.ArgumentParser(description="Subrosa seat administration (operator tool)")
    sub = p.add_subparsers(dest="cmd")
    pl = sub.add_parser("list", help="show identities and seat usage (read-only)")
    pl.add_argument("--full-fingerprints", action="store_true", help="print complete fingerprints")
    pr = sub.add_parser("revoke", help="revoke an identity (dry run unless --yes)")
    pr.add_argument("fingerprint")
    pr.add_argument("--yes", action="store_true", help="actually perform the revocation")
    args = p.parse_args(argv)
    if args.cmd in (None, "list"):
        if args.cmd is None:
            args.full_fingerprints = False
        return cmd_list(args)
    return cmd_revoke(args)


if __name__ == "__main__":
    sys.exit(main())
