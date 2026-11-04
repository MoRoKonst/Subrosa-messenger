#!/usr/bin/env python3
"""
Generate additional one-time server access codes without restarting the
server — inserts directly into the same SQLite database server.py uses
(server_access_codes table). register() always reads that table live, so
a running server picks up new codes immediately, no restart needed.

Only meaningful if the server is running with SERVER_ACCESS_PROTECTED=true —
see docs/ISSUE_backup_identity_hijack.md, "server-side allowlist", and
.env.example.

Usage:
    python3 admin_gen_codes.py 5
    python3 admin_gen_codes.py 5 --server-url wss://myserver.ru   # prints ready subrosa:// links
    python3 admin_gen_codes.py 5 --server-url wss://myserver.ru --out-dir /data/qr
    DB_PATH=/data/messages.db python3 admin_gen_codes.py 5        # if not default
    python3 admin_gen_codes.py 5 --purge-legacy                   # also deletes old unused 32-bit codes first

QR images (optional): install `qrcode[pil]` (see requirements.txt, commented
out by default) to also get a PNG per code, generated entirely offline on
this machine — no third-party QR-generator service, nothing leaves the
server. Without it, only the text link is printed; paste that into any QR
generator you trust, or send it as plain text (the app also accepts a
subrosa:// link pasted straight into the manual "add server" field).

Codes are 128-bit (32 hex chars) as of S6-41 (external review 2026-09-05) —
only each code's SHA-256 hash is ever written to server_access_codes; the
raw value is shown/QR-encoded here and nowhere else. server.py refuses to
start with SERVER_ACCESS_PROTECTED=true while any UNUSED pre-S6-41 code
(32-bit, stored in plaintext) still exists — run with --purge-legacy to
delete those before generating fresh ones.
"""

import argparse
import hashlib
import io
import os
import re
import secrets
import sqlite3
import sys
import time
import urllib.parse

# Same UTF-8 stdout reconfiguration as server.py/admin_logs.py — without it,
# Cyrillic output can break on a Windows console using a non-UTF-8 codepage
# (found by actually running this once, not just ast.parse).
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

DB_PATH = os.environ.get("DB_PATH", "messages.db")

# Mirrors server.py's own ACCESS_CODE_RANDOM_BYTES/ACCESS_CODE_HASH_PREFIX/
# is_valid_access_code() exactly (external review 2026-09-05, S6-41) — this
# script is intentionally standalone (no `import server`, so it keeps
# working even against a server.py that isn't importable in this
# environment), so the canonical shape/hash logic is duplicated here rather
# than shared, same as generate_code()/build_access_link() already were
# before this fix. Keep both copies in sync if either ever changes.
# Was `secrets.token_hex(4).upper()` — only 32 bits, cheaply guessable
# online (server.py now also enforces a dedicated attempt budget and closes
# the connection on the first wrong guess, but the credential itself must
# not depend on that alone). 16 random bytes = 128 bits.
ACCESS_CODE_RANDOM_BYTES = 16
ACCESS_CODE_HASH_PREFIX  = "sha256:"
_ACCESS_CODE_HASH_RE     = re.compile(r"^sha256:[0-9a-f]{64}$")


def generate_code() -> str:
    return secrets.token_hex(ACCESS_CODE_RANDOM_BYTES).upper()


def hash_code(raw: str) -> str:
    return ACCESS_CODE_HASH_PREFIX + hashlib.sha256(raw.encode("ascii")).hexdigest()


def build_access_link(server_url: str, code: str):
    if not server_url:
        return None
    try:
        raw = server_url if "://" in server_url else f"wss://{server_url}"
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or server_url
        port = parsed.port or 9000
        return f"subrosa://server?host={host}&port={port}&code={code}"
    except Exception:
        return None


def save_qr_png(link: str, out_dir: str, code: str):
    """Renders `link` as a QR PNG entirely offline (no network call, no
    third-party service — the whole point of doing this locally instead of
    pasting the link into some website). Returns the file path, or None on
    failure (e.g. out_dir not writable)."""
    try:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{code}.png")
        qrcode.make(link).save(path)
        return path
    except Exception as e:
        print(f"  (не удалось сохранить QR-картинку для {code}: {e})")
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate additional server access codes")
    parser.add_argument("count", type=int, help="How many new codes to generate")
    parser.add_argument(
        "--server-url", default=os.environ.get("SERVER_URL", ""),
        help="Server address to embed in printed subrosa:// links (defaults to $SERVER_URL)"
    )
    parser.add_argument(
        "--out-dir", default="access_codes_qr",
        help="Where to save QR PNGs, one per code (only if qrcode[pil] is installed)"
    )
    parser.add_argument(
        "--purge-legacy", action="store_true",
        help="Delete UNUSED pre-S6-41 codes first (32-bit plaintext, stored "
             "before this script hashed codes at rest) -- server.py refuses "
             "to start with SERVER_ACCESS_PROTECTED on while any such row "
             "exists, since hashing them retroactively would not make them "
             "safe. USED legacy rows are left alone (harmless history, "
             "can't grant access anymore)."
    )
    args = parser.parse_args()
    if args.count <= 0:
        print("count must be positive")
        return 1

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS server_access_codes (
                code       TEXT PRIMARY KEY,
                used       INTEGER NOT NULL DEFAULT 0,
                used_by    TEXT,
                used_at    REAL,
                created_at REAL NOT NULL
            )
        """)

        if args.purge_legacy:
            legacy_rows = conn.execute(
                "SELECT code FROM server_access_codes WHERE used = 0"
            ).fetchall()
            legacy_codes = [row[0] for row in legacy_rows if not _ACCESS_CODE_HASH_RE.match(row[0])]
            if legacy_codes:
                conn.executemany(
                    "DELETE FROM server_access_codes WHERE code = ?",
                    [(c,) for c in legacy_codes]
                )
                conn.commit()
            print(f"Удалено неиспользованных кодов старого формата: {len(legacy_codes)}")

        # Only the sha256: hash of each new code is ever written to SQLite
        # (external review 2026-09-05, S6-41) -- the raw values live only
        # in this process's memory long enough to print/QR-encode them
        # below, same as server.py's own _db_gen_access_codes_sync().
        codes = []
        now = time.time()
        for _ in range(args.count):
            code = generate_code()
            conn.execute(
                "INSERT OR IGNORE INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
                (hash_code(code), now)
            )
            codes.append(code)
        conn.commit()

    print(f"Сгенерировано {len(codes)} новых кодов доступа ({DB_PATH}):")
    any_link = False
    for c in codes:
        link = build_access_link(args.server_url, c)
        if not link:
            print(f"  {c}   (передай --server-url или задай $SERVER_URL, чтобы получить готовую ссылку)")
            continue
        any_link = True
        print(f"  {c}   ->   {link}")
        if HAS_QRCODE:
            png_path = save_qr_png(link, args.out_dir, c)
            if png_path:
                print(f"       QR: {png_path}")

    if any_link and not HAS_QRCODE:
        print()
        print("Картинки QR не сгенерированы — пакет qrcode[pil] не установлен "
              "(pip install qrcode[pil], офлайн, ничего никуда не уходит). "
              "Пока просто разошли ссылки текстом.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
