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

QR images (optional): install `qrcode[pil]` (see requirements.txt, commented
out by default) to also get a PNG per code, generated entirely offline on
this machine — no third-party QR-generator service, nothing leaves the
server. Without it, only the text link is printed; paste that into any QR
generator you trust, or send it as plain text (the app also accepts a
subrosa:// link pasted straight into the manual "add server" field).
"""

import argparse
import io
import os
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


def generate_code() -> str:
    return secrets.token_hex(4).upper()


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
        codes = []
        now = time.time()
        for _ in range(args.count):
            code = generate_code()
            conn.execute(
                "INSERT OR IGNORE INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
                (code, now)
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
