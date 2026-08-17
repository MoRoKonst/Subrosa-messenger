import asyncio
import websockets
import ssl
import json
import time
import sys
import io
import hmac
import sqlite3
import threading
import secrets
import base64
import hashlib
import struct
import tempfile
import os
import urllib.parse
from collections import defaultdict

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
if hasattr(sys.stderr, 'buffer'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

# ─── Состояние ────────────────────────────────────────────────────────────────

authenticated_users = {}   # websocket → username
clients             = {}   # username → {"ws": ws, "name": str, "public_key": str}
lock                = asyncio.Lock()
prekey_bundles      = {}   # username → bundle (dict)
active_calls        = {}   # username → {"peer": str, "call_id": str} — для auto call_end при дисконнекте

# ─── Anonymous Token Routing ──────────────────────────────────────────────────
# Каждый клиент подписывается на набор случайных токенов (subscribe_tokens).
# Отправитель адресует сообщение по токену (anon_message), а не по fingerprint.
# Сервер не знает кому принадлежит токен — только какой WebSocket его слушает.
token_to_ws:  dict = {}   # token (str) → websocket
token_pending: dict = {}  # token (str) → list[dict]  (очередь для офлайн-клиентов)
token_pending_created: dict = {}  # token (str) → time.time() когда встал в очередь (для TTL)
ws_to_tokens: dict = {}   # websocket → set[str]       (для очистки при дисконнекте)
known_tokens: set  = set() # токены, которые хоть раз были зарегистрированы (фейки дропаем)
TOKEN_PENDING_TTL_SEC = 24 * 3600

# ─── Anonymous Mailbox ────────────────────────────────────────────────────────
# Слепое хранилище для первого контакта: сервер не знает кто кому пишет.
# Клиент A кладёт зашифрованный блоб по тегу из инвайта (mailbox_put).
# Клиент B спрашивает сервер со списком тегов — своим настоящим + фейковыми (mailbox_fetch).
# Сервер отдаёт блобы по совпавшим тегам. Клиент пробует расшифровать каждый.
MAILBOX_TTL        = 48 * 3600       # блобы живут 48 часов
MAILBOX_TAG_LEN    = 32              # hex-символов (16 байт)
MAILBOX_MAX_BLOB   = 8 * 1024        # 8 КБ на блоб
MAILBOX_MAX_FETCH  = 20              # максимум тегов в одном запросе
mailbox: dict      = {}              # tag (str) → list[{blob: str, ts: float}]
MAX_TOKEN_LEN = 32
MAX_TOKENS_PER_SUBSCRIBE = 100

MAX_BUNDLE_SIZE_BYTES  = 64  * 1024
MAX_PACKET_SIZE_BYTES  = 6 * 1024 * 1024
OPK_LOW_WATERMARK      = 5
HANDSHAKE_TIMEOUT_SEC  = 15
# Cap on get_prekey_bundles_batch — bundles now carry an ML-KEM key, so kept
# smaller than the mailbox's 20-tag padding to bound bandwidth/server work.
MAX_BATCH_BUNDLE_TARGETS = 10

rate_limits = defaultdict(lambda: defaultdict(lambda: {"count": 0, "reset_time": time.time()}))
# Note: per-user dict is itself a defaultdict — missing message types self-heal
# instead of KeyError'ing (bit us once: the old fixed-key dict only listed
# message/reaction/typing/prekey_fetch, so adding a new rate-limited type to
# default_limits in rate_limit_check() without also touching this factory
# crashed with KeyError on that type — e.g. 'register_bundle').
# "disconnected_at" isn't pre-seeded: every write is a plain assignment
# (rate_limits[username]["disconnected_at"] = ...) and every read goes
# through .get(..., 0), so it never needs to exist ahead of time.

banned_users        = {}
banned_ips          = {}
suspicious_activity = defaultdict(lambda: {"violations": 0, "last_violation": 0})

# ─── Channels ─────────────────────────────────────────────────────────────────
# channel_id → {"name", "avatar", "description", "admin", "subscribers": set()}
channels = {}

# ─── User avatars ──────────────────────────────────────────────────────────────
# username → base64-encoded JPEG avatar (128×128, ~5-8 KB)
user_avatars = {}

# ─── Device-gated registration TOTP ────────────────────────────────────────────
# username (fingerprint) → base32 TOTP secret. One secret per account, set once:
# once present, "totp_setup" is refused for that username — an attacker who only
# holds the stolen private key (e.g. from a leaked backup) cannot provision a
# second, parallel secret to regain a working second factor. Disabling requires
# a valid current code, not just the private key, for the same reason.
#
# NOT checked on every register() — only when device_id differs from the
# fingerprint's currently active session, i.e. exactly the moment that would
# otherwise produce a session_conflict. A normal reconnect from the same
# device_id never needs a code, so this doesn't affect ordinary mobile-network
# reconnect churn at all. Same secret the client's backup-import TOTP check
# already uses (see docs/ISSUE_backup_identity_hijack.md) — a legitimate new
# device that imported the backup through the app already has it; an attacker
# who extracted the key and wrote their own client bypassing the app does not.
user_totp_secrets = {}
# username → last accepted 30s time-step counter, to reject code replay
user_totp_last_counter = {}

# ─── Optional at-rest encryption for stored TOTP secrets ──────────────────────
# TOTP inherently needs the verifier (this server) to hold the raw shared
# secret in memory to compute codes — that part can't be avoided, hashing it
# like a password would make verification impossible. What CAN be avoided:
# the on-disk SQLite copy being plaintext if the DB file itself ever leaks
# (stolen backup/snapshot, disk theft) without the attacker also controlling
# the live server process. Off by default (matches existing plaintext
# behavior for deployments that never set this). Set TOTP_SECRET_ENCRYPTION_KEY
# to a Fernet key (`python3 -c "from cryptography.fernet import Fernet;
# print(Fernet.generate_key().decode())"`) and keep it OUT of whatever backs
# up the SQLite file — the whole point is the two must not travel together.
# "fernet1:" prefix marks an encrypted value so existing plaintext rows keep
# working unchanged (same transparent-migration pattern as the client's own
# StorageKeyManager.SMK_PREFIX) — they get re-encrypted the next time that
# account's secret is saved.
TOTP_FERNET_PREFIX = "fernet1:"
_totp_fernet = None
_totp_key_env = os.environ.get("TOTP_SECRET_ENCRYPTION_KEY", "").strip()
if _totp_key_env:
    try:
        from cryptography.fernet import Fernet
        _totp_fernet = Fernet(_totp_key_env.encode())
    except Exception as e:
        print(f"[TOTP] TOTP_SECRET_ENCRYPTION_KEY задан, но невалиден ({e}) — секреты останутся как есть в БД")


def _totp_encrypt_for_storage(secret: str) -> str:
    if not _totp_fernet:
        return secret
    return TOTP_FERNET_PREFIX + _totp_fernet.encrypt(secret.encode()).decode()


def _totp_decrypt_from_storage(stored: str) -> str:
    if not stored.startswith(TOTP_FERNET_PREFIX):
        return stored  # legacy plaintext row, or encryption was never configured
    if not _totp_fernet:
        # Encrypted on disk, but no key configured right now — can't recover
        # it. Fails closed: this account effectively loses its stored secret
        # until the key is restored, rather than crashing the whole server.
        print("[TOTP] Зашифрованный секрет в БД, но TOTP_SECRET_ENCRYPTION_KEY не задан — пропущен")
        return ""
    try:
        return _totp_fernet.decrypt(stored[len(TOTP_FERNET_PREFIX):].encode()).decode()
    except Exception as e:
        print(f"[TOTP] Не удалось расшифровать секрет из БД ({e}) — пропущен")
        return ""

# ─── Optional server access-code allowlist ─────────────────────────────────────
# Off by default (personal self-hosting doesn't need this — it's for a private/
# business deployment that wants to control who can even create an account).
# Enabled via SERVER_ACCESS_PROTECTED. When on, a fingerprint's very FIRST-EVER
# register() on this server must include a valid, unused access_code — never
# required again afterward (checked against `registered_fingerprints`, not the
# in-memory `clients` dict, so it survives restarts and reconnects). Codes are
# generated at startup (SERVER_ACCESS_CODE_COUNT) or any time later via
# ForEXP/admin_gen_codes.py, which writes straight into the same SQLite file —
# register() always reads the DB live, so no server restart is needed to add
# more. All code validity/consumption logic lives here, server-side, on
# purpose — the client only ever passes through whatever it scanned, it never
# decides whether a code is required or valid.
SERVER_ACCESS_PROTECTED = os.environ.get("SERVER_ACCESS_PROTECTED", "").strip().lower() in ("1", "true", "yes")

# ─── Registration flood/Sybil mitigation ──────────────────────────────────────
# Neither of these cares about the caller's IP, on purpose — an attacker with
# many real devices/IPs defeats any per-IP limit trivially, so both are keyed
# on the thing that's actually scarce for them: minting a brand-new identity.
#
# MAX_REGISTERED_USERS: hard cap on total distinct fingerprints ever
# registered (registered_fingerprints table, survives restarts). 0/unset =
# unlimited. Deliberately a *setting*, not a fixed number baked into the
# code — every deployment's real capacity differs.
MAX_REGISTERED_USERS = int(os.environ.get("MAX_REGISTERED_USERS", "0") or "0")

# POW_DIFFICULTY_BITS: a brand-new fingerprint's first-ever register() must
# include a pow_nonce such that sha256(handshake_challenge + pow_nonce) has
# at least this many leading zero bits. Only paid once per identity, never
# again on reconnect — costs a real device real CPU time per fake account it
# wants to mint, which a per-IP limit can't touch. 0 = disabled. ~18 bits is
# sub-second on a phone but adds up fast at scale (avg 2^18 ≈ 262k hashes).
POW_DIFFICULTY_BITS = int(os.environ.get("POW_DIFFICULTY_BITS", "18") or "0")


def pow_leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


# ─── Federation ───────────────────────────────────────────────────────────────
# Set env FEDERATION_SECRET to the same value on all servers (shared symmetric key).
# Set env FEDERATION_PEERS to a comma-separated list of peer WebSocket URLs,
# e.g. "ws://server2:9000,wss://server3:9000"

FEDERATION_SECRET = os.environ.get("FEDERATION_SECRET", "")
FEDERATION_PEERS  = [p.strip() for p in os.environ.get("FEDERATION_PEERS", "").split(",") if p.strip()]
# Own public WebSocket URL — sent to father via peer_announce so clients can discover this server.
# Example: "wss://myserver.ru" or "wss://myserver.ru:4433"
SERVER_URL        = os.environ.get("SERVER_URL", "")

federation_ws        = {}   # url → websocket | None  (outgoing connections to peers)
fed_pending          = {}   # req_id → asyncio.Future  (async prekey bundle requests)
dynamic_peer_urls    = set() # URLs announced via peer_announce (discovered at runtime)
dynamic_peer_strikes = {}    # url → consecutive failure count (too many → evict)
_fed_ssl_ctx         = None  # SSL context for outgoing federation connections
incoming_peer_ws     = set() # websocket objects of authenticated incoming federation peers

DYNAMIC_PEER_MAX_STRIKES = 3   # evict dynamic peer after this many hourly misses

# Дедупликация федеративных сообщений: msg_id → timestamp доставки (TTL 5 мин)
delivered_msg_ids: dict = {}   # только для сообщений, доставленных онлайн-клиентам

# ─── Rate limit для входящих федеративных пиров ───────────────────────────────
FED_BUNDLE_LIMIT   = 60    # максимум запросов prekey bundle от одного пира за окно
FED_BUNDLE_WINDOW  = 60    # секунд в окне
FED_BUNDLE_BAN_SEC = 3600  # бан на 1 час при превышении
fed_bundle_rate    = {}    # ip → {"count": int, "reset_time": float}
fed_bundle_banned  = {}    # ip → ban_until timestamp

# ─── Offline Message Queue (SQLite) ───────────────────────────────────────────
# Messages for offline users are stored here and flushed on reconnect.
# Configure with env vars:  DB_PATH (default: messages.db), MSG_TTL_DAYS (default: 30)

DB_PATH     = os.environ.get("DB_PATH", "messages.db")
MSG_TTL_SEC = int(os.environ.get("MSG_TTL_DAYS", "30")) * 86400


def _db_setup_sync():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient  TEXT    NOT NULL,
                payload    TEXT    NOT NULL,
                created_at REAL    NOT NULL,
                msg_id     TEXT    UNIQUE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_recip ON pending_messages(recipient)")
        conn.execute("DELETE FROM pending_messages WHERE created_at < ?",
                     (time.time() - MSG_TTL_SEC,))

        # Prekey bundles (персистируем чтобы не терять при перезапуске сервера)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS prekey_bundles_db (
                username   TEXT PRIMARY KEY,
                bundle     TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
        """)

        # Channels
        conn.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                channel_id   TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                avatar       TEXT DEFAULT '📢',
                description  TEXT DEFAULT '',
                admin        TEXT NOT NULL,
                admin_name   TEXT DEFAULT '',
                created_at   REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS channel_posts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id TEXT NOT NULL,
                post_id    TEXT NOT NULL UNIQUE,
                text       TEXT NOT NULL,
                timestamp  INTEGER NOT NULL,
                author_id  TEXT NOT NULL,
                author_name TEXT DEFAULT '',
                image_data  TEXT DEFAULT ''
            )
        """)
        # Migrate existing DBs that don't have image_data column
        try:
            conn.execute("ALTER TABLE channel_posts ADD COLUMN image_data TEXT DEFAULT ''")
            conn.commit()
        except Exception:
            pass  # Column already exists
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ch_posts ON channel_posts(channel_id)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS channel_subscribers (
                channel_id TEXT NOT NULL,
                username   TEXT NOT NULL,
                PRIMARY KEY (channel_id, username)
            )
        """)
        # User avatars
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_avatars (
                username   TEXT PRIMARY KEY,
                avatar_b64 TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        # Device-gated registration TOTP — one secret per account, see comment
        # near user_totp_secrets above.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_totp (
                username   TEXT PRIMARY KEY,
                secret     TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        # One-time recovery codes issued alongside a TOTP secret at setup time —
        # the safety net for "lost my authenticator, still have the codes I saved".
        # Hashed (SHA-256 is fine here: these are server-generated, high-entropy
        # random tokens, not user-chosen low-entropy passwords, so a fast hash
        # isn't a brute-force risk the way it would be for a password). Redeeming
        # one revokes the account's TOTP secret AND all its other recovery codes —
        # forces a fresh, deliberate re-setup rather than leaving stale codes
        # usable by whoever else might have seen them.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS totp_recovery_codes (
                username   TEXT NOT NULL,
                code_hash  TEXT NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                PRIMARY KEY (username, code_hash)
            )
        """)
        # Optional access-code allowlist — see SERVER_ACCESS_PROTECTED above.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS server_access_codes (
                code       TEXT PRIMARY KEY,
                used       INTEGER NOT NULL DEFAULT 0,
                used_by    TEXT,
                used_at    REAL,
                created_at REAL NOT NULL
            )
        """)
        # Every fingerprint that has EVER completed register() on this server —
        # not the same as `clients` (in-memory, only currently-connected).
        # Existence here is what makes the access-code check a one-time,
        # first-registration-only gate instead of firing on every reconnect.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS registered_fingerprints (
                fingerprint         TEXT PRIMARY KEY,
                first_registered_at REAL NOT NULL
            )
        """)
        # Client-initiated identity revocation ("Меня скомпрометировали" —
        # see docs/ISSUE_backup_identity_hijack.md, "Candidate fixes" item 4).
        # A revoked fingerprint can no longer complete register() on this
        # server, even though the caller still cryptographically proves
        # possession of the private key in the challenge/response handshake —
        # that's the whole point: possession of a stolen key stops being
        # sufficient once the real owner has revoked it.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS revoked_fingerprints (
                fingerprint TEXT PRIMARY KEY,
                revoked_at  REAL NOT NULL
            )
        """)
        conn.commit()


def _db_load_channels_sync():
    """Load all channels from SQLite into memory on startup."""
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT channel_id, name, avatar, description, admin, admin_name FROM channels"
        ).fetchall()
        for row in rows:
            channel_id, name, avatar, desc, admin, admin_name = row
            subs = {r[0] for r in conn.execute(
                "SELECT username FROM channel_subscribers WHERE channel_id=?", (channel_id,)
            ).fetchall()}
            posts = [
                {"post_id": r[0], "text": r[1], "timestamp": r[2],
                 "author_id": r[3], "author_name": r[4], "image_data": r[5] or ""}
                for r in conn.execute(
                    "SELECT post_id, text, timestamp, author_id, author_name, image_data "
                    "FROM channel_posts WHERE channel_id=? ORDER BY timestamp DESC LIMIT 200",
                    (channel_id,)
                ).fetchall()
            ]
            posts.reverse()
            channels[channel_id] = {
                "name": name, "avatar": avatar, "description": desc,
                "admin": admin, "admin_name": admin_name,
                "subscribers": subs, "created_at": 0, "posts": posts
            }


def _db_save_channel_sync(channel_id, ch):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT OR REPLACE INTO channels
            (channel_id, name, avatar, description, admin, admin_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (channel_id, ch["name"], ch.get("avatar", "📢"), ch.get("description", ""),
              ch["admin"], ch.get("admin_name", ""), ch.get("created_at", time.time())))
        conn.commit()


def _db_save_subscriber_sync(channel_id, username):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO channel_subscribers (channel_id, username) VALUES (?, ?)",
            (channel_id, username)
        )
        conn.commit()


def _db_remove_subscriber_sync(channel_id, username):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM channel_subscribers WHERE channel_id=? AND username=?",
            (channel_id, username)
        )
        conn.commit()


def _db_save_post_sync(channel_id, post):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO channel_posts
            (channel_id, post_id, text, timestamp, author_id, author_name, image_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (channel_id, post["post_id"], post["text"], post["timestamp"],
              post["author_id"], post.get("author_name", ""), post.get("image_data", "")))
        conn.commit()


def _db_store_sync(recipient, payload_json, msg_id=None):
    with sqlite3.connect(DB_PATH) as conn:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO pending_messages "
                "(recipient, payload, created_at, msg_id) VALUES (?, ?, ?, ?)",
                (recipient, payload_json, time.time(), msg_id)
            )
            conn.commit()
        except Exception:
            pass


def _db_flush_sync(recipient):
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, payload FROM pending_messages WHERE recipient = ? ORDER BY id",
            (recipient,)
        ).fetchall()
        if rows:
            ids = [r[0] for r in rows]
            conn.execute(
                f"DELETE FROM pending_messages WHERE id IN ({','.join('?' * len(ids))})", ids
            )
            conn.commit()
        return [r[1] for r in rows]


def _db_load_avatars_sync():
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT username, avatar_b64 FROM user_avatars").fetchall()
    return {row[0]: row[1] for row in rows}


def _db_save_avatar_sync(username, avatar_b64):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO user_avatars (username, avatar_b64, updated_at) VALUES (?, ?, ?)",
            (username, avatar_b64, time.time())
        )
        conn.commit()


async def db_save_avatar(username, avatar_b64):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_save_avatar_sync, username, avatar_b64)


def _db_load_totp_sync():
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT username, secret FROM user_totp").fetchall()
    result = {}
    for username, stored in rows:
        secret = _totp_decrypt_from_storage(stored)
        if secret:
            result[username] = secret
    return result


def _db_save_totp_sync(username, secret):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO user_totp (username, secret, created_at) VALUES (?, ?, ?)",
            (username, _totp_encrypt_for_storage(secret), time.time())
        )
        conn.commit()


def _db_delete_totp_sync(username):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM user_totp WHERE username = ?", (username,))
        conn.commit()


async def db_save_totp(username, secret):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_save_totp_sync, username, secret)


async def db_delete_totp(username):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_delete_totp_sync, username)


def _db_gen_access_codes_sync(count):
    codes = [secrets.token_hex(4).upper() for _ in range(count)]
    with sqlite3.connect(DB_PATH) as conn:
        now = time.time()
        for c in codes:
            conn.execute(
                "INSERT OR IGNORE INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
                (c, now)
            )
        conn.commit()
    return codes


def _db_count_access_codes_sync():
    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM server_access_codes").fetchone()[0]
        unused = conn.execute("SELECT COUNT(*) FROM server_access_codes WHERE used = 0").fetchone()[0]
    return total, unused


def _db_check_and_consume_access_code_sync(code, fingerprint):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT used FROM server_access_codes WHERE code = ?", (code,)).fetchone()
        if row is None or row[0]:
            return False
        conn.execute(
            "UPDATE server_access_codes SET used = 1, used_by = ?, used_at = ? WHERE code = ?",
            (fingerprint, time.time(), code)
        )
        conn.commit()
        return True


def _db_is_fingerprint_registered_sync(fingerprint):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM registered_fingerprints WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
    return row is not None


def _db_mark_fingerprint_registered_sync(fingerprint):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO registered_fingerprints (fingerprint, first_registered_at) VALUES (?, ?)",
            (fingerprint, time.time())
        )
        conn.commit()


async def db_check_and_consume_access_code(code, fingerprint):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_check_and_consume_access_code_sync, code, fingerprint)


async def db_is_fingerprint_registered(fingerprint):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_is_fingerprint_registered_sync, fingerprint)


async def db_mark_fingerprint_registered(fingerprint):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_mark_fingerprint_registered_sync, fingerprint)


def _db_count_registered_fingerprints_sync():
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT COUNT(*) FROM registered_fingerprints").fetchone()
    return row[0] if row else 0


async def db_count_registered_fingerprints():
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_count_registered_fingerprints_sync)


def _db_revoke_fingerprint_sync(fingerprint):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_fingerprints (fingerprint, revoked_at) VALUES (?, ?)",
            (fingerprint, time.time())
        )
        conn.commit()


def _db_is_fingerprint_revoked_sync(fingerprint):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM revoked_fingerprints WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
    return row is not None


async def db_revoke_fingerprint(fingerprint):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_revoke_fingerprint_sync, fingerprint)


async def db_is_fingerprint_revoked(fingerprint):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_is_fingerprint_revoked_sync, fingerprint)


def save_access_code_qr(link, code):
    """Renders `link` as a QR PNG entirely offline (no network call, no
    third-party QR-generator service — nothing about the code/address ever
    leaves this machine). Only runs if the optional qrcode[pil] package is
    installed (see requirements.txt). Returns the file path, or None."""
    if not HAS_QRCODE:
        return None
    try:
        out_dir = os.environ.get("ACCESS_CODE_QR_DIR", "access_codes_qr")
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{code}.png")
        qrcode.make(link).save(path)
        return path
    except Exception:
        return None


def build_access_link(code):
    """Turns a bare access code into a scannable subrosa://server?... link,
    using SERVER_URL for the address — same link format the Android client's
    parseServerQrPayload() expects. Returns just the code (with a manual-setup
    note) if SERVER_URL isn't configured, since there's no address to embed."""
    if not SERVER_URL:
        return None
    try:
        raw = SERVER_URL if "://" in SERVER_URL else f"wss://{SERVER_URL}"
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or SERVER_URL
        port = parsed.port or 9000
        return f"subrosa://server?host={host}&port={port}&code={code}"
    except Exception:
        return None


def _totp_code_at_counter(secret_b32: str, counter: int) -> str:
    """RFC 6238 TOTP code (HMAC-SHA1, 6 digits) for a given 30s time-step counter."""
    padded = secret_b32.strip().upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 1_000_000).zfill(6)


def totp_code_matches(secret_b32: str, code: str, window: int = 1):
    """Returns the matching time-step counter if `code` is valid for `secret_b32`
    within `window` steps of clock drift, else None."""
    if not secret_b32 or not code:
        return None
    code = code.strip()
    counter_now = int(time.time() // 30)
    for drift in range(-window, window + 1):
        try:
            if hmac.compare_digest(_totp_code_at_counter(secret_b32, counter_now + drift), code):
                return counter_now + drift
        except Exception:
            return None
    return None


def totp_verify_and_consume(username: str, code: str) -> bool:
    """Verifies `code` against the account's stored secret and rejects replay of
    an already-used time-step."""
    secret = user_totp_secrets.get(username)
    if not secret:
        return False
    matched = totp_code_matches(secret, code)
    if matched is None:
        return False
    if matched <= user_totp_last_counter.get(username, -1):
        print(f"[SECURITY] TOTP replay отклонён для {username}")
        return False
    user_totp_last_counter[username] = matched
    return True


def _hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


def generate_recovery_codes(count: int = 8) -> list:
    """Human-typeable, high-entropy: 10 hex chars, grouped for readability
    (e.g. 'A1B2C-D3E4F'). Not derived from the TOTP secret -- an independent
    credential, so losing one doesn't compromise the other."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(5).upper()
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def _db_save_recovery_codes_sync(username: str, codes: list):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM totp_recovery_codes WHERE username = ?", (username,))
        now = time.time()
        for code in codes:
            conn.execute(
                "INSERT INTO totp_recovery_codes (username, code_hash, used, created_at) VALUES (?, ?, 0, ?)",
                (username, _hash_recovery_code(code), now)
            )
        conn.commit()


def _db_delete_recovery_codes_sync(username: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM totp_recovery_codes WHERE username = ?", (username,))
        conn.commit()


def _db_check_and_consume_recovery_code_sync(username: str, code: str) -> bool:
    """One-shot: marks the code used in the same statement it checks it, so
    two concurrent redemption attempts (same code) can't both succeed."""
    code_hash = _hash_recovery_code(code)
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "UPDATE totp_recovery_codes SET used = 1 "
            "WHERE username = ? AND code_hash = ? AND used = 0",
            (username, code_hash)
        )
        conn.commit()
        return cur.rowcount > 0


async def db_save_recovery_codes(username: str, codes: list):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_save_recovery_codes_sync, username, codes)


async def db_delete_recovery_codes(username: str):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_delete_recovery_codes_sync, username)


async def db_check_and_consume_recovery_code(username: str, code: str) -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_check_and_consume_recovery_code_sync, username, code)


async def db_store(recipient, payload_dict, msg_id=None):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_store_sync, recipient, json.dumps(payload_dict), msg_id)


async def db_flush(recipient):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_flush_sync, recipient)


def _db_save_bundle_sync(username, bundle_data):
    """Persist prekey bundle to SQLite so it survives server restarts."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO prekey_bundles_db (username, bundle, updated_at) VALUES (?, ?, ?)",
                (username, json.dumps(bundle_data), time.time())
            )
            conn.commit()
    except Exception as e:
        print(f"[DB] Ошибка сохранения bundle для {username}: {e}")


def _db_load_bundles_sync():
    """Load all prekey bundles from SQLite into memory on startup."""
    result = {}
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT username, bundle FROM prekey_bundles_db"
            ).fetchall()
            for username, bundle_json in rows:
                try:
                    result[username] = json.loads(bundle_json)
                except Exception:
                    pass
    except Exception as e:
        print(f"[DB] Ошибка загрузки bundles: {e}")
    return result


async def db_save_bundle(username, bundle_data):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_save_bundle_sync, username, bundle_data)


def fed_bundle_rate_ok(ip: str) -> bool:
    """
    Проверяет rate limit запросов prekey bundle от федеративного пира.
    Возвращает False и выставляет бан если лимит превышен.
    """
    now = time.time()
    # Проверяем бан
    ban_until = fed_bundle_banned.get(ip, 0)
    if now < ban_until:
        return False
    # Инициализируем / сбрасываем окно
    entry = fed_bundle_rate.get(ip)
    if not entry or now > entry["reset_time"]:
        fed_bundle_rate[ip] = {"count": 1, "reset_time": now + FED_BUNDLE_WINDOW}
        return True
    entry["count"] += 1
    if entry["count"] > FED_BUNDLE_LIMIT:
        fed_bundle_banned[ip] = now + FED_BUNDLE_BAN_SEC
        fed_bundle_rate.pop(ip, None)
        print(f"[FEDERATION] Rate limit: пир {ip} забанен на {FED_BUNDLE_BAN_SEC}с (спам prekey)")
        return False
    return True


async def forward_to_peers(to: str, payload: dict) -> bool:
    """Forward a message payload to all connected federation peers.
    Returns True if at least one peer received the message."""
    if not federation_ws:
        return False
    data = json.dumps({"type": "federated_forward", "to": to, "payload": payload})
    sent = False
    for url, ws in list(federation_ws.items()):
        if ws is not None:
            ok = await send_safe(ws, data)
            sent = sent or ok
    return sent


async def federated_get_bundle(target: str):
    """Ask all connected peers for a prekey bundle. Returns first response or None."""
    if not federation_ws:
        return None
    req_id = secrets.token_hex(8)
    loop   = asyncio.get_event_loop()
    fut    = loop.create_future()
    fed_pending[req_id] = fut
    data = json.dumps({"type": "federated_get_bundle", "target": target, "req_id": req_id})
    for url, ws in list(federation_ws.items()):
        if ws is not None:
            await send_safe(ws, data)
    try:
        return await asyncio.wait_for(asyncio.shield(fut), timeout=3.0)
    except asyncio.TimeoutError:
        return None
    finally:
        fed_pending.pop(req_id, None)
        if not fut.done():
            fut.cancel()


async def broadcast_roster_update(new_url: str, skip_ws=None):
    """
    Gossip: рассылаем новый URL пира всем остальным подключённым федеративным пирам
    (как исходящим, так и входящим), кроме skip_ws (источника сообщения).
    """
    data = json.dumps({"type": "peer_roster", "peers": [new_url]})
    for url, ws in list(federation_ws.items()):
        if ws is not None and ws is not skip_ws:
            asyncio.create_task(send_safe(ws, data))
    for ws in list(incoming_peer_ws):
        if ws is not skip_ws:
            asyncio.create_task(send_safe(ws, data))


async def handle_federation_response(msg: dict):
    """Handle a response message that arrives on an outgoing federation connection."""
    msg_type = msg.get("type")

    if msg_type == "federated_bundle_response":
        req_id = msg.get("req_id")
        bundle = msg.get("bundle")
        fut    = fed_pending.get(req_id)
        # Резолвим только на реальный bundle: null-ответы от пиров, у которых нет данного пользователя,
        # игнорируем — ждём до таймаута, чтобы ответ от "правильного" пира не был вытеснен.
        if fut and not fut.done() and bundle is not None:
            fut.set_result(bundle)

    # Gossip: получили ростер от пира — подключаемся ко всем новым
    elif msg_type == "peer_roster":
        peers = msg.get("peers", [])
        for url in peers:
            url = url.strip()
            if url and url != SERVER_URL and url not in dynamic_peer_urls and url not in FEDERATION_PEERS:
                dynamic_peer_urls.add(url)
                asyncio.create_task(federation_connect_to_peer(url, _fed_ssl_ctx))
                print(f"[FEDERATION] Новый пир из ростера: {url}")


async def handle_federation_peer_incoming(websocket, ip: str):
    """Handle messages from an authenticated incoming federation peer connection."""
    print(f"[FEDERATION] Входящий пир подключен: {ip}")
    incoming_peer_ws.add(websocket)

    # Gossip: отправляем новому пиру весь известный нам ростер
    roster = list(dynamic_peer_urls)
    if roster:
        await send_safe(websocket, json.dumps({"type": "peer_roster", "peers": roster}))
        print(f"[FEDERATION] Ростер ({len(roster)} пиров) отправлен входящему пиру")

    try:
        async for raw_msg in websocket:
            if len(raw_msg) > MAX_PACKET_SIZE_BYTES * 2:
                break
            try:
                msg = json.loads(raw_msg)
            except Exception:
                continue

            msg_type = msg.get("type")

            # ── Deliver a forwarded message to a local client ─────────────────
            if msg_type == "federated_forward":
                to      = msg.get("to")
                payload = msg.get("payload", {})
                if not to:
                    continue
                msg_id = payload.get("id")

                # Дедупликация: одно и то же сообщение может прийти по нескольким путям меша
                if msg_id:
                    now = time.time()
                    if msg_id in delivered_msg_ids:
                        continue  # уже доставлено — отбрасываем
                    # Чистим просроченные записи (TTL 5 мин) при каждом новом сообщении
                    expired = [k for k, v in list(delivered_msg_ids.items()) if now - v > 300]
                    for k in expired:
                        del delivered_msg_ids[k]
                    delivered_msg_ids[msg_id] = now

                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(payload))
                    print(f"[FEDERATION] Доставлено: → {to}")
                else:
                    await db_store(to, payload, msg_id)
                    print(f"[FEDERATION] Очередь: → {to} (офлайн)")

            # ── Son server announces itself to father ─────────────────────────
            elif msg_type == "peer_announce":
                url = msg.get("url", "").strip()
                if url and url not in dynamic_peer_urls and url not in FEDERATION_PEERS:
                    dynamic_peer_urls.add(url)
                    print(f"[FEDERATION] Новый пир зарегистрирован: {url}")
                    asyncio.create_task(federation_connect_to_peer(url, _fed_ssl_ctx))
                    # Gossip: рассылаем новый URL всем остальным пирам
                    asyncio.create_task(broadcast_roster_update(url, skip_ws=websocket))

            # ── Serve a prekey bundle to a requesting peer ────────────────────
            elif msg_type == "federated_get_bundle":
                if not fed_bundle_rate_ok(ip):
                    print(f"[FEDERATION] Запрос bundle от {ip} отклонён (rate limit)")
                    continue
                target = msg.get("target")
                req_id = msg.get("req_id")
                bundle_to_send = None
                async with lock:
                    bundle_data = prekey_bundles.get(target)
                    if bundle_data:
                        if isinstance(bundle_data, dict) and "bundle" in bundle_data:
                            used_opk = None
                            if bundle_data["bundle"].get("opks"):
                                used_opk  = bundle_data["bundle"]["opks"].pop(0)
                                remaining = len(bundle_data["bundle"]["opks"])
                                if remaining < OPK_LOW_WATERMARK:
                                    target_ws = clients.get(target, {}).get("ws")
                                    if target_ws:
                                        asyncio.create_task(send_safe(
                                            target_ws,
                                            json.dumps({"type": "prekey_bundle_request"})
                                        ))
                            bundle_to_send = dict(bundle_data["bundle"])
                            bundle_to_send["opks"] = [used_opk] if used_opk else []
                        else:
                            bundle_to_send = bundle_data
                await send_safe(websocket, json.dumps({
                    "type":   "federated_bundle_response",
                    "req_id": req_id,
                    "bundle": bundle_to_send
                }))

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"[FEDERATION] Ошибка входящего пира {ip}: {e}")
    finally:
        incoming_peer_ws.discard(websocket)
        print(f"[FEDERATION] Входящий пир отключился: {ip}")


async def federation_connect_to_peer(url: str, ssl_ctx=None):
    """Maintain a persistent outgoing WebSocket connection to a federation peer."""
    backoff = 5
    while True:
        try:
            print(f"[FEDERATION] Подключение к {url}…")
            async with websockets.connect(
                url, ssl=ssl_ctx, ping_interval=30, ping_timeout=10
            ) as ws:
                federation_ws[url] = ws

                # ── Receive challenge ─────────────────────────────────────────
                raw = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT_SEC)
                msg = json.loads(raw)
                if msg.get("type") != "challenge":
                    raise Exception("Ожидался challenge от пира")

                # ── Respond with HMAC-SHA256 of challenge ─────────────────────
                challenge_bytes = base64.b64decode(msg["data"])
                mac = hmac.new(
                    FEDERATION_SECRET.encode(), challenge_bytes, hashlib.sha256
                ).digest()
                await ws.send(json.dumps({
                    "type": "federation_auth",
                    "mac":  base64.b64encode(mac).decode()
                }))

                raw = await asyncio.wait_for(ws.recv(), timeout=10)
                msg = json.loads(raw)
                if msg.get("type") != "federation_auth_ok":
                    raise Exception(f"Аутентификация отклонена: {msg}")

                backoff = 5
                print(f"[FEDERATION] Подключен к {url}")

                # ── Announce own URL to father so clients can discover us ─────
                if SERVER_URL:
                    await ws.send(json.dumps({
                        "type": "peer_announce",
                        "url":  SERVER_URL
                    }))
                    print(f"[FEDERATION] peer_announce отправлен → {url} (наш адрес: {SERVER_URL})")

                # ── Handle responses (bundle lookups etc.) ────────────────────
                async for raw_msg in ws:
                    try:
                        await handle_federation_response(json.loads(raw_msg))
                    except Exception as e:
                        print(f"[FEDERATION] Ошибка ответа от {url}: {e}")

        except Exception as e:
            print(f"[FEDERATION] Соединение с {url} потеряно: {e}")
        finally:
            federation_ws[url] = None

        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)


# ─── Вспомогательные ──────────────────────────────────────────────────────────

def strip_padding(message: dict) -> dict:
    message.pop("_p", None)
    message.pop("p",  None)
    return message

def check_ip_banned(ip):
    if ip in banned_ips:
        if time.time() < banned_ips[ip]:
            return True
        del banned_ips[ip]
    return False

def ban_ip(ip, duration=600):
    banned_ips[ip] = time.time() + duration
    print(f"[BAN] IP {ip} забанен на {duration} секунд")

def check_banned(username):
    if username in banned_users:
        if time.time() < banned_users[username]:
            return True
        del banned_users[username]
    return False

def report_violation(username, reason):
    now = time.time()
    activity = suspicious_activity[username]
    if now - activity["last_violation"] > 300:
        activity["violations"] = 0
    activity["violations"] += 1
    activity["last_violation"] = now
    print(f"[SECURITY] Нарушение от {username}: {reason} (всего: {activity['violations']})")
    if activity["violations"] >= 5:
        banned_users[username] = now + 600
        print(f"[BAN] {username} забанен на 10 минут")
        return True
    return False

def rate_limit_check(username, msg_type, limit=None, window=60):
    default_limits = {
        "message": 50, "reaction": 100, "typing": 200, "prekey_fetch": 10,
        # Раньше было 100 — легко пробивалось одним видеокружком/файлом
        # (чанки по 120 000 символов, пачками по 5), особенно если
        # соединение падало посреди отправки и клиент начинал заново с
        # первого чанка. Поднято до 500 — тот же порядок, что у уже
        # существующего call_ice (300) для похожей причины (много мелких
        # сообщений на одно действие пользователя), плюс отдельно чинится
        # сам повтор с нуля на клиенте.
        "anon_message": 500, "mailbox_put": 20, "subscribe_tokens": 10,
        "channel_create": 5, "register_bundle": 20, "profile_update": 10,
        # Call signaling: call_ice legitimately fires many times per single call
        # (one message per ICE candidate, several restarts possible) so it needs
        # a generous ceiling; call_offer is the tightest, since each one can also
        # trigger missed-call storage + an FCM wakeup push to the offline target.
        "call_offer": 20, "call_answer": 30, "call_ice": 300, "call_end": 30,
        "call_ringing": 30, "call_ice_restart": 30,
        "call_group_invite": 20, "call_group_join": 30, "call_group_answer": 30,
        "call_group_ice": 300, "call_group_leave": 30, "call_group_peer_list": 30,
        "call_request_audio": 20, "call_request_video": 20, "call_response": 30,
        "bootstrap_diagnostic": 5,
    }
    max_count = limit or default_limits.get(msg_type)
    if not max_count:
        return True
    now = time.time()
    limit_data = rate_limits[username][msg_type]
    if now - limit_data["reset_time"] > window:
        limit_data["count"]      = 0
        limit_data["reset_time"] = now
    limit_data["count"] += 1
    if limit_data["count"] > max_count:
        print(f"[RATE_LIMIT] {username} превысил лимит {msg_type}")
        return False
    return True

def pick_bootstrap_token(target: str):
    """Hands a requester one of `target`'s currently-registered anon tokens,
    without consuming it — it stays valid (token_to_ws/known_tokens
    untouched) until actually used in an anon_message, exactly like a token
    shared peer-to-peer via the existing sendAnonTokensTo flow. Lets a fresh
    X3DH handshake's session_init be delivered anonymously instead of
    directly addressed, whether this bundle was fetched directly or as part
    of an anonymous batched fetch (see get_prekey_bundles_batch below).
    Returns None if target is offline or has no registered tokens.
    """
    target_data = clients.get(target)
    if not target_data:
        return None
    target_ws = target_data.get("ws")
    owned = ws_to_tokens.get(target_ws)
    if not owned:
        return None
    return next(iter(owned))

def cleanup_stale_rate_limits():
    now = time.time()
    stale = [u for u, data in rate_limits.items()
             if data.get("disconnected_at", 0) > 0
             and now - data["disconnected_at"] > 900]
    for u in stale:
        rate_limits.pop(u, None)
        suspicious_activity.pop(u, None)

async def send_safe(ws, data: str) -> bool:
    try:
        await ws.send(data)
        return True
    except Exception:
        return False

# ─── FCM wake-up ─────────────────────────────────────────────────────────────
# Требуется: pip install firebase-admin
# Настройка: задай переменную окружения GOOGLE_APPLICATION_CREDENTIALS=path/to/serviceAccount.json
# (JSON-файл скачивается в Firebase Console → Project Settings → Service Accounts → Generate new private key)

_firebase_initialized = False

def _init_firebase() -> bool:
    """Инициализирует Firebase Admin SDK один раз. Возвращает True если успешно."""
    global _firebase_initialized
    if _firebase_initialized:
        return True
    cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not cred_path:
        return False
    try:
        import firebase_admin
        from firebase_admin import credentials as fb_credentials
        if not firebase_admin._apps:
            cred = fb_credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        return True
    except Exception as e:
        print(f"[FCM] Ошибка инициализации Firebase: {e}")
        return False

async def send_fcm_wakeup(target_username: str):
    """Отправляет silent FCM push чтобы разбудить приложение получателя."""
    try:
        async with lock:
            fcm_token = clients.get(target_username, {}).get("fcm_token")
        if not fcm_token:
            return  # нет токена — пропускаем

        if not _init_firebase():
            return  # GOOGLE_APPLICATION_CREDENTIALS не задан — FCM отключён

        from firebase_admin import messaging
        msg = messaging.Message(
            data={"type": "wakeup"},
            android=messaging.AndroidConfig(priority="high"),
            token=fcm_token
        )
        # messaging.send() — синхронный, запускаем в потоке чтобы не блокировать event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, messaging.send, msg)
        print(f"[FCM] Wakeup отправлен пользователю {target_username}")
    except Exception as e:
        print(f"[FCM] Ошибка wake-up для {target_username}: {e}")

async def send_fcm_session_conflict(fcm_token: str, ts: float):
    """Пушит ВИДИМОЕ уведомление (не silent data) о вытеснении сессии — должно
    показаться даже если приложение свёрнуто/убито, а не только при активном
    WebSocket-соединении. Токен уже известен (взят из вытесняемой сессии), без
    доп. lookup по username."""
    try:
        if not _init_firebase():
            return
        from firebase_admin import messaging
        msg = messaging.Message(
            notification=messaging.Notification(
                title="Активна сессия на другом устройстве",
                body="Твой аккаунт только что открыли с нового устройства — эта сессия закрыта.",
            ),
            data={"type": "session_conflict", "ts": str(ts)},
            android=messaging.AndroidConfig(priority="high"),
            token=fcm_token
        )
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, messaging.send, msg)
        print(f"[FCM] session_conflict push отправлен")
    except Exception as e:
        print(f"[FCM] Ошибка session_conflict push: {e}")

# ─── Обработчик клиента ───────────────────────────────────────────────────────

async def handle_client(websocket):
    ip = websocket.remote_address[0] if websocket.remote_address else "unknown"

    if check_ip_banned(ip):
        print(f"[SECURITY] Заблокированный IP: {ip}")
        await websocket.close()
        return

    username             = None
    authenticated        = False
    is_fed               = False
    challenge            = None
    verified_public_key  = None  # raw key bytes proven via challenge_response; register must match this

    try:
        print(f"[+] Новое подключение от {ip}")

        # ─── Handshake challenge ──────────────────────────────────────────────
        challenge     = secrets.token_bytes(32)
        challenge_b64 = base64.b64encode(challenge).decode()
        await websocket.send(json.dumps({"type": "challenge", "data": challenge_b64}))

        # Ждём ответ на challenge с таймаутом — не даём полуоткрытым соединениям висеть
        try:
            raw_handshake = await asyncio.wait_for(websocket.recv(), timeout=HANDSHAKE_TIMEOUT_SEC)
        except asyncio.TimeoutError:
            print(f"[SECURITY] Handshake timeout от {ip}")
            return

        if len(raw_handshake) > MAX_PACKET_SIZE_BYTES:
            ban_ip(ip)
            return
        try:
            hs_msg = json.loads(raw_handshake)
        except Exception:
            print(f"[SECURITY] Невалидный JSON в handshake от {ip}")
            return
        strip_padding(hs_msg)
        hs_type = hs_msg.get("type")

        if hs_type == "federation_auth" and FEDERATION_SECRET:
            provided = base64.b64decode(hs_msg.get("mac", ""))
            expected = hmac.new(FEDERATION_SECRET.encode(), challenge, hashlib.sha256).digest()
            if not hmac.compare_digest(provided, expected):
                print(f"[FEDERATION] Неверный MAC от {ip}")
                return
            is_fed = True
            await websocket.send(json.dumps({"type": "federation_auth_ok"}))
            print(f"[FEDERATION] Входящий пир аутентифицирован: {ip}")
            # Передаём управление федерационному обработчику ниже
        elif hs_type == "challenge_response":
            try:
                from cryptography.hazmat.primitives import serialization, hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.backends import default_backend
                from cryptography.exceptions import InvalidSignature

                public_key_b64 = hs_msg.get("public_key")
                signature_b64  = hs_msg.get("signature")
                if not public_key_b64 or not signature_b64:
                    return

                key_bytes  = base64.b64decode(public_key_b64)
                public_key = serialization.load_der_public_key(key_bytes, backend=default_backend())
                sig_bytes  = base64.b64decode(signature_b64)
                public_key.verify(sig_bytes, challenge, ec.ECDSA(hashes.SHA256()))

                verified_public_key = key_bytes
                authenticated = True
                print(f"[HANDSHAKE] Успешно: {ip}")
                await websocket.send(json.dumps({"type": "handshake_ok"}))

            except InvalidSignature:
                print(f"[HANDSHAKE] Неверная подпись от {ip}")
                return
            except Exception as e:
                print(f"[HANDSHAKE] Ошибка: {e}")
                return
        else:
            print(f"[SECURITY] Ожидался challenge_response, получен {hs_type} от {ip}")
            return

        if not authenticated and not is_fed:
            return

        async for raw_message in websocket:

            # Лимит размера пакета
            if len(raw_message) > MAX_PACKET_SIZE_BYTES:
                print(f"[SECURITY] Слишком большой пакет от {ip}: {len(raw_message)} bytes")
                ban_ip(ip)
                return

            try:
                message = json.loads(raw_message)
            except Exception:
                print(f"[SECURITY] Невалидный JSON от {ip}")
                continue

            strip_padding(message)
            msg_type = message.get("type")

            ALLOWED_TYPES = [
                "register", "register_bundle", "request_prekey", "get_key", "ping", "pong",
                "message", "session_init",
                "reaction", "voice", "typing", "edit",
                "image_chunk", "file_chunk", "video_chunk", "chunk_ack",
                "read",
                "publish_prekey_bundle",
                "get_prekey_bundle", "get_prekey_bundles_batch", "group_reaction",
                "group_create",
                "group_message",
                "group_member_removed",
                "group_key_rotation",
                "group_invite_accepted",
                "delivered",
                "channel_create",
                "channel_subscribe",
                "channel_unsubscribe",
                "channel_post",
                "channel_get_info",
                # ── Call signaling ──
                "call_offer", "call_answer", "call_ice",
                "call_end", "call_ringing",
                "call_group_invite", "call_group_join",
                "call_group_answer", "call_group_ice", "call_group_leave",
                "call_group_peer_list", "call_ice_restart",
                # ── Two-phase call flow (request/response before real signaling) ──
                "call_request_audio", "call_request_video", "call_response",
                # ── Chat features ──
                "message_delete", "disappear_timer",
                "group_message_delete",
                # ── FCM token registration ──
                "register_fcm",
                # ── Profile ──
                "profile_update",
                # ── Session management ──
                "session_reset", "revoke_identity",
                # ── Anonymous token routing ──
                "subscribe_tokens", "anon_message", "anon_delivery_ack",
                # ── Anonymous Mailbox ──
                "mailbox_put", "mailbox_fetch",
                # ── Device-gated registration TOTP ──
                "totp_setup", "totp_disable",
                # ── Client-side diagnostics ──
                "bootstrap_diagnostic"
            ]
            if msg_type not in ALLOWED_TYPES:
                print(f"[SECURITY] Неизвестный тип '{msg_type}' от {ip}")
                continue

            # ─── Register ────────────────────────────────────────────────────
            if msg_type == "register":
                name       = message.get("name", "")[:64]  # max 64 chars
                public_key = message.get("public_key")
                device_id  = message.get("device_id")

                try:
                    key_bytes = base64.b64decode(public_key)
                except Exception:
                    continue

                # The identity (fingerprint) must be derived from the same key that
                # was cryptographically proven in the challenge_response handshake —
                # otherwise a client could pass the handshake with a throwaway key it
                # owns, then register under someone else's (public) public key value
                # and hijack that fingerprint's connection slot. Federation peers are
                # exempt: they authenticate via a separate HMAC-based mechanism, not
                # per-user ECDSA proof-of-possession.
                if not is_fed and (verified_public_key is None or key_bytes != verified_public_key):
                    print(f"[SECURITY] register: public_key не совпадает с ключом handshake'а от {ip}")
                    continue

                fingerprint = hashlib.sha256(key_bytes).digest()[:8].hex().upper()
                username    = fingerprint

                is_new_fingerprint = not await db_is_fingerprint_registered(username)

                # Registration cap + proof-of-work — both keyed on "is this a
                # brand-new identity", never re-checked on reconnect. Neither
                # cares about IP: a cap counts real DB rows regardless of who
                # asked, and PoW cost is paid by the device doing the hashing,
                # not routed through any address the attacker chose.
                if is_new_fingerprint and MAX_REGISTERED_USERS > 0:
                    total = await db_count_registered_fingerprints()
                    if total >= MAX_REGISTERED_USERS:
                        print(f"[SECURITY] register: сервер заполнен ({total}/{MAX_REGISTERED_USERS}), отказ новому {username} от {ip}")
                        await send_safe(websocket, json.dumps({"type": "registration_full"}))
                        continue

                if is_new_fingerprint and POW_DIFFICULTY_BITS > 0:
                    pow_nonce = message.get("pow_nonce", "")
                    digest = hashlib.sha256(challenge + pow_nonce.encode("utf-8", "ignore")).digest()
                    if pow_leading_zero_bits(digest) < POW_DIFFICULTY_BITS:
                        print(f"[SECURITY] register: недостаточный PoW для нового аккаунта {username} от {ip}")
                        await send_safe(websocket, json.dumps({
                            "type": "pow_required",
                            "difficulty_bits": POW_DIFFICULTY_BITS
                        }))
                        continue

                # Optional access-code allowlist — see SERVER_ACCESS_PROTECTED.
                # Only for this fingerprint's very first-ever registration; a
                # client is free to keep sending a (by then already-consumed,
                # or simply absent) access_code on every later reconnect —
                # harmless, since it's not even looked at once the fingerprint
                # is already known.
                if SERVER_ACCESS_PROTECTED and is_new_fingerprint:
                    access_code = (message.get("access_code") or "").strip().upper()
                    if not access_code or not await db_check_and_consume_access_code(access_code, username):
                        print(f"[SECURITY] register: неверный/отсутствующий access_code для нового аккаунта {username} от {ip}")
                        await send_safe(websocket, json.dumps({"type": "access_code_required"}))
                        continue

                # Identity revoked via "Меня скомпрометировали" (revoke_identity,
                # below) — the challenge/response handshake still proves
                # possession of the private key, but possession alone is no
                # longer enough once the real owner has revoked it. Not
                # federation-exempt: revocation is meaningful precisely because
                # the fingerprint is derived from a key someone else may now
                # also hold.
                if await db_is_fingerprint_revoked(username):
                    print(f"[SECURITY] register: отклонена регистрация отозванного fingerprint {username} от {ip}")
                    await send_safe(websocket, json.dumps({"type": "identity_revoked"}))
                    continue

                totp_rejected = False
                async with lock:
                    existing = clients.get(username)
                    is_new_device = bool(
                        existing and device_id and existing.get("device_id")
                        and device_id != existing.get("device_id")
                    )

                    # Device-gated registration TOTP — only checked for a device_id
                    # the fingerprint hasn't registered with before (exactly the
                    # condition that would otherwise produce session_conflict). A
                    # reconnect from an already-known device_id never needs a code.
                    # See user_totp_secrets comment near the top of this file.
                    recovery_used = False
                    if is_new_device and username in user_totp_secrets:
                        totp_code = message.get("totp_code", "")
                        if not totp_verify_and_consume(username, totp_code):
                            # Lost-authenticator fallback — a valid, unused
                            # recovery code substitutes for the TOTP code. On
                            # success this revokes the secret and all other
                            # codes (see db_save_recovery_codes/totp_setup) —
                            # the account is left unprotected until the user
                            # deliberately re-enables TOTP from the now-
                            # trusted device, rather than leaving the old
                            # secret (which the user just proved they can't
                            # produce codes for) or other codes still valid.
                            recovery_code = message.get("recovery_code", "")
                            if recovery_code and await db_check_and_consume_recovery_code(username, recovery_code):
                                recovery_used = True
                            else:
                                totp_rejected = True

                    if recovery_used:
                        user_totp_secrets.pop(username, None)
                        user_totp_last_counter.pop(username, None)
                        asyncio.create_task(db_delete_totp(username))
                        asyncio.create_task(db_delete_recovery_codes(username))
                        print(f"[SECURITY] {username}: новое устройство зашло по recovery-коду — TOTP-защита сброшена, требует повторной настройки")

                    if not totp_rejected:
                        if existing:
                            if is_new_device:
                                # Другое устройство — вытесняем старую сессию
                                print(f"[SESSION_CONFLICT] {username}: новое устройство, закрываем старую сессию")
                                conflict_ts = time.time()
                                asyncio.create_task(send_safe(existing["ws"], json.dumps({"type": "session_conflict", "ts": conflict_ts})))
                                asyncio.create_task(existing["ws"].close())
                                # Old session may not be connected by the time this fires
                                # (backgrounded/killed app) — push a visible notification
                                # through FCM too, not just the WebSocket message.
                                existing_fcm_token = existing.get("fcm_token")
                                if existing_fcm_token:
                                    asyncio.create_task(send_fcm_session_conflict(existing_fcm_token, conflict_ts))
                            else:
                                print(f"[RECONNECT] {username} переподключился")
                                asyncio.create_task(existing["ws"].close())

                        clients[username] = {
                            "ws":         websocket,
                            "name":       name,
                            "public_key": public_key,
                            "device_id":  device_id
                        }
                        authenticated_users[websocket] = username

                if totp_rejected:
                    print(f"[SECURITY] register: неверный/отсутствующий TOTP-код для нового устройства {username} от {ip}")
                    await send_safe(websocket, json.dumps({"type": "totp_required"}))
                    continue

                if username in rate_limits:
                    rate_limits[username]["disconnected_at"] = 0
                else:
                    cleanup_stale_rate_limits()

                print(f"[OK] Зарегистрирован: {username}")
                asyncio.create_task(db_mark_fingerprint_registered(username))

                # ── Обмен аватарами ───────────────────────────────────────────
                incoming_avatar = message.get("avatar", "")
                if incoming_avatar and len(incoming_avatar) < 200_000:
                    user_avatars[username] = incoming_avatar
                    asyncio.create_task(db_save_avatar(username, incoming_avatar))
                    # Рассылаем наш аватар всем онлайн-пользователям
                    avatar_payload = json.dumps({
                        "type": "avatar_data",
                        "from": username,
                        "avatar": incoming_avatar
                    })
                    async with lock:
                        online_snapshot = dict(clients)
                    for uid, cinfo in online_snapshot.items():
                        if uid != username:
                            asyncio.create_task(send_safe(cinfo["ws"], avatar_payload))
                # Отправляем регистрирующемуся все известные аватары
                known_snapshot = dict(user_avatars)
                for uid, av in known_snapshot.items():
                    if uid != username and av:
                        await send_safe(websocket, json.dumps({
                            "type": "avatar_data",
                            "from": uid,
                            "avatar": av
                        }))

                # ── Deliver queued offline messages ───────────────────────────
                pending = await db_flush(username)
                for payload_str in pending:
                    await send_safe(websocket, payload_str)
                if pending:
                    print(f"[QUEUE] Доставлено {len(pending)} отложенных сообщений")

                # ── Deliver TURN credentials (from env vars — never hardcoded) ──
                turn_user = os.environ.get("TURN_USER", "")
                turn_pass = os.environ.get("TURN_PASS", "")
                if turn_user and turn_pass:
                    await send_safe(websocket, json.dumps({
                        "type": "turn_config",
                        "user": turn_user,
                        "pass": turn_pass
                    }))
                    print(f"[TURN] Учётные данные доставлены: {username}")

                # ── Send mesh peer list for client-side failover ──────────────
                # Only include peers that are currently connected (avoids stale dynamic IPs)
                active_peers = [u for u, ws in federation_ws.items() if ws is not None]
                if active_peers:
                    await send_safe(websocket, json.dumps({
                        "type":  "server_peers",
                        "peers": active_peers
                    }))
                    print(f"[FEDERATION] Список пиров отправлен → {username} ({len(active_peers)} пиров)")
                continue

            # ─── Register Bundle ──────────────────────────────────────────────
            if msg_type == "register_bundle":
                if not rate_limit_check(username, "register_bundle"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                bundle     = message.get("bundle")
                bundle_str = json.dumps(bundle) if bundle else ""
                if len(bundle_str) > MAX_BUNDLE_SIZE_BYTES:
                    print(f"[SECURITY] Слишком большой bundle (register_bundle) от {username}")
                    report_violation(username, "oversized bundle")
                    continue
                if bundle and username:
                    async with lock:
                        prekey_bundles[username] = bundle
                    asyncio.create_task(db_save_bundle(username, bundle))
                    print(f"[OK] Prekey bundle зарегистрирован: {username}")
                continue

            if not username:
                continue

            if check_banned(username):
                await websocket.send(json.dumps({"type": "error", "reason": "You are temporarily banned"}))
                continue

            # ─── Profile Update (аватар) ──────────────────────────────────────
            if msg_type == "profile_update":
                if not rate_limit_check(username, "profile_update"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                new_avatar = message.get("avatar", "")
                if new_avatar and len(new_avatar) < 200_000:
                    user_avatars[username] = new_avatar
                    asyncio.create_task(db_save_avatar(username, new_avatar))
                    broadcast_payload = json.dumps({
                        "type": "avatar_data",
                        "from": username,
                        "avatar": new_avatar
                    })
                    async with lock:
                        online_snapshot = dict(clients)
                    for uid, cinfo in online_snapshot.items():
                        if uid != username:
                            asyncio.create_task(send_safe(cinfo["ws"], broadcast_payload))
                    print(f"[AVATAR] Обновлён и разослан аватар: {username}")
                continue

            if msg_type == "read":
                to         = message.get("to")
                message_id = message.get("id")
                async with lock:
                    recipient = clients.get(to)
                read_payload = {"type": "read", "from": username, "id": message_id}
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(read_payload))
                elif FEDERATION_SECRET:
                    await forward_to_peers(to, read_payload)
                # read receipts are ephemeral — not queued for offline delivery
                continue

            # ─── Delivered Receipt ────────────────────────────────────────────
            if msg_type == "delivered":
                to         = message.get("to")
                message_id = message.get("id")
                async with lock:
                    sender_ws = clients.get(to, {}).get("ws")
                if sender_ws:
                    await send_safe(sender_ws, json.dumps({
                        "type": "delivered", "from": username, "id": message_id
                    }))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(
                        to, {"type": "delivered", "from": username, "id": message_id}
                    )
                    if not forwarded:
                        # Отправитель офлайн — ставим в очередь, доставим при реконнекте
                        await db_store(to, {"type": "delivered", "from": username, "id": message_id})
                continue

            # ─── Request Prekey ───────────────────────────────────────────────
            if msg_type == "request_prekey":
                if not rate_limit_check(username, "prekey_fetch"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue

                target = message.get("target")
                async with lock:
                    bundle = prekey_bundles.get(target)

                response = {
                    "type": "prekey_bundle_response",
                    "from": target,
                    "bundle": bundle
                }
                await websocket.send(json.dumps(response))
                print("[PREKEY] Bundle отправлен по запросу request_prekey")
                continue

            # ─── Publish Prekey Bundle ────────────────────────────────────────
            if msg_type == "publish_prekey_bundle":
                bundle     = message.get("bundle")
                bundle_str = json.dumps(bundle) if bundle else ""
                if len(bundle_str) > MAX_BUNDLE_SIZE_BYTES:
                    print(f"[SECURITY] Слишком большой bundle от {username}")
                    report_violation(username, "oversized bundle")
                    continue
                if bundle and isinstance(bundle, dict):
                    bundle_data = {"bundle": bundle, "updated_at": time.time()}
                    async with lock:
                        prekey_bundles[username] = bundle_data
                    asyncio.create_task(db_save_bundle(username, bundle_data))
                    print(f"[PREKEY] Bundle сохранён для {username}")
                continue

            # ─── Get Prekey Bundle ────────────────────────────────────────────
            if msg_type == "get_prekey_bundle":
                if not rate_limit_check(username, "prekey_fetch"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue

                target = message.get("target")
                opk_consumed = False
                async with lock:
                    bundle_data = prekey_bundles.get(target)
                    used_opk    = None
                    if bundle_data and isinstance(bundle_data, dict) and bundle_data.get("bundle", {}).get("opks"):
                        used_opk  = bundle_data["bundle"]["opks"].pop(0)
                        opk_consumed = True
                        remaining = len(bundle_data["bundle"]["opks"])
                        if remaining < OPK_LOW_WATERMARK:
                            target_ws = clients.get(target, {}).get("ws")
                            if target_ws:
                                asyncio.create_task(send_safe(
                                    target_ws,
                                    json.dumps({"type": "prekey_bundle_request"})
                                ))
                                print(f"[PREKEY] OPK на исходе у {target} (осталось {remaining})")
                # Persist updated OPK state so the consumed OPK is not reused after restart
                if opk_consumed and bundle_data:
                    asyncio.create_task(db_save_bundle(target, bundle_data))

                if bundle_data:
                    if isinstance(bundle_data, dict) and "bundle" in bundle_data:
                        bundle_to_send         = dict(bundle_data["bundle"])
                        bundle_to_send["opks"] = [used_opk] if used_opk else []
                    else:
                        bundle_to_send = bundle_data
                    # Attached fresh at serve time (not stored with the bundle,
                    # so it can never go stale between publishes) — lets the
                    # requester deliver session_init anonymously via anon_message
                    # instead of a directly-addressed packet. Omitted if target
                    # is offline or has no currently-registered tokens.
                    bootstrap_token = pick_bootstrap_token(target)
                    if bootstrap_token:
                        bundle_to_send["bootstrap_token"] = bootstrap_token
                    # Flags a bundle belonging to a fingerprint revoked via
                    # "Меня скомпрометировали"/Dead Man's Switch (see
                    # docs/ISSUE_backup_identity_hijack.md, Тир 5's "Пометка
                    # prekey bundle как revoked") — register() already
                    # refuses a revoked fingerprint outright, but a contact
                    # starting a *new* X3DH session against this bundle has
                    # no other way to learn the identity was revoked before
                    # trusting it.
                    if await db_is_fingerprint_revoked(target):
                        bundle_to_send["revoked"] = True
                    response = json.dumps({"type": "prekey_bundle_response", "from": target, "bundle": bundle_to_send})
                    await websocket.send(response)
                else:
                    # Try to fetch from a federation peer
                    fed_bundle = None
                    if FEDERATION_SECRET:
                        fed_bundle = await federated_get_bundle(target)
                    if fed_bundle:
                        response = json.dumps({"type": "prekey_bundle_response", "from": target, "bundle": fed_bundle})
                    else:
                        response = json.dumps({"type": "prekey_bundle_response", "from": target, "bundle": None})
                    await websocket.send(response)

                continue

            # ─── Get Prekey Bundles (batched, anonymous) ───────────────────────
            # Client fetches bundles for a real target PLUS decoy targets
            # (its own existing contacts, shuffled together) so the server
            # cannot tell which one it actually wants. Mirrors the anonymous
            # mailbox's fake-tag padding, but decoys here must be real
            # fingerprints (bundles are keyed by identity, unlike mailbox
            # tags). Never consumes an OPK — a decoy fetch must not burn a
            # stranger's one-time prekey; the resulting X3DH falls back to
            # the existing no-OPK path.
            if msg_type == "get_prekey_bundles_batch":
                if not rate_limit_check(username, "prekey_fetch"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue

                targets = message.get("targets")
                if not isinstance(targets, list) or not targets:
                    continue
                targets = [t for t in targets if isinstance(t, str)][:MAX_BATCH_BUNDLE_TARGETS]

                results = {}
                async with lock:
                    for t in targets:
                        bundle_data = prekey_bundles.get(t)
                        if not bundle_data:
                            results[t] = None
                            continue
                        if isinstance(bundle_data, dict) and "bundle" in bundle_data:
                            bundle_to_send = dict(bundle_data["bundle"])
                        else:
                            bundle_to_send = dict(bundle_data)
                        bundle_to_send["opks"] = []  # never consumed for batched/anonymous fetches
                        bootstrap_token = pick_bootstrap_token(t)
                        if bootstrap_token:
                            bundle_to_send["bootstrap_token"] = bootstrap_token
                        results[t] = bundle_to_send

                # Same revoked-flag as get_prekey_bundle, checked outside the
                # lock (same reasoning: SQLite lookups shouldn't serialize
                # behind the in-memory clients/prekey_bundles lock). Flagging
                # a decoy target's bundle here doesn't leak which target in
                # the batch is the real one — the server can't tell that
                # either way, decoy or not.
                fetched_targets = [t for t in targets if results.get(t) is not None]
                revoked_flags = await asyncio.gather(*(db_is_fingerprint_revoked(t) for t in fetched_targets))
                for t, is_revoked in zip(fetched_targets, revoked_flags):
                    if is_revoked:
                        results[t]["revoked"] = True

                await websocket.send(json.dumps({
                    "type": "prekey_bundles_batch_response",
                    "bundles": results
                }))
                print(f"[PREKEY] Batch bundle-fetch обслужен ({len(targets)} целей)")
                continue

            # ─── Get Public Key (legacy) ──────────────────────────────────────
            if msg_type == "get_key":
                target = message.get("target")
                async with lock:
                    target_data = clients.get(target)
                await websocket.send(json.dumps({
                    "type":     "public_key",
                    "username": target,
                    "key":      target_data["public_key"] if target_data else None
                }))
                # Также отправляем аватар цели, если он есть в хранилище
                target_avatar = user_avatars.get(target)
                if target_avatar:
                    await websocket.send(json.dumps({
                        "type":   "avatar_data",
                        "from":   target,
                        "avatar": target_avatar
                    }))
                continue

            # ─── Ping ─────────────────────────────────────────────────────────
            if msg_type == "ping":
                await websocket.send(json.dumps({"type": "pong"}))
                continue

            # ─── Typing ───────────────────────────────────────────────────────
            if msg_type == "typing":
                if not rate_limit_check(username, "typing"):
                    continue
                to = message.get("to")
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps({"type": "typing", "from": username}))
                elif FEDERATION_SECRET:
                    await forward_to_peers(to, {"type": "typing", "from": username})
                # typing is ephemeral — not queued for offline delivery
                continue

            # ─── Session reset ────────────────────────────────────────────────
            if msg_type == "session_reset":
                to = message.get("to")
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps({"type": "session_reset", "from": username}))
                # ephemeral — not queued for offline delivery
                continue

            # ─── Identity revocation ("Меня скомпрометировали") ────────────────
            # `username` here is this connection's own fingerprint, proven by the
            # challenge/response handshake at connect time — not client-supplied,
            # so there's no way to revoke anyone else's identity through this.
            # Fired by the client right before it locally wipes the old key (see
            # BackupManager.resetCompromisedIdentity() / ProfileScreen.kt's
            # "Меня скомпрометировали"), so the old key stops being sufficient to
            # log back in even if whoever compromised it still has it.
            if msg_type == "revoke_identity":
                await db_revoke_fingerprint(username)
                print(f"[SECURITY] Identity отозвана по запросу владельца: {username}")
                await send_safe(websocket, json.dumps({"type": "identity_revoked_ack"}))
                await websocket.close()
                return

            # ─── Edit ─────────────────────────────────────────────────────────
            if msg_type == "edit":
                to = message.get("to")
                async with lock:
                    recipient = clients.get(to)
                edit_payload = {
                    "type": "edit", "from": username,
                    "id": message.get("id"), "text": message.get("text"),
                    "signature": message.get("signature")
                }
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(edit_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, edit_payload)
                    if not forwarded:
                        await db_store(to, edit_payload)
                continue

            # ─── Session Init ─────────────────────────────────────────────────
            if msg_type == "session_init":
                if not rate_limit_check(username, "message"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                to     = message.get("to")
                msg_id = message.get("id")
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps({
                        "type": "session_init", "from": username,
                        "sender_ik": message.get("sender_ik"),
                        "x3dh_header": message.get("x3dh_header"),
                        "session_header": message.get("session_header"),
                        "text": message.get("text"),
                        "signature": message.get("signature"),
                        "id": msg_id, "protocol_version": 2
                    }))
                    await websocket.send(json.dumps({"type": "ack", "id": msg_id}))
                    print("[MSG] session_init delivered")
                else:
                    fwd = {
                        "type": "session_init", "from": username,
                        "sender_ik": message.get("sender_ik"),
                        "x3dh_header": message.get("x3dh_header"),
                        "session_header": message.get("session_header"),
                        "text": message.get("text"),
                        "signature": message.get("signature"),
                        "id": msg_id, "protocol_version": 2
                    }
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, fwd)
                    if not forwarded:
                        await db_store(to, fwd, msg_id)
                        print("[MSG] session_init queued (offline)")
                    else:
                        print("[MSG] session_init forwarded via federation")
                    # Разбудить приложение получателя через FCM
                    asyncio.create_task(send_fcm_wakeup(to))
                    await websocket.send(json.dumps({"type": "ack", "id": msg_id}))
                continue

            # ─── Message ──────────────────────────────────────────────────────
            if msg_type == "message":
                if not rate_limit_check(username, "message"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                to     = message.get("to")
                msg_id = message.get("id")
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    payload = {"type": "message", "from": username,
                               "text": message.get("text"), "signature": message.get("signature"),
                               "id": msg_id, "protocol_version": message.get("protocol_version", 2)}
                    if "session_header" in message:
                        payload["session_header"] = message["session_header"]
                    await send_safe(recipient["ws"], json.dumps(payload))
                    await websocket.send(json.dumps({"type": "ack", "id": msg_id}))
                    print("[MSG] message delivered")
                else:
                    fwd_payload = {"type": "message", "from": username,
                                   "text": message.get("text"), "signature": message.get("signature"),
                                   "id": msg_id, "protocol_version": message.get("protocol_version", 2)}
                    if "session_header" in message:
                        fwd_payload["session_header"] = message["session_header"]
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, fwd_payload)
                    if not forwarded:
                        await db_store(to, fwd_payload, msg_id)
                        print("[MSG] message queued (offline)")
                    else:
                        print("[MSG] message forwarded via federation")
                    # Разбудить приложение получателя через FCM
                    asyncio.create_task(send_fcm_wakeup(to))
                    await websocket.send(json.dumps({"type": "ack", "id": msg_id}))
                continue

            # ─── Reaction ────────────────────────────────────────────────────
            if msg_type == "reaction":
                if not rate_limit_check(username, "reaction"):
                    continue
                to = message.get("to")
                async with lock:
                    recipient = clients.get(to)
                reaction_payload = {
                    "type": "reaction", "from": username,
                    "message_id": message.get("message_id"),
                    "emoji": message.get("emoji"), "signature": message.get("signature")
                }
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(reaction_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, reaction_payload)
                    if not forwarded:
                        await db_store(to, reaction_payload)
                continue
            # ─── Group Reaction ───────────────────────────────────────────────
            if msg_type == "group_reaction":
                if not rate_limit_check(username, "reaction"):
                    continue
                to = message.get("to")
                async with lock:
                    recipient = clients.get(to)
                gr_payload = {
                    "type":       "group_reaction",
                    "from":       username,
                    "group_id":   message.get("group_id"),
                    "message_id": message.get("message_id"),
                    "emoji":      message.get("emoji"),
                    "signature":  message.get("signature")
                }
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(gr_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, gr_payload)
                    if not forwarded:
                        await db_store(to, gr_payload)
                continue


            # ─── Voice ───────────────────────────────────────────────────────
            if msg_type == "voice":
                to = message.get("to")
                async with lock:
                    recipient = clients.get(to)
                voice_payload = {
                    "type": "voice", "from": username,
                    "voice_id": message.get("voice_id"),
                    "voice_data": message.get("voice_data"),
                    "signature": message.get("signature"),
                    "duration": message.get("duration")
                }
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(voice_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, voice_payload)
                    if not forwarded:
                        await db_store(to, voice_payload)
                continue

            # ─── Image Chunk ──────────────────────────────────────────────────
            if msg_type == "image_chunk":
                to      = message.get("to")
                msg_id  = message.get("image_id")
                chunk_i = message.get("chunk_index")
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    ok = await send_safe(recipient["ws"], json.dumps({
                        "type": "image_chunk", "from": username,
                        "image_id": msg_id, "chunk_index": chunk_i,
                        "total_chunks": message.get("total_chunks"),
                        "data": message.get("data"), "signature": message.get("signature"),
                        "encrypted": message.get("encrypted", False)   # BUG FIX: обязательно пересылаем флаг
                    }))
                    if ok:
                        await websocket.send(json.dumps({"type": "chunk_ack", "image_id": msg_id, "chunk_index": chunk_i}))
                    else:
                        await websocket.send(json.dumps({"type": "status", "id": msg_id, "status": "offline", "chunk": chunk_i}))
                else:
                    await websocket.send(json.dumps({"type": "status", "id": msg_id, "status": "offline", "chunk": chunk_i}))
                continue

            # ─── Video Circle Chunk ──────────────────────────────────────────
            if msg_type == "video_chunk":
                to      = message.get("to")
                msg_id  = message.get("video_id")
                chunk_i = message.get("chunk_index")
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    ok = await send_safe(recipient["ws"], json.dumps({
                        "type": "video_chunk", "from": username,
                        "video_id": msg_id, "chunk_index": chunk_i,
                        "total_chunks": message.get("total_chunks"),
                        "data": message.get("data"), "signature": message.get("signature"),
                        "duration": message.get("duration", 0),
                        "encrypted": message.get("encrypted", True)
                    }))
                    if ok:
                        # Используем video_id (не image_id!) чтобы клиент мог матчить ACK
                        await websocket.send(json.dumps({"type": "chunk_ack", "video_id": msg_id, "chunk_index": chunk_i}))
                    else:
                        await websocket.send(json.dumps({"type": "status", "id": msg_id, "status": "offline", "chunk": chunk_i}))
                else:
                    await websocket.send(json.dumps({"type": "status", "id": msg_id, "status": "offline", "chunk": chunk_i}))
                continue

            # ─── File Chunk ───────────────────────────────────────────────────
            if msg_type == "file_chunk":
                to      = message.get("to")
                file_id = message.get("file_id")
                chunk_i = message.get("chunk_index")
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    ok = await send_safe(recipient["ws"], json.dumps({
                        "type": "file_chunk", "from": username,
                        "file_id": file_id, "file_name": message.get("file_name"),
                        "chunk_index": chunk_i, "total_chunks": message.get("total_chunks"),
                        "data": message.get("data"), "signature": message.get("signature")
                    }))
                    if ok:
                        await websocket.send(json.dumps({"type": "chunk_ack", "file_id": file_id, "chunk_index": chunk_i}))
                    else:
                        await websocket.send(json.dumps({"type": "status", "id": file_id, "status": "offline", "chunk": chunk_i}))
                else:
                    await websocket.send(json.dumps({"type": "status", "id": file_id, "status": "offline", "chunk": chunk_i}))
                continue

            # ─── Group Create ─────────────────────────────────────────────────
            if msg_type == "group_create":
                to            = message.get("to")
                group_id      = message.get("group_id")
                group_name    = message.get("group_name")
                group_avatar  = message.get("group_avatar")
                encrypted_key = message.get("encrypted_group_key")
                signature     = message.get("signature")
                gc_payload = {
                    "type": "group_create", "from": username,
                    "group_id": group_id, "group_name": group_name,
                    "group_avatar": group_avatar,
                    "encrypted_group_key": encrypted_key, "signature": signature
                }
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(gc_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, gc_payload)
                    if not forwarded:
                        await db_store(to, gc_payload)
                continue

            # ─── Group Message ────────────────────────────────────────────────
            if msg_type == "group_message":
                if not rate_limit_check(username, "message"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                to          = message.get("to")
                gm_payload  = {
                    "type": "group_message", "from": username,
                    "group_id":    message.get("group_id"),
                    "message_id":  message.get("message_id"),
                    "sender_name": message.get("sender_name"),
                    "text":        message.get("text"),
                    "signature":   message.get("signature")
                }
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(gm_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, gm_payload)
                    if not forwarded:
                        await db_store(to, gm_payload, gm_payload.get("message_id"))
                continue

            # ─── Group Member Removed ─────────────────────────────────────────
            if msg_type == "group_member_removed":
                to  = message.get("to")
                gmr_payload = {
                    "type": "group_member_removed", "from": username,
                    "group_id":       message.get("group_id"),
                    "removed_member": message.get("removed_member")
                }
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(gmr_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, gmr_payload)
                    if not forwarded:
                        await db_store(to, gmr_payload)
                continue

            # ─── Group Key Rotation ───────────────────────────────────────────
            if msg_type == "group_key_rotation":
                to  = message.get("to")
                gkr_payload = {
                    "type": "group_key_rotation", "from": username,
                    "group_id":         message.get("group_id"),
                    "encrypted_new_key": message.get("encrypted_new_key"),
                    "signature":        message.get("signature")
                }
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(gkr_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, gkr_payload)
                    if not forwarded:
                        await db_store(to, gkr_payload)
                continue

            # ─── Group Invite Accepted ────────────────────────────────────────
            if msg_type == "group_invite_accepted":
                to  = message.get("to")
                gia_payload = {
                    "type": "group_invite_accepted", "from": username,
                    "group_id":       message.get("group_id"),
                    "new_member":     message.get("new_member"),
                    "new_member_name": message.get("new_member_name")
                }
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(gia_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, gia_payload)
                    if not forwarded:
                        await db_store(to, gia_payload)
                continue

            # ─── Create Channel ───────────────────────────────────────────────
            if msg_type == "channel_create":
                if not rate_limit_check(username, "channel_create"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                channel_name  = message.get("channel_name", "").strip()
                channel_desc  = message.get("channel_description", "").strip()
                channel_avatar = message.get("channel_avatar", "📢")

                if not channel_name:
                    await websocket.send(json.dumps({"type": "error", "reason": "Название канала не может быть пустым"}))
                    continue
                if len(channel_name) > 100:
                    await websocket.send(json.dumps({"type": "error", "reason": "Слишком длинное название канала"}))
                    continue

                async with lock:
                    channel_id = secrets.token_urlsafe(16)
                    channels[channel_id] = {
                        "name": channel_name,
                        "avatar": channel_avatar,
                        "description": channel_desc,
                        "admin": username,
                        "admin_name": clients.get(username, {}).get("name", username),
                        "subscribers": {username},
                        "created_at": time.time(),
                        "posts": []
                    }

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _db_save_channel_sync, channel_id, channels[channel_id])
                await loop.run_in_executor(None, _db_save_subscriber_sync, channel_id, username)

                await websocket.send(json.dumps({
                    "type": "channel_created",
                    "channel_id": channel_id,
                    "channel_name": channel_name,
                    "channel_avatar": channel_avatar,
                    "channel_description": channel_desc,
                }))
                print(f"[CHANNEL] Created: {channel_name} ({channel_id}) by {username}")
                continue

            # ─── Subscribe to Channel ─────────────────────────────────────────
            if msg_type == "channel_subscribe":
                channel_id = message.get("channel_id", "")
                async with lock:
                    ch = channels.get(channel_id)
                    if not ch:
                        await websocket.send(json.dumps({"type": "error", "reason": "Канал не найден"}))
                        continue
                    ch["subscribers"].add(username)

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _db_save_subscriber_sync, channel_id, username)

                # Send channel info and recent posts (up to 50)
                async with lock:
                    ch = channels.get(channel_id, {})
                    recent_posts = ch.get("posts", [])[-50:]

                await websocket.send(json.dumps({
                    "type": "channel_info",
                    "channel_id": channel_id,
                    "channel_name": ch.get("name", ""),
                    "channel_avatar": ch.get("avatar", "📢"),
                    "channel_description": ch.get("description", ""),
                    "is_admin": ch.get("admin") == username,
                    "posts": recent_posts
                }))
                print(f"[CHANNEL] {username} subscribed to {channel_id}")
                continue

            # ─── Unsubscribe from Channel ─────────────────────────────────────
            if msg_type == "channel_unsubscribe":
                channel_id = message.get("channel_id", "")
                async with lock:
                    ch = channels.get(channel_id)
                    if ch:
                        ch["subscribers"].discard(username)
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _db_remove_subscriber_sync, channel_id, username)
                continue

            # ─── Channel Post (admin only) ────────────────────────────────────
            if msg_type == "channel_post":
                channel_id = message.get("channel_id", "")
                text       = message.get("text", "").strip()
                image_data = message.get("image_data", "")
                post_id    = message.get("id", secrets.token_urlsafe(16))
                timestamp  = int(time.time() * 1000)  # всегда серверное время

                # Validate image size (max 5MB base64)
                if len(image_data) > 5 * 1024 * 1024:
                    await websocket.send(json.dumps({"type": "error", "reason": "Изображение слишком большое (макс 5 МБ)"}))
                    continue

                async with lock:
                    ch = channels.get(channel_id)
                    if not ch:
                        await websocket.send(json.dumps({"type": "error", "reason": "Канал не найден"}))
                        continue
                    if ch["admin"] != username:
                        await websocket.send(json.dumps({"type": "error", "reason": "Только администратор может публиковать"}))
                        continue
                    if not text and not image_data:
                        continue
                    # Store post
                    post = {
                        "post_id": post_id,
                        "text": text,
                        "timestamp": timestamp,
                        "author_id": username,
                        "author_name": clients.get(username, {}).get("name", username),
                        "image_data": image_data
                    }
                    ch["posts"].append(post)
                    # Keep only last 200 posts in memory
                    if len(ch["posts"]) > 200:
                        ch["posts"] = ch["posts"][-200:]
                    subscribers = set(ch["subscribers"])

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _db_save_post_sync, channel_id, post)

                # Broadcast to all online subscribers
                payload = json.dumps({
                    "type": "channel_update",
                    "channel_id": channel_id,
                    "post_id": post_id,
                    "text": text,
                    "timestamp": timestamp,
                    "author_id": post["author_id"],
                    "author_name": post["author_name"],
                    "image_data": image_data
                })
                async with lock:
                    recipient_wss = [
                        clients[sub]["ws"]
                        for sub in subscribers
                        if sub in clients and sub != username  # don't echo to sender
                    ]
                for ws in recipient_wss:
                    asyncio.create_task(send_safe(ws, payload))

                print(f"[CHANNEL] Post delivered to {len(recipient_wss)} subscriber(s){' [+image]' if image_data else ''}")
                continue

            # ─── Get Channel Info ─────────────────────────────────────────────
            if msg_type == "channel_get_info":
                channel_id = message.get("channel_id", "")
                async with lock:
                    ch = channels.get(channel_id)
                if not ch:
                    await websocket.send(json.dumps({"type": "error", "reason": "Канал не найден"}))
                    continue
                await websocket.send(json.dumps({
                    "type": "channel_info",
                    "channel_id": channel_id,
                    "channel_name": ch["name"],
                    "channel_avatar": ch.get("avatar", "📢"),
                    "channel_description": ch.get("description", ""),
                    "is_admin": ch["admin"] == username,
                }))
                continue

            # ─── Call Signaling Relay ──────────────────────────────────────────
            # All call messages are relayed as-is to the target recipient.
            # The server never decrypts or stores call data (DTLS-SRTP is E2E).
            CALL_RELAY_TYPES = {
                "call_offer", "call_answer", "call_ice",
                "call_end", "call_ringing",
                "call_group_invite", "call_group_join",
                "call_group_answer", "call_group_ice", "call_group_leave",
                "call_group_peer_list", "call_ice_restart",
                # Two-phase call flow: usually anon-routed (opaque inside anon_message,
                # never reaches this block), but sendAnonOrDirect() falls back to sending
                # these directly when no anon token is available yet — same relay/offline-
                # queue/FCM-wake treatment as the rest of call signaling in that case.
                "call_request_audio", "call_request_video", "call_response",
            }
            if msg_type in CALL_RELAY_TYPES:
                if not rate_limit_check(username, msg_type):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                target = message.get("to", "")
                if not target:
                    continue
                message["from"] = username  # always set from server-side
                # Трекинг активных звонков для auto call_end при дисконнекте
                if msg_type == "call_offer":
                    # Трекаем звонящего уже на этапе вызова (до ответа).
                    # Без этого: если A отвалится до того, как B ответит,
                    # сервер не знает о звонке и B продолжает бесконечно звонить.
                    call_id = message.get("call_id", "")
                    async with lock:
                        active_calls[username] = {"peer": target, "call_id": call_id}
                elif msg_type == "call_answer":
                    call_id = message.get("call_id", "")
                    async with lock:
                        active_calls[username] = {"peer": target, "call_id": call_id}
                        active_calls[target]   = {"peer": username, "call_id": call_id}
                elif msg_type in ("call_end", "call_group_leave"):
                    async with lock:
                        active_calls.pop(username, None)
                        active_calls.pop(target, None)
                async with lock:
                    target_ws = clients.get(target, {}).get("ws")
                if target_ws:
                    asyncio.create_task(send_safe(target_ws, json.dumps(message)))
                    print(f"[CALL] {msg_type} relayed")
                else:
                    if msg_type == "call_offer":
                        # Получатель оффлайн — сохраняем пропущенный звонок и будим через FCM
                        missed = {
                            "type": "missed_call",
                            "from": username,
                            "is_video": message.get("is_video", False),
                            "timestamp": int(time.time() * 1000)
                        }
                        await db_store(target, missed)
                        asyncio.create_task(send_fcm_wakeup(target))
                        print("[CALL] missed call stored (recipient offline)")
                    else:
                        print(f"[CALL] {msg_type} dropped (recipient offline)")
                continue

            # ─── Chat features relay ───────────────────────────────────────────
            # message_delete и disappear_timer — простой relay по полю "to"
            if msg_type in {"message_delete", "disappear_timer"}:
                target = message.get("to", "")
                if not target:
                    continue
                message["from"] = username
                async with lock:
                    target_ws = clients.get(target, {}).get("ws")
                if target_ws:
                    asyncio.create_task(send_safe(target_ws, json.dumps(message)))
                else:
                    # BUG FIX: сохраняем в offline queue, иначе команда теряется
                    forwarded = FEDERATION_SECRET and await forward_to_peers(target, message)
                    if not forwarded:
                        await db_store(target, message)
                    asyncio.create_task(send_fcm_wakeup(target))
                continue

            # group_message_delete — relay каждому адресату по полю "to"
            if msg_type == "group_message_delete":
                target = message.get("to", "")
                if not target:
                    continue
                message["from"] = username
                async with lock:
                    target_ws = clients.get(target, {}).get("ws")
                if target_ws:
                    asyncio.create_task(send_safe(target_ws, json.dumps(message)))
                else:
                    # BUG FIX: сохраняем в offline queue
                    forwarded = FEDERATION_SECRET and await forward_to_peers(target, message)
                    if not forwarded:
                        await db_store(target, message)
                    asyncio.create_task(send_fcm_wakeup(target))
                continue

            # ─── Anonymous Token Routing ──────────────────────────────────────
            if msg_type == "subscribe_tokens":
                if not rate_limit_check(username, "subscribe_tokens"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                raw_tokens = message.get("tokens", [])
                if isinstance(raw_tokens, list):
                    valid = [t for t in raw_tokens
                             if isinstance(t, str) and len(t) == MAX_TOKEN_LEN][:MAX_TOKENS_PER_SUBSCRIBE]
                    async with lock:
                        existing = ws_to_tokens.get(websocket, set())
                        for t in valid:
                            token_to_ws[t] = websocket
                            known_tokens.add(t)
                            existing.add(t)
                            # Same "stays queued until anon_delivery_ack"
                            # discipline as the anon_message handler — see
                            # docs/ISSUE_backup_identity_hijack.md,
                            # 2026-08-17. This used to pop the fallback copy
                            # unconditionally and fire a fire-and-forget
                            # send with the result never checked — if that
                            # redelivery attempt also failed (or the client
                            # failed to actually process it), the message
                            # was gone with zero trace anywhere, since
                            # nothing ever put it back. Confirmed live: a
                            # message queued as "офлайн" got silently lost
                            # exactly this way on the recipient's next
                            # reconnect. Left in token_pending here — only
                            # the anon_delivery_ack handler clears it now.
                            pending = token_pending.get(t, [])
                            for p in pending:
                                asyncio.create_task(send_safe(websocket, json.dumps(p)))
                        ws_to_tokens[websocket] = existing
                    print(f"[ANON] {username} подписан на {len(valid)} токенов")
                continue

            if msg_type == "anon_message":
                if not rate_limit_check(username, "anon_message"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                token   = message.get("token", "")
                payload = message.get("payload", {})
                msg_id  = payload.get("id", "") if isinstance(payload, dict) else ""
                if not token or not isinstance(payload, dict) or len(token) != MAX_TOKEN_LEN:
                    continue
                async with lock:
                    is_known = token in known_tokens
                if not is_known:
                    # Фейковый/cover-traffic токен — дропаем без очереди и без лога
                    if msg_id:
                        await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                    continue
                delivery = json.dumps({"type": "anon_delivery", "token": token, "payload": payload})

                # Queued as a fallback BEFORE attempting live delivery, and
                # only cleared once the recipient explicitly acks it
                # (anon_delivery_ack, above) — send_safe() succeeding below
                # only means the write to the socket didn't raise, not that
                # the recipient's app actually processed the frame. Without
                # this, a connection dying in that exact race window
                # silently lost the message with zero trace, no retry
                # anywhere. Single-use tokens mean at most one entry is ever
                # queued here per token, so a plain overwrite (not append)
                # is correct. subscribe_tokens's existing flush-on-resubscribe
                # logic is what actually redelivers this if the live attempt
                # below never gets acked — no new retry mechanism needed.
                async with lock:
                    token_pending[token] = [{"type": "anon_delivery", "token": token, "payload": payload}]
                    token_pending_created[token] = time.time()
                    target_ws = token_to_ws.get(token)
                if target_ws:
                    ok = await send_safe(target_ws, delivery)
                    if ok:
                        print(f"[ANON] Отправлено по токену …{token[-6:]} (ждём anon_delivery_ack)")
                    # else: получатель закрыл сокет между проверкой и отправкой — уже в очереди выше
                else:
                    # Токен не зарегистрирован локально — пробуем федерацию по fingerprint из payload
                    fed_to = payload.get("to") if isinstance(payload, dict) else None
                    if fed_to and FEDERATION_SECRET:
                        forwarded = await forward_to_peers(fed_to, payload)
                        if forwarded:
                            print(f"[ANON→FED] Токен …{token[-6:]} не найден локально, переслано по fingerprint → {fed_to}")
                            # Federation path doesn't ack back through this
                            # server, so the local pending-fallback would
                            # never get cleared — drop it rather than
                            # redeliver forever on every future resubscribe.
                            async with lock:
                                token_pending.pop(token, None)
                                token_pending_created.pop(token, None)
                        else:
                            print(f"[ANON] Токен …{token[-6:]} офлайн, сообщение в очереди")
                    else:
                        print(f"[ANON] Токен …{token[-6:]} офлайн, сообщение в очереди")
                if msg_id:
                    await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                continue

            # ─── Anonymous Mailbox ────────────────────────────────────────────
            if msg_type == "mailbox_put":
                if not rate_limit_check(username, "mailbox_put"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                tag  = message.get("tag", "")
                blob = message.get("blob", "")
                if (not tag or not blob
                        or len(tag) != MAILBOX_TAG_LEN
                        or not all(c in "0123456789abcdef" for c in tag)
                        or not isinstance(blob, str)
                        or len(blob) > MAILBOX_MAX_BLOB):
                    continue
                now = time.time()
                async with lock:
                    # Чистим устаревшие блобы в этом слоте
                    existing = [e for e in mailbox.get(tag, []) if now - e["ts"] < MAILBOX_TTL]
                    if len(existing) >= 5:  # max 5 блобов на тег — защита от DoS
                        continue
                    existing.append({"blob": blob, "ts": now})
                    mailbox[tag] = existing
                continue

            if msg_type == "mailbox_fetch":
                raw_tags = message.get("tags", [])
                if not isinstance(raw_tags, list):
                    continue
                tags = [t for t in raw_tags
                        if isinstance(t, str)
                        and len(t) == MAILBOX_TAG_LEN
                        and all(c in "0123456789abcdef" for c in t)][:MAILBOX_MAX_FETCH]
                now = time.time()
                result = {}
                async with lock:
                    for tag in tags:
                        blobs = [e for e in mailbox.get(tag, []) if now - e["ts"] < MAILBOX_TTL]
                        if blobs:
                            result[tag] = [e["blob"] for e in blobs]
                            # Удаляем доставленные
                            del mailbox[tag]
                if result:
                    await send_safe(websocket, json.dumps({"type": "mailbox_result", "blobs": result}))
                continue

            # register_fcm — сохраняем FCM-токен пользователя
            if msg_type == "register_fcm":
                token = message.get("fcm_token", "")
                if token:
                    async with lock:
                        if username in clients:
                            clients[username]["fcm_token"] = token
                    print(f"[FCM] Токен сохранён для {username}")
                continue

            # ─── Device-gated registration TOTP: one-time setup ─────────────────
            # Refused outright if this account already has a secret — an account
            # with a working TOTP secret can never have it silently replaced by
            # someone who only holds the private key (e.g. a stolen backup).
            if msg_type == "totp_setup":
                if not username:
                    continue
                if username in user_totp_secrets:
                    await send_safe(websocket, json.dumps({"type": "totp_setup_failed", "reason": "already_enabled"}))
                    continue
                secret = message.get("secret", "")
                code   = message.get("code", "")
                if not secret or totp_code_matches(secret, code) is None:
                    await send_safe(websocket, json.dumps({"type": "totp_setup_failed", "reason": "invalid_code"}))
                    continue
                user_totp_secrets[username] = secret
                asyncio.create_task(db_save_totp(username, secret))
                # Recovery codes are the safety net for "lost the authenticator" --
                # generated once here, shown to the user exactly once by the
                # client, never retrievable again (only hashes are stored).
                recovery_codes = generate_recovery_codes()
                asyncio.create_task(db_save_recovery_codes(username, recovery_codes))
                print(f"[TOTP] Device-gated registration protection enabled for {username}")
                await send_safe(websocket, json.dumps({
                    "type": "totp_setup_ok",
                    "recovery_codes": recovery_codes
                }))
                continue

            # ─── Device-gated registration TOTP: disable ────────────────────────
            # Requires a valid current code — proof of the secret, not just the
            # private key — so a stolen backup+password alone can't turn this
            # protection off either.
            if msg_type == "totp_disable":
                if not username or username not in user_totp_secrets:
                    continue
                code = message.get("code", "")
                if not totp_verify_and_consume(username, code):
                    await send_safe(websocket, json.dumps({"type": "totp_disable_failed"}))
                    continue
                del user_totp_secrets[username]
                user_totp_last_counter.pop(username, None)
                asyncio.create_task(db_delete_totp(username))
                asyncio.create_task(db_delete_recovery_codes(username))
                print(f"[TOTP] Device-gated registration protection disabled for {username}")
                await send_safe(websocket, json.dumps({"type": "totp_disable_ok"}))
                continue

            # ─── Anonymous delivery confirmation ───────────────────────────────
            # Real end-to-end delivery confirmation — see the anon_message
            # handler above: send_safe() succeeding only means the write to
            # the socket didn't raise, not that the recipient's app actually
            # processed the frame. A connection dying in that exact race
            # window used to silently lose the message with zero trace, no
            # retry anywhere. Found live 2026-08-17 — confirmed as a
            # genuinely frequent case (unstable mobile connections), not a
            # rare edge case. See docs/ISSUE_backup_identity_hijack.md.
            if msg_type == "anon_delivery_ack":
                token = message.get("token", "")
                if token and len(token) == MAX_TOKEN_LEN:
                    async with lock:
                        token_pending.pop(token, None)
                        token_pending_created.pop(token, None)
                        target_ws_final = token_to_ws.pop(token, None)
                        if target_ws_final:
                            ws_to_tokens.get(target_ws_final, set()).discard(token)
                    print(f"[ANON] Подтверждена доставка токена …{token[-6:]}")
                continue

            # ─── Client-side diagnostic "ticket" ─────────────────────────────────
            # Fired by the client once, after 5 minutes of a stuck first-contact
            # mailbox bootstrap (docs/ISSUE_backup_identity_hijack.md, "5-минутный
            # ретрай"). Deliberately carries no target/contact info — just a
            # clearly-tagged log line for the operator to find via
            # ForEXP/admin_logs.py while investigating, not an automated report
            # to anyone.
            if msg_type == "bootstrap_diagnostic":
                if not username or not rate_limit_check(username, "bootstrap_diagnostic"):
                    continue
                print(f"[TICKET] {username}: mailbox-бутстрап первого контакта завис дольше 5 минут")
                continue

        if is_fed:
            await handle_federation_peer_incoming(websocket, ip)

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        if username:
            # Anon-token cleanup happens once, further down (the
            # ownership-checked block right before rate_limits cleanup) — a
            # duplicate, unguarded copy of this exact loop used to live here
            # too and ran FIRST, popping ws_to_tokens[websocket] before the
            # real (guarded) block below ever got to see it — so the guard
            # never actually ran against real data. Root-caused live
            # 2026-08-17 (second round) — see docs/ISSUE_backup_identity_hijack.md.

            # Auto call_end: если пользователь отвалился во время звонка — уведомляем собеседника
            call_info = None
            async with lock:
                call_info = active_calls.pop(username, None)
            if call_info:
                peer = call_info.get("peer", "")
                call_id = call_info.get("call_id", "")
                async with lock:
                    active_calls.pop(peer, None)
                    peer_ws = clients.get(peer, {}).get("ws")
                if peer_ws:
                    try:
                        await send_safe(peer_ws, json.dumps({
                            "type": "call_end",
                            "from": username,
                            "to": peer,
                            "call_id": call_id,
                            "reason": "disconnected"
                        }))
                        print(f"[CALL] auto call_end: {username} отключился, уведомлён {peer}")
                    except Exception:
                        pass
            async with lock:
                if clients.get(username, {}).get("ws") == websocket:
                    clients.pop(username, None)
                authenticated_users.pop(websocket, None)
                # Only the dead socket's routing entry is cleared here — there
                # is genuinely nowhere left to deliver to. known_tokens and
                # token_pending are deliberately left alone: this used to
                # wipe them too ("чтобы очередь не растёт вечно"), but that
                # tied a token's very existence to a single continuous
                # WebSocket session, so ANY disconnect — even a benign few-
                # second reconnect — instantly turned every token this owner
                # had handed out into an unknown/fake-looking token. A
                # contact still holding one of those tokens got a silently
                # dropped anon_message and a *faked* "ack" back (see the
                # anon_message handler's is_known branch — that fake ack is
                # intentional, to keep real vs. decoy tokens
                # indistinguishable from the sender's point of view), which
                # looks exactly like "sent successfully" while nothing was
                # ever delivered. token_pending is already self-bounded (10
                # queued messages per token, see anon_message handler) so
                # there's no unbounded-growth risk from leaving it populated
                # across a reconnect; known_tokens re-links to the new
                # websocket for free the moment the owner resubscribes
                # (subscribe_tokens already flushes token_pending on
                # (re)subscribe). Root-caused live 2026-08-13 — see
                # docs/ISSUE_backup_identity_hijack.md.
                #
                # The per-token pop below must check ownership first. A client
                # always resubscribes the same persistent ~50-token set on every
                # reconnect. If the OLD connection is a zombie (TCP half-open,
                # only detected dead once ping_timeout=30s elapses) and the
                # client already reconnected and re-subscribed on a NEW
                # websocket in that window, token_to_ws[t] now correctly points
                # at the new connection — but this cleanup running late for the
                # old one would blow that fresh mapping away, making every one
                # of those tokens report "офлайн" for up to ping_timeout
                # seconds after a perfectly healthy reconnect. Root-caused live
                # 2026-08-17 (server log showed tokens just subscribed on a new
                # connection reported offline 18-42s later — exactly the
                # ping_timeout window) — see docs/ISSUE_backup_identity_hijack.md.
                owned_tokens = ws_to_tokens.pop(websocket, set())
                for t in owned_tokens:
                    if token_to_ws.get(t) == websocket:
                        token_to_ws.pop(t, None)
            if username in rate_limits:
                rate_limits[username]["disconnected_at"] = time.time()
            suspicious_activity.pop(username, None)
        print(f"[-] Отключился: {ip}")


# ─── UPnP: автопроброс порта на домашнем роутере ─────────────────────────────

def setup_upnp(port: int = 9000) -> str:
    """
    Открывает порт на домашнем роутере через UPnP (как Minecraft, BitTorrent).
    Возвращает 'ws://public_ip:port' при успехе или '' при ошибке.
    Работает без регистраций и ручной настройки — достаточно включённого UPnP на роутере.
    """
    try:
        import miniupnpc
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 2000   # 2 сек на поиск шлюза
        found = upnp.discover()
        if not found:
            print("[UPnP] Роутер с UPnP не найден — включи UPnP в настройках роутера")
            return ""
        upnp.selectigd()
        public_ip = upnp.externalipaddress()
        if not public_ip:
            print("[UPnP] Не удалось получить внешний IP от роутера")
            return ""
        # Удаляем старый маппинг если был, затем создаём новый
        try:
            upnp.deleteportmapping(port, "TCP")
        except Exception:
            pass
        upnp.addportmapping(port, "TCP", upnp.lanaddr, port, "Subrosa Messenger", "")
        url = f"ws://{public_ip}:{port}"
        print(f"[UPnP] Порт {port} открыт автоматически. Адрес этого сервера: {url}")
        return url
    except ImportError:
        print("[UPnP] miniupnpc не установлен — запусти: pip install miniupnpc")
        return _upnp_http_fallback()
    except Exception as e:
        print(f"[UPnP] Ошибка: {e}")
        return _upnp_http_fallback()


def _upnp_http_fallback() -> str:
    """
    Если UPnP недоступен — пытаемся узнать внешний IP через публичный API.
    Порт пробрасывать мы не можем, поэтому только сообщаем пользователю,
    что нужно сделать вручную в настройках роутера.
    """
    try:
        import urllib.request
        external_ip = urllib.request.urlopen(
            "https://api.ipify.org", timeout=5
        ).read().decode().strip()
        if external_ip:
            print(f"[UPnP] Внешний IP определён: {external_ip}")
            print(f"[UPnP] UPnP недоступен — пробрось порт 9000 вручную в настройках роутера.")
            print(f"[UPnP] После этого задай в .env:  SERVER_URL=ws://{external_ip}:9000")
    except Exception:
        print("[UPnP] Не удалось определить внешний IP. Задай SERVER_URL в .env вручную.")
    return ""


# ─── Watchdog: очистка мёртвых пиров (раз в час) ─────────────────────────────

async def federation_watchdog():
    """
    Every hour: check each dynamic peer.
    Peers with no active connection get a strike.
    After DYNAMIC_PEER_MAX_STRIKES strikes the URL is evicted so clients
    stop receiving it in server_peers lists.
    Static FEDERATION_PEERS are never evicted — they reconnect indefinitely.
    """
    while True:
        await asyncio.sleep(3600)
        if not dynamic_peer_urls:
            continue

        evict = []
        for url in list(dynamic_peer_urls):
            ws = federation_ws.get(url)
            alive = False
            if ws is not None:
                try:
                    # Реальный ping: обнаруживает half-open соединения,
                    # которые websocket-объект считает живыми
                    await asyncio.wait_for(ws.ping(), timeout=10)
                    alive = True
                except Exception:
                    alive = False
            if alive:
                dynamic_peer_strikes[url] = 0   # reset on success
                print(f"[WATCHDOG] Пир живой: {url}")
            else:
                strikes = dynamic_peer_strikes.get(url, 0) + 1
                dynamic_peer_strikes[url] = strikes
                print(f"[WATCHDOG] Пир не отвечает ({strikes}/{DYNAMIC_PEER_MAX_STRIKES}): {url}")
                if strikes >= DYNAMIC_PEER_MAX_STRIKES:
                    evict.append(url)

        for url in evict:
            dynamic_peer_urls.discard(url)
            dynamic_peer_strikes.pop(url, None)
            federation_ws.pop(url, None)
            print(f"[WATCHDOG] Пир удалён из реестра: {url}")


# ─── Watchdog: TTL для token_pending (раз в час) ─────────────────────────────
# token_pending — чистая in-memory очередь без персистентности (осознанно, см.
# комментарий у anon_message выше): рестарт сервера и так её обнуляет. Но пока
# сервер живёт, запись держится там БЕЗГРАНИЧНО, пока получатель не пришлёт
# anon_delivery_ack — если получатель пропал на дни/недели (не просто на
# реконнект), это неограниченный рост в ОЗУ. TTL 24ч: после этого срока
# сообщение считается устаревшим и вычищается — тот же принцип, что и у
# pending_messages в SQLite (MSG_TTL_SEC), просто отдельный, более короткий
# срок для in-memory очереди.
async def token_pending_watchdog():
    while True:
        await asyncio.sleep(3600)
        now = time.time()
        async with lock:
            expired = [t for t, created in token_pending_created.items()
                       if now - created > TOKEN_PENDING_TTL_SEC]
            for t in expired:
                token_pending.pop(t, None)
                token_pending_created.pop(t, None)
        if expired:
            print(f"[WATCHDOG] token_pending: вычищено {len(expired)} устаревших (>24ч) записей")


# ─── Запуск ───────────────────────────────────────────────────────────────────

async def main(ssl_context=None):
    global _fed_ssl_ctx
    # Start outgoing federation connections
    if FEDERATION_SECRET and FEDERATION_PEERS:
        # For peer connections: skip certificate verification (peers may use self-signed certs)
        fed_ssl = None
        if ssl_context:
            fed_ssl = ssl.create_default_context()
            fed_ssl.check_hostname = False
            fed_ssl.verify_mode    = ssl.CERT_NONE
        _fed_ssl_ctx = fed_ssl
        for peer_url in FEDERATION_PEERS:
            asyncio.create_task(federation_connect_to_peer(peer_url, fed_ssl))
    elif FEDERATION_SECRET:
        fed_ssl = None
        if ssl_context:
            fed_ssl = ssl.create_default_context()
            fed_ssl.check_hostname = False
            fed_ssl.verify_mode    = ssl.CERT_NONE
        _fed_ssl_ctx = fed_ssl
        print(f"[FEDERATION] Инициализация: {len(FEDERATION_PEERS)} пиров → {FEDERATION_PEERS}")
    elif FEDERATION_SECRET:
        print("[FEDERATION] FEDERATION_SECRET задан, но FEDERATION_PEERS пуст — сервер принимает входящих пиров")

    if FEDERATION_SECRET:
        asyncio.create_task(federation_watchdog())
        print("[WATCHDOG] Запущен (проверка пиров каждые 3600с)")

    asyncio.create_task(token_pending_watchdog())
    print(f"[WATCHDOG] token_pending TTL запущен (проверка раз в час, TTL={TOKEN_PENDING_TTL_SEC//3600}ч)")

    async with websockets.serve(
        handle_client,
        "0.0.0.0",
        9000,
        ssl=ssl_context,
        ping_interval=15,
        ping_timeout=30,
        max_size=MAX_PACKET_SIZE_BYTES,
        compression=None,        # отключаем permessage-deflate: трафик уже зашифрован, сжатие бесполезно и добавляет ~5-15мс
        write_limit=2**16,       # 64KB write buffer — меньше накопления → ниже задержка при burst
    ):
        print("[*] WebSocket сервер запущен")
        print(f"[*] Режим: {'TLS' if ssl_context else 'DEV (без TLS)'}")
        await asyncio.Future()


def start_server():
    global SERVER_URL
    # UPnP: автопроброс порта если сервер — сын федерации и адрес не задан вручную
    if FEDERATION_SECRET and FEDERATION_PEERS and not SERVER_URL:
        detected = setup_upnp(9000)
        if detected:
            SERVER_URL = detected
        else:
            print("[UPnP] Автонастройка не удалась. Задай SERVER_URL в .env вручную.")

    _db_setup_sync()
    _db_load_channels_sync()
    loaded_bundles = _db_load_bundles_sync()
    prekey_bundles.update(loaded_bundles)
    loaded_avatars = _db_load_avatars_sync()
    user_avatars.update(loaded_avatars)
    loaded_totp = _db_load_totp_sync()
    user_totp_secrets.update(loaded_totp)
    print(f"[DB] Хранилище сообщений: {DB_PATH}")
    print(f"[DB] Каналов загружено из БД: {len(channels)}")
    print(f"[DB] Prekey bundles загружено: {len(loaded_bundles)}")
    print(f"[DB] Аватаров загружено: {len(loaded_avatars)}")
    print(f"[DB] Аккаунтов с TOTP-защитой (новых устройств): {len(loaded_totp)}")
    print(f"[TOTP] Шифрование секретов в БД: {'включено' if _totp_fernet else 'выключено (TOTP_SECRET_ENCRYPTION_KEY не задан)'}")

    if SERVER_ACCESS_PROTECTED:
        total_codes, unused_codes = _db_count_access_codes_sync()
        if total_codes == 0:
            want_count = int(os.environ.get("SERVER_ACCESS_CODE_COUNT", "0") or "0")
            if want_count > 0:
                new_codes = _db_gen_access_codes_sync(want_count)
                print(f"[ACCESS] SERVER_ACCESS_PROTECTED включён — сгенерировано {len(new_codes)} одноразовых кодов доступа:")
                for c in new_codes:
                    link = build_access_link(c)
                    if link:
                        print(f"[ACCESS]   {c}   ->   {link}")
                        qr_path = save_access_code_qr(link, c)
                        if qr_path:
                            print(f"[ACCESS]        QR: {qr_path}")
                    else:
                        print(f"[ACCESS]   {c}   (SERVER_URL не задан — ссылку/QR собери вручную)")
                if not HAS_QRCODE:
                    print("[ACCESS] QR-картинки не сгенерированы — пакет qrcode[pil] не установлен "
                          "(офлайн, ничего никуда не уходит — см. requirements.txt).")
                print("[ACCESS] Раздай ссылки/QR пользователям. Ещё коды позже — без рестарта: "
                      "python3 ForEXP/admin_gen_codes.py <N>")
            else:
                print("[ACCESS] SERVER_ACCESS_PROTECTED включён, но кодов нет и SERVER_ACCESS_CODE_COUNT не задан — "
                      "никто новый не сможет зарегистрироваться. Запусти: python3 ForEXP/admin_gen_codes.py <N>")
        else:
            print(f"[ACCESS] SERVER_ACCESS_PROTECTED включён, неиспользованных кодов: {unused_codes}/{total_codes}")

    # Печатаем строку подключения для пользователей
    if SERVER_URL:
        print("")
        print("=" * 50)
        print(f"  Адрес для подключения: {SERVER_URL}")
        print("=" * 50)
        print("")

    # DEV режим — без TLS
    if "--dev" in sys.argv:
        print("[DEV] Запуск без TLS на порту 9000")
        asyncio.run(main(None))
        return

    # Продакшн — с TLS
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    import os
    # 1. Из переменной окружения
    key_password = os.environ.get("BEACON_KEY_PASSWORD", "").strip()
    # 2. Из файла .key рядом со скриптом (просто сырой пароль, без кавычек и синтаксиса)
    if not key_password:
        key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".key")
        if os.path.exists(key_file):
            with open(key_file, "r") as _kf:
                key_password = _kf.read().strip()
    # 3. Интерактивный ввод (fallback)
    if not key_password:
        print("[*] Введите пароль от ключа:", flush=True)
        key_password = input("Пароль: ").strip()

    try:
        with open('key_encrypted.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=key_password.encode(), backend=default_backend()
            )
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        print("[OK] Ключ расшифрован")
    except Exception as e:
        print(f"[ERROR] {repr(e)}")
        exit(1)

    temp_key_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as tmp:
            tmp.write(key_pem)
            temp_key_path = tmp.name

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.load_cert_chain('cert.pem', temp_key_path)

        try:
            os.remove(temp_key_path)
            temp_key_path = None
            print("[OK] Временный файл ключа удалён")
        except Exception as e:
            print(f"[WARN] {e}")

        asyncio.run(main(ssl_context))

    finally:
        if temp_key_path:
            try:
                os.remove(temp_key_path)
            except Exception:
                pass


if __name__ == "__main__":
    start_server()