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
import tempfile
import os
from collections import defaultdict

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
ws_to_tokens: dict = {}   # websocket → set[str]       (для очистки при дисконнекте)
known_tokens: set  = set() # токены, которые хоть раз были зарегистрированы (фейки дропаем)
MAX_TOKEN_LEN = 32
MAX_TOKENS_PER_SUBSCRIBE = 100

MAX_BUNDLE_SIZE_BYTES  = 64  * 1024
MAX_PACKET_SIZE_BYTES  = 6 * 1024 * 1024
OPK_LOW_WATERMARK      = 5
HANDSHAKE_TIMEOUT_SEC  = 15

rate_limits = defaultdict(lambda: {
    "message":      {"count": 0, "reset_time": time.time()},
    "reaction":     {"count": 0, "reset_time": time.time()},
    "typing":       {"count": 0, "reset_time": time.time()},
    "prekey_fetch": {"count": 0, "reset_time": time.time()},
    "disconnected_at": 0
})

banned_users        = {}
banned_ips          = {}
suspicious_activity = defaultdict(lambda: {"violations": 0, "last_violation": 0})

# ─── Channels ─────────────────────────────────────────────────────────────────
# channel_id → {"name", "avatar", "description", "admin", "subscribers": set()}
channels             = {}
# one-time invite codes for channel creation
# code → {"channel_name", "avatar", "description", "expires": timestamp, "used": bool}
channel_invite_codes = {}
# Secret for generating channel creation codes (set via env var CHANNEL_ADMIN_SECRET)
CHANNEL_ADMIN_SECRET = os.getenv("CHANNEL_ADMIN_SECRET", "")

# ─── User avatars ──────────────────────────────────────────────────────────────
# username → base64-encoded JPEG avatar (128×128, ~5-8 KB)
user_avatars = {}

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
        print(f"[FEDERATION] Ростер ({len(roster)} пиров) отправлен → {ip}")

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
    default_limits = {"message": 50, "reaction": 100, "typing": 200, "prekey_fetch": 10}
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

# ─── Обработчик клиента ───────────────────────────────────────────────────────

async def handle_client(websocket):
    ip = websocket.remote_address[0] if websocket.remote_address else "unknown"

    if check_ip_banned(ip):
        print(f"[SECURITY] Заблокированный IP: {ip}")
        await websocket.close()
        return

    username      = None
    authenticated = False
    is_fed        = False
    challenge     = None

    try:
        print(f"[+] Новое подключение от {ip}")

        # ─── Handshake challenge ──────────────────────────────────────────────
        challenge     = secrets.token_bytes(32)
        challenge_b64 = base64.b64encode(challenge).decode()
        await websocket.send(json.dumps({"type": "challenge", "data": challenge_b64}))

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

            if not authenticated:
                if msg_type == "federation_auth" and FEDERATION_SECRET:
                    provided = base64.b64decode(message.get("mac", ""))
                    expected = hmac.new(
                        FEDERATION_SECRET.encode(), challenge, hashlib.sha256
                    ).digest()
                    if not hmac.compare_digest(provided, expected):
                        print(f"[FEDERATION] Неверный MAC от {ip}")
                        return
                    is_fed = True
                    await websocket.send(json.dumps({"type": "federation_auth_ok"}))
                    print(f"[FEDERATION] Входящий пир аутентифицирован: {ip}")
                    break  # exit the message loop → handle_federation_peer_incoming below
                elif msg_type != "challenge_response":
                    print(f"[SECURITY] Попытка {msg_type} до handshake от {ip}")
                    continue

            ALLOWED_TYPES = [
                "register", "register_bundle", "request_prekey", "get_key", "ping", "pong",
                "message", "session_init",
                "reaction", "voice", "typing", "edit",
                "image_chunk", "file_chunk", "video_chunk",
                "challenge_response", "read",
                "publish_prekey_bundle",
                "get_prekey_bundle", "group_reaction",
                "group_create",
                "group_message",
                "group_member_removed",
                "group_key_rotation",
                "group_invite_accepted",
                "delivered",
                "generate_channel_code",
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
                # ── Chat features ──
                "message_delete", "disappear_timer",
                "group_message_delete",
                # ── FCM token registration ──
                "register_fcm",
                # ── Profile ──
                "profile_update",
                # ── Session management ──
                "session_reset",
                # ── Anonymous token routing ──
                "subscribe_tokens", "anon_message"
            ]
            if msg_type not in ALLOWED_TYPES:
                print(f"[SECURITY] Неизвестный тип '{msg_type}' от {ip}")
                continue

            # ─── Challenge-Response ───────────────────────────────────────────
            if msg_type == "challenge_response":
                try:
                    from cryptography.hazmat.primitives import serialization, hashes
                    from cryptography.hazmat.primitives.asymmetric import ec
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.exceptions import InvalidSignature

                    public_key_b64 = message.get("public_key")
                    signature_b64  = message.get("signature")
                    if not public_key_b64 or not signature_b64:
                        return

                    key_bytes  = base64.b64decode(public_key_b64)
                    public_key = serialization.load_der_public_key(key_bytes, backend=default_backend())
                    sig_bytes  = base64.b64decode(signature_b64)
                    public_key.verify(sig_bytes, challenge, ec.ECDSA(hashes.SHA256()))

                    authenticated = True
                    print(f"[HANDSHAKE] Успешно: {ip}")
                    await websocket.send(json.dumps({"type": "handshake_ok"}))

                except InvalidSignature:
                    print(f"[HANDSHAKE] Неверная подпись от {ip}")
                    return
                except Exception as e:
                    print(f"[HANDSHAKE] Ошибка: {e}")
                    return
                continue

            # ─── Register ────────────────────────────────────────────────────
            if msg_type == "register":
                name       = message.get("name", "")
                public_key = message.get("public_key")
                device_id  = message.get("device_id")

                key_bytes   = base64.b64decode(public_key)
                fingerprint = hashlib.sha256(key_bytes).digest()[:8].hex().upper()
                username    = fingerprint

                async with lock:
                    existing = clients.get(username)
                    if existing:
                        existing_device_id = existing.get("device_id")
                        if device_id and existing_device_id and device_id != existing_device_id:
                            # Другое устройство — вытесняем старую сессию
                            print(f"[SESSION_CONFLICT] {username}: новое устройство, закрываем старую сессию")
                            asyncio.create_task(send_safe(existing["ws"], json.dumps({"type": "session_conflict"})))
                            asyncio.create_task(existing["ws"].close())
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

                if username in rate_limits:
                    rate_limits[username]["disconnected_at"] = 0
                else:
                    cleanup_stale_rate_limits()

                print(f"[OK] Зарегистрирован: {username}")

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
                    print(f"[QUEUE] Доставлено {len(pending)} отложенных сообщений → {username}")

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
                bundle = message.get("bundle")
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
                print(f"[PREKEY] Отправлен bundle {target} -> {username}")
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
                    print(f"[MSG] {username} → {to} session_init (доставлено)")
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
                        print(f"[MSG] {username} → {to} session_init (оффлайн, сохранено)")
                    else:
                        print(f"[MSG] {username} → {to} session_init (переслано федерации)")
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
                    print(f"[MSG] {username} → {to} (доставлено)")
                else:
                    fwd_payload = {"type": "message", "from": username,
                                   "text": message.get("text"), "signature": message.get("signature"),
                                   "id": msg_id, "protocol_version": message.get("protocol_version", 2)}
                    if "session_header" in message:
                        fwd_payload["session_header"] = message["session_header"]
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, fwd_payload)
                    if not forwarded:
                        await db_store(to, fwd_payload, msg_id)
                        print(f"[MSG] {username} → {to} (оффлайн, сохранено в очередь)")
                    else:
                        print(f"[MSG] {username} → {to} (переслано федерации)")
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

            # ─── Generate Channel Invite Code (admin only) ────────────────────
            if msg_type == "generate_channel_code":
                admin_secret = message.get("admin_secret", "")
                if not CHANNEL_ADMIN_SECRET or admin_secret != CHANNEL_ADMIN_SECRET:
                    await websocket.send(json.dumps({"type": "error", "reason": "Unauthorized"}))
                    continue
                # Generate a unique one-time code
                code = secrets.token_urlsafe(12)
                expires = time.time() + 24 * 3600  # 24 hours
                async with lock:
                    channel_invite_codes[code] = {
                        "expires": expires,
                        "used": False
                    }
                await websocket.send(json.dumps({"type": "channel_code_generated", "code": code}))
                print(f"[CHANNEL] Invite code generated: {code} by {username}")
                continue

            # ─── Create Channel ───────────────────────────────────────────────
            if msg_type == "channel_create":
                invite_code   = message.get("invite_code", "")
                channel_name  = message.get("channel_name", "").strip()
                channel_desc  = message.get("channel_description", "").strip()
                channel_avatar = message.get("channel_avatar", "📢")

                async with lock:
                    code_entry = channel_invite_codes.get(invite_code)
                    if not code_entry:
                        await websocket.send(json.dumps({"type": "error", "reason": "Неверный инвайт-код"}))
                        continue
                    if code_entry["used"]:
                        await websocket.send(json.dumps({"type": "error", "reason": "Инвайт-код уже использован"}))
                        continue
                    if time.time() > code_entry["expires"]:
                        await websocket.send(json.dumps({"type": "error", "reason": "Инвайт-код истёк"}))
                        continue
                    if not channel_name:
                        await websocket.send(json.dumps({"type": "error", "reason": "Название канала не может быть пустым"}))
                        continue

                    # Mark code as used
                    channel_invite_codes[invite_code]["used"] = True

                    # Create channel
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
                timestamp  = message.get("timestamp", int(time.time() * 1000))

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

                print(f"[CHANNEL] Post in {channel_id} by {username}: {text[:50]}{' [+image]' if image_data else ''}")
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
                "call_group_peer_list", "call_ice_restart"
            }
            if msg_type in CALL_RELAY_TYPES:
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
                    print(f"[CALL] {msg_type} {username} → {target}")
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
                        print(f"[CALL] missed call stored for {target} from {username}")
                    else:
                        print(f"[CALL] {msg_type} {username} → {target} (offline, dropped)")
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
                            # Флашим отложенные сообщения для этого токена
                            pending = token_pending.pop(t, [])
                            for p in pending:
                                asyncio.create_task(send_safe(websocket, json.dumps(p)))
                        ws_to_tokens[websocket] = existing
                    print(f"[ANON] {username} подписан на {len(valid)} токенов")
                continue

            if msg_type == "anon_message":
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
                delivery = json.dumps({"type": "anon_delivery", "payload": payload})
                async with lock:
                    target_ws = token_to_ws.get(token)
                if target_ws:
                    ok = await send_safe(target_ws, delivery)
                    if ok:
                        # Токен одноразовый — удаляем после доставки
                        async with lock:
                            token_to_ws.pop(token, None)
                            ws_to_tokens.get(target_ws, set()).discard(token)
                        print(f"[ANON] Доставлено по токену …{token[-6:]}")
                    else:
                        # Получатель закрыл сокет между проверкой и отправкой — ставим в очередь
                        async with lock:
                            token_pending.setdefault(token, []).append({"type": "anon_delivery", "payload": payload})
                else:
                    # Офлайн — ставим в очередь; доставим когда клиент переподпишется
                    async with lock:
                        token_pending.setdefault(token, []).append({"type": "anon_delivery", "payload": payload})
                    print(f"[ANON] Токен …{token[-6:]} офлайн, сообщение в очереди")
                if msg_id:
                    await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
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

        if is_fed:
            await handle_federation_peer_incoming(websocket, ip)

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        if username:
            # Очищаем анонимные токены этого клиента
            async with lock:
                tokens = ws_to_tokens.pop(websocket, set())
                for t in tokens:
                    token_to_ws.pop(t, None)

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
            if username in rate_limits:
                rate_limits[username]["disconnected_at"] = time.time()
            suspicious_activity.pop(username, None)
        print(f"[-] Отключился: {ip}")


# ─── Admin HTTP API (порт 9001, только localhost) ─────────────────────────────
# Использование: curl "http://127.0.0.1:9001/channel_code?secret=YOUR_SECRET"
# Возвращает JSON: {"code": "xxx", "expires_in": "24h"}

ADMIN_PORT = int(os.getenv("ADMIN_PORT", "9001"))

async def handle_admin_http(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=5)
        request = data.decode(errors="replace")
        # Parse simple GET request
        first_line = request.split("\r\n")[0] if "\r\n" in request else request.split("\n")[0]
        # e.g. "GET /channel_code?secret=xxx HTTP/1.1"
        path = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else ""

        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(path)
        params = parse_qs(parsed.query)
        provided_secret = params.get("secret", [""])[0]

        if parsed.path == "/channel_code":
            if not CHANNEL_ADMIN_SECRET:
                body = '{"error": "CHANNEL_ADMIN_SECRET not set"}'
                status = "503 Service Unavailable"
            elif provided_secret != CHANNEL_ADMIN_SECRET:
                body = '{"error": "Invalid secret"}'
                status = "403 Forbidden"
            else:
                code = secrets.token_urlsafe(12)
                expires = time.time() + 24 * 3600
                async with lock:
                    channel_invite_codes[code] = {"expires": expires, "used": False}
                body = f'{{"code": "{code}", "expires_in": "24h"}}'
                status = "200 OK"
                print(f"[ADMIN] Channel invite code generated: {code}")
        else:
            body = '{"error": "Not found"}'
            status = "404 Not Found"

        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()
    except Exception as e:
        print(f"[ADMIN] HTTP error: {e}")
    finally:
        writer.close()

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
        upnp.addportmapping(port, "TCP", upnp.lanaddr, port, "Beacon Messenger", "")
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

    # Admin HTTP API (только localhost, без TLS)
    if CHANNEL_ADMIN_SECRET:
        admin_server = await asyncio.start_server(handle_admin_http, "127.0.0.1", ADMIN_PORT)
        print(f"[ADMIN] HTTP API запущен на 127.0.0.1:{ADMIN_PORT}")
        print(f"[ADMIN] Генерация кода: curl \"http://127.0.0.1:{ADMIN_PORT}/channel_code?secret=YOUR_SECRET\"")

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
    print(f"[DB] Хранилище сообщений: {DB_PATH}")
    print(f"[DB] Каналов загружено из БД: {len(channels)}")
    print(f"[DB] Prekey bundles загружено: {len(loaded_bundles)}")
    print(f"[DB] Аватаров загружено: {len(loaded_avatars)}")

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