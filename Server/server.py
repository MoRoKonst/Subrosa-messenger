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
import weakref
import secrets
import base64
import hashlib
import struct
import tempfile
import os
import socket
import ipaddress
import urllib.parse
import re
from collections import defaultdict, OrderedDict
from contextlib import asynccontextmanager

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    from sqlcipher3 import dbapi2 as sqlcipher
    HAS_SQLCIPHER = True
except ImportError:
    HAS_SQLCIPHER = False

if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
if hasattr(sys.stderr, 'buffer'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

# ─── Состояние ────────────────────────────────────────────────────────────────

authenticated_users = {}   # websocket → username
clients             = {}   # username → {"ws": ws, "name": str, "public_key": str}
lock                = asyncio.Lock()
prekey_bundles      = {}   # username → bundle (dict)

# Used only to pick WHICH other registered accounts get offered up as decoy
# candidates (get_decoy_candidates) — not a secret-generation context (no
# token/key material comes out of this), but secrets.SystemRandom() is used
# anyway rather than introducing the plain `random` module into a file that
# otherwise draws every other instance of randomness from `secrets`, so an
# auditor scanning imports never has to ask "is this one the weak one".
_SECURE_RANDOM = secrets.SystemRandom()


def is_valid_fingerprint(value) -> bool:
    """Canonical fingerprint shape check (external review 2026-09-04,
    S6-35) — `register()` derives every real username as
    `sha256(key_bytes).digest()[:8].hex().upper()`: exactly 16 uppercase
    hex characters, always. Every prekey API that takes a `target`/
    `username` meant to identify a REAL account (get_prekey_bundle,
    get_prekey_bundles_batch, federated_get_bundle, both directions) must
    reject anything that doesn't already look like one of these BEFORE it
    ever reaches a lock-registry/cache/DB/federation lookup — see
    prekey_mutation_guard()'s own comment for the specific RAM-growth
    attack this closes. Deliberately does NOT normalize (lowercase, strip,
    truncate, etc.) — every real fingerprint this server has ever minted is
    already exactly this shape; silently coercing a near-miss into a valid-
    looking key would just move the validation gap somewhere subtler."""
    return (
        isinstance(value, str)
        and len(value) == 16
        and all(c in "0123456789ABCDEF" for c in value)
    )


# Canonical device_id shape check (external review 2026-09-04, S6-37) — both
# Android (`UserStorage.getDeviceId()`) and Desktop (`UserStorage.getDeviceId()`)
# generate this exactly once per install via `UUID.randomUUID().toString()`
# and persist it indefinitely (EncryptedStorage/DesktopStorage) — a standard
# RFC-4122 textual UUID, always exactly 36 characters
# (8-4-4-4-12 hex groups joined by hyphens). Before this fix, `register()`
# took `device_id = message.get("device_id")` with no format/length bound at
# all, bounded only by the multi-megabyte websocket frame ceiling — an
# authenticated client (any account, no elevated privilege) could reconnect
# repeatedly with a fresh oversized/malformed device_id every time and
# permanently grow `authorized_devices` (see MAX_AUTHORIZED_DEVICES_PER_
# ACCOUNT below for the durable-growth half of this fix; this is the input-
# shape half). Deliberately case-insensitive on the hex groups (Java's
# `UUID.toString()` is always lowercase, but nothing about the protocol
# requires that) and deliberately does NOT normalize/canonicalize a match —
# `device_id` participates byte-for-byte in the signed data
# (`SUBROSA_DEVICE_V1 || challenge || username || device_id`), so rewriting
# it server-side would change what the client actually signed.
_DEVICE_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def is_valid_device_id(value) -> bool:
    return isinstance(value, str) and _DEVICE_ID_RE.match(value) is not None


# Protocol-specific bounds on the two device-auth crypto fields, checked as
# plain string-length comparisons BEFORE base64.b64decode()/DER parsing ever
# runs (external review 2026-09-04, S6-37) — `device_public_key` is a DER
# X.509 SubjectPublicKeyInfo for a secp256r1 (P-256) public key, a fixed 91
# raw bytes (124 base64 characters); `device_signature` is a DER-encoded
# ECDSA signature over that same curve, variable but typically 70-72 raw
# bytes (roughly 96-100 base64 characters). Both bounds below are deliberately
# generous relative to those real sizes (headroom for a future curve/key-size
# change) while still being tiny relative to `MAX_PACKET_SIZE_BYTES` — these
# fields carry a single EC key or signature, never megabytes of legitimate
# data, so there is no reason to let arbitrary attacker-supplied input that
# large reach `base64.b64decode()`/`load_der_public_key()` at all.
MAX_DEVICE_PUBKEY_B64_LEN    = 512
MAX_DEVICE_SIGNATURE_B64_LEN = 256

# Canonical identity-key crypto bounds/decoder (external review 2026-09-05,
# S6-45) — same reasoning as MAX_DEVICE_PUBKEY_B64_LEN/MAX_DEVICE_SIGNATURE_
# B64_LEN just above, for the long-lived per-ACCOUNT identity key instead of
# a per-device one: it's the exact same algorithm/encoding on both shipped
# clients (Android's/Desktop's CryptoManager, grepped — secp256r1 keypair,
# `SHA256withECDSA` signatures, standard X.509 SubjectPublicKeyInfo DER for
# the public key), so the same ~91-raw-byte/124-b64-char public key and
# ~70-72-raw-byte/~96-100-b64-char signature sizes apply. Used by BOTH the
# handshake's challenge_response AND register() (S6-45's own point: hardening
# only the handshake would leave a second, equally attacker-reachable path
# to the same expensive base64/DER work) — one shared helper instead of
# duplicating slightly different decode/validation rules between the two.
MAX_IDENTITY_PUBKEY_B64_LEN    = 512
MAX_IDENTITY_SIGNATURE_B64_LEN = 256


def decode_identity_public_key(value):
    """Cheap shape/length/base64-syntax checks BEFORE base64.b64decode()/
    load_der_public_key() ever run, then enforces the protocol's actual EC
    algorithm — P-256/secp256r1, confirmed as the sole identity-key curve on
    both shipped clients (external review 2026-09-05) — since
    load_der_public_key() alone happily parses any EC curve's DER blob, or
    even a non-EC key entirely. Returns (key_bytes, public_key) on success,
    None on ANY failure (wrong type/empty/oversized/invalid base64/
    unparseable DER/wrong key type/wrong curve) — callers don't need to
    distinguish which, same externally-indistinguishable-rejection posture
    already used throughout this file (e.g. is_valid_access_code()). Doesn't
    change fingerprint semantics at all: the fingerprint remains SHA-256 over
    these exact same canonical DER bytes, computed by the caller as before."""
    if (not isinstance(value, str) or not value
            or len(value) > MAX_IDENTITY_PUBKEY_B64_LEN):
        return None
    try:
        key_bytes = base64.b64decode(value, validate=True)
    except Exception:
        return None
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        public_key = serialization.load_der_public_key(key_bytes, backend=default_backend())
    except Exception:
        return None
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        return None
    return key_bytes, public_key


def decode_identity_signature(value):
    """Same cheap shape/length/base64-syntax checks as
    decode_identity_public_key(), for the DER-encoded ECDSA signature
    accompanying it. Returns the raw decoded bytes on success, None on any
    failure — verification itself (the only step that can determine
    validity beyond syntax) stays the caller's job."""
    if (not isinstance(value, str) or not value
            or len(value) > MAX_IDENTITY_SIGNATURE_B64_LEN):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None

# Hard per-account cap on durably PINNED device keys (external review
# 2026-09-04, S6-37) — enforced atomically inside db_bind_device_pubkey()'s
# own BEGIN IMMEDIATE transaction, only against genuinely NEW rows (an
# existing legacy NULL-pubkey row can still be claimed even at/over the cap
# — see that function's own comment). Even after removing the TOTP-disabled
# NULL-row admission path (register()'s own comment on that removal), an
# account that legitimately keeps re-proving TOTP for brand-new device_ids
# (each reinstall/phone change generates a fresh one — see
# is_valid_device_id()'s own comment on device_id's origin) could otherwise
# durably enroll an unbounded number of pinned device keys over the
# account's lifetime. 32 is generous relative to how many distinct
# devices/reinstalls a single real account plausibly accumulates (this
# server only ever allows ONE live session per account at a time —
# session_conflict eviction in register()'s Phase 2 — so this bounds
# historical device turnover, not concurrent device count). Required
# strictly positive, same "hard process/data protection, not an optional
# abuse-mitigation knob" posture as MAILBOX_MAX_TOTAL_BYTES/PENDING_
# MESSAGES_MAX_TOTAL_ROWS — a misconfigured value refuses to start rather
# than silently running unbounded or permanently locking every account out
# of ever adding a device.
MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = int(os.environ.get("MAX_AUTHORIZED_DEVICES_PER_ACCOUNT", "32"))
if MAX_AUTHORIZED_DEVICES_PER_ACCOUNT <= 0:
    print("[FATAL] MAX_AUTHORIZED_DEVICES_PER_ACCOUNT должен быть > 0 (обязательная защита от "
          "неограниченного роста authorized_devices, а не отключаемая опция) — отказ запуска.",
          flush=True)
    sys.exit(1)


# Narrow, per-target lock for a prekey bundle's read-modify-write cycle
# (publish, OPK consumption) — external review 2026-09-04, invariant #39.
# Deliberately SEPARATE from the global `lock`: DB awaits are allowed while
# holding one of these (only ever the single entry for the target actually
# being mutated), never while holding `lock` itself (invariant #34) — see
# store_prekey_bundle()/consume_prekey_bundle_for_serve()'s own comments.
#
# Ref-counted, self-pruning keyed-lock registry (external review
# 2026-09-04, S6-35) — replaces a `defaultdict(asyncio.Lock)` that used to
# keep one asyncio.Lock PERMANENTLY per distinct key ever looked up, for
# the life of the process. `consume_prekey_bundle_for_serve(target)`
# acquires this lock for `target` before knowing whether `target` is even
# a real account/bundle at all — combined with `get_prekey_bundle`'s old
# `target = message.get("target")` (no shape validation at all), any
# authenticated client could mint a permanent RAM-resident lock (plus its
# retained dict key — up to MAX_PACKET_SIZE_BYTES long, since nothing
# bounded `target`'s length either) for every unique garbage string it
# felt like sending, at up to the `prekey_fetch` rate limit (10/min) —
# straightforward unbounded RAM growth from an ordinary authenticated
# session, no privilege beyond "can register" required. Fixed on two
# fronts: `is_valid_fingerprint()` above rejects a non-canonical target
# before it ever reaches this registry (closes the growth AND the
# oversized-key amplification at once — see its own comment), and this
# registry itself now only holds an entry for a key while at least one
# coroutine is actively holding OR WAITING for that key's lock — see
# prekey_mutation_guard()'s own comment for why waiters, not just the
# current holder, must count toward that.
prekey_mutation_locks: dict = {}


@asynccontextmanager
async def prekey_mutation_guard(target: str):
    """Replaces bare `async with prekey_mutation_locks[target]:` — acquires
    (creating on first use) the one asyncio.Lock for `target`, then prunes
    the registry entry once nobody holds or is waiting on it anymore, so a
    never-repeated `target` leaves no permanent trace (see
    prekey_mutation_locks' own comment for the growth this closes).

    The `refs` counter is the entire correctness argument, and it MUST
    count waiters, not just the current holder — found live 2026-09-04: an
    earlier draft decremented (and possibly pruned) on entering the
    critical section rather than on truly leaving it, which reopens
    exactly the split-lock race invariant #39 exists to prevent:

        coroutine A holds lock L1 for "target"
        coroutine B is already awaiting L1.acquire() (queued behind A)
        A finishes its critical section and this registry prunes "target"
          (WRONG: this must not happen while B is still waiting)
        coroutine C calls this for the same "target" -> registry miss ->
          creates a brand-new lock L2
        B's queued acquire() on L1 finally succeeds; C's acquire() on L2
          also succeeds -- B and C are now BOTH inside a "target"-target
          critical section at once, the exact interleaving invariant #39's
          per-target serialization exists to rule out (a concurrent
          publish and a concurrent OPK consumption for one target could
          interleave again).

    `refs` is incremented for this call the INSTANT it either creates or
    finds the registry entry — before the `await` on `.acquire()` — so a
    second caller for the same target arriving while this one is still
    QUEUED (not yet holding the lock) sees `refs >= 1` and reuses this same
    entry/lock instead of racing a fresh one into existence. No `await`
    happens between the registry lookup/create and that increment, and
    this is a single-threaded asyncio event loop, so that whole sequence is
    atomic with respect to every other coroutine — no explicit lock is
    needed to protect the registry dict itself, only the per-target
    asyncio.Lock it hands out.

    `refs` is decremented in a `finally` that wraps BOTH the wait-to-acquire
    step and the critical section, so cancellation while still waiting to
    acquire, cancellation while holding, and a normal exit all decrement
    exactly once — the registry entry is popped only when `refs` reaches 0
    AND the dict still maps `target` to THIS exact entry object (guards
    against a pathological pop-then-recreate-then-pop-again double-free if
    two prunes for the same target were ever attempted, which shouldn't
    happen given the ordering above, but costs nothing to guard anyway)."""
    entry = prekey_mutation_locks.get(target)
    if entry is None:
        entry = {"lock": asyncio.Lock(), "refs": 0}
        prekey_mutation_locks[target] = entry
    entry["refs"] += 1
    try:
        async with entry["lock"]:
            yield
    finally:
        entry["refs"] -= 1
        if entry["refs"] == 0 and prekey_mutation_locks.get(target) is entry:
            prekey_mutation_locks.pop(target, None)


active_calls        = {}   # username → {"peer": str, "call_id": str} — для auto call_end при дисконнекте


def active_call_matches(user: str, peer: str, call_id: str) -> bool:
    """True iff active_calls[user] currently reciprocally reflects an active
    call with EXACTLY this peer + call_id (external review 2026-09-08,
    S6-61). Callers must hold `lock` — same as every other active_calls
    read/write. Used to gate every CROSS-USER mutation (writing/popping
    someone ELSE's entry) so an attacker naming an arbitrary victim as `to`
    can no longer overwrite or erase that victim's real active_calls state
    just by sending a well-formed call_answer/call_end/disconnecting — a
    user's OWN entry (keyed by their own authenticated username) remains
    freely writable by that user at any time, unchanged."""
    entry = active_calls.get(user)
    return entry is not None and entry.get("peer") == peer and entry.get("call_id") == call_id

# ─── WebRTC call signaling protocol bounds (S6-51) ─────────────────────────────
# call_id/group_id are always UUID.randomUUID().toString() on BOTH clients
# (Android: CallManager.kt startCall()/startGroupCall(); Desktop:
# DesktopCallManager.kt startCall(); group_id: CreateGroupScreen.kt/
# WebSocketClient.kt createGroup(), both plain java.util.UUID output) — a
# SEPARATE validator from is_valid_device_id() (identical shape, but
# device_id participates in a signed byte string elsewhere in this file and
# the two concepts are kept decoupled) since call_id/group_id are opaque
# routing/tracking keys only, never cryptographically compared.
_CALL_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def is_valid_call_uuid(value) -> bool:
    return isinstance(value, str) and _CALL_ID_RE.match(value) is not None


# SDP session descriptions from both clients' WebRTC stacks (Android:
# org.webrtc, Desktop: webrtc-java/native libwebrtc) are ordinarily a few KB
# (media/codec/fingerprint lines, no embedded ICE candidates — both clients
# use trickle ICE, sent as separate call_ice messages) — 64 KiB is a
# generous multiple of that, not a guess.
CALL_SDP_MAX_LEN = 64 * 1024
# A single ICE candidate line ("candidate:842163049 1 udp ...") is well
# under 300 bytes in practice; 1024 gives real headroom without admitting
# megabytes.
CALL_ICE_CANDIDATE_MAX_LEN = 1024
# sdp_mid is a short media-stream identifier ("0", "audio", "video1", ...).
CALL_ICE_SDP_MID_MAX_LEN = 64
# Every reason string either client or this server itself ever sends on the
# wire, across call_end/call_group_leave/call_response — grepped both
# CallManager.kt/DesktopCallManager.kt and this file's own auto-call_end
# disconnect handler. An explicit allow-list, not a length bound alone,
# since the full set is small and enumerable.
CALL_REASON_ALLOWED = {
    "hangup", "stale", "busy", "decline", "timeout", "ice_failed", "disconnected",
}
# call_group_peer_list's `peers` array — Android-only (Desktop has no group
# calls). WebRTC mesh calls don't scale past a handful of participants in
# practice; 50 is a generous cap, not a realistic expectation.
CALL_GROUP_PEER_LIST_MAX_COUNT = 50

# Dedicated per-type signaling envelope ceilings, all substantially below
# MAX_PACKET_SIZE_BYTES (6 MiB) — call signaling is small schema-defined
# traffic; the multi-megabyte application frame ceiling stays available for
# message/media protocols that actually need it, per-type rather than one
# common value since SDP-carrying types genuinely need more room than a
# single ICE candidate or a bare control message does.
CALL_SIGNAL_SDP_MAX_PACKET_SIZE_BYTES       = 96 * 1024   # sdp (<=64 KiB) + envelope
CALL_SIGNAL_ICE_MAX_PACKET_SIZE_BYTES       = 4 * 1024    # one candidate (<=1 KiB) + envelope
CALL_SIGNAL_PEER_LIST_MAX_PACKET_SIZE_BYTES = 8 * 1024    # up to 50 fingerprints + envelope
CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES   = 2 * 1024    # to/call_id/reason/flags only

_CALL_SIGNAL_CEILING_BY_TYPE = {
    "call_offer": CALL_SIGNAL_SDP_MAX_PACKET_SIZE_BYTES,
    "call_answer": CALL_SIGNAL_SDP_MAX_PACKET_SIZE_BYTES,
    "call_group_answer": CALL_SIGNAL_SDP_MAX_PACKET_SIZE_BYTES,
    "call_group_join": CALL_SIGNAL_SDP_MAX_PACKET_SIZE_BYTES,
    "call_ice_restart": CALL_SIGNAL_SDP_MAX_PACKET_SIZE_BYTES,
    "call_ice": CALL_SIGNAL_ICE_MAX_PACKET_SIZE_BYTES,
    "call_group_ice": CALL_SIGNAL_ICE_MAX_PACKET_SIZE_BYTES,
    "call_group_peer_list": CALL_SIGNAL_PEER_LIST_MAX_PACKET_SIZE_BYTES,
    "call_end": CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES,
    "call_ringing": CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES,
    "call_group_invite": CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES,
    "call_group_leave": CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES,
    "call_request_audio": CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES,
    "call_request_video": CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES,
    "call_response": CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES,
}


def _call_signal_ceiling_bytes(msg_type: str) -> int:
    return _CALL_SIGNAL_CEILING_BY_TYPE.get(msg_type, CALL_SIGNAL_CONTROL_MAX_PACKET_SIZE_BYTES)


def _is_valid_call_bool(value) -> bool:
    return isinstance(value, bool)


def _is_valid_call_nonneg_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_valid_call_sdp(value) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= CALL_SDP_MAX_LEN


def _is_valid_call_ice_candidate(value) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= CALL_ICE_CANDIDATE_MAX_LEN


def _is_valid_call_reason(value) -> bool:
    return isinstance(value, str) and value in CALL_REASON_ALLOWED


def _sanitize_call_signal(msg_type: str, message: dict, from_user: str, target: str):
    """ONE canonical construction path for every relayed call-signaling
    message (S6-51) — builds a BRAND NEW dict containing only the fields
    THIS exact msg_type's current protocol defines, instead of forwarding
    the caller's arbitrary dict verbatim (the original vulnerability: a
    small legitimate candidate/SDP plus megabytes of unrelated JSON used to
    be relayed as-is, since nothing ever stripped unknown fields).
    `type`/`from`/`to`/`call_id` are always server-controlled or validated
    here; every other field is validated per-type, cheap type/length checks
    before anything else. Returns None if ANY field fails validation — the
    caller must treat that exactly like a malformed message (drop, no
    active_calls mutation, no relay), never a partial/best-effort payload."""
    call_id = message.get("call_id", "")
    if not is_valid_call_uuid(call_id):
        return None

    out = {"type": msg_type, "from": from_user, "to": target, "call_id": call_id}

    if msg_type == "call_offer":
        sdp = message.get("sdp")
        if not _is_valid_call_sdp(sdp):
            return None
        is_video = message.get("is_video", False)
        if not _is_valid_call_bool(is_video):
            return None
        is_group = message.get("is_group", False)
        if not _is_valid_call_bool(is_group):
            return None
        out["sdp"] = sdp
        out["is_video"] = is_video
        out["is_group"] = is_group
        group_id = message.get("group_id")
        if group_id is not None:
            if not is_valid_call_uuid(group_id):
                return None
            out["group_id"] = group_id
        ts = message.get("ts")
        if ts is not None:
            if not _is_valid_call_nonneg_int(ts):
                return None
            out["ts"] = ts

    elif msg_type in ("call_answer", "call_group_answer"):
        sdp = message.get("sdp")
        if not _is_valid_call_sdp(sdp):
            return None
        out["sdp"] = sdp
        if msg_type == "call_group_answer":
            group_id = message.get("group_id")
            if not is_valid_call_uuid(group_id):
                return None
            out["group_id"] = group_id

    elif msg_type in ("call_ice", "call_group_ice"):
        candidate = message.get("candidate")
        if not _is_valid_call_ice_candidate(candidate):
            return None
        sdp_m_line_index = message.get("sdp_m_line_index")
        if not _is_valid_call_nonneg_int(sdp_m_line_index) or sdp_m_line_index > 255:
            return None
        out["candidate"] = candidate
        out["sdp_m_line_index"] = sdp_m_line_index
        # sdp_mid can legitimately be absent — org.json's JSONObject.put()
        # drops a null value entirely rather than emitting a JSON null, and
        # a real IceCandidate.sdpMid CAN be null — only bounded/forwarded
        # when actually present, never invented.
        sdp_mid = message.get("sdp_mid")
        if sdp_mid is not None:
            if not isinstance(sdp_mid, str) or len(sdp_mid) > CALL_ICE_SDP_MID_MAX_LEN:
                return None
            out["sdp_mid"] = sdp_mid

    elif msg_type == "call_ice_restart":
        sdp = message.get("sdp")
        if not _is_valid_call_sdp(sdp):
            return None
        out["sdp"] = sdp

    elif msg_type in ("call_end", "call_group_leave"):
        reason = message.get("reason")
        if not _is_valid_call_reason(reason):
            return None
        out["reason"] = reason

    elif msg_type == "call_ringing":
        pass  # no additional fields defined by the current protocol

    elif msg_type == "call_group_invite":
        group_id = message.get("group_id")
        if not is_valid_call_uuid(group_id):
            return None
        is_video = message.get("is_video", False)
        if not _is_valid_call_bool(is_video):
            return None
        out["group_id"] = group_id
        out["is_video"] = is_video

    elif msg_type == "call_group_join":
        group_id = message.get("group_id")
        if not is_valid_call_uuid(group_id):
            return None
        sdp = message.get("sdp")
        if not _is_valid_call_sdp(sdp):
            return None
        out["group_id"] = group_id
        out["sdp"] = sdp

    elif msg_type == "call_group_peer_list":
        group_id = message.get("group_id")
        if not is_valid_call_uuid(group_id):
            return None
        peers = message.get("peers")
        if (not isinstance(peers, list) or len(peers) > CALL_GROUP_PEER_LIST_MAX_COUNT
                or not all(is_valid_fingerprint(p) for p in peers)):
            return None
        out["group_id"] = group_id
        out["peers"] = peers

    elif msg_type in ("call_request_audio", "call_request_video"):
        ts = message.get("ts")
        if ts is not None:
            if not _is_valid_call_nonneg_int(ts):
                return None
            out["ts"] = ts

    elif msg_type == "call_response":
        accepted = message.get("accepted", False)
        if not _is_valid_call_bool(accepted):
            return None
        out["accepted"] = accepted
        reason = message.get("reason")
        if reason is not None:
            if not _is_valid_call_reason(reason):
                return None
            out["reason"] = reason

    else:
        return None

    return out


# Process-local byte budgets for RELAYED call signaling (S6-51) — mirror
# media_chunk_user_rate_ok()/media_chunk_global_rate_ok()/
# media_chunk_recipient_rate_ok() exactly (S6-49, see either's own comment
# for the full reasoning, including why no explicit lock is needed and why
# these are process-local: a multi-process/replica deployment gets one
# independent budget per process, not one shared budget across the
# deployment). The EXISTING per-type count limits (rate_limit_check(),
# "call_offer": 20/min etc.) protect message FREQUENCY and are unchanged;
# these protect aggregate BYTES, since 300 call_ice/min at up to
# MAX_PACKET_SIZE_BYTES each was the actual amplification vector this patch
# closes. Accounted ONCE, from the exact sanitized relay payload
# (_sanitize_call_signal()'s output, json.dumps'd) — never the raw
# attacker-supplied frame, and only for a message that's actually about to
# be relayed to an ONLINE recipient (an offline target never costs any
# egress, so never touches these).
CALL_SIGNAL_USER_MAX_BYTES  = int(os.environ.get("CALL_SIGNAL_USER_MAX_BYTES", str(2 * 1024 * 1024)) or str(2 * 1024 * 1024))
CALL_SIGNAL_USER_WINDOW_SEC = 10
call_signal_user_rate: dict = {}   # username -> {"bytes": int, "reset_time": float}


def call_signal_user_rate_ok(username: str, nbytes: int) -> bool:
    """Bounded key space, same posture as media_chunk_user_rate_ok(): keyed
    only by a real authenticated username, never an attacker-minted string."""
    now = time.time()
    entry = call_signal_user_rate.get(username)
    if not entry or now - entry["reset_time"] >= CALL_SIGNAL_USER_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        call_signal_user_rate[username] = entry
    if entry["bytes"] + nbytes > CALL_SIGNAL_USER_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


CALL_SIGNAL_GLOBAL_MAX_BYTES  = int(os.environ.get("CALL_SIGNAL_GLOBAL_MAX_BYTES", str(20 * 1024 * 1024)) or str(20 * 1024 * 1024))
CALL_SIGNAL_GLOBAL_WINDOW_SEC = 10
call_signal_global_rate = {"bytes": 0, "reset_time": time.time()}


def call_signal_global_rate_ok(nbytes: int) -> bool:
    now  = time.time()
    data = call_signal_global_rate
    if now - data["reset_time"] >= CALL_SIGNAL_GLOBAL_WINDOW_SEC:
        data["bytes"]      = 0
        data["reset_time"] = now
    if data["bytes"] + nbytes > CALL_SIGNAL_GLOBAL_MAX_BYTES:
        return False
    data["bytes"] += nbytes
    return True


# Per-recipient ingress budget — the sender/global budgets above protect
# server capacity, but many Sybil senders could otherwise each spend their
# own individual allowance against the SAME online victim, monopolizing
# that recipient's bandwidth/attention. Keyed only by a genuinely-online
# recipient username (clients.get(target) already succeeded by the time
# this is ever checked), not an attacker-controlled arbitrary string.
CALL_SIGNAL_RECIPIENT_MAX_BYTES  = int(os.environ.get("CALL_SIGNAL_RECIPIENT_MAX_BYTES", str(8 * 1024 * 1024)) or str(8 * 1024 * 1024))
CALL_SIGNAL_RECIPIENT_WINDOW_SEC = 10
call_signal_recipient_rate: dict = {}   # recipient username -> {"bytes": int, "reset_time": float}


def call_signal_recipient_rate_ok(recipient_username: str, nbytes: int) -> bool:
    now = time.time()
    entry = call_signal_recipient_rate.get(recipient_username)
    if not entry or now - entry["reset_time"] >= CALL_SIGNAL_RECIPIENT_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        call_signal_recipient_rate[recipient_username] = entry
    if entry["bytes"] + nbytes > CALL_SIGNAL_RECIPIENT_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


# ─── Chat-control relay hardening (S6-53) ──────────────────────────────────
# message_delete/disappear_timer/group_message_delete used to relay the
# caller's entire raw JSON object verbatim (from message["from"] = username
# onward the ORIGINAL dict was forwarded/stored/federated as-is) — no schema
# reconstruction, unlike call signaling's _sanitize_call_signal() (S6-51).
# An authenticated client could attach an arbitrary multi-megabyte `junk`
# field to an otherwise-legitimate delete/timer command and have it relayed,
# re-serialized, and independently Task-fanned-out with no dedicated
# admission control. This mirrors S6-51's fix almost exactly: one brand-new
# sanitized dict per relay, containing only fields THIS protocol actually
# defines, plus its own small envelope ceiling, a shared count bucket, and
# byte budgets.
#
# message_id: every real client-generated id for these 3 types is
# UUID.randomUUID().toString() (grepped both clients' send paths — Android's
# sendDeleteMessage/sendGroupDeleteMessage/CreateGroupScreen, Desktop's
# sendDelete/sendGroupDeleteMessage) but kept a general bound rather than a
# strict UUID regex, matching OFFLINE_MSG_ID_MAX_LEN/is_valid_offline_msg_id's
# own precedent (msg_id has no single canonical format across every caller
# in this codebase).
CHAT_CONTROL_ID_MAX_LEN = 128
# Signature is SHA256withECDSA/P-256, DER-encoded, base64'd (CryptoManager.
# sign()) — same shape as every other identity signature in this protocol;
# mirrors MEDIA_CHUNK_SIGNATURE_MAX_LEN/MAX_IDENTITY_SIGNATURE_B64_LEN's own
# bound. Optional: Desktop's message_delete/group_message_delete never send
# one at all (grepped WebSocketClient.kt) — never invented if absent.
CHAT_CONTROL_SIGNATURE_MAX_LEN = 256
# disappear_timer's `seconds` — the ONLY 4 values ChatScreen.kt's disappear
# dialog ever offers (off/1h/24h/7d). An exact allowlist, not a numeric
# range, matching CALL_REASON_ALLOWED's own precedent for a small enumerable
# protocol value set.
CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED = frozenset({0, 3600, 86400, 604800})

# Dedicated envelope ceiling — these are tiny schema-defined control frames
# (a handful of short strings), must not inherit the 6 MiB MAX_PACKET_SIZE_
# BYTES application-frame budget. Matches CALL_SIGNAL_CONTROL_MAX_PACKET_
# SIZE_BYTES's own reasoning for "to/call_id/reason/flags only"-sized
# control messages — generous headroom over any real payload here, orders
# of magnitude below MAX_PACKET_SIZE_BYTES.
CHAT_CONTROL_MAX_PACKET_SIZE_BYTES = 2 * 1024


def is_valid_chat_control_id(value) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= CHAT_CONTROL_ID_MAX_LEN


def is_valid_chat_control_signature(value) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= CHAT_CONTROL_SIGNATURE_MAX_LEN


# group_create roster schema bounds (S6-65, external review 2026-09-09) —
# server-side shape/bound validation only, NOT cryptographic verification
# (that stays each recipient client's job, against its own locally-trusted
# roster_signature check — see docs/SECURITY_INVARIANTS.md #78). No existing
# client-enforced group-size product limit to derive from (grepped
# CreateGroupScreen.kt) — this is a NEW resource-protection ceiling, generous
# relative to any plausible real membership, same "generous, not guessed"
# posture as FED_MAX_TO_LEN for a fingerprint-list-adjacent field.
GROUP_ROSTER_MAX_MEMBERS = 256


def validate_group_roster(members, admins, from_user):
    """Bounds/shape-validates group_create's members/admins (S6-65). Returns
    (members, admins) as brand-new lists (never the caller's original) on
    success, None if any check fails. Enforces current client semantics as
    SCHEMA, not as an authorization decision this server is making: every
    admin must also be a member (GroupManager.isAdmin() on both platforms
    already requires membership), and the sender must be both a member and
    an admin of the group they're creating/inviting into (createGroup()'s
    own allMembers/admins construction on both platforms always does this)."""
    if not isinstance(members, list) or not isinstance(admins, list):
        return None
    if not members or not admins:
        return None
    if len(members) > GROUP_ROSTER_MAX_MEMBERS or len(admins) > GROUP_ROSTER_MAX_MEMBERS:
        return None
    if not all(isinstance(m, str) and is_valid_fingerprint(m) for m in members):
        return None
    if not all(isinstance(a, str) and is_valid_fingerprint(a) for a in admins):
        return None
    if len(set(members)) != len(members) or len(set(admins)) != len(admins):
        return None
    if not set(admins).issubset(set(members)):
        return None
    if from_user not in members or from_user not in admins:
        return None
    return list(members), list(admins)


def sanitize_chat_control(msg_type: str, message: dict, from_user: str, target: str):
    """ONE canonical construction path for every relayed chat-control
    message (S6-53) — builds a BRAND NEW dict containing only the fields
    THIS exact msg_type's current protocol defines, instead of forwarding
    the caller's arbitrary dict verbatim. Returns None if ANY field fails
    validation — caller must treat that exactly like a malformed message
    (drop, no relay/store/forward, no limiter-key creation).

    `from_user` is dual-purpose by design (S6-53, STEP 9): for a LOCALLY
    originated message this is the authenticated connection's own username
    (mandatory, server-controlled, never caller-suppliable) — for an
    INCOMING federated_forward payload of one of these 3 types this is the
    peer-supplied `from` already fingerprint-shape-validated by
    validate_federated_forward_payload() one level up, passed through
    UNCHANGED (this function never overwrites a federated origin with a
    local identity). Either way `from_user`/`target` themselves are never
    read out of `message` — only the caller-controlled protocol fields are."""
    fields = validate_chat_control_fields(msg_type, message)
    if fields is None:
        return None
    return {"type": msg_type, "from": from_user, "to": target, **fields}


def validate_chat_control_fields(msg_type: str, message: dict):
    """FIELD-ONLY half of sanitize_chat_control() (split out S6-59, STEP 5)
    — validates every field THIS msg_type's protocol defines with no
    knowledge of or reference to sender/recipient identity, returning just
    those fields (or None if any fails/msg_type unrecognized). Exists so the
    anon_message relay path can apply this SAME bound — including S6-54's
    signature requirement for message_delete/group_message_delete — to a
    chat-control-typed payload it can already see (S6-59's routing-matrix
    finding: Desktop's unsealed seal-failure fallback can expose a visible
    `type`) without ever constructing or learning a `from`/`to` pair for it.
    sanitize_chat_control() above remains the sole place that adds
    authenticated sender identity, for the ordinary direct/federated path."""
    if msg_type in ("message_delete", "group_message_delete"):
        # message_id (Android) / id (Desktop) — the two real clients use
        # different field names for the same concept (grepped both send
        # paths); each independently bounded when present, at least one
        # required. Preserved as an alias pair rather than picked/renamed,
        # since S6-53 is patch-level hardening, not a protocol redesign —
        # collapsing them into one name would break whichever client uses
        # the other spelling today.
        message_id = message.get("message_id")
        raw_id = message.get("id")
        has_message_id = message_id is not None
        has_id = raw_id is not None
        if not has_message_id and not has_id:
            return None
        if has_message_id and not is_valid_chat_control_id(message_id):
            return None
        if has_id and not is_valid_chat_control_id(raw_id):
            return None

        out = {}
        if has_message_id:
            out["message_id"] = message_id
        if has_id:
            out["id"] = raw_id

        if msg_type == "group_message_delete":
            # group_id is the SAME UUID space call signaling's own
            # call_group_*/group_id already treats as a canonical UUID
            # (CreateGroupScreen.kt: groupId = UUID.randomUUID().toString())
            # — reuse is_valid_call_uuid() rather than duplicating the regex.
            group_id = message.get("group_id")
            if not is_valid_call_uuid(group_id):
                return None
            out["group_id"] = group_id

    elif msg_type == "disappear_timer":
        seconds = message.get("seconds")
        # bool is a subclass of int in Python — reject explicitly before the
        # isinstance(int) check (S6-53, STEP 3), same posture as
        # _is_valid_call_bool()'s own strict-type checks elsewhere.
        if isinstance(seconds, bool) or not isinstance(seconds, int):
            return None
        if seconds not in CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED:
            return None
        out = {"seconds": seconds}

    else:
        return None

    signature = message.get("signature")
    if msg_type in ("message_delete", "group_message_delete"):
        # Required, not merely bounded-if-present, as of S6-54 (external
        # review 2026-09-06) — STEP-11 of the S6-53 review found that
        # neither official client actually verified a delete command's
        # authorization on receive, and Desktop sent no signature at all for
        # either of these two types. Now that both clients sign and verify a
        # versioned transcript (SUBROSA_MESSAGE_DELETE_V1/
        # SUBROSA_GROUP_MESSAGE_DELETE_V1) before applying a deletion, an
        # unsigned delete command can no longer come from an up-to-date
        # official client — the server rejecting it here is defense-in-depth
        # against official infrastructure ever relaying one, NOT the
        # authorization boundary itself (this server has no reliable
        # E2EE-message-author semantics to verify against; that check only
        # exists client-side, against each client's own locally stored
        # message).
        if not is_valid_chat_control_signature(signature):
            return None
        out["signature"] = signature
    elif signature is not None:
        if not is_valid_chat_control_signature(signature):
            return None
        out["signature"] = signature

    return out


# Process-local byte budgets for RELAYED chat-control traffic (S6-53) —
# mirror call_signal_user_rate_ok()/call_signal_global_rate_ok()/
# call_signal_recipient_rate_ok() (S6-51) exactly, scaled down for a much
# smaller envelope ceiling (2 KiB here vs up to 96 KiB for SDP signaling).
# The count limit below (shared "chat_control" rate_limit_check bucket)
# protects message FREQUENCY; this protects aggregate BYTES, since a burst
# of group_message_delete fanout (up to CALL_GROUP_PEER_LIST_MAX_COUNT=50
# members, ~2 KiB each) is the realistic legitimate ceiling this needs
# headroom over. Accounted ONCE, from the exact sanitized relay payload,
# and only for a message actually about to be relayed to an ONLINE
# recipient — an offline target never costs any egress.
CHAT_CONTROL_USER_MAX_BYTES       = int(os.environ.get("CHAT_CONTROL_USER_MAX_BYTES", str(256 * 1024)) or str(256 * 1024))
CHAT_CONTROL_USER_WINDOW_SEC      = 10
chat_control_user_rate: dict = {}   # username -> {"bytes": int, "reset_time": float}


def chat_control_user_rate_ok(username: str, nbytes: int) -> bool:
    now = time.time()
    entry = chat_control_user_rate.get(username)
    if not entry or now - entry["reset_time"] >= CHAT_CONTROL_USER_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        chat_control_user_rate[username] = entry
    if entry["bytes"] + nbytes > CHAT_CONTROL_USER_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


CHAT_CONTROL_GLOBAL_MAX_BYTES  = int(os.environ.get("CHAT_CONTROL_GLOBAL_MAX_BYTES", str(2 * 1024 * 1024)) or str(2 * 1024 * 1024))
CHAT_CONTROL_GLOBAL_WINDOW_SEC = 10
chat_control_global_rate = {"bytes": 0, "reset_time": time.time()}


def chat_control_global_rate_ok(nbytes: int) -> bool:
    now  = time.time()
    data = chat_control_global_rate
    if now - data["reset_time"] >= CHAT_CONTROL_GLOBAL_WINDOW_SEC:
        data["bytes"]      = 0
        data["reset_time"] = now
    if data["bytes"] + nbytes > CHAT_CONTROL_GLOBAL_MAX_BYTES:
        return False
    data["bytes"] += nbytes
    return True


# Per-recipient ingress budget — same reasoning as CALL_SIGNAL_RECIPIENT_
# MAX_BYTES's own comment: the sender/global budgets protect server
# capacity, but many Sybil senders could otherwise each spend their own
# individual allowance against the SAME online victim. Keyed only by a
# genuinely-online recipient username.
CHAT_CONTROL_RECIPIENT_MAX_BYTES  = int(os.environ.get("CHAT_CONTROL_RECIPIENT_MAX_BYTES", str(128 * 1024)) or str(128 * 1024))
CHAT_CONTROL_RECIPIENT_WINDOW_SEC = 10
chat_control_recipient_rate: dict = {}   # recipient username -> {"bytes": int, "reset_time": float}


def chat_control_recipient_rate_ok(recipient_username: str, nbytes: int) -> bool:
    now = time.time()
    entry = chat_control_recipient_rate.get(recipient_username)
    if not entry or now - entry["reset_time"] >= CHAT_CONTROL_RECIPIENT_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        chat_control_recipient_rate[recipient_username] = entry
    if entry["bytes"] + nbytes > CHAT_CONTROL_RECIPIENT_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


# ─── Sender Certificate Signing Key (Sealed Sender, шаг 1) ────────────────────
# Сервер подписывает короткоживущий сертификат, связывающий аутентифицированный
# fingerprint с его identity-ключом (request_sender_cert). Получатель проверяет
# подпись по этому публичному ключу сервера (пиннится в клиенте) и узнаёт, кто
# реально отправил sealed-конверт — сам сервер при этом не обязан знать, кто
# отправил конкретное anon_message (это отдельный, ещё не сделанный шаг —
# de-identified канал отправки, см. docs/TODO.md). Отдельный ключ от TLS —
# подписывает данные приложения, а не транспорт.
SENDER_CERT_TTL_SEC = 24 * 3600  # 24ч — короткоживущий, клиент обновляет заранее до истечения


def _load_or_create_cert_signing_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend

    key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets")
    os.makedirs(key_dir, exist_ok=True)
    key_path = os.path.join(key_dir, "sender_cert_signing_key.pem")

    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    else:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_path, "wb") as f:
            f.write(pem)
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass
        print(f"[SENDER_CERT] Новый ключ подписи сертификатов сгенерирован: {key_path}")

    public_key  = private_key.public_key()
    public_der  = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_b64 = base64.b64encode(public_der).decode()
    print(f"[SENDER_CERT] Публичный ключ сервера (запиньте в клиенте): {public_b64}")
    return private_key, public_b64


SENDER_CERT_PRIVATE_KEY, SENDER_CERT_PUBLIC_KEY_B64 = _load_or_create_cert_signing_key()

# ─── Anonymous Token Routing ──────────────────────────────────────────────────
# Каждый клиент подписывается на набор случайных токенов (subscribe_tokens).
# Отправитель адресует сообщение по токену (anon_message), а не по fingerprint.
# Сервер не знает кому принадлежит токен — только какой WebSocket его слушает.
token_to_ws:  dict = {}   # token (str) → websocket
token_pending: dict = {}  # token (str) → list[dict]  (очередь для офлайн-клиентов)
token_pending_created: dict = {}  # token (str) → time.time() когда встал в очередь (для TTL)
# token (str) → exact accounted serialized byte size of the queued delivery
# — external review 2026-09-04, S6-30 (see TOKEN_PENDING_MAX_TOTAL_BYTES's
# own comment). Written only by _token_pending_commit_reserved_locked(),
# read/removed only by _token_pending_remove_locked() — never touched
# directly anywhere else.
token_pending_sizes: dict = {}
ws_to_tokens: dict = {}   # websocket → set[str]       (для очистки при дисконнекте)
known_tokens: set  = set() # токены, которые хоть раз были зарегистрированы (фейки дропаем)
# Отдельно от known_tokens (external review 2026-08-23): known_tokens никогда
# не чистится, поэтому один и тот же токен, уже доставленный и подтверждённый
# anon_delivery_ack, всё ещё проходил "is_known" и принимался как настоящий
# при повторной отправке — тихо перезаписывая token_pending[token] вместо
# отказа. Разделено на "known" (когда-либо реальный, для отличия от decoy) и
# "spent" (уже доставлен, больше не принимать) — то же самое дерево причин,
# что двойная трата на клиенте (AnonTokenManager), просто на другом конце.
spent_tokens: set = set()
# token (str) → username of whoever FIRST subscribed to it. Found live
# 2026-09-03 (external review): subscribe_tokens used to have no concept of
# permanent ownership at all — token_to_ws only tracked the CURRENTLY live
# connection, so a token was only protected from reassignment while its
# original owner happened to be online. A token is known not just to its
# owner but to every contact it was ever handed to (that's the whole point —
# they use it to address anon_message at the owner) — so the moment the
# owner disconnected, anyone who knew the token (a contact it was shared
# with, honest or not) could subscribe_tokens to it themselves, hijacking
# delivery routing meant for the real owner. E2EE still protects the
# message CONTENT even if it lands on a hijacker's connection (the payload
# is sealed to the real owner's identity key, not decryptable by whoever
# grabbed the routing slot) — but the real owner never receives it, and the
# hijacker can still send a valid-looking anon_delivery_ack for a message
# they can't even read, so the sender believes delivery succeeded. This dict
# is deliberately NOT cleared on disconnect (only token_to_ws/ws_to_tokens
# are) — see the subscribe_tokens/disconnect-cleanup/unsubscribe_tokens
# handlers below — so the real owner can always reclaim the token on
# reconnect and nobody else ever can.
# UPDATED 2026-09-03: this dict (and spent_tokens above) is now just a fast
# RAM cache in front of the anon_token_state SQLite table — see
# db_claim_anon_tokens()/db_terminalize_anon_token() and
# anon_token_state's own comment in _db_setup_sync(). The DB is the durable
# source of truth precisely so a server restart no longer resets ownership —
# these dicts exist purely so the hot subscribe_tokens/anon_message paths
# don't need a DB round-trip for every single already-resolved token.
token_owner: dict = {}
# Bootstrap-address reservation (pick_bootstrap_token(), used by
# get_prekey_bundle/get_prekey_bundles_batch to hand a requester one of
# target's tokens for a fresh X3DH bootstrap) went through three RAM-only
# and DB-durable-but-global iterations before landing on its current,
# fully DB-authoritative shape — see anon_token_state's bootstrap_reserved/
# bootstrap_reserved_by columns in _db_setup_sync() and
# db_resolve_bootstrap_token()/pick_bootstrap_token()'s own comments for
# the full history and final per-(target, requester) design. Unlike
# token_owner/spent_tokens/anon_token_state_cache above, there is no RAM
# mirror of bootstrap reservation state anymore (a prior version,
# bootstrap_reserved_hashes, was removed 2026-09-03 round 5): once
# reservation became per-requester rather than a single global "is this
# token reserved at all" flag, a coarse RAM boolean couldn't answer "does
# THIS requester already have one" without a DB round-trip anyway, so the
# RAM shortcut stopped paying for itself — and unlike anon_message's
# unauthenticated anon_channel hot path, get_prekey_bundle/
# get_prekey_bundles_batch are authenticated and already rate-limited
# (prekey_fetch), so a DB call per request isn't the DoS surface a RAM
# cache exists to close elsewhere in this file.
# sha256(token) bytes → (owner, state) — full in-memory index of
# anon_token_state, loaded once at startup (_db_load_anon_token_state_sync,
# see start_server()) and kept in sync on every write
# (db_claim_anon_tokens()/db_terminalize_anon_token()). Found live
# 2026-09-03 (external review, DoS angle): anon_message's "is this a real
# token or cover-traffic noise" check for a RAM-cache miss used to fall back
# to a per-token SQLite SELECT (db_get_anon_token_state) — but anon_channel
# is unauthenticated and its only real limit is per-connection
# (ANON_CHANNEL_MAX_PER_MINUTE), not global, so an attacker opening many
# such connections and sending random 32-char strings as "tokens" could
# turn every single one into a thread-pool DB round-trip, at a rate this
# process doesn't otherwise defend against. A decoy/fake token was
# previously a pure O(1) RAM lookup that immediately said "no" — this index
# restores that property while still surviving a restart: SHA-256 the
# candidate, one dict lookup, done, no disk touched on the hot rejection
# path. SQLite (anon_token_state) remains the actual source of truth for
# every WRITE (claim/terminalize) — this is a read index only, never
# written to independently of a successful DB write.
anon_token_state_cache: dict = {}

# ─── PERF-02 (2026-11-03): subscribe_tokens tail latency ──────────────────────
#
# Measured problem (Server/stress/bench_token_claim.py, and the live
# bench_throughput.py subscribe_tokens scenario): p50 1.44 ms but p95 205 ms,
# p99 990 ms, max 1 208 ms at 20 concurrent claimers. The cause is NOT work
# inside the transaction — it is SQLite's busy-handler backoff.
# _db_claim_anon_tokens_sync() opens BEGIN IMMEDIATE, which takes a
# DATABASE-WIDE write lock, and SQLite's default busy handler does not queue
# fairly: it sleeps the loser on a fixed escalating schedule (1, 2, 5, 10, 15,
# 20, 25, 25, 25, 50, 50, 100 ms, ...) and retries. Under N-way contention a
# caller accumulates hundreds of milliseconds of SLEEP even though every
# transaction itself takes microseconds. Proof: a batch where every token is
# already known writes nothing and has a 0.06 ms p50, yet still measured
# 871 ms p99 under 20-way contention.
#
# Why that matters beyond this one message type: every durable call in this
# file reaches SQLite through loop.run_in_executor(None, ...), i.e. the default
# ThreadPoolExecutor (min(32, cpu+4) threads — only 6 on a 2-vCPU VPS). A
# claim sleeping in the busy handler OCCUPIES one of those threads for the
# whole sleep, so subscribe_tokens contention starves the pool for every other
# durable operation: register(), TOTP verification, prekey consumption,
# offline-message store. A reconnect burst (subscribe_tokens fires on every
# reconnect, legitimately 80-100 tokens split across MAX_TOKENS_PER_SUBSCRIBE
# -sized calls) is enough to trigger it — no attacker required.
#
# Fix, in two halves that only work together (measured: either half alone is
# worse than useless — the lock alone regresses p50 19x, 5.31 -> 102 ms, and
# the COUNT(*) skip alone barely moves anything because while the busy handler
# thrashes the transaction's duration is irrelevant). Together: 104 -> ~4 500
# claim-tx/s and p99 1 633 -> ~5 ms.
#
#   (1) THIS LOCK serialises EVERY anon_token_state writer in the application
#       so SQLite's busy handler never engages at all. Callers queue FIFO on an
#       asyncio lock — suspended coroutines, not blocked executor threads —
#       instead of fighting over the database write lock and sleeping on
#       backoff. It is held by exactly three wrappers:
#       db_claim_anon_tokens(), db_mark_anon_token_inflight() and
#       db_terminalize_anon_token().
#
#       ONE shared lock for all three, not one per path — measured, not
#       assumed (Server/stress/bench_anon_write_paths.py, mixed load: 20
#       senders doing mark_inflight+terminalize pairs alongside 4 claimers
#       doing 100-token batches, 200 000 pre-existing rows):
#
#         arrangement                     send/s  send p99  claim p99  WORST
#         no app lock (pre-PERF-02)          281   1198 ms    1090 ms  1198 ms
#         claim lock only (PERF-02)          347    864 ms     447 ms   864 ms
#         two separate locks                 769     23 ms     558 ms   558 ms
#         ONE shared lock  (chosen)          786     52 ms      52 ms    52 ms
#
#       Two separate locks give the send path a better tail in isolation
#       (23 vs 52 ms) but RE-BREAK claims to 558 ms, because a claim and a
#       send can then still collide at the SQLite level and the long claim
#       transaction is the one that loses the backoff lottery. One shared lock
#       costs the hot path ~29 ms at p99 and buys a 10x improvement for
#       claims, flattening both paths to ~52 ms. Judged on the worst p99
#       across both paths — the metric that actually bounds user-visible
#       latency — shared wins 52 ms vs 558 ms, at identical throughput.
#
#       Deliberately a SEPARATE lock from the global RAM `lock`: invariant 34
#       (SECURITY_INVARIANTS.md) forbids awaiting a blocking DB call while the
#       global lock is held. Note the ordering discipline that makes this
#       safe: this lock is acquired ONLY inside the three db_* wrappers, and
#       db_claim_anon_tokens() takes it strictly AFTER its own `async with
#       lock:` block has exited. So this lock is never held while the global
#       lock is acquired, in any path — there is no nesting to invert and no
#       deadlock to reason about. A future caller that already holds the
#       global lock can therefore call any of the three wrappers safely.
#       federation_dedup_lock is the existing precedent for a narrow,
#       purpose-specific module-level lock alongside the global one.
#
#       Throughput headroom to keep an eye on: the serialised ceiling measured
#       786 send/s here, against ~570 anon_message/s observed end-to-end at 40
#       concurrent clients — and the real path does its JSON/WebSocket work
#       outside the lock, so the lock is not the binding constraint today.
#       It is a ceiling that scales linearly with transaction duration, so
#       re-measure if the deployment grows substantially.
#
#       PER-PROCESS caveat, same as every RAM-only limiter in this file (see
#       access_code_global_rate's comment): this serialises within one process.
#       A multi-process deployment sharing one DB file still gets correct
#       atomicity from BEGIN IMMEDIATE — nothing about correctness depends on
#       this lock — it just loses the tail benefit for cross-process contention.
#
#   (2) The ANON_TOKEN_ROWS_HINT_MARGIN skip below removes the O(table-size)
#       `SELECT COUNT(*) FROM anon_token_state` from the common case. Note what
#       this deliberately does NOT do: it does not replace the authoritative
#       count with a maintained counter. An earlier draft of this fix proposed
#       exactly that, and it was rejected — a counter seeded wrongly during an
#       upgrade (e.g. 0 on a database with 1.9M rows) would silently disable
#       ANON_TOKEN_STATE_MAX_TOTAL_ROWS, i.e. fail OPEN on a disk/RAM
#       exhaustion guard, and no existing test would catch it because every
#       test runs against a fresh temp DB. Instead the real in-transaction
#       COUNT(*) remains the gate and is still executed whenever the table is
#       anywhere near the ceiling; it is merely skipped when the RAM mirror
#       proves we are far below it. Worst case if the hint is wrong high: we
#       run the COUNT, i.e. exactly the old behaviour. No schema change, no
#       migration, no new failure mode.
#       IMPLEMENTATION NOTE — why this is a per-loop registry and not a plain
#       module-level `asyncio.Lock()`. A module-level Lock binds itself to an
#       event loop LAZILY, on the first *contended* acquire: `Lock.acquire()`
#       has a fast path that returns without ever calling `_get_loop()` when
#       the lock is free, so an uncontended lock never binds at all. That is
#       why the global `lock` above has survived as a module-level object —
#       it is essentially never contended inside a single test. This lock IS
#       contended by design, and pytest-asyncio gives every test its own loop,
#       so a plain module-level Lock gets bound by whichever test first
#       contends it and then raises `RuntimeError: ... is bound to a different
#       event loop` for every later test — and worse, is left permanently
#       `[locked]` because the coroutine holding it died with its loop. Found
#       by test_subscribe_parallel_claims_cannot_exceed_cap_or_double_charge,
#       which fires parallel claims on purpose. Keyed on the running loop in a
#       WeakKeyDictionary so entries disappear when a loop is collected
#       (production has exactly one loop for the process's lifetime; the test
#       suite churns through one per test and leaks nothing). This mirrors the
#       pattern already used for totp_state_locks/avatar_mutation_locks/
#       pending_flush_locks/prekey_mutation_locks — on-demand lock registries
#       rather than import-time Lock objects.
_anon_token_write_locks: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def anon_token_write_lock() -> asyncio.Lock:
    """The one lock serialising every anon_token_state writer, for the
    currently-running event loop. See the comment block above."""
    loop = asyncio.get_running_loop()
    lk = _anon_token_write_locks.get(loop)
    if lk is None:
        lk = asyncio.Lock()
        _anon_token_write_locks[loop] = lk
    return lk

# How much slack to leave before trusting len(anon_token_state_cache) as a
# row-count lower bound. The cache is a strict full mirror of anon_token_state
# (loaded in full at startup, written on every state change, never evicted —
# and the table is append-only, there is no DELETE FROM anon_token_state
# anywhere in this file), so the only way it can UNDERCOUNT is a row committed
# by a claim that has not yet written its cache entry. With (1) above that is
# bounded by one in-flight claim, i.e. at most MAX_TOKENS_PER_SUBSCRIBE (100)
# rows. 10 000 is a 100x margin on that, and 0.5% of the 2 000 000-row default
# ceiling — deliberately not derived from MAX_TOKENS_PER_SUBSCRIBE so that
# removing the lock in (1) later cannot silently shrink the safety margin to
# the point where the skip becomes unsound.
ANON_TOKEN_ROWS_HINT_MARGIN = 10_000
# Lifecycle rank, ACTIVE < IN_FLIGHT < {SPENT, REVOKED} — added 2026-09-04
# (external review) alongside subscribe_tokens's own comment on the guard
# this backs: a token's state in anon_token_state_cache must never be
# overwritten by a rank going BACKWARDS, not just "non-terminal over
# terminal" as the guard originally only checked. SPENT and REVOKED share
# a rank (both terminal, interchangeable for this purpose — see the
# guard's own comment on why overwriting one with the other is a no-op,
# not a downgrade).
ANON_TOKEN_STATE_RANK = {"ACTIVE": 0, "IN_FLIGHT": 1, "SPENT": 2, "REVOKED": 2}

# ─── Anonymous-token durable-state resource hardening (external review ────────
# 2026-09-05, S6-44) ────────────────────────────────────────────────────────
# subscribe_tokens is additive and, before this fix, had no cap at all on how
# many DISTINCT never-before-seen tokens one authenticated account could turn
# into permanent anon_token_state rows: MAX_TOKENS_PER_SUBSCRIBE (100) times
# the "subscribe_tokens" rate limit (10/min) = up to 1000 brand-new durable
# rows/minute, ~1.44 million/day, from a single account sending no real
# messages at all. Since anon_token_state_cache mirrors the ENTIRE table in
# RAM (see its own comment — that's a deliberate DoS defense for the
# unauthenticated anon_channel hot path, not something this patch touches),
# unbounded durable growth is also unbounded startup/live RAM growth. Four
# independent limits close this, each aimed at a different attack shape:
#
#   MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT bounds one account's INSTANTANEOUS
#   footprint (how many ACTIVE/IN_FLIGHT rows it can own at once);
#
#   ANON_TOKEN_NEW_CLAIM_WINDOW_SEC/MAX_PER_WINDOW bounds one account's
#   SUSTAINED new-row issuance rate even across claim→unsubscribe(REVOKED)→
#   reclaim cycling, which the active cap alone doesn't stop (each cycle
#   frees active capacity but still mints a fresh permanent tombstone);
#
#   ANON_TOKEN_GLOBAL_CLAIM_LIMIT/WINDOW_SEC bounds AGGREGATE server-wide
#   claim-capable requests before they ever reach the executor/SQLite,
#   closing the Sybil angle (many accounts, each individually under quota);
#
#   ANON_TOKEN_STATE_MAX_TOTAL_ROWS is the final hard backstop on the whole
#   table regardless of account count — see its own comment for why this
#   does NOT mean rows are ever deleted to enforce it.
#
# Client pool sizing (inspected 2026-09-05, revised 2026-09-20 — Android's
# AnonTokenManager.kt, Desktop's AnonTokenManager.kt): both maintain exactly
# ONE "my tokens" pool per installation (subscribed via subscribe_tokens),
# target size POOL_SIZE=50, topped up only when below POOL_SIZE/2, with a
# client-side safety-valve ceiling MAX_POOL_HARD_CAP=500. Originally pinned
# at exactly this server's MAX_TOKENS_PER_SUBSCRIBE (100) so a full pool
# still fit in one subscribe_tokens call — found live 2026-09-20 that real
# call+chat traffic routinely pushes a single contact's resupply past 100
# within minutes (2-3 BATCH_TO_SHARE=20 batches landing before consumption
# catches up, e.g. right after a post-call forced reconnect), and every hit
# of that ceiling silently dropped still-outstanding tokens client-side
# BEFORE they ever reached a subscribe_tokens call at all. Both clients now
# split an oversized subscribe_tokens payload into multiple ≤100-token calls
# instead (this server's [:MAX_TOKENS_PER_SUBSCRIBE] slice was silently
# dropping the tail of any single call sent over the limit, with no error
# back to the client — the actual mechanism that caused the historical
# ~100-150 estimate below to be exceeded in practice). A legitimate single
# installation can now carry up to ~500-550 simultaneous ACTIVE/IN_FLIGHT
# tokens (pool + a small ack-pending overlap), spread across as many
# subscribe_tokens calls as needed — well within
# MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT's headroom. Multiple AUTHORIZED DEVICES
# per account are a real, separately supported flow
# (MAX_AUTHORIZED_DEVICES_PER_ACCOUNT=32, S6-37) — each device keeps its OWN
# local pool under the SAME account fingerprint (identity keys, and thus
# `username`, are shared across a user's own devices; token pools are not),
# so the true worst-case LEGITIMATE simultaneous footprint for one account is
# bounded by roughly device_count × ~550, not a single device's ~550 alone.
MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = int(os.environ.get("MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT", "5000") or "5000")
if MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT <= 0:
    print("[FATAL] MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT должен быть > 0 (обязательная защита "
          "процесса/диска от неограниченного роста на один аккаунт, а не отключаемая опция) — "
          "отказ запуска.", flush=True)
    sys.exit(1)

# Durable per-owner NEW-token issuance quota — closes the claim→revoke→
# reclaim cycling gap the active cap alone leaves open (see this section's
# own intro comment). A single legitimate top-up event mints at most
# MAX_POOL_HARD_CAP (100) brand-new tokens (a from-scratch pool, the largest
# single burst either client ever produces); 300 per 10 minutes comfortably
# covers that PLUS a second device (or a retried top-up) landing in the same
# window, while still bounding one account's sustained issuance rate to a
# small fraction of the original unbounded one (1000/minute).
ANON_TOKEN_NEW_CLAIM_WINDOW_SEC     = int(os.environ.get("ANON_TOKEN_NEW_CLAIM_WINDOW_SEC", "600") or "600")
ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = int(os.environ.get("ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW", "300") or "300")
if ANON_TOKEN_NEW_CLAIM_WINDOW_SEC <= 0 or ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW <= 0:
    print("[FATAL] ANON_TOKEN_NEW_CLAIM_WINDOW_SEC и ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW должны "
          "быть > 0 (обязательная защита от циклов claim→revoke→reclaim, а не отключаемая "
          "опция) — отказ запуска.", flush=True)
    sys.exit(1)

# Process-wide pre-SQLite request budget for subscribe_tokens calls that
# COULD create new state (checked in db_claim_anon_tokens(), before the
# executor hop) — same "reject for free before paying for the check" posture
# as OFFLINE_STORE_GLOBAL_LIMIT/global_prekey_publish_rate_ok(); protects the
# executor/SQLite from an aggregate flood across many Sybil accounts, each
# individually under its own per-owner quota above. 0 = explicitly disabled,
# same convention as every other RAM-only limiter in this file.
ANON_TOKEN_GLOBAL_CLAIM_LIMIT = int(os.environ.get("ANON_TOKEN_GLOBAL_CLAIM_LIMIT", "300") or "300")
if ANON_TOKEN_GLOBAL_CLAIM_LIMIT < 0:
    print("[FATAL] ANON_TOKEN_GLOBAL_CLAIM_LIMIT должен быть >= 0 (0 явно отключает агрегатный "
          "лимитер claim-запросов anon-токенов) — отказ запуска, чтобы не работать с "
          "неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
ANON_TOKEN_GLOBAL_CLAIM_ENABLED    = ANON_TOKEN_GLOBAL_CLAIM_LIMIT > 0
ANON_TOKEN_GLOBAL_CLAIM_WINDOW_SEC = 60
anon_token_global_claim_rate = {"count": 0, "reset_time": time.time()}


def anon_token_global_claim_rate_ok() -> bool:
    """Mirrors global_offline_store_rate_ok()'s own reasoning exactly (see
    its comment) — no `await` here, so the check-and-increment is atomic on
    this single event loop. Process-local, same caveat as every other
    RAM-only limiter in this file."""
    if not ANON_TOKEN_GLOBAL_CLAIM_ENABLED:
        return True
    now  = time.time()
    data = anon_token_global_claim_rate
    if now - data["reset_time"] >= ANON_TOKEN_GLOBAL_CLAIM_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= ANON_TOKEN_GLOBAL_CLAIM_LIMIT:
        return False
    data["count"] += 1
    return True

# Hard total row ceiling — the final disk/RAM safety backstop, independent of
# account count (a Sybil attacker creating many under-quota accounts would
# otherwise still add up to unbounded aggregate growth). Because
# anon_token_state_cache mirrors this entire table, this cap is also a real
# upper bound on startup/live RAM consumed by that cache — see
# _db_load_anon_token_state_sync()'s own comment. 2,000,000 is generous for
# this deployment class (self-hosted/small-business, not a mass-market
# service — see docs/SCENARIOS.md) — each row is small (a 32-byte hash plus
# a few short columns, no payload blob), and unlike pending_messages this
# table is NOT self-pruning (SPENT/REVOKED rows are durable tombstones,
# never deleted — see this constant's own startup-check comment in
# start_server() for why), so the ceiling has to accommodate legitimate
# ACTIVE footprint across every account PLUS whatever tombstones accumulate
# over the deployment's actual lifetime, not just a snapshot of current use.
ANON_TOKEN_STATE_MAX_TOTAL_ROWS = int(os.environ.get("ANON_TOKEN_STATE_MAX_TOTAL_ROWS", "2000000") or "2000000")
if ANON_TOKEN_STATE_MAX_TOTAL_ROWS <= 0:
    print("[FATAL] ANON_TOKEN_STATE_MAX_TOTAL_ROWS должен быть > 0 (обязательный потолок "
          "диска/RAM для anon_token_state и его полнотабличного RAM-кэша, а не отключаемая "
          "опция) — отказ запуска.", flush=True)
    sys.exit(1)

TOKEN_PENDING_TTL_SEC = 24 * 3600

# ─── Hard process-wide bound on token_pending RAM (external review ─────────────
# 2026-09-04, S6-30). TOKEN_PENDING_TTL_SEC above bounds how LONG a single
# entry can sit in RAM, but nothing previously bounded how MUCH RAM the
# WHOLE of token_pending could hold at once: a valid, authenticated
# subscriber's token can hold one potentially-large anon_delivery in RAM
# from the moment a sender fires anon_message until either
# anon_delivery_ack or the 24h TTL sweep. Many valid, live tokens therefore
# produce bounded retention TIME per entry but UNBOUNDED PEAK RAM in
# aggregate — TTL alone never caps how many entries can be in flight
# simultaneously. This is the same class of gap S6-29 (mailbox) closed for
# the anonymous mailbox, applied here to anonymous-token pending delivery.
#
# Deliberately a PATCH-LEVEL resource bound, not a protocol redesign: the
# one-token/one-message semantics, the 24h TTL, ACK semantics, RAM-only
# (never persisted) payload retention, the sealed-payload wire format, and
# anon_channel's identity-less authentication model are all UNCHANGED by
# this fix — only whether/when a queued delivery is admitted to RAM at all
# is new.
#
# Both required to be strictly positive, same posture as the mailbox caps
# — a hard, always-on process-protection bound, not an optional knob a
# deployment might reasonably disable; a misconfigured value refuses to
# start the server rather than silently running unbounded.
TOKEN_PENDING_MAX_TOTAL_BYTES = int(os.environ.get("TOKEN_PENDING_MAX_TOTAL_BYTES", str(128 * 1024 * 1024)))
TOKEN_PENDING_MAX_TOTAL_ITEMS = int(os.environ.get("TOKEN_PENDING_MAX_TOTAL_ITEMS", "5000"))
if TOKEN_PENDING_MAX_TOTAL_BYTES <= 0 or TOKEN_PENDING_MAX_TOTAL_ITEMS <= 0:
    print("[FATAL] TOKEN_PENDING_MAX_TOTAL_BYTES и TOKEN_PENDING_MAX_TOTAL_ITEMS должны быть > 0 "
          "(это обязательная защита процесса от OOM, а не отключаемая опция) — "
          "отказ запуска.", flush=True)
    sys.exit(1)

# Exact running totals for entries actually COMMITTED to token_pending —
# maintained incrementally by the canonical helpers below, never
# recomputed by summing token_pending itself.
token_pending_total_bytes = 0
token_pending_total_items = 0

# Capacity already PROMISED to a coroutine that passed the RAM admission
# check but is currently awaiting the durable ACTIVE→IN_FLIGHT SQLite
# transition (db_mark_anon_token_inflight) — see
# _token_pending_try_reserve_locked()'s own comment for why this two-phase
# reserve-then-commit shape exists at all (ordering: never burn a
# still-ACTIVE token just because the RAM queue happened to be full for a
# moment; never let two concurrent admissions both believe they got the
# last slot). A reservation is always either committed (moved into the
# totals above) or explicitly released — never left dangling; see
# anon_message's own comment on the try/finally-equivalent bookkeeping
# this requires.
token_pending_reserved_bytes = 0
token_pending_reserved_items = 0


def _token_pending_try_reserve_locked(size: int) -> bool:
    """Admission check for ONE prospective token_pending entry — MUST be
    called with `lock` already held, and MUST run BEFORE
    db_mark_anon_token_inflight() ever runs for the same message (external
    review 2026-09-04, S6-30). This ordering is the whole point: reserving
    RAM capacity first, atomically, means a capacity-full rejection never
    burns an otherwise-still-ACTIVE token — the token is left completely
    untouched (still ACTIVE, still spendable by a retry) rather than
    transitioning it to IN_FLIGHT and only then discovering there was
    nowhere to actually queue the payload.

    Counts both already-COMMITTED totals and any RESERVED-but-not-yet-
    committed capacity from other in-flight admissions racing this one —
    two concurrent anon_message calls that would collectively overflow the
    cap can never both believe they got the last slot, even though neither
    has committed anything to token_pending yet at the moment this runs.

    On success, increments the reservation counters exactly once and
    returns True — caller now owns exactly one reservation of `size` bytes
    that MUST later be resolved via exactly one of
    _token_pending_commit_reserved_locked() or
    _token_pending_release_reservation_locked(), never both, never
    neither."""
    global token_pending_reserved_bytes, token_pending_reserved_items
    if (token_pending_total_bytes + token_pending_reserved_bytes + size > TOKEN_PENDING_MAX_TOTAL_BYTES
            or token_pending_total_items + token_pending_reserved_items + 1 > TOKEN_PENDING_MAX_TOTAL_ITEMS):
        return False
    token_pending_reserved_bytes += size
    token_pending_reserved_items += 1
    return True


def _token_pending_release_reservation_locked(size: int) -> None:
    """Releases exactly one previously-successful
    _token_pending_try_reserve_locked(size) reservation without committing
    it — MUST be called with `lock` already held. Used whenever a
    reservation was taken but the corresponding token_pending entry must
    NOT actually be created after all (the DB ACTIVE→IN_FLIGHT claim
    failed, a concurrent terminalize won the race, or an
    exception/cancellation interrupted the coroutine holding the
    reservation — see anon_message's own comment on the
    try/finally-equivalent bookkeeping this requires). Never call this
    twice for the same reservation, and never call it for a reservation
    that was already committed — either would double-release capacity that
    was only ever promised once."""
    global token_pending_reserved_bytes, token_pending_reserved_items
    token_pending_reserved_bytes -= size
    token_pending_reserved_items -= 1


def _token_pending_commit_reserved_locked(token: str, delivery_obj: dict, size: int) -> None:
    """Converts exactly one previously-successful
    _token_pending_try_reserve_locked(size) reservation into a real,
    committed token_pending entry — MUST be called with `lock` already
    held, and only ever after the durable ACTIVE→IN_FLIGHT SQLite
    transition for this exact token has already succeeded (and, per the
    existing terminal-state race check, has not since been overtaken by a
    concurrent SPENT/REVOKED transition). Moves `size` from the reserved
    counters to the committed totals — the reservation this consumes must
    not also be released via _token_pending_release_reservation_locked()."""
    global token_pending_reserved_bytes, token_pending_reserved_items
    global token_pending_total_bytes, token_pending_total_items
    token_pending[token] = [delivery_obj]
    token_pending_created[token] = time.time()
    token_pending_sizes[token] = size
    token_pending_reserved_bytes -= size
    token_pending_reserved_items -= 1
    token_pending_total_bytes += size
    token_pending_total_items += 1


def _token_pending_remove_locked(token: str):
    """THE single canonical removal path for a committed token_pending
    entry — MUST be called with `lock` already held. Every direct
    `token_pending.pop(...)`/`token_pending_created.pop(...)` pair
    anywhere in this file (anon_delivery_ack, unsubscribe_tokens,
    token_pending_watchdog) was replaced with a call to this function
    (external review 2026-09-04, S6-30) — a direct pop correctly removed
    the entry but never decremented token_pending_total_bytes/
    token_pending_total_items, so the accounting would drift further from
    reality with every single ACK/revoke/expiry, eventually making the
    hard cap either falsely permanent (stuck believing the queue is full
    when it's actually empty) or, if the drift went the other way, no cap
    at all.

    No-op (and does NOT touch the counters at all) if `token` doesn't
    actually have a committed entry — removing a token that already isn't
    pending must never underflow the totals. Returns the removed
    `token_pending[token]` list if the caller finds it useful (currently
    unused by any caller, kept for symmetry/future use), or None if there
    was nothing to remove."""
    global token_pending_total_bytes, token_pending_total_items
    if token not in token_pending:
        token_pending_created.pop(token, None)
        token_pending_sizes.pop(token, None)
        return None
    removed = token_pending.pop(token)
    token_pending_created.pop(token, None)
    size = token_pending_sizes.pop(token, 0)
    token_pending_total_bytes -= size
    token_pending_total_items -= 1
    return removed


# ─── Anonymous delivery envelope/budget bounds (S6-59, external review ────────
# 2026-09-06) — STEP-1 of this fix's own investigation built the actual
# routing matrix (every producer of anon_message on both clients, grepped,
# not assumed) and found that essentially ALL 1:1-addressed protocol traffic
# in the current shipped apps — message, session_init, reaction, edit,
# message_delete/disappear_timer/group_message_delete, voice, image_chunk/
# video_chunk/file_chunk, and every 1:1 call_* signaling type — routes
# through sendAnonOrDirect(), which SEALS the packet (hybrid-encrypts the
# whole thing, opaque to the server) before wrapping it as anon_message's
# `payload`. Only GROUP calls (call_group_*, Android-only) bypass anon
# routing entirely. This means S6-49 (media chunks)/S6-51 (call signaling)/
# S6-53 (chat controls)/S6-57 (voice)'s own server-side per-type sanitizers
# — each of which only guards the BARE/direct handler for that type — never
# actually run for this real production traffic: `anon_message` accepted a
# `payload` dict with NO size bound of its own beyond the aggregate
# TOKEN_PENDING_MAX_TOTAL_BYTES RAM cap above (which bounds total RETAINED
# memory, not the size of any ONE admitted request) and the generic
# MAX_PACKET_SIZE_BYTES transport ceiling every message type already shares.
# Client-side bounds from those same S6 fixes remain fully effective (they
# run after the RECIPIENT unseals the packet), so this is a server-side
# resource-boundary gap, not a reopening of any client-side fix.
#
# ANON_PAYLOAD_MAX_BYTES is sized from the actual largest legitimate
# anonymous payload today, not guessed: a maximum-length voice message
# (VOICE_DATA_MAX_LEN = 4 MiB, S6-57) sealed via sealPacketForRecipient()'s
# own hybrid-encrypt-the-whole-packet-then-base64 step adds roughly another
# 4/3 expansion plus ~1.2 KB fixed overhead on top of the ~4 MiB+few-hundred-
# byte JSON envelope being sealed — approximately 5.3 MiB end to end. 5.5 MiB
# gives real headroom above that calculated worst case for encoding/padding
# variance, while still being a distinct, deliberately-chosen constant
# smaller than MAX_PACKET_SIZE_BYTES (6 MiB) — not simply reusing that
# transport-wide ceiling as this protocol's own boundary. Checked against
# the exact UTF-8 serialized `payload` dict, BEFORE any durable/expensive
# work (ACTIVE→IN_FLIGHT claim, token_pending reservation) ever runs.
ANON_PAYLOAD_MAX_BYTES = int(5.5 * 1024 * 1024)
if ANON_PAYLOAD_MAX_BYTES <= 0:
    print("[FATAL] ANON_PAYLOAD_MAX_BYTES должен быть > 0 — отказ запуска.", flush=True)
    sys.exit(1)
# Whole outer `anon_message` frame (type + token + payload + JSON syntax) —
# a small fixed margin above ANON_PAYLOAD_MAX_BYTES for the token (64 chars)
# and JSON structure overhead, generous rather than exact.
ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = ANON_PAYLOAD_MAX_BYTES + 4096

# Every payload `type` currently ever placed (visibly, unsealed) inside an
# anon_message payload on either shipped client, PLUS every type that COULD
# appear there via Desktop's own documented unsealed fallback
# (sendAnonOrDirect()/sendViaToken(): if sealPacketForRecipient() returns
# null, the raw packet is sent as-is rather than as an opaque {"id","blob"}
# wrapper) — grepped every sendAnonOrDirect()/sendViaToken()/sendCallSignal()
# call site on both platforms, not assumed. The OPAQUE {"id","blob"} sealed
# wrapper itself has no "type" key at all and is unaffected by this
# allowlist — this only ever fires when a "type" key is actually PRESENT in
# `payload`, closing the "arbitrary attacker-defined protocol name carried
# indefinitely" gap (S6-59, STEP 4) without rejecting the dominant sealed
# case, which was never a "type"-shaped dict to begin with.
ANON_PAYLOAD_ALLOWED_TYPES = frozenset({
    "message", "session_init", "reaction", "edit", "read", "delivered", "typing",
    "voice", "message_delete", "disappear_timer",
    "image_chunk", "video_chunk", "file_chunk",
    "group_create", "group_message", "group_member_removed", "group_member_added",
    "group_key_rotation", "group_invite_accepted", "group_reaction",
    "group_message_delete",
    "contact_ping", "contact_pong",
    "call_offer", "call_answer", "call_ice", "call_end", "call_ringing",
    "call_ice_restart", "call_response", "call_request_audio", "call_request_video",
})

# Per-connection anonymous-relay byte budget (S6-59, STEP 6) — anon_channel
# connections are identity-less by design (that's the whole point), so this
# is keyed by the websocket object itself, mirroring ws_to_tokens'/
# token_to_ws' own keying, never a per-user identity. A count-only limit
# (ANON_CHANNEL_MAX_PER_MINUTE above) is insufficient on its own for
# variable-size payloads up to ANON_PAYLOAD_MAX_BYTES each — see
# media_chunk_user_rate_ok()'s own reasoning, mirrored here exactly.
ANON_RELAY_CONN_MAX_BYTES  = int(os.environ.get("ANON_RELAY_CONN_MAX_BYTES", str(20 * 1024 * 1024)) or str(20 * 1024 * 1024))
ANON_RELAY_CONN_WINDOW_SEC = 10
anon_relay_conn_rate: dict = {}   # websocket -> {"bytes": int, "reset_time": float}


def anon_relay_conn_rate_ok(ws, nbytes: int) -> bool:
    now = time.time()
    entry = anon_relay_conn_rate.get(ws)
    if not entry or now - entry["reset_time"] >= ANON_RELAY_CONN_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        anon_relay_conn_rate[ws] = entry
    if entry["bytes"] + nbytes > ANON_RELAY_CONN_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


# Process-wide aggregate (S6-59, STEP 8/9) — the per-connection budget above
# is Sybil-multipliable: an attacker opening N anonymous websocket
# connections gets N independent per-connection budgets. This bounds
# aggregate anonymous-relay bytes regardless of N. Same no-await RAM-only
# pattern as every other aggregate guard in this file.
ANON_RELAY_GLOBAL_MAX_BYTES  = int(os.environ.get("ANON_RELAY_GLOBAL_MAX_BYTES", str(150 * 1024 * 1024)) or str(150 * 1024 * 1024))
ANON_RELAY_GLOBAL_WINDOW_SEC = 10
anon_relay_global_rate = {"bytes": 0, "reset_time": time.time()}


def anon_relay_global_rate_ok(nbytes: int) -> bool:
    now  = time.time()
    data = anon_relay_global_rate
    if now - data["reset_time"] >= ANON_RELAY_GLOBAL_WINDOW_SEC:
        data["bytes"]      = 0
        data["reset_time"] = now
    if data["bytes"] + nbytes > ANON_RELAY_GLOBAL_MAX_BYTES:
        return False
    data["bytes"] += nbytes
    return True


# Per-recipient ingress budget (S6-59, STEP 7) — once a real (non-fake, non-
# spent) token is resolved, the server DOES know who it belongs to, even
# though it deliberately never learns who SENT this particular message. This
# protects one victim from many anonymous connections/many distinct valid
# tokens/Sybil senders all targeting them at once. Entries are created ONLY
# after a token resolves to a real owner (never keyed on raw attacker-
# supplied garbage token strings, which would let an attacker mint unbounded
# limiter entries just by trying random 32-char strings) — self-pruning via
# the same fixed-window-reset mechanism every other budget in this file uses,
# not a permanently-growing registry.
ANON_RELAY_RECIPIENT_MAX_BYTES  = int(os.environ.get("ANON_RELAY_RECIPIENT_MAX_BYTES", str(40 * 1024 * 1024)) or str(40 * 1024 * 1024))
ANON_RELAY_RECIPIENT_WINDOW_SEC = 10
anon_relay_recipient_rate: dict = {}   # owner username -> {"bytes": int, "reset_time": float}


def anon_relay_recipient_rate_ok(owner: str, nbytes: int) -> bool:
    now = time.time()
    entry = anon_relay_recipient_rate.get(owner)
    if not entry or now - entry["reset_time"] >= ANON_RELAY_RECIPIENT_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        anon_relay_recipient_rate[owner] = entry
    if entry["bytes"] + nbytes > ANON_RELAY_RECIPIENT_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


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

# Real global expiry + a hard process-wide capacity bound (external review
# 2026-09-04, S6-29) — MAILBOX_TTL above was previously enforced only
# LAZILY, at the exact moment the touched tag was next read by
# mailbox_put/mailbox_fetch. A tag that's never touched again (the normal
# case for a one-shot first-contact bootstrap tag — nothing ever revisits
# it after the intended recipient's single fetch, or if that fetch never
# happens at all) stayed in the `mailbox` dict FOREVER, well past its
# supposedly-48h lifetime, since nothing ever swept it. The existing
# per-tag cap (5) does nothing against this: an attacker submitting a
# fresh, distinct, otherwise perfectly valid random tag on every
# mailbox_put never even approaches that per-tag limit. At the existing
# mailbox_put rate limit (20/min) and MAILBOX_MAX_BLOB (8 KiB), one single
# authenticated identity can add roughly 225 MiB of RAM-resident payload
# per day that nothing ever reclaims short of a restart; Sybil identities
# (open registration) multiply that without bound. Real global expiry
# (mailbox_watchdog() below) closes the "never touched again" leak; the
# two hard caps here are the actual backstop that keeps even genuinely
# still-live, sub-48h-old blobs from being able to OOM the process before
# their TTL naturally expires — TTL alone bounds average-case growth, not
# worst-case burst growth within one TTL window.
#
# Deliberately does NOT persist sender identity/owner per mailbox entry to
# implement a PER-USER occupancy quota instead of (or alongside) this
# global one — the server already sees the authenticated put request, but
# retaining a sender→mailbox-tag mapping for 48h would be a strictly worse
# metadata-retention posture than what this blind, sender-less storage
# already has; mailbox entries stay exactly as blind as before this fix.
#
# Process-local, same as `mailbox` itself and every other RAM cache in this
# file — NOT cross-replica durable. A future horizontally-replicated
# deployment sharing one logical mailbox needs shared, bounded external
# storage for it, not an assumption that these RAM counters somehow
# aggregate across separate processes.
#
# Both required to be strictly positive, not "0 = disabled" (unlike
# PREKEY_PUBLISH_GLOBAL_LIMIT elsewhere in this file) — this is a hard,
# always-on process-wide bound protecting the process itself from OOM, not
# an optional abuse-mitigation knob a deployment might reasonably want to
# turn off; a misconfigured 0 or negative value refuses to start rather
# than silently running with no cap at all.
MAILBOX_MAX_TOTAL_BYTES = int(os.environ.get("MAILBOX_MAX_TOTAL_BYTES", str(64 * 1024 * 1024)))
MAILBOX_MAX_TOTAL_BLOBS = int(os.environ.get("MAILBOX_MAX_TOTAL_BLOBS", "10000"))
MAILBOX_CLEANUP_INTERVAL_SEC = 300
if MAILBOX_MAX_TOTAL_BYTES <= 0 or MAILBOX_MAX_TOTAL_BLOBS <= 0:
    print("[FATAL] MAILBOX_MAX_TOTAL_BYTES и MAILBOX_MAX_TOTAL_BLOBS должны быть > 0 "
          "(это обязательная защита процесса от OOM, а не отключаемая опция) — "
          "отказ запуска.", flush=True)
    sys.exit(1)

# Exact running totals across the WHOLE mailbox, maintained incrementally
# by every mutation site (mailbox_put, mailbox_fetch, the watchdog's own
# expiry sweep) — never recomputed by summing `mailbox` itself, so reading
# them is O(1). Every mutation of `mailbox`/these two counters together
# MUST happen under the same `lock` — see mailbox_watchdog()'s and
# mailbox_put()'s own comments.
mailbox_total_bytes = 0
mailbox_total_blobs = 0

MAX_TOKEN_LEN = 32
MAX_TOKENS_PER_SUBSCRIBE = 100
# Per-message call-count backstop for subscribe_tokens — NOT the real
# defense against token-creation abuse (that's MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT/
# ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW/ANON_TOKEN_STATE_MAX_TOTAL_ROWS/
# ANON_TOKEN_GLOBAL_CLAIM_LIMIT, all enforced content-aware and atomically
# inside db_claim_anon_tokens()/_db_claim_anon_tokens_sync() regardless of
# how many messages a batch is split across). This one only bounds raw
# message-processing overhead (JSON parse, lock acquisition) from a client
# sending many small calls, and only ever gets charged for a call carrying
# at least one not-yet-cached token — the subscribe_tokens handler skips
# charging it entirely for a call that's pure idempotent resubscription
# (every token already a cache hit), so a reconnect restoring an existing
# pool is free. Was a flat 10/60s (found live 2026-09-20: real reconnect/
# startup bursts of 80-100 tokens, split across MAX_TOKENS_PER_SUBSCRIBE=100
# -sized chunks, could legitimately need several back-to-back calls and hit
# that ceiling). Derived from MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT instead of a
# second arbitrary tiny constant: enough chunks to restore this account's
# entire configured active-token capacity in one burst, with a floor for
# small/test deployments that lower that env var a lot.
SUBSCRIBE_TOKENS_RATE_LIMIT = max(20, MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT // MAX_TOKENS_PER_SUBSCRIBE)

MAX_BUNDLE_SIZE_BYTES  = 64  * 1024
MAX_PACKET_SIZE_BYTES  = 6 * 1024 * 1024
OPK_LOW_WATERMARK      = 5
HANDSHAKE_TIMEOUT_SEC  = 15

# Dedicated pre-auth handshake frame ceiling (external review 2026-09-05,
# S6-45) — MAX_PACKET_SIZE_BYTES (6 MiB) exists for legitimate POST-handshake
# traffic (image/video/file/voice payloads); the handshake itself is tiny by
# protocol design and was, before this fix, allowed to reuse that same
# multi-megabyte ceiling — an unauthenticated attacker got a multi-megabyte
# json.loads()/base64/DER parsing surface per connection for fields whose
# real representation is a few hundred bytes at most. Inspected both shipped
# clients (Android's/Desktop's `handleMessage()`'s `"challenge"` branch):
# neither applies its packet-padding helper (`addPadding()`/`_p`) to
# challenge_response, anon_channel, or any other handshake message — only to
# post-auth traffic (anon_message, cover-traffic noise, a few others) — so
# the real handshake frame is just `{"type":"challenge_response","public_key"
# :"<~124 b64 chars>","signature":"<~100 b64 chars>"}`, on the order of
# 250-300 bytes; `anon_channel`/`federation_auth` frames are smaller still.
# 8 KiB is generous headroom above every real handshake shape while staying
# three orders of magnitude below MAX_PACKET_SIZE_BYTES. Does NOT change
# `websockets.serve(... max_size=MAX_PACKET_SIZE_BYTES)` — that stays the
# transport-wide ceiling for all post-handshake application traffic; this is
# an additional, tighter application-level check specifically on the very
# first frame of a connection, before it's ever authenticated.
HANDSHAKE_MAX_PACKET_SIZE_BYTES = int(
    os.environ.get("HANDSHAKE_MAX_PACKET_SIZE_BYTES", str(8 * 1024)) or str(8 * 1024)
)
if HANDSHAKE_MAX_PACKET_SIZE_BYTES <= 0:
    print("[FATAL] HANDSHAKE_MAX_PACKET_SIZE_BYTES должен быть > 0 (обязательная защита "
          "pre-auth поверхности от многомегабайтного парсинга, а не отключаемая опция) — "
          "отказ запуска.", flush=True)
    sys.exit(1)

# Federation HMAC bound (external review 2026-09-05, S6-45) — the MAC is
# always exactly hashlib.sha256().digest_size (32) raw bytes, base64-encoded
# to a fixed ~44 characters; 128 is generous headroom while staying tiny
# relative to HANDSHAKE_MAX_PACKET_SIZE_BYTES itself.
MAX_FEDERATION_MAC_B64_LEN = 128

# PoW nonce bound (external review 2026-09-05, S6-45) — both clients that
# implement PoW (Android; Desktop doesn't yet send pow_nonce at all) encode
# it as `counter.toString()` for a signed 64-bit counter, at most ~20
# decimal digits. 64 is generous headroom while ensuring a malformed/
# oversized nonce can never make register() hash megabytes of
# attacker-controlled input — it simply fails the difficulty check exactly
# like any other wrong nonce would.
MAX_POW_NONCE_LEN = 64

# Named ceiling for incoming federation frames (external review 2026-09-04,
# S6-34) — replaces the previous unnamed `MAX_PACKET_SIZE_BYTES * 2` inline
# in handle_federation_peer_incoming(), so the federation-specific ceiling is
# independently configurable instead of silently tracking whatever
# MAX_PACKET_SIZE_BYTES happens to be. Larger than the client-facing packet
# ceiling by the same factor as before (a federated_forward wraps a whole
# client payload plus envelope fields) — not a behavior change, just a name.
FEDERATION_MAX_PACKET_SIZE_BYTES = MAX_PACKET_SIZE_BYTES * 2

# ─── Server-wide prekey-publish write budget (Sybil amplification guard) ──────
# S6-27 bounded the per-fingerprint publish rate ("prekey_publish" bucket,
# rate_limit_check()) — but with open registration, an attacker can mint
# many valid identities (subject only to POW_DIFFICULTY_BITS/
# MAX_REGISTERED_USERS if those are configured) and multiply the allowed
# AGGREGATE SQLite write rate linearly, one fresh fingerprint at a time.
# Each accepted publish is intentionally expensive since S6-26/S6-27
# (store_prekey_bundle()'s durable DB-first write, a per-target
# prekey_mutation_locks acquisition, executor-thread work) — external
# review 2026-09-04. This is a SECOND, orthogonal budget, layered ON TOP
# OF the per-user one, not a replacement for it: per-user fairness (no
# single identity can starve the others) and an aggregate capacity bound
# (no number of identities can exceed what this process can durably
# absorb) are two different properties, and Sybil attacks specifically
# defeat the first without the second.
#
# 0 (not negative) is the only value treated as "explicitly disabled" —
# a negative value is a configuration mistake, refused at startup rather
# than silently coerced into some guessed behavior.
PREKEY_PUBLISH_GLOBAL_LIMIT = int(os.environ.get("PREKEY_PUBLISH_GLOBAL_LIMIT", "200") or "200")
if PREKEY_PUBLISH_GLOBAL_LIMIT < 0:
    print("[FATAL] PREKEY_PUBLISH_GLOBAL_LIMIT должен быть >= 0 (0 явно отключает "
          "агрегатный лимитер публикации prekey-bundle'ов) — отказ запуска, чтобы "
          "не работать с неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
PREKEY_PUBLISH_GLOBAL_ENABLED    = PREKEY_PUBLISH_GLOBAL_LIMIT > 0
PREKEY_PUBLISH_GLOBAL_WINDOW_SEC = 60

# Process-local aggregate counter — explicitly NOT cross-process durable
# (external review 2026-09-04). Correct and sufficient for THIS
# deployment's current shape: one single asyncio process handling every
# connection. If this server is ever run as multiple replicas/processes
# behind a load balancer, EACH process gets its OWN independent
# PREKEY_PUBLISH_GLOBAL_LIMIT allowance — the real aggregate write rate
# across the whole deployment would then be (configured limit × replica
# count), not the configured limit itself. A genuinely multi-process
# deployment needs a SHARED limiter (Redis, a sidecar/gateway rate limit,
# etc.) — this plain RAM dict does not provide that, and is not meant to;
# see global_prekey_publish_rate_ok()'s own comment for why it is
# deliberately NOT SQLite-backed either.
global_prekey_publish_rate = {"count": 0, "reset_time": time.time()}


def global_prekey_publish_rate_ok() -> bool:
    """Server-wide prekey-publish budget — the aggregate counterpart to the
    per-user `"prekey_publish"` bucket (`rate_limit_check()`, S6-27).
    Deliberately NOT SQLite-backed: the entire point of this check is
    rejecting a write attempt BEFORE it costs a SQLite transaction —
    implementing the guard itself as a SQLite write would defeat much of
    its own purpose (a Sybil flood would still force one SQLite operation
    per request either way, just a cheaper one instead of none).

    No `await` anywhere in this function, by design: a single asyncio
    event loop makes the check-then-increment on `global_prekey_publish_rate`
    atomic with respect to every other coroutine — no other coroutine can
    run between the read and the write here, so no explicit lock is needed
    (the same "no await = atomic" property `rate_limit_check()` itself
    already relies on for its own plain-dict counters).

    Returns True (and consumes one slot from the current window) if the
    aggregate budget isn't exhausted. Returns True unconditionally, with no
    tracking at all, if `PREKEY_PUBLISH_GLOBAL_LIMIT` was configured as `0`
    (explicitly disabled) — see that constant's own comment."""
    if not PREKEY_PUBLISH_GLOBAL_ENABLED:
        return True
    now  = time.time()
    data = global_prekey_publish_rate
    if now - data["reset_time"] >= PREKEY_PUBLISH_GLOBAL_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= PREKEY_PUBLISH_GLOBAL_LIMIT:
        return False
    data["count"] += 1
    return True
# Per-connection cap for the identity-less anon_channel (Sealed Sender, шаг 2)
# — there's no username to key the normal rate_limit_check() on, so abuse
# containment here is: (a) this per-connection ceiling, (b) the fact that a
# flood of garbage tokens is already cheap to reject (is_known/is_spent dict
# lookup, same "fake ack" path as a real-but-spent token), (c) nginx/CF still
# see the real IP for their own layer even though server.py deliberately
# doesn't (see docs/TODO.md "IP invariant").
ANON_CHANNEL_MAX_PER_MINUTE = 60
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

# ─── S6-47: channel persistence resource hardening ─────────────────────────────
# (external review 2026-09-05) — channel_post had NO rate_limit_check() call at
# all, each post could carry up to ~5 MiB of image_data (measured in
# CHARACTERS via len(image_data), not decoded bytes — a base64 string is ~4/3
# larger than what it decodes to, so this bound was already looser than it
# looked), and every accepted post was persisted via a bare INSERT OR IGNORE
# and never deleted — the RAM-only `if len(ch["posts"]) > 200: ch["posts"] =
# ch["posts"][-200:]` bounds the in-memory list but does nothing to the
# underlying channel_posts SQLite rows, so disk usage grows without bound
# regardless of how little history the application ever actually surfaces.
# Fixed with the same bounded-storage pattern S6-31 established for
# pending_messages: protocol-specific field bounds checked before any DB work,
# a dedicated per-user rate limit plus a process-wide pre-SQLite write-attempt
# budget, a durable running-totals table (channel_posts_meta) checked+updated
# in the SAME transaction as every INSERT/DELETE so capacity never needs a
# COUNT(*)/SUM() over the whole table, and hard strictly-positive total
# row/byte ceilings.
#
# Field-shape bounds, derived from actual client behavior (grepped, not
# guessed): channel_id is server-generated via secrets.token_urlsafe(16) (~22
# chars); post_id is client-supplied UUID.randomUUID().toString() (36 chars)
# or, if omitted, the same token_urlsafe(16) server default — 128 covers both
# with headroom, matching OFFLINE_MSG_ID_MAX_LEN's own precedent for exactly
# this kind of field. channel_name was already effectively bounded at 100
# chars (pre-existing check in channel_create, formalized here as a named
# constant, unchanged). channel_description/channel_avatar had NO bound at all
# before this fix — 500/32 are generous relative to every real channel-
# creation UI field (channel_avatar is a single emoji or short ZWJ sequence in
# every observed usage) while still being real bounds. channel_post's `text`
# is plaintext the server actually reads and re-broadcasts (channels are NOT
# E2E-encrypted, unlike ordinary messages) — 4096 chars is a generous
# long-post ceiling with real-world precedent (matches Telegram's own
# channel-post text limit).
CHANNEL_ID_MAX_LEN            = 64
CHANNEL_POST_ID_MAX_LEN       = 128
CHANNEL_NAME_MAX_CHARS        = 100
CHANNEL_DESCRIPTION_MAX_CHARS = 500
CHANNEL_AVATAR_MAX_CHARS      = 32
CHANNEL_POST_TEXT_MAX_CHARS   = 4096

# image_data is base64 (Android's ImageHelper.prepareImageSingle:
# Base64.encodeToString(jpegBytes, Base64.NO_WRAP) — standard alphabet,
# padded, confirmed compatible with base64.b64decode(..., validate=True)). A
# real post image (scaled to <=1024px, JPEG quality 75) is on the order of
# 100-400 KB base64; CHANNEL_POST_IMAGE_MAX_BYTES (4 MiB decoded) is
# generously above that. CHANNEL_POST_IMAGE_B64_MAX_LEN is the exact
# base64-encoded length of a CHANNEL_POST_IMAGE_MAX_BYTES-byte payload
# (ceil(bytes/3)*4, plus a small slack for padding) — checked BEFORE
# base64.b64decode() ever runs, so an oversized string is rejected on a cheap
# len() call, not by first paying for the decode. Desktop currently never
# sends image_data at all (postToChannel() has no such field, confirmed by
# inspection) — this bound applies identically regardless.
CHANNEL_POST_IMAGE_MAX_BYTES   = int(os.environ.get("CHANNEL_POST_IMAGE_MAX_BYTES", str(4 * 1024 * 1024)) or str(4 * 1024 * 1024))
CHANNEL_POST_IMAGE_B64_MAX_LEN = ((CHANNEL_POST_IMAGE_MAX_BYTES + 2) // 3) * 4 + 4

# Single-post hard storage ceiling — independent of, and smaller than,
# MAX_PACKET_SIZE_BYTES (the websocket frame ceiling): one post's total
# durable footprint (channel_id + post_id + text + author_id + author_name +
# image_data, all as stored/counted in channel_posts.storage_bytes below) can
# never exceed this regardless of what the frame itself could carry.
CHANNEL_POST_MAX_BYTES = int(os.environ.get("CHANNEL_POST_MAX_BYTES", str(6 * 1024 * 1024)) or str(6 * 1024 * 1024))
if CHANNEL_POST_MAX_BYTES <= 0:
    print("[FATAL] CHANNEL_POST_MAX_BYTES должен быть > 0 (обязательная защита процесса/диска от "
          "неограниченного роста, а не отключаемая опция) — отказ запуска.", flush=True)
    sys.exit(1)

# Durable aggregate ceilings — same "always-on hard safety boundary, never
# 0=unlimited" posture as PENDING_MESSAGES_MAX_TOTAL_BYTES/ROWS (see that
# constant's own comment) — this protects the process/disk from unbounded
# growth, not an abuse-mitigation knob a deployment might reasonably want to
# disable.
CHANNEL_POSTS_MAX_TOTAL_BYTES = int(os.environ.get("CHANNEL_POSTS_MAX_TOTAL_BYTES", str(512 * 1024 * 1024)) or str(512 * 1024 * 1024))
CHANNEL_POSTS_MAX_TOTAL_ROWS  = int(os.environ.get("CHANNEL_POSTS_MAX_TOTAL_ROWS", "1000000") or "1000000")
if CHANNEL_POSTS_MAX_TOTAL_BYTES <= 0 or CHANNEL_POSTS_MAX_TOTAL_ROWS <= 0:
    print("[FATAL] CHANNEL_POSTS_MAX_TOTAL_BYTES и CHANNEL_POSTS_MAX_TOTAL_ROWS должны быть > 0 "
          "(обязательная защита процесса/диска от неограниченного роста, а не отключаемая опция) "
          "— отказ запуска.", flush=True)
    sys.exit(1)

# Per-channel durable retention (external review 2026-09-05) — the server
# already only LOADS (_db_load_channels_sync()) and RAM-keeps (channel_post
# handler) the most recent 200 posts per channel, and channel_subscribe only
# ever returns the most recent 50; grepped both clients and the server's own
# wire protocol for any "give me older posts" message (channel_history/
# pagination/before_timestamp/etc.) — none exists. Rows beyond the most
# recent 200 for a channel are therefore ALREADY unobservable through any
# current client, so persistence is made to match that reality: storing a new
# post atomically prunes older rows for the SAME channel beyond this count,
# in the SAME transaction, keeping channel_posts_meta exactly in sync. This
# is a product-semantics-aligned retention choice, not a workaround — if
# pagination/history retrieval is ever added, this constant (and the pruning
# it drives) needs to be revisited alongside that feature, not left in place
# unexamined.
CHANNEL_POSTS_MAX_PER_CHANNEL = 200

# Per-user rate limit (added to rate_limit_check()'s default_limits table) —
# channel_post had NO dedicated limit at all before this fix, despite each
# accepted post persisting durably and potentially carrying multi-megabyte
# image data. 10/min is generous for a human/automated channel publisher
# (this is NOT a chat message type — posting is admin-only, broadcast, and by
# nature much lower-frequency than ordinary messaging) while bounding how
# many expensive durable writes one account can force per minute. This is
# per-user fairness only — NOT a substitute for the durable caps above, which
# are what actually bound disk usage regardless of how many distinct accounts
# participate.
CHANNEL_POST_RATE_LIMIT = 10

# Process-wide pre-SQLite write-ATTEMPT budget — mirrors
# global_prekey_publish_rate_ok()/global_offline_store_rate_ok() exactly (see
# either's own comment for the full reasoning): Sybil accounts (or many
# distinct channels) each individually under CHANNEL_POST_RATE_LIMIT still
# defeat a purely per-user limit in aggregate. Checked BEFORE the
# executor/SQLite hop, not merely before the durable INSERT itself — once
# CHANNEL_POSTS_MAX_TOTAL_BYTES/ROWS is actually exhausted, every further
# channel_post would otherwise still pay a full BEGIN IMMEDIATE transaction
# just to be told FULL. Deliberately NOT SQLite-backed (forcing a SQLite
# write merely to reject SQLite-write DoS would defeat the point) and
# explicitly process-local — same caveat as every other RAM-only limiter in
# this file: a multi-process/replica deployment gets one independent budget
# PER PROCESS, not one shared budget across the deployment. 0 (not negative)
# explicitly disables it, same convention as
# PREKEY_PUBLISH_GLOBAL_LIMIT/OFFLINE_STORE_GLOBAL_LIMIT.
CHANNEL_POST_GLOBAL_LIMIT = int(os.environ.get("CHANNEL_POST_GLOBAL_LIMIT", "60") or "60")
if CHANNEL_POST_GLOBAL_LIMIT < 0:
    print("[FATAL] CHANNEL_POST_GLOBAL_LIMIT должен быть >= 0 (0 явно отключает агрегатный "
          "write-attempt лимитер публикации в каналы) — отказ запуска, чтобы не работать с "
          "неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
CHANNEL_POST_GLOBAL_ENABLED    = CHANNEL_POST_GLOBAL_LIMIT > 0
CHANNEL_POST_GLOBAL_WINDOW_SEC = 60
channel_post_global_rate = {"count": 0, "reset_time": time.time()}


def channel_post_global_rate_ok() -> bool:
    """Mirrors global_prekey_publish_rate_ok()/global_offline_store_rate_ok()
    exactly — see either's own comment for the full reasoning this shares,
    including why no explicit lock is needed (no `await` here, so a single
    asyncio event loop makes the check-then-increment atomic)."""
    if not CHANNEL_POST_GLOBAL_ENABLED:
        return True
    now  = time.time()
    data = channel_post_global_rate
    if now - data["reset_time"] >= CHANNEL_POST_GLOBAL_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= CHANNEL_POST_GLOBAL_LIMIT:
        return False
    data["count"] += 1
    return True


# Channel creation is a PERMANENT durable row — there is currently no
# channel-deletion feature at all (grepped: no channel_delete/DROP-style
# handler exists anywhere in this file), so channel_create's existing 5/min
# rate_limit_check() bucket only bounds the RATE of creation, not the
# LIFETIME total — an account could otherwise create channels forever.
# MAX_CHANNELS_PER_OWNER (per-account) and CHANNELS_MAX_TOTAL_ROWS
# (process-wide) are both hard durable ceilings, enforced atomically inside
# the SAME transaction as the INSERT (a SELECT COUNT(*) then a separately
# awaited INSERT would let two concurrent creations both observe "under cap"
# and both insert — same race S6-37's device-cap fix closed for
# authorized_devices). 20 per owner is generous for legitimate use (a
# business/community account running several topic channels) given channels
# are permanent; 100,000 total is a generous process-wide backstop for
# expected deployment scale.
MAX_CHANNELS_PER_OWNER  = int(os.environ.get("MAX_CHANNELS_PER_OWNER", "20") or "20")
CHANNELS_MAX_TOTAL_ROWS = int(os.environ.get("CHANNELS_MAX_TOTAL_ROWS", "100000") or "100000")
if MAX_CHANNELS_PER_OWNER <= 0 or CHANNELS_MAX_TOTAL_ROWS <= 0:
    print("[FATAL] MAX_CHANNELS_PER_OWNER и CHANNELS_MAX_TOTAL_ROWS должны быть > 0 "
          "(обязательная защита процесса/диска от неограниченного роста, а не отключаемая опция) "
          "— отказ запуска.", flush=True)
    sys.exit(1)


def is_valid_channel_id(value) -> bool:
    """Shape check for channel_id (S6-47) — every real channel_id this server
    has ever minted is secrets.token_urlsafe(16) (~22 URL-safe-base64
    characters); this bounds length/type before any dict/DB lookup, without
    assuming an exact charset (unlike is_valid_fingerprint()'s exact 16-hex
    shape) since it's never cryptographically compared, only used as an
    opaque lookup key."""
    return isinstance(value, str) and 1 <= len(value) <= CHANNEL_ID_MAX_LEN


def is_valid_channel_post_id(value) -> bool:
    """Shape check for channel_posts.post_id (S6-47) — client-supplied
    UUID.randomUUID().toString() (36 chars) or, if omitted, the server's own
    secrets.token_urlsafe(16) default (~22 chars); 128 covers both with
    generous headroom, matching OFFLINE_MSG_ID_MAX_LEN's own precedent."""
    return isinstance(value, str) and 1 <= len(value) <= CHANNEL_POST_ID_MAX_LEN


def validate_channel_post_image(value) -> bool:
    """Bounds+validates channel_post's image_data field (S6-47) — must be a
    str, its base64-encoded length checked BEFORE decode
    (CHANNEL_POST_IMAGE_B64_MAX_LEN), decoded with strict base64 syntax
    (validate=True — confirmed compatible with Android's
    Base64.encodeToString(..., Base64.NO_WRAP), which uses the identical
    padded standard alphabet), and finally the DECODED byte length checked
    against CHANNEL_POST_IMAGE_MAX_BYTES — the actual real-world image-size
    ceiling; the pre-decode string-length check alone is generous enough
    that a well-formed base64 string within it can never decode to
    meaningfully more than this. Empty string (no image) is always valid."""
    if value == "":
        return True
    if not isinstance(value, str) or len(value) > CHANNEL_POST_IMAGE_B64_MAX_LEN:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(decoded) <= CHANNEL_POST_IMAGE_MAX_BYTES


# ─── User avatars ──────────────────────────────────────────────────────────────
# username → base64-encoded JPEG avatar (128×128, ~5-8 KB)
user_avatars = {}

# Official format confirmed from Android's ProfileScreen.kt (the only client
# that currently sends its own avatar — Desktop has getMyAvatar()/
# saveMyAvatar() plumbing in UserStorage.kt but no UI wired to call either,
# and never includes "avatar" in its own register() packet at all):
# Bitmap.createScaledBitmap(...,128,128,...).compress(JPEG, 85, ...),
# Base64.encodeToString(..., NO_WRAP) — raw base64, no data-URI prefix,
# standard padded alphabet, real-world output a few KB (see this section's
# own long-standing comment above). AVATAR_MAX_DECODED_BYTES (64 KiB) is a
# generous multiple of that, not an attempt to prove 128×128/JPEG-ness — the
# server does not decode untrusted image formats merely to validate this;
# the encoded/decoded byte bounds below ARE the security boundary (external
# review 2026-09-06, S6-50), replacing the old unconditional
# `len(...) < 200_000` allowance (~150 KB decoded) that register()/
# profile_update each checked independently and which was never actually a
# real security boundary since nothing else bounded write RATE or aggregate
# persisted bytes.
AVATAR_MAX_DECODED_BYTES = int(os.environ.get("AVATAR_MAX_DECODED_BYTES", str(64 * 1024)) or str(64 * 1024))
if AVATAR_MAX_DECODED_BYTES <= 0:
    print("[FATAL] AVATAR_MAX_DECODED_BYTES должен быть > 0 (обязательная защита процесса/диска "
          "от неограниченного роста, а не отключаемая опция) — отказ запуска.", flush=True)
    sys.exit(1)
AVATAR_MAX_B64_LEN = ((AVATAR_MAX_DECODED_BYTES + 2) // 3) * 4 + 4


def is_valid_avatar(value) -> bool:
    """Canonical avatar validator (S6-50) — the ONE admission chokepoint
    every avatar write path (register's `avatar` field, profile_update, any
    future avatar write path) must pass through before touching RAM,
    SQLite, or a broadcast. Empty string means "no avatar carried in this
    message" (register's long-standing semantics — this protocol has no
    avatar-deletion wire concept, and this patch does not invent one) and is
    always valid. Mirrors validate_channel_post_image()'s exact shape: bound
    the encoded length BEFORE decode, strict base64 syntax (validate=True —
    confirmed compatible with Android's Base64.encodeToString(..., NO_WRAP),
    the identical padded standard alphabet), then bound the DECODED byte
    length — never coerced or truncated."""
    if value == "":
        return True
    if not isinstance(value, str) or len(value) > AVATAR_MAX_B64_LEN:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(decoded) <= AVATAR_MAX_DECODED_BYTES


# Durable aggregate ceilings — same "always-on hard safety boundary, never
# 0=unlimited" posture as CHANNEL_POSTS_MAX_TOTAL_BYTES/ROWS (see that
# constant's own comment): one avatar per fingerprint ties row count to
# account count, but MAX_REGISTERED_USERS defaults to unlimited, so actual
# attacker-controlled avatar BYTES still need an independent hard ceiling.
AVATARS_MAX_TOTAL_BYTES = int(os.environ.get("AVATARS_MAX_TOTAL_BYTES", str(256 * 1024 * 1024)) or str(256 * 1024 * 1024))
AVATARS_MAX_TOTAL_ROWS  = int(os.environ.get("AVATARS_MAX_TOTAL_ROWS", "1000000") or "1000000")
if AVATARS_MAX_TOTAL_BYTES <= 0 or AVATARS_MAX_TOTAL_ROWS <= 0:
    print("[FATAL] AVATARS_MAX_TOTAL_BYTES и AVATARS_MAX_TOTAL_ROWS должны быть > 0 "
          "(обязательная защита процесса/диска от неограниченного роста, а не отключаемая опция) "
          "— отказ запуска.", flush=True)
    sys.exit(1)

# Process-wide pre-SQLite write-ATTEMPT budget for avatar MUTATIONS — mirrors
# channel_post_global_rate_ok()/totp_setup_global_rate_ok() exactly (see
# either's own comment for the full reasoning). Checked only for a
# genuinely CHANGED avatar (see apply_avatar_mutation()) — an unchanged
# reconnect avatar never reaches this, so normal reconnect traffic can never
# exhaust it. 0 explicitly disables it, same convention as
# CHANNEL_POST_GLOBAL_LIMIT.
AVATAR_UPDATE_GLOBAL_LIMIT = int(os.environ.get("AVATAR_UPDATE_GLOBAL_LIMIT", "60") or "60")
if AVATAR_UPDATE_GLOBAL_LIMIT < 0:
    print("[FATAL] AVATAR_UPDATE_GLOBAL_LIMIT должен быть >= 0 (0 явно отключает агрегатный "
          "write-attempt лимитер обновления аватаров) — отказ запуска, чтобы не работать с "
          "неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
AVATAR_UPDATE_GLOBAL_ENABLED    = AVATAR_UPDATE_GLOBAL_LIMIT > 0
AVATAR_UPDATE_GLOBAL_WINDOW_SEC = 60
avatar_update_global_rate = {"count": 0, "reset_time": time.time()}


def avatar_update_global_rate_ok() -> bool:
    """Mirrors channel_post_global_rate_ok()/totp_setup_global_rate_ok()
    exactly — see either's own comment for the full reasoning this shares,
    including why no explicit lock is needed (no `await` here, so a single
    asyncio event loop makes the check-then-increment atomic)."""
    if not AVATAR_UPDATE_GLOBAL_ENABLED:
        return True
    now  = time.time()
    data = avatar_update_global_rate
    if now - data["reset_time"] >= AVATAR_UPDATE_GLOBAL_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= AVATAR_UPDATE_GLOBAL_LIMIT:
        return False
    data["count"] += 1
    return True


# Bounded reconnect/registration avatar-directory sync (S6-50) — replaces the
# old unconditional "send EVERY entry in user_avatars to every registering/
# reconnecting socket" behavior, which made one reconnect's egress scale
# with total account count regardless of how many avatars that account
# actually needs. Not sorted by recency (an arbitrary subset of
# user_avatars' current dict order once either cap is hit) — inspected both
# clients first: Android already re-populates AvatarStore from its own
# locally-cached ChatStorage avatars on every reconnect (see
# MessengerService.kt's post-register contact loop) and separately fetches
# a specific contact's avatar on demand via get_key() whenever that
# contact's public key isn't cached yet (flushQueue()) — so this bulk sync
# is a compatibility fallback for the "an existing contact updated their
# avatar while I was offline, and I already have their key cached" case,
# not the only way a client ever learns an avatar. A generous cap here
# keeps that fallback intact for any realistically-sized deployment while
# giving a hard ceiling instead of unbounded egress for an unexpectedly
# huge account base — see this patch's own documentation for the accepted
# trade-off (an account base larger than this cap may see some avatars only
# via the on-demand get_key() path instead of the bulk push).
AVATAR_SYNC_MAX_COUNT       = int(os.environ.get("AVATAR_SYNC_MAX_COUNT", "500") or "500")
AVATAR_SYNC_MAX_TOTAL_BYTES = int(os.environ.get("AVATAR_SYNC_MAX_TOTAL_BYTES", str(8 * 1024 * 1024)) or str(8 * 1024 * 1024))
if AVATAR_SYNC_MAX_COUNT <= 0 or AVATAR_SYNC_MAX_TOTAL_BYTES <= 0:
    print("[FATAL] AVATAR_SYNC_MAX_COUNT и AVATAR_SYNC_MAX_TOTAL_BYTES должны быть > 0 "
          "(обязательная защита процесса/диска от неограниченного роста, а не отключаемая опция) "
          "— отказ запуска.", flush=True)
    sys.exit(1)

# Mirrors totp_state_locks' own reasoning exactly (see its own comment):
# `username` here is always THIS connection's own proven identity
# (register()'s committed username, or profile_update's already-
# authenticated username), never an attacker-chosen string — growth is
# bounded by the number of distinct real accounts that have ever mutated
# their avatar, not a meaningful DoS surface on its own. Needed so two
# concurrent avatar mutations for the SAME fingerprint (a register racing a
# profile_update, or two devices racing each other) can't interleave as
# DB-write-A, DB-write-B, RAM-A, RAM-B and leave RAM disagreeing with
# whichever write actually committed last durably.
avatar_mutation_locks: dict = {}


def get_avatar_mutation_lock(username: str) -> asyncio.Lock:
    """Returns the one asyncio.Lock for `username`'s avatar mutations
    (creating it on first use) — see avatar_mutation_locks' own comment
    above for why this exists."""
    state_lock = avatar_mutation_locks.get(username)
    if state_lock is None:
        state_lock = asyncio.Lock()
        avatar_mutation_locks[username] = state_lock
    return state_lock

# Same reasoning/pattern as avatar_mutation_locks/totp_state_locks above —
# NOT the ref-counted self-pruning shape prekey_mutation_locks needs,
# because `username` here is always this connection's OWN already-committed
# identity (S6-39's candidate_username, graduated to `username` only after
# Phase 2's admission checks), never an attacker-chosen/unvalidated string —
# growth is bounded by the number of distinct real accounts ever seen, same
# bound `clients`/`rate_limits`/`avatar_mutation_locks` already accept (S6-55).
#
# Exists because register()'s session-conflict eviction (see its own
# comment) only fires-and-forgets the old socket's close() — the OLD
# connection's own reconnect-flush loop keeps running (on a socket that's
# closing but may not have finished closing yet) for an unbounded window
# after a NEW connection for the same account starts its own flush loop.
# Without this lock both loops could peek/send/delete concurrently: safe
# (db_delete_pending_row()'s NOT_FOUND handling keeps meta correct either
# way — see its own comment) but wasteful, and can genuinely double-deliver
# a row to two different live sockets instead of just the unavoidable
# crash-window duplicate this patch already accepts. Held ONLY around the
# flush loop itself, never across unrelated per-connection work.
pending_flush_locks: dict = {}


def get_pending_flush_lock(username: str) -> asyncio.Lock:
    """Returns the one asyncio.Lock for `username`'s reconnect offline-queue
    flush (creating it on first use) — see pending_flush_locks' own comment
    above for why this exists."""
    state_lock = pending_flush_locks.get(username)
    if state_lock is None:
        state_lock = asyncio.Lock()
        pending_flush_locks[username] = state_lock
    return state_lock

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

# Narrow, per-account lock serializing every LIVE TOTP state transition
# against every OTHER live TOTP state transition/admission decision for the
# SAME fingerprint (external review 2026-09-04, S6-32) — found live: TOTP
# enable/disable is durable in SQLite (db_commit_totp_setup()/
# db_commit_totp_disable()), but register()'s device-gating decision reads
# the RAM cache (`username in user_totp_secrets`), and totp_setup/
# totp_disable each `await` their durable commit BEFORE updating that same
# RAM cache (deliberately — see db_commit_totp_setup()'s own comment on why
# RAM must lag the DB commit, not race ahead of it). That `await` is a
# scheduling window: a concurrent register() for the same fingerprint,
# interleaved on this event loop while totp_setup's commit is in flight, can
# observe "TOTP already durably enabled in SQLite" AND "TOTP still absent
# from user_totp_secrets" at once — the transient state actually IN BETWEEN
# the two writes — and take the no-TOTP device-authorization path for a
# fingerprint whose owner is at that very moment enabling TOTP specifically
# to close it. NOT the global RAM `lock` (asyncio.Lock() shared by nearly
# everything in this file) — this is deliberately narrow and per-account so
# that fingerprint A's TOTP transition never blocks fingerprint B's register(),
# and DB `await`s are allowed while holding it (unlike the global `lock` —
# see invariant 34's own "no await under the global lock" rule, which this
# does not violate since it's a different, narrower lock entirely). See
# get_totp_state_lock()'s own comment for the acquisition helper, and
# register()'s/totp_setup's/totp_disable's own comments for where each one
# is actually held. Grows one entry per fingerprint that has ever reached
# one of these paths and is never pruned — but unlike prekey_mutation_locks
# (self-pruning since S6-35, keyed on a caller-supplied `target` an
# authenticated client could pick arbitrarily), `username` here is always
# THIS connection's own proven identity, never an attacker-chosen string —
# growth is bounded by the number of distinct real accounts that have ever
# registered/touched TOTP, tracking `authorized_devices`/`registered_
# fingerprints` row-count order, not a meaningful DoS surface on its own.
totp_state_locks: dict = {}


def get_totp_state_lock(username: str) -> asyncio.Lock:
    """Returns the one asyncio.Lock for `username`'s live TOTP state
    (creating it on first use) — see totp_state_locks' own comment above for
    why this exists and what it does/doesn't serialize against. Every
    caller MUST hold this for the ENTIRE span from the first
    `username in user_totp_secrets`-derived decision through the matching
    RAM write (`user_totp_secrets[username] = ...`/`.pop(username, None)`),
    not just around the DB call — see register()'s/totp_setup's/
    totp_disable's own comments for the exact spans held. Deliberately NOT
    acquired from inside totp_verify_and_consume() itself (or any other
    lower-level helper) — every caller of that function already holds this
    lock for the whole surrounding admission/transition, and acquiring it a
    second time here would self-deadlock (asyncio.Lock is not reentrant)."""
    state_lock = totp_state_locks.get(username)
    if state_lock is None:
        state_lock = asyncio.Lock()
        totp_state_locks[username] = state_lock
    return state_lock


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
    # Explicit encryption intent must never silently fall back to plaintext
    # (external review 2026-09-05, S6-43) — this used to just print a
    # warning and continue with _totp_fernet = None on an invalid key,
    # which _db_load_totp_sync()/_totp_decrypt_from_storage()'s own
    # fail-closed check does NOT catch on a fresh DB, a DB with no TOTP
    # accounts yet, or a DB containing only legacy plaintext rows (none of
    # those have an encrypted "fernet1:" row to trip that check) —
    # totp_setup on any of those would then durably write brand-new
    # secrets as plaintext despite the operator having explicitly
    # configured encryption. A NONEMPTY TOTP_SECRET_ENCRYPTION_KEY is
    # therefore now a hard requirement to actually construct a working
    # Fernet instance, covering both an invalid key value and the
    # `cryptography` package being unavailable at all (the bare `import`
    # below, not a top-of-file one, so an unset key still works without
    # the dependency installed) — either failure aborts startup entirely.
    # An ABSENT/empty key remains fully supported as before: _totp_fernet
    # stays None, legacy plaintext-at-rest mode, no behavior change there.
    try:
        from cryptography.fernet import Fernet
        _totp_fernet = Fernet(_totp_key_env.encode())
    except Exception as e:
        print(f"[FATAL] TOTP_SECRET_ENCRYPTION_KEY задан, но невалиден ({e}) — "
              "отказ запуска, чтобы не сохранять TOTP-секреты открытым текстом.", flush=True)
        sys.exit(1)


def _totp_encrypt_for_storage(secret: str) -> str:
    if not _totp_fernet:
        return secret
    return TOTP_FERNET_PREFIX + _totp_fernet.encrypt(secret.encode()).decode()


def _totp_decrypt_from_storage(stored: str) -> str:
    """Raises RuntimeError, never returns "", when a secret exists on disk
    but can't be recovered (external review 2026-09-04) — this used to
    return "" for both "no key configured" and "decryption failed", which
    _db_load_totp_sync() then silently treated as "this account has no TOTP
    secret" (skipped the `result[username] = secret` assignment). That's a
    fail-OPEN, not fail-closed, despite this function's own previous
    comment claiming otherwise: register()'s TOTP gate is entirely driven
    by `username in user_totp_secrets`, so an account whose secret merely
    failed to decrypt (wrong/missing TOTP_SECRET_ENCRYPTION_KEY at this
    boot) looked IDENTICAL to an account that never enabled TOTP at all —
    a stolen identity private key was again sufficient to register a new
    device, exactly the attack device-gated TOTP exists to stop.
    totp_setup would have compounded this: it also gates re-enrollment on
    `username in user_totp_secrets`, so it would have let a caller
    provision a brand-new secret for that account with no proof of the old
    one at all. Raising here instead propagates out of _db_load_totp_sync()
    (called synchronously in start_server(), before anything binds/serves)
    and refuses to start the server at all — see that function's own
    comment."""
    if not stored.startswith(TOTP_FERNET_PREFIX):
        return stored  # legacy plaintext row, or encryption was never configured
    if not _totp_fernet:
        raise RuntimeError(
            "Encrypted TOTP secret(s) present in the database, but "
            "TOTP_SECRET_ENCRYPTION_KEY is not set (or invalid) — refusing "
            "to silently treat protected accounts as TOTP-disabled"
        )
    try:
        return _totp_fernet.decrypt(stored[len(TOTP_FERNET_PREFIX):].encode()).decode()
    except Exception as e:
        raise RuntimeError(
            "A stored TOTP secret could not be decrypted with the "
            "configured TOTP_SECRET_ENCRYPTION_KEY — refusing to silently "
            "treat this account as TOTP-disabled"
        ) from e

# ─── Optional server access-code allowlist ─────────────────────────────────────
# Off by default (personal self-hosting doesn't need this — it's for a private/
# business deployment that wants to control who can even create an account).
# Enabled via SERVER_ACCESS_PROTECTED. When on, a fingerprint's very FIRST-EVER
# register() on this server must include a valid, unused access_code — never
# required again afterward (checked against `registered_fingerprints`, not the
# in-memory `clients` dict, so it survives restarts and reconnects). Codes are
# generated at startup (SERVER_ACCESS_CODE_COUNT) or any time later via
# Server/admin_gen_codes.py, which writes straight into the same SQLite file —
# register() always reads the DB live, so no server restart is needed to add
# more. All code validity/consumption logic lives here, server-side, on
# purpose — the client only ever passes through whatever it scanned, it never
# decides whether a code is required or valid.
SERVER_ACCESS_PROTECTED = os.environ.get("SERVER_ACCESS_PROTECTED", "").strip().lower() in ("1", "true", "yes")

# Canonical access-code shape (external review 2026-09-05, S6-41) — was
# `secrets.token_hex(4).upper()`, only 32 bits, cheaply brute-forceable
# online (no dedicated attempt limiter existed at all) and trivially so
# offline if the plaintext code itself was ever exposed (stolen DB copy,
# log line, etc. — see ACCESS_CODE_HASH_PREFIX below for the storage half
# of this fix). 16 random bytes = 128 bits, encoded as 32 uppercase hex
# characters — the same `secrets.token_hex(N).upper()` shape and validator
# pattern used elsewhere in this file (is_valid_fingerprint(),
# is_valid_device_id()). Neither Android nor Desktop assume any fixed
# length for a scanned/pasted access code (checked both client trees — the
# QR parser and the manual-entry field both just carry through whatever
# string was scanned/typed), so raising this is a pure server-side/generator
# change with no client update required.
ACCESS_CODE_RANDOM_BYTES = 16
ACCESS_CODE_HEX_LEN      = 32


def is_valid_access_code(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == ACCESS_CODE_HEX_LEN
        and all(c in "0123456789ABCDEF" for c in value)
    )


# Only the SHA-256 hash of a NEW access code is ever written to SQLite now
# (external review 2026-09-05, S6-41) — the raw 128-bit value exists only
# long enough to print/QR-encode it to the operator at generation time; a
# stolen offline copy of `server_access_codes` no longer hands out
# immediately-usable server invitations. Unsalted is fine here for the same
# reason it's fine for `totp_recovery_codes`/anon tokens elsewhere in this
# file: these are server-generated, uniformly random 128-bit values, not
# low-entropy user secrets a rainbow table could target. Prefixed (rather
# than a bare hex hash) so `code`'s stored representation is unambiguously
# distinguishable at a glance — and, more importantly, so old low-entropy
# plaintext rows from before this fix can be mechanically detected and
# refused at startup (see the legacy-code check in start_server()) instead
# of silently accepted as if hashing them retroactively made them safe (it
# wouldn't — hashing a 32-bit secret only turns online guessing into
# offline hashing of at most 2^32 values, not real 128-bit security).
ACCESS_CODE_HASH_PREFIX = "sha256:"


def _hash_access_code(raw: str) -> str:
    return ACCESS_CODE_HASH_PREFIX + hashlib.sha256(raw.encode("ascii")).hexdigest()


_ACCESS_CODE_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Process-wide pre-SQLite attempt budget for access-code admission
# (external review 2026-09-05, S6-41) — same two-tier reasoning as
# global_prekey_publish_rate_ok()/OFFLINE_STORE_GLOBAL_LIMIT: the 128-bit
# credential itself is the real defense (online guessing is now
# computationally hopeless regardless of this budget), but a flood of
# syntactically-valid-looking guesses would otherwise each still pay for a
# BEGIN IMMEDIATE SQLite transaction before being told "no". This budget
# rejects excess attempts for free, before the executor/SQLite hop, same as
# every other RAM-only aggregate budget in this file. Conservative default
# sized for real invite-driven registrations (tens of new accounts per
# minute, not thousands) — deliberately NOT security-critical on its own;
# even at this budget's ceiling, guessing a 128-bit code online is not a
# realistic attack, this only bounds resource cost. Explicitly process-local
# — see this function's own comment for what a multi-process deployment
# would need instead.
ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT = int(os.environ.get("ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT", "60") or "60")
if ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT < 0:
    print("[FATAL] ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT должен быть >= 0 (0 явно отключает "
          "агрегатный лимитер попыток access_code) — отказ запуска, чтобы не работать с "
          "неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
ACCESS_CODE_GLOBAL_ENABLED    = ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT > 0
ACCESS_CODE_GLOBAL_WINDOW_SEC = 60

# Process-local aggregate counter — same "one independent budget PER
# PROCESS" caveat as every other RAM-only limiter in this file
# (global_prekey_publish_rate, fed_forward_rate_global, ...): a
# multi-process/replica deployment gets one independent budget per worker,
# not one shared budget across the deployment. The credential itself stays
# secure regardless (128-bit, atomically consumed in SQLite via BEGIN
# IMMEDIATE, so first-write-wins holds across workers sharing one DB file
# too) — a shared/gateway attempt limiter would only be needed for
# aggregate resource protection at that point, not credential security.
access_code_global_rate = {"count": 0, "reset_time": time.time()}


def access_code_global_rate_ok() -> bool:
    """No `await` here, so the check-and-increment is atomic on this single
    event loop — mirrors global_prekey_publish_rate_ok()'s own reasoning."""
    if not ACCESS_CODE_GLOBAL_ENABLED:
        return True
    now  = time.time()
    data = access_code_global_rate
    if now - data["reset_time"] >= ACCESS_CODE_GLOBAL_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT:
        return False
    data["count"] += 1
    return True

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

# REGISTERED_ACCOUNTS_HARD_MAX_ROWS (S6-56, external review 2026-09-06) —
# MAX_REGISTERED_USERS=0 above was documented and treated as "unlimited",
# with no ceiling of any kind underneath it. STEP-1 of this fix's own
# investigation confirmed that's the actual shipped default: .env.example
# explicitly tells personal-server operators to leave SERVER_ACCESS_PROTECTED
# off, neither it nor MAX_REGISTERED_USERS/POW_DIFFICULTY_BITS is set by
# start-son-server.bat, and POW_DIFFICULTY_BITS is a computational speed
# bump an operator can set to 0 — none of that is a durable ceiling. A
# remote client that can complete the handshake can keep minting brand-new
# fingerprints forever, each one a permanent row in registered_fingerprints
# plus whatever per-account state it goes on to create — unbounded durable
# growth from ordinary, unauthenticated traffic. This is the same class of
# gap S6-31/S6-44/S6-50/S6-47 already closed for the offline queue/anon
# tokens/avatars/channels — the root account registry needs the same
# always-on safety ceiling, independent of whatever policy cap (if any) an
# operator configures. Same value as AVATARS_MAX_TOTAL_ROWS (also a
# one-row-per-account table) — not a guess, that cap already assumes a
# deployment never legitimately exceeds this many real accounts.
REGISTERED_ACCOUNTS_HARD_MAX_ROWS = int(os.environ.get("REGISTERED_ACCOUNTS_HARD_MAX_ROWS", "1000000") or "1000000")
if REGISTERED_ACCOUNTS_HARD_MAX_ROWS <= 0:
    print("[FATAL] REGISTERED_ACCOUNTS_HARD_MAX_ROWS должен быть > 0 (обязательный потолок "
          "процесса/диска на количество когда-либо зарегистрированных аккаунтов, а не "
          "отключаемая опция) — отказ запуска.", flush=True)
    sys.exit(1)


def effective_registration_cap() -> int:
    """The cap actually enforced by db_admit_new_fingerprint() for a brand-
    new fingerprint (S6-56) — MAX_REGISTERED_USERS remains the operator's
    own deployment-specific policy cap (0 meaning "no smaller cap than the
    hard ceiling below", never "no ceiling at all" anymore), while
    REGISTERED_ACCOUNTS_HARD_MAX_ROWS is the always-on safety ceiling no
    configuration can raise past. An operator cap smaller than the hard
    ceiling still wins, exactly as before this fix."""
    if MAX_REGISTERED_USERS > 0:
        return min(MAX_REGISTERED_USERS, REGISTERED_ACCOUNTS_HARD_MAX_ROWS)
    return REGISTERED_ACCOUNTS_HARD_MAX_ROWS


# POW_DIFFICULTY_BITS: a brand-new fingerprint's first-ever register() must
# include a pow_nonce such that sha256(handshake_challenge + pow_nonce) has
# at least this many leading zero bits. Only paid once per identity, never
# again on reconnect — costs a real device real CPU time per fake account it
# wants to mint, which a per-IP limit can't touch. 0 = disabled. ~18 bits is
# sub-second on a phone but adds up fast at scale (avg 2^18 ≈ 262k hashes).
POW_DIFFICULTY_BITS = int(os.environ.get("POW_DIFFICULTY_BITS", "18") or "0")

# Process-wide pre-SQLite attempt budget for brand-new-fingerprint admission
# (S6-56) — independent of PoW, since PoW is itself an optional, disableable
# setting (POW_DIFFICULTY_BITS=0). Same two-tier reasoning as
# access_code_global_rate_ok() just above: REGISTERED_ACCOUNTS_HARD_MAX_ROWS
# is the real durable-resource boundary, but without this, an attacker
# hammering register() as fast as the network allows would still make every
# single one of those attempts pay for a real BEGIN IMMEDIATE SQLite
# transaction on the way to eventually hitting that cap. This budget rejects
# excess NEW-fingerprint attempts for free, before the executor/SQLite hop —
# an EXISTING fingerprint's ordinary reconnect never touches this at all,
# it's charged only to `is_new_fingerprint` attempts, same scoping
# ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT already uses. Conservative default sized
# for real organic registration traffic (tens of genuinely new accounts a
# minute), not a security boundary on its own — REGISTERED_ACCOUNTS_HARD_MAX_ROWS
# and (when enabled) PoW/access-code are what actually make Sybil growth
# expensive; this only bounds wasted per-attempt resource cost. Explicitly
# process-local, same caveat as every other RAM-only aggregate budget here.
NEW_ACCOUNT_GLOBAL_LIMIT = int(os.environ.get("NEW_ACCOUNT_GLOBAL_LIMIT", "60") or "60")
if NEW_ACCOUNT_GLOBAL_LIMIT < 0:
    print("[FATAL] NEW_ACCOUNT_GLOBAL_LIMIT должен быть >= 0 (0 явно отключает агрегатный "
          "лимитер попыток регистрации нового аккаунта) — отказ запуска, чтобы не работать "
          "с неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
NEW_ACCOUNT_GLOBAL_ENABLED    = NEW_ACCOUNT_GLOBAL_LIMIT > 0
NEW_ACCOUNT_GLOBAL_WINDOW_SEC = 60

new_account_global_rate = {"count": 0, "reset_time": time.time()}


def new_account_global_rate_ok() -> bool:
    """No `await` here, so the check-and-increment is atomic on this single
    event loop — mirrors access_code_global_rate_ok()'s own reasoning."""
    if not NEW_ACCOUNT_GLOBAL_ENABLED:
        return True
    now  = time.time()
    data = new_account_global_rate
    if now - data["reset_time"] >= NEW_ACCOUNT_GLOBAL_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= NEW_ACCOUNT_GLOBAL_LIMIT:
        return False
    data["count"] += 1
    return True


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
# Set env FEDERATION_PEERS to a comma-separated list of peer WebSocket URLs — must
# all be wss:// (see FEDERATION_PEERS_REQUIRE_WSS below), e.g.
# "wss://server2:9000,wss://server3:9000"

FEDERATION_SECRET = os.environ.get("FEDERATION_SECRET", "")
FEDERATION_PEERS  = [p.strip() for p in os.environ.get("FEDERATION_PEERS", "").split(",") if p.strip()]
# Optional CA bundle (PEM) used to verify federation peer certificates —
# lets a deployment run its own private federation CA and issue certs to
# its own peers, rather than needing publicly-trusted certs just for
# server-to-server federation traffic. If unset, the platform's normal
# trusted CA store is used (ssl.create_default_context()'s default) — fine
# for peers with real publicly-trusted certs, but self-signed peer certs
# will then fail verification (as they should — see build_federation_ssl_context()
# below for why CERT_NONE is never the answer to that).
FEDERATION_CA_FILE = os.environ.get("FEDERATION_CA_FILE", "").strip()
# SSRF/egress policy for DYNAMICALLY gossip-discovered peers only
# (peer_announce/peer_roster) — external review 2026-09-04. wss:// +
# CERT_REQUIRED (build_federation_ssl_context()) authenticates the peer's
# certificate and encrypts the link, but does nothing to restrict WHICH
# HOST an already-authorized peer can direct this server to open an
# outbound TLS connection to: a compromised/malicious peer could announce
# an internal hostname or IP (a LAN admin panel, a cloud metadata
# endpoint, localhost-bound services on this same machine) and get this
# server to connect to it. Comma-separated CIDR ranges (v4 or v6) that are
# allowed to be a dynamic peer's destination even though they're
# private/loopback/link-local/reserved — empty by default, meaning NO
# private-range destination is ever allowed for a gossip-discovered peer.
# Static, operator-configured FEDERATION_PEERS are NOT filtered by this —
# they're explicit operator trust, not attacker-influenced input. Set this
# only if your federation mesh genuinely spans a private network, e.g.
# "10.20.0.0/16,fd12:3456::/48" — never a blanket "allow all private", to
# keep the allowlist meaningfully narrower than "everything RFC 1918".
FEDERATION_ALLOWED_PRIVATE_CIDRS = []
for _cidr in os.environ.get("FEDERATION_ALLOWED_PRIVATE_CIDRS", "").split(","):
    _cidr = _cidr.strip()
    if not _cidr:
        continue
    try:
        FEDERATION_ALLOWED_PRIVATE_CIDRS.append(ipaddress.ip_network(_cidr, strict=False))
    except ValueError:
        print(f"[FEDERATION] Игнорирую невалидный FEDERATION_ALLOWED_PRIVATE_CIDRS элемент: {_cidr}")
# Own public WebSocket URL — sent to father via peer_announce so clients can discover this server.
# Example: "wss://myserver.ru" or "wss://myserver.ru:4433"
SERVER_URL        = os.environ.get("SERVER_URL", "")

federation_ws        = {}   # url → websocket | None  (outgoing connections to peers)
# req_id → {"future": asyncio.Future, "target": str, "created_at": float}
# (async prekey bundle requests). Was a bare req_id → Future (external
# review 2026-09-05, S6-46) — any connected peer receiving our own
# `federated_get_bundle` request already knows a valid req_id (it's echoed
# in that very request), so a response carrying only req_id let ANY
# connected peer resolve the pending lookup with arbitrary bundle content,
# whether or not it actually owned `target`. Storing the target THIS
# lookup was created for means handle_federation_response() can check a
# response's claimed target/bundle identity against ground truth this
# server itself chose, never against something the responding peer
# supplied — see that function's own comment and SECURITY_INVARIANTS.md
# #59.
fed_pending          = {}
# Hard process-wide ceiling on concurrently outstanding federated bundle
# lookups (external review 2026-09-05, S6-46) — each entry already
# self-expires within ~3s (federated_get_bundle()'s own timeout, enforced
# in its `finally` regardless of success/timeout/cancellation) and
# creating one requires passing the per-user "prekey_fetch" rate limit
# (10/min, rate_limit_check()) first, so aggregate growth is already
# fairly narrow — this is a belt-and-suspenders cap on TOTAL concurrent
# entries across every user and peer combined, not a redesign of either
# existing limiter. Required strictly positive, same fail-closed posture
# as MAILBOX_MAX_TOTAL_BYTES/PENDING_MESSAGES_MAX_ROWS elsewhere in this
# file.
FED_PENDING_MAX = int(os.environ.get("FED_PENDING_MAX", "2000") or "2000")
if FED_PENDING_MAX <= 0:
    print("[FATAL] FED_PENDING_MAX должен быть > 0 (это защита процесса, "
          "а не отключаемая опция) — отказ запуска.", flush=True)
    sys.exit(1)

# Canonical req_id shape check (external review 2026-09-05, S6-46) —
# federated_get_bundle() always mints req_id via secrets.token_hex(8):
# exactly 16 LOWERCASE hex characters (unlike the 16 UPPERCASE hex
# fingerprint shape — is_valid_fingerprint()'s own comment). A peer
# response carrying anything else can never match a real fed_pending
# entry anyway (dict lookup would just miss), but rejecting the shape
# explicitly before using it as a lookup key or ever reflecting it back
# into a federated_bundle_response keeps this file's "reject non-
# canonical input outright" posture consistent everywhere it mints or
# echoes a token of its own. Deliberately does NOT normalize (case-fold,
# strip, etc.) for the same reason is_valid_fingerprint() doesn't.
def is_valid_fed_req_id(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 16
        and all(c in "0123456789abcdef" for c in value)
    )


dynamic_peer_urls    = set() # URLs announced via peer_announce (discovered at runtime)
dynamic_peer_strikes = {}    # url → consecutive failure count (too many → evict)
# url → the asyncio.Task running that dynamic peer's federation_connect_to_peer()
# reconnect loop — see start_dynamic_peer()'s own comment (external review
# 2026-09-04) for why this registry exists: without it there was no way to
# actually CANCEL a dynamic peer's persistent reconnect loop, only to stop
# tracking it in dynamic_peer_urls, which the loop itself never consulted.
dynamic_peer_tasks   = {}
_fed_ssl_ctx         = None  # SSL context for outgoing federation connections
incoming_peer_ws     = set() # websocket objects of authenticated incoming federation peers

DYNAMIC_PEER_MAX_STRIKES = 3   # evict dynamic peer after this many hourly misses
# Unbounded dynamic-peer gossip DoS (external review 2026-09-04) — a
# malicious/compromised federation peer's peer_roster could previously list
# an unlimited number of URLs, each becoming a permanent dynamic_peer_urls
# entry AND an infinite-reconnect asyncio.Task (federation_connect_to_peer()'s
# own `while True`), costing memory, sockets, DNS/TLS CPU, and outbound
# traffic per bogus entry, indefinitely — a single malicious gossip message
# could mint thousands of these. MAX_DYNAMIC_PEERS caps the total dynamic
# roster this server will ever hold at once (independent of how many
# distinct peers gossip URLs at it); MAX_ROSTER_PEERS caps how many URLs a
# SINGLE peer_roster message can introduce (a well-behaved deployment's
# entire mesh is expected to be small — tens of servers, not thousands);
# MAX_PEER_URL_LEN bounds a single URL's length before it's even parsed,
# so a peer can't send a pathological string to burn CPU or memory on a
# per-URL basis before the count limits above even apply.
MAX_DYNAMIC_PEERS = 64
MAX_ROSTER_PEERS   = 32
MAX_PEER_URL_LEN   = 512


def build_federation_ssl_context() -> ssl.SSLContext:
    """Real TLS peer authentication for outgoing federation connections
    (external review 2026-09-04) — replaces an SSL context that used to
    set `check_hostname = False` / `verify_mode = ssl.CERT_NONE`
    unconditionally. That combination means TLS still encrypts the link,
    but authenticates NOBODY on the other end — any MITM that can
    intercept the TCP connection (compromised network, malicious/coerced
    upstream, DNS/BGP hijack of the peer hostname) can terminate its own
    TLS session with each side and sit in the middle, relaying frames.

    The federation HMAC handshake (FEDERATION_SECRET) does NOT compensate
    for this: it authenticates the two ENDPOINTS' knowledge of the shared
    secret, but not the TLS CHANNEL each endpoint is actually talking
    through. A MITM never needs to know FEDERATION_SECRET at all — it just
    relays the challenge and the HMAC response verbatim between two real
    TLS sessions it separately terminates, and both real endpoints see a
    valid federation_auth exchange with each other. Past that point,
    federation frames have no per-message MAC or channel binding of their
    own, so the MITM can read and modify every frame on the link
    indefinitely. This is exactly why "TLS encryption without peer
    verification" is not an acceptable substitute for "TLS peer
    authentication" — see SECURITY_INVARIANTS.md's federation-TLS
    invariant.

    For a deployment with only self-signed peer certificates: the answer
    is a private federation CA (issue each peer server a cert signed by
    it, point every peer's FEDERATION_CA_FILE at that CA's certificate),
    never CERT_NONE. Real, verifiable certificate chains for
    server-to-server federation traffic are not meaningfully harder to
    operate than a shared HMAC secret already is."""
    if FEDERATION_CA_FILE:
        ctx = ssl.create_default_context(cafile=FEDERATION_CA_FILE)
    else:
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def is_valid_federation_url(url: str) -> bool:
    return url.lower().startswith("wss://")


def parse_federation_url(url: str):
    """Strict URL-syntax gate for a DYNAMIC (gossip-discovered) federation
    peer URL, ahead of any network activity at all — external review
    2026-09-04, first of three checks (syntax → destination-address policy
    → DNS) a dynamic peer must pass before start_dynamic_peer() ever runs.
    Returns (hostname, port) on success, None on anything else: wrong/
    missing scheme (must be exactly "wss", not just "starts with wss://" —
    catches accidental empty-hostname forms like "wss:///path" that
    startswith() alone would miss), no hostname at all, embedded
    userinfo (a federation URL has no legitimate use for `user:pass@host`
    — silently dropping it, as urlparse's own .hostname/.port already do,
    would be surprising; refusing outright is safer), or an unparseable
    port. Defaults to 443 (wss's standard port) when none is given,
    matching what websockets.connect() itself would use."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None

    if parsed.scheme.lower() != "wss":
        return None

    if not parsed.hostname:
        return None

    if parsed.username is not None or parsed.password is not None:
        return None

    try:
        port = parsed.port or 443
    except ValueError:
        return None

    return parsed.hostname, port


def _federation_ip_allowed(ip_str: str) -> bool:
    """Destination-address policy, second of the three dynamic-peer gates
    (external review 2026-09-04) — wss:// + CERT_REQUIRED authenticates
    WHO the peer's certificate says it is, but says nothing about WHERE
    this server is being told to open an outbound TLS connection to. A
    compromised/malicious federation peer could otherwise announce an
    internal hostname/IP (a LAN admin panel, a cloud metadata endpoint,
    localhost-bound services on this same machine) and get this server to
    connect to it — TLS/certificate verification does not defend against
    that at all, since the malicious "peer" IS the connection's actual
    destination in that scenario, not an interceptor.

    Fail-closed: any address that isn't unambiguously public
    (loopback/private/link-local/multicast/unspecified/reserved, per
    Python's own ipaddress classification) is rejected UNLESS it falls
    inside an operator-configured FEDERATION_ALLOWED_PRIVATE_CIDRS range —
    empty by default, so by default no private-range destination is ever
    allowed for a gossip-discovered peer at all."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if not (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    ):
        return True

    return any(ip in net for net in FEDERATION_ALLOWED_PRIVATE_CIDRS)


async def federation_host_allowed(host: str, port: int) -> bool:
    """Third dynamic-peer gate: resolve `host` and check EVERY returned
    address against _federation_ip_allowed() (external review 2026-09-04)
    — fail-closed on a single disallowed A/AAAA record, a DNS failure, or
    an empty result, not just the first address returned.

    Known, accepted residual gap — DNS TOCTOU/rebinding: this resolves
    `host` now, but federation_connect_to_peer()'s own
    `websockets.connect(url, ...)` resolves it AGAIN independently when it
    actually opens the connection; the two resolutions are not atomic, and
    a host controlled by an attacker (or an attacker with DNS-cache-poisoning
    reach) could serve a public address to this check and then a private one
    to the real connection attempt moments later. This check meaningfully
    raises the bar (an attacker needs active DNS control at exactly the
    right moment, not just a one-time malicious A record) but is not a
    complete fix for that class of attack. A fully rebinding-proof design
    would need to resolve once, connect directly to the verified IP, and
    keep the original hostname only for SNI/certificate hostname
    verification — or, simpler and more robust, enforce this at the
    network layer (firewall/container egress policy restricting the
    federation process to known peer CIDRs/ports) rather than in
    application code at all. Neither is implemented here; see
    SECURITY_INVARIANTS.md #37 and KNOWN_SECURITY_ISSUES.md OPEN-11 for the
    residual gap, tracked explicitly rather than silently accepted."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        return False

    addresses = {info[4][0] for info in infos if info and info[4]}
    if not addresses:
        return False

    return all(_federation_ip_allowed(ip) for ip in addresses)


def start_dynamic_peer(url: str) -> bool:
    """Single entry point for admitting a gossip-discovered (peer_roster/
    peer_announce) federation peer — external review 2026-09-04. Replaces
    every previous call site's own direct `dynamic_peer_urls.add(url)` +
    `asyncio.create_task(federation_connect_to_peer(url, _fed_ssl_ctx))`
    pair, which had two problems: (1) no cap on how many dynamic peers
    could ever accumulate — see MAX_DYNAMIC_PEERS's own comment for the
    DoS this enables; (2) the created Task was never tracked anywhere, so
    nothing could ever cancel it later — federation_watchdog()'s eviction
    only ever removed the URL from dynamic_peer_urls/dynamic_peer_strikes/
    federation_ws, leaving that peer's infinite reconnect loop running in
    the background forever, invisible and unstoppable. dynamic_peer_tasks
    now makes that loop cancellable (see the watchdog's eviction block),
    and federation_connect_to_peer(dynamic=True) additionally
    self-terminates if its own URL is no longer in dynamic_peer_urls, so a
    lost/failed cancellation still doesn't resurrect an evicted peer on its
    next reconnect attempt.

    Caller is responsible for URL validation (is_valid_federation_url(),
    length bounds) BEFORE calling this — this function only enforces the
    total-count cap and de-duplication, not URL shape."""
    if len(dynamic_peer_urls) >= MAX_DYNAMIC_PEERS:
        print(f"[SECURITY] start_dynamic_peer: MAX_DYNAMIC_PEERS ({MAX_DYNAMIC_PEERS}) достигнут, отклонён {url}")
        return False

    if url in dynamic_peer_urls or url in FEDERATION_PEERS:
        return False

    dynamic_peer_urls.add(url)

    task = asyncio.create_task(federation_connect_to_peer(url, _fed_ssl_ctx, dynamic=True))
    dynamic_peer_tasks[url] = task

    def _done(_):
        # Only clear the registry entry if IT'S the task we're tracking —
        # a fresh reconnect for the same URL after an eviction-then-
        # re-announce could otherwise have this stale callback pop the
        # NEW task's entry out from under it.
        if dynamic_peer_tasks.get(url) is task:
            dynamic_peer_tasks.pop(url, None)

    task.add_done_callback(_done)
    return True

# ─── Incoming federated_forward: bounded dedup + rate limits ──────────────────
# (external review 2026-09-04, S6-34) — federated_forward previously had NO
# dedicated rate limit at all (any authenticated peer could forward as fast
# as it could write to the socket), and its dedup dict (delivered_msg_ids)
# had a TTL but no hard entry cap — an attacker peer (or a compromised one)
# sending a flood of UNIQUE msg_ids within the 5-minute TTL grew this dict
# without bound. Worse, the OLD cleanup rescanned the ENTIRE dict on every
# single incoming message (`[k for k, v in list(delivered_msg_ids.items())
# if now - v > 300]`) — O(N) work per message, so a sustained flood of unique
# IDs was O(N^2) total CPU while ALSO growing RAM, a genuine DoS via a
# supposedly-trusted peer connection. See FED_DEDUP_MAX_IDS's own comment for
# the hard-cap fix and _federation_dedup_cleanup_locked()'s own comment for
# the O(1)-per-message cleanup fix.
FED_FORWARD_WINDOW_SEC   = 60
# Frame-shape bounds — a federated_forward's `to`/`payload["id"]` are never
# trusted to be well-formed just because the connection is an authenticated
# peer (external review 2026-09-04, S6-34): an unhashable/oversized value
# reaching a dict/set lookup (delivered_msg_ids/federation_delivery_inflight)
# would raise (TypeError for unhashable, or simply blow up memory/CPU for an
# absurdly long string) — validated up front instead, a bad frame is just
# `continue`d, never allowed to tear down the whole peer handler loop.
FED_MAX_TO_LEN           = 256
FED_DEDUP_MAX_MSG_ID_LEN = 128
# Abuse-mitigation knobs, same "0 = explicitly disabled, negative refuses to
# start" convention as PREKEY_PUBLISH_GLOBAL_LIMIT/OFFLINE_STORE_GLOBAL_LIMIT
# — a federation peer is already authenticated (knows FEDERATION_SECRET), but
# authenticated does not mean trusted-to-flood; these bound how much forward
# traffic ONE peer IP (fairness) and ALL peers COMBINED (aggregate capacity)
# can push through this server per window, independent of the hard dedup
# caps below (which protect RAM regardless of whether traffic is legitimate).
FED_FORWARD_PER_IP_LIMIT = int(os.environ.get("FED_FORWARD_PER_IP_LIMIT", "120") or "120")
FED_FORWARD_GLOBAL_LIMIT = int(os.environ.get("FED_FORWARD_GLOBAL_LIMIT", "1000") or "1000")
if FED_FORWARD_PER_IP_LIMIT < 0 or FED_FORWARD_GLOBAL_LIMIT < 0:
    print("[FATAL] FED_FORWARD_PER_IP_LIMIT и FED_FORWARD_GLOBAL_LIMIT должны быть >= 0 "
          "(0 явно отключает соответствующий лимитер) — отказ запуска, чтобы не работать "
          "с неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
FED_FORWARD_PER_IP_ENABLED = FED_FORWARD_PER_IP_LIMIT > 0
FED_FORWARD_GLOBAL_ENABLED = FED_FORWARD_GLOBAL_LIMIT > 0

# Process-local counters — same "one independent budget PER PROCESS, not one
# shared budget across a multi-replica deployment" caveat as every other
# RAM-only rate limiter in this file (global_prekey_publish_rate,
# global_offline_store_rate) — see their own comments.
fed_forward_rate_per_ip: dict = {}   # ip -> {"count": int, "reset_time": float}
fed_forward_rate_global = {"count": 0, "reset_time": time.time()}


def fed_forward_rate_per_ip_ok(ip: str) -> bool:
    """Per-peer-IP federated_forward budget — fairness between peers, same
    role as invariant 40's per-user prekey_publish bucket. No `await` here,
    so the check-and-increment is atomic on this single event loop."""
    if not FED_FORWARD_PER_IP_ENABLED:
        return True
    now = time.time()
    entry = fed_forward_rate_per_ip.get(ip)
    if not entry or now >= entry["reset_time"]:
        fed_forward_rate_per_ip[ip] = {"count": 1, "reset_time": now + FED_FORWARD_WINDOW_SEC}
        return True
    entry["count"] += 1
    return entry["count"] <= FED_FORWARD_PER_IP_LIMIT


def fed_forward_rate_global_ok() -> bool:
    """Server-wide aggregate federated_forward budget, layered ON TOP of the
    per-IP one — same two-tier reasoning as invariant 41's
    global_prekey_publish_rate_ok() (Sybil/multi-peer amplification guard):
    per-IP fairness alone doesn't bound how much a mesh of many peer
    connections can collectively push through this one process."""
    if not FED_FORWARD_GLOBAL_ENABLED:
        return True
    now  = time.time()
    data = fed_forward_rate_global
    if now - data["reset_time"] >= FED_FORWARD_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= FED_FORWARD_GLOBAL_LIMIT:
        return False
    data["count"] += 1
    return True


# ─── federated_forward byte/resource admission (S6-62) ─────────────────────
# FED_FORWARD_PER_IP_LIMIT/GLOBAL_LIMIT above bound MESSAGE COUNT only. A
# compromised/authenticated federation peer could send up to that many
# frames each near FEDERATION_MAX_PACKET_SIZE_BYTES (12 MiB), forcing
# json.loads()/validation/reserialization/relay-or-store work with no byte
# ceiling of its own — up to ~1.44 GB/window from one peer IP, ~12 GB/window
# aggregate, worst case. The largest LEGITIMATE inner payload forward_to_peers()
# ever produces is bounded by MAX_PACKET_SIZE_BYTES (6 MiB, the raw-frame
# ceiling every local client message — including one later forwarded — was
# already bounded by on the way in); only message_delete/disappear_timer/
# group_message_delete (sanitize_chat_control, ~2 KiB) and voice
# (sanitize_voice_payload, ~4 MiB) get a tighter per-type bound today —
# message/session_init/group_message/group_create/group_reaction/
# group_member_removed/group_member_added/group_key_rotation/
# group_invite_accepted have none. Federation is off by default
# (FEDERATION_SECRET/FEDERATION_PEERS both empty unless an operator
# explicitly configures them), so this requires a compromised/malicious
# already-authenticated peer, not an anonymous remote attacker — classified
# Medium accordingly, same reasoning as KL-30/S6-38's own federation-scope
# precedent.
FED_FORWARD_MAX_PAYLOAD_BYTES = MAX_PACKET_SIZE_BYTES + 4096   # legit max + small envelope headroom, mirrors ANON_DELIVERY_MAX_PACKET_SIZE_BYTES's own pattern

FED_FORWARD_PEER_MAX_BYTES  = int(os.environ.get("FED_FORWARD_PEER_MAX_BYTES", str(50 * 1024 * 1024)) or str(50 * 1024 * 1024))
FED_FORWARD_PEER_WINDOW_SEC = FED_FORWARD_WINDOW_SEC
fed_forward_byte_rate_per_ip: dict = {}   # ip -> {"bytes": int, "reset_time": float}


def fed_forward_byte_rate_per_ip_ok(ip: str, nbytes: int) -> bool:
    """Per-peer-IP federated_forward byte budget, layered on top of
    fed_forward_rate_per_ip_ok()'s existing count limit — same two-dimension
    reasoning as call_signal_user_rate_ok()'s own comment. Keyed only by the
    connection's own peer IP, never attacker-supplied."""
    now = time.time()
    entry = fed_forward_byte_rate_per_ip.get(ip)
    if not entry or now - entry["reset_time"] >= FED_FORWARD_PEER_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        fed_forward_byte_rate_per_ip[ip] = entry
    if entry["bytes"] + nbytes > FED_FORWARD_PEER_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


FED_FORWARD_GLOBAL_MAX_BYTES  = int(os.environ.get("FED_FORWARD_GLOBAL_MAX_BYTES", str(200 * 1024 * 1024)) or str(200 * 1024 * 1024))
FED_FORWARD_GLOBAL_BYTE_WINDOW_SEC = FED_FORWARD_WINDOW_SEC
fed_forward_byte_rate_global = {"bytes": 0, "reset_time": time.time()}


def fed_forward_byte_rate_global_ok(nbytes: int) -> bool:
    """Aggregate byte budget across ALL federation peers combined — a mesh
    of several compromised peers each staying under their own per-IP budget
    could otherwise still push unbounded aggregate bytes through this
    process. Same two-tier reasoning as fed_forward_rate_global_ok()."""
    now  = time.time()
    data = fed_forward_byte_rate_global
    if now - data["reset_time"] >= FED_FORWARD_GLOBAL_BYTE_WINDOW_SEC:
        data["bytes"]      = 0
        data["reset_time"] = now
    if data["bytes"] + nbytes > FED_FORWARD_GLOBAL_MAX_BYTES:
        return False
    data["bytes"] += nbytes
    return True


# Per-recipient budget — protects one LOCAL victim from being flooded via
# federated_forward specifically, the same role CALL_SIGNAL_RECIPIENT_MAX_BYTES/
# ANON_RELAY_RECIPIENT_MAX_BYTES play for their own transports. Keyed only
# after `to` has already passed is_valid_fingerprint() at the call site —
# never an attacker-minted arbitrary string, so this dict's key space stays
# bounded by real local account count.
FED_FORWARD_RECIPIENT_MAX_BYTES  = int(os.environ.get("FED_FORWARD_RECIPIENT_MAX_BYTES", str(20 * 1024 * 1024)) or str(20 * 1024 * 1024))
FED_FORWARD_RECIPIENT_WINDOW_SEC = FED_FORWARD_WINDOW_SEC
fed_forward_byte_rate_recipient: dict = {}   # recipient fingerprint -> {"bytes": int, "reset_time": float}


def fed_forward_byte_rate_recipient_ok(recipient: str, nbytes: int) -> bool:
    now = time.time()
    entry = fed_forward_byte_rate_recipient.get(recipient)
    if not entry or now - entry["reset_time"] >= FED_FORWARD_RECIPIENT_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        fed_forward_byte_rate_recipient[recipient] = entry
    if entry["bytes"] + nbytes > FED_FORWARD_RECIPIENT_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


# Hard, always-on caps on the dedup structures themselves — unlike the rate
# limiters above, these protect the PROCESS from unbounded RAM growth
# regardless of whether the incoming traffic is legitimate or malicious, so
# (same posture as MAILBOX_MAX_TOTAL_BYTES/TOKEN_PENDING_MAX_TOTAL_BYTES/
# PENDING_MESSAGES_MAX_TOTAL_BYTES) they're required strictly positive, not
# "0 = disabled".
FED_DEDUP_TTL_SEC      = 300
FED_DEDUP_MAX_IDS      = int(os.environ.get("FED_DEDUP_MAX_IDS", "20000"))
FED_DEDUP_MAX_INFLIGHT = int(os.environ.get("FED_DEDUP_MAX_INFLIGHT", "2000"))
if FED_DEDUP_MAX_IDS <= 0 or FED_DEDUP_MAX_INFLIGHT <= 0:
    print("[FATAL] FED_DEDUP_MAX_IDS и FED_DEDUP_MAX_INFLIGHT должны быть > 0 (обязательная "
          "защита процесса от неограниченного роста, а не отключаемая опция) — отказ "
          "запуска.", flush=True)
    sys.exit(1)

# msg_id -> delivered timestamp, ONLY for msg_ids whose local handoff
# (online send or durable offline store) actually succeeded — see
# federated_forward's own comment for the two-phase (reserve/handoff/
# resolve) flow this backs. OrderedDict, not a plain dict: insertion order
# is also, by construction, ascending delivery-timestamp order (every write
# either appends a brand-new key or is a fresh insert after a pop — Python
# dicts/OrderedDicts don't reorder on a value-only update, so as long as
# nothing ever re-inserts an already-present key mid-dict, the OLDEST entry
# is always first) — this is what lets
# _federation_dedup_cleanup_locked() below expire entries in O(1) amortized
# per message instead of rescanning the whole structure.
delivered_msg_ids: "OrderedDict[str, float]" = OrderedDict()

# msg_ids currently reserved for an in-flight local handoff (Phase A has run,
# Phase C hasn't yet) — a SEPARATE structure from delivered_msg_ids, not a
# "pending" flag inside it, so a concurrent duplicate frame for the same
# msg_id can be recognized and dropped WHILE the first one is still being
# delivered/stored, not just after it durably lands.
federation_delivery_inflight: set = set()

# Dedicated, narrow lock for the two structures above — deliberately NOT the
# global server-wide `lock` (invariant 34's "no DB/network await under the
# global lock" rule would otherwise apply here too, and Phase B's
# send_safe()/db_store() calls are exactly the kind of await this lock must
# never be held across). Never held across a network or DB call — every
# acquisition in federated_forward is a short, RAM-only critical section.
federation_dedup_lock = asyncio.Lock()


def _federation_dedup_cleanup_locked(now: float) -> None:
    """Expires entries from delivered_msg_ids whose TTL has passed — MUST be
    called with federation_dedup_lock already held. Because delivered_msg_ids
    is an OrderedDict and every entry is appended in delivery order (see its
    own comment), the OLDEST entry is always the first one — repeatedly
    peeking and popping just that one entry, stopping the instant it's not
    yet expired, does the same job a full `[k for k, v in ... if expired]`
    rescan used to do, in O(expired-count) instead of O(N) — and O(1) on the
    common case where nothing at the front has expired yet. This is what
    keeps a flood of unique msg_ids from being O(N^2) CPU on top of the
    unbounded RAM growth FED_DEDUP_MAX_IDS separately caps (external review
    2026-09-04, S6-34)."""
    while delivered_msg_ids:
        oldest_id, oldest_ts = next(iter(delivered_msg_ids.items()))
        if now - oldest_ts <= FED_DEDUP_TTL_SEC:
            break
        delivered_msg_ids.popitem(last=False)


# ─── Rate limit для входящих федеративных пиров ───────────────────────────────
FED_BUNDLE_LIMIT   = 60    # максимум запросов prekey bundle от одного пира за окно
FED_BUNDLE_WINDOW  = 60    # секунд в окне
FED_BUNDLE_BAN_SEC = 3600  # бан на 1 час при превышении
fed_bundle_rate    = {}    # ip → {"count": int, "reset_time": float}
fed_bundle_banned  = {}    # ip → ban_until timestamp

# ─── OPK issuance abuse guards (external review 2026-09-04, S6-36) ────────────
# S6-26 made OPK consumption durable/single-use; S6-35 bounded and validated
# the per-target lock registry. Neither stops a caller who is otherwise fully
# authorized to fetch prekey bundles (per-user "prekey_fetch" under
# rate_limit_check(), or an authenticated federation peer under
# FED_BUNDLE_LIMIT) from repeatedly re-fetching the SAME target's bundle and
# draining a fresh one-time OPK every single call -- no session_init or
# actual X3DH handshake is ever required to do this, so it is pure
# OPK-issuance abuse, a different problem than the bundle-FETCH-volume limits
# above already cover.
#
# Defaults chosen after inspecting Android's actual pool: SessionKeyManager
# refills the OPK pool to a target size of 10 (refillOpkPool(context,
# targetCount=10)) and this server already nudges a republish once a
# target's remaining count drops below OPK_LOW_WATERMARK (5, see
# consume_prekey_bundle_for_serve()). These guard defaults stay well under
# that pool size so a legitimate burst of new contacts (each needing exactly
# one real OPK) is never the reason a request gets throttled, while still
# bounding how fast one target's real pool -- or the whole server's
# aggregate OPK-issuance rate -- can be drained by a requester that never
# actually completes a session.
#
# Same "0 = explicitly disabled, negative refuses to start" convention as
# PREKEY_PUBLISH_GLOBAL_LIMIT/OFFLINE_STORE_GLOBAL_LIMIT/FED_FORWARD_*_LIMIT
# for the two budgets and the cooldown; the two WINDOW_SEC durations are
# plain durations (0 doesn't mean anything sensible for a sliding-window
# width), so those are only required to be strictly positive.
OPK_PAIR_COOLDOWN_SEC     = int(os.environ.get("OPK_PAIR_COOLDOWN_SEC", "300") or "300")
OPK_TARGET_WINDOW_SEC     = int(os.environ.get("OPK_TARGET_WINDOW_SEC", "60") or "60")
OPK_TARGET_MAX_PER_WINDOW = int(os.environ.get("OPK_TARGET_MAX_PER_WINDOW", "5") or "5")
OPK_GLOBAL_WINDOW_SEC     = int(os.environ.get("OPK_GLOBAL_WINDOW_SEC", "60") or "60")
OPK_GLOBAL_MAX_PER_WINDOW = int(os.environ.get("OPK_GLOBAL_MAX_PER_WINDOW", "300") or "300")
if OPK_TARGET_WINDOW_SEC <= 0 or OPK_GLOBAL_WINDOW_SEC <= 0:
    print("[FATAL] OPK_TARGET_WINDOW_SEC и OPK_GLOBAL_WINDOW_SEC должны быть > 0 (это ширина "
          "скользящего окна, а не отключаемая опция) — отказ запуска.", flush=True)
    sys.exit(1)
if OPK_PAIR_COOLDOWN_SEC < 0 or OPK_TARGET_MAX_PER_WINDOW < 0 or OPK_GLOBAL_MAX_PER_WINDOW < 0:
    print("[FATAL] OPK_PAIR_COOLDOWN_SEC, OPK_TARGET_MAX_PER_WINDOW и OPK_GLOBAL_MAX_PER_WINDOW "
          "должны быть >= 0 (0 явно отключает соответствующий guard) — отказ запуска, чтобы не "
          "работать с неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
OPK_PAIR_COOLDOWN_ENABLED = OPK_PAIR_COOLDOWN_SEC > 0
OPK_TARGET_ENABLED        = OPK_TARGET_MAX_PER_WINDOW > 0
OPK_GLOBAL_ENABLED        = OPK_GLOBAL_MAX_PER_WINDOW > 0

# (requester_scope, target) -> last-issuance timestamp. Created ONLY after
# db_consume_prekey_opk() actually popped a fresh OPK for that pair (see
# opk_record_pair_issuance()) -- a fake/nonexistent target, or one whose
# pool is already empty, never reaches that point and therefore never mints
# an entry here. OrderedDict, re-inserted (moved to the end) on every
# record, so entries stay in ascending issuance-time order -- the same
# trick delivered_msg_ids/_federation_dedup_cleanup_locked() (S6-34) uses --
# which is what lets _opk_pair_cleanup() expire only the stale FRONT in O(1)
# amortized instead of rescanning the whole structure. Bounded in practice
# by OPK_GLOBAL_MAX_PER_WINDOW: at most that many NEW entries can be minted
# per OPK_GLOBAL_WINDOW_SEC, and every entry older than OPK_PAIR_COOLDOWN_SEC
# is lazily pruned, so the live size never exceeds roughly
# (OPK_GLOBAL_MAX_PER_WINDOW / OPK_GLOBAL_WINDOW_SEC) * OPK_PAIR_COOLDOWN_SEC
# pairs, regardless of how many distinct requester_scopes or targets are
# involved.
opk_pair_last_issued: "OrderedDict[tuple, float]" = OrderedDict()

# target -> {"count": int, "reset_time": float} -- per-target aggregate
# issuance budget, only ever created for a target that already has a real
# bundle with at least one OPK available (same "no state for fake/empty
# targets" rule as opk_pair_last_issued above). Bounded by the number of
# real accounts that ever had someone consume one of their OPKs -- not an
# attacker-multipliable dimension the way per-requester state would be,
# since is_valid_fingerprint() alone doesn't make an arbitrary string an
# existing account with OPKs to drain.
opk_target_window: dict = {}

# Single server-wide aggregate counter, same shape as global_prekey_publish_
# rate/fed_forward_rate_global.
opk_global_window = {"count": 0, "reset_time": time.time()}


def opk_pair_cooldown_active(requester_scope: str, target: str, now: float) -> bool:
    """True if requester_scope was already issued an OPK for target within
    OPK_PAIR_COOLDOWN_SEC. Read-only -- does not itself record anything;
    call opk_record_pair_issuance() separately, and only after an OPK was
    ACTUALLY consumed (see consume_prekey_bundle_for_serve()'s own comment).
    Synchronous, no `await` -- safe to call from within a single coroutine's
    prekey_mutation_guard(target) span with no other coroutine able to
    interleave on this same target in between."""
    if not OPK_PAIR_COOLDOWN_ENABLED:
        return False
    last = opk_pair_last_issued.get((requester_scope, target))
    return last is not None and (now - last) < OPK_PAIR_COOLDOWN_SEC


def opk_record_pair_issuance(requester_scope: str, target: str, now: float) -> None:
    """Called ONLY after db_consume_prekey_opk() actually popped a fresh
    OPK for (requester_scope, target) -- never on a guard-rejected or
    nonexistent/empty-pool attempt, see this dict's own comment. Re-inserts
    (pop then set) so an already-present pair always moves to the back,
    keeping ascending issuance-time order for _opk_pair_cleanup()."""
    opk_pair_last_issued.pop((requester_scope, target), None)
    opk_pair_last_issued[(requester_scope, target)] = now


def _opk_pair_cleanup(now: float) -> None:
    """Lazily expires pair-cooldown entries older than OPK_PAIR_COOLDOWN_SEC
    -- same oldest-entry-only trick as _federation_dedup_cleanup_locked()
    (S6-34). Safe without a dedicated lock: every caller only ever touches
    this from within its own coroutine's prekey_mutation_guard(target) span
    with no `await` in between, so nothing else can interleave on this
    single event loop while it runs."""
    if not OPK_PAIR_COOLDOWN_ENABLED:
        return
    while opk_pair_last_issued:
        _oldest_key, oldest_ts = next(iter(opk_pair_last_issued.items()))
        if now - oldest_ts <= OPK_PAIR_COOLDOWN_SEC:
            break
        opk_pair_last_issued.popitem(last=False)


def opk_target_budget_ok(target: str, now: float) -> bool:
    """Per-target aggregate OPK-issuance budget -- bounds how fast ONE
    target's real pool can be drained regardless of how many distinct
    requester_scopes are used to do it (many Sybil usernames locally, or a
    federation peer retrying under a new source IP). Reserves (increments)
    the instant a request is admitted, same fail-closed convention as
    OFFLINE_STORE_GLOBAL_LIMIT/global_prekey_publish_rate_ok() -- NOT
    refunded if the subsequent durable consume raises; see
    consume_prekey_bundle_for_serve()'s own comment. No `await` here, so the
    check-and-increment is atomic on this single event loop. Only ever
    called after the caller already confirmed target has a real bundle with
    an available OPK -- a nonexistent/empty-pool target never reaches here
    and therefore never creates an entry."""
    if not OPK_TARGET_ENABLED:
        return True
    entry = opk_target_window.get(target)
    if not entry or now >= entry["reset_time"]:
        opk_target_window[target] = {"count": 1, "reset_time": now + OPK_TARGET_WINDOW_SEC}
        return True
    if entry["count"] >= OPK_TARGET_MAX_PER_WINDOW:
        return False
    entry["count"] += 1
    return True


def opk_global_budget_ok(now: float) -> bool:
    """Server-wide aggregate OPK-issuance budget, layered ON TOP of the
    per-target one -- same two-tier reasoning as global_prekey_publish_
    rate_ok()/fed_forward_rate_global_ok(): many DIFFERENT target accounts,
    each individually staying under its own per-target budget, must not
    collectively turn OPK consumption into unbounded aggregate SQLite-write
    amplification."""
    if not OPK_GLOBAL_ENABLED:
        return True
    if now - opk_global_window["reset_time"] >= OPK_GLOBAL_WINDOW_SEC:
        opk_global_window["count"]      = 0
        opk_global_window["reset_time"] = now
    if opk_global_window["count"] >= OPK_GLOBAL_MAX_PER_WINDOW:
        return False
    opk_global_window["count"] += 1
    return True


# ─── Offline Message Queue (SQLite) ───────────────────────────────────────────
# Messages for offline users are stored here and flushed on reconnect.
# Configure with env vars:  DB_PATH (default: messages.db), MSG_TTL_DAYS (default: 30)

DB_PATH     = os.environ.get("DB_PATH", "messages.db")
MSG_TTL_SEC = int(os.environ.get("MSG_TTL_DAYS", "30")) * 86400

# Hard process-wide capacity bounds on the durable offline queue (external
# review 2026-09-04, S6-31) — MSG_TTL_SEC alone only bounds how long a row
# CAN live, not how much it can grow WHILE still within that window. An
# attacker who keeps at least one recipient permanently offline (trivial —
# just never connect that fingerprint) could otherwise persist an unbounded
# number of SQLite rows for the full TTL, across every relay path that
# reaches db_store() (message, session_init, edit, reaction, voice, group_*,
# missed_call, ...) — several of which (voice in particular) have no
# per-message-type rate limit of their own at all. These three caps bound
# worst-case SQLite growth regardless of how many distinct message types or
# attacker-controlled identities are involved.
#
# Same "always-on, not an optional knob" posture as
# MAILBOX_MAX_TOTAL_BYTES/MAILBOX_MAX_TOTAL_BLOBS (see their own comment) —
# strictly positive required, not "0 = disabled": this protects the
# process/disk from unbounded growth, not abuse-mitigation a deployment
# might reasonably want to turn off.
#
# PENDING_MESSAGE_MAX_BYTES defaults to MAX_PACKET_SIZE_BYTES — the same
# ceiling the websocket layer itself already enforces on any single incoming
# frame — rather than some smaller arbitrary number: a legitimate payload
# that was ever accepted onto the wire in the first place (image/video/file
# chunks, voice notes) must also be storable offline, or durable delivery
# would silently become worse than live delivery for the exact same message.
PENDING_MESSAGES_MAX_TOTAL_BYTES = int(os.environ.get("PENDING_MESSAGES_MAX_TOTAL_BYTES", str(512 * 1024 * 1024)))
PENDING_MESSAGES_MAX_TOTAL_ROWS  = int(os.environ.get("PENDING_MESSAGES_MAX_TOTAL_ROWS", "200000"))
PENDING_MESSAGE_MAX_BYTES        = int(os.environ.get("PENDING_MESSAGE_MAX_BYTES", str(MAX_PACKET_SIZE_BYTES)))
if PENDING_MESSAGES_MAX_TOTAL_BYTES <= 0 or PENDING_MESSAGES_MAX_TOTAL_ROWS <= 0 or PENDING_MESSAGE_MAX_BYTES <= 0:
    print("[FATAL] PENDING_MESSAGES_MAX_TOTAL_BYTES, PENDING_MESSAGES_MAX_TOTAL_ROWS и "
          "PENDING_MESSAGE_MAX_BYTES должны быть > 0 (обязательная защита процесса/диска от "
          "неограниченного роста, а не отключаемая опция) — отказ запуска.", flush=True)
    sys.exit(1)

# pending_messages.recipient/msg_id byte-cap gap (external review 2026-09-05,
# S6-42) — PENDING_MESSAGES_MAX_TOTAL_BYTES above only bounds
# pending_messages_meta.total_bytes, which is derived SOLELY from
# len(payload_json.encode("utf-8")) (see db_store()). But `recipient` and
# `msg_id` are each their own separately-stored SQLite TEXT column, and
# before this fix neither had any shape/length bound of its own — a caller
# reaching db_store() with a client-controlled `to` (almost every relay
# handler: message, session_init, edit, reaction, voice, group_*, missed_call,
# ...) could make `recipient` many MiB long (up to the ~6 MiB websocket frame
# ceiling) while keeping the actual JSON payload tiny, contributing ZERO
# bytes to the tracked total_bytes cap while still consuming real disk. Such
# rows also can never legitimately flush (db_flush() looks up by exact
# recipient, and no genuine fingerprint will ever equal attacker-chosen
# garbage), so they'd sit until MSG_TTL_SEC expiry. Fixed at the root: every
# legitimate recipient in this table IS an is_valid_fingerprint() shape —
# exactly 16 uppercase hex characters, always — so recipient is now
# rejected outright (INVALID_RECIPIENT) if it isn't that shape, both in
# db_store() (before global_offline_store_rate_ok()/json.dumps()/executor)
# and again in _db_store_sync() as defense-in-depth (before BEGIN IMMEDIATE),
# in case a future internal caller ever bypasses db_store(). Once recipient
# is pinned to exactly 16 ASCII bytes, the only other unaccounted column is
# msg_id — bounded here too (OFFLINE_MSG_ID_MAX_LEN) so it can't reopen the
# same class of gap. Every msg_id this server has ever seen from either
# client is `UUID.randomUUID().toString()` (grepped both Android's and
# Desktop's message-send paths) — exactly 36 characters — so 128 is a
# generous compatibility margin, not a guess, while still being a real
# bound rather than none at all.
OFFLINE_MSG_ID_MAX_LEN = 128


def is_valid_offline_msg_id(msg_id) -> bool:
    """Shape check for pending_messages.msg_id (S6-42) — msg_id=None is
    always valid: most db_store() callers legitimately never pass one at
    all (delivered/edit/reaction/voice/group_reaction/group_create/
    group_member_removed/group_key_rotation/group_invite_accepted/
    missed_call/message_delete/disappear_timer/group_message_delete — see
    every db_store() call site), while message/session_init/group_message
    do pass one (their `id`/`message_id` field). When present, only bounds
    shape/length, doesn't require any particular format — unlike
    is_valid_fingerprint()'s exact 16-hex-char shape, msg_id has no single
    canonical format across every caller (some are the client's `id` field,
    some `message_id`), so this stays a general bound, not an exact-match
    validator."""
    if msg_id is None:
        return True
    return isinstance(msg_id, str) and 1 <= len(msg_id) <= OFFLINE_MSG_ID_MAX_LEN

# Periodic TTL sweep for pending_messages — before this fix, expired rows
# were only ever deleted once, at server startup (_db_setup_sync()'s own
# DELETE above); a long-running process accumulated every message that
# outlived MSG_TTL_SEC but never triggered a restart. Bounded per-batch
# (PENDING_MESSAGES_CLEANUP_BATCH_SIZE), not one unbounded DELETE per sweep
# — see _pending_messages_watchdog_tick()'s own comment for why.
PENDING_MESSAGES_CLEANUP_INTERVAL_SEC = 300
PENDING_MESSAGES_CLEANUP_BATCH_SIZE   = 1000

# Reconnect flush batch size (S6-55, external review 2026-09-06) — bounds how
# many rows a single db_peek_pending() call materializes into RAM/the
# executor result at once, same reasoning as PENDING_MESSAGES_CLEANUP_BATCH_SIZE
# above: an account with a huge backlog (up to PENDING_MESSAGES_MAX_TOTAL_ROWS)
# must never make one reconnect SELECT the whole thing into a Python list in
# one shot. See db_peek_pending()/the reconnect flush loop for how this is
# used — one bounded PEEK, then per-row send+delete, repeated until a batch
# comes back short.
PENDING_MESSAGES_FLUSH_BATCH_SIZE = int(os.environ.get("PENDING_MESSAGES_FLUSH_BATCH_SIZE", "200"))
if PENDING_MESSAGES_FLUSH_BATCH_SIZE <= 0:
    print("[FATAL] PENDING_MESSAGES_FLUSH_BATCH_SIZE должен быть > 0 — отказ запуска.", flush=True)
    sys.exit(1)

# Cheap process-wide write-ATTEMPT budget, checked BEFORE the executor/
# SQLite hop, not merely before the durable INSERT itself (external review
# 2026-09-04) — mirrors global_prekey_publish_rate_ok()'s own reasoning (see
# its comment): once PENDING_MESSAGES_MAX_TOTAL_BYTES/ROWS above is actually
# exhausted, every further db_store() call would otherwise still pay a full
# BEGIN IMMEDIATE transaction just to be told FULL — this budget rejects
# those attempts for free, before they ever reach the executor thread.
# Deliberately NOT SQLite-backed, for the exact same reason
# global_prekey_publish_rate_ok() isn't: forcing a SQLite write merely to
# reject SQLite-write DoS would defeat much of the point. Process-local,
# same caveat as every other RAM-only limiter in this file — see that
# function's own comment for what a multi-process deployment would need
# instead.
#
# 0 (not negative) is "explicitly disabled", same convention as
# PREKEY_PUBLISH_GLOBAL_LIMIT — unlike the hard byte/row caps above, this is
# an abuse-mitigation knob a deployment might reasonably want to turn off.
OFFLINE_STORE_GLOBAL_LIMIT = int(os.environ.get("OFFLINE_STORE_GLOBAL_LIMIT", "300") or "300")
if OFFLINE_STORE_GLOBAL_LIMIT < 0:
    print("[FATAL] OFFLINE_STORE_GLOBAL_LIMIT должен быть >= 0 (0 явно отключает агрегатный "
          "write-attempt лимитер offline-очереди) — отказ запуска, чтобы не работать с "
          "неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
OFFLINE_STORE_GLOBAL_ENABLED    = OFFLINE_STORE_GLOBAL_LIMIT > 0
OFFLINE_STORE_GLOBAL_WINDOW_SEC = 60

# Process-local aggregate counter — explicitly NOT cross-process durable,
# same caveat as global_prekey_publish_rate (S6-28, see its own comment): a
# multi-process/replica deployment gets one independent budget PER PROCESS,
# not one shared budget across the deployment.
global_offline_store_rate = {"count": 0, "reset_time": time.time()}


def global_offline_store_rate_ok() -> bool:
    """Server-wide write-ATTEMPT budget for db_store() — the offline-queue
    counterpart to global_prekey_publish_rate_ok() (S6-28); see that
    function's own comment for the full reasoning this mirrors, including
    why no explicit lock is needed (no `await` in this function — a single
    asyncio event loop makes the check-then-increment atomic)."""
    if not OFFLINE_STORE_GLOBAL_ENABLED:
        return True
    now  = time.time()
    data = global_offline_store_rate
    if now - data["reset_time"] >= OFFLINE_STORE_GLOBAL_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= OFFLINE_STORE_GLOBAL_LIMIT:
        return False
    data["count"] += 1
    return True

# Опционально — шифрование БД at-rest через SQLCipher (защита от кражи файла/бэкапа,
# НЕ от root-доступа к живому процессу, который всё равно держит ключ в памяти).
# Сгенерировать ключ: python3 -c "import secrets; print(secrets.token_hex(32))"
DB_ENCRYPTION_KEY_HEX = os.environ.get("DB_ENCRYPTION_KEY_HEX", "").strip()
if DB_ENCRYPTION_KEY_HEX:
    if not HAS_SQLCIPHER:
        print("[FATAL] DB_ENCRYPTION_KEY_HEX задан, но пакет sqlcipher3-binary не установлен "
              "(pip install sqlcipher3-binary) — отказ запуска, чтобы не молча работать "
              "с незашифрованной БД.", flush=True)
        sys.exit(1)
    try:
        bytes.fromhex(DB_ENCRYPTION_KEY_HEX)
    except ValueError:
        print("[FATAL] DB_ENCRYPTION_KEY_HEX должен быть hex-строкой (см. команду генерации выше).",
              flush=True)
        sys.exit(1)


# ─── SQLite connection reuse + WAL (PERF-01, 2026-11-02) ────────────────────
#
# Measured on this project's own benchmark (Server/stress/bench_sqlite_config.py
# and bench_throughput.py), not assumed:
#
#   * db_connect() used to open a BRAND-NEW sqlite3 connection on every call,
#     at all 39 `with db_connect() as conn:` sites, and set no PRAGMAs at all —
#     so every durable write ran under SQLite's defaults, `journal_mode=delete`
#     + `synchronous=FULL`: create a rollback-journal file, write, fsync,
#     commit, fsync, delete the journal. Two fsyncs plus two filesystem
#     metadata operations per transaction, on top of a fresh file open.
#   * Isolated measurement of just that configuration: 460 write-tx/s and
#     7 352 indexed reads/s. With WAL + the SAME `synchronous=FULL` + a reused
#     connection: 2 041 write-tx/s (x4.4) and 190 898 reads/s (x26).
#   * On the live protocol that mattered: an `anon_message` round trip performs
#     TWO durable transactions (db_mark_anon_token_inflight on send,
#     db_terminalize_anon_token on ack), and benchmarked at 158.8 msg/s —
#     almost exactly the 460/2 the configuration above allows. The same server
#     on the same machine relays 9 006 msg/s on the `message` path, which
#     performs no durable write at all. The hot path was disk-bound by
#     configuration, not CPU-bound by Python.
#
# Two deliberate non-choices, both of which would have produced bigger
# headline numbers and worse software:
#
#   1. `synchronous=NORMAL` benchmarks at 44 895 write-tx/s here (x97), and is
#      NOT taken. In WAL mode NORMAL is durable against a process crash but
#      NOT against OS crash / power loss: the last committed transactions can
#      be lost (the database stays uncorrupted). `anon_token_state` is exactly
#      where that is unacceptable — losing a committed SPENT row silently
#      returns a spent token to ACTIVE and reopens the replay window that
#      SECURITY_INVARIANTS.md invariants 24/27/28 exist to close. Invariant 28's
#      startup sweep only force-closes IN_FLIGHT; it cannot recover a SPENT
#      write that never reached the platter. `FULL` is therefore load-bearing
#      for a security property, not a conservative default, and must stay.
#   2. WAL *without* connection reuse is a REGRESSION, not a smaller win:
#      380 write-tx/s and 1 629 reads/s, i.e. slower than the original on both
#      counts, because each connection has to map the -wal/-shm files afresh.
#      The two halves of this change only work together — do not split them.
#
# Connections are thread-local rather than one global shared object: every
# durable call reaches this through `loop.run_in_executor(None, ...)`, i.e. an
# arbitrary ThreadPoolExecutor worker, and sqlite3 connections are not safe to
# share across threads by default. Thread-local gives one connection per
# executor worker (a naturally bounded pool, min(32, cpu+4)+1) with no locking
# of our own and no `check_same_thread=False` footgun. WAL is what makes that
# pool useful: readers no longer block the writer.
#
# NOTE: WAL requires the database file to live on a local filesystem — it uses
# a shared-memory (`-shm`) file and will not work correctly on NFS/SMB. The
# reference deployment is a VPS local disk, which is fine; a deployment that
# moves DB_PATH onto a network mount must revisit this.
_db_conn_local = threading.local()

# Set in this order: for the SQLCipher branch `PRAGMA key` has to come first,
# before any statement that touches the database pages, journal_mode included.
_DB_RUNTIME_PRAGMAS = (
    "journal_mode=WAL",
    "synchronous=FULL",   # see note 1 above — a security invariant, not a default
    "busy_timeout=5000",  # matches sqlite3.connect()'s own default timeout=5.0, made explicit
)

_db_nested_warned = False


def _db_configure(conn):
    for pragma in _DB_RUNTIME_PRAGMAS:
        conn.execute(f"PRAGMA {pragma}")
    return conn


def _db_open_new():
    if DB_ENCRYPTION_KEY_HEX:
        conn = sqlcipher.connect(DB_PATH)
        conn.execute(f"PRAGMA key = \"x'{DB_ENCRYPTION_KEY_HEX}'\"")
        return _db_configure(conn)
    return _db_configure(sqlite3.connect(DB_PATH))


def db_connect():
    """Единая точка подключения к БД. Если задан DB_ENCRYPTION_KEY_HEX — прозрачно
    открывает файл через SQLCipher, иначе обычный sqlite3 (обратная совместимость).

    Возвращает переиспользуемое соединение, своё на каждый поток (см. большой
    комментарий выше: PERF-01). Закрывать его вызывающему не нужно — все 39
    мест в server.py используют `with db_connect() as conn:`, а это контекстный
    менеджер ТРАНЗАКЦИИ (commit/rollback), а не закрытия. Но если вызывающий
    всё же закроет соединение (так делает, например,
    tests/test_security_invariants.py::test_anon_token_state_current_schema_db_untouched),
    следующий вызов это обнаружит и прозрачно откроет новое — кеш никогда не
    отдаёт мёртвый объект."""
    global _db_nested_warned
    cached = getattr(_db_conn_local, "conn", None)
    cached_path = getattr(_db_conn_local, "path", None)

    if cached is not None and cached_path == DB_PATH:
        # `in_transaction` doubles as the liveness probe here: on a live
        # connection it is a free attribute read, and on one the caller already
        # closed it raises ProgrammingError("Cannot operate on a closed
        # database") — which is exactly the signal needed to discard the cache
        # entry and reopen. Found by the existing test suite on the first run
        # after this change: a cached-but-closed connection was handed straight
        # back. Any other exception type is treated the same way, deliberately:
        # an unusable cached connection must never be returned, whatever the
        # reason it became unusable.
        #
        # A True result means an open transaction — either a leaked `BEGIN`
        # from a path that died outside a `with` block, or genuine nesting
        # (db_connect() called while an outer `with db_connect()` block is
        # still open on this same thread). Handing back a connection carrying
        # someone else's open transaction would be silently wrong in both
        # cases, and rolling it back would destroy the outer caller's work in
        # the nesting case. So fall back to this function's historical
        # behaviour instead — a fresh, independent connection, correct for
        # both — and say so once.
        #
        # Default True rather than False if the attribute is missing entirely:
        # the SQLCipher branch returns a sqlcipher3.dbapi2 connection, a
        # separate pysqlite fork that this project's default test run never
        # exercises (DB_ENCRYPTION_KEY_HEX is unset there). Missing attribute
        # then degrades to "always open a fresh connection" — i.e. exactly the
        # pre-PERF-01 behaviour, correct but slow — instead of silently
        # reusing a connection whose transaction state we cannot see.
        try:
            busy = getattr(cached, "in_transaction", True)
            alive = True
        except Exception:
            busy, alive = True, False

        if alive and not busy:
            return cached

        if alive:
            if not _db_nested_warned:
                _db_nested_warned = True
                print("[DB] db_connect(): соединение потока занято открытой транзакцией — "
                      "выдаю отдельное соединение (см. PERF-01). Если это повторяется, "
                      "значит есть вложенный `with db_connect()`.", flush=True)
            return _db_open_new()
        # Not alive: fall through to the reopen path below.

    # First call on this thread, or DB_PATH changed under us (tests that point
    # the module at a different database), or the cached connection is dead.
    # Drop the stale one explicitly rather than leaving it to refcount dealloc.
    if cached is not None:
        try:
            cached.close()
        except Exception:
            pass
        _db_conn_local.conn = None
        _db_conn_local.path = None

    conn = _db_open_new()
    _db_conn_local.conn = conn
    _db_conn_local.path = DB_PATH
    return conn


def _migrate_anon_token_state_check_constraint(conn):
    """One-time transactional migration for a pre-IN_FLIGHT anon_token_state
    table (S6-63, external review 2026-09-09) — `CREATE TABLE IF NOT EXISTS`
    just below does NOT retroactively widen an existing table's CHECK
    constraint (see that statement's own comment), so a database created
    before IN_FLIGHT was added would keep rejecting every ACTIVE→IN_FLIGHT
    write (db_mark_anon_token_inflight()) forever after an upgrade, even
    though a fresh database works fine — an upgrade/reliability gap, not
    something CREATE TABLE IF NOT EXISTS was ever going to self-heal.

    Detected from sqlite_master.sql, not PRAGMA table_info() — a CHECK
    constraint is not a column and doesn't appear there at all. A no-op if
    the table doesn't exist yet (the CREATE TABLE below makes the current
    schema directly) or already has the current 4-state CHECK — restart-safe
    and idempotent. Uses only plain conn.execute() DB-API calls (no
    sqlite3-specific helpers), so this works identically under SQLCipher
    (db_connect()'s sqlcipher3 branch) and plain sqlite3.

    Runs inside the SAME implicit transaction _db_setup_sync()'s own
    `with db_connect() as conn:` already wraps its entire body in (proven
    elsewhere in this function for other CREATE/ALTER TABLE statements) — a
    validation failure below raises, propagating out of _db_setup_sync()
    uncaught, so the whole setup transaction rolls back (the old table is
    never dropped before validation passes, and even a completed DROP+RENAME
    would be undone by the rollback) and startup crashes loudly rather than
    ever serving traffic against partially migrated token state.

    Preserves every existing row and column verbatim — ownership, state
    (ACTIVE/SPENT/REVOKED as originally written), created_at/updated_at, and
    bootstrap_reserved/bootstrap_reserved_by if already present (a table that
    picked up those columns via the ALTER TABLE blocks below on some earlier
    startup, while still carrying the legacy CHECK, is exactly the realistic
    case here — ALTER TABLE ADD COLUMN never cared about CHECK constraints).
    Missing bootstrap columns default to their normal fresh-row values (0 /
    NULL), then get added by the existing ALTER TABLE logic below as usual."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'anon_token_state'"
    ).fetchone()
    if row is None or row[0] is None or "IN_FLIGHT" in row[0]:
        return  # doesn't exist yet, or already current -- nothing to do

    print("[DB] anon_token_state: обнаружена устаревшая CHECK-схема (без IN_FLIGHT) — "
          "выполняется миграция таблицы...")

    old_cols = {r[1] for r in conn.execute("PRAGMA table_info(anon_token_state)").fetchall()}
    required = {"token_hash", "owner", "state", "created_at", "updated_at"}
    if not required.issubset(old_cols):
        raise RuntimeError(
            f"anon_token_state migration: legacy table is missing required column(s) "
            f"{required - old_cols} — refusing to guess, refusing to start. "
            f"Inspect the database manually before retrying."
        )

    old_row_count = conn.execute("SELECT COUNT(*) FROM anon_token_state").fetchone()[0]
    bad_states = conn.execute(
        "SELECT COUNT(*) FROM anon_token_state "
        "WHERE state NOT IN ('ACTIVE', 'IN_FLIGHT', 'SPENT', 'REVOKED')"
    ).fetchone()[0]
    if bad_states:
        raise RuntimeError(
            f"anon_token_state migration: {bad_states} row(s) have a state outside "
            f"ACTIVE/IN_FLIGHT/SPENT/REVOKED — refusing to silently drop or reset them, "
            f"refusing to start. Inspect the database manually before retrying."
        )

    has_bootstrap_reserved    = "bootstrap_reserved" in old_cols
    has_bootstrap_reserved_by = "bootstrap_reserved_by" in old_cols

    conn.execute("DROP TABLE IF EXISTS anon_token_state_s663_migration")
    conn.execute("""
        CREATE TABLE anon_token_state_s663_migration (
            token_hash             BLOB PRIMARY KEY,
            owner                  TEXT NOT NULL,
            state                  TEXT NOT NULL CHECK(state IN ('ACTIVE', 'IN_FLIGHT', 'SPENT', 'REVOKED')),
            created_at             REAL NOT NULL,
            updated_at             REAL NOT NULL,
            bootstrap_reserved     INTEGER NOT NULL DEFAULT 0,
            bootstrap_reserved_by  TEXT
        )
    """)
    conn.execute(f"""
        INSERT INTO anon_token_state_s663_migration
            (token_hash, owner, state, created_at, updated_at, bootstrap_reserved, bootstrap_reserved_by)
        SELECT
            token_hash, owner, state, created_at, updated_at,
            {"bootstrap_reserved" if has_bootstrap_reserved else "0"},
            {"bootstrap_reserved_by" if has_bootstrap_reserved_by else "NULL"}
        FROM anon_token_state
    """)

    new_row_count = conn.execute(
        "SELECT COUNT(*) FROM anon_token_state_s663_migration"
    ).fetchone()[0]
    if new_row_count != old_row_count:
        raise RuntimeError(
            f"anon_token_state migration: row count mismatch after copy "
            f"({old_row_count} -> {new_row_count}) — refusing to proceed, refusing to start."
        )

    conn.execute("DROP TABLE anon_token_state")
    conn.execute("ALTER TABLE anon_token_state_s663_migration RENAME TO anon_token_state")
    # Indexes are dropped along with the old table and recreated by the
    # existing CREATE INDEX/UNIQUE INDEX IF NOT EXISTS statements just below
    # in _db_setup_sync() — not duplicated here.
    print(f"[DB] anon_token_state: миграция завершена, перенесено строк: {new_row_count}")


def _db_setup_sync():
    with db_connect() as conn:
        _migrate_anon_token_state_check_constraint(conn)
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

        # payload_bytes migration (external review 2026-09-04, S6-31) — added
        # so the durable capacity bound below (PENDING_MESSAGES_MAX_TOTAL_BYTES)
        # can be enforced from a cheap running total (pending_messages_meta)
        # instead of re-summing every row's payload on every single write.
        # PRAGMA table_info(), not the try/ALTER/except sqlite3.OperationalError
        # probe used elsewhere in this function (e.g. authorized_devices'
        # device_pubkey column) — under SQLCipher (DB_ENCRYPTION_KEY_HEX),
        # ALTER TABLE ADD COLUMN on an already-migrated table doesn't
        # reliably surface as that same exception type through the
        # sqlcipher3 driver, so probing the column directly is what actually
        # works correctly in both DB_ENCRYPTION_KEY_HEX modes.
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(pending_messages)").fetchall()}
        if "payload_bytes" not in existing_cols:
            conn.execute("ALTER TABLE pending_messages ADD COLUMN payload_bytes INTEGER NOT NULL DEFAULT 0")
            # Backfill from what's actually on disk — length(CAST(x AS BLOB))
            # is SQLite's BYTE count (length() alone counts UTF-8 CHARACTERS
            # for a TEXT value, not bytes), matching exactly what
            # len(payload_json.encode("utf-8")) computes for every row
            # written from this point on — see db_store()'s own comment.
            conn.execute("UPDATE pending_messages SET payload_bytes = length(CAST(payload AS BLOB))")

        # Singleton running-totals row (external review 2026-09-04, S6-31) —
        # pending_messages itself remains the source of truth; this table is
        # cheap transactional bookkeeping so _db_store_sync()'s capacity
        # check doesn't need a COUNT(*)/SUM(payload_bytes) over the whole
        # table on every single write. Every mutation of pending_messages
        # (insert, flush-delete, TTL-cleanup-delete) updates this row in the
        # SAME transaction as the row it's mutating — see _db_store_sync()/
        # _db_flush_sync()/_pending_messages_cleanup_batch_sync()'s own
        # comments.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_messages_meta (
                id          INTEGER PRIMARY KEY CHECK(id = 1),
                total_rows  INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL
            )
        """)

        conn.execute("DELETE FROM pending_messages WHERE created_at < ?",
                     (time.time() - MSG_TTL_SEC,))

        # Reconcile the singleton from the real table, ONCE, at startup —
        # after both the TTL sweep and the payload_bytes backfill above, so
        # it reflects exactly what's left on disk right now. This is what
        # repairs the running totals after a crash mid-write, a manual DB
        # edit, or simply the first run ever seeing this table (row doesn't
        # exist yet — INSERT OR REPLACE below creates it starting from the
        # real count).
        total_rows, total_bytes = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM pending_messages"
        ).fetchone()
        conn.execute(
            "INSERT OR REPLACE INTO pending_messages_meta (id, total_rows, total_bytes) VALUES (1, ?, ?)",
            (total_rows, total_bytes)
        )

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

        # channel_posts.storage_bytes / channel_posts_meta (external review
        # 2026-09-05, S6-47) — see CHANNEL_POST_MAX_BYTES's own comment for
        # the unbounded-growth problem this closes: channel_posts was
        # persisted forever with no byte accounting at all, and the RAM-only
        # 200-post cap in the channel_post handler never touched SQLite.
        # PRAGMA table_info() probe, not try/ALTER/except
        # sqlite3.OperationalError (see authorized_devices.device_pubkey's
        # own comment above for why the except-based probe misbehaves under
        # SQLCipher).
        existing_ch_post_cols = {row[1] for row in conn.execute("PRAGMA table_info(channel_posts)").fetchall()}
        if "storage_bytes" not in existing_ch_post_cols:
            conn.execute("ALTER TABLE channel_posts ADD COLUMN storage_bytes INTEGER NOT NULL DEFAULT 0")
            # Backfill from what's actually on disk — length(CAST(x AS BLOB))
            # is SQLite's BYTE count (length() alone counts UTF-8 CHARACTERS
            # for a TEXT value, not bytes), matching exactly what
            # db_store_channel_post() computes for every row written from
            # this point on.
            conn.execute("""
                UPDATE channel_posts SET storage_bytes =
                    length(CAST(channel_id AS BLOB)) + length(CAST(post_id AS BLOB)) +
                    length(CAST(text AS BLOB)) + length(CAST(author_id AS BLOB)) +
                    length(CAST(author_name AS BLOB)) + length(CAST(image_data AS BLOB))
            """)

        # Singleton running-totals row (S6-47), same pairing principle as
        # pending_messages_meta (S6-31, see its own comment) — channel_posts
        # itself remains the source of truth; this table is cheap
        # transactional bookkeeping so _db_store_channel_post_sync()'s
        # capacity check doesn't need a COUNT(*)/SUM(storage_bytes) over the
        # whole table on every single write.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS channel_posts_meta (
                id          INTEGER PRIMARY KEY CHECK(id = 1),
                total_rows  INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL
            )
        """)

        # Retroactive per-channel retention prune (S6-47) — see
        # CHANNEL_POSTS_MAX_PER_CHANNEL's own comment for why rows beyond the
        # most recent 200 per channel are already unobservable through any
        # current client. Existing DBs from before this fix may have
        # accumulated far more than that per channel; this brings them in
        # line with the new invariant ONCE at startup, before the meta
        # reconciliation below so the running totals reflect exactly what's
        # actually being kept.
        conn.execute("""
            DELETE FROM channel_posts WHERE id IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY channel_id ORDER BY id DESC
                    ) AS rn
                    FROM channel_posts
                ) WHERE rn > ?
            )
        """, (CHANNEL_POSTS_MAX_PER_CHANNEL,))

        # Reconcile the singleton from the real table, ONCE, at startup —
        # after the storage_bytes backfill and the retention prune above, so
        # it reflects exactly what's left on disk right now. Repairs the
        # running totals after a crash mid-write, a manual DB edit, or simply
        # the first run ever seeing this table.
        total_ch_rows, total_ch_bytes = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(storage_bytes), 0) FROM channel_posts"
        ).fetchone()
        conn.execute(
            "INSERT OR REPLACE INTO channel_posts_meta (id, total_rows, total_bytes) VALUES (1, ?, ?)",
            (total_ch_rows, total_ch_bytes)
        )

        # User avatars
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_avatars (
                username   TEXT PRIMARY KEY,
                avatar_b64 TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        # avatar_bytes migration (S6-50) — same PRAGMA table_info() probe
        # pattern as pending_messages' payload_bytes column (see that
        # migration's own comment for why this style, not try/ALTER/except,
        # is what actually works reliably under SQLCipher too). Backfilled
        # from what's actually on disk — length(CAST(x AS BLOB)) is
        # SQLite's BYTE count (length() alone counts UTF-8 CHARACTERS for a
        # TEXT value, not bytes), matching exactly what
        # len(avatar_b64.encode("utf-8")) computes for every row written
        # from this point on — see apply_avatar_mutation()'s own comment.
        existing_avatar_cols = {row[1] for row in conn.execute("PRAGMA table_info(user_avatars)").fetchall()}
        if "avatar_bytes" not in existing_avatar_cols:
            conn.execute("ALTER TABLE user_avatars ADD COLUMN avatar_bytes INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE user_avatars SET avatar_bytes = length(CAST(avatar_b64 AS BLOB))")

        # Singleton running-totals row (S6-50) — same pending_messages_meta/
        # channel_posts_meta pattern: user_avatars itself remains the source
        # of truth, this table is cheap transactional bookkeeping so
        # _db_upsert_avatar_sync()'s capacity check doesn't need a
        # COUNT(*)/SUM(avatar_bytes) over the whole table on every write.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_avatars_meta (
                id          INTEGER PRIMARY KEY CHECK(id = 1),
                total_rows  INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL
            )
        """)
        # Reconcile the singleton from the real table, ONCE, at startup —
        # after the avatar_bytes backfill above, so it reflects exactly
        # what's left on disk right now. This is what repairs the running
        # totals after a crash mid-write, a manual DB edit, or simply the
        # first run ever seeing this table.
        total_avatar_rows, total_avatar_bytes = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(avatar_bytes), 0) FROM user_avatars"
        ).fetchone()
        conn.execute(
            "INSERT OR REPLACE INTO user_avatars_meta (id, total_rows, total_bytes) VALUES (1, ?, ?)",
            (total_avatar_rows, total_avatar_bytes)
        )

        # Device-gated registration TOTP — one secret per account, see comment
        # near user_totp_secrets above.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_totp (
                username     TEXT PRIMARY KEY,
                secret       TEXT NOT NULL,
                created_at   REAL NOT NULL,
                last_counter INTEGER NOT NULL DEFAULT -1
            )
        """)
        # last_counter added 2026-09-03 (external review) — replay-protects
        # a TOTP code by remembering the highest time-step counter already
        # accepted, same purpose as the RAM-only user_totp_last_counter dict
        # this replaces as source of truth (see totp_verify_and_consume()'s
        # own comment). CREATE TABLE IF NOT EXISTS won't add this column to
        # an already-created table, hence the explicit ALTER TABLE.
        # PRAGMA table_info() probe, not try/ALTER/except sqlite3.OperationalError
        # (external review 2026-09-05) — see authorized_devices.device_pubkey's
        # comment below for why the except-based probe crashes under SQLCipher.
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(user_totp)").fetchall()}
        if "last_counter" not in existing_cols:
            conn.execute(
                "ALTER TABLE user_totp ADD COLUMN last_counter INTEGER NOT NULL DEFAULT -1"
            )
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
        # Durable per-fingerprint second-factor rate limit (external review
        # 2026-09-04) — a 6-digit TOTP code is a 10^6 online-guessable
        # secret unless *something* durably caps attempts. Before this,
        # `register()`'s TOTP/recovery check, `totp_setup` re-enrollment
        # proof, and `totp_disable` had no dedicated limit at all — the
        # general rate_limit_check() doesn't cover any of these message
        # types, and even where it does elsewhere it's RAM-only (reset by a
        # restart, not shared across workers). totp_verify_and_consume()'s
        # own anti-replay only rejects an already-USED counter — a wrong
        # code costs the attacker nothing and consumes nothing. See
        # db_take_second_factor_attempt()'s own comment for the gating
        # mechanics this table backs.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS second_factor_guard (
                username       TEXT PRIMARY KEY,
                window_started REAL NOT NULL,
                attempts       INTEGER NOT NULL,
                locked_until   REAL NOT NULL DEFAULT 0
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
        # Durable per-fingerprint device allowlist (external review
        # 2026-09-03) — bug found live: the TOTP device-gate in register()
        # used to decide "is this a new device" purely from the currently
        # in-memory `clients[username]` entry (RAM, wiped on disconnect AND
        # on every server restart). Once that entry was gone — e.g. the
        # legitimate owner simply closed their app, or the server restarted
        # — `existing` was None, is_new_device came out False, and TOTP was
        # never even asked for. An attacker holding a stolen identity
        # private key could pass the challenge/response handshake (proves
        # key possession, nothing about TOTP) and register() straight in
        # with any device_id, defeating the entire point of TOTP as a
        # second factor against a stolen key — it was really only ever
        # protecting against a second device connecting WHILE the real
        # owner's session was still live, not against the stolen-key
        # scenario TOTP is supposed to be the second factor FOR. This table
        # makes "this device_id has been authorized for this fingerprint"
        # durable and independent of any live session — see
        # db_get_authorized_device()/db_bind_device_pubkey()/db_authorize_device()
        # and register()'s own comment on the ordering rule (never persist a
        # device's authorization before its TOTP/recovery code has actually
        # been verified — same insert-only-after-every-gate-passes
        # principle as db_admit_new_fingerprint()).
        #
        # device_pubkey added 2026-09-03 (round 2, external review) — bug
        # found live: device_id alone is just a client-supplied string, not
        # proof of anything. An attacker with a stolen identity private key
        # who also learned (or guessed) a legitimate device_id — nothing
        # about it is secret, it's sent in the clear in every register() —
        # could send that same string and have the durable check answer
        # "already authorized", skipping TOTP entirely. This turns the
        # allowlist from a bearer-token check into real device
        # authentication: a separate device keypair, generated on-device
        # and deliberately excluded from the identity backup, signs
        # SUBROSA_DEVICE_V1 || challenge || username || device_id on every
        # single register() (not just first enrollment) — see register()'s
        # own comment for the full verify-then-gate-then-bind flow. NULL
        # here means "device_id row exists but no pubkey pinned yet" — the
        # state a row is created in when TOTP wasn't configured yet (see
        # db_authorize_device(), still used for that path) or immediately
        # after this column's own migration for any pre-existing row; the
        # first register() for such a row while TOTP IS configured must
        # still pass TOTP once to pin a pubkey (db_bind_device_pubkey()),
        # exactly like a genuinely brand-new device_id would. Once pinned,
        # a device_pubkey is never replaced — see db_bind_device_pubkey()'s
        # own comment for why overwriting it would reopen exactly this bug.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS authorized_devices (
                username      TEXT NOT NULL,
                device_id     TEXT NOT NULL,
                device_pubkey BLOB,
                added_at      REAL NOT NULL,
                PRIMARY KEY (username, device_id)
            )
        """)
        # PRAGMA table_info() probe, not try/ALTER/except sqlite3.OperationalError
        # (external review 2026-09-05) — under SQLCipher, the driver raises
        # sqlcipher3.dbapi2.OperationalError for "duplicate column name", which
        # is NOT an instance of sqlite3.OperationalError, so that except clause
        # never caught it there and crashed the server on every restart once
        # this column already existed. Same fix already applied to
        # pending_messages.payload_bytes above — see its comment.
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(authorized_devices)").fetchall()}
        if "device_pubkey" not in existing_cols:
            conn.execute("ALTER TABLE authorized_devices ADD COLUMN device_pubkey BLOB")
        # One-time-in-effect legacy cleanup (external review 2026-09-04,
        # S6-37) — a NULL device_pubkey row confers no trust by itself (see
        # is_valid_device_id()'s/db_get_authorized_device()'s own comments:
        # `device_needs_totp` treats "no row" and "row exists, pubkey NULL"
        # identically, both still requiring TOTP/recovery-proof plus a
        # valid device signature before db_bind_device_pubkey() ever pins
        # anything), so deleting every such row is security-semantics-
        # neutral. Reclaims whatever the now-removed TOTP-disabled
        # `db_authorize_device()` admission path durably left behind over
        # this server's history. Safe to run unconditionally on every
        # startup, not just once: `_db_bind_device_pubkey_sync()` never
        # creates a NEW NULL-pubkey row itself (a fresh INSERT always
        # carries a real pubkey; only an UPDATE ever touches an existing
        # NULL row, replacing it with a real one) — nor does anything else
        # in this file anymore — so this becomes a costless no-op DELETE
        # once the initial backlog is gone. Never touches a row with a
        # pinned (non-NULL) pubkey.
        conn.execute("DELETE FROM authorized_devices WHERE device_pubkey IS NULL")
        # Persisted source of truth for anon token ownership/state — found
        # live 2026-09-03 (external review): token_owner/spent_tokens were
        # RAM-only, so a server restart reset every token's ownership at
        # once, reopening the exact hijack window they exist to close (see
        # token_owner's own comment above). The token itself is never
        # stored, only its SHA-256 hash (_hash_anon_token) — same reasoning
        # as totp_recovery_codes: these are server-generated high-entropy
        # values, not user secrets that need a slow KDF, and a hash is
        # enough to recognize a token presented later without being able to
        # reconstruct it from a DB compromise alone. RAM dicts
        # (token_owner/spent_tokens/anon_token_state_cache) remain as a fast
        # cache in front of this — see db_claim_anon_tokens()/
        # db_terminalize_anon_token()/db_mark_anon_token_inflight() and
        # anon_token_state_cache's own comment near token_owner.
        # anon_token_state_cache IS loaded in full at startup (unlike this
        # table's rows, which subscribe_tokens/anon_message only ever query
        # one hash at a time) — see start_server().
        #
        # IN_FLIGHT added 2026-09-03 (external review): a token accepted by
        # anon_message but not yet anon_delivery_ack'd used to have no
        # durable state of its own at all — only the RAM-only token_pending
        # dict marked it as "claimed, awaiting delivery", which a server
        # restart wiped clean while SQLite still said ACTIVE, letting the
        # exact same token be spent again. db_mark_anon_token_inflight()'s
        # atomic ACTIVE→IN_FLIGHT transition (mirroring
        # db_claim_anon_tokens()'s BEGIN IMMEDIATE pattern) closes that
        # window — see anon_message's own comment for the full flow. NOTE:
        # CREATE TABLE IF NOT EXISTS does not retroactively widen an
        # existing table's CHECK constraint — an already-created table from
        # before this change needs either a DROP TABLE anon_token_state (if
        # nothing in it is worth keeping, e.g. a test deployment) or a real
        # migration (ALTER TABLE can't touch CHECK in SQLite either; the
        # usual approach is create-new/copy/rename) before IN_FLIGHT rows
        # can actually be written.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anon_token_state (
                token_hash  BLOB PRIMARY KEY,
                owner       TEXT NOT NULL,
                state       TEXT NOT NULL CHECK(state IN ('ACTIVE', 'IN_FLIGHT', 'SPENT', 'REVOKED')),
                created_at  REAL NOT NULL,
                updated_at  REAL NOT NULL
            )
        """)
        # bootstrap_reserved added 2026-09-03 (external review): a token
        # handed out by pick_bootstrap_token() used to be tracked only in
        # the RAM-only bootstrap_reserved set (see its own comment, now
        # removed) — disconnect and restart both silently forgot the
        # reservation, and the exact same token could then be handed to a
        # second requester while the first one might still use it. This
        # column makes "handed out as a bootstrap address" durable
        # alongside the token's own ACTIVE/IN_FLIGHT/SPENT/REVOKED state —
        # see db_resolve_bootstrap_token() (the current resolution/
        # reservation logic — this column's own original reserve function
        # has since been folded into it, see its comment for the full
        # history) and _db_terminalize_anon_token_sync(), which clears this flag in
        # the same UPDATE that closes the token out, since a bootstrap
        # reservation on a token that's already SPENT/REVOKED means
        # nothing. CREATE TABLE IF NOT EXISTS won't add this column to an
        # already-created table, hence the explicit ALTER TABLE below.
        # PRAGMA table_info() probe, not try/ALTER/except sqlite3.OperationalError
        # (external review 2026-09-05) — see authorized_devices.device_pubkey's
        # comment above for why the except-based probe crashes under SQLCipher.
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(anon_token_state)").fetchall()}
        if "bootstrap_reserved" not in existing_cols:
            conn.execute(
                "ALTER TABLE anon_token_state "
                "ADD COLUMN bootstrap_reserved INTEGER NOT NULL DEFAULT 0"
            )
        # bootstrap_reserved_by added 2026-09-03 (external review, round 5):
        # bootstrap_reserved alone made a reservation durable, but not tied
        # to WHO requested it — every successful get_prekey_bundle(target)/
        # get_prekey_bundles_batch call minted a brand-new reservation on a
        # DIFFERENT one of target's tokens regardless of whether the SAME
        # authenticated requester had already been handed one moments ago.
        # A single account repeatedly fetching the same target's bundle
        # (get_prekey_bundle is 10/min under prekey_fetch, batch multiplies
        # this across every target in one call) could reserve target's
        # entire ~100-token pool in minutes without ever sending a single
        # anon_message — a remote DoS against that target's ability to
        # receive a fresh X3DH bootstrap from anyone else, no capability
        # ever actually used. This column records WHO a reservation is
        # for, so pick_bootstrap_token() can recognize "this exact
        # requester already has an outstanding reservation against this
        # target" and hand back the SAME token instead of minting a new
        # one — see its own comment for the full state machine
        # (ACTIVE-reservation → same token, IN_FLIGHT-reservation → None,
        # no reservation → atomically claim one fresh token). Cleared back
        # to NULL in the same UPDATE as bootstrap_reserved = 0 — see
        # _db_terminalize_anon_token_sync().
        # Re-probed rather than reusing existing_cols above — that set was
        # captured before the bootstrap_reserved ALTER just above and would be
        # stale for this second column check on the same table.
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(anon_token_state)").fetchall()}
        if "bootstrap_reserved_by" not in existing_cols:
            conn.execute(
                "ALTER TABLE anon_token_state "
                "ADD COLUMN bootstrap_reserved_by TEXT"
            )
        # Enforces the invariant db_resolve_bootstrap_token_sync()'s own
        # logic relies on but can't fully guarantee purely through
        # application-level BEGIN IMMEDIATE transactions alone (defense in
        # depth against a future code path adding a second reservation for
        # the same (target, requester) pair by mistake): at most ONE row can
        # have bootstrap_reserved_by = <requester> for a given owner =
        # <target> while that row is still ACTIVE/IN_FLIGHT and actually
        # reserved. Partial index (the WHERE clause) — a token that's SPENT/
        # REVOKED or never was reserved doesn't need to participate in this
        # uniqueness constraint at all.
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_anon_bootstrap_requester_target
            ON anon_token_state(owner, bootstrap_reserved_by)
            WHERE bootstrap_reserved = 1
              AND bootstrap_reserved_by IS NOT NULL
              AND state IN ('ACTIVE', 'IN_FLIGHT')
        """)
        # Index for _db_claim_anon_tokens_sync()'s per-owner active-count
        # query (external review 2026-09-05, S6-44) — without it, every
        # subscribe_tokens claim attempt would force a full table scan to
        # count one owner's ACTIVE/IN_FLIGHT rows, exactly the kind of
        # per-request cost this whole patch exists to bound.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_anon_token_owner_state ON anon_token_state(owner, state)")
        # Durable per-owner NEW-token issuance quota window (external review
        # 2026-09-05, S6-44) — see MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT's own
        # comment for why the active-row cap alone isn't enough (a
        # claim→unsubscribe(REVOKED)→reclaim cycle frees active capacity but
        # still mints a fresh permanent tombstone every time). One row per
        # account that has ever created at least one new token; read/written
        # only inside _db_claim_anon_tokens_sync()'s own BEGIN IMMEDIATE, so
        # the quota check and the INSERTs it gates can never race each other.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anon_token_claim_guard (
                username       TEXT PRIMARY KEY,
                window_started REAL NOT NULL,
                new_claims     INTEGER NOT NULL
            )
        """)
        # Fail-closed startup sweep (external review 2026-09-03): token_pending
        # is RAM-only (see IN_FLIGHT's own comment above — the sealed payload
        # is deliberately never persisted, a retention/privacy trade-off, not
        # revisited here), so it's always empty right after a restart. Any
        # row still IN_FLIGHT at this point can only mean the process died
        # between db_mark_anon_token_inflight() succeeding and the matching
        # delivery ever being acked — the payload is gone for good either
        # way, no future anon_delivery_ack for it is EVER coming. Left as
        # IN_FLIGHT, this would zombie the token forever: the server refuses
        # to accept a new anon_message on it (correctly — the whole point of
        # IN_FLIGHT), but the client that originally claimed it has no way
        # to learn that and would keep treating it as still spendable
        # indefinitely. Force-closing it to SPENT here — before
        # anon_token_state_cache is loaded a few lines down in
        # start_server() — means the existing subscribe_tokens_result:
        # "spent" path (see the subscribe_tokens handler) naturally tells
        # the owner's client to give up on it for good, the next time it
        # resubscribes. Security priority over delivery guarantee, by
        # design: losing one in-flight message across a restart is an
        # accepted reliability cost; a token capability that silently
        # outlives the message it was meant for is not.
        conn.execute(
            """
            UPDATE anon_token_state
            SET state = 'SPENT',
                bootstrap_reserved = 0,
                bootstrap_reserved_by = NULL,
                updated_at = ?
            WHERE state = 'IN_FLIGHT'
            """,
            (time.time(),)
        )
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
    with db_connect() as conn:
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


def _db_create_channel_sync(channel_id, ch):
    """Atomic, durable channel creation (S6-47) — replaces channel_create's
    old RAM-first-then-fire-and-forget-DB-write ordering (channels[channel_id]
    used to be populated under `lock` BEFORE any DB write ever ran) with a
    DB-first transaction that also enforces MAX_CHANNELS_PER_OWNER/
    CHANNELS_MAX_TOTAL_ROWS atomically alongside the INSERT — a bare `SELECT
    COUNT(*)` then a separately-awaited INSERT would let two concurrent
    creations (same or different owner) both observe "under cap" and both
    insert, the same race S6-37's db_bind_device_pubkey() closed for
    authorized_devices.

    Returns one of:
      "CREATED"     — the row was durably inserted.
      "OWNER_LIMIT" — this owner already has MAX_CHANNELS_PER_OWNER channels.
      "TOTAL_LIMIT" — CHANNELS_MAX_TOTAL_ROWS is already reached process-wide.

    channel_id collisions are not handled specially — it's a fresh
    secrets.token_urlsafe(16) value per call (cryptographically negligible
    to collide), and channels.channel_id is a PRIMARY KEY, so a genuine
    collision surfaces as a real IntegrityError, never silently ignored."""
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            owner_count = conn.execute(
                "SELECT COUNT(*) FROM channels WHERE admin = ?", (ch["admin"],)
            ).fetchone()[0]
            if owner_count + 1 > MAX_CHANNELS_PER_OWNER:
                conn.rollback()
                return "OWNER_LIMIT"
            total_count = conn.execute("SELECT COUNT(*) FROM channels").fetchone()[0]
            if total_count + 1 > CHANNELS_MAX_TOTAL_ROWS:
                conn.rollback()
                return "TOTAL_LIMIT"
            conn.execute("""
                INSERT INTO channels
                (channel_id, name, avatar, description, admin, admin_name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (channel_id, ch["name"], ch.get("avatar", "📢"), ch.get("description", ""),
                  ch["admin"], ch.get("admin_name", ""), ch.get("created_at", time.time())))
            conn.commit()
            return "CREATED"
        except Exception:
            conn.rollback()
            raise


def _db_save_subscriber_sync(channel_id, username):
    with db_connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO channel_subscribers (channel_id, username) VALUES (?, ?)",
            (channel_id, username)
        )
        conn.commit()


def _db_remove_subscriber_sync(channel_id, username):
    with db_connect() as conn:
        conn.execute(
            "DELETE FROM channel_subscribers WHERE channel_id=? AND username=?",
            (channel_id, username)
        )
        conn.commit()


def _db_store_channel_post_sync(channel_id, post, storage_bytes):
    """Canonical, durable, atomic channel-post store (S6-47) — replaces the
    old unconditional `_db_save_post_sync()`'s bare INSERT OR IGNORE with the
    same proven pattern S6-31 established for pending_messages
    (`_db_store_sync()`, see its own comment): ONE BEGIN IMMEDIATE
    transaction covers the duplicate lookup, the capacity read, the INSERT,
    the per-channel retention prune, and the channel_posts_meta counter
    update, so a caller only ever learns a post was durably stored once that
    transaction has actually committed.

    Returns one of:
      "STORED"    — a genuinely new row was inserted, counters incremented.
      "DUPLICATE" — post_id already existed with the SAME channel_id/text/
                    author_id/author_name/image_data — a harmless resend,
                    not a fresh row, no counter change.
      "CONFLICT"  — post_id already existed but any of those fields differ.
                    Never silently treated as success — post_id is UNIQUE
                    globally (not scoped per-channel), so a reused id with
                    different content is a genuine collision, not a resend.
      "FULL"      — inserting this row would exceed
                    CHANNEL_POSTS_MAX_TOTAL_BYTES/ROWS, read from
                    channel_posts_meta under the SAME transaction as the
                    insert attempt below, not a stale read from before this
                    call started.
      "TOO_LARGE" — storage_bytes alone exceeds CHANNEL_POST_MAX_BYTES.
                    Rejected before BEGIN IMMEDIATE is even issued.

    On any DB-layer failure: rolls back and RE-RAISES — never returns as if
    a post was durably stored when the write didn't actually commit (same
    posture as _db_store_sync())."""
    if storage_bytes > CHANNEL_POST_MAX_BYTES:
        return "TOO_LARGE"

    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT total_rows, total_bytes FROM channel_posts_meta WHERE id = 1"
            ).fetchone()
            total_rows, total_bytes = row if row else (0, 0)

            if (total_rows + 1 > CHANNEL_POSTS_MAX_TOTAL_ROWS
                    or total_bytes + storage_bytes > CHANNEL_POSTS_MAX_TOTAL_BYTES):
                conn.rollback()
                return "FULL"

            cur = conn.execute("""
                INSERT OR IGNORE INTO channel_posts
                (channel_id, post_id, text, timestamp, author_id, author_name, image_data, storage_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (channel_id, post["post_id"], post["text"], post["timestamp"],
                  post["author_id"], post.get("author_name", ""), post.get("image_data", ""),
                  storage_bytes))

            if cur.rowcount == 1:
                conn.execute(
                    "UPDATE channel_posts_meta SET total_rows = total_rows + 1, "
                    "total_bytes = total_bytes + ? WHERE id = 1",
                    (storage_bytes,)
                )
                # Per-channel retention prune (S6-47,
                # CHANNEL_POSTS_MAX_PER_CHANNEL) — atomically in the SAME
                # transaction as the insert, so channel_posts_meta's running
                # totals never disagree with what's actually left on disk.
                # See that constant's own comment for why rows beyond this
                # count are already unobservable to every current client.
                pruned = conn.execute("""
                    SELECT id, storage_bytes FROM channel_posts
                    WHERE channel_id = ? ORDER BY id DESC LIMIT -1 OFFSET ?
                """, (channel_id, CHANNEL_POSTS_MAX_PER_CHANNEL)).fetchall()
                if pruned:
                    pruned_ids   = [r[0] for r in pruned]
                    pruned_bytes = sum(r[1] for r in pruned)
                    conn.execute(
                        f"DELETE FROM channel_posts WHERE id IN ({','.join('?' * len(pruned_ids))})",
                        pruned_ids
                    )
                    conn.execute(
                        "UPDATE channel_posts_meta SET total_rows = total_rows - ?, "
                        "total_bytes = total_bytes - ? WHERE id = 1",
                        (len(pruned_ids), pruned_bytes)
                    )
                conn.commit()
                return "STORED"

            # rowcount == 0: the only way INSERT OR IGNORE silently no-ops
            # here is a post_id UNIQUE conflict — don't just assume that
            # conflict was a harmless resend; verify the existing row
            # actually matches before calling it a duplicate.
            existing = conn.execute(
                "SELECT channel_id, text, author_id, author_name, image_data "
                "FROM channel_posts WHERE post_id = ?",
                (post["post_id"],)
            ).fetchone()
            conn.rollback()
            if existing is not None and existing == (
                channel_id, post["text"], post["author_id"],
                post.get("author_name", ""), post.get("image_data", "")
            ):
                return "DUPLICATE"
            return "CONFLICT"
        except Exception:
            conn.rollback()
            raise


def _db_store_sync(recipient, payload_json, payload_bytes, msg_id=None):
    """Durable offline-message store — the sole write path for
    pending_messages since S6-31 (external review 2026-09-04; see
    PENDING_MESSAGES_MAX_TOTAL_BYTES's own comment for the unbounded-growth
    problem this closes, and OFFLINE_STORE_GLOBAL_LIMIT's own comment for
    the cheaper pre-executor guard layered in front of this call). ONE
    `BEGIN IMMEDIATE` transaction covers the capacity check, the INSERT OR
    IGNORE, and — only for an actual new row — the pending_messages_meta
    counter update, so a caller only ever learns a message was durably
    queued once that transaction has actually committed.

    Returns one of:
      "STORED"    — a genuinely new row was inserted, counters incremented.
      "DUPLICATE" — msg_id already existed for the SAME recipient with the
                    SAME payload — a harmless resend, not a fresh row, no
                    counter change. Safe to treat exactly like "STORED" for
                    ACK purposes: the message IS durably present either way.
      "CONFLICT"  — msg_id already existed but for a DIFFERENT recipient or
                    a DIFFERENT payload. Never silently treated as success —
                    a colliding/replayed msg_id is not a legitimate resend.
      "FULL"      — inserting this row would exceed
                    PENDING_MESSAGES_MAX_TOTAL_BYTES/ROWS, read from the
                    pending_messages_meta running totals under the SAME
                    transaction as the insert attempt below, not a stale
                    read from before this call started.
      "TOO_LARGE" — payload_bytes alone exceeds PENDING_MESSAGE_MAX_BYTES.
                    Rejected before BEGIN IMMEDIATE is even issued — no
                    reason to pay for a transaction on a payload that can
                    never fit regardless of how much headroom exists.
      "INVALID_RECIPIENT" — recipient isn't an is_valid_fingerprint() shape.
                    Rejected before BEGIN IMMEDIATE, same reasoning as
                    TOO_LARGE. Every legitimate caller already validates
                    this at the handler layer (S6-42) and db_store() itself
                    checks it before ever reaching here — this is
                    defense-in-depth only, for a hypothetical future
                    internal caller that bypasses db_store(). See
                    OFFLINE_MSG_ID_MAX_LEN's own comment for the byte-cap
                    gap a giant non-canonical recipient used to open.
      "INVALID_MSG_ID"    — msg_id is not None and fails
                    is_valid_offline_msg_id() (wrong type, empty, or over
                    OFFLINE_MSG_ID_MAX_LEN). Same defense-in-depth
                    reasoning and rejection point as INVALID_RECIPIENT.

    On any DB-layer failure: rolls back and RE-RAISES — never returns as if
    a message was durably stored when the write didn't actually commit (the
    old `except Exception: pass` this replaces was exactly that failure
    mode — see message/session_init's own ACK-gating comment for why that
    used to produce a false delivery ACK)."""
    if not is_valid_fingerprint(recipient):
        return "INVALID_RECIPIENT"
    if not is_valid_offline_msg_id(msg_id):
        return "INVALID_MSG_ID"
    if payload_bytes > PENDING_MESSAGE_MAX_BYTES:
        return "TOO_LARGE"

    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT total_rows, total_bytes FROM pending_messages_meta WHERE id = 1"
            ).fetchone()
            total_rows, total_bytes = row if row else (0, 0)

            if (total_rows + 1 > PENDING_MESSAGES_MAX_TOTAL_ROWS
                    or total_bytes + payload_bytes > PENDING_MESSAGES_MAX_TOTAL_BYTES):
                conn.rollback()
                return "FULL"

            cur = conn.execute(
                "INSERT OR IGNORE INTO pending_messages "
                "(recipient, payload, payload_bytes, created_at, msg_id) VALUES (?, ?, ?, ?, ?)",
                (recipient, payload_json, payload_bytes, time.time(), msg_id)
            )
            if cur.rowcount == 1:
                conn.execute(
                    "UPDATE pending_messages_meta SET total_rows = total_rows + 1, "
                    "total_bytes = total_bytes + ? WHERE id = 1",
                    (payload_bytes,)
                )
                conn.commit()
                return "STORED"

            # rowcount == 0: the only way INSERT OR IGNORE silently no-ops
            # here is a msg_id UNIQUE conflict (a NULL msg_id never
            # conflicts with anything else in SQLite) — don't just assume
            # that conflict was a harmless resend; verify the existing row
            # actually matches before calling it a duplicate.
            existing = conn.execute(
                "SELECT recipient, payload FROM pending_messages WHERE msg_id = ?",
                (msg_id,)
            ).fetchone()
            conn.rollback()
            if existing is not None and existing[0] == recipient and existing[1] == payload_json:
                return "DUPLICATE"
            return "CONFLICT"
        except Exception:
            conn.rollback()
            raise


def _db_peek_pending_sync(recipient, limit):
    """Read-only, bounded look at `recipient`'s durable backlog (S6-55,
    external review 2026-09-06) — replaces the old _db_flush_sync()'s
    SELECT-then-DELETE-ALL shape, which destroyed every queued row before
    even the first websocket send was attempted (see
    db_delete_pending_row()'s own comment for the reliability bug this
    closes). No transaction, no mutation of pending_messages or
    pending_messages_meta — a plain read, safe to call repeatedly and safe
    to call concurrently with anything else. Returns up to `limit` rows
    ordered by `id` (insertion order, i.e. FIFO), each a
    (row_id, payload, payload_bytes) tuple. An empty list means nothing
    (else) is currently queued for this recipient — NOT that the recipient
    doesn't exist."""
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, payload, payload_bytes FROM pending_messages "
            "WHERE recipient = ? ORDER BY id LIMIT ?",
            (recipient, limit)
        ).fetchall()
    return rows


def _db_delete_pending_row_sync(recipient, row_id):
    """Deletes exactly ONE durable row — the row-level counterpart to
    _db_store_sync()'s insert (S6-55). Callers are expected to invoke this
    ONLY after that row's payload has actually been handed off to a
    websocket (send_safe() returned True) — see the reconnect flush loop's
    own comment for the ordering this enforces and why. `recipient` is part
    of the WHERE clause (not just `row_id`) as an extra guard against ever
    deleting a row belonging to someone else, even though row_id alone is
    already a unique primary key and no caller here obtains a row_id except
    from a prior db_peek_pending() call for this exact `recipient`.

    ONE BEGIN IMMEDIATE transaction covers the ownership/existence check,
    the DELETE, and — only if a row actually was deleted — the
    pending_messages_meta counter decrement, so meta can never drift out of
    sync with what's actually still on disk (same pairing principle
    _db_store_sync()/_pending_messages_cleanup_batch_sync() already use).

    Returns:
      "DELETED"   — the row existed for this recipient and was removed;
                    meta was decremented by exactly this row's payload_bytes.
      "NOT_FOUND" — no such row for this recipient. This is a BENIGN,
                    expected outcome, not an error: the TTL watchdog
                    (_pending_messages_cleanup_batch_sync()) may have
                    already expired this exact row between our caller's
                    peek and this delete (STEP 8), or a concurrent flush
                    for the same account (STEP 6 — e.g. overlapping
                    reconnects during session replacement) may have already
                    delivered-and-deleted it first. Either way meta is left
                    untouched — never decremented for a row that didn't
                    actually exist, which is exactly what would eventually
                    drive total_rows/total_bytes negative."""
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT payload_bytes FROM pending_messages WHERE id = ? AND recipient = ?",
                (row_id, recipient)
            ).fetchone()
            if row is None:
                conn.rollback()
                return "NOT_FOUND"
            cur = conn.execute(
                "DELETE FROM pending_messages WHERE id = ? AND recipient = ?",
                (row_id, recipient)
            )
            if cur.rowcount != 1:
                # Lost a benign race against the TTL watchdog or a
                # concurrent flush for this same recipient between the
                # SELECT above and this DELETE — treat exactly like
                # "already gone", not an error (STEP 6/8).
                conn.rollback()
                return "NOT_FOUND"
            conn.execute(
                "UPDATE pending_messages_meta SET total_rows = total_rows - 1, "
                "total_bytes = total_bytes - ? WHERE id = 1",
                (row[0],)
            )
            conn.commit()
            return "DELETED"
        except Exception:
            conn.rollback()
            raise


def _pending_messages_cleanup_batch_sync(now: float, batch_size: int) -> int:
    """One bounded batch of expired-row TTL cleanup — the DELETE and the
    pending_messages_meta decrement happen in the SAME transaction (external
    review 2026-09-04, S6-31), same pairing principle as _db_store_sync()/
    _db_flush_sync() above. Capped at `batch_size` rows per call, not one
    unbounded DELETE over however large the expired backlog is — see
    _pending_messages_watchdog_tick()'s own comment for why. Returns the
    number of rows actually removed (0 means nothing left to clean up)."""
    cutoff = now - MSG_TTL_SEC
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT id, payload_bytes FROM pending_messages WHERE created_at < ? LIMIT ?",
                (cutoff, batch_size)
            ).fetchall()
            if not rows:
                conn.rollback()
                return 0
            ids = [r[0] for r in rows]
            freed_bytes = sum(r[1] for r in rows)
            conn.execute(
                f"DELETE FROM pending_messages WHERE id IN ({','.join('?' * len(ids))})", ids
            )
            conn.execute(
                "UPDATE pending_messages_meta SET total_rows = total_rows - ?, "
                "total_bytes = total_bytes - ? WHERE id = 1",
                (len(ids), freed_bytes)
            )
            conn.commit()
            return len(ids)
        except Exception:
            conn.rollback()
            raise


def _db_load_avatars_sync():
    with db_connect() as conn:
        rows = conn.execute("SELECT username, avatar_b64 FROM user_avatars").fetchall()
    return {row[0]: row[1] for row in rows}


def _db_get_avatars_meta_sync():
    """Cheap startup sanity-check read (S6-50) — a single-row lookup against
    the reconciled running total, not a COUNT(*)/SUM() over the whole table.
    See _db_setup_sync()'s user_avatars_meta reconciliation and
    start_server()'s own fail-closed check for why this exists — mirrors
    _db_count_anon_token_state_rows_sync()'s own reasoning."""
    with db_connect() as conn:
        row = conn.execute("SELECT total_rows, total_bytes FROM user_avatars_meta WHERE id = 1").fetchone()
    return row if row else (0, 0)


def _db_upsert_avatar_sync(username, avatar_b64, avatar_bytes):
    """Canonical, durable, atomic avatar upsert (S6-50) — replaces the old
    unconditional `_db_save_avatar_sync()`'s bare INSERT OR REPLACE with the
    same proven pattern S6-31/S6-47 established for pending_messages/
    channel_posts: ONE BEGIN IMMEDIATE transaction covers the old-row byte
    lookup, the aggregate byte/row-delta capacity check, and the
    INSERT OR REPLACE, so a caller only ever learns an avatar was durably
    stored once this has actually committed. An UPDATE replacing an
    existing avatar accounts for the DELTA (new_bytes - old_bytes), not
    new_bytes alone — changing an avatar never needs logical room for
    old+new simultaneously.

    Returns one of:
      "STORED" — inserted or replaced, user_avatars_meta counters updated
                 to match in the SAME transaction.
      "FULL"   — would exceed AVATARS_MAX_TOTAL_BYTES/AVATARS_MAX_TOTAL_ROWS,
                 read from user_avatars_meta under the SAME transaction as
                 this attempt, not a stale read from before this call.

    Never silently no-ops — the CALLER (apply_avatar_mutation()) is
    responsible for skipping this entirely when the avatar is unchanged, so
    every call here is a genuine mutation. On any DB-layer failure: rolls
    back and re-raises — never returns as if an avatar was durably stored
    when the write didn't actually commit."""
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            meta_row = conn.execute(
                "SELECT total_rows, total_bytes FROM user_avatars_meta WHERE id = 1"
            ).fetchone()
            total_rows, total_bytes = meta_row if meta_row else (0, 0)

            existing = conn.execute(
                "SELECT avatar_bytes FROM user_avatars WHERE username = ?", (username,)
            ).fetchone()
            old_bytes = existing[0] if existing else 0
            is_new_row = existing is None

            projected_rows  = total_rows + (1 if is_new_row else 0)
            projected_bytes = total_bytes - old_bytes + avatar_bytes

            if projected_rows > AVATARS_MAX_TOTAL_ROWS or projected_bytes > AVATARS_MAX_TOTAL_BYTES:
                conn.rollback()
                return "FULL"

            conn.execute(
                "INSERT OR REPLACE INTO user_avatars (username, avatar_b64, avatar_bytes, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (username, avatar_b64, avatar_bytes, time.time())
            )
            conn.execute(
                "UPDATE user_avatars_meta SET total_rows = ?, total_bytes = ? WHERE id = 1",
                (projected_rows, projected_bytes)
            )
            conn.commit()
            return "STORED"
        except Exception:
            conn.rollback()
            raise


async def db_upsert_avatar(username, avatar_b64, avatar_bytes) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_upsert_avatar_sync, username, avatar_b64, avatar_bytes)


async def apply_avatar_mutation(username: str, avatar_value) -> str:
    """ONE canonical avatar-mutation admission path (S6-50), shared by
    register()'s `avatar` field and profile_update — neither may bypass the
    other's controls, and register does NOT get an independent rate bucket
    that could be alternated with profile_update's (both share
    rate_limit_check()'s "profile_update" bucket here).

    Ordering deliberately puts the unchanged-value short-circuit BEFORE rate/
    budget admission — this is more specific than (and takes precedence
    over) the generic "validate → rate → mutate → DB → RAM → broadcast"
    template used elsewhere in this file, because the single most important
    property this patch establishes is that a reconnect carrying the SAME
    avatar it already sent costs nothing: no rate consumption, no DB write,
    no broadcast. Only a GENUINE change is rate/budget-admitted, DB-written
    (before RAM/broadcast, never the reverse), and broadcast.

    Never holds the global `lock` across the SQLite `await` below (invariant
    #34) — get_avatar_mutation_lock(username) is a separate, narrower lock
    (mirrors get_totp_state_lock()'s own precedent exactly), held across the
    DB await specifically so two concurrent mutations for the SAME
    fingerprint can't interleave as DB-write-A, DB-write-B, RAM-A, RAM-B and
    leave RAM disagreeing with whichever write actually committed last.

    Returns one of:
      "INVALID"      — failed is_valid_avatar(); rejected before RAM/SQLite/
                       broadcast. Caller sends no dedicated reply (register
                       has no per-field error channel here; profile_update
                       already silently dropped malformed input before this
                       patch too — unchanged).
      "EMPTY"        — avatar_value was "" — no avatar carried in this
                       message at all, not a mutation attempt.
      "UNCHANGED"    — byte-for-byte identical to the currently stored
                       avatar — the normal reconnect case.
      "RATE_LIMITED" — the shared per-user "profile_update" bucket or the
                       process-wide AVATAR_UPDATE_GLOBAL_LIMIT budget was
                       exhausted.
      "FULL"         — AVATARS_MAX_TOTAL_BYTES/AVATARS_MAX_TOTAL_ROWS would
                       be exceeded; the OLD avatar is left completely
                       intact (RAM and durable state both untouched)."""
    if not is_valid_avatar(avatar_value):
        return "INVALID"
    if avatar_value == "":
        return "EMPTY"

    async with get_avatar_mutation_lock(username):
        if user_avatars.get(username) == avatar_value:
            return "UNCHANGED"

        if not rate_limit_check(username, "profile_update"):
            return "RATE_LIMITED"
        if not avatar_update_global_rate_ok():
            return "RATE_LIMITED"

        avatar_bytes = len(avatar_value.encode("utf-8"))
        status = await db_upsert_avatar(username, avatar_value, avatar_bytes)
        if status == "FULL":
            return "FULL"

        user_avatars[username] = avatar_value
        avatar_payload = json.dumps({
            "type": "avatar_data",
            "from": username,
            "avatar": avatar_value
        })
        async with lock:
            online_snapshot = dict(clients)
        for uid, cinfo in online_snapshot.items():
            if uid != username:
                asyncio.create_task(send_safe(cinfo["ws"], avatar_payload))
        return "STORED"


def _db_load_totp_sync():
    """Fail-closed startup load (external review 2026-09-04) — see
    _totp_decrypt_from_storage()'s own comment for the fail-open bug this
    replaces. Any single account whose stored secret can't be decrypted
    right now (missing/wrong TOTP_SECRET_ENCRYPTION_KEY, corrupted row)
    aborts the ENTIRE server startup rather than silently starting with
    that one account looking TOTP-disabled — called synchronously from
    start_server(), before anything binds/serves, so this is the last
    point where refusing to start is still cheap and obvious (a crash-loop
    in a process supervisor, not a silent security downgrade nobody
    notices)."""
    with db_connect() as conn:
        rows = conn.execute("SELECT username, secret FROM user_totp").fetchall()
    result = {}
    for username, stored in rows:
        secret = _totp_decrypt_from_storage(stored)
        if not secret:
            raise RuntimeError(
                f"Cannot decrypt stored TOTP secret for {username}; "
                "refusing to start fail-open"
            )
        # S6-48 (external review 2026-09-05): a stored secret that decrypts
        # fine but isn't decode_totp_secret()-shaped (wrong length/alphabet)
        # could previously still be loaded into user_totp_secrets as-is and
        # later reach totp_code_matches() on every verification attempt for
        # that account. Same fail-closed reasoning as the decrypt check
        # just above — refuse the ENTIRE startup rather than silently
        # skipping the account (would look identical to "never enabled
        # TOTP", defeating device-gating for that fingerprint) or
        # truncating/repairing it (would silently invalidate every
        # authenticator app already enrolled with the real secret).
        if decode_totp_secret(secret) is None:
            raise RuntimeError(
                f"Stored TOTP secret for {username} is not protocol-bounded "
                "(unexpected shape/length after decryption); refusing to start fail-open"
            )
        result[username] = secret
    return result


def _db_consume_totp_counter_sync(username: str, counter: int) -> bool:
    """Atomic TOTP anti-replay consume (external review 2026-09-03) — replaces
    the RAM-only user_totp_last_counter dict (removed), which reset on every
    server restart: an already-used TOTP code, still within the ±1 time-step
    clock-drift window `totp_code_matches()` allows, could be replayed for up
    to ~90 seconds right after a restart. Single conditional UPDATE, rowcount
    is the only success signal — same first-write-wins shape used throughout
    this file's other anti-replay/atomicity fixes (db_mark_anon_token_inflight,
    db_terminalize_anon_token, etc.): two concurrent verification attempts for
    the same code, or multiple server processes/workers sharing this DB,
    can't both/all succeed for the same or an older counter value."""
    with db_connect() as conn:
        cur = conn.execute(
            """
            UPDATE user_totp
            SET last_counter = ?
            WHERE username = ?
              AND last_counter < ?
            """,
            (counter, username, counter)
        )
        conn.commit()
        return cur.rowcount == 1


async def db_consume_totp_counter(username: str, counter: int) -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_consume_totp_counter_sync, username, counter)


SECOND_FACTOR_GUARD_WINDOW_SEC = 300   # 5 minutes
SECOND_FACTOR_GUARD_MAX_ATTEMPTS = 5
SECOND_FACTOR_GUARD_LOCK_SEC = 900     # 15 minutes


def _db_take_second_factor_attempt_sync(username: str) -> bool:
    """Durable per-fingerprint second-factor rate limit (external review
    2026-09-04) — a 6-digit TOTP code is only as strong as whatever caps
    online guessing attempts, and nothing did: register()'s TOTP/recovery
    check, totp_setup re-enrollment proof, and totp_disable had no
    dedicated limit, rate_limit_check() doesn't cover these message types
    at all, and even where it's used elsewhere it's RAM-only (reset on
    restart, not shared across workers). totp_verify_and_consume()'s own
    anti-replay only rejects a code whose counter was already consumed — a
    WRONG code costs an attacker nothing and consumes nothing, so an
    unknown device could try indefinitely.

    Caller must call this ONCE per second-factor proof attempt (register()
    TOTP/recovery, totp_setup, totp_disable) and only proceed to actually
    check the supplied code if this returns True — the attempt is spent
    whether or not the code turns out to be correct; a correct code does
    not refund it. 5 attempts per rolling 5-minute window, then a 15-minute
    lock on further attempts for that fingerprint. Single BEGIN IMMEDIATE
    transaction, so concurrent attempts (e.g. two racing connections) can't
    each observe a stale attempts count and both slip under the cap."""
    now = time.time()
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT window_started, attempts, locked_until FROM second_factor_guard WHERE username = ?",
                (username,)
            ).fetchone()

            if row is None:
                conn.execute(
                    "INSERT INTO second_factor_guard (username, window_started, attempts, locked_until) "
                    "VALUES (?, ?, 1, 0)",
                    (username, now)
                )
                conn.commit()
                return True

            started, attempts, locked_until = row

            if locked_until > now:
                conn.rollback()
                return False

            if locked_until or now - started >= SECOND_FACTOR_GUARD_WINDOW_SEC:
                # Lock just expired, or the rolling window elapsed — fresh
                # window starting with this attempt.
                conn.execute(
                    "UPDATE second_factor_guard SET window_started = ?, attempts = 1, locked_until = 0 "
                    "WHERE username = ?",
                    (now, username)
                )
                conn.commit()
                return True

            if attempts >= SECOND_FACTOR_GUARD_MAX_ATTEMPTS:
                conn.execute(
                    "UPDATE second_factor_guard SET locked_until = ? WHERE username = ?",
                    (now + SECOND_FACTOR_GUARD_LOCK_SEC, username)
                )
                conn.commit()
                return False

            conn.execute(
                "UPDATE second_factor_guard SET attempts = attempts + 1 WHERE username = ?",
                (username,)
            )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise


async def db_take_second_factor_attempt(username: str) -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_take_second_factor_attempt_sync, username)


# ─── S6-48: TOTP setup/proof input hardening ───────────────────────────────────
# (external review 2026-09-05) — before this fix, totp_setup accepted
# client-controlled `secret`/`new_code`/`current_code`/`recovery_code` with no
# protocol-specific type/length bounds at all. Critically, SECOND_FACTOR_GUARD_*
# above only protects proof of an EXISTING factor — an authenticated account
# with NO TOTP configured yet reaches totp_code_matches(secret, new_code) ->
# _totp_code_at_counter() -> secret.strip().upper() -> padding/copies ->
# base64.b32decode() with no rate limit at all, up to the ordinary multi-
# megabyte websocket frame ceiling, every single message. Worse, if an
# attacker happens to supply a VALID code for its own huge valid-Base32
# secret, the server durably PERSISTS that secret (user_totp), and
# _db_load_totp_sync() loads every stored secret fully into
# user_totp_secrets at every startup — one oversized frame from a Sybil
# account becomes permanent SQLite + startup/live-RAM retention.
#
# Client secret format confirmed by inspection, not guessed (both Android's
# and Desktop's TotpManager.generateSecret(): `ByteArray(20)` +
# SecureRandom + a hand-rolled Base32 encoder with NO padding, uppercase
# `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567` alphabet only — identical on both
# platforms, unchanged in git history since TOTP was introduced) — neither
# client has any "import/scan an external secret" path, `generateSecret()`
# is the sole origin of every legitimate secret ever created. 20 bytes ->
# exactly 32 Base32 characters, never padded (160 bits is an exact multiple
# of 5). No server-side tool (admin_gen_codes.py, grepped) generates TOTP
# secrets in any other shape either. This is therefore the ONE canonical
# format, not a compatibility range — decode_totp_secret() requires it
# exactly, matching this file's existing posture for other single-format
# client-generated values (is_valid_fingerprint(), is_valid_device_id()).
TOTP_SECRET_B32_LEN        = 32   # canonical: 20 raw bytes, Base32, no padding
TOTP_SECRET_B32_MAX_LEN    = 40   # cheap pre-normalization gate (small slack
                                   # for incidental whitespace around the 32
                                   # canonical characters -- NOT a broader
                                   # compatibility range)
TOTP_SECRET_DECODED_BYTES  = 20


def decode_totp_secret(value):
    """Cheap shape/length/alphabet checks BEFORE base64.b32decode() ever
    runs (S6-48) — same externally-indistinguishable-rejection posture as
    decode_identity_public_key(): returns the normalized (stripped/
    uppercased) canonical Base32 string on success, None on ANY failure
    (wrong type/empty/oversized/bad alphabet/bad Base32 syntax/wrong
    decoded length). Preserves exactly the strip()/upper() normalization
    _totp_code_at_counter() already applied to its own input before this
    fix — no NEW leniency added, just moved earlier so a multi-megabyte
    value never reaches that normalization/padding/decode work at all."""
    if not isinstance(value, str) or not value or len(value) > TOTP_SECRET_B32_MAX_LEN:
        return None
    normalized = value.strip().upper()
    if len(normalized) != TOTP_SECRET_B32_LEN:
        return None
    if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in normalized):
        return None
    try:
        decoded = base64.b32decode(normalized)
    except Exception:
        return None
    if len(decoded) != TOTP_SECRET_DECODED_BYTES:
        return None
    return normalized


def is_valid_totp_code(value) -> bool:
    """Canonical RFC-6238 code shape (S6-48) — this server's own
    _totp_code_at_counter() always generates exactly 6 ASCII decimal
    digits, zero-padded. Checked (after the same strip() totp_code_matches()
    already applied before comparing, preserved here) BEFORE a code ever
    reaches hmac.compare_digest() or is used to key any lookup — a
    malformed or huge attacker-supplied value can never itself become
    work. Small pre-strip length gate (16) is slack for incidental
    whitespace only, not a broader format."""
    if not isinstance(value, str) or len(value) > 16:
        return False
    normalized = value.strip()
    return len(normalized) == 6 and all(c in "0123456789" for c in normalized)


# Canonical shape for a generated recovery code (S6-48) — generate_recovery_
# codes() below always produces `secrets.token_hex(10).upper()` (20 hex
# chars) formatted as "XXXXX-XXXXX-XXXXX-XXXXX" (23 characters total).
# Normalizes with the SAME strip()/upper() _hash_recovery_code() already
# applies before hashing — preserving existing tolerance for a code typed
# in lowercase or with stray surrounding whitespace, not adding any new
# leniency.
_RECOVERY_CODE_RE = re.compile(r"^[0-9A-F]{5}-[0-9A-F]{5}-[0-9A-F]{5}-[0-9A-F]{5}$")
RECOVERY_CODE_MAX_LEN = 40   # cheap pre-normalization gate, generous slack
                             # above the canonical 23 characters


def is_valid_recovery_code(value) -> bool:
    if not isinstance(value, str) or not value or len(value) > RECOVERY_CODE_MAX_LEN:
        return False
    return _RECOVERY_CODE_RE.match(value.strip().upper()) is not None


# Dedicated per-user totp_setup attempt rate (added to rate_limit_check()'s
# default_limits table, S6-48) — applies at the TOP of the totp_setup
# handler regardless of whether TOTP is already enabled for the account,
# since SECOND_FACTOR_GUARD_* above only ever engages for an ALREADY-
# enrolled account's re-enrollment proof; a first-time setup attempt
# (the actual resource-exhaustion path this whole fix closes) never reaches
# that guard at all. 5/min is generous for a human manually retyping a
# freshly-generated 6-digit code (one deliberate button press per attempt,
# no client-side auto-retry loop — grepped both clients) while bounding how
# many expensive parsing/setup attempts one account can force per minute.
# This is per-user fairness only — NOT a substitute for either
# SECOND_FACTOR_GUARD_* (the durable brute-force boundary for an existing
# factor) or the process-wide budget below (the aggregate Sybil-resistance
# boundary) — see TOTP_SETUP_GLOBAL_LIMIT's own comment.
TOTP_SETUP_RATE_LIMIT = 5

# Process-wide pre-verification setup-work budget (S6-48) — open/Sybil
# registration defeats a purely per-account bucket (MAX_REGISTERED_USERS
# permitting, an attacker can mint as many accounts as it wants, each
# individually under TOTP_SETUP_RATE_LIMIT). Mirrors the existing no-await
# RAM-only limiter pattern used throughout this file
# (global_prekey_publish_rate_ok()/global_offline_store_rate_ok()/
# channel_post_global_rate_ok()) — checked AFTER cheap shape validation
# (decode_totp_secret()/is_valid_totp_code()) but BEFORE totp_code_matches()
# ever runs, so a malformed/oversized value never consumes this budget at
# all — it exists specifically to bound aggregate valid-LOOKING (correct
# shape, unknown correctness) TOTP verification/setup work across many
# distinct accounts, not to catch garbage input (that's free to reject
# regardless of this budget's state). Explicitly process-local, same
# caveat as every other RAM-only limiter in this file: a multi-process/
# replica deployment gets one independent budget PER PROCESS. 0 (not
# negative) explicitly disables it, same convention as
# PREKEY_PUBLISH_GLOBAL_LIMIT/OFFLINE_STORE_GLOBAL_LIMIT/
# CHANNEL_POST_GLOBAL_LIMIT.
TOTP_SETUP_GLOBAL_LIMIT = int(os.environ.get("TOTP_SETUP_GLOBAL_LIMIT", "60") or "60")
if TOTP_SETUP_GLOBAL_LIMIT < 0:
    print("[FATAL] TOTP_SETUP_GLOBAL_LIMIT должен быть >= 0 (0 явно отключает агрегатный "
          "лимитер TOTP setup-работы) — отказ запуска, чтобы не работать с "
          "неоднозначной конфигурацией.", flush=True)
    sys.exit(1)
TOTP_SETUP_GLOBAL_ENABLED    = TOTP_SETUP_GLOBAL_LIMIT > 0
TOTP_SETUP_GLOBAL_WINDOW_SEC = 60
totp_setup_global_rate = {"count": 0, "reset_time": time.time()}


def totp_setup_global_rate_ok() -> bool:
    """Mirrors global_prekey_publish_rate_ok()/global_offline_store_rate_ok()
    exactly — see either's own comment for the full reasoning this shares,
    including why no explicit lock is needed (no `await` here, so a single
    asyncio event loop makes the check-then-increment atomic)."""
    if not TOTP_SETUP_GLOBAL_ENABLED:
        return True
    now  = time.time()
    data = totp_setup_global_rate
    if now - data["reset_time"] >= TOTP_SETUP_GLOBAL_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= TOTP_SETUP_GLOBAL_LIMIT:
        return False
    data["count"] += 1
    return True


def _db_gen_access_codes_sync(count):
    """Generates `count` fresh 128-bit access codes and durably stores only
    each one's `_hash_access_code()` representation (external review
    2026-09-05, S6-41) — the raw values are returned to the caller (which
    prints/QR-encodes them for the operator) but never themselves written
    to SQLite or logged anywhere in this function."""
    raw_codes = [secrets.token_hex(ACCESS_CODE_RANDOM_BYTES).upper() for _ in range(count)]
    with db_connect() as conn:
        now = time.time()
        for raw in raw_codes:
            conn.execute(
                "INSERT OR IGNORE INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
                (_hash_access_code(raw), now)
            )
        conn.commit()
    return raw_codes


def _db_count_access_codes_sync():
    with db_connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM server_access_codes").fetchone()[0]
        unused = conn.execute("SELECT COUNT(*) FROM server_access_codes WHERE used = 0").fetchone()[0]
    return total, unused


def _db_has_legacy_unused_access_codes_sync() -> bool:
    """True if any UNUSED row in server_access_codes is NOT the current
    `sha256:<64 hex>` representation (external review 2026-09-05, S6-41) —
    i.e. a pre-fix, low-entropy plaintext code that could still be redeemed.
    Hashing an already-generated 32-bit-entropy code would not make it
    safe (it would only turn online guessing into offline hashing of at
    most 2^32 values), so such rows must be purged and replaced with fresh
    128-bit codes, not silently grandfathered in. USED rows are excluded
    deliberately — a spent code can never grant access again regardless of
    its original format, so it's harmless historical/audit state, not a
    live credential; see start_server()'s own comment for how this gates
    startup."""
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT code FROM server_access_codes WHERE used = 0"
        ).fetchall()
    return any(not _ACCESS_CODE_HASH_RE.match(row[0]) for row in rows)


def _db_is_fingerprint_registered_sync(fingerprint):
    with db_connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM registered_fingerprints WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
    return row is not None


def _db_count_registered_fingerprints_sync() -> int:
    """Cheap COUNT(*), used only for the startup sanity log (S6-56) — unlike
    user_avatars/anon_token_state, registered_fingerprints is never loaded
    into RAM in bulk (every lookup elsewhere in this file is a per-row
    SELECT/INSERT against this exact table), so there is no full-table-load
    step this needs to guard ahead of; this exists purely so an operator
    sees actual account count vs. the configured caps at every startup,
    not only when a registration attempt happens to fail."""
    with db_connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM registered_fingerprints").fetchone()[0]


def _db_admit_new_fingerprint_sync(fingerprint: str, max_users: int, access_code: str, require_access_code: bool):
    """Atomic cap-check + access-code-consume + insert, all in ONE
    transaction (external review 2026-09-03) — replaces the old two-step
    cap-check-and-insert (formerly _db_try_register_new_fingerprint_sync,
    removed) plus a separate access-code consume (formerly
    _db_check_and_consume_access_code_sync, removed) as the new-registration
    path — both are now folded into this one transaction; nothing else
    called either of them. Bug found live: the previous split (insert-with-cap-check FIRST, PoW check
    SECOND, access-code check THIRD) inserted the fingerprint into
    registered_fingerprints before either gate ran. A failed PoW or missing/
    wrong access_code left that INSERT standing — db_is_fingerprint_registered()
    then reports the fingerprint as already-registered on any later attempt,
    and is_new_fingerprint permanently becomes False for it, so NEITHER PoW
    NOR the access-code gate is ever checked again. A single reconnect with
    an invalid PoW/no access_code was enough to permanently mint a
    "registered" identity — worse, with SERVER_ACCESS_PROTECTED or a
    MAX_REGISTERED_USERS cap in effect, an attacker could burn through the
    user-count cap with fingerprints that never passed either gate. This
    version never inserts until every gate has actually passed, in the same
    atomic transaction as the insert itself — PoW is still checked by the
    caller BEFORE this is even invoked (it's a pure computation, no DB
    write, nothing here needs to protect it), but the cap check, the
    access-code consume, and the insert now either all happen together or
    none of them do. Returns:
      "exists"        — a concurrent caller already registered this exact
                         fingerprint first (race between two connections
                         proving the same private key at once) — nothing
                         charged against the cap or the access code, this
                         caller just proceeds as if it were already known.
      "full"           — max_users cap reached; rolled back, access_code (if
                         any) was never touched, so a legitimate code isn't
                         wasted on a server that was full anyway.
      "access_denied"  — require_access_code was set and access_code didn't
                         match an unused row; rolled back, no insert.
      "ok"             — admitted: cap had room (or no cap), access code (if
                         required) was consumed, fingerprint is now durably
                         registered.
    BEGIN IMMEDIATE gives the same genuinely-atomic guarantee the old
    cap-check-and-insert had — a second concurrent caller blocks until the
    first's transaction fully commits (or rolls back) before it can see an
    updated count or claim the same access code."""
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            exists = conn.execute(
                "SELECT 1 FROM registered_fingerprints WHERE fingerprint = ?",
                (fingerprint,)
            ).fetchone()
            if exists:
                conn.commit()
                return "exists"

            if max_users > 0:
                count = conn.execute("SELECT COUNT(*) FROM registered_fingerprints").fetchone()[0]
                if count >= max_users:
                    conn.rollback()
                    return "full"

            if require_access_code:
                # Caller supplies the canonical RAW code (register()
                # validates its shape before ever reaching this function —
                # see is_valid_access_code()) — hashed here, once, and
                # compared against the hashed representation
                # _db_gen_access_codes_sync() actually stores (external
                # review 2026-09-05, S6-41). Never compares/stores the raw
                # value itself.
                cur = conn.execute(
                    "UPDATE server_access_codes SET used = 1, used_by = ?, used_at = ? WHERE code = ? AND used = 0",
                    (fingerprint, time.time(), _hash_access_code(access_code))
                )
                if cur.rowcount != 1:
                    conn.rollback()
                    return "access_denied"

            conn.execute(
                "INSERT INTO registered_fingerprints (fingerprint, first_registered_at) VALUES (?, ?)",
                (fingerprint, time.time())
            )
            conn.commit()
            return "ok"
        except Exception:
            conn.rollback()
            raise


async def db_is_fingerprint_registered(fingerprint):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_is_fingerprint_registered_sync, fingerprint)


async def db_admit_new_fingerprint(fingerprint, max_users, access_code, require_access_code):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, _db_admit_new_fingerprint_sync, fingerprint, max_users, access_code, require_access_code
    )


def _db_get_authorized_device_sync(username: str, device_id: str):
    """Returns (row_exists, pubkey_bytes_or_None) — the three states
    register() needs to branch on (see its own comment): no row at all
    (brand-new device_id), a row with pubkey NULL (legacy — created before
    device_pubkey existed, or by db_authorize_device() while TOTP wasn't
    configured — first connection under an active TOTP requirement must
    still pin a pubkey via db_bind_device_pubkey()), or a row with a pinned
    pubkey (the normal case — supplied device_public_key must match this
    exactly, checked by the caller, never by this function)."""
    with db_connect() as conn:
        row = conn.execute(
            "SELECT device_pubkey FROM authorized_devices WHERE username = ? AND device_id = ?",
            (username, device_id)
        ).fetchone()
    if row is None:
        return (False, None)
    stored = row[0]
    return (True, bytes(stored) if stored is not None else None)


async def db_get_authorized_device(username: str, device_id: str):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_get_authorized_device_sync, username, device_id)


def _db_bind_device_pubkey_sync(username: str, device_id: str, pubkey: bytes) -> str:
    """Atomically pins device_pubkey for (username, device_id) — either by
    inserting a brand-new row, or by claiming a legacy row whose pubkey is
    still NULL (see authorized_devices' own comment). Only ever called by
    register() after device_signature has already been verified against
    THIS SAME pubkey AND (since this is a first-time pin) TOTP/recovery has
    succeeded — see register()'s own comment for the full ordering.
    Critical invariant (external review 2026-09-03): an already-pinned
    pubkey is NEVER overwritten, by this function or any other code path in
    this file — allowing replacement would let an attacker who merely knows
    (or guesses) a legitimate device_id string re-pin it to a key they
    control, exactly the bearer-token weakness this whole device_pubkey
    mechanism exists to close. register() itself already refuses to reach
    this function at all when a stored pubkey exists and doesn't match the
    supplied one (see its own comment) — the read-then-refuse-to-overwrite
    check here is belt-and-suspenders against a TOCTOU in that ordering,
    not the primary defense.

    Returns one of four explicit statuses (external review 2026-09-04,
    S6-37 — was a bare bool):
      "BOUND"            — pubkey newly pinned (fresh row, or claimed a
                            legacy NULL row).
      "ALREADY_MATCHED"  — `pubkey` was already the pinned value (should be
                            unreachable given register()'s own check above,
                            but handled rather than assumed impossible).
      "CONFLICT"         — a DIFFERENT pubkey was already pinned (same
                            unreachable-in-practice caveat).
      "FULL"             — `device_id` has no existing row, and this
                            account is already at MAX_AUTHORIZED_DEVICES_
                            PER_ACCOUNT — the durable per-account device cap
                            (external review 2026-09-04, S6-37): even with
                            the TOTP-disabled NULL-row path removed, an
                            account that legitimately keeps proving TOTP for
                            brand-new device_ids could otherwise enroll
                            unboundedly many pinned device keys over time.
                            Enforced INSIDE this same BEGIN IMMEDIATE
                            transaction — a separate SELECT-COUNT-then-
                            INSERT-in-a-later-transaction would let two
                            concurrent enrollments both observe "under cap"
                            and both insert, overshooting it. A row whose
                            pubkey is still NULL (a pre-existing, not-yet-
                            pinned device_id) is exempt from this check: it
                            is EXISTING durable state, not new growth, so
                            claiming it must succeed even if the account is
                            already at or over the cap (e.g. after the cap
                            was lowered, or after legacy rows were created
                            before this fix existed)."""
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT device_pubkey FROM authorized_devices WHERE username = ? AND device_id = ?",
                (username, device_id)
            ).fetchone()
            if row is None:
                device_count = conn.execute(
                    "SELECT COUNT(*) FROM authorized_devices WHERE username = ?",
                    (username,)
                ).fetchone()[0]
                if device_count >= MAX_AUTHORIZED_DEVICES_PER_ACCOUNT:
                    conn.rollback()
                    return "FULL"
                conn.execute(
                    "INSERT INTO authorized_devices (username, device_id, device_pubkey, added_at) VALUES (?, ?, ?, ?)",
                    (username, device_id, pubkey, time.time())
                )
                conn.commit()
                return "BOUND"
            stored = row[0]
            if stored is not None:
                conn.rollback()
                return "ALREADY_MATCHED" if bytes(stored) == pubkey else "CONFLICT"
            # Existing NULL-pubkey row — claiming it is not new durable
            # growth, so it proceeds regardless of the account's current
            # device count (see this function's own comment on "FULL").
            cur = conn.execute(
                """
                UPDATE authorized_devices
                SET device_pubkey = ?, added_at = ?
                WHERE username = ? AND device_id = ? AND device_pubkey IS NULL
                """,
                (pubkey, time.time(), username, device_id)
            )
            conn.commit()
            return "BOUND" if cur.rowcount == 1 else "CONFLICT"
        except Exception:
            conn.rollback()
            raise


async def db_bind_device_pubkey(username: str, device_id: str, pubkey: bytes) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_bind_device_pubkey_sync, username, device_id, pubkey)


def _hash_anon_token(token: str) -> bytes:
    """The anon token itself is never stored — only this hash, so a DB
    compromise alone can't be used to reconstruct live routing secrets. See
    anon_token_state's own comment in _db_setup_sync()."""
    return hashlib.sha256(token.encode("utf-8")).digest()


def _db_claim_anon_tokens_sync(tokens: list, username: str, rows_hint: int = None):
    """Atomic first-claim-wins ownership check (external review 2026-09-03):
    the RAM-only token_owner dict this replaces as source of truth reset on
    every server restart, reopening the exact hijack window it exists to
    close — a contact who was only ever supposed to ADDRESS the real owner
    with a token could subscribe_tokens to it themselves right after a
    restart, before the real owner reconnects. BEGIN IMMEDIATE matters the
    same way it does in _db_admit_new_fingerprint_sync(): if Alice
    and Bob's connections both race to claim the same never-before-seen
    token at once, only one of them actually becomes its first owner —
    genuinely atomic, not "whoever's dict write wins" like the RAM-only
    version was. Nothing is loaded from this table at startup; each
    subscribe_tokens call resolves only the tokens it was actually given.

    Resource hardening (external review 2026-09-05, S6-44) — see
    MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT's own comment for the full problem
    this closes. EXISTING tokens (already a row in this table, regardless of
    owner/state) are ALWAYS resolved first and never consume any capacity —
    only inserting a genuinely NEW token_hash draws against three limits,
    all checked in this SAME transaction as the INSERTs so the count-then-
    admit can never race a concurrent claim: `username`'s own ACTIVE/
    IN_FLIGHT row count (MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT), `username`'s
    durable new-claim issuance window (ANON_TOKEN_NEW_CLAIM_WINDOW_SEC/
    MAX_PER_WINDOW, closing the claim→revoke→reclaim cycling gap the active
    cap alone leaves open), and the table-wide hard ceiling
    (ANON_TOKEN_STATE_MAX_TOTAL_ROWS). A batch of new tokens may be admitted
    PARTIALLY, up to whichever of the three limits has the least room left —
    the caller learns exactly which new tokens made it in via each token's
    own result entry.

    Returns {token: (owner, state)} for every token passed in. For a
    genuinely new token that could NOT be inserted because of any of the
    three limits above, the entry is `(None, "NEW_CLAIM_LIMIT")` — owner is
    deliberately `None` (never a real value) so callers can recognize at a
    glance that this token has NO backing row in the DB at all and must
    never be written into anon_token_state_cache (that cache is a strict
    mirror of this table's actual contents) or treated as this account's
    own ACTIVE token."""
    result = {}
    now = time.time()
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            new_tokens = []
            for token in tokens:
                token_hash = _hash_anon_token(token)
                row = conn.execute(
                    "SELECT owner, state FROM anon_token_state WHERE token_hash = ?",
                    (token_hash,)
                ).fetchone()
                if row is None:
                    new_tokens.append(token)
                else:
                    result[token] = (row[0], row[1])

            if not new_tokens:
                conn.commit()
                return result

            active_count = conn.execute(
                "SELECT COUNT(*) FROM anon_token_state WHERE owner = ? AND state IN ('ACTIVE', 'IN_FLIGHT')",
                (username,)
            ).fetchone()[0]
            active_room = max(0, MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT - active_count)

            guard_row = conn.execute(
                "SELECT window_started, new_claims FROM anon_token_claim_guard WHERE username = ?",
                (username,)
            ).fetchone()
            if guard_row is None or now - guard_row[0] >= ANON_TOKEN_NEW_CLAIM_WINDOW_SEC:
                window_started, claims_so_far = now, 0
            else:
                window_started, claims_so_far = guard_row
            quota_room = max(0, ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW - claims_so_far)

            # PERF-02: the authoritative in-transaction COUNT(*) is still the
            # gate — it is only skipped when the RAM mirror PROVES we are far
            # below the ceiling, so the guarantee this cap provides is
            # unchanged. See ANON_TOKEN_ROWS_HINT_MARGIN's comment for why a
            # maintained counter was rejected in favour of this. `rows_hint` is
            # a lower bound (len(anon_token_state_cache), which can only
            # undercount, never over), so hint + batch + margin < ceiling is a
            # sound proof that the INSERTs below cannot reach the ceiling.
            if (rows_hint is not None
                    and rows_hint + len(new_tokens) + ANON_TOKEN_ROWS_HINT_MARGIN
                        < ANON_TOKEN_STATE_MAX_TOTAL_ROWS):
                total_room = len(new_tokens)
            else:
                total_rows  = conn.execute("SELECT COUNT(*) FROM anon_token_state").fetchone()[0]
                total_room  = max(0, ANON_TOKEN_STATE_MAX_TOTAL_ROWS - total_rows)

            admit_count = min(len(new_tokens), active_room, quota_room, total_room)
            admitted, refused = new_tokens[:admit_count], new_tokens[admit_count:]

            for token in admitted:
                token_hash = _hash_anon_token(token)
                conn.execute(
                    """
                    INSERT INTO anon_token_state
                    (token_hash, owner, state, created_at, updated_at)
                    VALUES (?, ?, 'ACTIVE', ?, ?)
                    """,
                    (token_hash, username, now, now)
                )
                result[token] = (username, "ACTIVE")
            for token in refused:
                result[token] = (None, "NEW_CLAIM_LIMIT")

            if admitted:
                conn.execute(
                    "INSERT OR REPLACE INTO anon_token_claim_guard (username, window_started, new_claims) "
                    "VALUES (?, ?, ?)",
                    (username, window_started, claims_so_far + len(admitted))
                )

            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return result


async def db_claim_anon_tokens(tokens, username):
    """Process-wide pre-SQLite request budget for claims that could create
    NEW state (external review 2026-09-05, S6-44) — see
    ANON_TOKEN_GLOBAL_CLAIM_LIMIT's own comment. Classified against
    anon_token_state_cache (a cache MISS does not guarantee an INSERT will
    actually happen — _db_claim_anon_tokens_sync()'s own caps remain the
    real authority; this is a cheap work/request budget, not exact durable
    accounting): if every submitted token is already a cache hit, this call
    cannot possibly create a new row, so an ordinary reconnect resubscribing
    an already-owned pool costs nothing from this budget and never even
    checks it. Only a batch with at least one potential-new token spends one
    slot — and if the budget is exhausted, only THOSE potential-new tokens
    are refused; every already-cached token still resolves (straight from
    the cache, no DB/executor work at all), so a batch mixing existing and
    new tokens never loses access to the account's own already-owned pool
    just because the global budget happened to be exhausted at that
    moment — preserving the "EXISTING tokens always resolvable" invariant
    at this layer too, not just inside _db_claim_anon_tokens_sync()."""
    async with lock:
        cache_hits, potential_new = {}, []
        for t in tokens:
            cached = anon_token_state_cache.get(_hash_anon_token(t))
            if cached is not None:
                cache_hits[t] = cached
            else:
                potential_new.append(t)
        # PERF-02: read the mirror's size under the SAME lock that just read
        # its contents — free here, and a lower bound on the real row count.
        # See ANON_TOKEN_ROWS_HINT_MARGIN.
        rows_hint = len(anon_token_state_cache)
    if potential_new and not anon_token_global_claim_rate_ok():
        result = dict(cache_hits)
        for t in potential_new:
            result[t] = (None, "NEW_CLAIM_LIMIT")
        return result
    loop = asyncio.get_event_loop()
    # PERF-02/03: acquired here, AFTER the `async with lock:` block above has
    # exited, so this lock is never held while the global lock is acquired.
    # See anon_token_write_lock's comment for why that ordering matters.
    async with anon_token_write_lock():
        return await loop.run_in_executor(
            None, _db_claim_anon_tokens_sync, tokens, username, rows_hint
        )


def _db_mark_anon_token_inflight_sync(token: str):
    """Atomic ACTIVE→IN_FLIGHT transition (external review 2026-09-03) — see
    IN_FLIGHT's own comment in _db_setup_sync() for why this state exists at
    all. BEGIN IMMEDIATE + the WHERE state = 'ACTIVE' guard on the UPDATE
    means only one caller can ever win this transition for a given token,
    the same guarantee _db_claim_anon_tokens_sync() gives first-claim.
    Returns the token's owner on success, None if it wasn't ACTIVE (already
    IN_FLIGHT/SPENT/REVOKED, or never claimed at all) — the caller can't
    tell which from this alone, deliberately: an unknown token and an
    already-claimed one get the exact same externally-indistinguishable
    treatment in anon_message."""
    token_hash = _hash_anon_token(token)
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT owner, state FROM anon_token_state WHERE token_hash = ?",
                (token_hash,)
            ).fetchone()
            if row is None or row[1] != "ACTIVE":
                conn.rollback()
                return None
            owner = row[0]
            conn.execute(
                """
                UPDATE anon_token_state
                SET state = 'IN_FLIGHT', updated_at = ?
                WHERE token_hash = ? AND state = 'ACTIVE'
                """,
                (time.time(), token_hash)
            )
            conn.commit()
            return owner
        except Exception:
            conn.rollback()
            raise


async def db_mark_anon_token_inflight(token: str):
    loop = asyncio.get_event_loop()
    # PERF-03 (2026-11-03): serialised with every other anon_token_state
    # writer — see anon_token_write_lock. This is the hot path (one call per
    # anon_message), and measured mixed-load numbers are in that comment.
    async with anon_token_write_lock():
        return await loop.run_in_executor(None, _db_mark_anon_token_inflight_sync, token)


def _db_terminalize_anon_token_sync(token: str, owner: str, new_state: str):
    """Moves a token from ACTIVE or IN_FLIGHT to a terminal state (SPENT via
    anon_delivery_ack, REVOKED via unsubscribe_tokens) — the durable
    confirmation that anon_delivery_ack_ok/subscribe_tokens_result promise
    the client. Refuses (returns False, no write) if [owner] doesn't match
    the DB's recorded owner — the caller's own username, at the point this
    is invoked, has already been proven live-authenticated for this
    connection, so a mismatch here means the token genuinely isn't this
    caller's to terminalize, not just a caching gap. Already-terminal
    states are left alone (no downgrade path, no re-dating an old SPENT/
    REVOKED as if it just happened). IN_FLIGHT accepted alongside ACTIVE
    (external review 2026-09-03, IN_FLIGHT's own introduction): by the time
    an anon_delivery_ack for a real delivery arrives, anon_message's
    db_mark_anon_token_inflight() has normally already moved the token to
    IN_FLIGHT — only an ACTIVE token reaching here directly would be the
    unusual case (e.g. unsubscribe_tokens revoking a token that was never
    actually used to send anything). Bug found live 2026-09-03 (external
    review): the previous SELECT-then-conditionally-UPDATE version returned
    True unconditionally once past the owner check, even when
    current_state was ALREADY terminal and the UPDATE was skipped — so a
    caller (anon_delivery_ack, unsubscribe_tokens, the TTL watchdog) could
    overwrite anon_token_state_cache with a state that never actually
    happened in the DB, e.g. a watchdog SPENT racing an unsubscribe_tokens
    REVOKED could stamp the RAM cache back to SPENT over a genuinely
    REVOKED row. A single conditional UPDATE with the terminal-state guard
    IN the WHERE clause closes this: cur.rowcount tells the truth about
    whether THIS call actually transitioned anything, in the same atomic
    statement as the transition itself — no separate SELECT whose result
    could go stale before the UPDATE runs, even within one BEGIN IMMEDIATE
    transaction. Also clears bootstrap_reserved AND bootstrap_reserved_by
    (external review 2026-09-03, rounds 2 and 5, same pass as making that
    reservation durable and then per-requester) in this SAME UPDATE — a
    bootstrap reservation on a token that just went terminal means nothing
    (the token itself can never be used again either way), so there's no
    reason to leave either set; doing it here rather than as a separate
    statement means they can never observably disagree with the token's own
    state. This is also what makes pick_bootstrap_token()'s "does this
    requester already have an outstanding reservation against this target"
    check self-correcting after an ACK/revoke/TTL-expiry — the row simply
    stops matching bootstrap_reserved_by = <requester> at all once it's
    terminal, so the next fetch just claims a fresh token instead of
    incorrectly reporting "still reserved"."""
    token_hash = _hash_anon_token(token)
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                """
                UPDATE anon_token_state
                SET state = ?, bootstrap_reserved = 0, bootstrap_reserved_by = NULL, updated_at = ?
                WHERE token_hash = ?
                  AND owner = ?
                  AND state IN ('ACTIVE', 'IN_FLIGHT')
                """,
                (new_state, time.time(), token_hash, owner)
            )
            conn.commit()
            return cur.rowcount == 1
        except Exception:
            conn.rollback()
            raise


async def db_terminalize_anon_token(token, owner, state):
    loop = asyncio.get_event_loop()
    # PERF-03 (2026-11-03): serialised with every other anon_token_state
    # writer — see anon_token_write_lock. Covers all four call sites
    # (anon_delivery_ack, unsubscribe_tokens, the token_pending TTL watchdog,
    # and the ack path) by sitting in the wrapper rather than at each site, so
    # a future call site cannot forget it.
    async with anon_token_write_lock():
        return await loop.run_in_executor(None, _db_terminalize_anon_token_sync, token, owner, state)


def _db_count_anon_token_state_rows_sync() -> int:
    """Cheap startup sanity check (external review 2026-09-05, S6-44),
    called BEFORE _db_load_anon_token_state_sync() actually loads the whole
    table — see ANON_TOKEN_STATE_MAX_TOTAL_ROWS's own comment. A single
    COUNT(*) is trivial even against a huge table; loading an unexpectedly
    gigantic result set into RAM is not."""
    with db_connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM anon_token_state").fetchone()[0]


def _db_load_anon_token_state_sync():
    """Loads the full anon_token_state table into {token_hash: (owner,
    state)} once at startup — see anon_token_state_cache's comment for why
    this replaced a per-lookup SELECT (db_get_anon_token_state, removed):
    anon_channel is unauthenticated, so a per-token DB round-trip on every
    unrecognized "token" was a real DoS surface, not just a hot-path
    inefficiency. Only routing (token_to_ws) is deliberately never
    reconstructed this way — see anon_message's own comment."""
    with db_connect() as conn:
        rows = conn.execute("SELECT token_hash, owner, state FROM anon_token_state").fetchall()
    return {bytes(token_hash): (owner, state) for token_hash, owner, state in rows}


def _db_resolve_bootstrap_token_sync(candidates: list, target: str, requester: str):
    """Atomic per-(target, requester) bootstrap resolution (external review
    2026-09-03, round 5) — replaces the old _db_reserve_bootstrap_token_sync/
    db_reserve_bootstrap_token, which reserved a brand-new token on every
    call with no memory of who'd already been handed one. Bug found live:
    an authenticated account could repeatedly call get_prekey_bundle(target)
    (10/min under prekey_fetch; get_prekey_bundles_batch multiplies this
    across every target in one call) and mint a NEW reservation each time —
    a pool of ~100 tokens could be fully reserved (see bootstrap_reserved's
    own comment: a reservation never auto-expires, only clears on the
    token's own terminal transition) in a few minutes, without the attacker
    ever sending a single real anon_message. This makes repeated fetches
    from the SAME requester against the SAME target idempotent instead: at
    most one outstanding reservation is honored per (target, requester)
    pair. candidates is target's full currently RAM-known token list (raw,
    from ws_to_tokens — see _peek_bootstrap_candidates()), needed both to
    resolve an existing reservation's token_hash back to the raw string
    (never stored raw in the DB) and, if there's no existing reservation, to
    atomically claim one of them fresh. Returns (status, token):
      ("existing", token)     — target, requester already had an ACTIVE
                                 reservation; same token handed back again,
                                 nothing written.
      ("in_flight", None)     — target, requester's outstanding reservation
                                 is already IN_FLIGHT (a real anon_message
                                 was actually sent on it and hasn't been
                                 acked/expired yet) — refuses a second
                                 concurrent token for the same pair rather
                                 than let repeated fetches queue up an
                                 unbounded number of simultaneously
                                 outstanding capabilities; the requester
                                 gets one at a time, matching "one token,
                                 one message" in spirit.
      ("unresolvable", None)  — an existing reservation's hash didn't match
                                 anything in `candidates` (target's live
                                 ws_to_tokens set has changed since the
                                 caller peeked it) — no safe raw token to
                                 return this round.
      ("reserved", token)     — no existing reservation; one of `candidates`
                                 was atomically claimed fresh.
      ("none", None)          — no existing reservation, and every
                                 candidate was already ACTIVE+reserved (by
                                 someone else) or not actually ACTIVE
                                 anymore by the time this ran.
    The UNIQUE INDEX on (owner, bootstrap_reserved_by) — see
    idx_anon_bootstrap_requester_target in _db_setup_sync() — is what makes
    the existing-reservation SELECT below guaranteed to return at most one
    row; BEGIN IMMEDIATE is what makes the whole read-then-maybe-write
    sequence atomic against a concurrent call for the very same pair."""
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                """
                SELECT token_hash, state FROM anon_token_state
                WHERE owner = ? AND bootstrap_reserved_by = ? AND bootstrap_reserved = 1
                  AND state IN ('ACTIVE', 'IN_FLIGHT')
                """,
                (target, requester)
            ).fetchone()
            if row is not None:
                existing_hash, existing_state = bytes(row[0]), row[1]
                conn.commit()
                if existing_state == "IN_FLIGHT":
                    return ("in_flight", None)
                for t in candidates:
                    if _hash_anon_token(t) == existing_hash:
                        return ("existing", t)
                return ("unresolvable", None)

            for t in candidates:
                token_hash = _hash_anon_token(t)
                cur = conn.execute(
                    """
                    UPDATE anon_token_state
                    SET bootstrap_reserved = 1,
                        bootstrap_reserved_by = ?,
                        updated_at = ?
                    WHERE token_hash = ?
                      AND owner = ?
                      AND state = 'ACTIVE'
                      AND bootstrap_reserved = 0
                    """,
                    (requester, time.time(), token_hash, target)
                )
                if cur.rowcount == 1:
                    conn.commit()
                    return ("reserved", t)
            conn.rollback()
            return ("none", None)
        except Exception:
            conn.rollback()
            raise


async def db_resolve_bootstrap_token(candidates: list, target: str, requester: str):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_resolve_bootstrap_token_sync, candidates, target, requester)


def _db_revoke_fingerprint_sync(fingerprint):
    with db_connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_fingerprints (fingerprint, revoked_at) VALUES (?, ?)",
            (fingerprint, time.time())
        )
        conn.commit()


def _db_is_fingerprint_revoked_sync(fingerprint):
    with db_connect() as conn:
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
    within `window` steps of clock drift, else None.

    Both inputs are protocol-bounded before any Base32 decode/HMAC work
    happens (S6-48, external review 2026-09-05) — `code` must be
    is_valid_totp_code()-shaped and `secret_b32` must be
    decode_totp_secret()-shaped (the exact canonical 20-byte-decoded Base32
    format both shipped clients generate). A malformed/oversized value of
    either can never reach _totp_code_at_counter()'s base64.b32decode()
    call — this is what closes the resource-exhaustion gap an
    authenticated-but-not-yet-TOTP-enabled account could otherwise
    repeatedly trigger via totp_setup (no durable second-factor guard
    protects a FIRST enrollment attempt, only proof of an EXISTING factor —
    see TOTP_SETUP_RATE_LIMIT's own comment). Every current caller's secret
    is either already decode_totp_secret()-validated at enrollment time
    (user_totp_secrets, reached via register()/totp_disable) or validated
    by the caller immediately before this call (totp_setup's new_secret) —
    this is defense-in-depth, not the primary control point."""
    normalized_secret = decode_totp_secret(secret_b32)
    if normalized_secret is None or not is_valid_totp_code(code):
        return None
    code = code.strip()
    counter_now = int(time.time() // 30)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_totp_code_at_counter(normalized_secret, counter_now + drift), code):
            return counter_now + drift
    return None


async def totp_verify_and_consume(username: str, code: str) -> bool:
    """Verifies `code` against the account's stored secret and rejects replay of
    an already-used time-step — durable (external review 2026-09-03): this
    used to check/update a RAM-only user_totp_last_counter dict, which reset
    on every server restart, letting an already-used code within the ±1
    time-step drift window be replayed right after a restart, or accepted
    independently by multiple server processes/workers sharing one DB. The
    consumed counter now lives in user_totp.last_counter (SQLite), the sole
    source of truth — see db_consume_totp_counter()'s own comment for the
    atomic UPDATE mechanics. Resetting this on re-enrollment/disable needs no
    separate code path: _db_commit_totp_setup_sync()'s INSERT OR REPLACE
    recreates the whole row (last_counter defaults back to -1) whenever a
    new secret is saved, and _db_commit_totp_disable_sync() removes the row
    (and its counter) entirely on disable."""
    secret = user_totp_secrets.get(username)
    if not secret:
        return False
    matched = totp_code_matches(secret, code)
    if matched is None:
        return False
    if not await db_consume_totp_counter(username, matched):
        print(f"[SECURITY] TOTP replay отклонён для {username}")
        return False
    return True


def _hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


def generate_recovery_codes(count: int = 8) -> list:
    """Human-typeable, high-entropy: 20 hex chars (80 bits), grouped for
    readability (e.g. 'A1B2C-D3E4F-56789-ABCDE'). Not derived from the TOTP
    secret -- an independent credential, so losing one doesn't compromise
    the other.

    80 bits, not the previous 40 (external review, 2026-08-27): the stored
    hash (_hash_recovery_code, below) is a single unsalted SHA-256 -- fine
    for a high-entropy random token as originally reasoned, but 40 bits of
    entropy against a fast, trivially-parallelizable hash is NOT actually
    safe against offline brute force once an attacker has the hash (e.g.
    via KL-27, DB theft when SQLCipher isn't enabled) -- a single modern
    GPU exhausts 2^40 SHA-256 candidates in well under a minute. 80 bits
    keeps the same hash function (no KDF migration needed) but pushes
    brute-force cost back to infeasible."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(10).upper()
        codes.append(f"{raw[:5]}-{raw[5:10]}-{raw[10:15]}-{raw[15:]}")
    return codes


def _db_check_and_consume_recovery_code_sync(username: str, code: str) -> bool:
    """One-shot: marks the code used in the same statement it checks it, so
    two concurrent redemption attempts (same code) can't both succeed."""
    code_hash = _hash_recovery_code(code)
    with db_connect() as conn:
        cur = conn.execute(
            "UPDATE totp_recovery_codes SET used = 1 "
            "WHERE username = ? AND code_hash = ? AND used = 0",
            (username, code_hash)
        )
        conn.commit()
        return cur.rowcount > 0


async def db_check_and_consume_recovery_code(username: str, code: str) -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_check_and_consume_recovery_code_sync, username, code)


def _db_commit_totp_setup_sync(username: str, secret: str, codes: list) -> None:
    """Atomically persists a new/re-enrolled TOTP secret AND its recovery
    codes in ONE transaction (external review 2026-09-03) — replaces two
    independent fire-and-forget create_task() writes (formerly
    _db_save_totp_sync + _db_save_recovery_codes_sync, both removed) that
    totp_setup used to fire *after* already telling the client
    totp_setup_ok. That left a crash window: client receives
    totp_setup_ok, the process dies before either write (or only one of
    the two) lands, restart finds no row in user_totp — device-gating
    silently downgrades back to disabled — or a secret with no matching
    recovery codes, leaving the user unable to ever recover it. Caller
    must await this and only update RAM / send totp_setup_ok after it
    returns successfully.

    Independently refuses a non-protocol-bounded `secret` BEFORE
    _totp_encrypt_for_storage()/BEGIN IMMEDIATE/INSERT ever run (S6-48,
    external review 2026-09-05) — the totp_setup handler already validates
    this, but a future internal caller that bypasses the handler must not
    be able to persist an oversized/malformed secret merely by calling this
    function directly. `codes` are always server-generated
    (generate_recovery_codes()), never attacker-controlled, so no
    additional validation is added there beyond this function's existing
    behavior."""
    if decode_totp_secret(secret) is None:
        raise ValueError(
            f"_db_commit_totp_setup_sync: refusing to persist a non-protocol-bounded "
            f"TOTP secret for {username}"
        )
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            now = time.time()
            conn.execute(
                "INSERT OR REPLACE INTO user_totp (username, secret, created_at, last_counter) "
                "VALUES (?, ?, ?, -1)",
                (username, _totp_encrypt_for_storage(secret), now)
            )
            conn.execute("DELETE FROM totp_recovery_codes WHERE username = ?", (username,))
            for code in codes:
                conn.execute(
                    "INSERT INTO totp_recovery_codes (username, code_hash, used, created_at) VALUES (?, ?, 0, ?)",
                    (username, _hash_recovery_code(code), now)
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


async def db_commit_totp_setup(username: str, secret: str, codes: list) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_commit_totp_setup_sync, username, secret, codes)


def _db_commit_totp_disable_sync(username: str) -> None:
    """Atomic counterpart to _db_commit_totp_setup_sync for the disable path
    (external review 2026-09-03) — deletes user_totp and
    totp_recovery_codes in ONE transaction instead of two independent
    fire-and-forget deletes (formerly asyncio.create_task(db_delete_totp)
    + asyncio.create_task(db_delete_recovery_codes), both removed), so
    totp_disable_ok is never sent before both durably land."""
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM user_totp WHERE username = ?", (username,))
            conn.execute("DELETE FROM totp_recovery_codes WHERE username = ?", (username,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise


async def db_commit_totp_disable(username: str) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _db_commit_totp_disable_sync, username)


async def db_store(recipient, payload_dict, msg_id=None) -> str:
    """Async entry point for the durable offline queue — the ONLY caller of
    _db_store_sync(). Serializes payload_dict and measures its exact UTF-8
    byte size ONCE here, reused both for the cheap pre-executor
    OFFLINE_STORE_GLOBAL_LIMIT check below and for the real write, so the
    two can never disagree about size (same split as anon_message's own
    delivery_json/pending_size, S6-30).

    Returns the exact status _db_store_sync() (or the pre-executor budget
    check) produced — see that function's own comment for the full list of
    possible statuses. Every caller MUST treat only "STORED"/"DUPLICATE" as
    genuine durable success; every other status means the message is NOT
    queued and the sender must not be told otherwise (see message/
    session_init's own critical-ACK-rule comment).

    recipient/msg_id are validated FIRST, before global_offline_store_rate_ok(),
    json.dumps(), or the executor hop (external review 2026-09-05, S6-42) —
    a malformed recipient/msg_id can never legitimately store anyway (every
    real recipient is an is_valid_fingerprint() shape; see
    OFFLINE_MSG_ID_MAX_LEN's own comment), so rejecting it here for free
    means it consumes neither the aggregate write-attempt budget nor any
    executor/SQLite work — the same "reject before paying for the check"
    posture PENDING_MESSAGE_MAX_BYTES already has via TOO_LARGE. Every
    caller of this function is expected to have already rejected an invalid
    `to` at the handler layer (S6-42) — these are last-line defense-in-depth,
    not the primary control."""
    if not is_valid_fingerprint(recipient):
        return "INVALID_RECIPIENT"
    if not is_valid_offline_msg_id(msg_id):
        return "INVALID_MSG_ID"
    if not global_offline_store_rate_ok():
        return "RATE_LIMITED"
    payload_json  = json.dumps(payload_dict)
    payload_bytes = len(payload_json.encode("utf-8"))
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_store_sync, recipient, payload_json, payload_bytes, msg_id)


async def db_peek_pending(recipient, limit):
    """Async entry point for _db_peek_pending_sync() (S6-55) — the ONLY
    read side of the reconnect flush loop. See that function's own comment
    for the read-only/no-mutation guarantee."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_peek_pending_sync, recipient, limit)


async def db_delete_pending_row(recipient, row_id):
    """Async entry point for _db_delete_pending_row_sync() (S6-55) — the
    ONLY way a durable pending_messages row is ever removed after a
    successful websocket handoff. Call this ONLY once send_safe() for this
    exact row's payload has returned True — see the reconnect flush loop's
    own comment for why that ordering is the entire point of this patch."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_delete_pending_row_sync, recipient, row_id)


async def db_store_channel_post(channel_id, post) -> str:
    """Async entry point for durable channel-post storage (S6-47) — the ONLY
    caller of _db_store_channel_post_sync(). Computes storage_bytes ONCE
    here (exact UTF-8 byte count of every attacker-controlled variable-size
    field that ends up in a channel_posts row: channel_id, post_id, text,
    author_id, author_name, image_data), reused both for the cheap
    pre-executor CHANNEL_POST_GLOBAL_LIMIT check below and the real write —
    same split as db_store()'s own payload_bytes (S6-31).

    channel_id/post_id are validated FIRST, before channel_post_global_rate_ok()
    or the executor hop — every legitimate caller already validated them at
    the handler layer; this is last-line defense-in-depth only, same "reject
    before paying for the check" posture db_store() uses for S6-42's
    INVALID_RECIPIENT/INVALID_MSG_ID."""
    if not is_valid_channel_id(channel_id):
        return "INVALID_CHANNEL_ID"
    if not is_valid_channel_post_id(post.get("post_id")):
        return "INVALID_POST_ID"
    if not channel_post_global_rate_ok():
        return "RATE_LIMITED"
    storage_bytes = (
        len(channel_id.encode("utf-8")) +
        len(post["post_id"].encode("utf-8")) +
        len(post.get("text", "").encode("utf-8")) +
        len(post["author_id"].encode("utf-8")) +
        len(post.get("author_name", "").encode("utf-8")) +
        len(post.get("image_data", "").encode("utf-8"))
    )
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, _db_store_channel_post_sync, channel_id, post, storage_bytes
    )


async def _pending_messages_watchdog_tick():
    """One full TTL sweep of pending_messages, factored out of the
    `while True: sleep` wrapper — same split as mailbox_watchdog()/
    _token_pending_watchdog_tick() (external review 2026-09-04, S6-31): lets
    tests drive exactly one sweep directly, without faking out
    asyncio.sleep() globally. Runs in bounded
    PENDING_MESSAGES_CLEANUP_BATCH_SIZE-row batches, each its own short
    BEGIN IMMEDIATE transaction, rather than one unbounded DELETE — a huge
    expired backlog would otherwise hold the SQLite write lock for an
    unbounded stretch, blocking every db_store()/db_flush() in the
    meantime."""
    loop = asyncio.get_event_loop()
    total_cleaned = 0
    while True:
        now = time.time()
        cleaned = await loop.run_in_executor(
            None, _pending_messages_cleanup_batch_sync, now, PENDING_MESSAGES_CLEANUP_BATCH_SIZE
        )
        total_cleaned += cleaned
        if cleaned < PENDING_MESSAGES_CLEANUP_BATCH_SIZE:
            break
    if total_cleaned:
        print(f"[WATCHDOG] pending_messages: {total_cleaned} устаревших "
              f"(>{MSG_TTL_SEC // 86400}д) записей удалено")


async def pending_messages_watchdog():
    while True:
        await asyncio.sleep(PENDING_MESSAGES_CLEANUP_INTERVAL_SEC)
        await _pending_messages_watchdog_tick()


def _db_save_bundle_sync(username, bundle_data):
    """Persist prekey bundle to SQLite so it survives server restarts.

    Raises on failure instead of swallowing the exception (external review
    2026-09-04) — this used to catch-and-print, safe only as long as every
    caller fired it via `asyncio.create_task()` and never checked the
    result. Now `store_prekey_bundle()` awaits this directly and only syncs
    the RAM cache after it returns — a silently-swallowed failure here
    would otherwise report "stored" while nothing durable actually
    happened, exactly the RAM/DB divergence this whole fix exists to
    close."""
    with db_connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO prekey_bundles_db (username, bundle, updated_at) VALUES (?, ?, ?)",
            (username, json.dumps(bundle_data), time.time())
        )
        conn.commit()


def _db_load_bundles_sync():
    """Load all prekey bundles from SQLite into memory on startup.

    Needs no special handling for the durable-OPK-consumption fix (external
    review 2026-09-04) — `_db_consume_prekey_opk_sync()` mutates
    `prekey_bundles_db` directly and commits before ever reporting an OPK
    as consumed, so whatever this reads at startup already reflects every
    OPK actually consumed before a crash/restart, same as any other
    already-committed row. There is no separate "pending consumption"
    state to reconcile."""
    result = {}
    try:
        with db_connect() as conn:
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


def _db_consume_prekey_opk_sync(target: str):
    """Atomically pops exactly one OPK from `target`'s canonical prekey
    bundle directly in SQLite (external review 2026-09-04) — the durable
    consumption operation invariant #39 requires every OPK-serving path to
    share. ONE `BEGIN IMMEDIATE` transaction covers the SELECT, the JSON
    parse, `opks.pop(0)`, and the UPDATE writing the mutated bundle back —
    a caller only ever learns an OPK was consumed (return value's
    `used_opk` is not None) once that transaction has actually committed.
    There is no window where an OPK could be reported to a requester
    before its removal from the available pool is durable.

    Handles both bundle shapes that can be on disk: canonical (wrapped
    `{"bundle": {...}, "updated_at": ...}`, written by
    `store_prekey_bundle()`) and a raw legacy shape (the X3DH bundle dict
    itself, `opks` at the top level) that could still be sitting in
    `prekey_bundles_db` for an account that hasn't reconnected since
    `store_prekey_bundle()` became the sole writer — it self-heals to
    canonical the next time that account sends `register_bundle`/
    `publish_prekey_bundle`, nothing here needs to force that migration.

    Returns `(updated_bundle_data, used_opk, remaining_count)`:
      updated_bundle_data — the row's full parsed JSON (same shape it was
                             stored in), mutated if an OPK was popped, or
                             `None` if no row exists for `target` at all.
      used_opk             — the popped OPK dict, or `None` if the row
                             exists but has no OPKs left (or no `opks` at
                             all).
      remaining_count       — OPKs left after this consumption (0 if there
                             were never any, or the row doesn't exist).

    On any DB failure: rolls back and RE-RAISES — never returns as if an
    OPK was consumed when the write didn't actually commit."""
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT bundle FROM prekey_bundles_db WHERE username = ?",
                (target,)
            ).fetchone()
            if row is None:
                conn.rollback()
                return None, None, 0

            try:
                bundle_data = json.loads(row[0])
            except Exception:
                conn.rollback()
                return None, None, 0

            if isinstance(bundle_data, dict) and isinstance(bundle_data.get("bundle"), dict):
                inner = bundle_data["bundle"]
            elif isinstance(bundle_data, dict):
                inner = bundle_data  # raw legacy shape — opks at the top level
            else:
                conn.rollback()
                return bundle_data, None, 0

            if not inner.get("opks"):
                conn.rollback()
                return bundle_data, None, 0

            used_opk  = inner["opks"].pop(0)
            remaining = len(inner["opks"])

            conn.execute(
                "UPDATE prekey_bundles_db SET bundle = ?, updated_at = ? WHERE username = ?",
                (json.dumps(bundle_data), time.time(), target)
            )
            conn.commit()
            return bundle_data, used_opk, remaining
        except Exception:
            conn.rollback()
            raise


async def db_consume_prekey_opk(target: str):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _db_consume_prekey_opk_sync, target)


async def store_prekey_bundle(username: str, bundle) -> bool:
    """The single canonical prekey-bundle admission path (external review
    2026-09-04) — both the legacy `register_bundle` message type (still
    sent by Android, unconditionally, on every connect — see its own
    comment) and the canonical `publish_prekey_bundle` (Desktop, and
    Android's own OPK-replenishment path) now call this instead of each
    maintaining its own storage shape.

    Originally fixed to agree on ONE shape (`register_bundle` used to store
    the bundle RAW while `publish_prekey_bundle` wrapped it — see
    KNOWN_SECURITY_ISSUES.md S6-25 for that history). Tightened further the
    same review pass that added durable OPK consumption (S6-26,
    SECURITY_INVARIANTS.md #39): this used to update the RAM cache FIRST
    and merely `asyncio.create_task()` the durable SQLite write afterward —
    a crash between those two steps left `prekey_bundles[username]`
    (RAM) disagreeing with `prekey_bundles_db` (disk) until the next
    publish, and, more importantly, raced `consume_prekey_bundle_for_serve()`
    consuming an OPK for the SAME target with no ordering guarantee between
    the two. Now both share `prekey_mutation_guard(username)` — the same
    narrow, per-target, self-pruning lock OPK consumption uses (S6-35) —
    and this function writes durably (awaited) BEFORE ever touching the RAM
    cache, never the reverse; the two operations can never interleave for
    the same target, and a concurrent republish can never be silently
    overwritten by a stale post-consumption save (or vice versa) racing it.

    Returns False (no-op, nothing stored) if `bundle` fails basic shape
    validation — callers are still responsible for their own size check
    (MAX_BUNDLE_SIZE_BYTES) before calling this, since that check needs the
    raw JSON string form they already have to hand. `username` here is
    always the CALLING connection's own proven identity (never an
    arbitrary attacker-supplied string the way `consume_prekey_bundle_for_
    serve()`'s `target` can be), so this function itself does not
    additionally validate it as a canonical fingerprint — see
    is_valid_fingerprint()'s own comment for where that validation actually
    needs to happen instead."""
    if not username or not bundle or not isinstance(bundle, dict):
        return False
    bundle_data = {"bundle": bundle, "updated_at": time.time()}
    async with prekey_mutation_guard(username):
        # Identical-bundle skip — optimization only, external review
        # 2026-09-04, S6-28. NOT a substitute for either rate limiter
        # above (both must still reject an over-quota caller before this
        # function is ever reached, regardless of what it would have done)
        # — this only avoids a redundant SQLite UPDATE/REPLACE for a
        # request that would have changed nothing, e.g. register_bundle
        # re-sending an unchanged bundle on every Android reconnect.
        # Compared against the RAM cache, which is always in sync with
        # disk immediately after any successful store under this same
        # per-target lock — see this function's own comment on that
        # DB-first-then-RAM ordering.
        async with lock:
            existing = prekey_bundles.get(username)
        if isinstance(existing, dict) and existing.get("bundle") == bundle:
            return True
        # DB write first, awaited — no fire-and-forget create_task() here.
        # If this raises, we return before ever touching prekey_bundles,
        # so RAM and disk can't diverge (see this function's own comment).
        await db_save_bundle(username, bundle_data)
        async with lock:
            prekey_bundles[username] = bundle_data
    return True


async def consume_prekey_bundle_for_serve(target: str, requester_scope: str):
    """Canonical, durable OPK-consumption path for EVERY prekey-serving
    caller (external review 2026-09-04, SECURITY_INVARIANTS.md #39) —
    `get_prekey_bundle` and the incoming `federated_get_bundle` handler
    both call this instead of each mutating
    `prekey_bundles[target]["bundle"]["opks"]` directly under the global
    `lock`. Fail-closed rule this enforces end to end: an OPK is included
    in a response ONLY after the SQLite COMMIT removing it from the
    available pool has already succeeded — never the reverse order, and
    never merely "queued to be saved."

    Locking, in order:
      1. `prekey_mutation_guard(target)` — narrow, per-target,
         DB-awaits-allowed, self-pruning lock (S6-35). Serializes
         concurrent consumption attempts AND a concurrent
         `store_prekey_bundle()` publish for this SAME target (same
         underlying lock instance), so the two operations can never
         interleave for one target — a fresh republish can't be silently
         clobbered by a stale post-consumption RAM write, and a
         consumption in flight can't be resurrected by a republish landing
         mid-transaction. Never blocks any OTHER target's traffic, or the
         rest of the server. Entered BEFORE this function knows whether
         `target` is even a real account — see is_valid_fingerprint()'s
         own comment for why every CALLER of this function is required to
         validate `target` first, so this lock is only ever acquired for
         something that at least looks like a real fingerprint.
      2. AFTER the DB transaction has already committed, briefly acquire
         the server-wide `lock` just long enough to sync the RAM cache
         (`prekey_bundles[target]`) to match reality — invariant #34
         forbids awaiting a DB call while holding that lock, so DB-first-
         then-lock-protected-RAM-sync-with-no-await-inside is the only
         correct ordering.
    No network `await` (`send_safe`, etc.) ever happens while holding
    either lock — the OPK_LOW_WATERMARK republish nudge is scheduled only
    after both locks are released.

    OPK-issuance abuse guards (external review 2026-09-04, S6-36) —
    `requester_scope` is `username` for a local caller, `"fed:" + ip` for
    an incoming federation peer (never put on the wire; the federation
    identity is only shared-secret/IP scoped, not a cryptographic peer
    identity, so this is a best-effort fairness key, not an identity
    claim — the per-target/global budgets below are the real backstop if a
    peer reconnects under a new source address). Evaluated only AFTER
    peeking the RAM cache (safe: `prekey_mutation_guard(target)` is held
    for this whole span, so nothing else can mutate `prekey_bundles[target]`
    concurrently) and confirming a real bundle with an available OPK
    exists — a nonexistent target, or one whose pool is already empty,
    never creates any guard state and never reaches the durable consume
    below (see opk_pair_last_issued's/opk_target_window's own comments).
    If ANY guard denies the request, this returns the otherwise-normal
    bundle with `opks: []` — never `None`, never a distinguishable error,
    and no SQLite mutation — so the existing no-OPK X3DH fallback remains
    available. This is abuse containment, not a new protocol failure mode.

    Returns `(bundle_to_send, remaining_count)`: `bundle_to_send` is a
    dict with `opks` set to `[used_opk]` (or `[]` if none was available or
    issuance was denied by a guard), ready for the caller to attach
    `bootstrap_token`/`revoked` and send. Returns `(None, 0)` if `target`
    has no bundle at all."""
    async with prekey_mutation_guard(target):
        async with lock:
            existing = prekey_bundles.get(target)

        if existing is None:
            return None, 0

        if isinstance(existing, dict) and isinstance(existing.get("bundle"), dict):
            existing_inner = existing["bundle"]
        elif isinstance(existing, dict):
            existing_inner = existing
        else:
            return None, 0
        existing_opks = existing_inner.get("opks") or []

        if not existing_opks:
            # Real bundle, but nothing to issue — never reaches the guards
            # below, so an empty-pool target never accumulates limiter
            # state just from being repeatedly (and harmlessly) polled.
            bundle_to_send = dict(existing_inner)
            bundle_to_send["opks"] = []
            return bundle_to_send, 0

        now = time.time()
        _opk_pair_cleanup(now)
        if (opk_pair_cooldown_active(requester_scope, target, now)
                or not opk_target_budget_ok(target, now)
                or not opk_global_budget_ok(now)):
            # Denied by a guard — normal bundle, opks=[], no DB mutation,
            # no pair-cooldown state recorded (see this function's own
            # comment). A retry whose first response was lost therefore
            # falls back to the no-OPK X3DH path instead of ever re-serving
            # the same one-time key.
            bundle_to_send = dict(existing_inner)
            bundle_to_send["opks"] = []
            return bundle_to_send, len(existing_opks)

        updated_bundle_data, used_opk, remaining = await db_consume_prekey_opk(target)

        if updated_bundle_data is None:
            return None, 0

        if used_opk is not None:
            # Only after successful durable consumption — see this
            # function's own comment and opk_record_pair_issuance()'s.
            opk_record_pair_issuance(requester_scope, target, now)

        async with lock:
            # Sync RAM to the now-durable state — never the reverse. See
            # this function's own comment on why a concurrent
            # store_prekey_bundle() for this exact target can't race this.
            prekey_bundles[target] = updated_bundle_data

    # Outside BOTH locks — network I/O must never happen while holding
    # either (same reasoning as invariant #34, extended to this narrower
    # lock too).
    if used_opk is not None and remaining < OPK_LOW_WATERMARK:
        async with lock:
            target_ws = clients.get(target, {}).get("ws")
        if target_ws:
            asyncio.create_task(send_safe(target_ws, json.dumps({"type": "prekey_bundle_request"})))
            print(f"[PREKEY] OPK на исходе у {target} (осталось {remaining})")

    if isinstance(updated_bundle_data, dict) and isinstance(updated_bundle_data.get("bundle"), dict):
        bundle_to_send = dict(updated_bundle_data["bundle"])
    elif isinstance(updated_bundle_data, dict):
        bundle_to_send = dict(updated_bundle_data)
    else:
        bundle_to_send = {}
    bundle_to_send["opks"] = [used_opk] if used_opk else []

    return bundle_to_send, remaining


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


# Dedicated federation-forwarding protocol surface (external review
# 2026-09-04, S6-38) — NOT the same trust surface as ALLOWED_TYPES.
# ALLOWED_TYPES describes what an authenticated CLIENT may send to its OWN
# server; federated_forward is what one federation SERVER is willing to
# relay to another on behalf of ITS OWN clients, a much narrower set. Before
# this fix, an authenticated federation peer could put an ARBITRARY
# `payload["type"]` inside a federated_forward frame — S6-34 bounded and
# rate-limited the OUTER envelope, but the inner payload was still handed
# straight to a local client (`send_safe`) or the offline queue
# (`db_store`) with no check that this server would ever have produced that
# payload type through federation itself. A compromised/malicious peer
# could inject `session_conflict`, `totp_setup_ok`, `identity_revoked`,
# `prekey_bundle_response`, `subscribe_tokens_result`, or any other
# privileged/control client-protocol message this way.
#
# Derived from EVERY current forward_to_peers() call site in this file
# (grepped, not assumed) — each entry below has a real, currently-live
# producer:
#   read                    — "read" handler
#   delivered               — "delivered" handler
#   typing                  — "typing" handler
#   edit                    — "edit" handler
#   session_init            — "session_init" handler
#   message                 — "message" handler
#   reaction                — "reaction" handler
#   group_reaction          — "group_reaction" handler
#   voice                   — "voice" handler
#   group_create            — "group_create" handler
#   group_message           — "group_message" handler
#   group_member_removed    — "group_member_removed" handler
#   group_member_added      — "group_member_added" handler
#   group_key_rotation      — "group_key_rotation" handler
#   group_invite_accepted   — "group_invite_accepted" handler
#   message_delete          — "message_delete"/"disappear_timer" relay
#   disappear_timer         — "message_delete"/"disappear_timer" relay
#   group_message_delete    — "group_message_delete" relay
#
# Deliberately does NOT include (no current forward_to_peers() producer for
# any of these, even though several are individually plausible-sounding):
# session_conflict, identity_revoked/identity_revoked_ack, any totp_* type,
# any device-auth/control response, register/register_bundle, prekey
# publish/get control messages, subscribe/unsubscribe token control,
# anon_delivery_ack(_ok), mailbox control, federation protocol messages
# themselves (peer_announce/peer_roster/federated_get_bundle/
# federated_bundle_response/federated_forward itself), challenge/handshake
# messages, or any other current/future ALLOWED_TYPES entry. Adding a NEW
# federated payload type later requires deliberately adding it here — this
# is intentionally an allowlist, not a denylist, so a forgotten exclusion
# can never silently become forwardable.
FEDERATED_FORWARD_ALLOWED_TYPES = frozenset({
    "read",
    "delivered",
    "typing",
    "edit",
    "session_init",
    "message",
    "reaction",
    "group_reaction",
    "voice",
    "group_create",
    "group_message",
    "group_member_removed",
    "group_member_added",
    "group_key_rotation",
    "group_invite_accepted",
    "message_delete",
    "disappear_timer",
    "group_message_delete",
})


def validate_federated_forward_payload(payload) -> bool:
    """Canonical incoming/outgoing federated_forward payload check (S6-38).
    Every currently-federated payload type above has its `from` set
    server-side by the ORIGINATING server to the connection's own proven
    fingerprint before forward_to_peers() is ever called (grepped every
    call site — each constructs `"from": username` or mutates
    `message["from"] = username` from the authenticated sender's own
    identity, never client-supplied) — so `is_valid_fingerprint(sender)`
    is a meaningful shape check for all of them, no per-type exception
    needed.

    Important limitation this does NOT solve: a canonical-shaped `from`
    only proves SYNTAX, not origin. With today's shared federation secret
    and no per-user origin signature at the federation layer, this server
    cannot cryptographically prove the sending peer actually owns or
    serves that fingerprint — a compromised/malicious peer can still lie
    about `from` for an otherwise-ALLOWED type. Closing that requires
    cryptographic remote-user/server ownership binding or another
    federation-origin design; out of scope for this patch (see
    SECURITY_INVARIANTS.md #51's own comment)."""
    if not isinstance(payload, dict):
        return False
    if payload.get("type") not in FEDERATED_FORWARD_ALLOWED_TYPES:
        return False
    if not is_valid_fingerprint(payload.get("from")):
        return False
    return True


async def forward_to_peers(to: str, payload: dict) -> bool:
    """Forward a message payload to all connected federation peers.
    Returns True if at least one peer received the message.

    Outbound defense-in-depth (external review 2026-09-04, S6-38) — the
    SAME allowlist/shape check the incoming handler enforces on a peer's
    federated_forward is enforced here too, on OUR OWN outbound traffic.
    This is deliberately redundant with every current call site already
    only ever passing an allowed type: the point is that a FUTURE local
    handler that accidentally calls this function with a local-only
    privileged/control payload (a copy-paste of some other forward call,
    say) fails closed immediately, rather than silently leaking a
    control message to every connected peer until someone notices. Keeps
    the outbound and inbound federation surfaces from ever drifting
    apart."""
    if not is_valid_fingerprint(to):
        print(f"[FEDERATION] forward_to_peers: отказ — невалидный to={to!r} (программная ошибка вызывающего кода)")
        return False
    if not validate_federated_forward_payload(payload):
        bad_type = payload.get("type") if isinstance(payload, dict) else type(payload).__name__
        print(f"[FEDERATION] forward_to_peers: отказ — payload не прошёл валидацию (type={bad_type!r}, "
              f"программная/протокольная ошибка вызывающего кода)")
        return False
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
    # Defense-in-depth (external review 2026-09-04, S6-35) — the local
    # caller (get_prekey_bundle's handler) already validates `target`
    # before ever reaching here, so this should be unreachable with an
    # invalid value in practice; refusing it here too means this function
    # can never itself become a path that creates a `fed_pending` future or
    # sends attacker-supplied garbage out to every connected peer, even if
    # some future caller forgets the earlier check.
    if not is_valid_fingerprint(target):
        return None
    if not federation_ws:
        return None
    # S6-46: hard process-wide ceiling — see FED_PENDING_MAX's own comment.
    # Rejected here means no entry is created and no request is sent to any
    # peer at all, same "reject before doing any work" posture as every
    # other cap in this file.
    if len(fed_pending) >= FED_PENDING_MAX:
        print(f"[SECURITY] federated_get_bundle: fed_pending на пределе ({FED_PENDING_MAX}) — запрос отклонён")
        return None
    req_id = secrets.token_hex(8)
    loop   = asyncio.get_event_loop()
    fut    = loop.create_future()
    fed_pending[req_id] = {"future": fut, "target": target, "created_at": time.time()}
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


async def handle_federation_response(msg: dict, peer_url: str = ""):
    """Handle a response message that arrives on an outgoing federation connection.

    `peer_url` (external review 2026-09-05, S6-46) is the URL of the outgoing
    connection this message arrived on — passed in by
    federation_connect_to_peer()'s own read loop, used here only for bounded
    security logging (which peer sent a rejected response). This is NOT an
    authenticated "peer X owns fingerprint Y" mapping — federation currently
    has no such authority system (see the residual-limitation note below and
    KNOWN_SECURITY_ISSUES.md S6-46) — so it must never be used as a trust
    input, only a diagnostic one.
    """
    msg_type = msg.get("type")

    if msg_type == "federated_bundle_response":
        # S6-46: full response-poisoning fix. Previously: ANY connected peer
        # that had merely seen our own outgoing federated_get_bundle request
        # (which necessarily contains req_id) could resolve the pending
        # Future with arbitrary bundle content, first-response-wins, with no
        # check that the bundle actually belonged to the target we asked
        # about. Every gate below can only ever narrow what already-pending
        # state resolves to — none of them can CREATE a fed_pending entry,
        # so a malformed/random req_id here is an O(1) dict-miss reject.
        req_id = msg.get("req_id")
        if not is_valid_fed_req_id(req_id):
            return
        pending = fed_pending.get(req_id)
        if pending is None:
            return
        fut = pending["future"]
        if fut.done():
            return

        bundle = msg.get("bundle")
        # Легитимный "у меня нет такого пользователя" ответ — ждём, не
        # резолвим и не отменяем: ответ от "правильного" пира не должен быть
        # вытеснен null-ответом от пира, у которого просто нет этого bundle.
        if bundle is None:
            return

        # Correlation (defense-in-depth, NOT authentication — see this
        # function's own docstring and STEP 3's framing in
        # KNOWN_SECURITY_ISSUES.md S6-46): the response's claimed target
        # must match the target THIS pending lookup was created for, per
        # OUR OWN records, never per something the peer supplied. Any peer
        # that received our federated_get_bundle already knows `target`
        # too, so an attacker can trivially echo the right value here — the
        # actual proof is the identity-key fingerprint check further down.
        resp_target = msg.get("target")
        if not is_valid_fingerprint(resp_target) or resp_target != pending["target"]:
            print(f"[SECURITY] federated_bundle_response: target не совпадает с ожидаемым "
                  f"(req_id={req_id}, peer={peer_url}) — ответ проигнорирован")
            return

        if not isinstance(bundle, dict):
            print(f"[SECURITY] federated_bundle_response: bundle не dict (peer={peer_url})")
            return
        # Bound BEFORE any base64/DER/crypto work, same byte-exact ceiling a
        # local user's own register_bundle/publish_prekey_bundle is held to
        # (MAX_BUNDLE_SIZE_BYTES) — a malicious peer's response must never
        # buy a bigger budget than a genuine local publisher gets. Exact
        # UTF-8 byte count, same semantics used at every other
        # MAX_BUNDLE_SIZE_BYTES call site in this file.
        serialized = json.dumps(bundle, separators=(",", ":"))
        if len(serialized.encode("utf-8")) > MAX_BUNDLE_SIZE_BYTES:
            print(f"[SECURITY] federated_bundle_response: bundle превышает MAX_BUNDLE_SIZE_BYTES "
                  f"(peer={peer_url})")
            return

        # Cryptographic identity binding — the actual proof this bundle
        # belongs to who we asked for. Uses the exact same canonical
        # decoder (S6-45) and fingerprint computation (sha256(DER)[:8]
        # hex().upper()) register() uses for every real account, so a
        # bundle can only resolve this lookup if its OWN identity public
        # key derives to the SAME fingerprint as pending["target"] — a
        # peer cannot forge this by echoing `target`, only by actually
        # possessing target-bound public key material (see the residual-
        # limitation note in KNOWN_SECURITY_ISSUES.md S6-46 for what that
        # still doesn't prove about peer authority).
        decoded = decode_identity_public_key(bundle.get("identity_key"))
        if decoded is None:
            print(f"[SECURITY] federated_bundle_response: невалидный identity_key (peer={peer_url})")
            return
        key_bytes, _ = decoded
        computed_fingerprint = hashlib.sha256(key_bytes).digest()[:8].hex().upper()
        if computed_fingerprint != pending["target"]:
            print(f"[SECURITY] federated_bundle_response: identity-key fingerprint не совпадает "
                  f"с target (req_id={req_id}, peer={peer_url}) — возможная попытка подмены bundle")
            return

        fut.set_result(bundle)

    # Gossip: получили ростер от пира — подключаемся ко всем новым.
    # Input hardened against an unbounded/malicious roster (external review
    # 2026-09-04, alongside start_dynamic_peer()'s own comment): container
    # shape checked before iterating at all, the list itself is truncated
    # to MAX_ROSTER_PEERS BEFORE the loop body runs (a single message can't
    # introduce more than that many candidates, regardless of how many it
    # actually contains), and each entry is bounds-checked
    # (MAX_PEER_URL_LEN) and type-checked before any string method touches
    # it. start_dynamic_peer() itself enforces the total-count cap
    # (MAX_DYNAMIC_PEERS) and de-duplication — this loop no longer touches
    # dynamic_peer_urls/dynamic_peer_tasks directly.
    elif msg_type == "peer_roster":
        peers = msg.get("peers", [])
        if not isinstance(peers, list):
            return
        for raw_url in peers[:MAX_ROSTER_PEERS]:
            if not isinstance(raw_url, str):
                continue
            if len(raw_url) > MAX_PEER_URL_LEN:
                continue
            url = raw_url.strip()
            if not url or url == SERVER_URL:
                continue
            # Three fail-closed gates before any DNS/TCP/TLS activity at all
            # (external review 2026-09-04, SSRF/egress — see
            # federation_host_allowed()'s own comment for the residual DNS
            # TOCTOU/rebinding gap this does NOT close): (1) strict URL
            # syntax — wss:// scheme, real hostname, no embedded
            # credentials; (2) resolve the hostname and check every
            # returned address against destination-address policy —
            # otherwise a gossiped internal hostname/IP (LAN admin panel,
            # cloud metadata endpoint, this-machine-localhost) would get
            # this server to open an outbound TLS connection to it, which
            # wss://+CERT_REQUIRED alone does nothing to prevent (the
            # malicious "peer" IS the destination in that scenario, not an
            # interceptor). Only once both pass does start_dynamic_peer()
            # (gate 3: count cap + de-dup) even run.
            parsed = parse_federation_url(url)
            if parsed is None:
                print(f"[SECURITY] peer_roster: отклонён невалидный URL пира: {url}")
                continue
            host, port = parsed
            if not await federation_host_allowed(host, port):
                print(f"[SECURITY] peer_roster: отклонён egress policy для {url}")
                continue
            if start_dynamic_peer(url):
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
            if len(raw_msg) > FEDERATION_MAX_PACKET_SIZE_BYTES:
                break
            try:
                msg = json.loads(raw_msg)
            except Exception:
                continue

            # A federation peer is authenticated, not trusted to send
            # well-formed JSON shapes — `json.loads` on a bare string/number/
            # list/etc. succeeds but has no `.get()`, which used to raise
            # AttributeError straight into the OUTER try/except below,
            # tearing down this WHOLE peer connection's loop over one
            # malformed frame (external review 2026-09-04, S6-34). One bad
            # frame is now just skipped.
            if not isinstance(msg, dict):
                continue

            msg_type = msg.get("type")

            # ── Deliver a forwarded message to a local client ─────────────────
            if msg_type == "federated_forward":
                # Rate-limited BEFORE any validation/dedup/DB/client-send
                # work below — applies to EVERY federated_forward frame,
                # including malformed ones and ones with no msg_id at all
                # (which can't use dedup and so have no other bound on
                # repeat-send cost) — see both functions' own comments.
                if not fed_forward_rate_per_ip_ok(ip):
                    continue
                if not fed_forward_rate_global_ok():
                    continue

                to      = msg.get("to")
                payload = msg.get("payload")
                if not isinstance(to, str) or not to or len(to) > FED_MAX_TO_LEN:
                    continue
                if not isinstance(payload, dict):
                    continue

                # Canonical destination + allowlisted-payload validation
                # (external review 2026-09-04, S6-38) — checked AFTER the
                # cheap outer rate/shape checks above, BEFORE msg_id shape
                # validation and (further below) the dedup reservation/
                # local send/db_store, so a semantically-invalid frame never
                # reserves dedup state, never reaches send_safe()/db_store(),
                # and never terminates this peer connection — it's simply
                # dropped, same as any other malformed frame in this loop.
                # `to` must be a canonical LOCAL-account fingerprint, not
                # merely length-bounded, so a junk recipient "namespace"
                # never reaches clients[]/SQLite. `payload` must be one of
                # FEDERATED_FORWARD_ALLOWED_TYPES with a canonical `from` —
                # see validate_federated_forward_payload()'s own comment for
                # why this is a NARROWER allowlist than ALLOWED_TYPES (the
                # client-facing surface), and for the residual `from`-
                # spoofing limitation this does NOT solve.
                if not is_valid_fingerprint(to):
                    continue
                if not validate_federated_forward_payload(payload):
                    continue

                # Byte/resource admission for the inner payload (S6-62) —
                # serialized and accounted ONCE here, reused for every check
                # below, BEFORE dedup reservation, clients lookup, send_safe,
                # or db_store — an oversized/over-budget payload costs
                # exactly as much as malformed input: none of those. The
                # per-type count limiters above (fed_forward_rate_per_ip_ok/
                # fed_forward_rate_global_ok) are unchanged; these are
                # ADDITIONAL byte-shaped budgets layered on top, same
                # two-dimension posture as S6-51/S6-59's own count+byte
                # pairing. Recipient budget only after `to` has already
                # passed is_valid_fingerprint() just above — never keyed by
                # an attacker-minted string.
                fwd_payload_json  = json.dumps(payload, separators=(",", ":"))
                fwd_payload_bytes = len(fwd_payload_json.encode("utf-8"))
                if fwd_payload_bytes > FED_FORWARD_MAX_PAYLOAD_BYTES:
                    continue
                if not fed_forward_byte_rate_per_ip_ok(ip, fwd_payload_bytes):
                    continue
                if not fed_forward_byte_rate_global_ok(fwd_payload_bytes):
                    continue
                if not fed_forward_byte_rate_recipient_ok(to, fwd_payload_bytes):
                    continue

                # Per-type chat-control schema binding (S6-53, STEP 9) — a
                # malicious/compromised federation peer could otherwise
                # bypass the LOCAL schema hardening entirely by wrapping an
                # oversized/unrelated-field-stuffed message_delete/
                # disappear_timer/group_message_delete inside an otherwise-
                # ALLOWED federated_forward. Reuses the exact same
                # sanitize_chat_control() field validation the local relay
                # path uses — `from` stays EXACTLY what the peer supplied
                # (already fingerprint-shape-validated by
                # validate_federated_forward_payload() above, never
                # overwritten with a local identity: there is no
                # "authenticated local username" for an incoming federation
                # frame). Dropped here, BEFORE msg_id extraction/dedup
                # reservation below, same "malformed input reserves nothing"
                # posture as everything else in this handler. This does NOT
                # solve validate_federated_forward_payload()'s own
                # documented residual limitation — a canonical-shaped `from`
                # still only proves syntax, not that this peer genuinely
                # owns/serves that fingerprint (S6-38); closing THAT remains
                # out of scope here too.
                if payload.get("type") in ("message_delete", "disappear_timer", "group_message_delete"):
                    payload = sanitize_chat_control(payload.get("type"), payload, payload.get("from"), to)
                    if payload is None:
                        continue

                # Per-type voice schema binding (S6-57, STEP 5) — a
                # malicious/compromised federation peer could otherwise
                # bypass the LOCAL voice_data/signature/voice_id/duration
                # bounds entirely by wrapping an oversized voice payload
                # inside an otherwise-ALLOWED federated_forward. Reuses the
                # exact same sanitize_voice_payload() the local relay path
                # uses — `from` stays EXACTLY what the peer supplied (already
                # fingerprint-shape-validated above), same "no authenticated
                # local username for an incoming federation frame" reasoning
                # as the chat-control dispatch just above. This does NOT
                # additionally bound the whole federated_forward envelope —
                # FEDERATION_MAX_PACKET_SIZE_BYTES (2x MAX_PACKET_SIZE_BYTES)
                # already applies to every federation frame before this point.
                if payload.get("type") == "voice":
                    payload = sanitize_voice_payload(payload, payload.get("from"), to)
                    if payload is None:
                        continue

                # Per-type roster schema binding for group_create (S6-65) —
                # same "a malicious/compromised federation peer could
                # otherwise bypass local hardening" reasoning as the
                # chat-control/voice dispatch just above, applied to
                # members/admins/roster_signature specifically. `from` stays
                # EXACTLY what the peer supplied (already fingerprint-shape-
                # validated by validate_federated_forward_payload() above).
                if payload.get("type") == "group_create":
                    roster = validate_group_roster(payload.get("members"), payload.get("admins"), payload.get("from"))
                    roster_signature = payload.get("roster_signature")
                    if roster is None or not is_valid_chat_control_signature(roster_signature):
                        continue
                    members, admins = roster
                    payload = dict(payload)
                    payload["members"], payload["admins"], payload["roster_signature"] = members, admins, roster_signature

                # msg_id, if present, must be a well-formed, boundedly-sized
                # string BEFORE it's ever used as a delivered_msg_ids/
                # federation_delivery_inflight dict/set key — an unhashable
                # value (list/dict) would raise TypeError there, and an
                # absurdly long string is needless RAM/hash-CPU for a value
                # that's only ever compared for equality (external review
                # 2026-09-04, S6-34). A malformed msg_id rejects the whole
                # frame rather than silently downgrading to "no dedup" — a
                # crafted oversized/malformed id specifically to dodge dedup
                # is exactly the kind of input this validates against.
                raw_msg_id = payload.get("id")
                msg_id = None
                if raw_msg_id is not None:
                    if (not isinstance(raw_msg_id, str) or not raw_msg_id
                            or len(raw_msg_id) > FED_DEDUP_MAX_MSG_ID_LEN):
                        continue
                    msg_id = raw_msg_id

                # Дедупликация: одно и то же сообщение может прийти по
                # нескольким путям меша. Two-phase reserve/handoff/resolve
                # (external review 2026-09-04, S6-34) — see
                # federation_delivery_inflight's own comment for why a
                # SEPARATE in-flight set (not just delivered_msg_ids) is
                # needed to catch a concurrent duplicate arriving on a
                # DIFFERENT peer connection while the first copy is still
                # mid-delivery, and _federation_dedup_cleanup_locked()'s own
                # comment for the O(1)-amortized expiry this replaces an
                # O(N)-per-message full rescan with. Skipped entirely when
                # msg_id is absent — such a payload can never be deduped,
                # only rate-limited (already done above).
                if msg_id is not None:
                    async with federation_dedup_lock:
                        now = time.time()
                        _federation_dedup_cleanup_locked(now)
                        if msg_id in delivered_msg_ids or msg_id in federation_delivery_inflight:
                            continue  # already delivered, or a concurrent duplicate in flight
                        if len(federation_delivery_inflight) >= FED_DEDUP_MAX_INFLIGHT:
                            print(f"[FEDERATION] federated_forward отклонён: "
                                  f"inflight-очередь дедупликации переполнена ({ip})")
                            continue
                        federation_delivery_inflight.add(msg_id)

                # Phase B: the actual handoff, OUTSIDE federation_dedup_lock
                # — send_safe()/db_store() are exactly the network/DB awaits
                # that lock must never be held across (same "no await under
                # this lock" rule as the global `lock`, invariant 34).
                # `success` is what Phase C below uses to decide whether
                # this msg_id is now genuinely, durably deduplicated —
                # reserving it in Phase A did NOT already commit that;
                # reserving only prevented a concurrent duplicate from
                # racing this same attempt.
                success = False
                try:
                    async with lock:
                        recipient = clients.get(to)
                    if recipient:
                        success = await send_safe(recipient["ws"], json.dumps(payload))
                        if success:
                            print(f"[FEDERATION] Доставлено: → {to}")
                    else:
                        # STORED or a genuine DUPLICATE (same recipient+
                        # payload already durably queued) both mean the
                        # message really is present offline — anything else
                        # (FULL/TOO_LARGE/CONFLICT/RATE_LIMITED, S6-31's own
                        # status list) means it is NOT, and must not be
                        # reported as queued, nor durably deduplicated —
                        # doing so would silently drop the message forever
                        # (external review 2026-09-04, S6-34).
                        status = await db_store(to, payload, msg_id)
                        success = status in ("STORED", "DUPLICATE")
                        if success:
                            print(f"[FEDERATION] Очередь: → {to} (офлайн)")
                finally:
                    # Phase C: resolve the reservation — under `try`/
                    # `finally` so a cancellation or an unexpected exception
                    # from send_safe()/db_store() (e.g. a real DB failure,
                    # S6-31's "never swallow" — propagates past this
                    # `finally` to the outer handler, closing just this peer
                    # connection) still releases the in-flight reservation
                    # rather than leaking it forever.
                    if msg_id is not None:
                        async with federation_dedup_lock:
                            federation_delivery_inflight.discard(msg_id)
                            if success:
                                # Only a message that's ACTUALLY somewhere a
                                # future subscribe/fetch can find it becomes
                                # durably deduplicated — a failed attempt
                                # must remain retryable, not suppressed for
                                # FED_DEDUP_TTL_SEC on a message that was
                                # never actually delivered anywhere.
                                now2 = time.time()
                                _federation_dedup_cleanup_locked(now2)
                                delivered_msg_ids[msg_id] = now2
                                while len(delivered_msg_ids) > FED_DEDUP_MAX_IDS:
                                    # Evicting the oldest tombstone under
                                    # pressure is an accepted, bounded
                                    # trade-off (external review 2026-09-04,
                                    # S6-34) — may let an unusually old
                                    # duplicate through once in a while, but
                                    # never fails NEW federation traffic just
                                    # because the cache is full, and the rate
                                    # limits above already bound how much
                                    # duplicate work that could cost anyway.
                                    delivered_msg_ids.popitem(last=False)

            # ── Son server announces itself to father ─────────────────────────
            elif msg_type == "peer_announce":
                raw_url = msg.get("url", "")
                if not isinstance(raw_url, str) or len(raw_url) > MAX_PEER_URL_LEN:
                    continue
                url = raw_url.strip()
                if url and url not in dynamic_peer_urls and url not in FEDERATION_PEERS:
                    # Same three fail-closed gates as the peer_roster
                    # handler above — see its comment (external review
                    # 2026-09-04, SSRF/egress) and
                    # federation_host_allowed()'s own comment for the
                    # residual DNS TOCTOU/rebinding gap this does not close.
                    parsed = parse_federation_url(url)
                    if parsed is None:
                        print(f"[SECURITY] peer_announce: отклонён невалидный URL пира: {url}")
                        continue
                    host, port = parsed
                    if not await federation_host_allowed(host, port):
                        print(f"[SECURITY] peer_announce: отклонён egress policy для {url}")
                        continue
                    # start_dynamic_peer() enforces MAX_DYNAMIC_PEERS and
                    # de-duplication, and registers the reconnect Task in
                    # dynamic_peer_tasks so federation_watchdog() can
                    # actually cancel it later (external review 2026-09-04)
                    # — see its own comment.
                    if start_dynamic_peer(url):
                        print(f"[FEDERATION] Новый пир зарегистрирован: {url}")
                        # Gossip: рассылаем новый URL всем остальным пирам
                        asyncio.create_task(broadcast_roster_update(url, skip_ws=websocket))

            # ── Serve a prekey bundle to a requesting peer ────────────────────
            # OPK consumption durable end-to-end (external review
            # 2026-09-04) — this used to pop bundle_data["bundle"]["opks"]
            # directly under the global `lock` with NO persistence at all,
            # unlike the local get_prekey_bundle path (which at least fired
            # a fire-and-forget db_save_bundle()). A federation peer could
            # re-request the same target's bundle after any restart (or
            # simply race two requests) and receive the SAME OPK twice —
            # worse than the local path's crash-window gap, this had no
            # persistence whatsoever. consume_prekey_bundle_for_serve() is
            # the same canonical, durably-committed-before-ever-returned
            # consumption path get_prekey_bundle now uses too — see its own
            # comment and SECURITY_INVARIANTS.md #39.
            elif msg_type == "federated_get_bundle":
                if not fed_bundle_rate_ok(ip):
                    print(f"[FEDERATION] Запрос bundle от {ip} отклонён (rate limit)")
                    continue
                target = msg.get("target")
                req_id = msg.get("req_id")
                # Canonical-fingerprint validation BEFORE consume_prekey_
                # bundle_for_serve() (external review 2026-09-04, S6-35) —
                # that function acquires prekey_mutation_guard(target)
                # before knowing whether target is even real; a peer-
                # controlled garbage target must never reach that lock
                # registry (see is_valid_fingerprint()'s own comment). No
                # response sent either — never echo attacker-supplied
                # invalid target data back into a federation response.
                if not is_valid_fingerprint(target):
                    continue
                # S6-46: req_id shape-checked too, BEFORE it's ever
                # reflected back into federated_bundle_response (and before
                # consume_prekey_bundle_for_serve() potentially burns an
                # OPK for a request we're not going to answer usefully
                # anyway) — see is_valid_fed_req_id()'s own comment.
                if not is_valid_fed_req_id(req_id):
                    continue
                bundle_to_send, _remaining = await consume_prekey_bundle_for_serve(target, "fed:" + ip)
                # `target` echoed back (S6-46) so the ORIGINATING server can
                # correlate this response against the pending lookup it
                # actually created — this is defense-in-depth correlation
                # only, not proof of ownership, since any peer receiving
                # our request already knows `target` too. See
                # handle_federation_response()'s own comment for the
                # cryptographic check that actually matters.
                await send_safe(websocket, json.dumps({
                    "type":   "federated_bundle_response",
                    "req_id": req_id,
                    "target": target,
                    "bundle": bundle_to_send
                }))

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"[FEDERATION] Ошибка входящего пира {ip}: {e}")
    finally:
        incoming_peer_ws.discard(websocket)
        print(f"[FEDERATION] Входящий пир отключился: {ip}")


async def federation_connect_to_peer(url: str, ssl_ctx=None, *, dynamic: bool = False):
    """Maintain a persistent outgoing WebSocket connection to a federation peer.

    dynamic=True (gossip-discovered peers only, via start_dynamic_peer())
    self-terminates once `url` is no longer in dynamic_peer_urls (external
    review 2026-09-04) — a belt-and-suspenders backstop for
    federation_watchdog()'s eviction: even if cancelling this Task via
    dynamic_peer_tasks somehow fails or races, this loop won't reconnect an
    evicted peer on its own next iteration. Static FEDERATION_PEERS
    (dynamic=False, the default) reconnect indefinitely regardless, same as
    before — an operator-configured peer is never auto-evicted."""
    backoff = 5
    while True:
        if dynamic and url not in dynamic_peer_urls:
            print(f"[FEDERATION] {url} больше не в dynamic_peer_urls — прекращаю reconnect-цикл")
            return
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
                        await handle_federation_response(json.loads(raw_msg), url)
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
        # get_decoy_candidates (metadata-protection hardening) — called once
        # per bootstrap attempt alongside prekey_fetch, same order of
        # magnitude ceiling; it hands out identities only, never bundle
        # content or anything that consumes server resources beyond a
        # RAM sample, so it doesn't need its own tighter number.
        "decoy_candidates": 20,
        # Раньше было 100 — легко пробивалось одним видеокружком/файлом
        # (чанки по 120 000 символов, пачками по 5), особенно если
        # соединение падало посреди отправки и клиент начинал заново с
        # первого чанка. Поднято до 500 — тот же порядок, что у уже
        # существующего call_ice (300) для похожей причины (много мелких
        # сообщений на одно действие пользователя), плюс отдельно чинится
        # сам повтор с нуля на клиенте.
        "anon_message": 500, "mailbox_put": 20, "subscribe_tokens": SUBSCRIBE_TOKENS_RATE_LIMIT,
        "channel_create": 5, "channel_post": CHANNEL_POST_RATE_LIMIT, "profile_update": 10,
        # get_key (S6-50) — legacy public-key/avatar lookup, previously
        # unrated entirely. flushQueue() calls it once per queued message
        # whose target's public key isn't cached yet; 30/min is generous for
        # any realistic burst of newly-first-contacted targets after being
        # offline while still bounding abuse.
        "get_key": 30,
        # register_fcm (S6-52) -- Firebase token refresh is rare (rotates on
        # app reinstall/data-clear/token-expiry, not routine use); 10/min is
        # generous relative to any real refresh cadence while bounding a
        # flood. Identical-token re-registration never reaches this bucket
        # at all (see register_fcm's own comment) -- Android's own frequent
        # reconnect-time re-send of its cached token is free.
        "register_fcm": 10,
        "totp_setup": TOTP_SETUP_RATE_LIMIT,
        # One shared bucket for EVERY client-triggerable path that reaches
        # store_prekey_bundle() (external review 2026-09-04) — both
        # register_bundle (legacy, still Android's every-connect call) and
        # publish_prekey_bundle (canonical) now perform a real durable
        # SQLite write via the same function, so they must share ONE
        # logical rate limit, not two independent ones keyed on message
        # type: alternating the two message types against separate buckets
        # would double the allowed write rate, and publish_prekey_bundle
        # previously had no rate limit here at all. See
        # SECURITY_INVARIANTS.md #40. (Replaces the old, now-removed
        # "register_bundle" bucket, which register_bundle alone used to be
        # keyed on.)
        "prekey_publish": 20,
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
        # Refreshed well before its 24h expiry, not on every reconnect —
        # generous ceiling is just abuse-proofing, not the normal rate.
        "request_sender_cert": 10,
        # voice (S6-57) — previously had NO entry here at all (default_limits.get()
        # returned None, so rate_limit_check() short-circuited to True
        # unconditionally). See VOICE_RATE_LIMIT's own comment for why 60/min
        # is generous for genuine usage while the byte budgets alongside it
        # bound aggregate relay cost.
        "voice": VOICE_RATE_LIMIT,
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

def _peek_bootstrap_candidates(target: str):
    """RAM-only candidate lookup — must be called under `lock` (reads
    ws_to_tokens/spent_tokens, same shared state every other lock-protected
    reader touches). Does NOT reserve or resolve anything; see
    pick_bootstrap_token()/db_resolve_bootstrap_token() for the actual
    atomic DB work, which has to happen outside the lock since it's a DB
    call. Returns target's FULL currently RAM-known token list (raw, not
    hashed) — deliberately unfiltered by reservation status (unlike an
    earlier version): db_resolve_bootstrap_token() needs the complete set
    to have any chance of resolving requester's own already-reserved
    token's hash back to its raw value, not just the subset that LOOKS
    free. Still excludes anything already spent — a token can reach SPENT
    (or be revoked, which also marks it spent) without ever going through
    unsubscribe_tokens/disconnect-cleanup pruning it from ws_to_tokens
    first, so this alone isn't redundant with the ws_to_tokens membership
    check, and a spent token could never be anyone's valid reservation
    target anyway."""
    target_data = clients.get(target)
    if not target_data:
        return []
    target_ws = target_data.get("ws")
    owned = ws_to_tokens.get(target_ws)
    if not owned:
        return []
    return [t for t in owned if t not in spent_tokens]


async def pick_bootstrap_token(target: str, requester: str):
    """Hands `requester` one of `target`'s currently-registered anon tokens,
    without consuming it — it stays valid (token_to_ws/known_tokens
    untouched) until actually used in an anon_message, exactly like a token
    shared peer-to-peer via the existing sendAnonTokensTo flow. Lets a fresh
    X3DH handshake's session_init be delivered anonymously instead of
    directly addressed, whether this bundle was fetched directly or as part
    of an anonymous batched fetch (see get_prekey_bundles_batch below).
    Returns None if target is offline, has no available registered tokens,
    requester's existing reservation against target is already IN_FLIGHT,
    or every fresh candidate lost its reservation race (see
    db_resolve_bootstrap_token()'s own comment for the full return-status
    breakdown this collapses to None vs. a real token).

    Made per-requester 2026-09-03 (external review, round 5) — bug found
    live: reservation was durable (see bootstrap_reserved's own comment in
    _db_setup_sync() for that earlier fix) but global — every successful
    call minted a NEW reservation on a DIFFERENT token regardless of
    whether the SAME authenticated requester had already been handed one.
    A single account repeatedly calling get_prekey_bundle(target) (10/min
    under prekey_fetch; get_prekey_bundles_batch multiplies this across
    every target in one call) could reserve target's entire pool — a
    remote DoS against target's ability to receive a bootstrap token from
    anyone else, without the attacker ever sending one real anon_message.
    Now: an existing ACTIVE reservation for (target, requester) is handed
    back again unchanged; an existing IN_FLIGHT one (meaning requester
    genuinely already sent something on it and it hasn't been acked/
    expired yet) yields None rather than a second concurrently-outstanding
    token for the same pair; only with no existing reservation at all does
    this claim a fresh one. Repeated fetches from the same requester now
    look like T1 → T1 → T1 → T1, not T1 → T2 → T3 → T4.

    The RAM-only candidate lookup (_peek_bootstrap_candidates) still
    happens under `lock`; the actual resolution/reservation is a separate
    DB round-trip taken outside it, same pattern as every other lock+DB
    combination in this file.

    Deliberately NOT a timed reservation — no new failure mode, no signal
    to the server about which specific token is "hot" right now. A
    requester's ACTIVE reservation stays exactly theirs (returned again
    unchanged on every subsequent fetch) until the token itself reaches a
    terminal state (see _db_terminalize_anon_token_sync(), called from
    anon_delivery_ack/unsubscribe_tokens/the TTL watchdog) — disconnect
    does not clear it."""
    async with lock:
        candidates = _peek_bootstrap_candidates(target)
    if not candidates:
        return None
    status, token = await db_resolve_bootstrap_token(candidates, target, requester)
    if status in ("existing", "reserved"):
        return token
    # "in_flight" / "unresolvable" / "none" — no token to offer this round.
    return None

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

# ─── S6-49: direct media-chunk relay hardening ─────────────────────────────────
# (external review 2026-09-05) — image_chunk/video_chunk/file_chunk are live
# ALLOWED_TYPES whose handlers did approximately `recipient = clients.get(to)`
# then relayed `message.get("data")` verbatim via send_safe(), with no
# is_valid_fingerprint(to) (S6-42 never touched these three — it only ever
# reached db_store()-adjacent call sites, and these handlers never queue
# offline), no protocol-specific bounds on any field, and no chunk-specific
# rate/byte limit at all — an authenticated client could use this as an
# unrestricted high-bandwidth relay to any online fingerprint, up to
# MAX_PACKET_SIZE_BYTES (6 MiB) per frame, with none of the limits that
# protect ordinary message/call traffic.
#
# Protocol shape confirmed from CURRENT client code (not the old "~120,000
# characters" comment, though it turned out accurate) — grepped both
# clients' sendImage()/sendFile()/sendVideoCircle()/processVideoChunk():
# chunks are `packedData.chunked(120_000)` — exactly 120,000 BASE64
# CHARACTERS per chunk (~90 KB decoded), image_id/video_id/file_id are
# `UUID.randomUUID().toString()` (36 chars), chunk_index/total_chunks are
# plain non-negative ints, signatures are SHA256withECDSA over
# transferId||chunkIndex||chunkData, DER-encoded, base64 (~70-72 raw bytes,
# ~96-100 b64 chars — same order as MAX_IDENTITY_SIGNATURE_B64_LEN, S6-45).
# Neither shipped client currently sends these three bare/direct types in
# practice: sendImage()/sendFile()/sendVideoCircle() all route through
# sendAnonOrDirect(), which ALWAYS delivers via anon_message (sealed, or an
# unsealed-but-still-anon_message-wrapped fallback on Desktop) — never a
# bare top-level image_chunk/video_chunk/file_chunk frame with a literal
# `to`. The three handlers remain live ALLOWED_TYPES regardless, reachable
# by any custom/legacy client addressing a real online fingerprint
# directly, and are hardened here anyway — same "dormant is not deleted"
# posture as S6-47's Channels note.
MEDIA_CHUNK_ID_MAX_LEN         = 128    # UUID.randomUUID().toString() is 36 chars; generous headroom
MEDIA_CHUNK_DATA_MAX_LEN       = 130_000  # 120,000-char chunks + slack, never MAX_PACKET_SIZE_BYTES
MEDIA_CHUNK_SIGNATURE_MAX_LEN  = 256     # mirrors MAX_IDENTITY_SIGNATURE_B64_LEN's own bound
MEDIA_CHUNK_MAX_TOTAL_CHUNKS   = 20_000  # ~1.7 GB decoded at ~90 KB/chunk — generous, still bounded
MEDIA_CHUNK_FILENAME_MAX_LEN   = 512     # file_name/encrypted_file_name, generous for any real name
MEDIA_CHUNK_MAX_DURATION_SEC   = 24 * 3600  # video_chunk's `duration` — sanity bound, not exploitable either way


def _validate_media_chunk_envelope(message: dict, id_field: str):
    """Canonical validator for the common image_chunk/video_chunk/file_chunk
    envelope (S6-49) — these three handlers duplicate almost the identical
    protocol, hardened once here instead of three times. Checked BEFORE
    clients.get()/json.dumps()/send_safe() ever run. Returns
    (to, transfer_id, chunk_index, total_chunks, data, signature) on
    success, None on ANY failure — wrong container types, non-canonical
    `to`, or an out-of-range/oversized field are all rejected the same way,
    never coerced (no int(attacker_value), no silent truncation)."""
    to = message.get("to")
    if not is_valid_fingerprint(to):
        return None
    transfer_id = message.get(id_field)
    if not isinstance(transfer_id, str) or not (1 <= len(transfer_id) <= MEDIA_CHUNK_ID_MAX_LEN):
        return None
    chunk_index = message.get("chunk_index")
    # bool is a subclass of int in Python -- explicitly excluded, same
    # posture as every other integer-shaped field validator in this file.
    if not isinstance(chunk_index, int) or isinstance(chunk_index, bool) or chunk_index < 0:
        return None
    total_chunks = message.get("total_chunks")
    if (not isinstance(total_chunks, int) or isinstance(total_chunks, bool)
            or total_chunks < 1 or total_chunks > MEDIA_CHUNK_MAX_TOTAL_CHUNKS):
        return None
    if chunk_index >= total_chunks:
        return None
    data = message.get("data")
    if not isinstance(data, str) or not data or len(data) > MEDIA_CHUNK_DATA_MAX_LEN:
        return None
    signature = message.get("signature")
    if signature is not None and (not isinstance(signature, str) or len(signature) > MEDIA_CHUNK_SIGNATURE_MAX_LEN):
        return None
    return to, transfer_id, chunk_index, total_chunks, data, signature


def _bounded_media_chunk_filename(value):
    """Bounds an optional file_name/encrypted_file_name field (S6-49,
    STEP 3) — file_chunk forwards this on every single chunk, so an
    unbounded value would let a tiny `data` payload smuggle megabytes of
    auxiliary string past the intended per-chunk ceiling. Returns None for
    anything that isn't a non-empty, in-bounds string (never truncates)."""
    if not isinstance(value, str) or not value or len(value) > MEDIA_CHUNK_FILENAME_MAX_LEN:
        return None
    return value


# Per-user transfer-byte budget (S6-49, STEP 4) — a count-only limiter is
# insufficient for variable-size chunks (a flood of maximum-size chunks
# still fits under any reasonable per-minute COUNT while consuming the
# full per-chunk byte ceiling every time). Windowed byte counter, same
# no-await check-then-increment pattern as every other RAM-only limiter in
# this file (global_prekey_publish_rate_ok() etc.) — accounts
# len(data.encode("utf-8")) for each chunk actually admitted for ONLINE
# relay (see media_chunk_recipient_rate_ok()'s own comment for why offline
# attempts don't charge this). 50 MiB / 10s (~5 MB/s sustained) comfortably
# covers an official client's own batched-chunk pace (5-15 chunks per ~30ms
# pause) with headroom, while still bounding a single account's aggregate
# relay cost.
MEDIA_CHUNK_USER_MAX_BYTES  = int(os.environ.get("MEDIA_CHUNK_USER_MAX_BYTES", str(50 * 1024 * 1024)) or str(50 * 1024 * 1024))
MEDIA_CHUNK_USER_WINDOW_SEC = 10
media_chunk_user_rate: dict = {}   # username -> {"bytes": int, "reset_time": float}


def media_chunk_user_rate_ok(username: str, nbytes: int) -> bool:
    """Process-local per-user egress-byte budget. Keyed by username, same
    bounded-key-space posture as `rate_limits` elsewhere in this file (only
    ever a real registered/authenticated account, never an attacker-minted
    arbitrary string) — not the pre-S6-35 unbounded-key anti-pattern."""
    now = time.time()
    entry = media_chunk_user_rate.get(username)
    if not entry or now - entry["reset_time"] >= MEDIA_CHUNK_USER_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        media_chunk_user_rate[username] = entry
    if entry["bytes"] + nbytes > MEDIA_CHUNK_USER_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


# Process-wide aggregate byte budget (S6-49, STEP 5) — per-user budgets are
# Sybil-multipliable (MAX_REGISTERED_USERS permitting, many distinct
# accounts each individually under MEDIA_CHUNK_USER_MAX_BYTES still sum to
# an arbitrarily large aggregate relay cost). Same no-await RAM-only
# pattern as every other aggregate guard in this file
# (global_prekey_publish_rate_ok()/channel_post_global_rate_ok()/
# totp_setup_global_rate_ok()). 500 MiB / 10s is generous for a modest
# single-process deployment's real aggregate media traffic while still
# bounding it. Explicitly process-local — a multi-process/replica
# deployment gets one independent budget PER PROCESS, not one shared
# budget across the deployment.
MEDIA_CHUNK_GLOBAL_MAX_BYTES  = int(os.environ.get("MEDIA_CHUNK_GLOBAL_MAX_BYTES", str(500 * 1024 * 1024)) or str(500 * 1024 * 1024))
MEDIA_CHUNK_GLOBAL_WINDOW_SEC = 10
media_chunk_global_rate = {"bytes": 0, "reset_time": time.time()}


def media_chunk_global_rate_ok(nbytes: int) -> bool:
    now  = time.time()
    data = media_chunk_global_rate
    if now - data["reset_time"] >= MEDIA_CHUNK_GLOBAL_WINDOW_SEC:
        data["bytes"]      = 0
        data["reset_time"] = now
    if data["bytes"] + nbytes > MEDIA_CHUNK_GLOBAL_MAX_BYTES:
        return False
    data["bytes"] += nbytes
    return True


# Per-recipient ingress budget (S6-49, STEP 7) — the sender/global budgets
# above protect server capacity, but a single attacker could still spend
# its entire allowance against ONE online victim, monopolizing that
# recipient's share of relay bandwidth. Keyed by RECIPIENT username, and
# only ever populated for a target that just resolved as genuinely online
# (clients.get(to) succeeded) — bounded by "currently connected accounts",
# never an attacker-controlled arbitrary string, so this is NOT the
# pre-S6-35 permanent-unbounded-registry anti-pattern. Deliberately more
# generous per-window than the per-user budget (a recipient may
# legitimately be receiving from several contacts at once).
MEDIA_CHUNK_RECIPIENT_MAX_BYTES  = int(os.environ.get("MEDIA_CHUNK_RECIPIENT_MAX_BYTES", str(100 * 1024 * 1024)) or str(100 * 1024 * 1024))
MEDIA_CHUNK_RECIPIENT_WINDOW_SEC = 10
media_chunk_recipient_rate: dict = {}   # recipient username -> {"bytes": int, "reset_time": float}


def media_chunk_recipient_rate_ok(recipient_username: str, nbytes: int) -> bool:
    now = time.time()
    entry = media_chunk_recipient_rate.get(recipient_username)
    if not entry or now - entry["reset_time"] >= MEDIA_CHUNK_RECIPIENT_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        media_chunk_recipient_rate[recipient_username] = entry
    if entry["bytes"] + nbytes > MEDIA_CHUNK_RECIPIENT_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


# Cheap per-user chunk-ATTEMPT counter (S6-49, STEP 6) — independent of the
# byte budgets above, which are only ever charged for a chunk actually
# admitted for ONLINE relay (see the three handlers below: an offline/
# nonexistent recipient's "status":"offline" response costs no egress
# bytes, by design, matching this feature's pre-existing behavior). Inbound
# JSON parsing/envelope validation still costs real CPU regardless of
# whether the target turns out to be online, so a cheap ATTEMPT bucket
# (independent of size) bounds that cost even against a permanently-
# offline or nonexistent target. 1000/10s is generous relative to any
# realistic official-client pace (batched 5-15 chunks per ~30ms pause,
# throttled far below this by real network I/O in practice) while still
# bounding a pure attempt-spam flood.
MEDIA_CHUNK_ATTEMPT_LIMIT      = int(os.environ.get("MEDIA_CHUNK_ATTEMPT_LIMIT", "1000") or "1000")
MEDIA_CHUNK_ATTEMPT_WINDOW_SEC = 10


def media_chunk_attempt_ok(username: str) -> bool:
    return rate_limit_check(username, "media_chunk_attempt",
                             limit=MEDIA_CHUNK_ATTEMPT_LIMIT, window=MEDIA_CHUNK_ATTEMPT_WINDOW_SEC)


# ─── Voice message protocol bounds (S6-57, external review 2026-09-06) ────────
# The "voice" handler relayed the caller's `voice_id`/`voice_data`/`signature`/
# `duration` fields with NO protocol-specific size bound of any kind and NO
# message-type rate limit at all (not present in rate_limit_check()'s
# default_limits) — the multi-megabyte MAX_PACKET_SIZE_BYTES application
# frame ceiling was the ONLY thing standing between an authenticated sender
# and using "voice" as a high-bandwidth relay/decrypt-work amplifier against
# any online recipient, exactly the same shape S6-49 (media chunks) and S6-51
# (call signaling) already closed for their own message types.
#
# Numbers below are DERIVED, not guessed, from both shipping clients'
# ACTUAL voice implementations (grepped, not assumed):
#   - Android (AudioHelper.kt): MediaRecorder AMR-NB/3GPP, empirically ~2000
#     bytes/sec of ENCODED audio (ChatScreen.kt's own `duration` bugfix
#     comment: "the actual recording bitrate is roughly double" the
#     previously-assumed 1000 bytes/sec).
#   - Desktop (VoiceRecorder.kt): UNCOMPRESSED 16 kHz/16-bit/mono PCM WAV —
#     32,000 bytes/sec of RAW audio, a much larger per-second cost than
#     Android's compressed codec. This is the dominant/worst case that sizes
#     every bound below (Android's AMR-NB voice messages fit comfortably
#     inside whatever accommodates Desktop's WAV at the same duration).
#   - Both clients: `voice_id` is always `UUID.randomUUID().toString()`
#     (Android: ChatScreen.kt send site; Desktop: ChatScreen.kt send site) —
#     a genuine canonical UUID on both platforms, not merely an opaque
#     bounded string, so it's validated as one (mirrors is_valid_call_uuid()'s
#     own "kept decoupled despite identical shape" reasoning — a SEPARATE
#     validator, not a cross-protocol reuse of the call-signaling one).
#   - Both clients sign only `CryptoManager.sign(encrypted)` — the encrypted
#     `voice_data` alone, never `voice_id`/`duration` — see
#     sanitize_voice_payload()'s own comment for what this does and does not
#     protect.
#   - Wire expansion, both clients identical: raw audio bytes -> base64
#     (client's own `voiceBase64`, ~4/3 expansion) -> that STRING is the
#     plaintext handed to CryptoManager.encrypt() (fixed ~1.2 KB hybrid-
#     handshake overhead: 2-byte-length-prefixed ephemeral EC pubkey +
#     2-byte-length-prefixed ML-KEM-768 ciphertext [1088 bytes] + 12-byte
#     GCM IV + 16-byte GCM tag) -> that combined binary blob is base64-
#     encoded AGAIN for the wire `voice_data` field (another ~4/3
#     expansion) — roughly 1.78x the raw audio bytes, plus ~1.6 KB fixed
#     overhead, end to end.
#
# MAX_VOICE_DURATION_SECONDS = 60 is the finite PRODUCT maximum this patch
# establishes (STEP 9) — neither client previously had ANY cap on recording
# length. At 60s, Desktop's worst-case wire `voice_data` is
# ~32,000*60*1.78 + 1,600 ≈ 3.26 MiB — VOICE_DATA_MAX_LEN below gives real
# headroom above that (encoding/padding variance), while VOICE_MAX_PACKET_
# SIZE_BYTES stays meaningfully below MAX_PACKET_SIZE_BYTES (6 MiB) rather
# than silently re-permitting the full application frame ceiling for this
# message type.
MAX_VOICE_DURATION_SECONDS = int(os.environ.get("MAX_VOICE_DURATION_SECONDS", "60") or "60")
if MAX_VOICE_DURATION_SECONDS <= 0:
    print("[FATAL] MAX_VOICE_DURATION_SECONDS должен быть > 0 — отказ запуска.", flush=True)
    sys.exit(1)

VOICE_DATA_MAX_LEN            = 4 * 1024 * 1024        # wire `voice_data` (base64 ciphertext), see derivation above
VOICE_SIGNATURE_MAX_LEN       = 256                     # mirrors MAX_IDENTITY_SIGNATURE_B64_LEN's own bound
VOICE_MAX_PACKET_SIZE_BYTES   = int(4.5 * 1024 * 1024)  # whole envelope; substantially below MAX_PACKET_SIZE_BYTES (6 MiB)

_VOICE_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def is_valid_voice_id(value) -> bool:
    return isinstance(value, str) and _VOICE_ID_RE.match(value) is not None


def sanitize_voice_payload(message: dict, from_user: str, target: str):
    """ONE canonical construction path for a relayed "voice" message (S6-57)
    — builds a BRAND NEW dict containing only `type`/`from`/`to`/`voice_id`/
    `voice_data`/`signature`/`duration`, instead of forwarding the caller's
    arbitrary dict verbatim (the original vulnerability: `voice_data` had no
    size ceiling of its own at all, and no other field was validated either
    — mirrors _sanitize_call_signal()'s own "canonical construction, not a
    verbatim relay" reasoning). `type`/`from`/`to` are always server-
    controlled here; every other field is validated, cheap type/length
    checks first. Returns None if ANY field fails validation — the caller
    must treat that exactly like a malformed message (drop, no relay, no
    db_store()), never a partial/best-effort payload.

    Does NOT solve (reported, not silently fixed here — S6-57 STEP 10): both
    shipping clients sign only the encrypted `voice_data`, never `voice_id`
    or `duration` — a signature proves who encrypted this audio, not that
    THIS specific voice_id/duration pairing is the one they intended. A
    compromised/malicious server (not a federation peer, which is
    independently bound by S6-38's own `from` semantics) could in principle
    relabel `voice_id`/`duration` on an otherwise-validly-signed payload
    without invalidating the signature. `duration` is UI-metadata-only
    (playback slider length) with no storage/dedup consequence; `voice_id`
    IS used as a local storage/file-naming key on both clients, so a
    relabeled voice_id has more realistic consequence (e.g. colliding with
    or overwriting an unrelated locally-stored voice file id) — flagged here
    as a follow-up semantic-authentication candidate, not fixed in this
    resource-bounding patch."""
    fields = validate_voice_fields(message)
    if fields is None:
        return None
    return {"type": "voice", "from": from_user, "to": target, **fields}


def validate_voice_fields(message: dict):
    """FIELD-ONLY half of sanitize_voice_payload() (split out S6-59, STEP 5)
    — validates voice_id/voice_data/signature/duration with no knowledge of
    or reference to sender/recipient identity, returning just those four
    fields (or None if any fails). Exists so the anon_message relay path can
    apply this SAME bound to a "voice"-typed payload it can already see
    (S6-59's routing-matrix finding: Desktop's unsealed seal-failure
    fallback can expose a visible `type`) without ever constructing or
    learning a `from`/`to` pair for it — sanitize_voice_payload() above
    remains the sole place that adds authenticated sender identity, for the
    ordinary direct/federated path."""
    voice_id = message.get("voice_id")
    if not is_valid_voice_id(voice_id):
        return None
    voice_data = message.get("voice_data")
    if not isinstance(voice_data, str) or not voice_data or len(voice_data) > VOICE_DATA_MAX_LEN:
        return None
    signature = message.get("signature")
    if not isinstance(signature, str) or not signature or len(signature) > VOICE_SIGNATURE_MAX_LEN:
        return None
    duration = message.get("duration")
    # bool is a subclass of int in Python -- explicitly excluded, same
    # posture as every other integer-shaped field validator in this file.
    if (not isinstance(duration, int) or isinstance(duration, bool)
            or duration < 0 or duration > MAX_VOICE_DURATION_SECONDS):
        return None
    return {
        "voice_id": voice_id, "voice_data": voice_data,
        "signature": signature, "duration": duration,
    }


# Voice-specific count rate limit (S6-57, STEP 4) — "voice" had no entry in
# rate_limit_check()'s default_limits at all before this fix (`max_count =
# limit or default_limits.get(msg_type)` silently returned True for every
# attempt). 60/min is generous for genuine voice-note usage (a real user
# cannot record-and-send anywhere near this fast) while bounding a pure
# frequency flood; the byte budgets below are what actually bound aggregate
# relay cost, since voice blobs vary substantially in size and a count-only
# limit alone is insufficient (STEP 4's own point).
VOICE_RATE_LIMIT = 60

# Per-sender egress-byte budget (S6-57, STEP 4) — same windowed-counter
# pattern as call_signal_user_rate_ok()/media_chunk_user_rate_ok(). Accounted
# from the exact sanitized relay payload (json.dumps'd), only for a voice
# message actually being relayed to an ONLINE recipient — an offline target
# is queued/federated instead, governed by S6-31's own separate global
# offline-queue caps, never double-charged here.
VOICE_USER_MAX_BYTES  = int(os.environ.get("VOICE_USER_MAX_BYTES", str(20 * 1024 * 1024)) or str(20 * 1024 * 1024))
VOICE_USER_WINDOW_SEC = 10
voice_user_rate: dict = {}   # username -> {"bytes": int, "reset_time": float}


def voice_user_rate_ok(username: str, nbytes: int) -> bool:
    now = time.time()
    entry = voice_user_rate.get(username)
    if not entry or now - entry["reset_time"] >= VOICE_USER_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        voice_user_rate[username] = entry
    if entry["bytes"] + nbytes > VOICE_USER_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


# Process-wide aggregate byte budget (S6-57, STEP 4) — per-sender budgets are
# Sybil-multipliable; mirrors media_chunk_global_rate_ok()/
# call_signal_global_rate_ok() exactly.
VOICE_GLOBAL_MAX_BYTES  = int(os.environ.get("VOICE_GLOBAL_MAX_BYTES", str(150 * 1024 * 1024)) or str(150 * 1024 * 1024))
VOICE_GLOBAL_WINDOW_SEC = 10
voice_global_rate = {"bytes": 0, "reset_time": time.time()}


def voice_global_rate_ok(nbytes: int) -> bool:
    now  = time.time()
    data = voice_global_rate
    if now - data["reset_time"] >= VOICE_GLOBAL_WINDOW_SEC:
        data["bytes"]      = 0
        data["reset_time"] = now
    if data["bytes"] + nbytes > VOICE_GLOBAL_MAX_BYTES:
        return False
    data["bytes"] += nbytes
    return True


# Per-recipient ingress budget (S6-57, STEP 4) — many Sybil senders could
# otherwise each spend their own individual sender/global allowance against
# the SAME online victim, monopolizing that recipient's bandwidth and
# forcing it to verify/decrypt/decode voice audio from all of them at once.
# Keyed only by a genuinely-online recipient username (clients.get(target)
# already succeeded by the time this is ever checked) — mirrors
# call_signal_recipient_rate_ok()/media_chunk_recipient_rate_ok() exactly.
VOICE_RECIPIENT_MAX_BYTES  = int(os.environ.get("VOICE_RECIPIENT_MAX_BYTES", str(40 * 1024 * 1024)) or str(40 * 1024 * 1024))
VOICE_RECIPIENT_WINDOW_SEC = 10
voice_recipient_rate: dict = {}   # recipient username -> {"bytes": int, "reset_time": float}


def voice_recipient_rate_ok(recipient_username: str, nbytes: int) -> bool:
    now = time.time()
    entry = voice_recipient_rate.get(recipient_username)
    if not entry or now - entry["reset_time"] >= VOICE_RECIPIENT_WINDOW_SEC:
        entry = {"bytes": 0, "reset_time": now}
        voice_recipient_rate[recipient_username] = entry
    if entry["bytes"] + nbytes > VOICE_RECIPIENT_MAX_BYTES:
        return False
    entry["bytes"] += nbytes
    return True


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

# ─── FCM push scheduling hardening (S6-52) ─────────────────────────────────
# STEP 1 finding (external review 2026-09-06): `fcm_token` lives ONLY in
# `clients[username]["fcm_token"]` — populated by `register_fcm` on an
# already-authenticated live connection, wiped by `clients.pop(username, ...)`
# on disconnect, and never carried over to the FRESH dict register() builds
# on every reconnect (`clients[candidate_username] = {"ws":..., ...}`, no
# "fcm_token" key). Every wakeup call site below only ever calls this AFTER
# confirming the target is NOT in `clients` (offline) — by construction,
# `clients.get(target_username, {})` is `{}` at that exact moment, so
# `send_fcm_wakeup()`'s original token lookup could never have found one.
# This means the "wake a genuinely disconnected client" path was already
# FUNCTIONALLY DEAD before this patch — not a security bypass of an existing
# push, just a push that could never fire for its stated purpose. This patch
# does NOT add token persistence to make it work (that's a deliberate
# metadata-retention decision out of scope here, see KNOWN_SECURITY_ISSUES.md
# S6-52) — it hardens the surrounding admission/scheduling/token-input
# surface regardless, since (a) `register_fcm`'s input bound and rate limit
# matter independently of whether wakeups ever fire, (b) unbounded
# `asyncio.create_task()` per Sybil-triggered offline message/missed-call
# still allocates and schedules a Task even though that Task immediately
# no-ops, and (c) `send_fcm_session_conflict()` uses a token read from a
# STILL-LIVE connection at the moment of eviction, which genuinely can reach
# Firebase — the only currently-reachable push path in this file.
FCM_TOKEN_MAX_LEN = int(os.environ.get("FCM_TOKEN_MAX_LEN", "4096") or "4096")
if FCM_TOKEN_MAX_LEN <= 0:
    print("[FATAL] FCM_TOKEN_MAX_LEN должен быть > 0 (обязательная защита процесса от "
          "неограниченного роста, а не отключаемая опция) — отказ запуска.", flush=True)
    sys.exit(1)

# Silent `wakeup` pushes are idempotent (`data={"type":"wakeup"}`) -- ten
# queued messages arriving for the same offline recipient in a burst do not
# need ten separate high-priority Firebase sends. Derived from Android's own
# reconnect/wake behavior: MessengerService's RINGING_TIMEOUT_MS-class
# windows are tens of seconds, and a woken client reconnects and drains its
# whole offline queue in one pass — a single wakeup within this window is
# exactly as useful as ten.
FCM_WAKEUP_RECIPIENT_COOLDOWN_SEC = 5
# Sender budget (per authenticated username that CAUSED a wakeup attempt --
# never an attacker-supplied `from`, always the connection's own proven
# identity). Server-internal pushes with no meaningful human sender (none
# exist today, all current call sites have a real authenticated username)
# would use this sentinel scope instead of pretending to be the target.
FCM_SYSTEM_SOURCE = "__system__"
FCM_WAKEUP_SOURCE_LIMIT      = int(os.environ.get("FCM_WAKEUP_SOURCE_LIMIT", "20") or "20")
FCM_WAKEUP_SOURCE_WINDOW_SEC = 60
# Recipient budget -- per-source limiting alone does not protect one victim
# against many distinct Sybil senders each legitimately reaching the wakeup
# path (offline message/session_init/missed_call/message_delete/etc.).
FCM_WAKEUP_RECIPIENT_LIMIT      = int(os.environ.get("FCM_WAKEUP_RECIPIENT_LIMIT", "10") or "10")
FCM_WAKEUP_RECIPIENT_WINDOW_SEC = 60
# Global budget -- protects Firebase API quota/cost, executor work, sockets,
# and process memory from aggregate Sybil amplification across many targets
# at once; independent of and layered on top of the per-source/per-recipient
# budgets above, not a replacement for either.
FCM_PUSH_GLOBAL_LIMIT      = int(os.environ.get("FCM_PUSH_GLOBAL_LIMIT", "120") or "120")
FCM_PUSH_GLOBAL_WINDOW_SEC = 60
# Hard, always-on cap on SIMULTANEOUS Firebase sends across ALL recipients
# combined -- rate limiting only bounds how many sends START per window, not
# how many can be simultaneously slow/stuck in run_in_executor() at once.
# Reserved synchronously BEFORE asyncio.create_task() ever runs (see
# schedule_fcm_wakeup()/schedule_fcm_session_conflict() below) -- never an
# asyncio.Semaphore awaited from inside an already-created Task, which would
# still leave thousands of Tasks sitting in memory even while "bounded".
FCM_MAX_INFLIGHT_SENDS = int(os.environ.get("FCM_MAX_INFLIGHT_SENDS", "50") or "50")
if FCM_MAX_INFLIGHT_SENDS <= 0:
    print("[FATAL] FCM_MAX_INFLIGHT_SENDS должен быть > 0 (обязательная защита процесса от "
          "неограниченного роста конкурентных Firebase-отправок) — отказ запуска.", flush=True)
    sys.exit(1)
# Short backoff after a Firebase SEND EXCEPTION (not a rejection at
# admission time) -- prevents a tight immediate-retry storm against a
# transiently-failing Firebase backend without silently retrying forever.
FCM_WAKEUP_FAILURE_BACKOFF_SEC = 30
# session_conflict is a separate VISIBLE notification, not silent-wakeup
# coalescing -- deliberately its OWN cooldown/inflight/backoff state, not
# shared with fcm_wakeup_*'s dicts below (STEP 4/12), but it DOES share the
# process-wide global budget and the hard inflight cap (STEP 12).
FCM_SESSION_CONFLICT_COOLDOWN_SEC = 5

# All keyed ONLY by a real registered/authenticated username (validated by
# is_valid_fingerprint() before ever reaching a limiter below, or -- for
# `source` -- always the connection's own proven identity, never
# attacker-supplied) -- same bounded-key-space posture as `rate_limits`/
# `totp_state_locks`/`avatar_mutation_locks` elsewhere in this file: growth
# is bounded by the number of distinct real accounts that have ever
# triggered/received a push, not a meaningful DoS surface on its own, so no
# additional expiry-sweep machinery is needed beyond each windowed counter's
# own self-reset.
fcm_wakeup_last_sent: dict = {}          # target username -> float (last SUCCESSFUL send time)
fcm_wakeup_inflight: set = set()         # target usernames with a send currently in flight
fcm_wakeup_failure_until: dict = {}      # target username -> float (backoff expiry after a Firebase exception)
fcm_wakeup_source_rate: dict = {}        # source username -> {"count", "reset_time"}
fcm_wakeup_recipient_rate: dict = {}     # target username -> {"count", "reset_time"}
fcm_push_global_rate = {"count": 0, "reset_time": time.time()}
fcm_inflight_count = 0                  # GLOBAL simultaneous-send counter, shared by wakeup + session_conflict

fcm_session_conflict_last_sent: dict = {}      # username -> float
fcm_session_conflict_inflight: set = set()
fcm_session_conflict_failure_until: dict = {}  # username -> float


def _fcm_wakeup_source_rate_ok(source: str) -> bool:
    now  = time.time()
    data = fcm_wakeup_source_rate.setdefault(source, {"count": 0, "reset_time": now})
    if now - data["reset_time"] >= FCM_WAKEUP_SOURCE_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= FCM_WAKEUP_SOURCE_LIMIT:
        return False
    data["count"] += 1
    return True


def _fcm_wakeup_recipient_rate_ok(target: str) -> bool:
    now  = time.time()
    data = fcm_wakeup_recipient_rate.setdefault(target, {"count": 0, "reset_time": now})
    if now - data["reset_time"] >= FCM_WAKEUP_RECIPIENT_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= FCM_WAKEUP_RECIPIENT_LIMIT:
        return False
    data["count"] += 1
    return True


def _fcm_push_global_rate_ok() -> bool:
    now  = time.time()
    data = fcm_push_global_rate
    if now - data["reset_time"] >= FCM_PUSH_GLOBAL_WINDOW_SEC:
        data["count"]      = 0
        data["reset_time"] = now
    if data["count"] >= FCM_PUSH_GLOBAL_LIMIT:
        return False
    data["count"] += 1
    return True


def schedule_fcm_wakeup(target_username: str, source_username: str, reason: str) -> bool:
    """Synchronous, no-`await` admission gate (S6-52, STEP 3) — every cheap
    RAM check below happens BEFORE `asyncio.create_task()` ever runs, so a
    rejected wakeup never allocates or schedules a Task at all (unlike the
    original `asyncio.create_task(send_fcm_wakeup(target))`, which always
    allocated a Task regardless of what the coroutine did once it actually
    ran). Returns True only if a real send was actually scheduled.

    `reason` is a short caller-supplied label for logging only (e.g.
    "message", "missed_call") — never relayed to the client, never used in
    any decision here."""
    global fcm_inflight_count
    if not is_valid_fingerprint(target_username):
        return False

    if target_username in fcm_wakeup_inflight:
        return False  # STEP 4: another wakeup already in flight for this target

    last_sent = fcm_wakeup_last_sent.get(target_username)
    if last_sent is not None and time.time() - last_sent < FCM_WAKEUP_RECIPIENT_COOLDOWN_SEC:
        return False  # STEP 4: coalesced within the recipient cooldown window

    backoff_until = fcm_wakeup_failure_until.get(target_username)
    if backoff_until is not None and time.time() < backoff_until:
        return False  # STEP 10: short backoff after a recent Firebase exception

    if source_username != FCM_SYSTEM_SOURCE and not _fcm_wakeup_source_rate_ok(source_username):
        return False  # STEP 5
    if not _fcm_wakeup_recipient_rate_ok(target_username):
        return False  # STEP 6
    if not _fcm_push_global_rate_ok():
        return False  # STEP 7

    if fcm_inflight_count >= FCM_MAX_INFLIGHT_SENDS:
        return False  # STEP 8: hard cap, reserved BEFORE create_task()

    fcm_inflight_count += 1
    fcm_wakeup_inflight.add(target_username)
    asyncio.create_task(_run_fcm_wakeup(target_username, reason))
    return True


async def _run_fcm_wakeup(target_username: str, reason: str):
    """The actual Firebase send — only ever reached via
    schedule_fcm_wakeup()'s admission gate above, never called directly."""
    global fcm_inflight_count
    try:
        async with lock:
            fcm_token = clients.get(target_username, {}).get("fcm_token")
        if not fcm_token:
            return  # нет токена — пропускаем (see this section's own STEP-1 comment)

        if not _init_firebase():
            return  # GOOGLE_APPLICATION_CREDENTIALS не задан — FCM отключён

        from firebase_admin import messaging
        msg = messaging.Message(
            data={"type": "wakeup"},
            android=messaging.AndroidConfig(priority="high"),
            token=fcm_token
        )
        loop = asyncio.get_event_loop()
        try:
            # messaging.send() — синхронный, запускаем в потоке чтобы не блокировать event loop
            await loop.run_in_executor(None, messaging.send, msg)
        except Exception as e:
            # STEP 10: short failure backoff, never an indefinite/immediate
            # retry storm. STEP 11: only a SPECIFIC confirmed-invalid-token
            # response invalidates the stored token — a generic/transient/
            # timeout/quota exception must not.
            fcm_wakeup_failure_until[target_username] = time.time() + FCM_WAKEUP_FAILURE_BACKOFF_SEC
            await _invalidate_fcm_token_if_unregistered(target_username, fcm_token, e)
            print(f"[FCM] Ошибка wake-up для {target_username} (reason={reason}): {e}")
            return
        fcm_wakeup_last_sent[target_username] = time.time()
        print(f"[FCM] Wakeup отправлен пользователю {target_username} (reason={reason})")
    finally:
        fcm_wakeup_inflight.discard(target_username)
        fcm_inflight_count -= 1


async def _invalidate_fcm_token_if_unregistered(target_username: str, sent_token: str, exc: Exception):
    """STEP 11 — `firebase_admin.messaging.UnregisteredError` is the specific,
    documented condition for "this registration token is permanently invalid
    / no longer registered" in firebase-admin>=6 — the one exception type
    safe to act on. Every other exception (timeout, generic network error,
    quota error, transient backend error) leaves the stored token alone;
    removing it on those would durably lose a perfectly good token over a
    hiccup. Only clears it if it still matches what was actually sent — the
    client may have already re-registered a fresh token while this send was
    in flight, and that newer token must never be clobbered by a stale
    failure callback. RAM-only (this file never persists fcm_token
    durably today, see this section's own STEP-1 comment) — no DB work
    needed or attempted here."""
    try:
        from firebase_admin import messaging as _messaging
    except Exception:
        return
    if not isinstance(exc, _messaging.UnregisteredError):
        return
    async with lock:
        entry = clients.get(target_username)
        if entry is not None and entry.get("fcm_token") == sent_token:
            entry.pop("fcm_token", None)
    print(f"[FCM] Токен инвалидирован (UnregisteredError) для {target_username}")


def schedule_fcm_session_conflict(username: str, fcm_token, ts: float) -> bool:
    """Synchronous, no-`await` admission gate for the VISIBLE session-conflict
    push (S6-52, STEP 12) — mirrors schedule_fcm_wakeup()'s structure exactly,
    but with its OWN cooldown/inflight/backoff state (never shares silent-
    wakeup coalescing, since a real session takeover must still promptly
    notify the displaced device, not be silently swallowed by an unrelated
    wakeup's cooldown) while sharing the process-wide global budget and hard
    inflight cap with wakeup (both cost the same underlying Firebase/
    executor/process resources)."""
    global fcm_inflight_count
    if not isinstance(fcm_token, str) or not fcm_token or len(fcm_token) > FCM_TOKEN_MAX_LEN:
        return False  # defense-in-depth: already bounded at register_fcm time

    if username in fcm_session_conflict_inflight:
        return False

    last_sent = fcm_session_conflict_last_sent.get(username)
    if last_sent is not None and time.time() - last_sent < FCM_SESSION_CONFLICT_COOLDOWN_SEC:
        return False

    backoff_until = fcm_session_conflict_failure_until.get(username)
    if backoff_until is not None and time.time() < backoff_until:
        return False

    if not _fcm_push_global_rate_ok():
        return False

    if fcm_inflight_count >= FCM_MAX_INFLIGHT_SENDS:
        return False

    fcm_inflight_count += 1
    fcm_session_conflict_inflight.add(username)
    asyncio.create_task(_run_fcm_session_conflict(username, fcm_token, ts))
    return True


async def _run_fcm_session_conflict(username: str, fcm_token: str, ts: float):
    """Пушит ВИДИМОЕ уведомление (не silent data) о вытеснении сессии — должно
    показаться даже если приложение свёрнуто/убито, а не только при активном
    WebSocket-соединении. Токен уже известен (взят из вытесняемой сессии), без
    доп. lookup по username. Only ever reached via
    schedule_fcm_session_conflict()'s admission gate above."""
    global fcm_inflight_count
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
        try:
            await loop.run_in_executor(None, messaging.send, msg)
        except Exception as e:
            fcm_session_conflict_failure_until[username] = time.time() + FCM_WAKEUP_FAILURE_BACKOFF_SEC
            print(f"[FCM] Ошибка session_conflict push для {username}: {e}")
            return
        fcm_session_conflict_last_sent[username] = time.time()
        print(f"[FCM] session_conflict push отправлен для {username}")
    finally:
        fcm_session_conflict_inflight.discard(username)
        fcm_inflight_count -= 1

# Allowlist of message types an authenticated CLIENT may send to its OWN
# server (NOT the same trust surface as FEDERATED_FORWARD_ALLOWED_TYPES,
# which describes what one federation server forwards to another — see that
# constant's own comment). Hoisted to module level (external review
# 2026-09-05, S6-47) — was previously rebuilt as a fresh list literal on
# EVERY single incoming message inside handle_client()'s own loop; moving it
# out changes nothing about its contents or the check itself
# (`msg_type not in ALLOWED_TYPES`, unchanged), it only lets test code
# reference/temporarily override the one canonical list instead of it being
# unreachable outside the function body.
ALLOWED_TYPES = [
    "register", "register_bundle", "get_key", "ping", "pong",
    "message", "session_init",
    "reaction", "voice", "typing", "edit",
    "image_chunk", "file_chunk", "video_chunk", "chunk_ack",
    "read",
    "publish_prekey_bundle",
    "get_prekey_bundle", "get_prekey_bundles_batch", "group_reaction",
    "group_create",
    "group_message",
    "group_member_removed",
    "group_member_added",
    "group_key_rotation",
    "group_invite_accepted",
    "delivered",
    # channel_create/channel_subscribe/channel_unsubscribe/
    # channel_post/channel_get_info removed from here (external
    # review 2026-08-28, SCOPE-01) -- the Channels feature was
    # only ever disabled at the Android/Desktop UI layer, while
    # these server-side handlers (and their DB tables) stayed
    # fully live. SECURITY.md's Known Limitations #12 claimed
    # this had "no live attack surface today" because of the UI
    # disablement, which was wrong: any custom WebSocket client
    # (not just the shipped apps) could reach channel_create/
    # channel_post/etc. directly, with none of the anon-routing
    # protection the rest of the protocol has (channel posts and
    # subscriber lists were never anonymized, by design, since
    # the feature predates that work). Removed from
    # ALLOWED_TYPES so these now hit the same "неизвестный тип"
    # rejection as any other unsupported message -- matches the
    # product's actual intent (disabled) rather than only
    # appearing disabled in the UI. The handler code and DB
    # tables are left in place, unreachable, not deleted -- see
    # docs/TODO.md if Channels is ever re-enabled. Still resource-
    # hardened (S6-47, 2026-09-05) despite being dormant: unreachable
    # today is not the same guarantee as deleted, and any future
    # re-enablement (docs/TODO.md) inherits the hardening for free
    # instead of needing it redone from scratch.
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
    "subscribe_tokens", "unsubscribe_tokens", "anon_message", "anon_delivery_ack",
    # ── Anonymous Mailbox ──
    "mailbox_put", "mailbox_fetch",
    # ── Device-gated registration TOTP ──
    "totp_setup", "totp_disable",
    # ── Client-side diagnostics ──
    "bootstrap_diagnostic",
    # ── Sealed Sender: sender certificate issuance ──
    "request_sender_cert"
]


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
    is_anon_channel      = False  # Sealed Sender, шаг 2 — see the "anon_channel" handshake branch below
    challenge            = None
    verified_public_key  = None  # raw key bytes proven via challenge_response; register must match this
    # Anti-spam for the anon-only channel: there is no username to key
    # rate_limit_check() on (that's the whole point — see below), so this is
    # a simple per-connection counter instead. Unused for ordinary connections.
    anon_channel_count       = 0
    anon_channel_window_start = time.time()

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

        # Dedicated pre-auth ceiling, not MAX_PACKET_SIZE_BYTES (external
        # review 2026-09-05, S6-45) — see HANDSHAKE_MAX_PACKET_SIZE_BYTES's
        # own comment. Checked against the actual encoded UTF-8 byte count,
        # not Python's `len()` character count (which undercounts for any
        # non-ASCII content) — `websocket.recv()` returns `str` for a text
        # frame here, never `bytes`, but this stays correct either way.
        raw_handshake_len = (
            len(raw_handshake) if isinstance(raw_handshake, bytes)
            else len(raw_handshake.encode("utf-8"))
        )
        if raw_handshake_len > HANDSHAKE_MAX_PACKET_SIZE_BYTES:
            # No username exists yet at handshake time — IP is the only
            # thing to ban on. Weak behind a reverse proxy for the same
            # reason noted at the post-auth oversized-packet check below
            # (bans the proxy's loopback, not the real client) — acceptable
            # here since there's genuinely no identity to fall back to yet.
            print(f"[SECURITY] Слишком большой handshake от {ip}: {raw_handshake_len} bytes")
            ban_ip(ip)
            return
        try:
            hs_msg = json.loads(raw_handshake)
        except Exception:
            print(f"[SECURITY] Невалидный JSON в handshake от {ip}")
            return
        # A syntactically-valid JSON value can be a list/string/number/null,
        # not just an object — strip_padding() assumes a dict and calls
        # `.pop("_p", None)` on it immediately, which would raise on
        # anything else (external review 2026-09-05, S6-45). Reject before
        # that call, not via the exception escaping into whatever teardown
        # happens to catch it.
        if not isinstance(hs_msg, dict):
            print(f"[SECURITY] Handshake — не JSON-объект от {ip}")
            return
        strip_padding(hs_msg)
        hs_type = hs_msg.get("type")

        if hs_type == "federation_auth" and FEDERATION_SECRET:
            # Bounded BEFORE base64 decode (external review 2026-09-05,
            # S6-45) — the MAC is always exactly 32 raw bytes; see
            # MAX_FEDERATION_MAC_B64_LEN's own comment. Strict base64
            # (validate=True), then the decoded LENGTH is checked before
            # hmac.compare_digest() ever runs — compare_digest() itself
            # doesn't require equal-length inputs, so a malformed/wrong-size
            # value must be rejected explicitly rather than silently
            # compared and (correctly, but for the wrong stated reason)
            # failing.
            mac_b64 = hs_msg.get("mac")
            if (not isinstance(mac_b64, str) or not mac_b64
                    or len(mac_b64) > MAX_FEDERATION_MAC_B64_LEN):
                print(f"[FEDERATION] Невалидный формат MAC от {ip}")
                return
            try:
                provided = base64.b64decode(mac_b64, validate=True)
            except Exception:
                print(f"[FEDERATION] Невалидный base64 MAC от {ip}")
                return
            if len(provided) != hashlib.sha256().digest_size:
                print(f"[FEDERATION] Некорректная длина MAC от {ip}")
                return
            expected = hmac.new(FEDERATION_SECRET.encode(), challenge, hashlib.sha256).digest()
            if not hmac.compare_digest(provided, expected):
                print(f"[FEDERATION] Неверный MAC от {ip}")
                return
            is_fed = True
            await websocket.send(json.dumps({"type": "federation_auth_ok"}))
            print(f"[FEDERATION] Входящий пир аутентифицирован: {ip}")
            # Передаём управление федерационному обработчику ниже
        elif hs_type == "challenge_response":
            # Canonical bounded decode (external review 2026-09-05, S6-45) —
            # see decode_identity_public_key()/decode_identity_signature()'s
            # own comments: cheap shape/length/base64-syntax checks, and the
            # protocol's actual P-256 curve, are all enforced BEFORE
            # load_der_public_key()/verify() ever run. Same helper register()
            # reuses below, so hardening isn't limited to just this one path.
            public_key_b64 = hs_msg.get("public_key")
            signature_b64  = hs_msg.get("signature")

            decoded_key = decode_identity_public_key(public_key_b64)
            if decoded_key is None:
                print(f"[HANDSHAKE] Невалидный/неподдерживаемый public_key от {ip}")
                return
            key_bytes, public_key = decoded_key

            sig_bytes = decode_identity_signature(signature_b64)
            if sig_bytes is None:
                print(f"[HANDSHAKE] Невалидная подпись (формат) от {ip}")
                return

            try:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.exceptions import InvalidSignature
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
        elif hs_type == "anon_channel":
            # Sealed Sender, шаг 2: канал отправки anon_message без identity
            # вообще — никакого public_key/подписи не запрашивается и не
            # проверяется. См. docs/TODO.md, "новый канал отправки
            # anon_message... не требует username вообще". challenge_response
            # (ветка выше) уже само по себе выдаёт identity серверу — публичный
            # ключ приходит в открытую и fingerprint = sha256(public_key)[:8]
            # вычислим тривиально, поэтому второй сокет с той же
            # identity-аутентификацией ничего бы не скрыл. Это соединение
            # НИКОГДА не получит username и ограничено ниже (async for) строго
            # одним типом сообщения — anon_message, всё остальное отклоняется.
            is_anon_channel = True
            authenticated   = True
            await websocket.send(json.dumps({"type": "anon_channel_ok"}))
            print(f"[ANON_CHANNEL] Подключение без identity: {ip}")
        else:
            print(f"[SECURITY] Ожидался challenge_response, получен {hs_type} от {ip}")
            return

        if not authenticated and not is_fed:
            return

        # Federation peers get their OWN dedicated handler and must never
        # fall through into the identified-client loop below (external
        # review 2026-09-04). Before this fix, `is_fed=True` only skipped
        # straight to `handle_federation_peer_incoming()` AFTER the `async
        # for` loop below exited — i.e. never, while the connection was
        # alive, since that loop runs until the socket closes. A federation
        # connection was therefore processed by the general client protocol
        # (full ALLOWED_TYPES) the entire time it was open. That's a real
        # privilege escalation, not just dead code: register()'s
        # proof-of-possession check is `if not is_fed and (... key_bytes !=
        # verified_public_key)` — deliberately skipped for federation peers,
        # since inter-server federation forwarding was never meant to prove
        # a *user's* private key. Any peer that knows FEDERATION_SECRET
        # could reach `register` here with a victim's public_key and no
        # private key at all, and register as that victim's fingerprint.
        # is_fed and authenticated (challenge_response) are mutually
        # exclusive states from the handshake dispatch above, so this
        # branch is a hard split, not a special case of the loop below.
        if is_fed:
            await handle_federation_peer_incoming(websocket, ip)
            return

        async for raw_message in websocket:

            # Лимит размера пакета
            if len(raw_message) > MAX_PACKET_SIZE_BYTES:
                # Бан по IP здесь почти бесполезен для обычных клиентов: за
                # reverse-proxy'ем server.py видит только 127.0.0.1 у ВСЕХ
                # (SECURITY.md, инвариант item 30) — ban_ip(ip) забанил бы
                # loopback-адрес прокси целиком, а не конкретного клиента.
                # Если соединение уже аутентифицировано (username известен),
                # баним по fingerprint — тому же banned_users, что уже
                # использует report_violation() для других нарушений, ниже
                # по коду. IP-бан остаётся единственным вариантом только для
                # пред-регистрационного флуда (username ещё None) — тут он
                # слабый по той же причине, но это не хуже статус-кво, и не
                # относится к federation-пирам (те подключаются напрямую, не
                # через анонимизирующий прокси, см. docs/TODO.md).
                if username:
                    banned_users[username] = time.time() + 600
                    print(f"[SECURITY] Слишком большой пакет от {username} ({ip}): "
                          f"{len(raw_message)} bytes — забанен на 10 минут")
                else:
                    print(f"[SECURITY] Слишком большой пакет от {ip}: {len(raw_message)} bytes")
                    ban_ip(ip)
                return

            try:
                message = json.loads(raw_message)
            except Exception:
                print(f"[SECURITY] Невалидный JSON от {ip}")
                continue

            # Defense-in-depth, not the main S6-45 finding (external review
            # 2026-09-05) — a syntactically-valid JSON value can be a
            # list/string/number/null, not just an object; strip_padding()
            # assumes a dict and would raise on anything else.
            if not isinstance(message, dict):
                continue

            strip_padding(message)
            msg_type = message.get("type")

            if msg_type not in ALLOWED_TYPES:
                print(f"[SECURITY] Неизвестный тип '{msg_type}' от {ip}")
                continue

            # ─── Anon-only channel restriction ─────────────────────────────────
            # This connection never proved (or claimed) an identity — it must
            # never reach register/session_init/prekey-fetch/etc., only the
            # one thing it exists for. A peer trying anything else here is
            # either a bug or a probe; closing (not just dropping the message)
            # avoids leaving a connection open that keeps trying.
            if is_anon_channel:
                if msg_type != "anon_message":
                    print(f"[SECURITY] anon_channel {ip} запросил '{msg_type}' — закрываю")
                    return
                now = time.time()
                if now - anon_channel_window_start > 60:
                    anon_channel_count = 0
                    anon_channel_window_start = now
                anon_channel_count += 1
                if anon_channel_count > ANON_CHANNEL_MAX_PER_MINUTE:
                    print(f"[SECURITY] anon_channel {ip} превысил лимит — закрываю")
                    return

            # ─── Hard authorization boundary (external review 2026-09-05,
            # S6-39, tightened S6-40) ────────────────────────────────────────
            # Defense in depth on top of the register() refactor above (which
            # stops a REJECTED candidate identity from ever populating
            # `username`) — even if some future change to register()'s many
            # failure paths accidentally reintroduced an early assignment,
            # this boundary independently refuses to process ANY ordinary
            # client message for a socket that hasn't actually completed
            # registration, checked against the one authoritative live
            # mapping (`authenticated_users`) that register()'s successful
            # Phase 2 commit — and ONLY that commit — ever writes to.
            # `is_anon_channel` connections are exempt: they intentionally
            # never register or enter `authenticated_users` at all, and are
            # already fully restricted to exactly `anon_message` by the block
            # above (so `msg_type` here is always `anon_message`, never
            # `register`, whenever `is_anon_channel` is true). Federation
            # peers never reach this loop in the first place (see `is_fed`'s
            # dedicated early-return above).
            #
            # No other exceptions. S6-39 briefly also exempted
            # `register_bundle`, since Android's `handshake_ok` handler used
            # to send it from a coroutine independent of (and racing) the one
            # sending `register` itself, with no ordering guarantee between
            # the two — verified live, not assumed (see the git history for
            # that fix's own comment). That was a client-side ordering bug,
            # not a server requirement: fixed at the source (S6-40,
            # MessengerService.kt) by making `register` → server's explicit
            # `register_ok` acknowledgment → `register_bundle`/other
            # account-scoped startup traffic an event-driven, generation-
            # scoped sequence (no polling), so `register_bundle` now
            # physically cannot reach this server before `register` has
            # already been fully processed. The compatibility exception (and
            # the `register_bundle` handler's matching `if not username:
            # continue` guard, needed only because that exception could let
            # it through pre-registration) are both removed now that the
            # client-side ordering is deterministic — restoring the original,
            # simpler invariant: no ordinary message of any kind reaches this
            # server before a completed `register`.
            if not is_anon_channel and msg_type != "register":
                committed_username = authenticated_users.get(websocket)
                if committed_username is None:
                    print(f"[SECURITY] '{msg_type}' от {ip} до успешной регистрации — закрываю")
                    await send_safe(websocket, json.dumps({
                        "type": "error",
                        "reason": "Registration required"
                    }))
                    await websocket.close()
                    return
                username = committed_username

            # ─── Register ────────────────────────────────────────────────────
            if msg_type == "register":
                name       = message.get("name", "")[:64]  # max 64 chars
                public_key = message.get("public_key")
                device_id  = message.get("device_id")

                # Canonical device_id shape check (external review
                # 2026-09-04, S6-37) — before ANY device DB lookup/write,
                # before even the identity-key checks below, since this has
                # nothing to do with which fingerprint is registering. Only
                # rejects a device_id that was actually PROVIDED and doesn't
                # match the canonical shape both real clients always send —
                # an absent/empty device_id is "missing", not "invalid", and
                # falls through unchanged into the existing TOTP-required
                # fail-closed check further below (see is_valid_device_id()'s
                # own comment). Never truncated/normalized — see that same
                # comment for why silently rewriting it would be wrong.
                if device_id and not is_valid_device_id(device_id):
                    print(f"[SECURITY] register: невалидный формат device_id от {ip}")
                    await send_safe(websocket, json.dumps({"type": "device_auth_failed"}))
                    continue

                # Same canonical bounded decode as the handshake's own
                # challenge_response (external review 2026-09-05, S6-45) —
                # hardening only the handshake would leave THIS path, reached
                # right after handshake_ok on an already-"authenticated"
                # connection, equally able to force a multi-megabyte base64/
                # DER parse merely by sending a giant register public_key,
                # even though the PROVEN handshake key was tiny. See
                # decode_identity_public_key()'s own comment for the exact
                # bounds/curve check; returns None on any failure (wrong
                # type/empty/oversized/invalid base64/unparseable DER/wrong
                # curve), all treated identically here, same as before.
                decoded_key = decode_identity_public_key(public_key)
                if decoded_key is None:
                    print(f"[SECURITY] register: невалидный/неподдерживаемый public_key от {ip}")
                    continue
                key_bytes, _ = decoded_key

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

                # CRITICAL (external review 2026-09-05, S6-39): this is a
                # CANDIDATE identity only — derived from a key whose
                # possession was proven at handshake time, but that is NOT
                # the same thing as successful registration. The connection-
                # scope `username` (declared `None` above, at function
                # entry) must stay `None` through every gate below and is
                # committed to this value ONLY inside Phase 2's successful
                # `async with lock:` commit, after every admission/
                # revocation/TOTP/device-authentication gate has actually
                # passed. Before this fix, `username = fingerprint` happened
                # HERE — before any of those gates ran — so a REJECTED
                # candidate (bad PoW, full server, wrong/absent access code,
                # revoked identity, missing/failed TOTP, invalid device
                # signature, device cap reached, ...) still left `username`
                # populated with that fingerprint for the rest of THIS
                # connection's lifetime, because every rejection below is a
                # bare `continue` (stays on the same connection, doesn't
                # close it) — a subsequent ordinary message on the SAME
                # socket was then processed as that fingerprint, bypassing
                # every gate the failed register() was supposed to enforce.
                # See SECURITY_INVARIANTS.md #52.
                candidate_username = hashlib.sha256(key_bytes).digest()[:8].hex().upper()

                is_new_fingerprint = not await db_is_fingerprint_registered(candidate_username)

                # Registration cap + proof-of-work + access-code — all keyed
                # on "is this a brand-new identity", never re-checked on
                # reconnect. Neither PoW nor the cap care about IP: a cap
                # counts real DB rows regardless of who asked, and PoW cost
                # is paid by the device doing the hashing, not routed
                # through any address the attacker chose.
                #
                # Reordered 2026-09-03 (external review, round 4) — bug
                # found live: the previous version called
                # db_try_register_new_fingerprint() (cap-check-and-INSERT)
                # HERE, before PoW was even checked below. A fingerprint
                # that then failed PoW (or, further down, the access-code
                # check) still ended up durably INSERTed into
                # registered_fingerprints — db_is_fingerprint_registered()
                # reports it as already-registered on any later attempt, so
                # is_new_fingerprint becomes False for good and NEITHER gate
                # is ever checked again for that identity. One reconnect
                # with a bogus PoW nonce (or no access_code at all) was
                # enough to permanently mint a "registered" identity — and
                # with SERVER_ACCESS_PROTECTED or MAX_REGISTERED_USERS
                # active, an attacker could burn through the user cap with
                # fingerprints that never actually passed either gate.
                #
                # Fixed by never inserting until every gate has passed: PoW
                # is checked FIRST — it's a pure computation, no DB write,
                # nothing to make atomic — and only once it passes does
                # db_admit_new_fingerprint() run the cap check, the
                # access-code consume, and the INSERT together in one
                # transaction (see its own comment for the BEGIN IMMEDIATE
                # mechanics). This also fixes a second, related bug: the old
                # ordering could consume a real access_code and THEN find
                # the server full — the code was burned for nothing. Now the
                # whole admission is one transaction, so a "full" rollback
                # never touches the access_code row at all.
                if is_new_fingerprint and POW_DIFFICULTY_BITS > 0:
                    # Bounded BEFORE hashing (external review 2026-09-05,
                    # S6-45) — both shipped clients that solve PoW represent
                    # pow_nonce as a small decimal counter string (Android's
                    # `counter.toString()` for a 64-bit counter, at most ~20
                    # digits; Desktop doesn't send PoW at all yet); see
                    # MAX_POW_NONCE_LEN's own comment. A non-string or
                    # oversized value is simply treated as an empty nonce —
                    # exactly as unable to satisfy the difficulty check as
                    # any other wrong guess, never hashed as attacker-
                    # controlled megabytes.
                    pow_nonce = message.get("pow_nonce", "")
                    if not isinstance(pow_nonce, str) or len(pow_nonce) > MAX_POW_NONCE_LEN:
                        pow_nonce = ""
                    digest = hashlib.sha256(challenge + pow_nonce.encode("utf-8", "ignore")).digest()
                    if pow_leading_zero_bits(digest) < POW_DIFFICULTY_BITS:
                        print(f"[SECURITY] register: недостаточный PoW для нового аккаунта {candidate_username} от {ip}")
                        await send_safe(websocket, json.dumps({
                            "type": "pow_required",
                            "difficulty_bits": POW_DIFFICULTY_BITS
                        }))
                        continue

                # Optional access-code allowlist — see SERVER_ACCESS_PROTECTED.
                # Only read/consumed for this fingerprint's very first-ever
                # registration; a client is free to keep sending a (by then
                # already-consumed, or simply absent) access_code on every
                # later reconnect — harmless, since it's not even looked at
                # once the fingerprint is already known.
                if is_new_fingerprint:
                    # Process-wide pre-SQLite new-ACCOUNT attempt budget
                    # (S6-56) — unlike access_code_global_rate_ok() just
                    # below, this applies to EVERY new-fingerprint attempt
                    # regardless of whether SERVER_ACCESS_PROTECTED is even
                    # on, and regardless of whether PoW is enabled: PoW is
                    # itself an optional, disableable setting
                    # (POW_DIFFICULTY_BITS=0), so it can't be the only thing
                    # standing between an attacker and hammering
                    # db_admit_new_fingerprint()'s real SQLite transaction as
                    # fast as the network allows. See its own comment for why
                    # this is abuse mitigation, not the durable-resource
                    # boundary (that's REGISTERED_ACCOUNTS_HARD_MAX_ROWS).
                    if not new_account_global_rate_ok():
                        print(f"[SECURITY] register: превышен глобальный лимит попыток регистрации нового аккаунта от {ip}")
                        await send_safe(websocket, json.dumps({"type": "registration_full"}))
                        continue
                    if SERVER_ACCESS_PROTECTED:
                        # Canonical shape validated BEFORE any DB round trip
                        # (external review 2026-09-05, S6-41) — missing,
                        # wrong-type, wrong-length, or non-hex input never
                        # reaches db_admit_new_fingerprint()/BEGIN IMMEDIATE
                        # at all. Gets the exact same generic response and
                        # connection close as a well-formed-but-wrong code
                        # below — a caller must never be able to tell
                        # malformed apart from wrong apart from nonexistent.
                        raw_access_code = message.get("access_code")
                        access_code = raw_access_code.strip().upper() if isinstance(raw_access_code, str) else ""
                        if not is_valid_access_code(access_code):
                            print(f"[SECURITY] register: невалидный формат access_code для нового аккаунта {candidate_username} от {ip}")
                            await send_safe(websocket, json.dumps({"type": "access_code_required"}))
                            await websocket.close()
                            return
                        # Process-wide pre-SQLite attempt budget (S6-41) —
                        # only syntactically-valid guesses ever count
                        # against it, so malformed junk can't burn it for
                        # free. See access_code_global_rate_ok()'s own
                        # comment for why this is process-local and not
                        # itself the credential's security boundary.
                        if not access_code_global_rate_ok():
                            print(f"[SECURITY] register: превышен глобальный лимит попыток access_code от {ip}")
                            await send_safe(websocket, json.dumps({"type": "access_code_required"}))
                            await websocket.close()
                            return
                    else:
                        access_code = ""
                    # effective_registration_cap() (S6-56), not the raw
                    # MAX_REGISTERED_USERS setting — 0/unset no longer means
                    # "no cap enforced at all" here, it means "no smaller
                    # operator-defined cap than REGISTERED_ACCOUNTS_HARD_MAX_
                    # ROWS". _db_admit_new_fingerprint_sync()'s own cap check
                    # (`if max_users > 0`) is unchanged — it always receives
                    # a strictly-positive value now, since the hard ceiling
                    # is itself always > 0.
                    admit = await db_admit_new_fingerprint(
                        candidate_username, effective_registration_cap(), access_code, SERVER_ACCESS_PROTECTED
                    )
                    if admit == "full":
                        print(f"[SECURITY] register: сервер заполнен (эффективный потолок "
                              f"{effective_registration_cap()}, оператор={MAX_REGISTERED_USERS or 'не задан'}), "
                              f"отказ новому {candidate_username} от {ip}")
                        await send_safe(websocket, json.dumps({"type": "registration_full"}))
                        continue
                    elif admit == "access_denied":
                        # Terminates this connection outright — deliberately
                        # NOT `continue` (external review 2026-09-05, S6-41).
                        # The websocket handshake's `challenge` never changes
                        # across multiple register() attempts on the SAME
                        # socket, so a solved PoW nonce would otherwise be
                        # reusable for unlimited further access-code guesses
                        # at zero additional PoW cost, and every guess would
                        # still reach a real BEGIN IMMEDIATE SQLite
                        # transaction. Closing forces a brand-new connection
                        # — a fresh random challenge, a freshly-solved PoW —
                        # per guess, independent of the code's own entropy.
                        print(f"[SECURITY] register: неверный/отсутствующий access_code для нового аккаунта {candidate_username} от {ip}")
                        await send_safe(websocket, json.dumps({"type": "access_code_required"}))
                        await websocket.close()
                        return
                    # "ok" or "exists" (lost an admission race to a
                    # concurrent connection proving the same private key) —
                    # either way this fingerprint is now durably registered,
                    # proceed exactly as the pre-existing flow did.

                # Identity revoked via "Меня скомпрометировали" (revoke_identity,
                # below) — the challenge/response handshake still proves
                # possession of the private key, but possession alone is no
                # longer enough once the real owner has revoked it. Not
                # federation-exempt: revocation is meaningful precisely because
                # the fingerprint is derived from a key someone else may now
                # also hold.
                if await db_is_fingerprint_revoked(candidate_username):
                    print(f"[SECURITY] register: отклонена регистрация отозванного fingerprint {candidate_username} от {ip}")
                    await send_safe(websocket, json.dumps({"type": "identity_revoked"}))
                    continue

                # Device-gated registration TOTP — durable, per-fingerprint
                # device AUTHENTICATION (external review 2026-09-03, round
                # 2), not "is this the one device_id currently live in
                # clients[]" (round 1's bug) and not "does the client merely
                # know an authorized device_id string" (round 1's fix, still
                # a bearer-token weakness — see below).
                #
                # Round 1 bug: the old is_new_device check compared device_id
                # against clients.get(username) — purely in-memory, gone the
                # instant the real owner's app closes OR the server
                # restarts. An attacker holding a stolen identity private
                # key could pass challenge/response (proves key possession
                # only, nothing about TOTP) and register() with any
                # device_id the moment `existing` was None — TOTP was never
                # even asked for. Fixed by making "has this device_id been
                # authorized" durable (authorized_devices, below).
                #
                # Round 2 bug: device_id is just a client-supplied string —
                # sent in the clear on every register(), nothing about it is
                # secret. An attacker with a stolen identity private key who
                # also learned a legitimate device_id (not hard — it's not a
                # secret, just an identifier) could send that same string
                # and have the round-1 durable check answer "already
                # authorized", skipping TOTP entirely. Real device
                # authentication needs a credential the string alone can't
                # substitute for: a separate device keypair, generated
                # on-device and deliberately excluded from the identity
                # backup (so a stolen identity-key backup alone still can't
                # produce a valid device signature), proving live possession
                # by signing SUBROSA_DEVICE_V1 || challenge || username ||
                # device_id on EVERY register() — not just first enrollment,
                # since challenge is fresh per-connection and this is what
                # actually stops a captured device_id string (or even a
                # captured signature from a past connection) from being
                # replayed. The client sends device_public_key (DER,
                # base64) and device_signature (base64) alongside device_id.
                #
                # Critical invariant enforced below and in
                # db_bind_device_pubkey(): once a device_id has a pinned
                # pubkey, it is NEVER replaced — an attacker sending a
                # matching device_id with a DIFFERENT key they control must
                # be refused outright (device_auth_failed), not silently
                # treated as "unknown device, please prove TOTP" (which
                # would let a successful TOTP/recovery-code compromise
                # re-pin someone else's device_id to the attacker's key).
                #
                # Fixed the same ordering way as the fingerprint-registration
                # gate (db_admit_new_fingerprint): nothing is durably pinned
                # until every gate has passed — db_bind_device_pubkey() below
                # is only ever called after totp_rejected is known to be
                # False. A device that already passed this once stays
                # authorized forever (until removed, not implemented — see
                # revoke_identity for the fingerprint-level equivalent),
                # independent of whether its session is currently live — but
                # it must still resign the challenge on every single
                # reconnect; only the TOTP/recovery-code step is skipped for
                # an already-pinned device.
                #
                # Fail-closed on an empty device_id, or a missing/malformed
                # device_public_key/device_signature, when TOTP is
                # configured (external review 2026-09-03) — a custom/
                # malicious client could otherwise omit these to dodge the
                # whole check below. The official client always sends a
                # real device_id and, once it supports this, a real device
                # signature; only a nonstandard client would ever hit this.
                device_needs_totp = False
                device_pubkey_bytes = None
                # Account-scoped TOTP-state lock (external review
                # 2026-09-04, S6-32) — held from the FIRST decision derived
                # from `username in user_totp_secrets` through the entire
                # device-admission phase below, released only right before
                # Phase 2's global `lock`. See totp_state_locks' own comment
                # for the race this closes: without this, a concurrent
                # totp_setup/totp_disable for this SAME fingerprint could
                # durably commit to SQLite while this coroutine is suspended
                # on one of the `await`s below, and this coroutine would
                # then finish acting on the STALE `user_totp_secrets` read
                # it took before ever acquiring the lock. Narrow and
                # per-account, not the global `lock` — DB `await`s are fine
                # while holding this one, and it never blocks a DIFFERENT
                # fingerprint's register().
                async with get_totp_state_lock(candidate_username):
                    if candidate_username in user_totp_secrets:
                        if not device_id:
                            print(f"[SECURITY] register: пустой device_id при включённой TOTP-защите для {candidate_username} от {ip}")
                            await send_safe(websocket, json.dumps({"type": "totp_required"}))
                            continue

                        device_public_key_b64 = message.get("device_public_key")
                        device_signature_b64  = message.get("device_signature")
                        if not device_public_key_b64 or not device_signature_b64:
                            print(f"[SECURITY] register: отсутствует device_public_key/device_signature для {candidate_username}/{device_id} от {ip}")
                            await send_safe(websocket, json.dumps({"type": "device_auth_failed"}))
                            continue
                        # Protocol-bounded BEFORE base64/DER parsing (external
                        # review 2026-09-04, S6-37) — these two fields carry a
                        # single EC key/signature (real size: ~124/~96-100
                        # base64 chars respectively, see MAX_DEVICE_PUBKEY_
                        # B64_LEN's own comment), never megabytes of
                        # legitimate data; a plain length check here is free
                        # and rejects oversized input before it ever reaches
                        # base64.b64decode()/load_der_public_key().
                        if (not isinstance(device_public_key_b64, str)
                                or not isinstance(device_signature_b64, str)
                                or len(device_public_key_b64) > MAX_DEVICE_PUBKEY_B64_LEN
                                or len(device_signature_b64) > MAX_DEVICE_SIGNATURE_B64_LEN):
                            print(f"[SECURITY] register: превышен допустимый размер device_public_key/device_signature для {candidate_username}/{device_id} от {ip}")
                            await send_safe(websocket, json.dumps({"type": "device_auth_failed"}))
                            continue
                        try:
                            supplied_device_pubkey = base64.b64decode(device_public_key_b64, validate=True)
                            device_sig_bytes       = base64.b64decode(device_signature_b64, validate=True)
                        except Exception:
                            print(f"[SECURITY] register: невалидный base64 в device_public_key/device_signature для {candidate_username} от {ip}")
                            await send_safe(websocket, json.dumps({"type": "device_auth_failed"}))
                            continue

                        device_row_exists, stored_device_pubkey = await db_get_authorized_device(candidate_username, device_id)

                        if device_row_exists and stored_device_pubkey is not None:
                            # Pinned already — the supplied key MUST match the
                            # stored one exactly. A mismatch here is either an
                            # attacker who knows the device_id string but not
                            # the real device's private key, or a legitimate
                            # device that lost its local device keypair (e.g.
                            # reinstall) — either way, this device_id is refused
                            # outright; a genuinely reinstalled client should
                            # generate a fresh device_id and go through the
                            # brand-new-device TOTP flow again, not silently
                            # take over the old device_id's trust.
                            if supplied_device_pubkey != stored_device_pubkey:
                                print(f"[SECURITY] register: device_pubkey НЕ совпадает с закреплённым для {candidate_username}/{device_id} от {ip} — возможная попытка угона device_id")
                                await send_safe(websocket, json.dumps({"type": "device_auth_failed"}))
                                continue
                            verify_pubkey_bytes = stored_device_pubkey
                            device_needs_totp = False
                        else:
                            # Brand-new device_id, or a legacy row with no
                            # pubkey pinned yet — first-time binding, needs
                            # TOTP/recovery regardless of whether the row itself
                            # already existed.
                            verify_pubkey_bytes = supplied_device_pubkey
                            device_pubkey_bytes = supplied_device_pubkey
                            device_needs_totp = True

                        try:
                            from cryptography.hazmat.primitives import serialization as _ser, hashes as _hashes
                            from cryptography.hazmat.primitives.asymmetric import ec as _ec
                            from cryptography.hazmat.backends import default_backend as _default_backend

                            device_pub = _ser.load_der_public_key(verify_pubkey_bytes, backend=_default_backend())
                            # candidate_username, not committed `username` --
                            # this is signing over the fingerprint BEING
                            # registered, which is exactly what must be
                            # authenticated here regardless of whether
                            # registration ultimately succeeds (S6-39).
                            signed_data = b"SUBROSA_DEVICE_V1" + challenge + candidate_username.encode("utf-8") + device_id.encode("utf-8")
                            device_pub.verify(device_sig_bytes, signed_data, _ec.ECDSA(_hashes.SHA256()))
                        except Exception:
                            print(f"[SECURITY] register: неверная device_signature для {candidate_username}/{device_id} от {ip}")
                            await send_safe(websocket, json.dumps({"type": "device_auth_failed"}))
                            continue

                    # Second-factor online-brute-force guard (external review
                    # 2026-09-04) — gates the TOTP/recovery-code proof about to
                    # be checked below, before it's checked, not after: the
                    # attempt is spent regardless of whether the code turns out
                    # right. Deliberately called BEFORE `async with lock:` below
                    # (a separate, already-flagged issue: awaiting a blocking
                    # DB call while holding the server-wide lock would serialize
                    # every connection's register()/TOTP path on this one call)
                    # — see db_take_second_factor_attempt()'s own comment.
                    if device_needs_totp:
                        if not await db_take_second_factor_attempt(candidate_username):
                            print(f"[SECURITY] register: second-factor rate limit для {candidate_username}/{device_id} от {ip}")
                            await send_safe(websocket, json.dumps({"type": "second_factor_rate_limited"}))
                            continue

                    # ── Phase 1: every security/DB proof, WITHOUT the global
                    # lock (external review 2026-09-04) — found live:
                    # totp_verify_and_consume()/db_check_and_consume_recovery_code()/
                    # db_bind_device_pubkey()/db_authorize_device() are all
                    # `await`ed SQLite calls (run in an executor thread), and
                    # this whole block used to run INSIDE `async with lock:`
                    # below. asyncio.Lock() doesn't block the event loop itself,
                    # but every OTHER coroutine anywhere in the server that
                    # needs this same lock — nearly everything, it's the one
                    # server-wide lock — has to wait for whichever of these DB
                    # calls is currently in flight, for as long as SQLite takes
                    # under contention. A purely per-connection proof check
                    # (this account's TOTP code) became a server-wide
                    # availability bottleneck. None of these calls touch shared
                    # RAM (`clients`/`authenticated_users`/etc.) — only Phase 2
                    # below does, and that's genuinely RAM-only and fast; see
                    # SECURITY_INVARIANTS.md's invariant for this split. (The
                    # totp_state_lock held around this whole block is a
                    # DIFFERENT, narrower lock than the global `lock` this
                    # comment refers to — see totp_state_locks' own comment.)
                    totp_rejected = False
                    recovery_used = False
                    # None = no bind attempted / not reached; otherwise one
                    # of db_bind_device_pubkey()'s explicit statuses other
                    # than "BOUND"/"ALREADY_MATCHED" (S6-37) — "FULL" gets
                    # its own distinct wire response below, everything else
                    # (should be unreachable, see that function's own
                    # comment) falls back to the generic device_auth_failed.
                    device_bind_status = None

                    if device_needs_totp:
                        totp_code = message.get("totp_code", "")
                        if not await totp_verify_and_consume(candidate_username, totp_code):
                            # Lost-authenticator fallback — a valid, unused
                            # recovery code substitutes for the TOTP code.
                            #
                            # Changed 2026-08-30 (docs/TODO.md "recovery-code
                            # takeover window" decision): this used to wipe
                            # the secret AND every other unused code on a
                            # single successful use — meaning any FUTURE
                            # new-device registration under this fingerprint
                            # needed no code at all, forever, until someone
                            # noticed and manually re-enrolled. That's a much
                            # bigger window than "one recovery event" implies.
                            # Now only the single code just used is consumed
                            # (db_check_and_consume_recovery_code already does
                            # this atomically) — the secret and remaining
                            # codes stay live, so every subsequent new-device
                            # registration still needs a TOTP code or one of
                            # the dwindling recovery codes, not nothing.
                            # Re-enrollment (getting a genuinely fresh secret)
                            # is still available, deliberately, via the
                            # totp_setup/totp_disable recovery-code path added
                            # in this same change (see those handlers below) —
                            # a user who just proved they lost their
                            # authenticator can immediately spend one more
                            # code to properly replace it, rather than being
                            # locked out of re-enrolling until codes run out.
                            # S6-48: is_valid_recovery_code() checked before
                            # this proof runs — db_check_and_consume_
                            # recovery_code() has no internal shape guard of
                            # its own, so a huge recovery_code would
                            # otherwise still reach _hash_recovery_code()'s
                            # strip()/upper()/SHA-256.
                            recovery_code = message.get("recovery_code", "")
                            if is_valid_recovery_code(recovery_code) and await db_check_and_consume_recovery_code(candidate_username, recovery_code):
                                recovery_used = True
                            else:
                                totp_rejected = True

                    if recovery_used:
                        print(f"[SECURITY] {candidate_username}: новое устройство зашло по recovery-коду (TOTP-защита остаётся включена, потрачен один код)")

                    if not totp_rejected:
                        # Only ever reached once any required TOTP/recovery
                        # check above has actually succeeded (or wasn't
                        # required at all) — see this whole block's own
                        # comment above for why nothing gets pinned any
                        # earlier than this.
                        if device_pubkey_bytes is not None:
                            # First-time pin — device_needs_totp was True,
                            # meaning this device_id (or a legacy row for
                            # it) had no pubkey pinned yet, and TOTP/recovery
                            # just succeeded. db_bind_device_pubkey() is the
                            # atomic never-overwrite commit — see its own
                            # comment; a False return here should be
                            # unreachable (register()'s own pubkey-match
                            # check above already refuses a mismatch before
                            # this point), but is treated as an outright
                            # failure rather than silently proceeding.
                            bind_status = await db_bind_device_pubkey(candidate_username, device_id, device_pubkey_bytes)
                            if bind_status == "FULL":
                                print(f"[SECURITY] register: MAX_AUTHORIZED_DEVICES_PER_ACCOUNT достигнут для {candidate_username} (device_id={device_id}) от {ip}")
                                device_bind_status = "FULL"
                            elif bind_status not in ("BOUND", "ALREADY_MATCHED"):
                                print(f"[SECURITY] register: db_bind_device_pubkey отказал ({bind_status}) для {candidate_username}/{device_id} от {ip} — не должно быть достижимо")
                                device_bind_status = bind_status
                        # else: TOTP configured AND device was already
                        # pinned (device_needs_totp was False from the
                        # start) — signature already verified above against
                        # the stored key this connection; nothing new to
                        # persist.
                        #
                        # Removed (external review 2026-09-04, S6-37): a
                        # third branch used to durably INSERT a NULL-pubkey
                        # `authorized_devices` row here whenever TOTP wasn't
                        # configured at all — `elif device_id and username
                        # not in user_totp_secrets: await
                        # db_authorize_device(username, device_id)`. A
                        # NULL-pubkey row confers no trust by itself (see
                        # is_valid_device_id()'s/db_get_authorized_device()'s
                        # own comments): `device_needs_totp` above treats "no
                        # row" and "row exists, pubkey NULL" identically —
                        # both still require TOTP/recovery-proof PLUS a valid
                        # device signature before db_bind_device_pubkey()
                        # ever pins anything. With TOTP disabled, that old
                        # branch durably grew `authorized_devices` by one row
                        # per unique device_id, forever, for zero security
                        # benefit — an authenticated account could reconnect
                        # repeatedly with a fresh device_id every time and
                        # grow the table without bound (see
                        # MAX_AUTHORIZED_DEVICES_PER_ACCOUNT below for the
                        # cap that now also protects the TOTP-enabled
                        # pinning path itself). `clients[username]["device_
                        # id"]` (Phase 2, RAM-only, below) already tracks the
                        # live session's device_id for session-conflict
                        # purposes — nothing durable was ever needed for the
                        # TOTP-disabled case. `db_authorize_device()` itself
                        # removed as dead code — this was its only caller.
                # ── totp_state_lock released here, BEFORE Phase 2's global
                # `lock` below — lock ordering is deliberately never
                # inverted (totp_state_lock → release → global `lock`, never
                # the other way around, and never both held at once).

                if totp_rejected:
                    print(f"[SECURITY] register: неверный/отсутствующий TOTP-код для нового устройства {candidate_username} от {ip}")
                    await send_safe(websocket, json.dumps({"type": "totp_required"}))
                    continue

                if device_bind_status == "FULL":
                    await send_safe(websocket, json.dumps({"type": "device_limit_reached"}))
                    continue
                elif device_bind_status is not None:
                    await send_safe(websocket, json.dumps({"type": "device_auth_failed"}))
                    continue

                # ── Phase 2: short RAM-only commit under the global lock.
                # By construction, nothing below `await`s a DB call or does
                # network I/O while holding `lock` — `asyncio.create_task()`
                # only SCHEDULES a coroutine, it does not await it, so it
                # doesn't hold the lock open for that scheduled work.
                #
                # This is also the ONLY place the connection-scope `username`
                # is ever assigned (S6-39) — every gate above has now
                # succeeded, so `candidate_username` graduates into the
                # committed application identity for this connection exactly
                # here, atomically with the `clients`/`authenticated_users`
                # writes below. `authenticated_users[websocket]` is the
                # authoritative record of "this socket completed
                # registration" that the rest of the client loop's hard
                # authorization boundary checks against (see the `msg_type
                # != "register"` gate near the top of this loop).
                async with lock:
                    existing = clients.get(candidate_username)
                    # Purely a live-routing decision now (whether to kick an
                    # existing WebSocket session) — the security-relevant
                    # "has this device ever been authorized" question was
                    # already answered from durable state in Phase 1 above,
                    # not from whatever happens to be in `clients` right now.
                    is_different_live_device = bool(
                        existing and device_id and existing.get("device_id")
                        and device_id != existing.get("device_id")
                    )

                    if existing:
                        if is_different_live_device:
                            # Другое устройство — вытесняем старую сессию
                            print(f"[SESSION_CONFLICT] {candidate_username}: новое устройство, закрываем старую сессию")
                            conflict_ts = time.time()
                            asyncio.create_task(send_safe(existing["ws"], json.dumps({"type": "session_conflict", "ts": conflict_ts})))
                            asyncio.create_task(existing["ws"].close())
                            # Old session may not be connected by the time this fires
                            # (backgrounded/killed app) — push a visible notification
                            # through FCM too, not just the WebSocket message.
                            existing_fcm_token = existing.get("fcm_token")
                            if existing_fcm_token:
                                schedule_fcm_session_conflict(candidate_username, existing_fcm_token, conflict_ts)
                        else:
                            print(f"[RECONNECT] {candidate_username} переподключился")
                            asyncio.create_task(existing["ws"].close())

                    clients[candidate_username] = {
                        "ws":         websocket,
                        "name":       name,
                        "public_key": public_key,
                        "device_id":  device_id
                    }
                    authenticated_users[websocket] = candidate_username
                    username = candidate_username

                if username in rate_limits:
                    rate_limits[username]["disconnected_at"] = 0
                else:
                    cleanup_stale_rate_limits()

                print(f"[OK] Зарегистрирован: {username}")
                # db_mark_fingerprint_registered() call removed from here
                # (external review 2026-08-23) -- new fingerprints are now
                # inserted atomically at the cap-check above, the single
                # source of truth; this late, unawaited duplicate served no
                # purpose beyond what INSERT OR IGNORE already made a no-op.

                # Explicit, unconditional success acknowledgment (external
                # review 2026-09-05, S6-40) — before this, there was no wire
                # signal at all marking "registration actually committed";
                # every current failure path already has its own explicit
                # reply (totp_required/device_auth_failed/registration_
                # full/...), but success was purely implicit (inferred from
                # the absence of an error, or from whatever OTHER message
                # happened to arrive next). Sent as the very FIRST reply
                # after this point specifically so a client can treat it as
                # the one authoritative "safe to send account-scoped
                # traffic now" signal — see Android's MessengerService.kt
                # `registrationReady` synchronization point, which this
                # message exists to drive (fixes the register_bundle-
                # before-register race the S6-39 compatibility exception
                # temporarily tolerated).
                await send_safe(websocket, json.dumps({"type": "register_ok"}))

                # ── Обмен аватарами (S6-50) ───────────────────────────────────
                # register()'s avatar field now routes through the SAME
                # canonical admission path profile_update uses — no
                # independent validator, no independent rate bucket, and a
                # reconnect carrying the SAME avatar (the overwhelmingly
                # common case — Android includes it on every register(), not
                # just the first) costs nothing at all. See
                # apply_avatar_mutation()'s own comment for the exact
                # ordering/statuses.
                incoming_avatar = message.get("avatar", "")
                await apply_avatar_mutation(username, incoming_avatar)

                # Отправляем регистрирующемуся аватары — ограниченный снимок
                # (S6-50). Раньше отправлялся ВЕСЬ user_avatars безусловно на
                # каждый коннект/реконнект, так что один реконнект стоил
                # O(число аккаунтов на сервере) исходящего трафика независимо
                # от того, сколько из них реально нужны этому клиенту. Android
                # уже восстанавливает аватары контактов из собственного
                # локального кэша (ChatStorage) на каждый реконнект и
                # отдельно запрашивает конкретный аватар по требованию через
                # get_key(), когда публичный ключ контакта ещё не закэширован
                # — этот снимок остаётся лишь запасным путём для случая
                # "контакт обновил аватар, пока я был офлайн, а его ключ у
                # меня уже есть", не единственным способом когда-либо узнать
                # чей-то аватар. Не отсортировано по свежести (произвольное
                # подмножество текущего порядка user_avatars при достижении
                # любого из потолков) — намеренный компромисс, см.
                # AVATAR_SYNC_MAX_COUNT/AVATAR_SYNC_MAX_TOTAL_BYTES.
                known_snapshot = dict(user_avatars)
                sent_avatar_count = 0
                sent_avatar_bytes = 0
                for uid, av in known_snapshot.items():
                    if uid == username or not av:
                        continue
                    if (sent_avatar_count >= AVATAR_SYNC_MAX_COUNT
                            or sent_avatar_bytes + len(av) > AVATAR_SYNC_MAX_TOTAL_BYTES):
                        break
                    await send_safe(websocket, json.dumps({
                        "type": "avatar_data",
                        "from": uid,
                        "avatar": av
                    }))
                    sent_avatar_count += 1
                    sent_avatar_bytes += len(av)

                # ── Deliver queued offline messages (S6-55) ───────────────────
                # Bounded PEEK → send → delete-only-on-success, replacing the
                # old db_flush()'s SELECT-then-DELETE-ALL — that shape
                # destroyed every queued row before even the first websocket
                # send was attempted, so a disconnect mid-flush silently lost
                # every message that hadn't been sent yet (see
                # db_delete_pending_row()'s own comment). A row is durable
                # until send_safe() for THAT row returns True; a failed or
                # interrupted send leaves it and every later row in SQLite
                # for the next reconnect, preserving FIFO order. Held under
                # get_pending_flush_lock(username) (STEP 6) so an evicted OLD
                # connection's own still-running flush loop for this same
                # account can't interleave with this NEW one.
                total_delivered = 0
                async with get_pending_flush_lock(username):
                    while clients.get(username, {}).get("ws") is websocket:
                        rows = await db_peek_pending(username, PENDING_MESSAGES_FLUSH_BATCH_SIZE)
                        if not rows:
                            break
                        stopped_early = False
                        for row_id, payload_str, _payload_bytes in rows:
                            if not await send_safe(websocket, payload_str):
                                # STOP IMMEDIATELY — this row and every row
                                # after it in the batch/backlog stay durable.
                                # No catching this and continuing to the next
                                # row: that would silently skip over an
                                # unsent message instead of leaving it queued.
                                stopped_early = True
                                break
                            await db_delete_pending_row(username, row_id)
                            total_delivered += 1
                        if stopped_early or len(rows) < PENDING_MESSAGES_FLUSH_BATCH_SIZE:
                            break
                if total_delivered:
                    print(f"[QUEUE] Доставлено {total_delivered} отложенных сообщений")

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
            # Legacy message type — still sent by Android unconditionally on
            # every connect (MessengerService.kt), now only AFTER the
            # client's own registrationReady synchronization point confirms
            # this socket's `register` actually committed (external review
            # 2026-09-05, S6-40 — closes the register_bundle-before-register
            # race that used to require a temporary pre-registration
            # exception here; see the hard-authorization-boundary comment
            # above). Reachable only from an already-committed registered
            # connection now, same as every other message type below.
            # Thin adapter to the same canonical storage store_prekey_bundle()
            # writes for publish_prekey_bundle below (external review
            # 2026-09-04) — see that function's own comment for the OPK
            # single-use bypass this closes. Do NOT reintroduce a separate
            # `prekey_bundles[username] = bundle` write here.
            if msg_type == "register_bundle":
                # Shared "prekey_publish" bucket with publish_prekey_bundle
                # below, NOT a separate "register_bundle" key (external
                # review 2026-09-04) — both reach the same durable
                # store_prekey_bundle() write; a separate bucket per
                # message type would let a client double its effective
                # write rate by alternating between the two. See
                # SECURITY_INVARIANTS.md #40.
                if not rate_limit_check(username, "prekey_publish"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                # Aggregate, server-wide budget checked SECOND, still before
                # any bundle validation or durable work (external review
                # 2026-09-04, S6-28) — the per-user bucket alone doesn't
                # bound total write load under open registration: an
                # attacker who mints many identities gets a fresh
                # "prekey_publish" allowance per identity, multiplying the
                # aggregate SQLite write rate linearly. Same generic error
                # as the per-user rejection above — a caller must not be
                # able to tell which bucket was exhausted. See
                # SECURITY_INVARIANTS.md #41.
                if not global_prekey_publish_rate_ok():
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                bundle     = message.get("bundle")
                bundle_str = json.dumps(bundle) if bundle else ""
                if len(bundle_str) > MAX_BUNDLE_SIZE_BYTES:
                    print(f"[SECURITY] Слишком большой bundle (register_bundle) от {username}")
                    report_violation(username, "oversized bundle")
                    continue
                if await store_prekey_bundle(username, bundle):
                    print(f"[OK] Prekey bundle зарегистрирован: {username}")
                continue

            if not username and not is_anon_channel:
                continue

            if username and check_banned(username):
                await websocket.send(json.dumps({"type": "error", "reason": "You are temporarily banned"}))
                continue

            # ─── Profile Update (аватар) ──────────────────────────────────────
            if msg_type == "profile_update":
                # S6-50: the standalone rate_limit_check() call that used to
                # sit here (consuming the "profile_update" bucket for EVERY
                # profile_update message regardless of content) is removed —
                # apply_avatar_mutation() now owns that admission decision,
                # and only actually consumes it for a genuine change, so
                # register() and profile_update share exactly one bucket
                # instead of register's avatar field bypassing this one
                # entirely (the original vulnerability this patch closes).
                new_avatar = message.get("avatar", "")
                status = await apply_avatar_mutation(username, new_avatar)
                if status == "RATE_LIMITED":
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                elif status == "STORED":
                    print(f"[AVATAR] Обновлён и разослан аватар: {username}")
                continue

            if msg_type == "read":
                to         = message.get("to")
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers() (external review 2026-09-05, S6-42) —
                # `to` here always means a real account; silently dropped,
                # same as get_prekey_bundle's own target check.
                if not is_valid_fingerprint(to):
                    continue
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
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store() (external review 2026-09-05,
                # S6-42) — see is_valid_fingerprint()'s own comment and
                # OFFLINE_MSG_ID_MAX_LEN's own comment for the durable-queue
                # byte-cap bypass this closes for every db_store() path.
                if not is_valid_fingerprint(to):
                    continue
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

            # request_prekey (legacy, pre-dates the canonical
            # get_prekey_bundle/get_prekey_bundles_batch OPK-consumption
            # design) removed entirely (external review 2026-09-04) —
            # neither Android nor Desktop send this type (grepped both
            # client trees, zero hits). It returned prekey_bundles[target]
            # completely as-is: no opks.pop(0), no persisted OPK-consumed
            # state, no bootstrap_token, no revoked-fingerprint flag — a
            # second, weaker wire path to the exact same bundle data that
            # bypassed every single-use/anonymity/revocation guarantee
            # get_prekey_bundle enforces. Since it's dead client-side,
            # removing the surface is strictly better than hardening a
            # handler nothing calls; also removed from ALLOWED_TYPES below.

            # ─── Publish Prekey Bundle ────────────────────────────────────────
            if msg_type == "publish_prekey_bundle":
                # Previously had NO rate limit at all here (external review
                # 2026-09-04) — now that both this and register_bundle
                # above reach the same durable store_prekey_bundle() write
                # (a real SQLite transaction, per-target mutation-lock
                # acquisition, and executor-thread work), an authenticated
                # client could otherwise spam this message type
                # indefinitely to force unbounded DB writes. Shares the
                # SAME "prekey_publish" bucket as register_bundle, not a
                # separate one — see that handler's own comment and
                # SECURITY_INVARIANTS.md #40. Checked BEFORE size
                # validation or any DB/lock work, so a flood of malformed
                # requests is capped by this same bucket too.
                if not rate_limit_check(username, "prekey_publish"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                # Aggregate, server-wide budget checked SECOND, same generic
                # error, same bucket register_bundle above shares (external
                # review 2026-09-04, S6-28) — see that handler's comment and
                # SECURITY_INVARIANTS.md #41.
                if not global_prekey_publish_rate_ok():
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                bundle     = message.get("bundle")
                bundle_str = json.dumps(bundle) if bundle else ""
                if len(bundle_str) > MAX_BUNDLE_SIZE_BYTES:
                    print(f"[SECURITY] Слишком большой bundle от {username}")
                    report_violation(username, "oversized bundle")
                    continue
                if await store_prekey_bundle(username, bundle):
                    print(f"[PREKEY] Bundle сохранён для {username}")
                continue

            # ─── Get Prekey Bundle ────────────────────────────────────────────
            if msg_type == "get_prekey_bundle":
                if not rate_limit_check(username, "prekey_fetch"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue

                target = message.get("target")
                # Canonical-fingerprint validation BEFORE any consume/DB/
                # lock-registry work (external review 2026-09-04, S6-35) —
                # consume_prekey_bundle_for_serve() below acquires
                # prekey_mutation_guard(target) before knowing whether
                # target is even real; without this check, an authenticated
                # client could mint one permanent-until-pruned lock-registry
                # entry per unique garbage string it sent (see
                # is_valid_fingerprint()'s own comment) — silently dropped,
                # same as any other malformed-input rejection in this file
                # (e.g. mailbox_put's tag/blob shape check).
                if not is_valid_fingerprint(target):
                    continue
                # Durable OPK consumption (external review 2026-09-04) — see
                # consume_prekey_bundle_for_serve()'s own comment and
                # SECURITY_INVARIANTS.md #39. This used to pop the OPK from
                # the RAM cache under `lock`, THEN fire-and-forget
                # db_save_bundle() afterward — a crash in that window (or
                # simply the process dying before the create_task() ever
                # ran) meant the SAME OPK could be handed out again on
                # restart or to a concurrent requester. The canonical path
                # commits the SQLite removal FIRST; an OPK is only ever
                # returned once that commit has actually succeeded.
                bundle_to_send, _remaining = await consume_prekey_bundle_for_serve(target, username)

                if bundle_to_send is not None:
                    # Attached fresh at serve time (not stored with the bundle,
                    # so it can never go stale between publishes) — lets the
                    # requester deliver session_init anonymously via anon_message
                    # instead of a directly-addressed packet. Omitted if target
                    # is offline or has no currently-registered tokens.
                    bootstrap_token = await pick_bootstrap_token(target, username)
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
                # Filtered to canonical fingerprints (was merely
                # `isinstance(t, str)`) BEFORE any bundle/DB/cache work,
                # still capped at MAX_BATCH_BUNDLE_TARGETS afterward — same
                # is_valid_fingerprint() gate as get_prekey_bundle/
                # federated_get_bundle (external review 2026-09-04, S6-35).
                # A non-canonical decoy/real target here would otherwise
                # still reach the `prekey_bundles.get(t)`/bootstrap-token
                # lookups below for free — never a lock-registry entry
                # (this path never consumes an OPK), but still needless
                # cache-lookup cost for garbage input.
                targets = [t for t in targets if is_valid_fingerprint(t)][:MAX_BATCH_BUNDLE_TARGETS]

                results = {}
                # Bootstrap-token resolution split into peek (RAM, under
                # `lock`) + resolve (DB, outside `lock`) — same reasoning as
                # pick_bootstrap_token() itself (see its own comment):
                # db_resolve_bootstrap_token() is a DB round-trip and must
                # not run while holding the same lock every other connection
                # needs for its own prekey_bundles/ws_to_tokens reads.
                candidates = {}
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
                        results[t] = bundle_to_send
                        peeked = _peek_bootstrap_candidates(t)
                        if peeked:
                            candidates[t] = peeked

                # requester is `username` for every target in the batch,
                # decoys included — see pick_bootstrap_token()'s own comment
                # for why this is per-(target, requester), not just
                # per-target: without it, one batched call already reserves
                # a token per real+decoy target, and repeating the SAME
                # batch call would otherwise keep minting new reservations
                # instead of resolving back to the ones already held. This
                # doesn't hand the server any information it doesn't already
                # have — this handler only runs on an authenticated
                # connection that already identified itself as username, and
                # already sees the full targets list in plaintext.
                candidate_items = list(candidates.items())
                if candidate_items:
                    resolved = await asyncio.gather(
                        *(db_resolve_bootstrap_token(toks, t, username) for t, toks in candidate_items)
                    )
                    for (t, _toks), (status, tok) in zip(candidate_items, resolved):
                        if status in ("existing", "reserved"):
                            results[t]["bootstrap_token"] = tok

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

            # ─── Get Decoy Candidates (metadata-protection hardening) ──────────
            # get_prekey_bundles_batch's decoys are the REQUESTER's OWN existing
            # contacts (see that handler's comment) — which gives a brand-new or
            # lightly-connected account (few or zero contacts) no real cover at
            # all; requestPrekeyBundle() on the client falls back to a fully
            # non-anonymous single-target fetch in exactly that case today. This
            # endpoint lets the client pad its decoy pool with OTHER accounts on
            # this deployment that it doesn't already know, so the effective
            # anonymity set becomes "how many accounts are on this server" rather
            # than "how many contacts does this one user happen to have".
            #
            # Deliberately hands out bare fingerprints only, never bundle
            # content — the client still has to go through
            # get_prekey_bundles_batch (which never consumes an OPK) to actually
            # fetch anything, so this can't be used to read key material or to
            # burn a stranger's one-time prekey. Sampled from `prekey_bundles`
            # (accounts with a CURRENTLY published bundle) rather than the full
            # `registered_fingerprints` table, so every candidate returned looks
            # equally "live" — a decoy with no bundle at all would come back null
            # from the batch fetch while the real target doesn't, trivially
            # un-mixing the two by elimination.
            #
            # Residual gap, stated plainly: this does teach the server "these N
            # fingerprints exist and have published bundles", which a pure
            # contacts-only decoy pool never revealed. Accepted deliberately —
            # within a single-deployment, single-company server this is not new
            # information (colleagues already know roughly who else is on the
            # same install), and the alternative (no server-assisted decoys) is
            # the status quo bug this closes: a lone/lightly-connected account
            # getting literally zero cover. Freshly sampled on every call, never
            # cached or replayed server-side — reusing the same decoy set across
            # multiple real bootstrap events would let a logging adversary tell
            # "stable across requests" (decoy) apart from "the one that changes"
            # (real target) by simple set intersection over time.
            if msg_type == "get_decoy_candidates":
                if not rate_limit_check(username, "decoy_candidates"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                requested = message.get("count", 0)
                count = requested if isinstance(requested, int) else 0
                count = max(0, min(count, MAX_BATCH_BUNDLE_TARGETS - 1))
                async with lock:
                    pool = [fp for fp in prekey_bundles.keys() if fp != username]
                    candidates = _SECURE_RANDOM.sample(pool, min(count, len(pool))) if count and pool else []
                await websocket.send(json.dumps({
                    "type": "decoy_candidates_result",
                    "candidates": candidates
                }))
                continue

            # ─── Get Public Key (legacy) ──────────────────────────────────────
            if msg_type == "get_key":
                # Rate-limited + canonical-target-validated (external review
                # 2026-09-06, S6-50) — previously the one remaining
                # unrestricted-rate bandwidth endpoint: a public key AND (if
                # cached) a full avatar payload on every single call, no
                # rate limit at all, and no shape check on `target` before
                # either dict lookup. Mirrors get_prekey_bundle's own
                # ordering exactly: rate check first (explicit error reply,
                # same as every other rate-limited handler), then a
                # canonical-fingerprint check on `target` (silently dropped
                # if malformed, same posture as every other account-
                # fingerprint handler, S6-42) before either lookup.
                if not rate_limit_check(username, "get_key"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                target = message.get("target")
                if not is_valid_fingerprint(target):
                    continue
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
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers() (external review 2026-09-05, S6-42).
                if not is_valid_fingerprint(to):
                    continue
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
                # Canonical-fingerprint validation before clients.get()
                # (external review 2026-09-05, S6-42).
                if not is_valid_fingerprint(to):
                    continue
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps({"type": "session_reset", "from": username}))
                # ephemeral — not queued for offline delivery
                continue

            # ─── Sender Certificate (Sealed Sender, шаг 1) ──────────────────────
            # Клиент просит сервер подтвердить "это я" по обычному, уже
            # аутентифицированному соединению — тут нечего скрывать, запрос не
            # содержит адресата (в отличие от anon_message/session_init).
            # Сертификат кладётся ВНУТРЬ sealed-конверта (sealPacketForRecipient)
            # получателем не читается сервером — получатель проверяет подпись
            # сам, зная публичный ключ сервера. verified_public_key — тот же
            # ключ, что уже был доказан ECDSA-подписью в challenge_response, не
            # взят из клиентского сообщения.
            if msg_type == "request_sender_cert":
                if not rate_limit_check(username, "request_sender_cert"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                if not verified_public_key:
                    continue
                now = int(time.time())
                cert = {
                    "fingerprint":  username,
                    "public_key":   base64.b64encode(verified_public_key).decode(),
                    "issued_at":    now,
                    "expires_at":   now + SENDER_CERT_TTL_SEC,
                }
                # Signed over a fixed, simple pipe-delimited string — deliberately
                # NOT a JSON serialization. Byte-exact JSON canonicalization
                # (sorted keys, separators, float formatting) is a classic
                # cross-language footgun: Python's json.dumps and the Kotlin
                # client's org.json would need to agree on every formatting
                # detail (in particular float repr) for signature verification
                # to ever succeed, and any future stdlib/library change on
                # either side could silently break it. Integer timestamps +
                # explicit field order sidesteps that entirely.
                sign_string = f"{cert['fingerprint']}|{cert['public_key']}|{cert['issued_at']}|{cert['expires_at']}"
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                signature = SENDER_CERT_PRIVATE_KEY.sign(sign_string.encode(), ec.ECDSA(hashes.SHA256()))
                await send_safe(websocket, json.dumps({
                    "type":      "sender_cert",
                    "cert":      cert,
                    "signature": base64.b64encode(signature).decode(),
                }))
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
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store() (external review 2026-09-05,
                # S6-42).
                if not is_valid_fingerprint(to):
                    continue
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
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store()/send_fcm_wakeup()
                # (external review 2026-09-05, S6-42) — rejected with an
                # explicit error rather than a silent drop, since this type
                # (unlike ephemeral read/typing/session_reset) already has
                # an ack/error contract the sender is waiting on; never
                # falls through to a false "ack". db_store()/
                # _db_store_sync() would independently refuse this as
                # INVALID_RECIPIENT anyway (defense-in-depth), but rejecting
                # here means it never reaches clients.get()/
                # forward_to_peers()/the offline queue at all.
                if not is_valid_fingerprint(to):
                    await websocket.send(json.dumps({"type": "error", "reason": "Invalid recipient"}))
                    continue
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
                    if forwarded:
                        print("[MSG] session_init forwarded via federation")
                        delivered = True
                    else:
                        store_status = await db_store(to, fwd, msg_id)
                        # Critical ACK rule (external review 2026-09-04,
                        # S6-31) — see db_store()'s own comment for the full
                        # status list. Only "STORED"/"DUPLICATE" mean the
                        # message is actually durably present; every other
                        # status (FULL/TOO_LARGE/CONFLICT/RATE_LIMITED) means
                        # the offline copy was NEVER written, so the sender
                        # must not be told it was delivered — the old
                        # unconditional ACK here (regardless of db_store()'s
                        # outcome, back when it couldn't even fail loudly)
                        # was exactly that false-delivery-ACK bug.
                        delivered = store_status in ("STORED", "DUPLICATE")
                        if delivered:
                            print("[MSG] session_init queued (offline)")
                        else:
                            print(f"[MSG] session_init NOT queued (offline store failed: {store_status})")
                    if delivered:
                        # Разбудить приложение получателя через FCM — only
                        # once the message is actually somewhere it can be
                        # delivered from (forwarded or durably stored), not
                        # on a failed store that has nothing to wake up for.
                        schedule_fcm_wakeup(to, username, "session_init")
                        await websocket.send(json.dumps({"type": "ack", "id": msg_id}))
                    else:
                        await websocket.send(json.dumps({
                            "type": "error", "reason": "Storage unavailable, please retry"
                        }))
                continue

            # ─── Message ──────────────────────────────────────────────────────
            if msg_type == "message":
                if not rate_limit_check(username, "message"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                to     = message.get("to")
                msg_id = message.get("id")
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store()/send_fcm_wakeup() (external
                # review 2026-09-05, S6-42) — see session_init's own copy
                # of this comment above for the full reasoning.
                if not is_valid_fingerprint(to):
                    await websocket.send(json.dumps({"type": "error", "reason": "Invalid recipient"}))
                    continue
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
                    if forwarded:
                        print("[MSG] message forwarded via federation")
                        delivered = True
                    else:
                        store_status = await db_store(to, fwd_payload, msg_id)
                        # Critical ACK rule (external review 2026-09-04,
                        # S6-31) — see db_store()'s own comment for the full
                        # status list, and session_init's own copy of this
                        # comment above for the full reasoning.
                        delivered = store_status in ("STORED", "DUPLICATE")
                        if delivered:
                            print("[MSG] message queued (offline)")
                        else:
                            print(f"[MSG] message NOT queued (offline store failed: {store_status})")
                    if delivered:
                        # Разбудить приложение получателя через FCM
                        schedule_fcm_wakeup(to, username, "message")
                        await websocket.send(json.dumps({"type": "ack", "id": msg_id}))
                    else:
                        await websocket.send(json.dumps({
                            "type": "error", "reason": "Storage unavailable, please retry"
                        }))
                continue

            # ─── Reaction ────────────────────────────────────────────────────
            if msg_type == "reaction":
                if not rate_limit_check(username, "reaction"):
                    continue
                to = message.get("to")
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store() (external review 2026-09-05,
                # S6-42).
                if not is_valid_fingerprint(to):
                    continue
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
                # `to` is the per-member account fingerprint this
                # group_reaction is being relayed to, NOT group_id (a
                # separate field/namespace) — canonical-fingerprint
                # validation before clients.get()/forward_to_peers()/
                # db_store() (external review 2026-09-05, S6-42).
                if not is_valid_fingerprint(to):
                    continue
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
                # Dedicated envelope ceiling checked FIRST, against the raw
                # frame bytes, before any parsing/validation work below
                # (S6-57, STEP 3) — substantially below MAX_PACKET_SIZE_BYTES
                # (see VOICE_MAX_PACKET_SIZE_BYTES's own derivation), same
                # "cheapest possible rejection first" posture as
                # _call_signal_ceiling_bytes()'s own check.
                if len(raw_message.encode("utf-8")) > VOICE_MAX_PACKET_SIZE_BYTES:
                    continue
                # Voice count rate limit (S6-57, STEP 4) — previously absent
                # entirely (no "voice" entry in rate_limit_check()'s
                # default_limits). Checked before the (cheap) fingerprint/
                # sanitizer work below, same ordering media_chunk_attempt_ok()
                # uses ahead of _validate_media_chunk_envelope().
                if not rate_limit_check(username, "voice"):
                    continue
                to = message.get("to")
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store() (external review 2026-09-05,
                # S6-42) — see OFFLINE_MSG_ID_MAX_LEN's own comment.
                if not is_valid_fingerprint(to):
                    continue
                # Field-specific validation + brand-new sanitized payload
                # (S6-57, STEP 2) — an unrelated extra field, an oversized
                # voice_data/signature, a non-canonical voice_id, or an
                # out-of-range/wrong-typed duration is rejected here, never
                # reflected to the recipient or reaching db_store()/
                # forward_to_peers() at all.
                sanitized = sanitize_voice_payload(message, username, to)
                if sanitized is None:
                    continue

                async with lock:
                    recipient = clients.get(to)

                # Byte budgets (S6-57, STEP 4) — only ever charged for a
                # voice message actually about to be relayed to an ONLINE
                # recipient; an offline target is federated/queued instead,
                # governed by S6-31's own separate global offline-queue caps
                # (matches media_chunk/call_signal precedent exactly — see
                # VOICE_USER_MAX_BYTES's own comment). Accounted from the
                # exact sanitized payload, computed once and reused for both
                # the check and the real send.
                if recipient:
                    serialized  = json.dumps(sanitized, separators=(",", ":"))
                    relay_bytes = len(serialized.encode("utf-8"))
                    if (not voice_user_rate_ok(username, relay_bytes)
                            or not voice_global_rate_ok(relay_bytes)
                            or not voice_recipient_rate_ok(to, relay_bytes)):
                        await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                        continue
                    await send_safe(recipient["ws"], serialized)
                else:
                    # Only the sanitized payload may ever reach federation/
                    # db_store() (S6-57, STEP 5/6) — never the caller's raw
                    # message. S6-31's own global queue rows/bytes remain the
                    # sole offline durability authority; a FULL/RATE_LIMITED
                    # db_store() result here is not, and never was, treated
                    # as delivery.
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, sanitized)
                    if not forwarded:
                        await db_store(to, sanitized)
                continue

            # ─── Image Chunk ──────────────────────────────────────────────────
            if msg_type == "image_chunk":
                # S6-49: canonical envelope validation BEFORE clients.get()/
                # json.dumps()/send_safe() ever run — see
                # _validate_media_chunk_envelope()'s own comment. A
                # malformed/oversized/wrong-type field is dropped silently,
                # same posture as any other malformed-input rejection in
                # this file; no ack, no status, nothing to key a reply on
                # that hasn't itself been validated yet.
                envelope = _validate_media_chunk_envelope(message, "image_id")
                if envelope is None:
                    continue
                to, image_id, chunk_i, total_chunks, data, signature = envelope
                encrypted_flag = message.get("encrypted", False)
                if not isinstance(encrypted_flag, bool):
                    encrypted_flag = False

                # Cheap per-user attempt counter (S6-49, STEP 6) — bounds
                # inbound parsing/validation cost regardless of whether the
                # target turns out to be online, checked BEFORE the
                # online-recipient lookup.
                if not media_chunk_attempt_ok(username):
                    await websocket.send(json.dumps({"type": "status", "id": image_id, "status": "rate_limited", "chunk": chunk_i}))
                    continue

                async with lock:
                    recipient = clients.get(to)
                if not recipient:
                    await websocket.send(json.dumps({"type": "status", "id": image_id, "status": "offline", "chunk": chunk_i}))
                    continue

                # Byte budgets (S6-49, STEPS 4/5/7) only ever charged for a
                # chunk that will ACTUALLY be relayed online — an offline
                # target above already returned without touching any of
                # these, never consuming egress allowance for bytes the
                # server never sends.
                nbytes = len(data.encode("utf-8"))
                if (not media_chunk_user_rate_ok(username, nbytes)
                        or not media_chunk_global_rate_ok(nbytes)
                        or not media_chunk_recipient_rate_ok(to, nbytes)):
                    await websocket.send(json.dumps({"type": "status", "id": image_id, "status": "rate_limited", "chunk": chunk_i}))
                    continue

                ok = await send_safe(recipient["ws"], json.dumps({
                    "type": "image_chunk", "from": username,
                    "image_id": image_id, "chunk_index": chunk_i,
                    "total_chunks": total_chunks,
                    "data": data, "signature": signature,
                    "encrypted": encrypted_flag   # BUG FIX: обязательно пересылаем флаг
                }))
                if ok:
                    await websocket.send(json.dumps({"type": "chunk_ack", "image_id": image_id, "chunk_index": chunk_i}))
                else:
                    await websocket.send(json.dumps({"type": "status", "id": image_id, "status": "offline", "chunk": chunk_i}))
                continue

            # ─── Video Circle Chunk ──────────────────────────────────────────
            if msg_type == "video_chunk":
                envelope = _validate_media_chunk_envelope(message, "video_id")
                if envelope is None:
                    continue
                to, video_id, chunk_i, total_chunks, data, signature = envelope
                encrypted_flag = message.get("encrypted", True)
                if not isinstance(encrypted_flag, bool):
                    encrypted_flag = True
                duration = message.get("duration", 0)
                if not isinstance(duration, int) or isinstance(duration, bool) or not (0 <= duration <= MEDIA_CHUNK_MAX_DURATION_SEC):
                    duration = 0

                if not media_chunk_attempt_ok(username):
                    await websocket.send(json.dumps({"type": "status", "id": video_id, "status": "rate_limited", "chunk": chunk_i}))
                    continue

                async with lock:
                    recipient = clients.get(to)
                if not recipient:
                    await websocket.send(json.dumps({"type": "status", "id": video_id, "status": "offline", "chunk": chunk_i}))
                    continue

                nbytes = len(data.encode("utf-8"))
                if (not media_chunk_user_rate_ok(username, nbytes)
                        or not media_chunk_global_rate_ok(nbytes)
                        or not media_chunk_recipient_rate_ok(to, nbytes)):
                    await websocket.send(json.dumps({"type": "status", "id": video_id, "status": "rate_limited", "chunk": chunk_i}))
                    continue

                ok = await send_safe(recipient["ws"], json.dumps({
                    "type": "video_chunk", "from": username,
                    "video_id": video_id, "chunk_index": chunk_i,
                    "total_chunks": total_chunks,
                    "data": data, "signature": signature,
                    "duration": duration,
                    "encrypted": encrypted_flag
                }))
                if ok:
                    # Используем video_id (не image_id!) чтобы клиент мог матчить ACK
                    await websocket.send(json.dumps({"type": "chunk_ack", "video_id": video_id, "chunk_index": chunk_i}))
                else:
                    await websocket.send(json.dumps({"type": "status", "id": video_id, "status": "offline", "chunk": chunk_i}))
                continue

            # ─── File Chunk ───────────────────────────────────────────────────
            if msg_type == "file_chunk":
                envelope = _validate_media_chunk_envelope(message, "file_id")
                if envelope is None:
                    continue
                to, file_id, chunk_i, total_chunks, data, signature = envelope
                # STEP 3: file_name/encrypted_file_name are repeated on
                # EVERY chunk of a transfer — bounded before relay so a
                # tiny `data` payload can't smuggle megabytes of auxiliary
                # string past the intended per-chunk ceiling. Both fields
                # forwarded (not just the legacy plaintext one the old code
                # relayed) since CURRENT sendFile() on both clients sends
                # `encrypted_file_name`, never bare `file_name` — the old
                # relay list was stale relative to the actual current
                # sender, confirmed by grep.
                file_name           = _bounded_media_chunk_filename(message.get("file_name"))
                encrypted_file_name = _bounded_media_chunk_filename(message.get("encrypted_file_name"))

                if not media_chunk_attempt_ok(username):
                    await websocket.send(json.dumps({"type": "status", "id": file_id, "status": "rate_limited", "chunk": chunk_i}))
                    continue

                async with lock:
                    recipient = clients.get(to)
                if not recipient:
                    await websocket.send(json.dumps({"type": "status", "id": file_id, "status": "offline", "chunk": chunk_i}))
                    continue

                nbytes = len(data.encode("utf-8"))
                if (not media_chunk_user_rate_ok(username, nbytes)
                        or not media_chunk_global_rate_ok(nbytes)
                        or not media_chunk_recipient_rate_ok(to, nbytes)):
                    await websocket.send(json.dumps({"type": "status", "id": file_id, "status": "rate_limited", "chunk": chunk_i}))
                    continue

                ok = await send_safe(recipient["ws"], json.dumps({
                    "type": "file_chunk", "from": username,
                    "file_id": file_id, "file_name": file_name,
                    "encrypted_file_name": encrypted_file_name,
                    "chunk_index": chunk_i, "total_chunks": total_chunks,
                    "data": data, "signature": signature
                }))
                if ok:
                    await websocket.send(json.dumps({"type": "chunk_ack", "file_id": file_id, "chunk_index": chunk_i}))
                else:
                    await websocket.send(json.dumps({"type": "status", "id": file_id, "status": "offline", "chunk": chunk_i}))
                continue

            # ─── Group Create ─────────────────────────────────────────────────
            if msg_type == "group_create":
                to            = message.get("to")
                # `to` is the per-member account fingerprint, NOT group_id
                # (a separate field/namespace) — canonical-fingerprint
                # validation before clients.get()/forward_to_peers()/
                # db_store() (external review 2026-09-05, S6-42).
                if not is_valid_fingerprint(to):
                    continue
                group_id      = message.get("group_id")
                group_name    = message.get("group_name")
                group_avatar  = message.get("group_avatar")
                encrypted_key = message.get("encrypted_group_key")
                signature     = message.get("signature")
                # members/admins/roster_signature were previously dropped
                # here entirely (external review 2026-09-09, S6-65) — both
                # clients produce a signed initial roster but every
                # recipient fell back to an unauthenticated [from, self]/
                # [from] guess, since the roster never actually arrived.
                # Required (not merely bounded-if-present): both current
                # clients always send these, and requiring them closes the
                # unsigned-roster fallback for current-version group_create.
                # Shape/bound validation only, not cryptographic
                # verification — see validate_group_roster()'s own comment.
                roster = validate_group_roster(message.get("members"), message.get("admins"), username)
                roster_signature = message.get("roster_signature")
                if roster is None or not is_valid_chat_control_signature(roster_signature):
                    continue
                members, admins = roster
                gc_payload = {
                    "type": "group_create", "from": username,
                    "group_id": group_id, "group_name": group_name,
                    "group_avatar": group_avatar,
                    "encrypted_group_key": encrypted_key, "signature": signature,
                    "members": members, "admins": admins, "roster_signature": roster_signature
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
                # `to` is the per-member account fingerprint, NOT group_id
                # — canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store() (external review 2026-09-05,
                # S6-42).
                if not is_valid_fingerprint(to):
                    continue
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
                # `to` is the per-member account fingerprint, NOT group_id —
                # canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store() (external review 2026-09-05,
                # S6-42).
                if not is_valid_fingerprint(to):
                    continue
                # signature was silently dropped from the relayed payload —
                # both clients require it on receive (they verify it against
                # the sender's admin key and reject the message otherwise),
                # so every legitimate removal was being rejected by every
                # up-to-date client (external review 2026-09-08, S6-60).
                # Required, not merely bounded-if-present, mirroring S6-54's
                # message_delete/group_message_delete precedent.
                gmr_signature = message.get("signature")
                if not is_valid_chat_control_signature(gmr_signature):
                    continue
                gmr_payload = {
                    "type": "group_member_removed", "from": username,
                    "group_id":       message.get("group_id"),
                    "removed_member": message.get("removed_member"),
                    "signature":      gmr_signature
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

            # ─── Group Member Added ────────────────────────────────────────────
            # Was entirely missing from ALLOWED_TYPES (external review
            # 2026-09-08, S6-60) — Android's addGroupMember() has sent this
            # type, and MessengerService.kt has verified+applied it on
            # receive, since the original group-roster fix (see
            # docs/ISSUE_backup_identity_hijack.md), and SECURITY.md's group-
            # key-distribution writeup documents it as the mechanism existing
            # members learn a new member's {memberId, encKey} pair through —
            # but with no "group_member_added" handler here it hit the
            # generic "неизвестный тип" rejection and was silently dropped on
            # every send. Existing members' rosters never actually updated
            # for a member added after group creation on ANY platform.
            if msg_type == "group_member_added":
                to  = message.get("to")
                if not is_valid_fingerprint(to):
                    continue
                gma_signature = message.get("signature")
                if not is_valid_chat_control_signature(gma_signature):
                    continue
                gma_payload = {
                    "type": "group_member_added", "from": username,
                    "group_id":        message.get("group_id"),
                    "new_member":      message.get("new_member"),
                    "new_member_name": message.get("new_member_name"),
                    "signature":       gma_signature
                }
                async with lock:
                    recipient = clients.get(to)
                if recipient:
                    await send_safe(recipient["ws"], json.dumps(gma_payload))
                else:
                    forwarded = FEDERATION_SECRET and await forward_to_peers(to, gma_payload)
                    if not forwarded:
                        await db_store(to, gma_payload)
                continue

            # ─── Group Key Rotation ───────────────────────────────────────────
            if msg_type == "group_key_rotation":
                to  = message.get("to")
                # `to` is the per-member account fingerprint, NOT group_id —
                # canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store() (external review 2026-09-05,
                # S6-42).
                if not is_valid_fingerprint(to):
                    continue
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
                # `to` is the per-member account fingerprint, NOT group_id —
                # canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store() (external review 2026-09-05,
                # S6-42).
                if not is_valid_fingerprint(to):
                    continue
                # Same signature-drop bug as group_member_removed just above
                # — both clients require and verify it on receive (proof the
                # named new_member consented to join), so it was previously
                # relayed with no signature and rejected by every up-to-date
                # client (external review 2026-09-08, S6-60).
                gia_signature = message.get("signature")
                if not is_valid_chat_control_signature(gia_signature):
                    continue
                gia_payload = {
                    "type": "group_invite_accepted", "from": username,
                    "group_id":       message.get("group_id"),
                    "new_member":     message.get("new_member"),
                    "new_member_name": message.get("new_member_name"),
                    "signature":      gia_signature
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

                channel_name_raw   = message.get("channel_name", "")
                channel_desc_raw   = message.get("channel_description", "")
                channel_avatar_raw = message.get("channel_avatar", "📢")

                # S6-47: require actual str before any .strip()/len() — a
                # list/dict/int here previously reached .strip() unchecked
                # (channel_name/channel_description) or was stored completely
                # unbounded (channel_avatar had no check at all).
                if (not isinstance(channel_name_raw, str) or not isinstance(channel_desc_raw, str)
                        or not isinstance(channel_avatar_raw, str)):
                    await websocket.send(json.dumps({"type": "error", "reason": "Некорректный формат данных канала"}))
                    continue
                channel_name   = channel_name_raw.strip()
                channel_desc   = channel_desc_raw.strip()
                channel_avatar = channel_avatar_raw

                if not channel_name:
                    await websocket.send(json.dumps({"type": "error", "reason": "Название канала не может быть пустым"}))
                    continue
                if len(channel_name) > CHANNEL_NAME_MAX_CHARS:
                    await websocket.send(json.dumps({"type": "error", "reason": "Слишком длинное название канала"}))
                    continue
                if len(channel_desc) > CHANNEL_DESCRIPTION_MAX_CHARS:
                    await websocket.send(json.dumps({"type": "error", "reason": "Слишком длинное описание канала"}))
                    continue
                if len(channel_avatar) > CHANNEL_AVATAR_MAX_CHARS:
                    await websocket.send(json.dumps({"type": "error", "reason": "Некорректный аватар канала"}))
                    continue

                channel_id = secrets.token_urlsafe(16)
                new_ch = {
                    "name": channel_name,
                    "avatar": channel_avatar,
                    "description": channel_desc,
                    "admin": username,
                    "admin_name": clients.get(username, {}).get("name", username),
                    "created_at": time.time(),
                }

                # S6-47: DB-first atomic count+insert — see
                # _db_create_channel_sync()'s own comment for the race this
                # closes (MAX_CHANNELS_PER_OWNER/CHANNELS_MAX_TOTAL_ROWS).
                # RAM (`channels`) is only ever populated AFTER the durable
                # row actually exists.
                loop = asyncio.get_event_loop()
                create_status = await loop.run_in_executor(None, _db_create_channel_sync, channel_id, new_ch)
                if create_status == "OWNER_LIMIT":
                    await websocket.send(json.dumps({"type": "error", "reason": "Достигнут лимит каналов для этого аккаунта"}))
                    continue
                if create_status == "TOTAL_LIMIT":
                    await websocket.send(json.dumps({"type": "error", "reason": "Сервер достиг лимита каналов"}))
                    continue

                async with lock:
                    channels[channel_id] = {**new_ch, "subscribers": {username}, "posts": []}

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
                # S6-47: bounded/canonical channel_id before any dict/DB
                # lookup — an unbounded attacker-controlled string was
                # previously usable directly as a `channels` dict key.
                if not is_valid_channel_id(channel_id):
                    await websocket.send(json.dumps({"type": "error", "reason": "Канал не найден"}))
                    continue
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
                if not is_valid_channel_id(channel_id):
                    continue
                async with lock:
                    ch = channels.get(channel_id)
                    if ch:
                        ch["subscribers"].discard(username)
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _db_remove_subscriber_sync, channel_id, username)
                continue

            # ─── Channel Post (admin only) ────────────────────────────────────
            if msg_type == "channel_post":
                # S6-47: dedicated per-user rate limit — channel_post had
                # NONE before this fix, despite every accepted post
                # persisting durably and potentially carrying multi-
                # megabyte image data. Checked FIRST, before any field
                # validation/DB work.
                if not rate_limit_check(username, "channel_post"):
                    await websocket.send(json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue

                channel_id_raw = message.get("channel_id", "")
                text_raw       = message.get("text", "")
                image_data     = message.get("image_data", "")
                post_id_raw    = message.get("id", secrets.token_urlsafe(16))
                timestamp      = int(time.time() * 1000)  # всегда серверное время

                # S6-47: type/shape checks BEFORE .strip()/len()/any DB
                # work — a list/dict/int reaching .strip() would crash the
                # handler; reaching SQLite unchecked would let an attacker-
                # controlled non-string durably corrupt a TEXT column.
                if (not isinstance(channel_id_raw, str) or not isinstance(text_raw, str)
                        or not isinstance(post_id_raw, str)):
                    await websocket.send(json.dumps({"type": "error", "reason": "Некорректный формат поста"}))
                    continue
                if not is_valid_channel_id(channel_id_raw):
                    await websocket.send(json.dumps({"type": "error", "reason": "Канал не найден"}))
                    continue
                if not is_valid_channel_post_id(post_id_raw):
                    await websocket.send(json.dumps({"type": "error", "reason": "Некорректный идентификатор поста"}))
                    continue
                channel_id = channel_id_raw
                post_id    = post_id_raw
                text       = text_raw.strip()
                if len(text) > CHANNEL_POST_TEXT_MAX_CHARS:
                    await websocket.send(json.dumps({"type": "error", "reason": "Слишком длинный текст поста"}))
                    continue
                # image_data: base64 string, bounded encoded length checked
                # BEFORE decode, strict base64 syntax, decoded byte length
                # bounded to the real image-size ceiling — see
                # validate_channel_post_image()'s own comment. Replaces the
                # old `len(image_data) > 5 * 1024 * 1024` check, which
                # measured base64 CHARACTERS, not decoded bytes, and never
                # rejected a non-str value at all.
                if not validate_channel_post_image(image_data):
                    await websocket.send(json.dumps({"type": "error", "reason": "Изображение слишком большое или повреждено"}))
                    continue

                # S6-47/STEP 7: verify channel/admin and snapshot
                # subscribers under the short global lock, but do NOT
                # mutate ch["posts"] yet — the durable write below can
                # still fail/be rejected, and RAM/broadcast must never
                # reflect a post that wasn't actually stored.
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
                    author_name = clients.get(username, {}).get("name", username)
                    subscribers = set(ch["subscribers"])

                post = {
                    "post_id": post_id,
                    "text": text,
                    "timestamp": timestamp,
                    "author_id": username,
                    "author_name": author_name,
                    "image_data": image_data
                }

                # DB FIRST — never holding `lock` across this await
                # (invariant #34) — see db_store_channel_post()'s own
                # comment for the full status contract.
                store_status = await db_store_channel_post(channel_id, post)

                if store_status not in ("STORED", "DUPLICATE"):
                    error_reasons = {
                        "TOO_LARGE": "Пост слишком большой",
                        "FULL": "Хранилище каналов заполнено, попробуйте позже",
                        "CONFLICT": "Конфликт идентификатора поста",
                        "RATE_LIMITED": "Rate limit exceeded",
                        "INVALID_CHANNEL_ID": "Канал не найден",
                        "INVALID_POST_ID": "Некорректный идентификатор поста",
                    }
                    await websocket.send(json.dumps({
                        "type": "error",
                        "reason": error_reasons.get(store_status, "Не удалось опубликовать пост")
                    }))
                    continue

                if store_status == "DUPLICATE":
                    # Already durably present (and, if it was ever STORED
                    # live, already in RAM/already broadcast then) — never
                    # append or broadcast a second copy.
                    continue

                # store_status == "STORED"
                async with lock:
                    ch = channels.get(channel_id)
                    if ch is not None:
                        ch["posts"].append(post)
                        # Keep only last 200 posts in memory
                        if len(ch["posts"]) > 200:
                            ch["posts"] = ch["posts"][-200:]

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
                if not is_valid_channel_id(channel_id):
                    await websocket.send(json.dumps({"type": "error", "reason": "Канал не найден"}))
                    continue
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

            # ─── Call Signaling Relay (S6-51) ───────────────────────────────────
            # Signaling is small, schema-defined traffic — bounded before
            # active_calls mutation/relay, and a NEW sanitized payload is
            # relayed (never the caller's raw dict). See
            # _sanitize_call_signal()'s own comment for the full field-level
            # reasoning and SECURITY_INVARIANTS.md #64.
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
                # Existing per-type count limit — protects message FREQUENCY,
                # unchanged by this patch. Checked first, same as before.
                if not rate_limit_check(username, msg_type):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                # Dedicated per-type envelope ceiling (S6-51, STEP 2) — checked
                # against the ACTUAL received UTF-8 frame, before active_calls
                # mutation, clients lookup, or any field-level work. Silently
                # dropped, same posture as every other malformed-input
                # rejection in this handler — a legitimate client's signaling
                # never approaches these ceilings.
                if len(raw_message.encode("utf-8")) > _call_signal_ceiling_bytes(msg_type):
                    continue
                target = message.get("to", "")
                # Canonical-fingerprint validation before active_calls/
                # clients.get()/db_store()/send_fcm_wakeup() (external
                # review 2026-09-05, S6-42) — subsumes the old empty-string
                # check (an empty string is never a valid fingerprint
                # either).
                if not is_valid_fingerprint(target):
                    continue
                # Field-specific validation + brand-new sanitized payload
                # (S6-51, STEP 3/4) — an unrelated extra field the caller
                # stuffed into the frame is discarded here, never reflected
                # to the recipient, regardless of how small the legitimate
                # fields themselves are.
                sanitized = _sanitize_call_signal(msg_type, message, username, target)
                if sanitized is None:
                    continue
                call_id = sanitized["call_id"]

                async with lock:
                    target_ws = clients.get(target, {}).get("ws")

                # Byte budgets (S6-51, STEP 6) — only ever charged for a
                # message actually about to be relayed to an ONLINE
                # recipient; an offline target never costs any egress, so
                # never touches these (matches S6-49's media-chunk
                # precedent exactly). Accounted from the exact sanitized
                # payload, computed once and reused for both the check and
                # the real send. Rejected HERE, before active_calls is ever
                # touched (S6-51, STEP 5) — over-budget signaling leaves
                # exactly as much state behind as malformed signaling: none.
                serialized = None
                if target_ws:
                    serialized  = json.dumps(sanitized, separators=(",", ":"))
                    relay_bytes = len(serialized.encode("utf-8"))
                    if (not call_signal_user_rate_ok(username, relay_bytes)
                            or not call_signal_global_rate_ok(relay_bytes)
                            or not call_signal_recipient_rate_ok(target, relay_bytes)):
                        await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                        continue

                # Трекинг активных звонков для auto call_end при дисконнекте —
                # only ever from the VALIDATED call_id now (S6-51, STEP 5),
                # never the raw attacker-supplied value, and only once this
                # signaling has cleared byte-budget admission too (above).
                if msg_type == "call_offer":
                    # Трекаем звонящего уже на этапе вызова (до ответа).
                    # Без этого: если A отвалится до того, как B ответит,
                    # сервер не знает о звонке и B продолжает бесконечно звонить.
                    async with lock:
                        active_calls[username] = {"peer": target, "call_id": call_id}
                elif msg_type == "call_answer":
                    async with lock:
                        # Own entry: always freely writable by its own
                        # authenticated user. Reciprocal (target's) entry:
                        # only promoted/overwritten if target's own tracked
                        # state already reflects a call_offer FROM username
                        # with this exact call_id (S6-61) — otherwise an
                        # unrelated attacker naming any victim as `to` could
                        # overwrite that victim's real active_calls entry
                        # with a bogus one merely by sending a well-formed
                        # call_answer, corrupting the auto-call_end-on-
                        # disconnect target for a call they were never in.
                        active_calls[username] = {"peer": target, "call_id": call_id}
                        if active_call_matches(target, username, call_id):
                            active_calls[target] = {"peer": username, "call_id": call_id}
                elif msg_type in ("call_end", "call_group_leave"):
                    async with lock:
                        # Each side's entry is popped only if IT reciprocally
                        # still matches this exact peer + call_id (S6-61) —
                        # never an unconditional pop of either party, so a
                        # stale/forged/unrelated call_end can't erase a
                        # victim's real, current active_calls state (their
                        # own or someone else's newer call). Also protects
                        # call_group_leave, which shares this branch but was
                        # never populated by the group-call handshake in the
                        # first place — the correlation check makes its pop
                        # a safe no-op against any unrelated 1:1 call state
                        # rather than blindly reusing pair-call semantics.
                        if active_call_matches(username, target, call_id):
                            active_calls.pop(username, None)
                        if active_call_matches(target, username, call_id):
                            active_calls.pop(target, None)

                if target_ws:
                    # Awaited, not asyncio.create_task() (S6-51, STEP 7) — one
                    # bounded signaling packet per relay, so the sender's own
                    # message loop naturally gets backpressure instead of an
                    # unbounded number of pending send Tasks accumulating
                    # against a slow recipient. Signaling is small after this
                    # patch; this does not need an architectural send queue.
                    await send_safe(target_ws, serialized)
                    print(f"[CALL] {msg_type} relayed")
                else:
                    if msg_type == "call_offer":
                        # Получатель оффлайн — сохраняем пропущенный звонок и будим через FCM.
                        # Only the small server-created missed_call is ever
                        # stored — SDP/ICE are never persisted merely because
                        # this handler was touched. db_store() already has its
                        # own independent write-attempt budget
                        # (global_offline_store_rate_ok(), S6-31) bounding
                        # aggregate missed-call storage across Sybil callers.
                        # Wakeup is now only requested once the store ACTUALLY
                        # succeeded (S6-52, STEP 13) — the original
                        # unconditional asyncio.create_task(send_fcm_wakeup())
                        # here fired regardless of db_store()'s returned
                        # status (FULL/TOO_LARGE/RATE_LIMITED included),
                        # unlike message/session_init's own already-correct
                        # `delivered` gating just above.
                        missed = {
                            "type": "missed_call",
                            "from": username,
                            "is_video": sanitized.get("is_video", False),
                            "timestamp": int(time.time() * 1000)
                        }
                        store_status = await db_store(target, missed)
                        if store_status in ("STORED", "DUPLICATE"):
                            schedule_fcm_wakeup(target, username, "missed_call")
                            print("[CALL] missed call stored (recipient offline)")
                        else:
                            print(f"[CALL] missed call NOT stored (recipient offline, store failed: {store_status})")
                    else:
                        print(f"[CALL] {msg_type} dropped (recipient offline)")
                continue

            # ─── Chat-control relay (S6-53) ────────────────────────────────────
            # message_delete/disappear_timer/group_message_delete used to relay
            # the caller's raw arbitrary JSON verbatim — see sanitize_chat_
            # control()'s own module-level comment for the full history. Now
            # follows the exact same admission shape as CALL_RELAY_TYPES above:
            # shared count limit -> envelope ceiling -> target validation ->
            # field sanitization -> byte budgets -> awaited bounded relay.
            CHAT_CONTROL_TYPES = {"message_delete", "disappear_timer", "group_message_delete"}
            if msg_type in CHAT_CONTROL_TYPES:
                # One shared logical bucket (S6-53, STEP 5) — alternating
                # between these 3 types is the same abuse resource (one
                # relayed control frame to one recipient), so they must not
                # each get an independent allowance. Uses a synthetic
                # "chat_control" key rather than msg_type, same precedent as
                # the shared "prekey_publish" bucket's own comment.
                if not rate_limit_check(username, "chat_control", limit=60):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                # Dedicated small envelope ceiling (S6-53, STEP 4) — checked
                # against the ACTUAL received UTF-8 frame, before any
                # clients lookup/limiter-key creation/field-level work.
                if len(raw_message.encode("utf-8")) > CHAT_CONTROL_MAX_PACKET_SIZE_BYTES:
                    continue
                target = message.get("to", "")
                # Canonical-fingerprint validation before clients.get()/
                # forward_to_peers()/db_store()/send_fcm_wakeup() (external
                # review 2026-09-05, S6-42) — subsumes the old empty-string
                # check.
                if not is_valid_fingerprint(target):
                    continue
                # Field-specific validation + brand-new sanitized payload
                # (S6-53, STEP 2/3) — an unrelated extra field the caller
                # stuffed into the frame is discarded here, never reflected
                # to the recipient. `from` is always the authenticated
                # connection's own username here (local origin), never
                # caller-suppliable.
                sanitized = sanitize_chat_control(msg_type, message, username, target)
                if sanitized is None:
                    continue

                async with lock:
                    target_ws = clients.get(target, {}).get("ws")

                # Byte budgets (S6-53, STEP 6) — only ever charged for a
                # message actually about to be relayed to an ONLINE
                # recipient; an offline target never costs any egress.
                # Accounted from the exact sanitized payload, computed once
                # and reused for both the check and the real send. Rejected
                # HERE, before any offline store/forward path runs — malformed
                # AND over-budget control traffic leave exactly as much state
                # behind: none.
                if target_ws:
                    serialized  = json.dumps(sanitized, separators=(",", ":"))
                    relay_bytes = len(serialized.encode("utf-8"))
                    if (not chat_control_user_rate_ok(username, relay_bytes)
                            or not chat_control_global_rate_ok(relay_bytes)
                            or not chat_control_recipient_rate_ok(target, relay_bytes)):
                        await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                        continue
                    # Awaited, not asyncio.create_task() (S6-53, STEP 7) — one
                    # bounded control packet per relay, natural websocket
                    # backpressure instead of an unbounded number of pending
                    # send Tasks accumulating against a slow recipient. No
                    # retry of a failed online send is queued in RAM.
                    await send_safe(target_ws, serialized)
                else:
                    # Offline: ONLY the sanitized payload is ever forwarded/
                    # stored (S6-53, STEP 8) — never the raw caller dict.
                    forwarded = FEDERATION_SECRET and await forward_to_peers(target, sanitized)
                    if forwarded:
                        stored_or_forwarded = True
                    else:
                        store_status = await db_store(target, sanitized)
                        stored_or_forwarded = store_status in ("STORED", "DUPLICATE")
                    # Wakeup only once actually forwarded/stored (S6-52,
                    # STEP 13, preserved as-is) — never for FULL/RATE_LIMITED/etc.
                    if stored_or_forwarded:
                        schedule_fcm_wakeup(target, username, msg_type)
                continue

            # ─── Anonymous Token Routing ──────────────────────────────────────
            if msg_type == "subscribe_tokens":
                raw_tokens = message.get("tokens", [])
                if isinstance(raw_tokens, list):
                    valid = [t for t in raw_tokens
                             if isinstance(t, str) and len(t) == MAX_TOKEN_LEN][:MAX_TOKENS_PER_SUBSCRIBE]
                    # Reconnect-friendly admission (found live 2026-09-20 in
                    # production: legitimate startup/reconnect bursts of
                    # 80-100 tokens, split across MAX_TOKENS_PER_SUBSCRIBE=100
                    # -sized chunks, were hitting a flat per-message limit
                    # that charged a call re-stating 100 already-owned tokens
                    # the same as a call full of brand-new ones). Cheap,
                    # lock-protected, in-memory-only peek at whether this
                    # batch has anything NOT already a cache hit — mirrors
                    # the same cache-hit/potential-new split
                    # db_claim_anon_tokens() does for ANON_TOKEN_GLOBAL_CLAIM_LIMIT
                    # a few lines down. A purely idempotent resubscribe
                    # (every token already known) never touches the
                    # per-message limiter at all; only a batch containing at
                    # least one not-yet-cached token can be rate-limited
                    # here. The real defense against actual new-token abuse
                    # is untouched — MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT/
                    # ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW/
                    # ANON_TOKEN_STATE_MAX_TOTAL_ROWS/ANON_TOKEN_GLOBAL_CLAIM_LIMIT
                    # are all still enforced content-aware and atomically
                    # inside db_claim_anon_tokens()/_db_claim_anon_tokens_sync()
                    # below, regardless of how many messages a batch is split
                    # across.
                    async with lock:
                        has_new = any(_hash_anon_token(t) not in anon_token_state_cache for t in valid)
                    if has_new and not rate_limit_check(username, "subscribe_tokens"):
                        await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                        continue
                    # SQLite is now the source of truth for ownership/state —
                    # found live 2026-09-03 (external review): the RAM-only
                    # token_owner/spent_tokens dicts this replaces reset on
                    # every server restart, reopening the hijack window they
                    # exist to close. Resolved OUTSIDE the lock (it's its
                    # own atomic transaction, see
                    # _db_claim_anon_tokens_sync's BEGIN IMMEDIATE) —
                    # holding the asyncio lock across a blocking DB call
                    # would serialize every concurrent subscribe_tokens call
                    # server-wide for no reason.
                    #
                    # PERF-02/03 (2026-11-03): still true of the GLOBAL lock —
                    # unchanged. Serialisation against OTHER anon_token_state
                    # writers now happens inside db_claim_anon_tokens() on
                    # anon_token_write_lock, deliberately NOT here, so that no
                    # caller ever holds that lock while acquiring the global
                    # one. See the lock's own comment near
                    # anon_token_state_cache.
                    claims = await db_claim_anon_tokens(valid, username)
                    # Never-downgrade-by-RANK guard, not just
                    # never-downgrade-from-terminal (external review
                    # 2026-09-04, tightened from the original 2026-09-03
                    # round-3 version) — claims reflects each token's DB
                    # state as of the `await` above, which can already be
                    # stale by the time this loop runs: a concurrent
                    # anon_message/anon_delivery_ack/unsubscribe_tokens/
                    # watchdog could have durably advanced one of these SAME
                    # tokens (and updated the cache under its own lock)
                    # while this coroutine was suspended waiting on
                    # db_claim_anon_tokens(). The original version of this
                    # guard only blocked "stale non-terminal claim over an
                    # already-terminal cache entry" — it missed the
                    # identical problem one rank down: a stale ACTIVE claim
                    # (this token's state before some concurrent
                    # anon_message won ACTIVE→IN_FLIGHT) could still
                    # overwrite a freshly-written IN_FLIGHT cache entry back
                    # to ACTIVE, even though ACTIVE→IN_FLIGHT never
                    # legitimately reverses (invariant 28: an IN_FLIGHT
                    # token is force-closed to SPENT, never silently
                    # returned to ACTIVE, by TTL/restart or anything else).
                    # ANON_TOKEN_STATE_RANK generalizes the check: only ever
                    # apply a claim whose rank is >= the currently cached
                    # rank — equal-rank writes (e.g. SPENT overwriting
                    # REVOKED) stay allowed, same as before, since neither
                    # terminal state is ever a downgrade from the other.
                    async with lock:
                        for claimed_t, claimed_state in claims.items():
                            claimed_owner, claimed_rank_state = claimed_state
                            # NEW_CLAIM_LIMIT (external review 2026-09-05,
                            # S6-44) — owner is deliberately None (see
                            # _db_claim_anon_tokens_sync()'s own comment):
                            # this token has NO backing row in the DB at
                            # all, refused by the active-row cap/durable
                            # issuance quota/total-row ceiling/global
                            # claim-request budget. anon_token_state_cache
                            # is a strict mirror of the DB's actual
                            # contents — writing a synthetic entry for a
                            # token that was never actually inserted would
                            # corrupt that invariant for every other reader
                            # of this cache (anon_message's hot-path check
                            # included).
                            if claimed_owner is None:
                                continue
                            claimed_hash = _hash_anon_token(claimed_t)
                            cached = anon_token_state_cache.get(claimed_hash)
                            cached_state = cached[1] if cached else None
                            if (cached_state is not None
                                    and ANON_TOKEN_STATE_RANK.get(claimed_rank_state, 0)
                                        < ANON_TOKEN_STATE_RANK.get(cached_state, 0)):
                                continue
                            anon_token_state_cache[claimed_hash] = claimed_state
                    already_spent  = []
                    claim_limited  = []
                    ws_cap_limited = []
                    async with lock:
                        existing = ws_to_tokens.get(websocket, set())
                        for t in valid:
                            db_owner, db_state = claims[t]

                            # NEW_CLAIM_LIMIT — no real DB row for this
                            # token at all (external review 2026-09-05,
                            # S6-44); never touches token_to_ws/
                            # known_tokens/token_owner/ws_to_tokens, since
                            # there is nothing real to route to yet.
                            if db_owner is None:
                                claim_limited.append(t)
                                continue

                            # Ownership first — see token_owner's comment
                            # above for the full hijack scenario this closes
                            # (a contact who was handed this token to
                            # ADDRESS the owner subscribing to it themselves,
                            # stealing routing rather than just using it to
                            # send). db_claim_anon_tokens() already resolved
                            # who the real, durable owner is — the first
                            # subscriber ever, tracked in SQLite so a restart
                            # can't reset it.
                            if db_owner != username:
                                print(f"[SECURITY] subscribe_tokens: {username} попытался завладеть токеном "
                                      f"…{t[-6:]}, принадлежащим {db_owner} — отклонено")
                                continue

                            # Only the real owner gets reconciliation on a
                            # terminal token — collected so a single
                            # subscribe_tokens_result can tell the client
                            # "you can stop waiting for this", closing the
                            # loop even when anon_delivery_ack_ok itself
                            # (not just the original ack) was what got lost.
                            token_owner[t] = db_owner  # RAM cache
                            if db_state in ("SPENT", "REVOKED"):
                                already_spent.append(t)
                                spent_tokens.add(t)  # RAM cache
                                continue

                            # ACTIVE. Found live 2026-08-29 (external review): this
                            # used to overwrite token_to_ws[t] unconditionally
                            # — no check for whether t was already owned by a
                            # DIFFERENT live account. A token only ever
                            # reaches a second party through a leak (the
                            # pick_bootstrap_token() collision fixed the same
                            # day is the one confirmed way so far), but if
                            # that ever happens, this let the second holder
                            # silently steal delivery routing for messages
                            # meant for the original owner — misdelivery/DoS,
                            # not a confidentiality break (E2EE still
                            # protects content even if it lands on the wrong
                            # device). Reject the reassignment unless the
                            # current owner is this same authenticated
                            # account (a normal reconnect with a fresh
                            # websocket) or the token isn't currently owned
                            # by any live connection at all.
                            current_owner_ws = token_to_ws.get(t)
                            if current_owner_ws is not None and current_owner_ws is not websocket:
                                owner_username = next(
                                    (u for u, d in clients.items() if d.get("ws") is current_owner_ws),
                                    None,
                                )
                                if owner_username is not None and owner_username != username:
                                    print(f"[SECURITY] subscribe_tokens: {username} попытался переподписать токен "
                                          f"…{t[-6:]}, принадлежащий {owner_username} — отклонено")
                                    continue

                            # Live routing-set cap (external review
                            # 2026-09-05, S6-44) — independent of the
                            # durable active-row cap enforced inside
                            # db_claim_anon_tokens(): bounds how many
                            # DISTINCT tokens THIS websocket's own
                            # ws_to_tokens entry can accumulate via
                            # repeated additive subscribe_tokens calls.
                            # A token already in `existing` (this
                            # connection already subscribed to it earlier
                            # in this same call or a previous one) never
                            # consumes another slot — only genuinely
                            # growing the live set counts against the cap.
                            if t not in existing and len(existing) >= MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT:
                                ws_cap_limited.append(t)
                                continue

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
                    if claim_limited or ws_cap_limited:
                        print(f"[SECURITY] subscribe_tokens: {username} превысил лимит(ы) "
                              f"anon-токенов — claim_limited={len(claim_limited)}, "
                              f"ws_cap_limited={len(ws_cap_limited)}")
                    print(f"[ANON] {username} подписан на {len(valid)} токенов"
                          + (f" ({len(already_spent)} уже spent/revoked)" if already_spent else ""))
                    # Sent outside the lock, same reasoning as
                    # anon_delivery_ack_ok above — completes the
                    # self-healing loop when the ORIGINAL anon_delivery_ack_ok
                    # was the thing that got lost, not the ack itself: the
                    # client re-subscribes an ACK_PENDING token on reconnect,
                    # finds out here it was already durably spent, and can
                    # finally forget it for good.
                    if already_spent:
                        await send_safe(websocket, json.dumps({
                            "type": "subscribe_tokens_result",
                            "spent": already_spent,
                        }))
                elif not rate_limit_check(username, "subscribe_tokens"):
                    # Malformed (non-list) "tokens" — never reaches the
                    # has_new peek above, so charge the plain per-message
                    # limiter same as before this fix, rather than let
                    # garbage payloads process for free indefinitely.
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                continue

            # ─── Explicit token revocation ("контакт скомпрометирован") ────────
            # Mirror of subscribe_tokens, but subtracting instead of adding.
            # Needed because subscribe_tokens is purely additive and disconnect
            # cleanup only ever wipes a token's routing entry, never
            # known_tokens — so without this, the only way to stop a
            # compromised contact's still-outstanding tokens from routing to
            # me was to stop resubscribing them, which only takes effect on
            # my NEXT reconnect. This takes effect immediately.
            #
            # No longer gated on ws_to_tokens[websocket] membership (external
            # review 2026-09-03, round 3) — that used to mean a token could
            # only be revoked from the exact connection that currently owned
            # its live routing entry, e.g. right after a reconnect and before
            # the next subscribe_tokens re-establishes it. SQLite ownership
            # is the actual source of truth now (same as subscribe_tokens
            # itself), so revocation is authorized the same way: attempted
            # for every token the client claims, actually applied only where
            # db_terminalize_anon_token()'s atomic "owner = ? AND state IN
            # ('ACTIVE', 'IN_FLIGHT')" UPDATE finds a match. A stranger's
            # token still can't be revoked this way — the DB owner check
            # rejects it (rowcount 0) regardless of live routing state; this
            # was never really what gated authorization, just an incidental
            # side effect of gating on connection routing instead.
            if msg_type == "unsubscribe_tokens":
                if not rate_limit_check(username, "subscribe_tokens"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                raw_tokens = message.get("tokens", [])
                if isinstance(raw_tokens, list):
                    valid = [t for t in raw_tokens
                             if isinstance(t, str) and len(t) == MAX_TOKEN_LEN][:MAX_TOKENS_PER_SUBSCRIBE]
                    # Persisted to SQLite BEFORE any RAM cleanup — same
                    # reasoning as anon_delivery_ack: a revoked token needs
                    # to already be durably REVOKED (see db_terminalize_anon_token)
                    # the instant this succeeds, not just "will be, once some
                    # later RAM-only write also happens to run" — otherwise a
                    # restart between this and the RAM write below would
                    # leave the compromised contact's token looking ACTIVE
                    # again server-side, the exact hijack window this whole
                    # ownership/state persistence effort exists to close.
                    # Sequential, not batched like db_claim_anon_tokens() —
                    # unsubscribe_tokens is a rare, user-triggered action
                    # ("contact compromised"), not a hot path.
                    removed = 0
                    for t in valid:
                        persisted = await db_terminalize_anon_token(t, username, "REVOKED")
                        if not persisted:
                            print(f"[SECURITY] unsubscribe_tokens: не удалось подтвердить владельца токена …{t[-6:]} в БД")
                            continue
                        token_hash = _hash_anon_token(t)
                        # Cache write combined with the RAM cleanup under
                        # ONE lock (external review 2026-09-03, round 3) — a
                        # terminal transition needs to land in
                        # anon_token_state_cache and token_pending/routing
                        # together, atomically, or a concurrent anon_message
                        # reading the cache mid-way (between this write and
                        # the cleanup below) could still see a state that
                        # doesn't match what token_pending actually holds.
                        # See anon_message's own comment on the matching
                        # half of this fix — a terminal RAM state can never
                        # be overwritten back to IN_FLIGHT precisely because
                        # every writer of anon_token_state_cache for this
                        # token now agrees on doing so under this same lock.
                        async with lock:
                            anon_token_state_cache[token_hash] = (username, "REVOKED")
                            spent_tokens.add(t)
                            # Moved to a terminal state, not just freed —
                            # found live 2026-09-03 (external review):
                            # simply removing a revoked token from
                            # known_tokens/token_to_ws left token ownership
                            # as the only thing stopping the compromised
                            # contact this was revoked FROM re-subscribing to
                            # it right after — which the ownership check does
                            # already block on its own (the owner identity
                            # never changes), but marking it spent here too
                            # closes the belt-and-suspenders gap of that same
                            # contact still being able to spend it via a
                            # genuine anon_message send before anyone else
                            # notices, and matches "revoked = permanently
                            # dead", not "revoked = anyone's for the taking
                            # again". RAM cache only — SQLite (just above) is
                            # the durable record.
                            known_tokens.discard(t)
                            # A revoked token is permanently dead — leaving
                            # its token_pending fallback copy (if any) around
                            # would otherwise sit until the 24h TTL sweep for
                            # a token that will never legitimately be
                            # delivered/acked again. Canonical removal
                            # (external review 2026-09-04, S6-30) — a direct
                            # pop here would correctly clear the entry but
                            # never decrement token_pending_total_bytes/
                            # token_pending_total_items, silently drifting
                            # the RAM-cap accounting away from reality.
                            _token_pending_remove_locked(t)
                            owner_ws = token_to_ws.pop(t, None)
                            if owner_ws is not None:
                                ws_to_tokens.get(owner_ws, set()).discard(t)
                            # Belt-and-suspenders for this connection
                            # specifically — covers a token that's owned by
                            # username (the DB check above already confirmed
                            # that) and sitting in THIS websocket's
                            # ws_to_tokens without (for whatever reason) a
                            # matching token_to_ws entry, which the discard()
                            # above wouldn't otherwise reach.
                            ws_to_tokens.get(websocket, set()).discard(t)
                        removed += 1
                    print(f"[ANON] {username} отозвал {removed} токенов")
                continue

            if msg_type == "anon_message":
                # is_anon_channel connections have no username to key
                # rate_limit_check() on — already counted per-connection
                # above (anon_channel_count). Deliberately not falling back
                # to rate_limit_check(None, ...) here: that would share one
                # global bucket across every anon-channel connection at
                # once, letting one abusive connection rate-limit everyone
                # else's unrelated one.
                if not is_anon_channel and not rate_limit_check(username, "anon_message"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                token   = message.get("token", "")
                payload = message.get("payload", {})
                msg_id  = payload.get("id", "") if isinstance(payload, dict) else ""
                # isinstance(token, str) checked BEFORE len(token) (found via
                # adversarial fuzz testing, 2026-09-25) — a non-string
                # truthy `token` (e.g. the JSON integer 1) made len(token)
                # raise TypeError here, uncaught until handle_client()'s
                # top-level except, which ends the whole connection instead
                # of silently dropping the malformed message like every
                # other malformed-field case in this file (compare
                # register_fcm's already-correct
                # `not isinstance(token, str)` guard a few hundred lines
                # down). Self-inflicted only (kills the sender's own
                # connection, not anyone else's), but still a real
                # inconsistency with this file's own established pattern.
                if not token or not isinstance(token, str) or not isinstance(payload, dict) or len(token) != MAX_TOKEN_LEN:
                    continue

                # S6-59 outer envelope bound (STEP 2-4) — computed and
                # checked BEFORE any token-state lookup, durable claim, or
                # token_pending reservation, per the ordering this fix
                # requires: a malformed/oversized packet must fail before
                # ever burning a real token. Previously this transport had
                # NO per-packet ceiling of its own at all — only the
                # AGGREGATE TOKEN_PENDING_MAX_TOTAL_BYTES RAM cap (how much
                # is retained in total) and the generic MAX_PACKET_SIZE_BYTES
                # transport frame ceiling every message type already shares.
                # STEP-1's own routing-matrix audit found essentially every
                # 1:1 protocol type (message/reaction/edit/delete/voice/
                # media-chunk/call-signaling) routes through here sealed
                # (opaque to the server), so this bound has to be sized for
                # the largest LEGITIMATE anonymous payload today — see
                # ANON_PAYLOAD_MAX_BYTES's own comment for that derivation
                # (a max-length sealed voice message).
                #
                # Reused as-is for the real send/relay below and for every
                # budget check that follows — never re-serialized.
                token_hash    = _hash_anon_token(token)
                delivery_obj  = {"type": "anon_delivery", "token": token, "payload": payload}
                delivery_json = json.dumps(delivery_obj)
                pending_size  = len(delivery_json.encode("utf-8"))
                payload_type  = payload.get("type") if isinstance(payload.get("type"), str) else None
                # A visible `type` key only ever appears for the rare
                # payloads that are NOT sealed (sendAnonTokensTo()'s
                # beacon_tokens resupply, or Desktop's documented seal-
                # failure unsealed fallback) — the dominant sealed
                # {"id","blob"} case has no "type" key and skips this
                # entirely. Do not allow an arbitrary attacker-defined
                # protocol name to be carried indefinitely if no official
                # client ever produces it (STEP 4).
                oversized_or_bad_type = (
                    pending_size > ANON_DELIVERY_MAX_PACKET_SIZE_BYTES
                    or (payload_type is not None and payload_type not in ANON_PAYLOAD_ALLOWED_TYPES)
                )
                # Defense-in-depth field reuse (STEP 5) — ONLY for the rare
                # visible-type case, and ONLY where the server already sees
                # every field it would need anyway (no new metadata
                # exposure), never learning or injecting a from/to pair
                # here. A visible "voice" payload gets the exact same
                # voice_id/voice_data/signature/duration bound as the direct
                # path (field-only half of sanitize_voice_payload()). A
                # visible message_delete/group_message_delete/
                # disappear_timer payload gets the exact same bound as the
                # direct path (field-only half of sanitize_chat_control()),
                # including S6-54's signature-required rule for the two
                # delete types — an unsigned/malformed delete cannot bypass
                # that rule just by arriving via anon_message instead of
                # directly. Call-signaling (S6-51) and media-chunk (S6-49)
                # field-level reuse for this same rare edge case is
                # deferred — the generic envelope/byte bounds above and
                # below already close the actual bypass (an oversized
                # packet of either type is rejected the same as any other),
                # and neither has an S6-54-style correctness rule whose
                # absence would matter here.
                if not oversized_or_bad_type and payload_type == "voice" and validate_voice_fields(payload) is None:
                    oversized_or_bad_type = True
                if (not oversized_or_bad_type
                        and payload_type in ("message_delete", "group_message_delete", "disappear_timer")
                        and validate_chat_control_fields(payload_type, payload) is None):
                    oversized_or_bad_type = True
                if oversized_or_bad_type:
                    # Same externally-indistinguishable fake ack as every
                    # other anon_message rejection path — an oversized or
                    # disallowed-type packet must not itself be a
                    # distinguishable signal, and must never reach the
                    # token-state lookup below (so a fake/decoy token
                    # accompanying a too-big payload is dropped exactly like
                    # any other fake token, not treated any differently).
                    if msg_id:
                        await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                    continue

                # S6-59 generic byte admission (STEP 6/8/9) — per-connection
                # first (anon_channel has no username to key a normal
                # rate_limit_check() on, mirrors ANON_CHANNEL_MAX_PER_MINUTE's
                # own per-connection posture, keyed on the websocket object
                # itself, never a fabricated per-user identity), then
                # process-wide (an attacker opening many anon-channel
                # connections gets many independent per-connection budgets,
                # so only a GLOBAL bound actually caps aggregate admitted
                # bytes regardless of connection count). Checked before any
                # token-state work, same reasoning as the envelope bound
                # above: a budget rejection must never burn a token.
                if not anon_relay_conn_rate_ok(websocket, pending_size) or not anon_relay_global_rate_ok(pending_size):
                    if msg_id:
                        await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                    continue

                async with lock:
                    is_known = token in known_tokens
                    is_spent = token in spent_tokens
                # anon_token_state_cache fallback for a RAM-cache miss —
                # found live 2026-09-03 (external review), the same class of
                # gap the subscribe_tokens/anon_delivery_ack persistence
                # work above was for: known_tokens/spent_tokens are
                # per-process RAM caches (see token_owner's comment), so a
                # server restart empties them, and a real, still-ACTIVE
                # token (Bob has it because Alice legitimately handed it to
                # him, anon_token_state already knows this) looked exactly
                # like a fake/decoy one until whichever client happens to
                # resubscribe it next — the message would've been silently
                # dropped via the fake-ack path below, no queue, no retry,
                # not just delayed. Deliberately a plain in-memory dict
                # lookup here, NOT a DB round-trip (db_get_anon_token_state,
                # removed) — external review: anon_channel is
                # unauthenticated and ANON_CHANNEL_MAX_PER_MINUTE is
                # per-connection, not global, so an attacker opening many
                # such connections and sending random 32-char strings could
                # turn every single unrecognized "token" into a thread-pool
                # SQLite SELECT, a real DoS surface a RAM-only reject never
                # had. anon_token_state_cache (loaded once at startup, kept
                # in sync on every write) restores the O(1) property while
                # still surviving a restart.
                if not is_known:
                    durable = anon_token_state_cache.get(_hash_anon_token(token))
                    if durable is not None:
                        db_owner, db_state = durable
                        if db_state == "ACTIVE":
                            is_known = True
                            # Only the safe RAM caches get restored —
                            # known_tokens/token_owner are pure bookkeeping.
                            # token_to_ws (live routing) is deliberately
                            # NEVER reconstructed from the DB — it only ever
                            # reflects an actual currently-connected
                            # websocket, and none exists yet for a token
                            # whose owner hasn't reconnected/resubscribed
                            # since the restart. This message still queues
                            # into token_pending below and waits for that
                            # real subscribe_tokens to happen, exactly like
                            # any other "recipient currently offline" case.
                            async with lock:
                                known_tokens.add(token)
                                token_owner[token] = db_owner
                        elif db_state in ("SPENT", "REVOKED"):
                            is_spent = True
                if not is_known or is_spent:
                    # Фейковый/cover-traffic токен ИЛИ уже доставленный и
                    # anon_delivery_ack'нутый ранее — оба дропаются одинаково
                    # (без очереди, без лога, с тем же "ack" отправителю), чтобы
                    # снаружи нельзя было отличить decoy-токен от настоящего, но
                    # уже потраченного — иначе разное поведение само по себе
                    # утекло бы информацию о том, какие токены реальны.
                    if msg_id:
                        await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                    continue

                # S6-59 recipient ingress budget (STEP 7) — resolved from
                # anon_token_state_cache, the durable owner record populated
                # at claim time for every token this server has ever issued
                # (loaded fully at startup, kept in sync on every write —
                # see its own comment above), NOT the token_owner RAM dict
                # (only populated on the restore-from-restart path above and
                # on revoke, so it can't be relied on as the general case).
                # Checked and enforced BEFORE the durable ACTIVE→IN_FLIGHT
                # claim below, so a recipient-capacity rejection can never
                # burn an otherwise-still-ACTIVE token — this is exactly the
                # ordering hazard STEP 8 calls out by name. Never keyed on a
                # raw attacker-supplied token string: if the cache has no
                # entry (token isn't real), no limiter entry is created and
                # no check runs — an attacker spraying garbage tokens cannot
                # grow this dict at all, only a token that has actually been
                # durably claimed by a real account can.
                durable_owner_entry = anon_token_state_cache.get(token_hash)
                recipient_owner = durable_owner_entry[0] if durable_owner_entry else None
                if recipient_owner is not None and not anon_relay_recipient_rate_ok(recipient_owner, pending_size):
                    if msg_id:
                        await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                    continue

                # Hard process-wide RAM cap on token_pending, reserved
                # BEFORE the durable ACTIVE→IN_FLIGHT claim below (external
                # review 2026-09-04, S6-30 — see TOKEN_PENDING_MAX_TOTAL_BYTES's
                # own comment for the full problem this closes). Ordering
                # is deliberate: reserve RAM capacity first, atomically, so
                # a capacity-full rejection never burns an otherwise-still-
                # ACTIVE token — db_mark_anon_token_inflight() below is
                # never even called if this fails. Same externally-
                # indistinguishable fake ack as every other anon_message
                # rejection path (unknown token, already spent) — a
                # capacity rejection must not itself leak whether the queue
                # happens to be full right now.
                async with lock:
                    reserved = _token_pending_try_reserve_locked(pending_size)
                if not reserved:
                    if msg_id:
                        await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                    continue

                # From this point on, this coroutine owns exactly one RAM
                # reservation that MUST be resolved via exactly one of
                # _token_pending_commit_reserved_locked()/
                # _token_pending_release_reservation_locked() on every exit
                # path below, including an unexpected exception or
                # cancellation — external review 2026-09-04, S6-30.
                # reservation_resolved tracks whether that already happened
                # on a normal path, so the `finally` block can release the
                # reservation on an ABNORMAL exit without ever double-
                # releasing (or leaking) it on a normal one.
                reservation_resolved = False
                try:
                    # Durable ACTIVE→IN_FLIGHT claim, BEFORE anything touches
                    # token_pending — found live 2026-09-03 (external review,
                    # two rounds). Round 1: the token's single-use guarantee
                    # only actually held at anon_delivery_ack time
                    # (spent_tokens.add(token) happened there), but the old
                    # token_pending commit ran unconditionally on every
                    # anon_message with a valid token, overwriting (not
                    # appending) whatever fallback copy was already queued —
                    # the SENDER knows the token, so nothing stopped them firing
                    # it twice before the first delivery was ever acked. Round
                    # 2: a same-process RAM-only "already claimed" check (an
                    # earlier version of this comment) doesn't survive a
                    # restart — token_pending is RAM-only by design (no sealed
                    # payload retention on disk, a deliberate trade-off, not
                    # revisited here), so a claimed-but-not-yet-acked token
                    # would silently look ACTIVE again in anon_token_state after
                    # a restart and could be spent a second time. This atomic
                    # DB transition (mirroring db_claim_anon_tokens()'s BEGIN
                    # IMMEDIATE) is what actually survives that: only one caller
                    # can ever win ACTIVE→IN_FLIGHT for a given token, checked
                    # and committed together, durable the instant it succeeds —
                    # not merely "true in this process's RAM right now". Known,
                    # accepted residual gap: if the process crashes AFTER this
                    # succeeds but BEFORE token_pending is set below, the
                    # already-IN_FLIGHT token's sealed payload is gone for good
                    # (a reliability/message-loss limitation, not a reuse
                    # bug) — see IN_FLIGHT's own comment in _db_setup_sync().
                    owner = await db_mark_anon_token_inflight(token)
                    if owner is None:
                        # Someone already spent/revoked/claimed this token, or
                        # it was never really ACTIVE at all — same externally-
                        # indistinguishable fake ack as an unknown token, on
                        # purpose: this is the real "one token, one message"
                        # guarantee, not merely "one token, one ACK". The RAM
                        # reservation taken above is released, not committed —
                        # no token_pending entry is ever created for a claim
                        # that never actually won (external review 2026-09-04,
                        # S6-30).
                        async with lock:
                            _token_pending_release_reservation_locked(pending_size)
                        reservation_resolved = True
                        if msg_id:
                            await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                        continue

                    # Race found live 2026-09-03 (external review, round 3): the
                    # DB transition above is an `await`, so anon_delivery_ack/
                    # unsubscribe_tokens/the TTL watchdog can each run their own
                    # complete DB-transition-plus-RAM-cleanup in the window
                    # between that await returning and this point — e.g.
                    # unsubscribe_tokens durably REVOKEs this exact token AND
                    # clears its RAM cache/token_pending entirely, all before
                    # this coroutine gets back here. Writing
                    # anon_token_state_cache/token_pending unconditionally at
                    # that point would resurrect a token SQLite already
                    # considers dead, purely in RAM. Fix: the cache write and
                    # the token_pending commit happen together, under the SAME
                    # lock, and only if the cache doesn't ALREADY show a
                    # terminal state — a terminal RAM state can never be
                    # overwritten back to IN_FLIGHT, matching what's already
                    # true in SQLite (this UPDATE already lost that race there;
                    # anon_delivery_ack_ok/subscribe_tokens_result will tell the
                    # sender's own reconciliation path, not this one, to catch
                    # up). If lost, this is the same externally-indistinguishable
                    # fake ack as any other rejected token. The RAM reservation
                    # is released (external review 2026-09-04, S6-30), same as
                    # the owner-is-None branch above, if this coroutine lost
                    # the race — no token_pending entry for a token the cache
                    # already considers terminal.
                    accepted = False
                    target_ws = None
                    async with lock:
                        cached = anon_token_state_cache.get(token_hash)
                        cached_state = cached[1] if cached else None
                        if cached_state not in ("SPENT", "REVOKED"):
                            anon_token_state_cache[token_hash] = (owner, "IN_FLIGHT")
                            _token_pending_commit_reserved_locked(token, delivery_obj, pending_size)
                            target_ws = token_to_ws.get(token)
                            accepted = True
                        else:
                            _token_pending_release_reservation_locked(pending_size)
                    reservation_resolved = True

                    if not accepted:
                        if msg_id:
                            await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                        continue

                    if target_ws:
                        ok = await send_safe(target_ws, delivery_json)
                        if ok:
                            print(f"[ANON] Отправлено по токену …{token[-6:]} (ждём anon_delivery_ack)")
                        # else: получатель закрыл сокет между проверкой и отправкой — уже в очереди выше
                    else:
                        # Токен не зарегистрирован локально — раньше здесь была
                        # попытка federation-форварда по fingerprint из
                        # payload.get("to"). Убрано 2026-08-30 (docs/TODO.md
                        # decision, вариант "принять и честно
                        # задокументировать"): начиная с item 31, payload для
                        # реального 1:1-трафика (sendAnonOrDirect/
                        # sendWithForwardSecrecy/sendAnonTokensTo — то есть
                        # практически весь живой anon_message-трафик) — это
                        # непрозрачный {"id":..., "blob":...}, "to" лежит внутри
                        # зашифрованного blob, а не в открытом JSON. Код молча
                        # ловил fed_to=None и просто ставил сообщение в очередь —
                        # тот же итог, что и без этой ветки вообще, только с
                        # лишним неработающим путём, вводящим в заблуждение
                        # будущего читателя. Кросс-серверная доставка 1:1-сообщений
                        # между узлами федерации для sealed-трафика сейчас не
                        # поддерживается — см. SECURITY.md/ARCHITECTURE.md.
                        print(f"[ANON] Токен …{token[-6:]} офлайн, сообщение в очереди")
                    if msg_id:
                        await send_safe(websocket, json.dumps({"type": "ack", "id": msg_id}))
                    continue
                finally:
                    if not reservation_resolved:
                        # An exception or cancellation interrupted this
                        # coroutine somewhere between taking the reservation
                        # and resolving it on a normal path — release it here
                        # rather than leaking reserved capacity forever
                        # (external review 2026-09-04, S6-30). A no-op on
                        # every normal exit: each one above already sets
                        # reservation_resolved = True before its own
                        # `continue`, so this only ever fires on the abnormal
                        # path.
                        async with lock:
                            _token_pending_release_reservation_locked(pending_size)

            # ─── Anonymous Mailbox ────────────────────────────────────────────
            # global mailbox_total_bytes/mailbox_total_blobs declared once
            # for the rest of this function (mailbox_put and mailbox_fetch
            # below both rebind them) — external review 2026-09-04, S6-29.
            global mailbox_total_bytes, mailbox_total_blobs
            if msg_type == "mailbox_put":
                if not rate_limit_check(username, "mailbox_put"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                tag  = message.get("tag", "")
                blob = message.get("blob", "")
                # isinstance(tag, str) before len(tag)/iterating its chars —
                # same uncaught-TypeError-closes-the-connection bug class as
                # anon_message/anon_delivery_ack above (found by the same
                # fuzz run, 2026-09-25): a JSON-truthy non-string tag (e.g.
                # the boolean true) made len(tag) raise TypeError here,
                # uncaught until handle_client()'s top-level `except
                # Exception`, ending the whole connection instead of just
                # dropping this one malformed message.
                if (not tag or not isinstance(tag, str) or not blob
                        or len(tag) != MAILBOX_TAG_LEN
                        or not all(c in "0123456789abcdef" for c in tag)
                        or not isinstance(blob, str)
                        or len(blob) > MAILBOX_MAX_BLOB):
                    continue
                now = time.time()
                async with lock:
                    # Fast path: clean only THIS tag's expired entries, not
                    # a full mailbox scan — see mailbox_watchdog()'s own
                    # comment for why a full scan on every put would itself
                    # be an O(n) cost per request; the hard caps below are
                    # what bounds that periodic full scan's own worst case
                    # instead.
                    _mailbox_cleanup_tag_expired_locked(tag, now)
                    existing = mailbox.get(tag, [])
                    if len(existing) >= 5:  # max 5 блобов на тег — защита от DoS
                        continue
                    # Hard process-wide caps, checked BEFORE appending
                    # (external review 2026-09-04, S6-29) — real global TTL
                    # enforcement (the watchdog above) still lets unbounded
                    # RAM accumulate for up to MAILBOX_TTL from
                    # never-touched-again unique tags; these two caps are
                    # the actual backstop bounding that window's worst case
                    # regardless of TTL. Silently rejected — same
                    # externally-indistinguishable behavior as every other
                    # mailbox_put failure path (invalid tag/blob, per-tag
                    # cap), so remaining capacity can't be probed from
                    # outside. See mailbox_total_bytes's own comment (near
                    # MAILBOX_TTL) for the full reasoning.
                    if (mailbox_total_blobs + 1 > MAILBOX_MAX_TOTAL_BLOBS
                            or mailbox_total_bytes + len(blob) > MAILBOX_MAX_TOTAL_BYTES):
                        continue
                    existing.append({"blob": blob, "ts": now})
                    mailbox[tag] = existing
                    mailbox_total_bytes += len(blob)
                    mailbox_total_blobs += 1
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
                        # Same delete-on-fetch semantics as before this fix
                        # (deliberately unchanged — see this handler's own
                        # note above about not mixing in the separate
                        # delete-before-send-reliability question). Counter
                        # decrement covers the FULL set of entries actually
                        # being removed (all_entries), not just the
                        # still-live subset returned to the caller (blobs)
                        # — external review 2026-09-04, S6-29: an
                        # already-expired entry sharing a tag with a
                        # still-live one is removed by the same `del`
                        # either way, and must be counted out here too, or
                        # the global counters would slowly drift upward
                        # from reality.
                        all_entries = mailbox.get(tag, [])
                        blobs = [e for e in all_entries if now - e["ts"] < MAILBOX_TTL]
                        if blobs:
                            result[tag] = [e["blob"] for e in blobs]
                            mailbox_total_bytes -= sum(len(e["blob"]) for e in all_entries)
                            mailbox_total_blobs -= len(all_entries)
                            del mailbox[tag]
                if result:
                    await send_safe(websocket, json.dumps({"type": "mailbox_result", "blobs": result}))
                continue

            # register_fcm — сохраняем FCM-токен пользователя (S6-52)
            if msg_type == "register_fcm":
                token = message.get("fcm_token", "")
                # FCM registration tokens are opaque, Firebase-issued strings
                # with no documented exact format/alphabet -- only bound by
                # type/length (FCM_TOKEN_MAX_LEN, generous headroom over any
                # observed real-world token), never an invented regex on
                # content. Rejected before ever touching clients RAM.
                if not isinstance(token, str) or not token or len(token) > FCM_TOKEN_MAX_LEN:
                    continue
                # Identical re-registration is a no-op BEFORE the rate check
                # (S6-52, STEP 2) -- mirrors S6-50's avatar-mutation ordering
                # exactly: Android's own reconnect flow re-sends its
                # last-known token on nearly every reconnect (falls back to
                # the cached token when no NEW one is pending), so this is
                # the overwhelmingly common case, not an edge case.
                async with lock:
                    current_token = clients.get(username, {}).get("fcm_token")
                if current_token == token:
                    continue
                if not rate_limit_check(username, "register_fcm"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                async with lock:
                    if username in clients:
                        clients[username]["fcm_token"] = token
                print(f"[FCM] Токен сохранён для {username}")
                continue

            # ─── Device-gated registration TOTP: one-time setup ─────────────────
            # Refused if this account already has a working secret UNLESS the
            # caller proves it either still has a valid current code for it, or
            # a valid unused recovery code — an account can never have its
            # secret silently replaced by someone who only holds the private
            # key (e.g. a stolen backup), but a legitimate user who lost their
            # authenticator (which is exactly what a recovery code proves —
            # see the register()/recovery_code path above, changed the same day
            # this comment was added) must still have a way to properly
            # re-enroll rather than being stuck re-spending recovery codes on
            # every future device forever.
            if msg_type == "totp_setup":
                if not username:
                    continue
                # S6-48 (external review 2026-09-05): dedicated per-user
                # rate limit, checked at the TOP of this handler regardless
                # of whether TOTP is already enabled for this account —
                # SECOND_FACTOR_GUARD_* below only ever engages for an
                # ALREADY-enrolled account's re-enrollment proof, so a
                # first-time setup attempt (no existing secret, the actual
                # resource-exhaustion path this fix closes) never reached
                # any per-attempt guard at all before this. Independent of,
                # not a replacement for, that durable guard — see
                # TOTP_SETUP_RATE_LIMIT's own comment.
                if not rate_limit_check(username, "totp_setup"):
                    await send_safe(websocket, json.dumps({"type": "error", "reason": "Rate limit exceeded"}))
                    continue
                # Whole state-dependent operation held under the SAME
                # account-scoped lock register() uses (external review
                # 2026-09-04, S6-32) — see totp_state_locks' own comment.
                # The re-check of `username in user_totp_secrets` right
                # below, the durable commit, and the matching RAM write
                # (`user_totp_secrets[username] = new_secret`) all happen
                # without ever releasing this lock in between — a
                # concurrent register() for this same fingerprint can now
                # never observe the moment in between the DB commit and the
                # RAM write.
                #
                # TWO INDEPENDENT PROOFS, never the same wire field (external
                # review 2026-09-04, S6-33) — found live: this used to read
                # `message["code"]` for BOTH (a) proving possession of the
                # CURRENT secret when re-enrolling, and (b) validating the
                # NEW secret being enrolled. Those are two unrelated TOTP
                # secrets — a code that validates against one essentially
                # never validates against the other by coincidence (1 in
                # ~10^6) — so current-TOTP-authorized re-enrollment was
                # practically unusable; only the recovery_code fallback ever
                # actually worked. Worse, the OLD ordering tried the
                # dual-purpose field against the CURRENT secret FIRST, before
                # ever validating it against the NEW one, so a lucky/attacker-
                # forced coincidental match could consume the current TOTP
                # counter even though setup was about to fail validation of
                # the new secret anyway. Fixed with three distinct fields —
                # `new_code` (proof for `secret`, the new one — required
                # always), `current_code` (proof for the EXISTING secret,
                # only meaningful/read when already enrolled), `recovery_code`
                # (alternative proof for the existing account) — validated in
                # an order where an invalid new_code is rejected immediately,
                # before either existing-secret proof is ever attempted, so a
                # doomed setup attempt never burns a current TOTP time-step or
                # a recovery code for nothing. `new_code` falls back to the
                # legacy `code` field for clients not yet updated to send it
                # explicitly (Android historically always sent the NEW
                # secret's code under that name, never a current-secret
                # proof — see MessengerService.kt's sendTotpSetup()).
                async with get_totp_state_lock(username):
                    already_enabled = username in user_totp_secrets

                    new_secret_raw = message.get("secret", "")
                    new_code_raw   = message.get("new_code") or message.get("code", "")

                    # S6-48: cheap type/length/shape validation BEFORE the
                    # process-wide setup-work budget below, and well before
                    # totp_code_matches() ever runs — a malformed/oversized
                    # secret or code is rejected for free, never consuming
                    # that budget (see TOTP_SETUP_GLOBAL_LIMIT's own
                    # comment for why that ordering matters).
                    new_secret = decode_totp_secret(new_secret_raw)
                    if new_secret is None or not is_valid_totp_code(new_code_raw):
                        await send_safe(websocket, json.dumps({"type": "totp_setup_failed", "reason": "invalid_code"}))
                        continue

                    # Process-wide setup-work budget (S6-48) — only a
                    # syntactically-valid-shaped secret/code pair ever
                    # reaches this point, so this bounds aggregate REAL
                    # verification work across Sybil accounts, not garbage
                    # input (which is already free to reject above).
                    if not totp_setup_global_rate_ok():
                        await send_safe(websocket, json.dumps({"type": "totp_setup_failed", "reason": "invalid_code"}))
                        continue

                    # Validate the NEW secret/new_code — pure verification
                    # (totp_code_matches), no DB write, no counter/recovery-
                    # code consumption — before either existing-secret proof
                    # below is ever attempted.
                    if totp_code_matches(new_secret, new_code_raw) is None:
                        await send_safe(websocket, json.dumps({"type": "totp_setup_failed", "reason": "invalid_code"}))
                        continue

                    if already_enabled:
                        # Second-factor online-brute-force guard (external
                        # review 2026-09-04) — see
                        # db_take_second_factor_attempt()'s own comment. Gates
                        # the current_code/recovery_code proof below, before
                        # it's checked, same as register()'s device-auth path.
                        if not await db_take_second_factor_attempt(username):
                            print(f"[SECURITY] totp_setup: second-factor rate limit для {username}")
                            await send_safe(websocket, json.dumps({"type": "second_factor_rate_limited"}))
                            continue
                        current_code   = message.get("current_code", "")
                        proof_recovery = message.get("recovery_code", "")
                        authorized_via = None
                        # S6-48: is_valid_totp_code()/is_valid_recovery_code()
                        # checked before either proof function ever runs —
                        # totp_verify_and_consume() -> totp_code_matches()
                        # already defends itself, but db_check_and_consume_
                        # recovery_code() has no such internal guard, so a
                        # huge recovery_code would otherwise still reach
                        # _hash_recovery_code()'s strip()/upper()/SHA-256.
                        if is_valid_totp_code(current_code) and await totp_verify_and_consume(username, current_code):
                            authorized_via = "current TOTP code"
                        elif is_valid_recovery_code(proof_recovery) and await db_check_and_consume_recovery_code(username, proof_recovery):
                            authorized_via = "recovery code"
                        if authorized_via is None:
                            await send_safe(websocket, json.dumps({"type": "totp_setup_failed", "reason": "already_enabled"}))
                            continue
                        print(f"[TOTP] {username}: re-enrollment authorized ({authorized_via})")

                    # Recovery codes are the safety net for "lost the authenticator" --
                    # generated once here, shown to the user exactly once by the
                    # client, never retrievable again (only hashes are stored).
                    # This always fully replaces any prior codes (including ones
                    # left over from a previous secret being re-enrolled above) --
                    # a fresh secret with stale old codes still valid for it would
                    # be inconsistent.
                    new_recovery_codes = generate_recovery_codes()
                    # Secret + recovery codes committed in ONE durable transaction
                    # BEFORE touching RAM or replying (external review 2026-09-03)
                    # — replaces two independent fire-and-forget create_task()
                    # writes that used to run only *after* totp_setup_ok had
                    # already been sent. A crash between "client got
                    # totp_setup_ok" and either write landing used to leave
                    # user_totp with no row at all (silent downgrade back to
                    # TOTP-disabled) or a secret with no matching recovery codes
                    # (unrecoverable). See _db_commit_totp_setup_sync's own
                    # comment. last_counter needs no separate reset — the
                    # INSERT OR REPLACE inside that transaction recreates the
                    # whole row, so it gets DEFAULT (-1) automatically; see
                    # totp_verify_and_consume()'s own comment. If this raises,
                    # the `async with` above still releases the lock (via
                    # __aexit__) and user_totp_secrets is never reached — RAM
                    # stays exactly as it was before this call (external
                    # review 2026-09-04, S6-32).
                    await db_commit_totp_setup(username, new_secret, new_recovery_codes)
                    user_totp_secrets[username] = new_secret
                    print(f"[TOTP] Device-gated registration protection enabled for {username}")
                    await send_safe(websocket, json.dumps({
                        "type": "totp_setup_ok",
                        "recovery_codes": new_recovery_codes
                    }))
                continue

            # ─── Device-gated registration TOTP: disable ────────────────────────
            # Requires a valid current code, OR (added 2026-08-30, same
            # reasoning as totp_setup above) a valid unused recovery code —
            # proof of the secret or of lost-authenticator recovery access, not
            # just the private key, so a stolen backup+password alone still
            # can't turn this protection off.
            if msg_type == "totp_disable":
                if not username:
                    continue
                # Same account-scoped lock as totp_setup/register() (external
                # review 2026-09-04, S6-32) — see totp_state_locks' own
                # comment. The `username not in user_totp_secrets` re-check,
                # the durable delete, and the matching RAM pop all happen
                # under the SAME held lock.
                async with get_totp_state_lock(username):
                    if username not in user_totp_secrets:
                        continue
                    # Second-factor online-brute-force guard (external review
                    # 2026-09-04) — see db_take_second_factor_attempt()'s own
                    # comment. Same gate as totp_setup/register(); disabling
                    # TOTP is exactly as sensitive a second-factor proof as
                    # enabling it.
                    if not await db_take_second_factor_attempt(username):
                        print(f"[SECURITY] totp_disable: second-factor rate limit для {username}")
                        await send_safe(websocket, json.dumps({"type": "second_factor_rate_limited"}))
                        continue
                    code = message.get("code", "")
                    recovery_code = message.get("recovery_code", "")
                    authorized = await totp_verify_and_consume(username, code)
                    # S6-48: is_valid_recovery_code() checked before this
                    # proof runs — db_check_and_consume_recovery_code() has
                    # no internal shape guard of its own (unlike
                    # totp_verify_and_consume(), which now defends itself
                    # via totp_code_matches()), so a huge recovery_code
                    # would otherwise still reach _hash_recovery_code()'s
                    # strip()/upper()/SHA-256.
                    if not authorized and is_valid_recovery_code(recovery_code):
                        authorized = await db_check_and_consume_recovery_code(username, recovery_code)
                    if not authorized:
                        await send_safe(websocket, json.dumps({"type": "totp_disable_failed"}))
                        continue
                    # user_totp + totp_recovery_codes deleted in ONE durable
                    # transaction BEFORE touching RAM or replying (external
                    # review 2026-09-03) — same crash-window reasoning as
                    # totp_setup above, mirrored for disable: totp_disable_ok
                    # must never be sent before both durably land. See
                    # _db_commit_totp_disable_sync's own comment. No separate
                    # last_counter cleanup needed — that transaction removes the
                    # whole user_totp row (counter included). If this raises,
                    # the `async with` above still releases the lock and
                    # user_totp_secrets is never popped — RAM stays enabled,
                    # matching the still-durably-enabled DB state (external
                    # review 2026-09-04, S6-32).
                    await db_commit_totp_disable(username)
                    del user_totp_secrets[username]
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
                ack_confirmed = False
                # isinstance(token, str) before len(token) — same
                # uncaught-TypeError-kills-the-connection bug as
                # anon_message above, same fix, found by the same fuzz run
                # (2026-09-25).
                if isinstance(token, str) and token and len(token) == MAX_TOKEN_LEN:
                    # Ownership check added (external review 2026-08-23):
                    # this previously accepted an ACK for any token from
                    # ANY authenticated connection, not just the one that
                    # actually registered/owns it via subscribe_tokens. The
                    # sender itself knows the token it just used to send a
                    # message, so it could "confirm" its own message's
                    # delivery to a recipient who never actually received or
                    # processed anything — destroying the token_pending
                    # fallback copy before the real recipient ever got a
                    # chance to ACK it for real. Only honored if the current
                    # websocket is the one currently routed for this token.
                    async with lock:
                        is_current_owner = token_to_ws.get(token) is websocket
                    if is_current_owner:
                        # Persisted to SQLite BEFORE any RAM cleanup — found
                        # live 2026-09-03 (external review): the state a
                        # client relies on (via subscribe_tokens_result on a
                        # later reconnect, if this ack itself is what gets
                        # lost past this point) needs to already be durable
                        # the instant this succeeds, not just "will be, once
                        # some later RAM-only write also happens to run".
                        # owner=username double-checks against the DB's own
                        # permanent record, independent of the live
                        # token_to_ws mapping just checked above.
                        persisted = await db_terminalize_anon_token(token, username, "SPENT")
                        if not persisted:
                            print(f"[SECURITY] anon_delivery_ack: не удалось подтвердить владельца токена …{token[-6:]} в БД")
                        else:
                            # Cache write combined with the RAM cleanup under
                            # ONE lock (external review 2026-09-03, round 3) —
                            # see unsubscribe_tokens'/anon_message's own
                            # comments on this same fix: a terminal
                            # transition has to land in
                            # anon_token_state_cache and token_pending/
                            # routing together, or a concurrent anon_message
                            # could still resurrect this token in RAM after
                            # this coroutine already considered it done.
                            async with lock:
                                anon_token_state_cache[_hash_anon_token(token)] = (username, "SPENT")
                                # Canonical removal (external review
                                # 2026-09-04, S6-30) — see
                                # unsubscribe_tokens' own comment on this
                                # same replacement.
                                _token_pending_remove_locked(token)
                                token_to_ws.pop(token, None)
                                ws_to_tokens.get(websocket, set()).discard(token)
                                # Marked spent, not just removed from
                                # token_to_ws (external review 2026-08-23) —
                                # token_to_ws only tracked live routing, not
                                # single-use history; known_tokens is never
                                # cleared, so a replayed anon_message with
                                # this same token was still accepted as
                                # "real" and could silently overwrite
                                # token_pending[token] with a new entry. See
                                # the anon_message handler's is_spent check
                                # above. RAM cache only now — SQLite (just
                                # above) is the durable record.
                                spent_tokens.add(token)
                                ack_confirmed = True
                            print(f"[ANON] Подтверждена доставка токена …{token[-6:]}")
                    else:
                        print(f"[SECURITY] anon_delivery_ack: токен …{token[-6:]} не принадлежит этому соединению — игнорируем")
                    # Sent outside the lock (network I/O shouldn't hold it) —
                    # explicit confirmation that pending/spent state above is
                    # now durable server-side. Without this, the client's own
                    # "did my ack actually leave the socket" signal is not
                    # proof the server ever received/processed it (found live
                    # 2026-09-03, external review): a client that removed its
                    # own copy of the token right after locally sending the
                    # ack — before knowing whether it truly landed — could
                    # never re-subscribe to it after a reconnect if the ack
                    # was lost in flight, permanently orphaning this
                    # token_pending entry until its 24h TTL sweep. See
                    # AnonTokenManager.kt's ACK_PENDING state on the client.
                    # And if THIS confirmation itself gets lost after the DB
                    # write above already succeeded, subscribe_tokens_result
                    # (see the subscribe_tokens handler) is what closes that
                    # remaining gap on the client's next reconnect.
                    if ack_confirmed:
                        await send_safe(websocket, json.dumps({"type": "anon_delivery_ack_ok", "token": token}))
                continue

            # ─── Client-side diagnostic "ticket" ─────────────────────────────────
            # Fired by the client once, after 5 minutes of a stuck first-contact
            # mailbox bootstrap (docs/ISSUE_backup_identity_hijack.md, "5-минутный
            # ретрай"). Deliberately carries no target/contact info — just a
            # clearly-tagged log line for the operator to find via
            # Server/admin_logs.py while investigating, not an automated report
            # to anyone.
            if msg_type == "bootstrap_diagnostic":
                if not username or not rate_limit_check(username, "bootstrap_diagnostic"):
                    continue
                print(f"[TICKET] {username}: mailbox-бутстрап первого контакта завис дольше 5 минут")
                continue

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
                    # Only erase peer's entry if it still reciprocally points
                    # back at username + this exact call_id (S6-61) — peer may
                    # already be in a newer, unrelated call by the time this
                    # runs, and an unconditional pop would silently corrupt
                    # that real state. The disconnect notification below is
                    # still sent unconditionally — it reflects username's own
                    # recorded call, regardless of what peer's bookkeeping
                    # has since moved on to.
                    if active_call_matches(peer, username, call_id):
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
                # S6-59: per-connection anon-relay byte budget is keyed on
                # this exact websocket object (no username to key it on for
                # an anon_channel connection) — must be dropped here or it
                # leaks one dict entry per connection forever across
                # reconnects/churn, same posture as every other per-
                # websocket cleanup in this block.
                anon_relay_conn_rate.pop(websocket, None)
                owned_tokens = ws_to_tokens.pop(websocket, set())
                for t in owned_tokens:
                    # Deliberately NOT clearing a bootstrap reservation here
                    # (external review 2026-09-03, round 2) — a disconnect
                    # doesn't mean the requester who was handed this token as
                    # a bootstrap address forgot it; they can still send with
                    # it any time before it's actually spent/revoked/expires.
                    # An earlier version discarded the reservation on
                    # disconnect specifically to avoid tokens getting stuck
                    # reserved forever — but that reopened the exact race
                    # this reservation exists to close: a second person
                    # fetching the same target's bundle right after the first
                    # requester's connection happened to drop (a routine,
                    # frequent event, not a rare edge case) could be handed
                    # the SAME token, which the first requester might still
                    # be about to use. See token_owner's own comment (near
                    # the top of this file) for bootstrap reservation's full
                    # history: the only things that ever clear a reservation
                    # now are the token's own terminal-state transitions
                    # (ACK, TTL watchdog, revoke, or the restart-time
                    # IN_FLIGHT sweep) via _db_terminalize_anon_token_sync().
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
        # URL is a hardcoded literal, not attacker-controlled input -- the
        # rule flags urllib's file:// support as an SSRF/arbitrary-file-read
        # risk when the URL comes from user data, which isn't the case here.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
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
            # Actually tear down the peer's lifecycle, not just stop
            # tracking it (external review 2026-09-04) — this used to only
            # remove bookkeeping entries, leaving federation_connect_to_peer()'s
            # `while True` reconnect loop for this URL running in the
            # background indefinitely, invisible (not in dynamic_peer_urls
            # anymore) and unstoppable (no reference to its Task existed
            # anywhere). Cancelling via dynamic_peer_tasks is the real fix;
            # discarding url from dynamic_peer_urls FIRST also means that
            # even if this cancel is somehow lost, the Task's own
            # `dynamic=True` self-check (federation_connect_to_peer's own
            # comment) will see this URL is gone and return on its next
            # loop iteration instead of reconnecting.
            dynamic_peer_urls.discard(url)
            dynamic_peer_strikes.pop(url, None)
            task = dynamic_peer_tasks.pop(url, None)
            if task is not None:
                task.cancel()
            ws = federation_ws.pop(url, None)
            if ws is not None:
                asyncio.create_task(ws.close())
            print(f"[WATCHDOG] Пир удалён из реестра: {url}")


# ─── Watchdog: TTL для anonymous mailbox (external review 2026-09-04, S6-29) ──
# See mailbox_total_bytes's own comment (near MAILBOX_TTL) for the full
# problem this closes: lazy per-tag-only TTL enforcement let a
# never-touched-again tag sit in `mailbox` forever, unbounded.

def _mailbox_cleanup_tag_expired_locked(tag: str, now: float) -> None:
    """Removes expired entries from exactly ONE mailbox tag, decrementing
    the global byte/blob counters for whatever it actually removes. MUST
    be called with `lock` already held — every mutation of `mailbox`/
    `mailbox_total_bytes`/`mailbox_total_blobs` together happens under that
    same lock, no exceptions. Shared by mailbox_watchdog()'s full sweep
    (called once per tag, in a loop) and mailbox_put()'s own per-tag fast
    path (called for just the one tag being written to) — one place owns
    the counter bookkeeping for an expired-entry removal, not two
    independently-maintained copies of the same logic."""
    global mailbox_total_bytes, mailbox_total_blobs
    entries = mailbox.get(tag)
    if not entries:
        return
    live = []
    for entry in entries:
        if now - entry["ts"] < MAILBOX_TTL:
            live.append(entry)
        else:
            mailbox_total_bytes -= len(entry["blob"])
            mailbox_total_blobs -= 1
    if live:
        mailbox[tag] = live
    else:
        mailbox.pop(tag, None)


def _mailbox_cleanup_expired_locked(now: float) -> None:
    """Full-mailbox expiry scan — MUST be called with `lock` already held.
    Only mailbox_watchdog() ever runs this over the WHOLE mailbox;
    mailbox_put()'s own fast path deliberately never triggers a full scan,
    only ever cleaning the one tag it's about to write to via
    _mailbox_cleanup_tag_expired_locked() directly — see that function's
    own comment. The two hard caps (MAILBOX_MAX_TOTAL_BYTES/
    MAILBOX_MAX_TOTAL_BLOBS) are what keeps THIS scan's own worst case
    bounded, independent of how long the watchdog's interval is."""
    for tag in list(mailbox.keys()):
        _mailbox_cleanup_tag_expired_locked(tag, now)


async def mailbox_watchdog():
    while True:
        await asyncio.sleep(MAILBOX_CLEANUP_INTERVAL_SEC)
        now = time.time()
        async with lock:
            _mailbox_cleanup_expired_locked(now)


# ─── Watchdog: TTL для token_pending (раз в час) ─────────────────────────────
# token_pending — чистая in-memory очередь без персистентности (осознанно, см.
# комментарий у anon_message выше): рестарт сервера и так её обнуляет. Но пока
# сервер живёт, запись держится там БЕЗГРАНИЧНО, пока получатель не пришлёт
# anon_delivery_ack — если получатель пропал на дни/недели (не просто на
# реконнект), это неограниченный рост в ОЗУ. TTL 24ч: после этого срока
# сообщение считается устаревшим и вычищается — тот же принцип, что и у
# pending_messages в SQLite (MSG_TTL_SEC), просто отдельный, более короткий
# срок для in-memory очереди.
async def _token_pending_watchdog_tick():
    """One full sweep of token_pending_watchdog()'s logic, factored out of
    the `while True: sleep` wrapper (external review 2026-09-04, S6-30) —
    same reasoning as mailbox_watchdog()/_mailbox_cleanup_expired_locked()'s
    own split: lets tests (and any future caller) drive exactly one sweep
    directly, without needing to fake out asyncio.sleep(3600) globally.

    Found live 2026-09-03 (external review): this used to just pop the
    RAM-only token_pending/token_pending_created entries and stop there —
    but a token surviving to this point is, by construction, IN_FLIGHT in
    anon_token_state (anon_message's db_mark_anon_token_inflight() is the
    only thing that ever creates a token_pending entry in the first
    place). Leaving it IN_FLIGHT forever after this cleanup is the exact
    same zombie-state _db_setup_sync()'s startup sweep exists to prevent
    for a restart — the server permanently refuses to accept a new
    anon_message on this token, but the owning client, having no signal,
    keeps treating it as spendable. Closed the same way here: terminalize
    to SPENT via the existing durable path, so it reaches the client
    through the existing subscribe_tokens_result: "spent" reconciliation
    the next time they resubscribe — same self-healing story as
    anon_delivery_ack_ok itself getting lost."""
    now = time.time()
    async with lock:
        expired = [t for t, created in token_pending_created.items()
                   if now - created > TOKEN_PENDING_TTL_SEC]
    cleaned = 0
    for t in expired:
        token_hash = _hash_anon_token(t)
        cached = anon_token_state_cache.get(token_hash)
        owner = cached[0] if cached else token_owner.get(t)
        if owner is None:
            # Shouldn't happen — db_mark_anon_token_inflight() always
            # records an owner before token_pending is ever set — but if
            # it somehow does, there's nothing safe to terminalize
            # against; just drop the RAM-only entry so it stops being
            # considered every hour. Canonical removal (external review
            # 2026-09-04, S6-30) — see unsubscribe_tokens' own comment
            # on this same replacement.
            async with lock:
                _token_pending_remove_locked(t)
            continue
        persisted = await db_terminalize_anon_token(t, owner, "SPENT")
        if not persisted:
            print(f"[SECURITY] token_pending_watchdog: не удалось подтвердить владельца токена …{t[-6:]} в БД")
            continue
        # Cache write combined with the RAM cleanup under ONE lock
        # (external review 2026-09-03, round 3) — see unsubscribe_tokens'/
        # anon_delivery_ack's/anon_message's own comments on this same
        # fix: a terminal transition has to land in
        # anon_token_state_cache and token_pending/routing together, or
        # a concurrent anon_message could still resurrect this token in
        # RAM after this coroutine already considered it done.
        owner_ws = None
        async with lock:
            anon_token_state_cache[token_hash] = (owner, "SPENT")
            spent_tokens.add(t)
            # Canonical removal (external review 2026-09-04, S6-30) —
            # see unsubscribe_tokens' own comment on this same
            # replacement.
            _token_pending_remove_locked(t)
            owner_ws = token_to_ws.pop(t, None)
            if owner_ws is not None:
                ws_to_tokens.get(owner_ws, set()).discard(t)
        cleaned += 1
        # Best-effort — if the owner isn't online right now (likely,
        # given this token has been undelivered for 24h+), or this send
        # itself is lost, the same subscribe_tokens_result reconciliation
        # fires on their next subscribe_tokens regardless.
        if owner_ws is not None:
            await send_safe(owner_ws, json.dumps({"type": "subscribe_tokens_result", "spent": [t]}))
    if cleaned:
        print(f"[WATCHDOG] token_pending: {cleaned} устаревших (>24ч) IN_FLIGHT-записей приведено к SPENT")


async def token_pending_watchdog():
    while True:
        await asyncio.sleep(3600)
        await _token_pending_watchdog_tick()


# ─── Запуск ───────────────────────────────────────────────────────────────────

# Bind address, overridable for local test/stress harnesses that must never
# touch the production 0.0.0.0:9000 default — see Server/tests/protocol_harness.py
# and Server/stress/, both of which set these to 127.0.0.1 + an isolated free
# port and assert loopback-only before starting anything adversarial.
SUBROSA_BIND_HOST = os.environ.get("SUBROSA_BIND_HOST", "0.0.0.0")
SUBROSA_BIND_PORT = int(os.environ.get("SUBROSA_BIND_PORT", "9000") or "9000")


def _print_at_rest_posture():
    """Report, at every start, which optional protections are OFF.

    All three are opt-in and default to off for backwards compatibility with
    deployments that predate them. That is a defensible default, but it made
    the state invisible: the operator had no way to tell a hardened deployment
    from a bare one short of reading their own .env, and the repository's
    recommended Docker quick start used to point at a root .env.example that
    did not mention these keys at all -- so the configuration a new operator
    actually ran was the least protected one available, silently.

    Deliberately NOT fatal. Making an unencrypted database refuse to start
    would break every existing deployment on upgrade, and a personal server
    with open registration is a legitimate configuration. The goal is that
    nobody ends up in this state without having been told.

    Wording is English on purpose, unlike most output here: this message is
    read together with .env.example and the README by operators deploying
    their own instance, who are not necessarily Russian-speaking.
    """
    off = []
    if not DB_ENCRYPTION_KEY_HEX:
        off.append(
            "  - Database at-rest encryption is OFF (DB_ENCRYPTION_KEY_HEX unset).\n"
            "    The offline message queue, registration records and routing tokens\n"
            "    are plaintext on disk. End-to-end encrypted message CONTENT is not\n"
            "    affected. Cannot be enabled later without an empty database."
        )
    if _totp_fernet is None:
        off.append(
            "  - TOTP secrets are stored unencrypted (TOTP_SECRET_ENCRYPTION_KEY unset).\n"
            "    Can be enabled later; existing rows migrate on next save."
        )
    if not SERVER_ACCESS_PROTECTED:
        off.append(
            "  - Registration is OPEN (SERVER_ACCESS_PROTECTED unset).\n"
            "    Anyone who can reach this server can create an account on it.\n"
            "    Correct for a personal server; wrong for a firm deployment."
        )

    if not off:
        print("[*] At-rest protection: database encrypted, TOTP secrets encrypted, "
              "registration gated by access code.")
        return

    print("[!] Optional protections not enabled on this deployment:")
    for item in off:
        print(item)
    print("[!] See .env.example for what each one covers and how to generate keys.")


async def main(ssl_context=None):
    global _fed_ssl_ctx
    # Start outgoing federation connections
    if FEDERATION_SECRET:
        # Real TLS peer authentication for every outgoing federation
        # connection (external review 2026-09-04) — see
        # build_federation_ssl_context()'s own comment for why the
        # previous CERT_NONE/check_hostname=False context made the
        # FEDERATION_SECRET HMAC handshake relayable by a MITM that never
        # needs to know the secret at all. Built unconditionally whenever
        # federation is enabled, independent of whether THIS server's own
        # listening socket happens to have TLS configured (ssl_context
        # above) — that's an unrelated setting; outgoing federation
        # connections always need real peer verification regardless.
        _fed_ssl_ctx = build_federation_ssl_context()
        if FEDERATION_PEERS:
            non_wss = [p for p in FEDERATION_PEERS if not is_valid_federation_url(p)]
            if non_wss:
                # Fail closed at startup, not per-connection — a ws://
                # federation peer has no TLS at all, so no certificate
                # verification could ever apply to it; refusing to even
                # start makes the misconfiguration impossible to miss,
                # rather than silently downgrading just that one peer.
                raise RuntimeError(
                    "FEDERATION_PEERS must all use wss:// (federation requires "
                    f"verified TLS, never plaintext ws://) — found: {non_wss}"
                )
            print(f"[FEDERATION] Инициализация: {len(FEDERATION_PEERS)} пиров → {FEDERATION_PEERS}")
            for peer_url in FEDERATION_PEERS:
                asyncio.create_task(federation_connect_to_peer(peer_url, _fed_ssl_ctx))
        else:
            print("[FEDERATION] FEDERATION_SECRET задан, но FEDERATION_PEERS пуст — сервер принимает входящих пиров")

    if FEDERATION_SECRET:
        asyncio.create_task(federation_watchdog())
        print("[WATCHDOG] Запущен (проверка пиров каждые 3600с)")

    asyncio.create_task(token_pending_watchdog())
    print(f"[WATCHDOG] token_pending TTL запущен (проверка раз в час, TTL={TOKEN_PENDING_TTL_SEC//3600}ч, "
          f"caps: {TOKEN_PENDING_MAX_TOTAL_ITEMS} записей / "
          f"{TOKEN_PENDING_MAX_TOTAL_BYTES//(1024*1024)}МиБ)")

    asyncio.create_task(mailbox_watchdog())
    print(f"[WATCHDOG] mailbox TTL запущен (проверка раз в {MAILBOX_CLEANUP_INTERVAL_SEC}с, "
          f"TTL={MAILBOX_TTL//3600}ч, caps: {MAILBOX_MAX_TOTAL_BLOBS} блобов / "
          f"{MAILBOX_MAX_TOTAL_BYTES//(1024*1024)}МиБ)")

    asyncio.create_task(pending_messages_watchdog())
    print(f"[WATCHDOG] pending_messages TTL запущен (проверка раз в "
          f"{PENDING_MESSAGES_CLEANUP_INTERVAL_SEC}с, TTL={MSG_TTL_SEC//86400}д, "
          f"caps: {PENDING_MESSAGES_MAX_TOTAL_ROWS} строк / "
          f"{PENDING_MESSAGES_MAX_TOTAL_BYTES//(1024*1024)}МиБ, "
          f"per-message: {PENDING_MESSAGE_MAX_BYTES//1024}КиБ)")

    async with websockets.serve(
        handle_client,
        SUBROSA_BIND_HOST,
        SUBROSA_BIND_PORT,
        ssl=ssl_context,
        ping_interval=15,
        ping_timeout=30,
        max_size=MAX_PACKET_SIZE_BYTES,
        compression=None,        # отключаем permessage-deflate: трафик уже зашифрован, сжатие бесполезно и добавляет ~5-15мс
        write_limit=2**16,       # 64KB write buffer — меньше накопления → ниже задержка при burst
    ):
        print("[*] WebSocket сервер запущен")
        print(f"[*] Режим: {'TLS' if ssl_context else 'DEV (без TLS)'}")
        _print_at_rest_posture()
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
    # Fail-closed startup sanity check (external review 2026-09-06, S6-50) —
    # a cheap single-row read against the reconciled user_avatars_meta
    # totals, BEFORE _db_load_avatars_sync() loads the whole table into RAM
    # below. Same posture as the anon_token_state check just below: refuses
    # to start rather than silently loading an unexpectedly huge
    # attacker-controlled avatar dataset into RAM, and does NOT delete rows
    # to repair this itself — an operator who intentionally raised real
    # usage past the configured cap needs to inspect/restore/raise that cap
    # themselves.
    existing_avatar_rows, existing_avatar_bytes = _db_get_avatars_meta_sync()
    if existing_avatar_rows > AVATARS_MAX_TOTAL_ROWS or existing_avatar_bytes > AVATARS_MAX_TOTAL_BYTES:
        print(f"[FATAL] user_avatars содержит {existing_avatar_rows} строк / {existing_avatar_bytes} байт — "
              f"больше настроенного потолка AVATARS_MAX_TOTAL_ROWS/AVATARS_MAX_TOTAL_BYTES "
              f"({AVATARS_MAX_TOTAL_ROWS}/{AVATARS_MAX_TOTAL_BYTES}). Отказ запуска, чтобы не "
              "загружать в RAM неожиданно огромный набор данных молча. Аватары НЕ удаляются "
              "автоматически — либо подними потолок(и) осознанно, либо разберись, почему рост "
              "оказался настолько большим.", flush=True)
        sys.exit(1)
    loaded_avatars = _db_load_avatars_sync()
    user_avatars.update(loaded_avatars)
    loaded_totp = _db_load_totp_sync()
    user_totp_secrets.update(loaded_totp)
    # Fail-closed startup sanity check (external review 2026-09-05, S6-44) —
    # a cheap COUNT(*) before the full-table load just below. Refuses to
    # start rather than silently loading an unexpectedly gigantic table into
    # RAM (anon_token_state_cache mirrors the entire table) — see
    # ANON_TOKEN_STATE_MAX_TOTAL_ROWS's own comment. Deliberately does NOT
    # delete rows to repair this itself: an operator who intentionally raised
    # real usage past the configured cap needs to inspect/restore/raise that
    # cap themselves, not have this silently start deleting anon-token
    # tombstones (which would reopen the exact replay window
    # MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT's own comment explains those
    # tombstones exist to close).
    existing_anon_token_rows = _db_count_anon_token_state_rows_sync()
    if existing_anon_token_rows > ANON_TOKEN_STATE_MAX_TOTAL_ROWS:
        print(f"[FATAL] anon_token_state содержит {existing_anon_token_rows} строк — больше "
              f"настроенного потолка ANON_TOKEN_STATE_MAX_TOTAL_ROWS ({ANON_TOKEN_STATE_MAX_TOTAL_ROWS}). "
              "Отказ запуска, чтобы не загружать в RAM неожиданно огромную таблицу молча. "
              "Строки НЕ удаляются автоматически — SPENT/REVOKED записи являются постоянными "
              "tombstone-записями (см. SECURITY_INVARIANTS.md #57); либо подними "
              "ANON_TOKEN_STATE_MAX_TOTAL_ROWS осознанно, либо разберись, почему рост оказался "
              "настолько большим.", flush=True)
        sys.exit(1)
    loaded_anon_tokens = _db_load_anon_token_state_sync()
    anon_token_state_cache.update(loaded_anon_tokens)
    print(f"[DB] Anonymous token states загружено: {len(loaded_anon_tokens)}")
    print(f"[DB] Хранилище сообщений: {DB_PATH} "
          f"({'зашифровано, SQLCipher' if DB_ENCRYPTION_KEY_HEX else 'НЕ зашифровано'})")
    print(f"[DB] Каналов загружено из БД: {len(channels)}")
    print(f"[DB] Prekey bundles загружено: {len(loaded_bundles)}")
    print(f"[DB] Аватаров загружено: {len(loaded_avatars)}")
    print(f"[DB] Аккаунтов с TOTP-защитой (новых устройств): {len(loaded_totp)}")
    print(f"[TOTP] Шифрование секретов в БД: {'включено' if _totp_fernet else 'выключено (TOTP_SECRET_ENCRYPTION_KEY не задан)'}")

    # Registered-account accounting (S6-56, external review 2026-09-06) —
    # registered_fingerprints is never bulk-loaded into RAM (see
    # _db_count_registered_fingerprints_sync()'s own comment), so unlike the
    # avatar/anon-token checks above there is no "refuse to start before an
    # unbounded RAM load" case here to guard against. What this DOES need to
    # surface is the actual account count against both caps, every startup —
    # not only when some future registration attempt happens to fail — plus
    # an explicit, visible confirmation that new registration is already
    # blocked if a prior REGISTERED_ACCOUNTS_HARD_MAX_ROWS was lowered (or
    # this table already legitimately exceeds it) rather than that silently
    # only manifesting as unexplained registration_full responses later.
    # Never deletes accounts to "fix" this — see effective_registration_cap()'s
    # own comment; an operator who intentionally raised real usage past a
    # newly-lowered cap needs to raise the cap back, not have rows removed.
    existing_account_rows = _db_count_registered_fingerprints_sync()
    print(f"[ACCOUNTS] Зарегистрировано аккаунтов: {existing_account_rows} "
          f"(потолок оператора: {MAX_REGISTERED_USERS if MAX_REGISTERED_USERS > 0 else 'не задан'}, "
          f"аппаратный потолок безопасности: {REGISTERED_ACCOUNTS_HARD_MAX_ROWS}, "
          f"действующий потолок для НОВЫХ аккаунтов: {effective_registration_cap()})")
    if existing_account_rows > REGISTERED_ACCOUNTS_HARD_MAX_ROWS:
        print(f"[ACCOUNTS] ВНИМАНИЕ: текущее число аккаунтов ({existing_account_rows}) уже превышает "
              f"REGISTERED_ACCOUNTS_HARD_MAX_ROWS ({REGISTERED_ACCOUNTS_HARD_MAX_ROWS}). Регистрация "
              "НОВЫХ аккаунтов уже отклоняется этим же потолком (registration_full) — уже "
              "зарегистрированные аккаунты продолжают работать как обычно (реконнект/устройства/TOTP "
              "не считаются новой регистрацией). Аккаунты НЕ удаляются автоматически — либо подними "
              "REGISTERED_ACCOUNTS_HARD_MAX_ROWS осознанно, либо разберись, почему рост оказался "
              "настолько большим.", flush=True)

    if SERVER_ACCESS_PROTECTED:
        # Fail-closed on any UNUSED legacy plaintext/low-entropy code
        # (external review 2026-09-05, S6-41) — a pre-fix 32-bit code
        # cannot be made safe merely by starting this newer version of the
        # server; hashing it now would only turn online guessing into
        # offline hashing of at most 2^32 values, not real 128-bit
        # security, and silently accepting it would defeat the whole point
        # of this fix. USED rows are exempt (see
        # _db_has_legacy_unused_access_codes_sync()'s own comment — a spent
        # code can never grant access again regardless of format).
        if _db_has_legacy_unused_access_codes_sync():
            print("[FATAL] Обнаружены неиспользованные access-коды старого формата "
                  "(32-битные, открытым текстом) в server_access_codes — они не "
                  "могут быть защищены хешированием задним числом (это лишь "
                  "переносит перебор в офлайн, не даёт настоящей 128-битной "
                  "стойкости). Удали неиспользованные строки старого формата и "
                  "сгенерируй новые 128-битные коды, например:\n"
                  "    python3 Server/admin_gen_codes.py --purge-legacy <N>\n"
                  "(уже ИСПОЛЬЗОВАННЫЕ старые коды не мешают запуску — доступ "
                  "они всё равно больше не дают). Отказ запуска.", flush=True)
            sys.exit(1)
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
                      "python3 Server/admin_gen_codes.py <N>")
            else:
                print("[ACCESS] SERVER_ACCESS_PROTECTED включён, но кодов нет и SERVER_ACCESS_CODE_COUNT не задан — "
                      "никто новый не сможет зарегистрироваться. Запусти: python3 Server/admin_gen_codes.py <N>")
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
        with open('secrets/key_encrypted.pem', 'rb') as f:
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
        ssl_context.load_cert_chain('secrets/cert.pem', temp_key_path)

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