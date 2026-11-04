"""
Protocol message-type inventory + valid-baseline packet builders for the
Subrosa server, built from reading server.py directly (not from docs) —
see the audit this module is based on: every entry below cites the exact
handler section it was derived from as of the 2026-09-25 read-through.

Two things live here:

1. `REACHABLE_TYPES` — the live set of types the running server currently
   accepts, read directly off `server.ALLOWED_TYPES` (not a hardcoded
   copy), plus the handshake-phase types that gate entry to it. This is
   what `test_coverage_is_complete` in test_protocol_negative.py compares
   BASELINE_CASES against — if server.py ever grows a new reachable type
   without a matching entry here, that test fails with the exact type
   name missing, per the "CURRENT_REACHABLE_TYPES <= TEST_COVERED_TYPES"
   requirement.

2. `BASELINE_CASES` — one `ProtocolCase` per reachable type, each able to
   build a packet the live handler actually accepts (proven by running
   them, not just by static reading — see test_protocol_negative.py's
   `test_baseline_is_accepted` parametrized over this dict). Negative/fuzz
   tests mutate a baseline's fields rather than fuzzing from nothing, per
   the project's own "prove reachability before fuzzing" requirement.

Field-shape notes on where each builder's requirements came from are kept
short here — the authoritative source is always the current server.py
handler, referenced by function/section name so it doesn't rot into a
copied line number.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

import server  # noqa: F401 — only used for ALLOWED_TYPES introspection, never started in-process here


# ─── Live reachable-type inventory (read off the running module, not copied) ─

REACHABLE_TYPES: frozenset[str] = frozenset(server.ALLOWED_TYPES)

# Handled entirely inside the pre-`ALLOWED_TYPES` handshake branch
# (handle_client()'s `hs_type` dispatch) — not in ALLOWED_TYPES at all, but
# still "reachable" in the sense this suite cares about, so state-machine
# tests cover them too even though they're absent from BASELINE_CASES
# (they don't fit the "ProtocolCase built after register()" shape).
HANDSHAKE_TYPES: frozenset[str] = frozenset({"challenge_response", "anon_channel", "federation_auth"})

# Present in the handler code but deliberately removed from ALLOWED_TYPES
# (external review 2026-08-28, SCOPE-01) — asserting these stay unreachable
# is itself a regression test, not something to build a baseline for.
DORMANT_UNREACHABLE_TYPES: frozenset[str] = frozenset({
    "channel_create", "channel_subscribe", "channel_unsubscribe",
    "channel_post", "channel_get_info",
})


# ─── TOTP helper (stdlib-only RFC 6238, no pyotp dependency) ───────────────

def _b32_decode(secret_b32: str) -> bytes:
    pad = "=" * (-len(secret_b32) % 8)
    return base64.b32decode(secret_b32.upper() + pad)


def totp_now(secret_b32: str, offset_steps: int = 0, digits: int = 6, step: int = 30) -> str:
    key = _b32_decode(secret_b32)
    counter = int(time.time()) // step + offset_steps
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def gen_totp_secret_b32() -> str:
    import secrets as _secrets
    return base64.b32encode(_secrets.token_bytes(20)).decode()


# ─── Baseline context ───────────────────────────────────────────────────────

@dataclass
class BaselineContext:
    """Everything a baseline builder might reference. Not every field is
    needed by every case — callers populate what the scenario has actually
    set up (a registered peer, a claimed anon token, ...)."""
    self_fp: str
    peer_fp: str = "AAAAAAAAAAAAAAAA"  # canonical-shaped fallback; real tests override with a 2nd registered client
    group_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    anon_token: Optional[str] = None      # 32-char hex token this client owns (subscribe_tokens first)
    totp_secret_b32: Optional[str] = None  # set once totp_setup has been exercised


def _sig(nbytes: int = 64) -> str:
    """Server-side these signature fields are only shape/length-checked
    (is_valid_chat_control_signature / VOICE_SIGNATURE_MAX_LEN /
    MEDIA_CHUNK_SIGNATURE_MAX_LEN) — real E2EE signature verification is
    client-side only, so a random-bytes base64 string of a plausible length
    is a faithful "valid shape, doesn't need to actually verify" baseline."""
    import os
    return base64.b64encode(os.urandom(nbytes)).decode()


def _small_b64(nbytes: int = 32) -> str:
    import os
    return base64.b64encode(os.urandom(nbytes)).decode()


# ─── ProtocolCase ───────────────────────────────────────────────────────────

@dataclass
class ProtocolCase:
    type: str
    category: str
    make_valid_packet: Callable[[BaselineContext], dict]
    # Field names a fuzzer should mutate one at a time. Anything not listed
    # here is either server-controlled (type/from) or intentionally not
    # part of the negative-input sweep for this type.
    mutable_fields: tuple[str, ...] = ()
    notes: str = ""


def _case(type_, category, builder, mutable_fields=(), notes=""):
    return ProtocolCase(type_, category, builder, mutable_fields, notes)


# ─── Baseline builders, grouped by category ────────────────────────────────

BASELINE_CASES: dict[str, ProtocolCase] = {}


def _register(case: ProtocolCase):
    BASELINE_CASES[case.type] = case


# -- 1:1 messaging (server.py ~9274-9834, sanitize_chat_control/direct paths)

_register(_case("message", "messaging", lambda c: {
    "type": "message", "to": c.peer_fp, "id": str(uuid.uuid4()),
    "text": _small_b64(48), "signature": _sig(), "protocol_version": 2,
}, ("to", "id", "text", "signature", "protocol_version")))

_register(_case("session_init", "messaging", lambda c: {
    "type": "session_init", "to": c.peer_fp, "id": str(uuid.uuid4()),
    "sender_ik": _small_b64(33), "x3dh_header": _small_b64(96),
    "session_header": _small_b64(48), "text": _small_b64(48), "signature": _sig(),
}, ("to", "id", "sender_ik", "x3dh_header", "session_header", "text", "signature")))

_register(_case("read", "messaging", lambda c: {
    "type": "read", "to": c.peer_fp, "id": str(uuid.uuid4()),
}, ("to", "id")))

_register(_case("delivered", "messaging", lambda c: {
    "type": "delivered", "to": c.peer_fp, "id": str(uuid.uuid4()),
}, ("to", "id")))

_register(_case("edit", "messaging", lambda c: {
    "type": "edit", "to": c.peer_fp, "id": str(uuid.uuid4()),
    "text": _small_b64(48), "signature": _sig(),
}, ("to", "id", "text", "signature")))

_register(_case("typing", "messaging", lambda c: {
    "type": "typing", "to": c.peer_fp,
}, ("to",)))

_register(_case("reaction", "messaging", lambda c: {
    "type": "reaction", "to": c.peer_fp, "message_id": str(uuid.uuid4()),
    "emoji": "\U0001F44D", "signature": _sig(),
}, ("to", "message_id", "emoji", "signature")))

_register(_case("message_delete", "messaging", lambda c: {
    "type": "message_delete", "to": c.peer_fp, "message_id": str(uuid.uuid4()),
    "signature": _sig(),
}, ("to", "message_id", "signature")))

_register(_case("disappear_timer", "messaging", lambda c: {
    "type": "disappear_timer", "to": c.peer_fp, "seconds": 86400,
}, ("to", "seconds")))

_register(_case("ping", "messaging", lambda c: {"type": "ping"}, ()))
_register(_case("pong", "messaging", lambda c: {"type": "pong"}, ()))
_register(_case("chunk_ack", "messaging", lambda c: {"type": "chunk_ack", "image_id": str(uuid.uuid4()), "chunk_index": 0}, ()))

# -- Voice (server.py ~9867, validate_voice_fields)

_register(_case("voice", "media", lambda c: {
    "type": "voice", "to": c.peer_fp, "voice_id": str(uuid.uuid4()),
    "voice_data": _small_b64(256), "signature": _sig(), "duration": 5,
}, ("to", "voice_id", "voice_data", "signature", "duration")))

# -- Media chunks (server.py ~7375 _validate_media_chunk_envelope)

_register(_case("image_chunk", "media", lambda c: {
    "type": "image_chunk", "to": c.peer_fp, "image_id": str(uuid.uuid4()),
    "chunk_index": 0, "total_chunks": 1, "data": _small_b64(256),
    "signature": _sig(), "encrypted": True,
}, ("to", "image_id", "chunk_index", "total_chunks", "data", "signature")))

_register(_case("video_chunk", "media", lambda c: {
    "type": "video_chunk", "to": c.peer_fp, "video_id": str(uuid.uuid4()),
    "chunk_index": 0, "total_chunks": 1, "data": _small_b64(256),
    "signature": _sig(), "encrypted": True, "duration": 3,
}, ("to", "video_id", "chunk_index", "total_chunks", "data", "signature", "duration")))

_register(_case("file_chunk", "media", lambda c: {
    "type": "file_chunk", "to": c.peer_fp, "file_id": str(uuid.uuid4()),
    "chunk_index": 0, "total_chunks": 1, "data": _small_b64(256),
    "signature": _sig(), "file_name": "a.txt", "encrypted_file_name": "b.enc",
}, ("to", "file_id", "chunk_index", "total_chunks", "data", "signature")))

# -- Prekey / OPK (server.py ~9215, 9333, 9367, 9440, 9524)

_register(_case("register_bundle", "prekey", lambda c: {
    "type": "register_bundle",
    "bundle": {"identity_key": _small_b64(33), "signed_prekey": _small_b64(33),
               "signed_prekey_signature": _sig(), "one_time_prekeys": [_small_b64(33) for _ in range(3)]},
}, ("bundle",)))

_register(_case("publish_prekey_bundle", "prekey", lambda c: {
    "type": "publish_prekey_bundle",
    "bundle": {"identity_key": _small_b64(33), "signed_prekey": _small_b64(33),
               "signed_prekey_signature": _sig(), "one_time_prekeys": [_small_b64(33) for _ in range(3)]},
}, ("bundle",)))

_register(_case("get_prekey_bundle", "prekey", lambda c: {
    "type": "get_prekey_bundle", "target": c.peer_fp,
}, ("target",)))

_register(_case("get_prekey_bundles_batch", "prekey", lambda c: {
    "type": "get_prekey_bundles_batch", "targets": [c.peer_fp],
}, ("targets",)))

_register(_case("get_key", "prekey", lambda c: {
    "type": "get_key", "target": c.peer_fp,
}, ("target",)))

# -- Groups (server.py ~10081-10286)

_register(_case("group_create", "group", lambda c: {
    "type": "group_create", "to": c.peer_fp, "group_id": c.group_id,
    "group_name": "test group", "group_avatar": "", "encrypted_group_key": _small_b64(48),
    "signature": _sig(), "members": [c.self_fp, c.peer_fp], "admins": [c.self_fp],
    "roster_signature": _sig(),
}, ("to", "group_id", "group_name", "encrypted_group_key", "signature", "members", "admins", "roster_signature")))

_register(_case("group_message", "group", lambda c: {
    "type": "group_message", "to": c.peer_fp, "group_id": c.group_id,
    "message_id": str(uuid.uuid4()), "sender_name": "t", "text": _small_b64(48),
    "signature": _sig(),
}, ("to", "group_id", "message_id", "text", "signature")))

_register(_case("group_reaction", "group", lambda c: {
    "type": "group_reaction", "to": c.peer_fp, "group_id": c.group_id,
    "message_id": str(uuid.uuid4()), "emoji": "\U0001F44D", "signature": _sig(),
}, ("to", "group_id", "message_id", "emoji", "signature")))

_register(_case("group_member_removed", "group", lambda c: {
    "type": "group_member_removed", "to": c.peer_fp, "group_id": c.group_id,
    "removed_member": c.peer_fp, "signature": _sig(),
}, ("to", "group_id", "removed_member", "signature")))

_register(_case("group_member_added", "group", lambda c: {
    "type": "group_member_added", "to": c.peer_fp, "group_id": c.group_id,
    "new_member": c.peer_fp, "new_member_name": "t", "signature": _sig(),
}, ("to", "group_id", "new_member", "signature")))

_register(_case("group_key_rotation", "group", lambda c: {
    "type": "group_key_rotation", "to": c.peer_fp, "group_id": c.group_id,
    "encrypted_new_key": _small_b64(48), "signature": _sig(),
}, ("to", "group_id", "encrypted_new_key", "signature")))

_register(_case("group_invite_accepted", "group", lambda c: {
    "type": "group_invite_accepted", "to": c.peer_fp, "group_id": c.group_id,
    "new_member": c.self_fp, "new_member_name": "t", "signature": _sig(),
}, ("to", "group_id", "new_member", "signature")))

_register(_case("group_message_delete", "group", lambda c: {
    "type": "group_message_delete", "to": c.peer_fp, "group_id": c.group_id,
    "message_id": str(uuid.uuid4()), "signature": _sig(),
}, ("to", "group_id", "message_id", "signature")))

# -- Call signaling (server.py ~405-540 _sanitize_call_signal)

_register(_case("call_offer", "call", lambda c: {
    "type": "call_offer", "to": c.peer_fp, "call_id": c.call_id,
    "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n", "is_video": False, "is_group": False,
}, ("to", "call_id", "sdp", "is_video", "is_group")))

_register(_case("call_answer", "call", lambda c: {
    "type": "call_answer", "to": c.peer_fp, "call_id": c.call_id,
    "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
}, ("to", "call_id", "sdp")))

_register(_case("call_ice", "call", lambda c: {
    "type": "call_ice", "to": c.peer_fp, "call_id": c.call_id,
    "candidate": "candidate:1 1 UDP 1 127.0.0.1 3478 typ host", "sdp_m_line_index": 0, "sdp_mid": "0",
}, ("to", "call_id", "candidate", "sdp_m_line_index", "sdp_mid")))

_register(_case("call_end", "call", lambda c: {
    "type": "call_end", "to": c.peer_fp, "call_id": c.call_id, "reason": "hangup",
}, ("to", "call_id", "reason")))

_register(_case("call_ringing", "call", lambda c: {
    "type": "call_ringing", "to": c.peer_fp, "call_id": c.call_id,
}, ("to", "call_id")))

_register(_case("call_group_invite", "call", lambda c: {
    "type": "call_group_invite", "to": c.peer_fp, "call_id": c.call_id,
    "group_id": c.group_id, "is_video": False,
}, ("to", "call_id", "group_id", "is_video")))

_register(_case("call_group_join", "call", lambda c: {
    "type": "call_group_join", "to": c.peer_fp, "call_id": c.call_id,
    "group_id": c.group_id, "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
}, ("to", "call_id", "group_id", "sdp")))

_register(_case("call_group_answer", "call", lambda c: {
    "type": "call_group_answer", "to": c.peer_fp, "call_id": c.call_id,
    "group_id": c.group_id, "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
}, ("to", "call_id", "group_id", "sdp")))

_register(_case("call_group_ice", "call", lambda c: {
    "type": "call_group_ice", "to": c.peer_fp, "call_id": c.call_id,
    "candidate": "candidate:1 1 UDP 1 127.0.0.1 3478 typ host", "sdp_m_line_index": 0,
}, ("to", "call_id", "candidate", "sdp_m_line_index")))

_register(_case("call_group_leave", "call", lambda c: {
    "type": "call_group_leave", "to": c.peer_fp, "call_id": c.call_id, "reason": "hangup",
}, ("to", "call_id", "reason")))

_register(_case("call_group_peer_list", "call", lambda c: {
    "type": "call_group_peer_list", "to": c.peer_fp, "call_id": c.call_id,
    "group_id": c.group_id, "peers": [c.peer_fp],
}, ("to", "call_id", "group_id", "peers")))

_register(_case("call_ice_restart", "call", lambda c: {
    "type": "call_ice_restart", "to": c.peer_fp, "call_id": c.call_id,
    "sdp": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
}, ("to", "call_id", "sdp")))

_register(_case("call_request_audio", "call", lambda c: {
    "type": "call_request_audio", "to": c.peer_fp, "call_id": c.call_id,
}, ("to", "call_id")))

_register(_case("call_request_video", "call", lambda c: {
    "type": "call_request_video", "to": c.peer_fp, "call_id": c.call_id,
}, ("to", "call_id")))

_register(_case("call_response", "call", lambda c: {
    "type": "call_response", "to": c.peer_fp, "call_id": c.call_id, "accepted": True,
}, ("to", "call_id", "accepted")))

# -- Account / session management

_register(_case("profile_update", "account", lambda c: {
    "type": "profile_update", "avatar": "",
}, ("avatar",)))

_register(_case("session_reset", "account", lambda c: {
    "type": "session_reset", "to": c.peer_fp,
}, ("to",)))

_register(_case("revoke_identity", "account", lambda c: {
    "type": "revoke_identity",
}, (), notes="Closes the connection on success — must be the LAST message sent on its socket."))

_register(_case("register_fcm", "account", lambda c: {
    "type": "register_fcm", "fcm_token": "fake-fcm-token-" + uuid.uuid4().hex,
}, ("fcm_token",)))

_register(_case("request_sender_cert", "account", lambda c: {
    "type": "request_sender_cert",
}, ()))

_register(_case("bootstrap_diagnostic", "account", lambda c: {
    "type": "bootstrap_diagnostic", "reason": "stuck_bootstrap",
}, ("reason",)))

# -- TOTP (server.py ~11611, ~11768)

def _totp_setup_packet(c: BaselineContext) -> dict:
    secret = c.totp_secret_b32 or gen_totp_secret_b32()
    return {"type": "totp_setup", "secret": secret, "new_code": totp_now(secret)}


_register(_case("totp_setup", "totp", _totp_setup_packet, ("secret", "new_code")))

_register(_case("totp_disable", "totp", lambda c: {
    "type": "totp_disable",
    "code": totp_now(c.totp_secret_b32) if c.totp_secret_b32 else "000000",
}, ("code", "recovery_code")))

# -- Anonymous token routing (server.py ~10800, 11052, 11138, 11830)

_register(_case("subscribe_tokens", "anon", lambda c: {
    "type": "subscribe_tokens", "tokens": [c.anon_token] if c.anon_token else [],
}, ("tokens",)))

_register(_case("unsubscribe_tokens", "anon", lambda c: {
    "type": "unsubscribe_tokens", "tokens": [c.anon_token] if c.anon_token else [],
}, ("tokens",)))

_register(_case("anon_message", "anon", lambda c: {
    "type": "anon_message",
    "token": c.anon_token or ("0" * 32),
    "payload": {"id": str(uuid.uuid4()), "blob": _small_b64(64)},
}, ("token", "payload")))

_register(_case("anon_delivery_ack", "anon", lambda c: {
    "type": "anon_delivery_ack", "token": c.anon_token or ("0" * 32),
}, ("token",)))

# -- Anonymous mailbox (server.py ~11490, 11535)

_register(_case("mailbox_put", "mailbox", lambda c: {
    "type": "mailbox_put", "tag": "0123456789abcdef0123456789abcdef", "blob": _small_b64(64),
}, ("tag", "blob"), notes="tag must be exactly MAILBOX_TAG_LEN=32 lowercase-hex chars."))

_register(_case("mailbox_fetch", "mailbox", lambda c: {
    "type": "mailbox_fetch", "tags": ["0123456789abcdef0123456789abcdef"],
}, ("tags",)))


# ─── Sanity: every ALLOWED_TYPES entry has a baseline, and vice versa ──────

# "register" is intentionally NOT a BASELINE_CASES entry: unlike every
# other reachable type it runs pre-authentication, needs the exact keypair
# proven in the handshake (not just a BaselineContext), and has no `to` —
# it doesn't fit the ProtocolCase(ctx) -> dict shape at all.
# protocol_harness.connect_and_register() IS its baseline/reachability
# proof (exercised by every single test that calls it), and
# test_protocol_stateful.py covers its state-machine edges directly.
KNOWN_BASELINE_EXCLUSIONS: frozenset[str] = frozenset({"register"})


def missing_baselines() -> frozenset[str]:
    """Types the live server accepts (server.ALLOWED_TYPES) with no
    corresponding BASELINE_CASES entry, excluding KNOWN_BASELINE_EXCLUSIONS.
    Should be empty — see
    test_protocol_negative.py::test_coverage_is_complete, which fails the
    build the moment server.py grows a new type this file hasn't caught up
    with yet."""
    return REACHABLE_TYPES - set(BASELINE_CASES.keys()) - KNOWN_BASELINE_EXCLUSIONS


def extra_baselines() -> frozenset[str]:
    """Baseline entries for a type the live server no longer accepts —
    signals this file is stale in the other direction (a type was removed
    from ALLOWED_TYPES but its baseline wasn't cleaned up)."""
    return set(BASELINE_CASES.keys()) - REACHABLE_TYPES


# ─── Per-field schema: boundary/encoding mutation + side-effect oracle basis ─
#
# Every field server.py actually TYPE/SHAPE-CHECKS gets `validated=True` and
# enough of a spec (kind + bounds/enum) to generate boundary and
# encoding-specific mutations, not just generic wrong-type ones — see each
# kind's own comment below for exactly which server.py validator/constant it
# mirrors. A field the server never checks at all (E2E ciphertext/content
# fields it only relays opaquely — `text`, `signature` on most 1:1/group
# types, `sender_ik`/`x3dh_header`/`session_header`, `emoji`,
# `group_name`/`group_avatar`/`encrypted_group_key`/`new_member_name`/
# `encrypted_new_key`, `id` on message/session_init/edit/read/delivered)
# gets `validated=False` — confirmed by reading the handler, not assumed —
# and the negative-mutation test only asserts crash-safety for it, never a
# rejection, since the server has no contract to enforce there in the first
# place (inventing one would be testing against a fiction, exactly the kind
# of false alarm the pentest_local_server.py profile_update/registration-cap
# fixes earlier in this same effort were about).

# server.py ~1956-1961: AVATAR_MAX_DECODED_BYTES=64KiB, base64-encoded length ceiling.
_AVATAR_MAX_B64_LEN = ((64 * 1024 + 2) // 3) * 4 + 4


@dataclass
class FieldSpec:
    validated: bool                    # False: opaque passthrough, crash-safety only
    kind: str = "string"
    min_len: int | None = None
    max_len: int | None = None
    enum_values: tuple | None = None
    int_min: int | None = None
    int_max: int | None = None
    nullable: bool = False             # server explicitly allows this field to be absent/None


# Name -> FieldSpec applied to every case whose mutable_fields contains that
# name, unless TYPE_FIELD_OVERRIDES has a more specific entry for
# (type, name). Field-name semantics are consistent across this protocol
# for the overwhelming majority of cases (verified while building this,
# not assumed) — the override table below exists for the real exceptions.
NAME_DEFAULTS: dict[str, FieldSpec] = {
    # Identity/routing — is_valid_fingerprint(): exactly 16 uppercase hex chars.
    "to": FieldSpec(True, "fingerprint"),
    "target": FieldSpec(True, "fingerprint"),
    "removed_member": FieldSpec(True, "fingerprint"),
    "new_member": FieldSpec(True, "fingerprint"),
    # is_valid_call_uuid(): canonical RFC-4122 UUID string.
    "call_id": FieldSpec(True, "uuid"),
    "group_id": FieldSpec(True, "uuid"),
    "voice_id": FieldSpec(True, "uuid"),
    # Anon tokens: MAX_TOKEN_LEN=32, exact length, no shape regex beyond that.
    "token": FieldSpec(True, "token_hex32"),
    # server.py ~331-337 call-signaling bounds.
    "sdp": FieldSpec(True, "string_bounded", min_len=1, max_len=64 * 1024),
    "candidate": FieldSpec(True, "string_bounded", min_len=1, max_len=1024),
    "sdp_mid": FieldSpec(True, "string_bounded", max_len=64, nullable=True),
    "sdp_m_line_index": FieldSpec(True, "int_bounded", int_min=0, int_max=255),
    "reason": FieldSpec(True, "enum", enum_values=("hangup", "stale", "busy", "decline", "timeout", "ice_failed", "disconnected")),
    "is_video": FieldSpec(True, "bool"),
    "is_group": FieldSpec(True, "bool"),
    "accepted": FieldSpec(True, "bool"),
    "peers": FieldSpec(True, "list_of_fingerprint", max_len=50),
    # server.py ~1956-1975 apply_avatar_mutation()/is_valid_avatar().
    "avatar": FieldSpec(True, "base64_bounded", max_len=_AVATAR_MAX_B64_LEN, nullable=True),
    # server.py ~7789 FCM_TOKEN_MAX_LEN.
    "fcm_token": FieldSpec(True, "string_bounded", min_len=1, max_len=4096),
    # server.py ~1475-1477 mailbox constants.
    "tag": FieldSpec(True, "hex_tag", min_len=32, max_len=32),
    "tags": FieldSpec(True, "list_of_hex_tag32", max_len=20),
    "blob": FieldSpec(True, "string_bounded", min_len=1, max_len=8 * 1024),
    "tokens": FieldSpec(True, "list_of_token_hex32", max_len=100),
    # server.py ~652 CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED (exact allow-list, not a range).
    "seconds": FieldSpec(True, "enum", enum_values=(0, 3600, 86400, 604800)),
    # server.py ~9356-9358/9239-9241: bundle is arbitrary JSON, bounded by
    # its own serialized byte length (MAX_BUNDLE_SIZE_BYTES=8192), not a
    # field-count/shape schema.
    "bundle": FieldSpec(True, "dict_bounded", max_len=8192),
    # server.py ~663-664 is_valid_chat_control_id() — used for
    # message_id/reaction/group_reaction/message_delete/group_message_delete.
    "message_id": FieldSpec(True, "string_bounded", min_len=1, max_len=128),
    # Opaque by default (E2E content/passthrough) — most 1:1/group "id" uses
    # (message/session_init/edit/read/delivered) have no server-side shape
    # check at all; overridden per-type below only where one exists.
    "id": FieldSpec(False),
    "text": FieldSpec(False),
    "sender_ik": FieldSpec(False),
    "x3dh_header": FieldSpec(False),
    "session_header": FieldSpec(False),
    "emoji": FieldSpec(False),
    "group_name": FieldSpec(False),
    "group_avatar": FieldSpec(False),
    "encrypted_group_key": FieldSpec(False),
    "new_member_name": FieldSpec(False),
    "encrypted_new_key": FieldSpec(False),
    # Opaque by default; overridden to validated for the specific types that
    # actually enforce it (message_delete/group_message_delete/voice/media
    # chunks) below.
    "signature": FieldSpec(False),
    # server.py ~7367-7372 media-chunk envelope bounds.
    "image_id": FieldSpec(True, "string_bounded", min_len=1, max_len=128),
    "video_id": FieldSpec(True, "string_bounded", min_len=1, max_len=128),
    "file_id": FieldSpec(True, "string_bounded", min_len=1, max_len=128),
    "chunk_index": FieldSpec(True, "int_bounded", int_min=0, int_max=20_000),
    "total_chunks": FieldSpec(True, "int_bounded", int_min=1, int_max=20_000),
    "data": FieldSpec(True, "string_bounded", min_len=1, max_len=130_000),
    "duration": FieldSpec(True, "int_bounded", int_min=0, int_max=24 * 3600),
    "voice_data": FieldSpec(True, "string_bounded", min_len=1, max_len=4 * 1024 * 1024),
    # TOTP/recovery — server.py ~4897-4928.
    "code": FieldSpec(True, "totp_code"),
    "new_code": FieldSpec(True, "totp_code"),
    "current_code": FieldSpec(True, "totp_code"),
    "recovery_code": FieldSpec(True, "recovery_code"),
    "secret": FieldSpec(True, "totp_secret_b32"),
    # anon_message's payload: must be a dict (server checks isinstance),
    # otherwise opaque/arbitrary content inside it.
    "payload": FieldSpec(True, "dict_bounded"),
    # group_create roster — validate_group_roster() (server.py ~682+):
    # shape/membership-checked, not opaque.
    "members": FieldSpec(True, "list_of_fingerprint", max_len=50),
    "admins": FieldSpec(True, "list_of_fingerprint", max_len=50),
    "roster_signature": FieldSpec(True, "string_bounded", min_len=1, max_len=256),
    "protocol_version": FieldSpec(False),
}

# (type, field) -> FieldSpec overrides where a name's semantics differ from
# NAME_DEFAULTS for that specific type.
TYPE_FIELD_OVERRIDES: dict[tuple[str, str], FieldSpec] = {
    # S6-54: signature is REQUIRED and shape-checked for these two delete
    # types specifically (server.py ~794-816) -- every other "signature"
    # field in the protocol is opaque passthrough.
    ("message_delete", "signature"): FieldSpec(True, "string_bounded", min_len=1, max_len=256),
    ("group_message_delete", "signature"): FieldSpec(True, "string_bounded", min_len=1, max_len=256),
    # validate_voice_fields()/_validate_media_chunk_envelope(): required for
    # voice, optional-but-shape-checked-if-present for the media chunks.
    ("voice", "signature"): FieldSpec(True, "string_bounded", min_len=1, max_len=256),
    ("image_chunk", "signature"): FieldSpec(True, "string_bounded", max_len=256, nullable=True),
    ("video_chunk", "signature"): FieldSpec(True, "string_bounded", max_len=256, nullable=True),
    ("file_chunk", "signature"): FieldSpec(True, "string_bounded", max_len=256, nullable=True),
    # register_bundle shares publish_prekey_bundle's exact bundle handling.
    ("register_bundle", "bundle"): FieldSpec(True, "dict_bounded", max_len=8192),
    # bootstrap_diagnostic's "reason" is never even read by the handler
    # (server.py ~11923-11927 just logs a fixed string) -- fully ignored,
    # not merely unvalidated content.
    ("bootstrap_diagnostic", "reason"): FieldSpec(False),
    # MAX_VOICE_DURATION_SECONDS defaults to 60 (server.py ~7579) -- NOT the
    # much larger MEDIA_CHUNK_MAX_DURATION_SEC=86400 video_chunk's own
    # "duration" field uses, which is what NAME_DEFAULTS["duration"] holds.
    ("voice", "duration"): FieldSpec(True, "int_bounded", int_min=0, int_max=60),
    # video_chunk's `duration` is SILENTLY CLAMPED to 0 on an out-of-range
    # or wrong-type value (server.py ~9996-9998: `if not isinstance(...)
    # or not (0 <= duration <= MEDIA_CHUNK_MAX_DURATION_SEC): duration =
    # 0`), never rejected -- the message still relays either way. Found via
    # the boundary/encoding mutation run (2026-09-25): NAME_DEFAULTS'
    # int_bounded spec assumed rejection like every other bounded int field
    # in this file, but this is a "sanitize by defaulting" field, a
    # genuinely different (also reasonable) validation strategy the
    # generic model doesn't have a category for -- validated=False here
    # means "don't assert rejection", not "the server doesn't care".
    ("video_chunk", "duration"): FieldSpec(False),
    # None of these are validated at all -- confirmed by reading every one
    # of these handlers directly (server.py ~9812-10284): only `to`
    # (fingerprint) and, where present, `signature` (chat-control shape)
    # are checked; group_id/new_member/removed_member/message_id here are
    # relayed exactly like group_name/encrypted_group_key/emoji/text --
    # opaque client metadata the server has no reason to interpret. This
    # is DIFFERENT from message_delete/group_message_delete (which DO
    # validate their own "id"/"message_id" via
    # validate_chat_control_fields) and from the CALL-category
    # call_group_*/group_id (which DOES validate via is_valid_call_uuid) --
    # NAME_DEFAULTS' blanket "group_id"->uuid and "message_id"->
    # chat_control_id and "new_member"/"removed_member"->fingerprint
    # mappings only hold for THOSE cases, not these. Found via the
    # boundary/encoding mutation run (2026-09-25).
    ("group_create", "group_id"): FieldSpec(False),
    ("group_message", "group_id"): FieldSpec(False),
    ("group_message", "message_id"): FieldSpec(False),
    ("group_reaction", "group_id"): FieldSpec(False),
    ("group_reaction", "message_id"): FieldSpec(False),
    ("reaction", "message_id"): FieldSpec(False),
    ("group_member_removed", "group_id"): FieldSpec(False),
    ("group_member_removed", "removed_member"): FieldSpec(False),
    ("group_member_added", "group_id"): FieldSpec(False),
    ("group_member_added", "new_member"): FieldSpec(False),
    ("group_key_rotation", "group_id"): FieldSpec(False),
    ("group_invite_accepted", "group_id"): FieldSpec(False),
    ("group_invite_accepted", "new_member"): FieldSpec(False),
}


def field_spec_for(type_: str, field: str) -> FieldSpec:
    return TYPE_FIELD_OVERRIDES.get((type_, field)) or NAME_DEFAULTS.get(field) or FieldSpec(False)


# Types with zero mutable_fields (no client-supplied input to mutate at
# all) -- structurally can't have "field-negative" coverage, already
# exercised by baseline reachability + top-level frame fuzzing.
TRIVIAL_NO_FIELD_TYPES: frozenset[str] = frozenset({
    t for t, case in BASELINE_CASES.items() if not case.mutable_fields
})
