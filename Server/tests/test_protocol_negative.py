"""
OPEN-3 coverage: negative/fuzz input testing against the live protocol
surface, plus the baseline-reachability proof section 6 of the spec this
suite implements requires before any fuzzing is meaningful.

Structure:
  - test_coverage_is_complete: static assertion, no server needed.
  - test_baseline_cases_reach_handlers: proves every BASELINE_CASES packet
    actually reaches its intended handler on the live server (one shared
    two-client session — see the ordering notes inline for why).
  - test_top_level_frame_fuzz_*: malformed/wrong-type top-level JSON frames.
  - test_field_negative_*: Hypothesis-driven per-field mutation of baseline
    packets for the highest-risk handlers.
"""
from __future__ import annotations

import asyncio
import json
import sys
import os
import uuid

import pytest
import websockets
from hypothesis import given, settings, strategies as st, HealthCheck

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol_harness as ph
import protocol_cases as pc

pytestmark = pytest.mark.asyncio

HYP_SETTINGS = settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])


# ─── Coverage assertion (no server needed) ─────────────────────────────────

def test_coverage_is_complete():
    missing = pc.missing_baselines()
    extra = pc.extra_baselines()
    assert not missing, f"server.ALLOWED_TYPES grew new type(s) with no baseline: {sorted(missing)}"
    assert not extra, f"BASELINE_CASES has stale entries for types no longer reachable: {sorted(extra)}"


# ─── Baseline reachability proof ───────────────────────────────────────────

RELAY_TYPES = frozenset({
    "message", "session_init", "read", "delivered", "edit", "typing", "reaction",
    "message_delete", "disappear_timer", "voice",
    "group_create", "group_message", "group_reaction", "group_member_removed",
    "group_member_added", "group_key_rotation", "group_invite_accepted", "group_message_delete",
    "call_offer", "call_answer", "call_ice", "call_end", "call_ringing",
    "call_group_invite", "call_group_join", "call_group_answer", "call_group_ice",
    "call_group_leave", "call_group_peer_list", "call_ice_restart",
    "call_request_audio", "call_request_video", "call_response",
    "session_reset", "image_chunk", "video_chunk", "file_chunk",
})

DIRECT_RESPONSE = {
    "get_prekey_bundle": "prekey_bundle_response",
    "get_prekey_bundles_batch": "prekey_bundles_batch_response",
    "get_key": "public_key",
    "request_sender_cert": "sender_cert",
    "ping": "pong",
}

SILENT_TYPES = frozenset({
    "profile_update", "register_fcm", "publish_prekey_bundle", "register_bundle",
    "chunk_ack", "bootstrap_diagnostic", "pong",
})

# Handled with bespoke ordering/setup, not the generic loop below.
SPECIAL_TYPES = frozenset({
    "subscribe_tokens", "unsubscribe_tokens", "anon_message", "anon_delivery_ack",
    "totp_setup", "totp_disable", "mailbox_put", "mailbox_fetch", "revoke_identity",
})


def _classification_covers_all_baselines():
    covered = RELAY_TYPES | set(DIRECT_RESPONSE) | SILENT_TYPES | SPECIAL_TYPES
    return set(pc.BASELINE_CASES) - covered


def test_classification_covers_every_baseline():
    leftover = _classification_covers_all_baselines()
    assert not leftover, f"baseline type(s) not classified for the reachability test: {sorted(leftover)}"


async def _find(msgs, msg_type):
    return next((m for m in msgs if isinstance(m, dict) and m.get("type") == msg_type), None)


async def test_baseline_cases_reach_handlers(managed_server: ph.ManagedServer):
    wsA, fpA, privA, pubA = await ph.connect_and_register(managed_server.url, device_id="baselineA")
    wsB, fpB, privB, pubB = await ph.connect_and_register(managed_server.url, device_id="baselineB")
    try:
        ctx = pc.BaselineContext(self_fp=fpA, peer_fp=fpB)
        failures: list[str] = []

        async def check(type_, sender_ws, expect_relay_on=None, expect_direct=None, expect_silent_alive=False):
            packet = pc.BASELINE_CASES[type_].make_valid_packet(ctx)
            await sender_ws.send(json.dumps(packet))
            try:
                if expect_relay_on is not None:
                    msgs = await ph.drain_all(expect_relay_on, quiet_for=1.0, max_total=3.0)
                    if await _find(msgs, type_) is None:
                        failures.append(f"{type_}: peer never received relayed '{type_}' (got {[m.get('type') for m in msgs if isinstance(m, dict)]})")
                elif expect_direct is not None:
                    msgs = await ph.drain_all(sender_ws, quiet_for=1.0, max_total=3.0)
                    if await _find(msgs, expect_direct) is None:
                        failures.append(f"{type_}: sender never received '{expect_direct}' (got {[m.get('type') for m in msgs if isinstance(m, dict)]})")
                elif expect_silent_alive:
                    await sender_ws.send(json.dumps({"type": "ping"}))
                    pong = await ph.drain_until(sender_ws, "pong", timeout=3.0)
                    if pong is None:
                        failures.append(f"{type_}: connection did not survive (no pong afterward)")
            except Exception as e:
                failures.append(f"{type_}: exception during check — {e!r}")

        for t in sorted(RELAY_TYPES):
            await check(t, wsA, expect_relay_on=wsB)
            await ph.drain_all(wsA, quiet_for=0.2, max_total=0.5)  # drop any sender-side chunk_ack noise

        for t, resp in DIRECT_RESPONSE.items():
            await check(t, wsA, expect_direct=resp)

        for t in sorted(SILENT_TYPES):
            await check(t, wsA, expect_silent_alive=True)

        # ── Special-ordered flows ──────────────────────────────────────
        # subscribe_tokens: claims ctx.anon_token, needed by anon_message/ack below.
        # A brand-new never-before-seen token gets NO reply on subscribe
        # (server.py ~11016: subscribe_tokens_result is only sent when the
        # claim set includes an already-SPENT/REVOKED token, so the client
        # can stop waiting on it -- a fresh ACTIVE claim is silent by
        # design). The anon_message self-delivery below is what actually
        # proves this claim landed.
        token = ph.rand_token()
        ctx.anon_token = token
        await wsA.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await wsA.send(json.dumps({"type": "ping"}))
        if await ph.drain_until(wsA, "pong", timeout=3.0) is None:
            failures.append("subscribe_tokens: connection did not survive")

        # anon_message: A sends using its OWN claimed token -> routes back to A itself.
        packet = pc.BASELINE_CASES["anon_message"].make_valid_packet(ctx)
        await wsA.send(json.dumps(packet))
        msgs = await ph.drain_all(wsA, quiet_for=1.0, max_total=3.0)
        if await _find(msgs, "anon_delivery") is None:
            failures.append(f"anon_message: sender (token owner) never received 'anon_delivery' (got {[m.get('type') for m in msgs]})")

        # anon_delivery_ack: A is still the current token owner (token_to_ws) after the self-delivery above.
        await wsA.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        msgs = await ph.drain_all(wsA, quiet_for=1.0, max_total=3.0)
        if await _find(msgs, "anon_delivery_ack_ok") is None:
            failures.append(f"anon_delivery_ack: never got anon_delivery_ack_ok (got {[m.get('type') for m in msgs]})")

        # unsubscribe_tokens: uses a SEPARATE freshly-claimed token so it doesn't disturb the flow above.
        # (Also silent on claim -- see the note above.)
        token2 = ph.rand_token()
        await wsA.send(json.dumps({"type": "subscribe_tokens", "tokens": [token2]}))
        await wsA.send(json.dumps({"type": "ping"}))
        assert await ph.drain_until(wsA, "pong", timeout=3.0) is not None
        await wsA.send(json.dumps({"type": "unsubscribe_tokens", "tokens": [token2]}))
        await wsA.send(json.dumps({"type": "ping"}))
        if await ph.drain_until(wsA, "pong", timeout=3.0) is None:
            failures.append("unsubscribe_tokens: connection did not survive")

        # totp_setup -> totp_disable, same identity, in order.
        secret = pc.gen_totp_secret_b32()
        ctx.totp_secret_b32 = secret
        await wsA.send(json.dumps({"type": "totp_setup", "secret": secret, "new_code": pc.totp_now(secret)}))
        msgs = await ph.drain_all(wsA, quiet_for=1.0, max_total=3.0)
        if await _find(msgs, "totp_setup_ok") is None:
            failures.append(f"totp_setup: never got totp_setup_ok (got {[m.get('type') for m in msgs]})")
        else:
            await wsA.send(json.dumps({"type": "totp_disable", "code": pc.totp_now(secret)}))
            msgs = await ph.drain_all(wsA, quiet_for=1.0, max_total=3.0)
            if await _find(msgs, "totp_disable_ok") is None:
                failures.append(f"totp_disable: never got totp_disable_ok (got {[m.get('type') for m in msgs]})")

        # mailbox_put -> mailbox_fetch, same tag.
        tag = "ab" * 16
        await wsA.send(json.dumps({"type": "mailbox_put", "tag": tag, "blob": "aGVsbG8="}))
        await wsA.send(json.dumps({"type": "mailbox_fetch", "tags": [tag]}))
        msgs = await ph.drain_all(wsA, quiet_for=1.0, max_total=3.0)
        if await _find(msgs, "mailbox_result") is None:
            failures.append(f"mailbox_put/mailbox_fetch: never got mailbox_result (got {[m.get('type') for m in msgs]})")

        assert not failures, "Baseline reachability failures:\n" + "\n".join(failures)
    finally:
        await wsA.close()
        await wsB.close()


async def test_revoke_identity_baseline(managed_server: ph.ManagedServer):
    """Separate connection/test — revoke_identity closes the socket on
    success by design, so it can't share the connection the main
    reachability test reuses for everything else."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="revokeidentity1")
    await ws.send(json.dumps({"type": "revoke_identity"}))
    ack = await ph.drain_until(ws, "identity_revoked_ack", timeout=3.0)
    assert ack is not None
    with pytest.raises(websockets.exceptions.ConnectionClosed):
        await ws.recv()


# ─── Boundary/encoding mutation + side-effect oracle ───────────────────────
#
# Complements the generic Hypothesis missing/null/wrong-type sweep below
# with mutations DERIVED FROM each field's actual server.py bound/shape
# (protocol_cases.FieldSpec/NAME_DEFAULTS/TYPE_FIELD_OVERRIDES) -- an
# off-by-one at a length ceiling, a wrong-length token, a disallowed enum
# value, a non-hex character where hex is required. Where the field is one
# server.py actually type/shape-checks (`validated=True`), the oracle
# asserts the corresponding SIDE EFFECT: an out-of-contract mutation must
# NOT produce the type's normal RELAY/DIRECT-response outcome, reusing the
# exact RELAY_TYPES/DIRECT_RESPONSE classification the baseline
# reachability test above already proved correct. A field the server never
# validates (`validated=False`) only gets the universal crash-safety check
# -- asserting rejection there would be testing against a contract the
# server was never written to enforce (see FieldSpec's own module-level
# comment in protocol_cases.py for why that's a deliberate choice, not an
# oversight -- this is exactly the class of false alarm the
# pentest_local_server.py profile_update/registration-cap fixes earlier in
# this same effort were about).
#
# Scope: full side-effect oracle for RELAY_TYPES + DIRECT_RESPONSE (every
# validated field of every type in those two categories) plus five SPECIAL
# types with a tractable, already-understood state flow (anon_message,
# anon_delivery_ack, mailbox_put, totp_setup, totp_disable). SILENT_TYPES
# and the remaining SPECIAL types (subscribe_tokens/unsubscribe_tokens/
# mailbox_fetch -- all `tokens`/`tags` LIST fields, where "reject the whole
# message" vs. "silently filter the bad element" semantics differ per
# handler and asserting one without re-reading each handler's exact
# filtering loop would risk inventing a wrong contract) get crash-safety
# only at this layer -- their missing/null/wrong-type coverage still comes
# from the generic Hypothesis sweep below, now extended to all 58 types.

def _boundary_and_encoding_mutations(spec: pc.FieldSpec) -> list[tuple[str, object, bool]]:
    """(label, mutated_value, expect_rejected) triples derived purely from
    the FieldSpec -- expect_rejected=True means this value is OUT of the
    server's own documented contract for this field and must not produce
    the type's normal success side effect; False means it's a boundary
    value still IN contract (only checked for crash-safety, not asserted
    to succeed -- the exact-valid case is already covered by the baseline
    reachability test)."""
    if not spec.validated:
        return []
    out: list[tuple[str, object, bool]] = []
    if spec.kind == "string_bounded":
        if spec.min_len and spec.min_len > 0:
            out.append(("empty_below_min", "", True))
        if spec.max_len:
            out.append(("max_minus_1", "a" * (spec.max_len - 1), False))
            out.append(("at_max", "a" * spec.max_len, False))
            out.append(("max_plus_1", "a" * (spec.max_len + 1), True))
    elif spec.kind == "int_bounded":
        if spec.int_min is not None:
            out.append(("below_min", spec.int_min - 1, True))
            out.append(("at_min", spec.int_min, False))
        if spec.int_max is not None:
            out.append(("at_max", spec.int_max, False))
            out.append(("above_max", spec.int_max + 1, True))
    elif spec.kind == "fingerprint":
        out.append(("too_short", "AB1234", True))
        out.append(("too_long", "AB1234AB1234AB1234", True))
        out.append(("lowercase", "ab1234ab1234ab12", True))
        out.append(("non_hex_char", "GHIJKLMNOPQRSTUV", True))
    elif spec.kind == "uuid":
        out.append(("not_uuid_shaped", "not-a-uuid-at-all", True))
        out.append(("truncated", str(uuid.uuid4())[:-1], True))
        out.append(("uppercase_still_valid", str(uuid.uuid4()).upper(), False))
    elif spec.kind == "token_hex32":
        out.append(("too_short", "a" * 31, True))
        out.append(("too_long", "a" * 33, True))
    elif spec.kind == "hex_tag":
        out.append(("too_short", "a" * 31, True))
        out.append(("too_long", "a" * 33, True))
        out.append(("non_hex_char", "z" * 32, True))
    elif spec.kind == "enum":
        bad = "definitely-not-an-allowed-value" if isinstance(spec.enum_values[0], str) else -999999
        out.append(("not_in_enum", bad, True))
    elif spec.kind == "totp_code":
        out.append(("wrong_length", "12345", True))
        out.append(("non_digit", "abcdef", True))
    elif spec.kind == "recovery_code":
        out.append(("wrong_shape", "not-a-recovery-code", True))
    elif spec.kind == "totp_secret_b32":
        out.append(("wrong_shape", "not-valid-base32!!", True))
    elif spec.kind == "base64_bounded" and spec.max_len:
        out.append(("max_plus_1", "A" * (spec.max_len + 1), True))
    elif spec.kind == "dict_bounded" and spec.max_len:
        out.append(("oversized", {"x": "y" * (spec.max_len * 2)}, True))
    return out


async def test_boundary_and_encoding_mutations_relay_and_direct(managed_server: ph.ManagedServer):
    wsA, fpA, privA, pubA = await ph.connect_and_register(managed_server.url, device_id="boundaryA")
    wsB, fpB, privB, pubB = await ph.connect_and_register(managed_server.url, device_id="boundaryB")
    try:
        ctx = pc.BaselineContext(self_fp=fpA, peer_fp=fpB)
        failures: list[str] = []

        async def check_one(type_, field, label, value, expect_rejected, response_type, on_peer):
            packet = pc.BASELINE_CASES[type_].make_valid_packet(ctx)
            packet[field] = value
            try:
                await wsA.send(json.dumps(packet, default=str))
                target_ws = wsB if on_peer else wsA
                msgs = await ph.drain_all(target_ws, quiet_for=0.5, max_total=1.5)
                got = await _find(msgs, response_type)
                if expect_rejected and got is not None:
                    failures.append(f"{type_}.{field}={label}: expected rejection but observed '{response_type}'")
                await wsA.send(json.dumps({"type": "ping"}))
                if await ph.drain_until(wsA, "pong", timeout=3.0) is None:
                    failures.append(f"{type_}.{field}={label}: connection did not survive")
            except Exception as e:
                failures.append(f"{type_}.{field}={label}: exception -- {e!r}")

        for type_ in sorted(RELAY_TYPES):
            case = pc.BASELINE_CASES[type_]
            for field in case.mutable_fields:
                spec = pc.field_spec_for(type_, field)
                for label, value, expect_rejected in _boundary_and_encoding_mutations(spec):
                    await check_one(type_, field, label, value, expect_rejected, type_, on_peer=True)
            await ph.drain_all(wsB, quiet_for=0.2, max_total=0.5)

        for type_, resp in DIRECT_RESPONSE.items():
            case = pc.BASELINE_CASES[type_]
            for field in case.mutable_fields:
                spec = pc.field_spec_for(type_, field)
                for label, value, expect_rejected in _boundary_and_encoding_mutations(spec):
                    await check_one(type_, field, label, value, expect_rejected, resp, on_peer=False)

        assert not failures, "Boundary/encoding mutation failures:\n" + "\n".join(failures)
    finally:
        await wsA.close()
        await wsB.close()


async def test_boundary_and_encoding_mutations_special_types(managed_server: ph.ManagedServer):
    """anon_message/anon_delivery_ack/mailbox_put/totp_setup/totp_disable --
    the SPECIAL types with a tractable, already-understood state flow (see
    the module note above for why subscribe_tokens/unsubscribe_tokens/
    mailbox_fetch are excluded here -- LIST fields, different semantics)."""
    wsA, fpA, privA, pubA = await ph.connect_and_register(managed_server.url, device_id="boundarySpecialA")
    failures: list[str] = []
    try:
        # -- anon_message / anon_delivery_ack: token field boundary/encoding.
        for label, bad_token, expect_rejected in _boundary_and_encoding_mutations(pc.field_spec_for("anon_message", "token")):
            token = ph.rand_token()
            await wsA.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
            await wsA.send(json.dumps({"type": "ping"}))
            await ph.drain_until(wsA, "pong", timeout=3.0)

            packet = {"type": "anon_message", "token": bad_token, "payload": {"id": f"bnd-{label}", "blob": "aGVsbG8="}}
            await wsA.send(json.dumps(packet, default=str))
            msgs = await ph.drain_all(wsA, quiet_for=0.6, max_total=1.5)
            got_delivery = await _find(msgs, "anon_delivery")
            if expect_rejected and got_delivery is not None:
                failures.append(f"anon_message.token={label}: expected rejection but got a delivery")

            # anon_delivery_ack with the SAME bad token shape.
            await wsA.send(json.dumps({"type": "anon_delivery_ack", "token": bad_token}, default=str))
            msgs2 = await ph.drain_all(wsA, quiet_for=0.6, max_total=1.5)
            got_ack = await _find(msgs2, "anon_delivery_ack_ok")
            if expect_rejected and got_ack is not None:
                failures.append(f"anon_delivery_ack.token={label}: expected rejection but got anon_delivery_ack_ok")

            await wsA.send(json.dumps({"type": "ping"}))
            if await ph.drain_until(wsA, "pong", timeout=3.0) is None:
                failures.append(f"anon token boundary {label}: connection did not survive")

        # -- mailbox_put: tag (shape-preserving mutations only, so
        # mailbox_fetch can still address the same tag to check the
        # side effect) and blob boundary/encoding.
        for label, bad_blob, expect_rejected in _boundary_and_encoding_mutations(pc.field_spec_for("mailbox_put", "blob")):
            tag = ph.rand_token()  # 32 hex chars, same shape mailbox needs
            await wsA.send(json.dumps({"type": "mailbox_put", "tag": tag, "blob": bad_blob}, default=str))
            await wsA.send(json.dumps({"type": "mailbox_fetch", "tags": [tag]}))
            msgs = await ph.drain_all(wsA, quiet_for=0.6, max_total=1.5)
            got = await _find(msgs, "mailbox_result")
            if expect_rejected and got is not None:
                failures.append(f"mailbox_put.blob={label}: expected rejection but blob was stored/fetched")
            await wsA.send(json.dumps({"type": "ping"}))
            if await ph.drain_until(wsA, "pong", timeout=3.0) is None:
                failures.append(f"mailbox_put.blob={label}: connection did not survive")

        # -- totp_setup: secret/new_code boundary/encoding (fresh identity
        # per attempt -- a failed setup attempt must not block a later one).
        for field in ("secret", "new_code"):
            for label, bad_value, expect_rejected in _boundary_and_encoding_mutations(pc.field_spec_for("totp_setup", field)):
                ws, fp, _, _ = await ph.connect_and_register(
                    managed_server.url, device_id=f"totpsetupbnd-{field}-{label}")
                try:
                    real_secret = pc.gen_totp_secret_b32()
                    packet = {"type": "totp_setup", "secret": real_secret, "new_code": pc.totp_now(real_secret)}
                    packet[field] = bad_value
                    await ws.send(json.dumps(packet, default=str))
                    msgs = await ph.drain_all(ws, quiet_for=0.6, max_total=1.5)
                    got = await _find(msgs, "totp_setup_ok")
                    if expect_rejected and got is not None:
                        failures.append(f"totp_setup.{field}={label}: expected rejection but got totp_setup_ok")
                    await ws.send(json.dumps({"type": "ping"}))
                    if await ph.drain_until(ws, "pong", timeout=3.0) is None:
                        failures.append(f"totp_setup.{field}={label}: connection did not survive")
                finally:
                    await ws.close()

        # -- totp_disable: needs a pre-enabled identity, code/recovery_code boundary/encoding.
        for field in ("code",):
            for label, bad_value, expect_rejected in _boundary_and_encoding_mutations(pc.field_spec_for("totp_disable", field)):
                ws, fp, _, _ = await ph.connect_and_register(
                    managed_server.url, device_id=f"totpdisablebnd-{label}")
                try:
                    secret = pc.gen_totp_secret_b32()
                    await ws.send(json.dumps({"type": "totp_setup", "secret": secret, "new_code": pc.totp_now(secret)}))
                    if await ph.drain_until(ws, "totp_setup_ok", timeout=3.0) is None:
                        failures.append(f"totp_disable.{field}={label}: setup precondition failed")
                        continue
                    packet = {"type": "totp_disable", "code": pc.totp_now(secret)}
                    packet[field] = bad_value
                    await ws.send(json.dumps(packet, default=str))
                    msgs = await ph.drain_all(ws, quiet_for=0.6, max_total=1.5)
                    got = await _find(msgs, "totp_disable_ok")
                    if expect_rejected and got is not None:
                        failures.append(f"totp_disable.{field}={label}: expected rejection but got totp_disable_ok")
                    await ws.send(json.dumps({"type": "ping"}))
                    if await ph.drain_until(ws, "pong", timeout=3.0) is None:
                        failures.append(f"totp_disable.{field}={label}: connection did not survive")
                finally:
                    await ws.close()

        assert not failures, "Special-type boundary/encoding mutation failures:\n" + "\n".join(failures)
    finally:
        await wsA.close()


# ─── Top-level frame fuzzing ────────────────────────────────────────────────

TOP_LEVEL_MALFORMED_FRAMES = [
    "not json at all {{{",
    "null",
    "true",
    "false",
    "42",
    "3.14",
    '"just a string"',
    "[]",
    "[1,2,3]",
    "{}",
    '{"type": null}',
    '{"type": false}',
    '{"type": 0}',
    '{"type": []}',
    '{"type": {}}',
    '{"type": ""}',
    '{"type": "totally_unknown_type_xyz"}',
    '{"type": "message"}',  # known type, everything else missing
    '{"type": "message", "to": null}',
    '{"type": "message", "to": 12345}',
    '{"type": "message", "to": []}',
    '{"type": "message", "to": {}}',
]


async def test_malformed_top_level_frames_do_not_crash_connection(managed_server: ph.ManagedServer):
    """One bad frame must never kill the whole server, and (per the
    protocol's own documented policy of silently dropping malformed
    messages rather than erroring) should generally not even kill the
    SENDING connection either -- proven here by following every malformed
    frame with a real ping and expecting a pong."""
    ws, fp, priv, pub = await ph.connect_and_register(managed_server.url, device_id="fuzzframes1")
    try:
        for frame in TOP_LEVEL_MALFORMED_FRAMES:
            await ws.send(frame)
            await ws.send(json.dumps({"type": "ping"}))
            pong = await ph.drain_until(ws, "pong", timeout=3.0)
            assert pong is not None, f"connection died after malformed frame: {frame!r}"
    finally:
        await ws.close()

    assert managed_server.is_alive(), "server process died during malformed-frame fuzzing"


async def test_oversized_handshake_is_rejected_not_crashed(managed_server: ph.ManagedServer):
    """A handshake frame over HANDSHAKE_MAX_PACKET_SIZE_BYTES must close
    that connection (and ban the IP) without affecting the server process
    itself or any OTHER connection."""
    # Control connection stays alive throughout, to prove the server itself
    # wasn't affected.
    control_ws, _, _, _ = await ph.connect_and_register(managed_server.url, device_id="controlws1")
    try:
        bad_ws = await websockets.connect(managed_server.url)
        oversized = json.dumps({"type": "challenge_response", "junk": "x" * (2 * 1024 * 1024)})
        await bad_ws.recv()  # the initial challenge
        await bad_ws.send(oversized)
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await bad_ws.recv()

        await control_ws.send(json.dumps({"type": "ping"}))
        assert await ph.drain_until(control_ws, "pong", timeout=3.0) is not None
    finally:
        await control_ws.close()

    assert managed_server.is_alive()


# ─── Per-field negative mutation (Hypothesis) ──────────────────────────────

BAD_STRING_LIKE = st.one_of(
    st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=0), st.text(alphabet=st.characters(whitelist_categories=("Cc",)), max_size=8),
    st.lists(st.integers(), max_size=3), st.dictionaries(st.text(max_size=3), st.integers(), max_size=3),
    st.text(min_size=1, max_size=5000),
)

# Every reachable type with at least one mutable field (58 total minus the
# 5 zero-field trivial types -- see protocol_cases.TRIVIAL_NO_FIELD_TYPES;
# `register` is separately excluded, see protocol_cases.KNOWN_BASELINE_EXCLUSIONS)
# gets generic missing/null/wrong-type Hypothesis coverage here. Extended
# 2026-09-25 from an initial 23-type high-risk subset to the full set, per
# the OPEN-3 closure requirement in docs/KNOWN_SECURITY_ISSUES.md -- see
# test_field_fuzz_coverage_is_complete below for the assertion that keeps
# this list honest as server.py grows.
FUZZ_TARGET_TYPES = sorted(
    set(pc.BASELINE_CASES) - pc.KNOWN_BASELINE_EXCLUSIONS - pc.TRIVIAL_NO_FIELD_TYPES
)


def test_field_fuzz_coverage_is_complete():
    """Fails the moment server.py grows a new reachable, non-trivial type
    that FUZZ_TARGET_TYPES hasn't caught up with -- the OPEN-3 definition
    this suite closes against requires exactly this: 'a coverage assertion
    detects new uncovered message types', not just a one-time manual list."""
    expected = set(pc.BASELINE_CASES) - pc.KNOWN_BASELINE_EXCLUSIONS - pc.TRIVIAL_NO_FIELD_TYPES
    actual = set(FUZZ_TARGET_TYPES)
    missing = expected - actual
    extra = actual - expected
    assert not missing, f"type(s) reachable and non-trivial but missing from FUZZ_TARGET_TYPES: {sorted(missing)}"
    assert not extra, f"FUZZ_TARGET_TYPES has stale entries no longer reachable/non-trivial: {sorted(extra)}"


async def _field_negative_case(url: str, type_: str, field: str, bad_value) -> str | None:
    """Returns an error description on failure, None on success. Kept as a
    plain coroutine (not the test itself) so the sync wrapper below can
    drive it with asyncio.run() -- see that function's own note on why
    Hypothesis's @given can't decorate an `async def` test directly
    (it calls the wrapped function and inspects the return value/raised
    exception synchronously; an unawaited coroutine object is neither)."""
    case = pc.BASELINE_CASES[type_]
    ws, fp, priv, pub = await ph.connect_and_register(url, device_id=f"fuzz_{type_}_{os.urandom(4).hex()}")
    try:
        ctx = pc.BaselineContext(self_fp=fp, peer_fp="AAAAAAAAAAAAAAAA")
        if type_ in ("subscribe_tokens", "unsubscribe_tokens", "anon_message", "anon_delivery_ack"):
            token = ph.rand_token()
            ctx.anon_token = token
            if type_ in ("anon_message", "anon_delivery_ack"):
                # Fresh-token claims are silent on success (no
                # subscribe_tokens_result -- see the reachability test's
                # own note); a short pause is enough for the claim to land
                # before the mutated packet races it.
                await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
                await ws.send(json.dumps({"type": "ping"}))
                await ph.drain_until(ws, "pong", timeout=3.0)

        packet = case.make_valid_packet(ctx)
        packet[field] = bad_value
        await ws.send(json.dumps(packet, default=str))

        # Prove the connection survived, regardless of whether this
        # specific mutated packet was accepted or silently dropped.
        await ws.send(json.dumps({"type": "ping"}))
        pong = await ph.drain_until(ws, "pong", timeout=3.0)
        if pong is None:
            return f"{type_}.{field}={bad_value!r} killed the connection (no pong)"
        return None
    except Exception as e:
        return f"{type_}.{field}={bad_value!r} raised {e!r}"
    finally:
        try:
            await ws.close()
        except Exception:
            pass


@pytest.fixture(scope="module")
def fuzz_managed_server():
    """A SEPARATE server instance from the shared `managed_server` fixture,
    with NEW_ACCOUNT_GLOBAL_LIMIT disabled. Field-mutation fuzzing
    registers a brand-new throwaway identity per Hypothesis example BY
    DESIGN (so one example's mutation can never taint another's baseline
    state) -- easily 100+ registrations across one parametrized type's
    examples, which legitimately trips the real NEW_ACCOUNT_GLOBAL_LIMIT=60
    /60s abuse limiter (server.py ~2467) under normal defaults. That
    limiter firing here would be a false positive from this suite's own
    traffic pattern, not a server bug -- confirmed by first running this
    against server DEFAULTS and observing exactly the registration_full
    pattern the limiter's own code produces, scattered across whichever
    Hypothesis examples happened to land inside an exhausted 60s window."""
    srv = ph.ManagedServer(extra_env={"NEW_ACCOUNT_GLOBAL_LIMIT": "0"})
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.mark.parametrize("type_", FUZZ_TARGET_TYPES)
def test_field_negative_mutation_does_not_crash(fuzz_managed_server: ph.ManagedServer, type_):
    """For each targeted type, take a KNOWN-VALID baseline packet and
    mutate exactly one field to an out-of-contract value (Hypothesis-driven
    over BAD_STRING_LIKE). The server must either silently drop it or reply
    with a well-formed message -- never crash, never leave the connection
    or the process in a broken state.

    Deliberately a SYNC test function driving asyncio.run() per example,
    not `async def` + `@given` -- Hypothesis's example-running loop calls
    the decorated function directly and inspects what it returns/raises;
    it does not know to await a coroutine, so an `async def` test under
    `@given` silently never executes its body (a real, documented
    Hypothesis/pytest-asyncio incompatibility, not a style preference)."""
    managed_server = fuzz_managed_server
    case = pc.BASELINE_CASES[type_]
    if not case.mutable_fields:
        pytest.skip(f"{type_} has no mutable_fields declared")
    fields = case.mutable_fields

    @given(bad_value=BAD_STRING_LIKE, field_index=st.integers(min_value=0))
    @HYP_SETTINGS
    def run_example(bad_value, field_index):
        field = fields[field_index % len(fields)]
        error = asyncio.run(_field_negative_case(managed_server.url, type_, field, bad_value))
        assert error is None, error
        assert managed_server.is_alive(), f"server process died on {type_}.{field}={bad_value!r}"

    run_example()
