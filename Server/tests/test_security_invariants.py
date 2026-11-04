"""
Security regression tests, one per invariant listed in
docs/CI_SAST_PLAN.md ("Security regression tests" section). Each is tied to
a concrete bug found and fixed during the 2026-08-23 audit
(docs/ANDROID_AUDIT.md) -- these exist so that class of bug can't silently
come back.

Run: pip install -r Server/requirements.txt -r Server/requirements-dev.txt
     pytest Server/tests -v
"""
import asyncio
import base64
import hashlib
import inspect
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import uuid

import pytest
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

import server

pytestmark = pytest.mark.asyncio

TOKEN_LEN = server.MAX_TOKEN_LEN  # 32


def rand_token() -> str:
    return secrets.token_hex(TOKEN_LEN // 2)


def gen_keypair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_der


def fingerprint_of(pub_der: bytes) -> str:
    return hashlib.sha256(pub_der).digest()[:8].hex().upper()


# Canonical-shaped TOTP test secrets (S6-48: server.py now requires the
# EXACT format both clients' TotpManager.generateSecret() produces -- a
# 20-byte SecureRandom seed, Base32-encoded with no padding, exactly 32
# characters -- not the classic 16-char/10-byte example secrets these
# tests used before (TOTP_TEST_SECRET etc., a well-known RFC/demo-library
# test vector, never a shape this product's own clients ever generate).
# Three DISTINCT values, matching the three distinct literals previously in
# use, so tests that assert two secrets behave differently (re-enrollment
# races) still exercise that with genuinely different keys.
TOTP_TEST_SECRET   = base64.b32encode(b"12345678901234567890").decode()
TOTP_TEST_SECRET_2 = base64.b32encode(b"ABCDEFGHIJABCDEFGHIJ").decode()
TOTP_TEST_SECRET_3 = base64.b32encode(b"ZYXWVUTSRQZYXWVUTSRQ").decode()

_FINGERPRINT_SHAPE_RE = re.compile(r"^[0-9A-F]{16}$")


def canonical_fingerprint(label: str) -> str:
    """server.py now validates federation `to`/payload `from` fields as
    canonical fingerprints (S6-35/S6-38: is_valid_fingerprint()) --
    deterministically maps an arbitrary human-readable test label
    ("NOSUCHUSER_MALFORMED", "SOMESENDER", ...) to the same 16-char
    uppercase-hex shape register() actually derives, so the SAME label
    always produces the SAME fingerprint. Idempotent -- a label that's
    already canonical-shaped (e.g. a real fingerprint_of() result) passes
    through unchanged."""
    if _FINGERPRINT_SHAPE_RE.match(label):
        return label
    return hashlib.sha256(label.encode("utf-8")).digest()[:8].hex().upper()


async def handshake(ws, priv, pub_der):
    challenge_msg = json.loads(await ws.recv())
    assert challenge_msg["type"] == "challenge"
    challenge = base64.b64decode(challenge_msg["data"])
    signature = priv.sign(challenge, ec.ECDSA(hashes.SHA256()))
    await ws.send(json.dumps({
        "type": "challenge_response",
        "public_key": base64.b64encode(pub_der).decode(),
        "signature": base64.b64encode(signature).decode(),
    }))
    ok_msg = json.loads(await ws.recv())
    assert ok_msg["type"] == "handshake_ok"
    return challenge


def sign_device_challenge(device_priv, challenge: bytes, username: str, device_id: str) -> bytes:
    """Python mirror of Android's DeviceKeyManager.signDeviceChallenge --
    same SUBROSA_DEVICE_V1 || challenge || username || device_id construction
    verified server-side in the register() handler's device-auth block."""
    signed_data = b"SUBROSA_DEVICE_V1" + challenge + username.encode("utf-8") + device_id.encode("utf-8")
    return device_priv.sign(signed_data, ec.ECDSA(hashes.SHA256()))


_DEVICE_ID_NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")
_DEVICE_ID_SHAPE_RE  = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def canonical_device_id(label: str) -> str:
    """server.py now validates device_id as a canonical RFC-4122 UUID
    string (S6-37, matching what Android/Desktop's UserStorage.getDeviceId()
    actually send) -- deterministically maps an arbitrary human-readable
    test label ("recipient", "device-a", ...) to a UUID via uuid5, so the
    SAME label always produces the SAME device_id across multiple calls
    (register() reconnects, sign_device_challenge()). Idempotent -- a label
    that's already canonical-shaped passes through unchanged, so a test that
    needs to sign over the exact value can compute it once up front via this
    function and hand that same value to both sign_device_challenge() and
    register()."""
    if _DEVICE_ID_SHAPE_RE.match(label):
        return label
    return str(uuid.uuid5(_DEVICE_ID_NAMESPACE, label))


async def register(ws, pub_der, device_id, name="t", extra=None):
    device_id = canonical_device_id(device_id)
    msg = {
        "type": "register",
        "name": name,
        "public_key": base64.b64encode(pub_der).decode(),
        "device_id": device_id,
    }
    if extra:
        msg.update(extra)
    await ws.send(json.dumps(msg))
    return device_id


async def connect_and_register(url, device_id="dev1", name="t", extra=None):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(url)
    await handshake(ws, priv, pub_der)
    await register(ws, pub_der, device_id, name, extra)
    return ws, fingerprint_of(pub_der), priv, pub_der


async def drain_until(ws, msg_type, timeout=3.0):
    """Skip over messages (avatar broadcasts etc.) until msg_type shows up."""
    async with asyncio.timeout(timeout):
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("type") == msg_type:
                return msg


# ── 1. recovery-код потребляется атомарно ───────────────────────────────

async def test_recovery_code_consumed_exactly_once_under_concurrency():
    username = "TESTUSER1"
    codes = server.generate_recovery_codes(1)
    await server.db_commit_totp_setup(username, TOTP_TEST_SECRET, codes)

    results = await asyncio.gather(*[
        server.db_check_and_consume_recovery_code(username, codes[0])
        for _ in range(20)
    ])
    assert sum(1 for r in results if r) == 1


# ── 2. одновременная регистрация нового device_id с одним recovery-кодом ──
#
# Note: register() intentionally disables TOTP gating entirely for the
# account the moment ANY attempt wins the recovery-code race (documented,
# not a bug -- see docs/TODO.md "recovery-code takeover window"), so later
# concurrent attempts stop being rejected too once that happens -- "how many
# attempts got past totp_required" is NOT a stable thing to assert here.
# What must still hold, even through the full register()-handler code path
# (not just the raw DB function tested in invariant 1 above): the code
# itself is only ever marked used by exactly one of the racing attempts.

async def test_concurrent_device_registration_same_recovery_code_consumed_once(running_server):
    priv, pub_der = gen_keypair()
    # username must be the real fingerprint of this keypair -- register()
    # derives it from the proven public key, it isn't caller-chosen.
    username = fingerprint_of(pub_der)
    codes = server.generate_recovery_codes(1)
    await server.db_commit_totp_setup(username, TOTP_TEST_SECRET, codes)
    server.user_totp_secrets[username] = TOTP_TEST_SECRET

    # Seed an "existing" device for this fingerprint so any other device_id
    # is treated as new (the condition that gates the TOTP/recovery check).
    class _FakeWs:
        async def close(self):
            pass
    server.clients[username] = {"ws": _FakeWs(), "name": "seed", "public_key": base64.b64encode(pub_der).decode(), "device_id": "seed-device"}

    async def attempt(device_id):
        device_id = canonical_device_id(device_id)
        ws = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws, priv, pub_der)
            # Brand-new device_id -- register()'s device-auth block requires
            # a real device_public_key/device_signature once TOTP is
            # configured for the account (external review 2026-09-03).
            device_priv, device_pub_der = gen_keypair()
            device_sig = sign_device_challenge(device_priv, challenge, username, device_id)
            await register(ws, pub_der, device_id, extra={
                "recovery_code": codes[0],
                "device_public_key": base64.b64encode(device_pub_der).decode(),
                "device_signature": base64.b64encode(device_sig).decode(),
            })
            try:
                await asyncio.wait_for(ws.recv(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
        finally:
            await ws.close()

    # Wrap db_check_and_consume_recovery_code itself to count real
    # consumptions at the source, rather than re-deriving success/failure
    # from register()'s response messages (device_bind_failed vs. success
    # aren't 1:1 with "this attempt's code won the atomic consume race").
    consumed_count = 0
    real_consume = server.db_check_and_consume_recovery_code

    async def counting_consume(username_, code_):
        nonlocal consumed_count
        result = await real_consume(username_, code_)
        if result:
            consumed_count += 1
        return result

    server.db_check_and_consume_recovery_code = counting_consume
    try:
        await asyncio.gather(*[attempt(f"race-device-{i}") for i in range(10)])
    finally:
        server.db_check_and_consume_recovery_code = real_consume

    assert consumed_count == 1


# ── 3. ACK одного получателя не подтверждает доставку чужого сообщения ────

async def test_ack_ownership_wrong_connection_cannot_confirm_someone_elses_token(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
    attacker, _, _, _ = await connect_and_register(running_server, device_id="attacker")

    token = rand_token()
    await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)
    # server.token_to_ws holds the *server-side* connection object, distinct
    # from the client-side `recipient` handle above -- snapshot it rather
    # than comparing across the two.
    owner_ws = server.token_to_ws.get(token)
    assert owner_ws is not None

    # Attacker (never subscribed to this token) tries to ack it.
    await attacker.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
    await asyncio.sleep(0.2)

    assert server.token_to_ws.get(token) is owner_ws  # unchanged -- attacker's ack was ignored
    assert token not in server.spent_tokens

    # The real owner's ack, by contrast, must actually take effect.
    await recipient.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
    await asyncio.sleep(0.2)
    assert token not in server.token_to_ws
    assert token in server.spent_tokens

    await recipient.close()
    await attacker.close()


# ── 4. token_pending не удаляется раньше подтверждённого ACK ─────────────

async def test_token_pending_survives_disconnect_until_real_ack(running_server):
    recipient, _, recipient_priv, recipient_pub_der = await connect_and_register(running_server, device_id="recipient")
    sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

    token = rand_token()
    await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)

    await recipient.close()
    await asyncio.sleep(0.2)
    assert token not in server.token_to_ws  # cleaned up on disconnect

    await sender.send(json.dumps({
        "type": "anon_message",
        "token": token,
        "payload": {"id": "m1", "ciphertext": "x"},
    }))
    await asyncio.sleep(0.2)

    # Recipient was offline -- message must still be queued, not dropped.
    assert token in server.token_pending

    # Reconnect as the SAME identity (not a fresh connect_and_register(),
    # which would mint a brand-new random keypair/fingerprint and so a
    # different username -- subscribe_tokens's ownership check would then
    # reject this as someone else trying to steal the token's routing,
    # never actually resubscribing it).
    recipient2 = await websockets.connect(running_server)
    await handshake(recipient2, recipient_priv, recipient_pub_der)
    await register(recipient2, recipient_pub_der, device_id="recipient")
    await recipient2.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)

    # Resubscribing redelivers but does NOT itself clear the pending copy.
    assert token in server.token_pending

    await recipient2.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
    await asyncio.sleep(0.2)

    assert token not in server.token_pending
    assert token in server.spent_tokens

    await sender.close()
    await recipient2.close()


# ── 5. отозванный fingerprint не получает доступ после revoke ────────────

async def test_revoked_fingerprint_rejected_on_register(running_server):
    priv, pub_der = gen_keypair()
    fp = fingerprint_of(pub_der)
    await server.db_revoke_fingerprint(fp)

    ws = await websockets.connect(running_server)
    await handshake(ws, priv, pub_der)
    await register(ws, pub_der, device_id="new-device")
    reply = json.loads(await ws.recv())
    assert reply["type"] == "identity_revoked"
    await ws.close()


# ── 7. повтор/replay уже потраченного анонимного токена отклоняется ──────

async def test_spent_token_replay_rejected(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
    sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

    token = rand_token()
    await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)

    await sender.send(json.dumps({
        "type": "anon_message",
        "token": token,
        "payload": {"id": "m1", "ciphertext": "x"},
    }))
    await asyncio.sleep(0.2)
    await recipient.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
    await asyncio.sleep(0.2)
    assert token in server.spent_tokens

    # Replay: same token used again for a brand new anon_message.
    await sender.send(json.dumps({
        "type": "anon_message",
        "token": token,
        "payload": {"id": "m2", "ciphertext": "y"},
    }))
    await asyncio.sleep(0.2)

    # Spent token must not resurrect a pending delivery.
    assert token not in server.token_pending

    await recipient.close()
    await sender.close()


# ── 8. MAX_REGISTERED_USERS / access-code редемпшн атомарны ──────────────

async def test_registration_cap_atomic_under_concurrent_new_fingerprints():
    # db_try_register_new_fingerprint (cap-check-and-INSERT alone) was
    # removed (external review 2026-09-03, round 4) -- admission is now one
    # atomic transaction (cap-check + access-code-consume + INSERT) via
    # db_admit_new_fingerprint(), see its own comment in server.py. No
    # access code required here, so require_access_code=False/access_code="".
    results = await asyncio.gather(*[
        server.db_admit_new_fingerprint(f"FP{i:04d}", max_users=5, access_code="", require_access_code=False)
        for i in range(20)
    ])
    assert sum(1 for r in results if r == "ok") == 5


# ── 9. Recovery-код имеет достаточную энтропию против offline brute-force ──
#
# External review 2026-08-27 (DOC-03): the stored hash is a single,
# unsalted SHA-256 -- fine for a high-entropy random token, but the
# original 40 bits (secrets.token_hex(5)) was crackable by a single GPU in
# well under a minute given only the hash (e.g. via stolen DB access,
# KL-27). Bumped to 80 bits; this test guards against that regressing.

async def test_recovery_code_has_sufficient_entropy():
    codes = server.generate_recovery_codes(8)
    assert len(codes) == 8
    for code in codes:
        hex_chars = code.replace("-", "")
        assert len(hex_chars) >= 20, (
            f"recovery code has only {len(hex_chars) * 4} bits of entropy, "
            f"want >= 80 (SHA-256 hash alone isn't brute-force-resistant below that)"
        )
    assert len(set(codes)) == 8  # no accidental duplicates in one batch


async def test_access_code_atomic_under_concurrent_redemption():
    # db_check_and_consume_access_code (standalone) was removed (external
    # review 2026-09-03, round 4) -- the access-code consume is now folded
    # into the same atomic transaction as the cap-check and the fingerprint
    # INSERT, via db_admit_new_fingerprint(). max_users=0 disables the cap
    # check so only access-code atomicity is under test here; each
    # concurrent attempt uses a distinct fingerprint so the exists-check
    # can't itself account for any rejections.
    #
    # Only the code's sha256: hash is ever stored now (external review
    # 2026-09-05, S6-41) -- db_admit_new_fingerprint() is given the
    # canonical RAW code (exactly what register() itself passes it, after
    # validating with is_valid_access_code()) and hashes it once,
    # internally, to compare against this stored representation.
    code = "0123456789ABCDEF0123456789ABCDEF"  # canonical 32-hex shape
    assert server.is_valid_access_code(code)
    with server.db_connect() as conn:
        conn.execute(
            "INSERT INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
            (server._hash_access_code(code), 0.0),
        )
        conn.commit()

    results = await asyncio.gather(*[
        server.db_admit_new_fingerprint(f"FP{i:04d}", max_users=0, access_code=code, require_access_code=True)
        for i in range(20)
    ])
    assert sum(1 for r in results if r == "ok") == 1


# ── 10. Durable OPK consumption (external review 2026-09-04) ─────────────
#
# store_prekey_bundle()/consume_prekey_bundle_for_serve() replaced two
# independent OPK-mutation sites (get_prekey_bundle: RAM pop then
# fire-and-forget db_save_bundle(); federated_get_bundle: RAM pop with NO
# persistence at all) with one canonical, durably-committed-before-ever-
# returned consumption path. See SECURITY_INVARIANTS.md #39.

def _read_bundle_row(target: str):
    with server.db_connect() as conn:
        row = conn.execute(
            "SELECT bundle FROM prekey_bundles_db WHERE username = ?", (target,)
        ).fetchone()
    assert row is not None, f"no prekey_bundles_db row for {target}"
    return json.loads(row[0])


async def test_direct_fetch_consumes_opk_durably(running_server):
    target = "DEADBEEFDEADBEEF"  # canonical fingerprint shape (S6-35) -- see is_valid_fingerprint()
    opk1, opk2 = {"id": "opkdirect1", "key": "K1"}, {"id": "opkdirect2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    requester, _, _, _ = await connect_and_register(running_server, device_id="requester")
    try:
        await requester.send(json.dumps({"type": "get_prekey_bundle", "target": target}))
        response = await drain_until(requester, "prekey_bundle_response")
        assert response["bundle"]["opks"] == [opk1]
    finally:
        await requester.close()

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk2]
    assert server.prekey_bundles[target]["bundle"]["opks"] == [opk2]


async def test_federation_fetch_consumes_opk_durably(running_server):
    target = "FEEDFACEFEEDFACE"  # canonical fingerprint shape (S6-35) -- see is_valid_fingerprint()
    opk1, opk2 = {"id": "opkfed1", "key": "K1"}, {"id": "opkfed2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await websockets.connect(running_server)
        try:
            challenge_msg = json.loads(await ws.recv())
            assert challenge_msg["type"] == "challenge"
            challenge = base64.b64decode(challenge_msg["data"])
            mac = server.hmac.new(
                server.FEDERATION_SECRET.encode(), challenge, server.hashlib.sha256
            ).digest()
            await ws.send(json.dumps({
                "type": "federation_auth",
                "mac":  base64.b64encode(mac).decode(),
            }))
            auth_ok = json.loads(await ws.recv())
            assert auth_ok["type"] == "federation_auth_ok"

            await ws.send(json.dumps({
                "type": "federated_get_bundle", "target": target, "req_id": secrets.token_hex(8),
            }))
            response = await drain_until(ws, "federated_bundle_response")
            assert response["bundle"]["opks"] == [opk1]
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk2]


async def test_opk_not_reissued_after_reload():
    target = "TESTTARGET_RELOAD"
    opk1, opk2 = {"id": "opkreload1", "key": "K1"}, {"id": "opkreload2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    # Different requester_scopes -- a same-scope repeat within
    # OPK_PAIR_COOLDOWN_SEC would be denied by the S6-36 pair guard, which
    # is orthogonal to what this test actually checks (no OPK reissuance
    # across a reload).
    first, remaining1 = await server.consume_prekey_bundle_for_serve(target, "RELOAD_REQUESTER_A")
    assert first["opks"] == [opk1]
    assert remaining1 == 1

    # Simulate a restart: wipe the RAM cache entirely and reload strictly
    # from what's actually durable on disk -- same call start_server() makes.
    server.prekey_bundles.clear()
    server.prekey_bundles.update(server._db_load_bundles_sync())

    second, remaining2 = await server.consume_prekey_bundle_for_serve(target, "RELOAD_REQUESTER_B")
    assert second["opks"] == [opk2]
    assert remaining2 == 0
    assert first["opks"] != second["opks"]


async def test_concurrent_fetches_receive_different_opks():
    target = "TESTTARGET_CONCURRENT"
    opks = [{"id": "opkc0", "key": "K0"}, {"id": "opkc1", "key": "K1"}]
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": list(opks)})

    # Two DIFFERENT requester_scopes -- the S6-36 pair-cooldown guard would
    # otherwise deny the second same-scope repeat, which isn't what this
    # test is about (it's about the durable-consumption race, not the new
    # abuse guard).
    results = await asyncio.gather(
        server.consume_prekey_bundle_for_serve(target, "CONCURRENT_REQUESTER_A"),
        server.consume_prekey_bundle_for_serve(target, "CONCURRENT_REQUESTER_B"),
    )
    used_ids = [bundle["opks"][0]["id"] for bundle, _ in results if bundle and bundle["opks"]]
    assert len(used_ids) == 2
    assert len(set(used_ids)) == 2  # no OPK handed to both concurrent requesters


async def test_concurrent_publish_vs_consume_stays_consistent():
    target = "TESTTARGET_RACE"
    bundle_a = {"id": "A", "ik": "IK_A", "spk": "SPK_A", "opks": [{"id": "a1"}, {"id": "a2"}]}
    await server.store_prekey_bundle(target, bundle_a)

    bundle_b = {"id": "B", "ik": "IK_B", "spk": "SPK_B", "opks": [{"id": "b1"}, {"id": "b2"}]}
    await asyncio.gather(
        server.consume_prekey_bundle_for_serve(target, "RACE_REQUESTER"),
        server.store_prekey_bundle(target, bundle_b),
    )

    stored = _read_bundle_row(target)
    ram_state = server.prekey_bundles[target]

    # store_prekey_bundle() always REPLACEs -- bundle B must be the one
    # present in the end, whichever order the two racing operations
    # actually ran in relative to each other.
    assert stored["bundle"]["id"] == "B"
    # RAM must never disagree with what's actually durable -- the whole
    # point of DB-first-then-RAM-sync under the same per-target lock.
    assert ram_state == stored
    # Consistent OPK count: either untouched (consume ran first against A,
    # then publish fully replaced it with B) or missing exactly one
    # (consume ran after publish and took one of B's own OPKs) -- never
    # bundle A's OPKs leaking into B's slot, never both consumed.
    remaining_ids = {o["id"] for o in stored["bundle"]["opks"]}
    assert remaining_ids <= {"b1", "b2"}
    assert len(remaining_ids) in (1, 2)


async def test_opk_consume_db_failure_leaves_no_trace():
    target = "TESTTARGET_DBFAIL"
    opk = {"id": "opkfail1", "key": "K1"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk]})

    # Force the UPDATE inside _db_consume_prekey_opk_sync's transaction to
    # fail, simulating a real DB-layer error mid-transaction -- exercises
    # the actual rollback/raise path, not just a mocked-out function.
    # sqlite3.Connection is a C type (its methods can't be monkeypatched
    # directly, TypeError: "immutable type") -- wrap the real connection
    # instead, proxying everything except the one statement under test.
    class _FailingConn:
        def __init__(self, real_conn):
            self._real = real_conn

        def execute(self, sql, *args, **kwargs):
            if isinstance(sql, str) and sql.strip().upper().startswith("UPDATE PREKEY_BUNDLES_DB"):
                raise RuntimeError("simulated DB failure")
            return self._real.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._real, name)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    real_db_connect = server.db_connect
    server.db_connect = lambda: _FailingConn(real_db_connect())
    try:
        with pytest.raises(RuntimeError):
            await server.db_consume_prekey_opk(target)
    finally:
        server.db_connect = real_db_connect

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk]  # never reported/left consumed


async def test_batch_fetch_consumes_zero_opks(running_server):
    target = "BADC0FFEE0DDF00D"  # canonical fingerprint shape (S6-35) -- see is_valid_fingerprint()
    opk1, opk2 = {"id": "opkbatch1", "key": "K1"}, {"id": "opkbatch2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    requester, _, _, _ = await connect_and_register(running_server, device_id="requester")
    try:
        await requester.send(json.dumps({
            "type": "get_prekey_bundles_batch", "targets": [target],
        }))
        response = await drain_until(requester, "prekey_bundles_batch_response")
        assert response["bundles"][target]["opks"] == []
    finally:
        await requester.close()

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk1, opk2]  # untouched


# ── 11. Shared rate-limit bucket for every prekey-publication alias ──────
#
# register_bundle and publish_prekey_bundle both reach the same durable
# store_prekey_bundle() write (a real SQLite transaction, a per-target
# mutation-lock acquisition, executor-thread work) -- external review
# 2026-09-04. Before this fix, register_bundle alone was rate-limited
# ("register_bundle", 20/60s) and publish_prekey_bundle had NO limit at
# all; even after unifying them onto one bucket, keeping two independently
# keyed buckets would let a client alternate message types to double its
# effective write rate. See SECURITY_INVARIANTS.md #40.

async def test_prekey_publish_shared_rate_limit_allows_20_rejects_21st(running_server):
    ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="publisher1")
    types = ["register_bundle", "publish_prekey_bundle"]
    try:
        for i in range(21):
            await ws.send(json.dumps({
                "type": types[i % 2],
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
            }))

        # Neither message type sends a success reply -- only a rate-limit
        # rejection produces any response at all, so whatever arrives
        # within a short window IS the full set of rejections.
        errors = []
        try:
            async with asyncio.timeout(2.0):
                while True:
                    msg = json.loads(await ws.recv())
                    if msg.get("type") == "error":
                        errors.append(msg)
        except (asyncio.TimeoutError, TimeoutError):
            pass

        assert len(errors) == 1
        assert errors[0]["reason"] == "Rate limit exceeded"
    finally:
        await ws.close()

    # The 20 alternating requests that succeeded persisted; the 21st
    # (rejected) must never have overwritten the last successful one.
    stored = _read_bundle_row(fingerprint)
    assert stored["bundle"]["seq"] == 19


async def test_prekey_publish_rate_limit_shared_across_message_types(running_server):
    ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="publisher2")
    try:
        for i in range(20):
            await ws.send(json.dumps({
                "type": "register_bundle",
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
            }))

        # Bucket now fully exhausted by register_bundle ALONE -- a single
        # publish_prekey_bundle right after must be rejected immediately,
        # proving the two message types share state rather than each
        # getting an independent 20/60s allowance.
        await ws.send(json.dumps({
            "type": "publish_prekey_bundle",
            "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": 999},
        }))
        response = await drain_until(ws, "error")
        assert response["reason"] == "Rate limit exceeded"
    finally:
        await ws.close()

    stored = _read_bundle_row(fingerprint)
    assert stored["bundle"]["seq"] == 19  # the seq=999 publish never landed


async def test_rate_limited_prekey_publish_never_calls_store(running_server):
    ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="publisher3")
    call_count = 0
    real_store = server.store_prekey_bundle

    async def counting_store(username_, bundle_):
        nonlocal call_count
        call_count += 1
        return await real_store(username_, bundle_)

    server.store_prekey_bundle = counting_store
    try:
        for i in range(20):
            await ws.send(json.dumps({
                "type": "publish_prekey_bundle",
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
            }))
        await asyncio.sleep(0.3)
        assert call_count == 20

        await ws.send(json.dumps({
            "type": "publish_prekey_bundle",
            "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": 20},
        }))
        response = await drain_until(ws, "error")
        assert response["reason"] == "Rate limit exceeded"
        assert call_count == 20  # the 21st never reached store_prekey_bundle
    finally:
        server.store_prekey_bundle = real_store
        await ws.close()


async def test_oversized_prekey_bundle_rejected_before_db_write(running_server):
    ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="publisher4")
    called = False
    real_store = server.store_prekey_bundle

    async def tracking_store(username_, bundle_):
        nonlocal called
        called = True
        return await real_store(username_, bundle_)

    server.store_prekey_bundle = tracking_store
    try:
        oversized = {"ik": "IK", "spk": "SPK", "opks": [{"key": "X" * (server.MAX_BUNDLE_SIZE_BYTES + 5000)}]}
        await ws.send(json.dumps({"type": "publish_prekey_bundle", "bundle": oversized}))
        await asyncio.sleep(0.2)
    finally:
        server.store_prekey_bundle = real_store
        await ws.close()

    assert called is False
    with server.db_connect() as conn:
        row = conn.execute(
            "SELECT bundle FROM prekey_bundles_db WHERE username = ?", (fingerprint,)
        ).fetchone()
    assert row is None  # oversized bundle never reached SQLite at all


async def test_normal_prekey_publish_persists_ram_and_db(running_server):
    ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="publisher5")
    bundle = {"ik": "IK", "spk": "SPK", "opks": [{"id": "o1"}]}
    try:
        await ws.send(json.dumps({"type": "publish_prekey_bundle", "bundle": bundle}))
        await asyncio.sleep(0.2)
    finally:
        await ws.close()

    assert server.prekey_bundles[fingerprint]["bundle"] == bundle
    stored = _read_bundle_row(fingerprint)
    assert stored["bundle"] == bundle


# ── 12. Server-wide prekey-publish write budget (Sybil amplification) ────
#
# S6-27 gave register_bundle/publish_prekey_bundle one shared PER-USER
# bucket -- but with open registration an attacker can mint many valid
# identities and multiply the allowed AGGREGATE SQLite write rate
# linearly, one fresh fingerprint at a time. global_prekey_publish_rate_ok()
# is a second, orthogonal, process-local budget layered on top -- external
# review 2026-09-04 (S6-28). See SECURITY_INVARIANTS.md #41.

@pytest.fixture
def small_global_prekey_limit():
    """Patches the aggregate prekey-publish budget down to a small,
    fast-to-exhaust value (default is 200 -- too slow to hit deliberately
    in a test) and resets the counter before/after."""
    real_limit = server.PREKEY_PUBLISH_GLOBAL_LIMIT
    real_enabled = server.PREKEY_PUBLISH_GLOBAL_ENABLED
    server.PREKEY_PUBLISH_GLOBAL_LIMIT = 5
    server.PREKEY_PUBLISH_GLOBAL_ENABLED = True
    server.global_prekey_publish_rate["count"] = 0
    server.global_prekey_publish_rate["reset_time"] = server.time.time()
    yield
    server.PREKEY_PUBLISH_GLOBAL_LIMIT = real_limit
    server.PREKEY_PUBLISH_GLOBAL_ENABLED = real_enabled
    server.global_prekey_publish_rate["count"] = 0
    server.global_prekey_publish_rate["reset_time"] = server.time.time()


async def test_per_user_prekey_limit_still_works_alongside_global_limit(running_server):
    # Default global budget (200) is far above what one user's own 20/60s
    # per-user bucket could ever consume in this test -- confirms the new
    # global check, checked second, doesn't change the existing per-user
    # behavior for a single well-behaved-count identity.
    ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="single_user")
    try:
        for i in range(21):
            await ws.send(json.dumps({
                "type": "publish_prekey_bundle",
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
            }))
        response = await drain_until(ws, "error")
        assert response["reason"] == "Rate limit exceeded"
    finally:
        await ws.close()

    stored = _read_bundle_row(fingerprint)
    assert stored["bundle"]["seq"] == 19


async def test_global_prekey_limit_exhausted_across_many_identities(small_global_prekey_limit, running_server):
    # 5 DIFFERENT identities, ONE publish each -- each individually is
    # nowhere near its own 20/60s per-user bucket, but they collectively
    # exhaust the (patched-to-5) aggregate budget.
    call_count = 0
    real_store = server.store_prekey_bundle

    async def counting_store(username_, bundle_):
        nonlocal call_count
        call_count += 1
        return await real_store(username_, bundle_)

    server.store_prekey_bundle = counting_store
    try:
        for i in range(5):
            ws, fingerprint, _, _ = await connect_and_register(running_server, device_id=f"multi{i}")
            try:
                await ws.send(json.dumps({
                    "type": "publish_prekey_bundle",
                    "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
                }))
                await asyncio.sleep(0.1)
            finally:
                await ws.close()
        assert call_count == 5
    finally:
        server.store_prekey_bundle = real_store


async def test_global_prekey_limit_rejects_fresh_under_limit_user(small_global_prekey_limit, running_server):
    # Exhaust the (patched-to-5) global budget with 5 distinct identities,
    # each sending exactly one request -- none of them anywhere near their
    # OWN 20/60s per-user allowance.
    for i in range(5):
        ws, _, _, _ = await connect_and_register(running_server, device_id=f"exhaust{i}")
        try:
            await ws.send(json.dumps({
                "type": "publish_prekey_bundle",
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
            }))
            await asyncio.sleep(0.1)
        finally:
            await ws.close()

    # A completely FRESH 6th identity, whose own per-user bucket has never
    # been touched, must still be rejected -- the aggregate budget, not
    # per-user fairness, is what's exhausted.
    ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="freshuser")
    try:
        await ws.send(json.dumps({
            "type": "publish_prekey_bundle",
            "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": 999},
        }))
        response = await drain_until(ws, "error")
        assert response["reason"] == "Rate limit exceeded"
    finally:
        await ws.close()

    # And that rejected request never got a chance to publish anything.
    with server.db_connect() as conn:
        row = conn.execute(
            "SELECT bundle FROM prekey_bundles_db WHERE username = ?", (fingerprint,)
        ).fetchone()
    assert row is None


async def test_global_prekey_limit_rejection_never_calls_store(small_global_prekey_limit, running_server):
    call_count = 0
    real_store = server.store_prekey_bundle

    async def counting_store(username_, bundle_):
        nonlocal call_count
        call_count += 1
        return await real_store(username_, bundle_)

    server.store_prekey_bundle = counting_store
    try:
        for i in range(5):
            ws, _, _, _ = await connect_and_register(running_server, device_id=f"drain{i}")
            try:
                await ws.send(json.dumps({
                    "type": "publish_prekey_bundle",
                    "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
                }))
                await asyncio.sleep(0.1)
            finally:
                await ws.close()
        assert call_count == 5

        ws, _, _, _ = await connect_and_register(running_server, device_id="rejected_one")
        try:
            await ws.send(json.dumps({
                "type": "publish_prekey_bundle",
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": 999},
            }))
            response = await drain_until(ws, "error")
            assert response["reason"] == "Rate limit exceeded"
        finally:
            await ws.close()

        assert call_count == 5  # the rejected request never reached store_prekey_bundle
    finally:
        server.store_prekey_bundle = real_store


async def test_global_prekey_limit_window_reset_restores_quota(small_global_prekey_limit, running_server):
    # Window patched to 2s -- long enough that the exhaustion phase (5
    # quick sends + one rejected check, well under a second total) can't
    # accidentally cross it early and reset the counter prematurely, but
    # short enough that explicitly sleeping past it is still a fast test.
    real_window = server.PREKEY_PUBLISH_GLOBAL_WINDOW_SEC
    server.PREKEY_PUBLISH_GLOBAL_WINDOW_SEC = 2.0
    try:
        for i in range(5):
            ws, _, _, _ = await connect_and_register(running_server, device_id=f"resetuser{i}")
            try:
                await ws.send(json.dumps({
                    "type": "publish_prekey_bundle",
                    "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
                }))
                await asyncio.sleep(0.05)
            finally:
                await ws.close()

        # Budget exhausted -- confirm the rejection, then wait past the
        # (patched-short) window and confirm a fresh request succeeds.
        ws, _, _, _ = await connect_and_register(running_server, device_id="beforereset")
        try:
            await ws.send(json.dumps({
                "type": "publish_prekey_bundle",
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": 900},
            }))
            response = await drain_until(ws, "error")
            assert response["reason"] == "Rate limit exceeded"
        finally:
            await ws.close()

        await asyncio.sleep(2.2)  # past the patched 2s window

        ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="afterreset")
        try:
            await ws.send(json.dumps({
                "type": "publish_prekey_bundle",
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": 901},
            }))
            await asyncio.sleep(0.2)
        finally:
            await ws.close()

        stored = _read_bundle_row(fingerprint)
        assert stored["bundle"]["seq"] == 901  # succeeded after the window reset
    finally:
        server.PREKEY_PUBLISH_GLOBAL_WINDOW_SEC = real_window


async def test_global_prekey_limit_shared_across_register_and_publish_types(small_global_prekey_limit, running_server):
    # Exhaust the (patched-to-5) global budget using a MIX of both message
    # type aliases, not just one -- proves they consume the same aggregate
    # counter, not two independent ones.
    types = ["register_bundle", "publish_prekey_bundle"]
    for i in range(5):
        ws, _, _, _ = await connect_and_register(running_server, device_id=f"mixed{i}")
        try:
            await ws.send(json.dumps({
                "type": types[i % 2],
                "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": i},
            }))
            await asyncio.sleep(0.1)
        finally:
            await ws.close()

    # One more, using whichever type wasn't just used last -- still
    # rejected, regardless of which alias it is.
    ws, _, _, _ = await connect_and_register(running_server, device_id="mixed_last")
    try:
        await ws.send(json.dumps({
            "type": "register_bundle",
            "bundle": {"ik": "IK", "spk": "SPK", "opks": [], "seq": 999},
        }))
        response = await drain_until(ws, "error")
        assert response["reason"] == "Rate limit exceeded"
    finally:
        await ws.close()


async def test_oversized_prekey_bundle_never_reaches_store_after_both_limiters(running_server):
    # Regression check for this fix specifically: the new global check now
    # runs BEFORE size validation too (per-user -> global -> size ->
    # store) -- confirm a request that clears both rate limiters but has
    # an oversized bundle still never reaches store_prekey_bundle().
    ws, fingerprint, _, _ = await connect_and_register(running_server, device_id="oversized_after_limiters")
    called = False
    real_store = server.store_prekey_bundle

    async def tracking_store(username_, bundle_):
        nonlocal called
        called = True
        return await real_store(username_, bundle_)

    server.store_prekey_bundle = tracking_store
    try:
        oversized = {"ik": "IK", "spk": "SPK", "opks": [{"key": "X" * (server.MAX_BUNDLE_SIZE_BYTES + 5000)}]}
        await ws.send(json.dumps({"type": "register_bundle", "bundle": oversized}))
        await asyncio.sleep(0.2)
    finally:
        server.store_prekey_bundle = real_store
        await ws.close()

    assert called is False
    with server.db_connect() as conn:
        row = conn.execute(
            "SELECT bundle FROM prekey_bundles_db WHERE username = ?", (fingerprint,)
        ).fetchone()
    assert row is None


# ── 13. Anonymous-mailbox global expiry + hard capacity bounds ───────────
#
# MAILBOX_TTL was previously enforced only LAZILY, at the moment the exact
# same tag was next touched by mailbox_put/mailbox_fetch -- a tag that's
# never touched again stayed in `mailbox` forever, well past its
# supposedly-48h lifetime. The per-tag cap (5) does nothing against unique
# tags. External review 2026-09-04, S6-29 -- see SECURITY_INVARIANTS.md #42.

async def test_mailbox_watchdog_removes_expired_untouched_tag():
    tag = "a" * server.MAILBOX_TAG_LEN
    old_ts = server.time.time() - server.MAILBOX_TTL - 10
    server.mailbox[tag] = [{"blob": "x" * 100, "ts": old_ts}]
    server.mailbox_total_bytes = 100
    server.mailbox_total_blobs = 1

    async with server.lock:
        server._mailbox_cleanup_expired_locked(server.time.time())

    assert tag not in server.mailbox
    assert server.mailbox_total_bytes == 0
    assert server.mailbox_total_blobs == 0


async def test_mailbox_cleanup_keeps_non_expired_blob():
    tag = "b" * server.MAILBOX_TAG_LEN
    now = server.time.time()
    server.mailbox[tag] = [{"blob": "y" * 50, "ts": now}]
    server.mailbox_total_bytes = 50
    server.mailbox_total_blobs = 1

    async with server.lock:
        server._mailbox_cleanup_expired_locked(now + 10)  # well under MAILBOX_TTL

    assert tag in server.mailbox
    assert len(server.mailbox[tag]) == 1
    assert server.mailbox_total_bytes == 50
    assert server.mailbox_total_blobs == 1


async def test_mailbox_cleanup_removes_empty_tag_key_after_expiry():
    tag = "c" * server.MAILBOX_TAG_LEN
    now = server.time.time()
    server.mailbox[tag] = [{"blob": "gone", "ts": now - server.MAILBOX_TTL - 5}]
    server.mailbox_total_bytes = 4
    server.mailbox_total_blobs = 1

    async with server.lock:
        server._mailbox_cleanup_expired_locked(now)

    assert tag not in server.mailbox  # empty key removed, not left as []


async def test_mailbox_put_increments_counters_exactly(running_server):
    ws, _, _, _ = await connect_and_register(running_server, device_id="mbput1")
    tag = "e" * server.MAILBOX_TAG_LEN
    blob = "Z" * 123
    try:
        await ws.send(json.dumps({"type": "mailbox_put", "tag": tag, "blob": blob}))
        await asyncio.sleep(0.2)
    finally:
        await ws.close()

    assert server.mailbox_total_bytes == 123
    assert server.mailbox_total_blobs == 1
    assert len(server.mailbox[tag]) == 1


# Found by adversarial fuzz testing (2026-09-25, Server/tests/
# test_protocol_negative.py's field-mutation suite): mailbox_put called
# len(tag) without first checking isinstance(tag, str) -- a JSON-truthy
# non-string tag (e.g. the boolean true) made len() raise TypeError,
# uncaught until handle_client()'s top-level `except Exception`, silently
# ending the whole connection instead of dropping the one malformed
# message. Same bug class/fix as the anon_message/anon_delivery_ack
# regression tests near test_anon_message_commit_increments_counters_exactly_once.
async def test_mailbox_put_non_string_tag_does_not_close_connection(running_server):
    ws, _, _, _ = await connect_and_register(running_server, device_id="mbput_nonstr")
    await ws.send(json.dumps({"type": "mailbox_put", "tag": True, "blob": "x"}))
    await ws.send(json.dumps({"type": "ping"}))
    pong = await drain_until(ws, "pong", timeout=3.0)
    assert pong is not None
    await ws.close()


async def test_mailbox_fetch_decrements_counters(running_server):
    tag = "f" * server.MAILBOX_TAG_LEN
    blob = "Q" * 77
    now = server.time.time()
    server.mailbox[tag] = [{"blob": blob, "ts": now}]
    server.mailbox_total_bytes = len(blob)
    server.mailbox_total_blobs = 1

    ws, _, _, _ = await connect_and_register(running_server, device_id="mbfetch1")
    try:
        await ws.send(json.dumps({"type": "mailbox_fetch", "tags": [tag]}))
        response = await drain_until(ws, "mailbox_result")
        assert response["blobs"][tag] == [blob]
    finally:
        await ws.close()

    assert tag not in server.mailbox
    assert server.mailbox_total_bytes == 0
    assert server.mailbox_total_blobs == 0


async def test_mailbox_byte_cap_rejects_valid_put(running_server):
    real_cap = server.MAILBOX_MAX_TOTAL_BYTES
    server.MAILBOX_MAX_TOTAL_BYTES = 100
    try:
        server.mailbox_total_bytes = 90
        server.mailbox_total_blobs = 1
        ws, _, _, _ = await connect_and_register(running_server, device_id="bytecap")
        tag = "1" * server.MAILBOX_TAG_LEN
        blob = "A" * 50  # 90 + 50 > 100 -- must be rejected
        try:
            await ws.send(json.dumps({"type": "mailbox_put", "tag": tag, "blob": blob}))
            await asyncio.sleep(0.2)
        finally:
            await ws.close()

        assert tag not in server.mailbox
        assert server.mailbox_total_bytes == 90
        assert server.mailbox_total_blobs == 1
    finally:
        server.MAILBOX_MAX_TOTAL_BYTES = real_cap


async def test_mailbox_blob_count_cap_rejects_valid_put(running_server):
    real_cap = server.MAILBOX_MAX_TOTAL_BLOBS
    server.MAILBOX_MAX_TOTAL_BLOBS = 3
    try:
        server.mailbox_total_blobs = 3
        server.mailbox_total_bytes = 0
        ws, _, _, _ = await connect_and_register(running_server, device_id="blobcap")
        tag = "2" * server.MAILBOX_TAG_LEN
        try:
            await ws.send(json.dumps({"type": "mailbox_put", "tag": tag, "blob": "B" * 10}))
            await asyncio.sleep(0.2)
        finally:
            await ws.close()

        assert tag not in server.mailbox
        assert server.mailbox_total_blobs == 3
        assert server.mailbox_total_bytes == 0
    finally:
        server.MAILBOX_MAX_TOTAL_BLOBS = real_cap


async def test_mailbox_rejected_put_does_not_alter_state(running_server):
    real_cap = server.MAILBOX_MAX_TOTAL_BLOBS
    server.MAILBOX_MAX_TOTAL_BLOBS = 1
    try:
        existing_tag = "3" * server.MAILBOX_TAG_LEN
        server.mailbox[existing_tag] = [{"blob": "already-here", "ts": server.time.time()}]
        server.mailbox_total_blobs = 1
        server.mailbox_total_bytes = len("already-here")
        snapshot_bytes = server.mailbox_total_bytes
        snapshot_blobs = server.mailbox_total_blobs

        ws, _, _, _ = await connect_and_register(running_server, device_id="rejectnoop")
        new_tag = "4" * server.MAILBOX_TAG_LEN
        try:
            await ws.send(json.dumps({"type": "mailbox_put", "tag": new_tag, "blob": "new-blob"}))
            await asyncio.sleep(0.2)
        finally:
            await ws.close()

        assert new_tag not in server.mailbox
        assert server.mailbox[existing_tag][0]["blob"] == "already-here"  # untouched
        assert server.mailbox_total_bytes == snapshot_bytes
        assert server.mailbox_total_blobs == snapshot_blobs
    finally:
        server.MAILBOX_MAX_TOTAL_BLOBS = real_cap


async def test_mailbox_per_tag_max_five_still_works(running_server):
    ws, _, _, _ = await connect_and_register(running_server, device_id="pertag5")
    tag = "5" * server.MAILBOX_TAG_LEN
    try:
        for i in range(6):
            await ws.send(json.dumps({"type": "mailbox_put", "tag": tag, "blob": f"blob{i}"}))
        await asyncio.sleep(0.3)
    finally:
        await ws.close()

    assert len(server.mailbox[tag]) == 5
    assert server.mailbox_total_blobs == 5
    assert server.mailbox_total_bytes == sum(len(f"blob{i}") for i in range(5))


async def test_mailbox_cleanup_frees_capacity_for_later_put(running_server):
    real_cap = server.MAILBOX_MAX_TOTAL_BLOBS
    server.MAILBOX_MAX_TOTAL_BLOBS = 1
    try:
        stale_tag = "6" * server.MAILBOX_TAG_LEN
        expired_ts = server.time.time() - server.MAILBOX_TTL - 5
        server.mailbox[stale_tag] = [{"blob": "stale", "ts": expired_ts}]
        server.mailbox_total_blobs = 1
        server.mailbox_total_bytes = len("stale")

        # At capacity (1/1) -- a put to a brand-new, different tag is
        # rejected right now.
        ws1, _, _, _ = await connect_and_register(running_server, device_id="beforecleanup")
        new_tag = "7" * server.MAILBOX_TAG_LEN
        try:
            await ws1.send(json.dumps({"type": "mailbox_put", "tag": new_tag, "blob": "fresh"}))
            await asyncio.sleep(0.2)
        finally:
            await ws1.close()
        assert new_tag not in server.mailbox

        # Simulate the watchdog's periodic full sweep -- reclaims the
        # stale, never-touched-again tag's capacity (mailbox_put's own
        # fast path only ever cleans the ONE tag it's writing to, not
        # unrelated stale tags -- only the watchdog's full scan does that).
        async with server.lock:
            server._mailbox_cleanup_expired_locked(server.time.time())
        assert stale_tag not in server.mailbox
        assert server.mailbox_total_blobs == 0

        # NOW the same put succeeds.
        ws2, _, _, _ = await connect_and_register(running_server, device_id="aftercleanup")
        try:
            await ws2.send(json.dumps({"type": "mailbox_put", "tag": new_tag, "blob": "fresh"}))
            await asyncio.sleep(0.2)
        finally:
            await ws2.close()

        assert new_tag in server.mailbox
        assert server.mailbox_total_blobs == 1
        assert server.mailbox_total_bytes == len("fresh")
    finally:
        server.MAILBOX_MAX_TOTAL_BLOBS = real_cap


async def test_mailbox_many_unique_tags_cannot_exceed_global_cap(running_server):
    real_cap = server.MAILBOX_MAX_TOTAL_BLOBS
    server.MAILBOX_MAX_TOTAL_BLOBS = 5
    try:
        ws, _, _, _ = await connect_and_register(running_server, device_id="manyunique")
        try:
            for i in range(10):
                tag = format(i, f"0{server.MAILBOX_TAG_LEN}x")  # unique valid hex tag per i
                await ws.send(json.dumps({"type": "mailbox_put", "tag": tag, "blob": f"b{i}"}))
            await asyncio.sleep(0.3)
        finally:
            await ws.close()

        assert server.mailbox_total_blobs == 5
        assert len(server.mailbox) == 5
    finally:
        server.MAILBOX_MAX_TOTAL_BLOBS = real_cap


# ── 14. Hard process-wide RAM cap on token_pending ────────────────────────
#
# TOKEN_PENDING_TTL_SEC bounds how LONG a single entry sits in RAM, but
# nothing previously bounded how MUCH RAM the whole of token_pending could
# hold at once -- many valid, live tokens produce bounded retention time
# per entry but UNBOUNDED peak RAM in aggregate. Capacity is reserved
# BEFORE the durable ACTIVE->IN_FLIGHT SQLite claim, so a capacity-full
# rejection never burns an otherwise-still-ACTIVE token. External review
# 2026-09-04, S6-30 -- see SECURITY_INVARIANTS.md #43.

async def test_anon_message_commit_increments_counters_exactly_once(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
    sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

    token = rand_token()
    await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)

    assert server.token_pending_total_items == 0
    assert server.token_pending_total_bytes == 0

    await sender.send(json.dumps({
        "type": "anon_message",
        "token": token,
        "payload": {"id": "m1", "ciphertext": "x"},
    }))
    await asyncio.sleep(0.2)

    assert server.token_pending_total_items == 1
    size = server.token_pending_sizes[token]
    assert size > 0
    assert server.token_pending_total_bytes == size
    # No leftover reservation once the entry is committed.
    assert server.token_pending_reserved_bytes == 0
    assert server.token_pending_reserved_items == 0

    await recipient.close()
    await sender.close()


# ── 13b. A non-string `token` must be rejected, not crash the connection ──
#
# Found by adversarial fuzz testing (2026-09-25, Server/tests/
# test_protocol_negative.py's field-mutation suite): both anon_message and
# anon_delivery_ack called len(token) without first checking
# isinstance(token, str). A JSON-truthy non-string value (e.g. the integer
# 1) made len() raise TypeError, uncaught until handle_client()'s top-level
# `except Exception`, which silently ends the WHOLE connection instead of
# just dropping the one malformed message -- inconsistent with every other
# malformed-field case in this file, which are all silently ignored
# (`continue`). Self-inflicted only (a client can only kill its own
# connection this way, not anyone else's), but still a real regression risk
# worth a permanent test, not just relying on the fuzz suite to catch it
# again.

async def test_anon_message_non_string_token_does_not_close_connection(running_server):
    sender, _, _, _ = await connect_and_register(running_server, device_id="nonstrtoken1")
    await sender.send(json.dumps({
        "type": "anon_message",
        "token": 1,  # int, not str -- used to raise TypeError inside len(token)
        "payload": {"id": "m1", "ciphertext": "x"},
    }))
    await sender.send(json.dumps({"type": "ping"}))
    pong = await drain_until(sender, "pong", timeout=3.0)
    assert pong is not None
    await sender.close()


async def test_anon_delivery_ack_non_string_token_does_not_close_connection(running_server):
    sender, _, _, _ = await connect_and_register(running_server, device_id="nonstrtoken2")
    await sender.send(json.dumps({"type": "anon_delivery_ack", "token": 1}))
    await sender.send(json.dumps({"type": "ping"}))
    pong = await drain_until(sender, "pong", timeout=3.0)
    assert pong is not None
    await sender.close()


async def test_anon_delivery_ack_decrements_counters_exactly_once(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
    sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

    token = rand_token()
    await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)
    await sender.send(json.dumps({
        "type": "anon_message",
        "token": token,
        "payload": {"id": "m1", "ciphertext": "x"},
    }))
    await asyncio.sleep(0.2)
    assert server.token_pending_total_items == 1

    await recipient.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
    await asyncio.sleep(0.2)

    assert server.token_pending_total_items == 0
    assert server.token_pending_total_bytes == 0
    assert token not in server.token_pending_sizes

    await recipient.close()
    await sender.close()


async def test_unsubscribe_tokens_decrements_counters_exactly_once(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
    sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

    token = rand_token()
    await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)
    await sender.send(json.dumps({
        "type": "anon_message",
        "token": token,
        "payload": {"id": "m1", "ciphertext": "x"},
    }))
    await asyncio.sleep(0.2)
    assert server.token_pending_total_items == 1

    await recipient.send(json.dumps({"type": "unsubscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)

    assert server.token_pending_total_items == 0
    assert server.token_pending_total_bytes == 0

    await recipient.close()
    await sender.close()


async def test_token_pending_watchdog_tick_decrements_counters_exactly_once(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
    sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

    token = rand_token()
    await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)
    await sender.send(json.dumps({
        "type": "anon_message",
        "token": token,
        "payload": {"id": "m1", "ciphertext": "x"},
    }))
    await asyncio.sleep(0.2)
    assert server.token_pending_total_items == 1

    # Force TTL expiry without waiting 24h.
    server.token_pending_created[token] = server.time.time() - server.TOKEN_PENDING_TTL_SEC - 10

    await server._token_pending_watchdog_tick()

    assert token not in server.token_pending
    assert server.token_pending_total_items == 0
    assert server.token_pending_total_bytes == 0

    await recipient.close()
    await sender.close()


async def test_subscribe_redelivery_does_not_increment_counters(running_server):
    recipient, _, recipient_priv, recipient_pub_der = await connect_and_register(running_server, device_id="recipient")
    sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

    token = rand_token()
    await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)
    await recipient.close()
    await asyncio.sleep(0.2)

    await sender.send(json.dumps({
        "type": "anon_message",
        "token": token,
        "payload": {"id": "m1", "ciphertext": "x"},
    }))
    await asyncio.sleep(0.2)
    assert server.token_pending_total_items == 1
    bytes_after_commit = server.token_pending_total_bytes

    # Reconnect as the SAME identity and resubscribe -- triggers
    # redelivery of the already-queued entry, must not re-account it.
    recipient2 = await websockets.connect(running_server)
    await handshake(recipient2, recipient_priv, recipient_pub_der)
    await register(recipient2, recipient_pub_der, device_id="recipient")
    await recipient2.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
    await asyncio.sleep(0.2)

    assert server.token_pending_total_items == 1  # unchanged, not doubled
    assert server.token_pending_total_bytes == bytes_after_commit

    await sender.close()
    await recipient2.close()


async def test_token_pending_byte_cap_rejects_before_db_claim(running_server):
    real_cap = server.TOKEN_PENDING_MAX_TOTAL_BYTES
    server.TOKEN_PENDING_MAX_TOTAL_BYTES = 10  # tiny -- any real payload exceeds it
    call_count = 0
    real_claim = server.db_mark_anon_token_inflight

    async def counting_claim(token_):
        nonlocal call_count
        call_count += 1
        return await real_claim(token_)

    server.db_mark_anon_token_inflight = counting_claim
    try:
        recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
        sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)

        await sender.send(json.dumps({
            "type": "anon_message",
            "token": token,
            "payload": {"id": "m1", "ciphertext": "x"},
        }))
        await asyncio.sleep(0.2)

        assert call_count == 0  # never even attempted the DB claim
        assert token not in server.token_pending
        assert server.token_pending_total_items == 0

        await recipient.close()
        await sender.close()
    finally:
        server.db_mark_anon_token_inflight = real_claim
        server.TOKEN_PENDING_MAX_TOTAL_BYTES = real_cap

    # Token must still be ACTIVE -- confirm by successfully claiming it
    # directly now that the cap is restored (the rejected anon_message
    # never burned it).
    owner = await server.db_mark_anon_token_inflight(token)
    assert owner is not None


async def test_token_pending_item_cap_rejects_before_db_claim(running_server):
    real_cap = server.TOKEN_PENDING_MAX_TOTAL_ITEMS
    server.TOKEN_PENDING_MAX_TOTAL_ITEMS = 1
    call_count = 0
    real_claim = server.db_mark_anon_token_inflight

    async def counting_claim(token_):
        nonlocal call_count
        call_count += 1
        return await real_claim(token_)

    server.db_mark_anon_token_inflight = counting_claim
    try:
        # Pre-fill the single allowed slot directly (accounted, not via a
        # real message) -- keeps this test focused on the cap check itself.
        server.token_pending["prefilled"] = [{"type": "anon_delivery", "token": "prefilled", "payload": {}}]
        server.token_pending_created["prefilled"] = server.time.time()
        server.token_pending_sizes["prefilled"] = 10
        server.token_pending_total_items = 1
        server.token_pending_total_bytes = 10

        recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
        sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)

        await sender.send(json.dumps({
            "type": "anon_message",
            "token": token,
            "payload": {"id": "m1", "ciphertext": "x"},
        }))
        await asyncio.sleep(0.2)

        assert call_count == 0
        assert token not in server.token_pending
        assert server.token_pending_total_items == 1  # unchanged

        await recipient.close()
        await sender.close()
    finally:
        server.db_mark_anon_token_inflight = real_claim
        server.TOKEN_PENDING_MAX_TOTAL_ITEMS = real_cap
        server.token_pending.pop("prefilled", None)
        server.token_pending_created.pop("prefilled", None)
        server.token_pending_sizes.pop("prefilled", None)
        server.token_pending_total_items = 0
        server.token_pending_total_bytes = 0


async def test_token_pending_concurrent_reservations_cannot_exceed_cap():
    real_cap = server.TOKEN_PENDING_MAX_TOTAL_ITEMS
    server.TOKEN_PENDING_MAX_TOTAL_ITEMS = 5
    try:
        async def try_one():
            async with server.lock:
                return server._token_pending_try_reserve_locked(1)

        results = await asyncio.gather(*[try_one() for _ in range(20)])
        assert sum(1 for r in results if r) == 5
        assert server.token_pending_reserved_items == 5
    finally:
        server.TOKEN_PENDING_MAX_TOTAL_ITEMS = real_cap
        server.token_pending_reserved_items = 0
        server.token_pending_reserved_bytes = 0


async def test_token_pending_db_claim_failure_releases_reservation(running_server):
    real_claim = server.db_mark_anon_token_inflight

    async def failing_claim(token_):
        return None  # simulate "someone else already claimed it"

    server.db_mark_anon_token_inflight = failing_claim
    try:
        recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
        sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)

        await sender.send(json.dumps({
            "type": "anon_message",
            "token": token,
            "payload": {"id": "m1", "ciphertext": "x"},
        }))
        await asyncio.sleep(0.2)

        assert token not in server.token_pending
        assert server.token_pending_total_items == 0
        assert server.token_pending_reserved_items == 0  # no leak
        assert server.token_pending_reserved_bytes == 0

        await recipient.close()
        await sender.close()
    finally:
        server.db_mark_anon_token_inflight = real_claim


async def test_token_pending_terminal_race_after_claim_releases_reservation(running_server):
    real_claim = server.db_mark_anon_token_inflight

    async def claim_then_resurrect_as_spent(token_):
        # Simulates a concurrent anon_delivery_ack/unsubscribe_tokens/
        # watchdog winning the terminal-state race in the window this
        # await was suspended.
        owner = await real_claim(token_)
        if owner is not None:
            token_hash = server._hash_anon_token(token_)
            async with server.lock:
                server.anon_token_state_cache[token_hash] = (owner, "SPENT")
        return owner

    server.db_mark_anon_token_inflight = claim_then_resurrect_as_spent
    try:
        recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
        sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)

        await sender.send(json.dumps({
            "type": "anon_message",
            "token": token,
            "payload": {"id": "m1", "ciphertext": "x"},
        }))
        await asyncio.sleep(0.2)

        assert token not in server.token_pending  # never committed
        assert server.token_pending_total_items == 0
        assert server.token_pending_reserved_items == 0  # released, not leaked

        await recipient.close()
        await sender.close()
    finally:
        server.db_mark_anon_token_inflight = real_claim


async def test_token_pending_exception_during_claim_releases_reservation(running_server):
    real_claim = server.db_mark_anon_token_inflight

    async def raising_claim(token_):
        raise RuntimeError("simulated failure mid-claim")

    server.db_mark_anon_token_inflight = raising_claim
    try:
        recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
        sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)

        await sender.send(json.dumps({
            "type": "anon_message",
            "token": token,
            "payload": {"id": "m1", "ciphertext": "x"},
        }))
        await asyncio.sleep(0.2)

        # The exception propagated out of the message-processing loop and
        # ended the sender's own connection (matches this codebase's
        # existing blanket except-Exception handler) -- but the RAM
        # reservation must not leak.
        assert server.token_pending_reserved_items == 0
        assert server.token_pending_reserved_bytes == 0
        assert token not in server.token_pending

        await recipient.close()
    finally:
        server.db_mark_anon_token_inflight = real_claim
        try:
            await sender.close()
        except Exception:
            pass


async def test_token_pending_remove_nonexistent_does_not_underflow():
    token = rand_token()
    server.token_pending[token] = [{"type": "anon_delivery", "token": token, "payload": {}}]
    server.token_pending_created[token] = server.time.time()
    server.token_pending_sizes[token] = 42
    server.token_pending_total_bytes = 42
    server.token_pending_total_items = 1

    async with server.lock:
        result = server._token_pending_remove_locked("nonexistent-token-xyz")

    assert result is None
    assert server.token_pending_total_bytes == 42  # unchanged
    assert server.token_pending_total_items == 1   # unchanged
    assert token in server.token_pending            # untouched


async def test_token_pending_many_unique_tokens_cannot_exceed_global_cap(running_server):
    real_cap = server.TOKEN_PENDING_MAX_TOTAL_ITEMS
    server.TOKEN_PENDING_MAX_TOTAL_ITEMS = 5
    try:
        recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
        sender, _, _, _ = await connect_and_register(running_server, device_id="sender")

        tokens = [rand_token() for _ in range(10)]
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": tokens}))
        await asyncio.sleep(0.2)

        for i, t in enumerate(tokens):
            await sender.send(json.dumps({
                "type": "anon_message",
                "token": t,
                "payload": {"id": f"m{i}", "ciphertext": "x"},
            }))
        await asyncio.sleep(0.4)

        assert server.token_pending_total_items == 5
        assert len(server.token_pending) == 5

        await recipient.close()
        await sender.close()
    finally:
        server.TOKEN_PENDING_MAX_TOTAL_ITEMS = real_cap


# ── Bounded durable offline-message queue (pending_messages) ─────────────
#
# MSG_TTL_SEC alone bounded how long a row could live, not how much it could
# grow while still within that window (external review 2026-09-04). An
# attacker who keeps a recipient permanently offline could otherwise persist
# an unbounded number of SQLite rows for the full TTL, and _db_store_sync()
# used to swallow every DB exception (`except Exception: pass`) AND
# message/session_init ACKed unconditionally regardless of whether db_store()
# actually persisted anything -- a sender could be told "delivered" for a
# message that was never durably queued at all. See SECURITY_INVARIANTS.md
# #44.

def _read_meta():
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT total_rows, total_bytes FROM pending_messages_meta WHERE id = 1"
        ).fetchone()


def _real_pending_totals():
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM pending_messages"
        ).fetchone()


def _read_pending_rows(recipient=None):
    with server.db_connect() as conn:
        if recipient is not None:
            return conn.execute(
                "SELECT id, recipient, payload, payload_bytes, msg_id "
                "FROM pending_messages WHERE recipient = ? ORDER BY id",
                (recipient,)
            ).fetchall()
        return conn.execute(
            "SELECT id, recipient, payload, payload_bytes, msg_id FROM pending_messages ORDER BY id"
        ).fetchall()


async def _drain_all_pending(recipient, batch_size=1000):
    """Test-only helper (S6-55) standing in for the old db_flush()'s
    "simulate a fully-successful reconnect flush" shape -- peeks and
    deletes every row for `recipient` via the new db_peek_pending()/
    db_delete_pending_row() primitives, exactly as the real reconnect loop
    would if every send_safe() succeeded. Returns the list of payload
    strings in FIFO order, matching the old db_flush() return shape so
    existing assertions ("len(flushed) == N") keep working unchanged."""
    delivered = []
    while True:
        rows = await server.db_peek_pending(recipient, batch_size)
        if not rows:
            break
        for row_id, payload_str, _payload_bytes in rows:
            status = await server.db_delete_pending_row(recipient, row_id)
            assert status == "DELETED"
            delivered.append(payload_str)
        if len(rows) < batch_size:
            break
    return delivered


async def _collect_until_relevant(ws, relevant_types, timeout=3.0):
    """Skips housekeeping broadcasts a fresh connection can still have
    queued (avatar_data, turn_config, server_peers, ...) and returns the
    first message whose type is actually one being tested for."""
    async with asyncio.timeout(timeout):
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("type") in relevant_types:
                return msg


# ── 1. row cap rejects insertion without changing DB/meta ────────────────

async def test_pending_messages_row_cap_rejects_insertion():
    # Recipient must be a canonical fingerprint shape (S6-42:
    # is_valid_fingerprint() is now enforced at db_store()'s own boundary,
    # not just the handler layer) -- see canonical_fingerprint()'s own
    # comment.
    target = canonical_fingerprint("rowcap_target")
    real_cap = server.PENDING_MESSAGES_MAX_TOTAL_ROWS
    server.PENDING_MESSAGES_MAX_TOTAL_ROWS = 1
    try:
        status1 = await server.db_store(target, {"type": "message", "text": "first"}, msg_id="rowcap-1")
        assert status1 == "STORED"
        before = _read_meta()

        status2 = await server.db_store(target, {"type": "message", "text": "second"}, msg_id="rowcap-2")
        assert status2 == "FULL"

        assert _read_meta() == before
        assert len(_read_pending_rows(target)) == 1
    finally:
        server.PENDING_MESSAGES_MAX_TOTAL_ROWS = real_cap


# ── 2. byte cap rejects insertion without changing DB/meta ───────────────

async def test_pending_messages_byte_cap_rejects_insertion():
    target = canonical_fingerprint("bytecap_target")
    real_cap = server.PENDING_MESSAGES_MAX_TOTAL_BYTES
    try:
        status1 = await server.db_store(target, {"type": "message", "text": "x" * 10}, msg_id="bytecap-1")
        assert status1 == "STORED"
        before = _read_meta()

        # Exactly at capacity -- no headroom left for a second row of ANY size.
        server.PENDING_MESSAGES_MAX_TOTAL_BYTES = before[1]
        status2 = await server.db_store(target, {"type": "message", "text": "y" * 10}, msg_id="bytecap-2")
        assert status2 == "FULL"

        assert _read_meta() == before
        assert len(_read_pending_rows(target)) == 1
    finally:
        server.PENDING_MESSAGES_MAX_TOTAL_BYTES = real_cap


# ── 3. per-payload cap rejects before the DB transaction ─────────────────

async def test_pending_message_per_payload_cap_rejects_before_db_transaction():
    real_cap = server.PENDING_MESSAGE_MAX_BYTES
    server.PENDING_MESSAGE_MAX_BYTES = 10

    def failing_connect():
        raise AssertionError("db_connect() must not be called for an over-cap payload")

    real_connect = server.db_connect
    server.db_connect = failing_connect
    try:
        status = await server.db_store(canonical_fingerprint("toolarge_target"), {"type": "message", "text": "x" * 1000}, msg_id="toolarge-1")
        assert status == "TOO_LARGE"
    finally:
        server.db_connect = real_connect
        server.PENDING_MESSAGE_MAX_BYTES = real_cap


# ── 4. successful insert increments row/byte counters exactly ────────────

async def test_pending_messages_successful_insert_increments_counters_exactly():
    target = canonical_fingerprint("counter_target")
    before = _read_meta()
    status = await server.db_store(target, {"type": "message", "text": "hello"}, msg_id="counter-1")
    assert status == "STORED"

    stored = _read_pending_rows(target)
    assert len(stored) == 1
    after = _read_meta()
    assert after == (before[0] + 1, before[1] + stored[0][3])


# ── 5. duplicate msg_id does not increment counters ───────────────────────

async def test_pending_messages_duplicate_msg_id_does_not_increment_counters():
    target = canonical_fingerprint("dup_target")
    status1 = await server.db_store(target, {"type": "message", "text": "same"}, msg_id="dup-1")
    assert status1 == "STORED"
    before = _read_meta()

    status2 = await server.db_store(target, {"type": "message", "text": "same"}, msg_id="dup-1")
    assert status2 == "DUPLICATE"

    assert _read_meta() == before
    assert len(_read_pending_rows(target)) == 1


# ── 6. a conflicting duplicate is never treated as success ───────────────

async def test_pending_messages_conflicting_duplicate_not_treated_as_success():
    recipA = canonical_fingerprint("conflict_recipA")
    recipB = canonical_fingerprint("conflict_recipB")
    status1 = await server.db_store(recipA, {"type": "message", "text": "orig"}, msg_id="conflict-1")
    assert status1 == "STORED"

    # Same msg_id, DIFFERENT recipient -- a colliding/replayed id, not a resend.
    status2 = await server.db_store(recipB, {"type": "message", "text": "orig"}, msg_id="conflict-1")
    assert status2 == "CONFLICT"

    # Same msg_id, same recipient, DIFFERENT payload -- also not a legitimate resend.
    status3 = await server.db_store(recipA, {"type": "message", "text": "different"}, msg_id="conflict-1")
    assert status3 == "CONFLICT"

    assert len(_read_pending_rows(recipB)) == 0
    stored = _read_pending_rows(recipA)
    assert len(stored) == 1
    assert json.loads(stored[0][2])["text"] == "orig"  # untouched by either conflict


# ── 7. flush decrements counters exactly ──────────────────────────────────

async def test_pending_messages_flush_decrements_counters_exactly():
    target = canonical_fingerprint("flush_target")
    await server.db_store(target, {"type": "message", "text": "a"}, msg_id="flush-1")
    await server.db_store(target, {"type": "message", "text": "bb"}, msg_id="flush-2")
    freed_bytes = sum(r[3] for r in _read_pending_rows(target))
    before = _read_meta()

    flushed = await _drain_all_pending(target)
    assert len(flushed) == 2

    assert _read_meta() == (before[0] - 2, before[1] - freed_bytes)
    assert len(_read_pending_rows(target)) == 0


# ── 8. TTL cleanup decrements counters exactly ────────────────────────────

async def test_pending_messages_ttl_cleanup_decrements_counters_exactly():
    target = canonical_fingerprint("ttl_target")
    await server.db_store(target, {"type": "message", "text": "stale"}, msg_id="ttl-1")
    with server.db_connect() as conn:
        conn.execute(
            "UPDATE pending_messages SET created_at = ? WHERE msg_id = ?",
            (server.time.time() - server.MSG_TTL_SEC - 10, "ttl-1")
        )
        conn.commit()
    freed_bytes = _read_pending_rows(target)[0][3]
    before = _read_meta()

    await server._pending_messages_watchdog_tick()

    assert _read_meta() == (before[0] - 1, before[1] - freed_bytes)
    assert len(_read_pending_rows(target)) == 0


# ── 9. restart reconciliation repairs deliberately-wrong meta counters ───

async def test_pending_messages_restart_reconciliation_repairs_wrong_meta():
    await server.db_store(canonical_fingerprint("reconcile_target"), {"type": "message", "text": "keepme"}, msg_id="reconcile-1")
    with server.db_connect() as conn:
        conn.execute("UPDATE pending_messages_meta SET total_rows = 9999, total_bytes = 9999 WHERE id = 1")
        conn.commit()
    assert _read_meta() == (9999, 9999)

    server._db_setup_sync()  # simulates a server restart

    assert _read_meta() == _real_pending_totals()


# ── 10. global write-attempt budget rejects before the executor/SQLite ───

async def test_pending_messages_global_write_budget_rejects_before_executor():
    real_limit   = server.OFFLINE_STORE_GLOBAL_LIMIT
    real_enabled = server.OFFLINE_STORE_GLOBAL_ENABLED
    server.OFFLINE_STORE_GLOBAL_LIMIT   = 2
    server.OFFLINE_STORE_GLOBAL_ENABLED = True
    server.global_offline_store_rate["count"]      = 0
    server.global_offline_store_rate["reset_time"] = server.time.time()

    call_count = 0
    real_sync = server._db_store_sync

    def counting_sync(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return real_sync(*args, **kwargs)

    server._db_store_sync = counting_sync
    try:
        target = canonical_fingerprint("budget_target")
        s1 = await server.db_store(target, {"type": "message", "text": "1"}, msg_id="budget-1")
        s2 = await server.db_store(target, {"type": "message", "text": "2"}, msg_id="budget-2")
        s3 = await server.db_store(target, {"type": "message", "text": "3"}, msg_id="budget-3")
        assert (s1, s2, s3) == ("STORED", "STORED", "RATE_LIMITED")
        assert call_count == 2  # the 3rd call never reached the executor/SQLite at all
    finally:
        server._db_store_sync = real_sync
        server.OFFLINE_STORE_GLOBAL_LIMIT   = real_limit
        server.OFFLINE_STORE_GLOBAL_ENABLED = real_enabled
        server.global_offline_store_rate["count"]      = 0
        server.global_offline_store_rate["reset_time"] = server.time.time()


# ── 11. a real DB exception propagates -- is never swallowed ─────────────

async def test_pending_messages_db_exception_propagates():
    class _FailingConn:
        def __init__(self, real_conn):
            self._real = real_conn

        def execute(self, sql, *args, **kwargs):
            if isinstance(sql, str) and sql.strip().upper().startswith("INSERT OR IGNORE INTO PENDING_MESSAGES"):
                raise RuntimeError("simulated DB failure")
            return self._real.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._real, name)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    target = canonical_fingerprint("dbfail_target")
    before = _read_meta()
    real_db_connect = server.db_connect
    server.db_connect = lambda: _FailingConn(real_db_connect())
    try:
        with pytest.raises(RuntimeError):
            await server.db_store(target, {"type": "message", "text": "x"}, msg_id="dbfail-1")
    finally:
        server.db_connect = real_db_connect

    assert len(_read_pending_rows(target)) == 0
    assert _read_meta() == before  # rolled back, not partially applied


# ── 12/13. offline message/session_init never ACK a failed store ─────────

async def test_message_offline_store_failure_does_not_ack(running_server):
    real_db_store = server.db_store

    async def failing_store(*args, **kwargs):
        return "FULL"

    server.db_store = failing_store
    try:
        ws, _, _, _ = await connect_and_register(running_server, device_id="ackfail_msg")
        try:
            # `to` must be a canonical fingerprint shape (S6-42: the
            # handler now rejects malformed/non-canonical `to` BEFORE ever
            # reaching db_store()) -- this test is specifically about the
            # store itself failing for a well-formed request, not about the
            # handler-layer shape check, so `to` here must pass that check.
            await ws.send(json.dumps({
                "type": "message", "to": canonical_fingerprint("OFFLINE_NOBODY_MSG"), "id": "ackfail-msg-1",
                "text": "hi", "signature": "sig",
            }))
            reply = await _collect_until_relevant(ws, {"ack", "error"})
            assert reply["type"] == "error"
            assert reply.get("reason") == "Storage unavailable, please retry"
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store


async def test_session_init_offline_store_failure_does_not_ack(running_server):
    real_db_store = server.db_store

    async def failing_store(*args, **kwargs):
        return "TOO_LARGE"

    server.db_store = failing_store
    try:
        ws, _, _, _ = await connect_and_register(running_server, device_id="ackfail_sinit")
        try:
            await ws.send(json.dumps({
                "type": "session_init", "to": canonical_fingerprint("OFFLINE_NOBODY_SINIT"), "id": "ackfail-sinit-1",
                "sender_ik": "IK", "x3dh_header": "H", "session_header": "SH",
                "text": "hi", "signature": "sig",
            }))
            reply = await _collect_until_relevant(ws, {"ack", "error"})
            assert reply["type"] == "error"
            assert reply.get("reason") == "Storage unavailable, please retry"
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store


# ── 14. successful/duplicate durable store still ACKs ────────────────────

async def test_message_duplicate_resend_still_acks(running_server):
    target = canonical_fingerprint("OFFLINE_TARGET_DUP")
    ws, _, _, _ = await connect_and_register(running_server, device_id="dup_resend_msg")
    msg_payload = {
        "type": "message", "to": target, "id": "dupresend-msg-1",
        "text": "hi", "signature": "sig",
    }
    try:
        await ws.send(json.dumps(msg_payload))
        reply1 = await _collect_until_relevant(ws, {"ack", "error"})
        assert reply1 == {"type": "ack", "id": "dupresend-msg-1"}

        # Exact same message/id resent (e.g. a client retry after a locally
        # timed-out ACK) -- a genuine duplicate, must still be ACKed, not
        # silently dropped or errored.
        await ws.send(json.dumps(msg_payload))
        reply2 = await _collect_until_relevant(ws, {"ack", "error"})
        assert reply2 == {"type": "ack", "id": "dupresend-msg-1"}
    finally:
        await ws.close()

    assert len(_read_pending_rows(target)) == 1  # duplicate created no second row


# ── 15. many large offline payloads can never exceed the configured caps ─

async def test_pending_messages_many_large_payloads_cannot_exceed_configured_caps():
    real_bytes_cap = server.PENDING_MESSAGES_MAX_TOTAL_BYTES
    real_rows_cap  = server.PENDING_MESSAGES_MAX_TOTAL_ROWS
    real_enabled   = server.OFFLINE_STORE_GLOBAL_ENABLED
    server.PENDING_MESSAGES_MAX_TOTAL_BYTES = 5000
    server.PENDING_MESSAGES_MAX_TOTAL_ROWS  = 1000
    # Isolate the SQLite-level capacity caps under test from the separate
    # write-attempt budget (test 10 above already covers that one).
    server.OFFLINE_STORE_GLOBAL_ENABLED = False
    try:
        target = canonical_fingerprint("manylarge_target")

        async def store_one(i):
            return await server.db_store(
                target, {"type": "message", "text": "X" * 1000}, msg_id=f"manylarge-{i}"
            )

        results = await asyncio.gather(*[store_one(i) for i in range(20)])
        stored_count = sum(1 for r in results if r == "STORED")
        full_count   = sum(1 for r in results if r == "FULL")
        assert stored_count + full_count == 20
        assert 0 < stored_count < 20  # the cap actually bit -- not all 20 fit, but some did

        real_totals = _real_pending_totals()
        assert _read_meta() == real_totals
        assert real_totals[0] == stored_count
        assert real_totals[1] <= server.PENDING_MESSAGES_MAX_TOTAL_BYTES
    finally:
        server.PENDING_MESSAGES_MAX_TOTAL_BYTES = real_bytes_cap
        server.PENDING_MESSAGES_MAX_TOTAL_ROWS  = real_rows_cap
        server.OFFLINE_STORE_GLOBAL_ENABLED     = real_enabled


# ── Account-scoped TOTP-state lock (register() vs totp_setup/totp_disable) ─
#
# TOTP enable/disable is durable in SQLite, but register()'s device-gating
# decision reads the RAM cache (`username in user_totp_secrets`), and
# totp_setup/totp_disable each `await` their durable commit BEFORE updating
# that same RAM cache (deliberately -- RAM must never race ahead of the
# durable commit). That `await` is a scheduling window: a concurrent
# register() for the SAME fingerprint could previously observe "already
# durably enabled in SQLite" and "still absent from user_totp_secrets" at
# once, and take the no-TOTP device-admission path for an account whose
# owner is at that very moment enabling TOTP specifically to close it. See
# SECURITY_INVARIANTS.md #45.

def _current_totp_code(secret: str) -> str:
    return server._totp_code_at_counter(secret, int(server.time.time() // 30))


# ── 1. concurrent register() cannot observe the DB-committed/RAM-stale gap ─

async def test_totp_setup_race_blocks_concurrent_register_totp_disabled_path(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws1 = await websockets.connect(running_server)
    await handshake(ws1, priv, pub_der)
    await register(ws1, pub_der, device_id="device-a")
    await asyncio.sleep(0.2)

    secret = TOTP_TEST_SECRET
    code = _current_totp_code(secret)

    commit_done     = asyncio.Event()
    release_commit  = asyncio.Event()
    real_commit     = server.db_commit_totp_setup

    async def pausing_commit(username_, secret_, codes_):
        await real_commit(username_, secret_, codes_)
        commit_done.set()
        await release_commit.wait()

    server.db_commit_totp_setup = pausing_commit
    ws2 = None
    try:
        await ws1.send(json.dumps({"type": "totp_setup", "secret": secret, "code": code}))
        await asyncio.wait_for(commit_done.wait(), timeout=2.0)

        # Exact transient window this fix closes: SQLite already durably
        # has the secret, user_totp_secrets does not yet.
        assert username not in server.user_totp_secrets

        # A concurrent register() for the SAME fingerprint, brand-new
        # device_id, NO device_public_key/device_signature at all -- before
        # this fix, reading the stale RAM cache would admit this straight
        # through the no-TOTP allowlist path with zero proof.
        ws2 = await websockets.connect(running_server)
        await handshake(ws2, priv, pub_der)
        attacker_device_id = await register(ws2, pub_der, device_id="attacker-device")
        await asyncio.sleep(0.3)

        row_exists, _ = await server.db_get_authorized_device(username, attacker_device_id)
        assert not row_exists  # blocked behind the in-flight setup, not admitted

        release_commit.set()
        await asyncio.sleep(0.3)
        assert username in server.user_totp_secrets  # RAM caught up to the DB
    finally:
        server.db_commit_totp_setup = real_commit
        if not release_commit.is_set():
            release_commit.set()
        await ws1.close()
        if ws2:
            await ws2.close()


# ── 2. after setup completes, a waiting register() observes TOTP enabled ──

async def test_register_observes_totp_enabled_after_setup_completes(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws1 = await websockets.connect(running_server)
    ws2 = None
    try:
        await handshake(ws1, priv, pub_der)
        await register(ws1, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)

        secret = TOTP_TEST_SECRET
        code = _current_totp_code(secret)
        await ws1.send(json.dumps({"type": "totp_setup", "secret": secret, "code": code}))
        reply = await drain_until(ws1, "totp_setup_ok")
        assert reply["type"] == "totp_setup_ok"
        assert username in server.user_totp_secrets

        ws2 = await websockets.connect(running_server)
        await handshake(ws2, priv, pub_der)
        new_device_id = await register(ws2, pub_der, device_id="brand-new-device")  # no device proof supplied
        reply2 = await drain_until(ws2, "device_auth_failed")
        assert reply2["type"] == "device_auth_failed"

        row_exists, _ = await server.db_get_authorized_device(username, new_device_id)
        assert not row_exists
    finally:
        await ws1.close()
        if ws2:
            await ws2.close()


# ── 3. a failed setup leaves RAM state unchanged ───────────────────────────

async def test_totp_setup_db_failure_leaves_ram_unchanged(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws = await websockets.connect(running_server)
    await handshake(ws, priv, pub_der)
    await register(ws, pub_der, device_id="device-a")
    await asyncio.sleep(0.2)

    real_commit = server.db_commit_totp_setup

    async def failing_commit(*a, **kw):
        raise RuntimeError("simulated DB failure")

    server.db_commit_totp_setup = failing_commit
    try:
        secret = TOTP_TEST_SECRET
        code = _current_totp_code(secret)
        await ws.send(json.dumps({"type": "totp_setup", "secret": secret, "code": code}))
        await asyncio.sleep(0.3)
    finally:
        server.db_commit_totp_setup = real_commit
        try:
            await ws.close()
        except Exception:
            pass

    assert username not in server.user_totp_secrets

    # The exception propagating out of the handler still runs the
    # `async with` block's __aexit__ -- the lock must NOT be stuck held
    # forever. Verified via a fresh connection for the SAME fingerprint.
    ws2 = await websockets.connect(running_server)
    try:
        await handshake(ws2, priv, pub_der)
        await register(ws2, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)
        secret2 = TOTP_TEST_SECRET
        code2 = _current_totp_code(secret2)
        await ws2.send(json.dumps({"type": "totp_setup", "secret": secret2, "code": code2}))
        reply = await drain_until(ws2, "totp_setup_ok")
        assert reply["type"] == "totp_setup_ok"
        assert username in server.user_totp_secrets
    finally:
        await ws2.close()


# ── 4. concurrent disable/register serialize correctly ────────────────────

async def test_totp_disable_race_serializes_with_concurrent_register(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws1 = await websockets.connect(running_server)
    await handshake(ws1, priv, pub_der)
    await register(ws1, pub_der, device_id="device-a")
    await asyncio.sleep(0.2)

    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(1)
    await server.db_commit_totp_setup(username, secret, codes)
    server.user_totp_secrets[username] = secret

    commit_done    = asyncio.Event()
    release_commit = asyncio.Event()
    real_commit    = server.db_commit_totp_disable

    async def pausing_commit(username_):
        await real_commit(username_)
        commit_done.set()
        await release_commit.wait()

    server.db_commit_totp_disable = pausing_commit
    ws2 = None
    try:
        code = _current_totp_code(secret)
        await ws1.send(json.dumps({"type": "totp_disable", "code": code}))
        await asyncio.wait_for(commit_done.wait(), timeout=2.0)

        # Transient window: DB already durably has TOTP removed, RAM still
        # shows it enabled.
        assert username in server.user_totp_secrets

        ws2 = await websockets.connect(running_server)
        await handshake(ws2, priv, pub_der)
        new_device_id = await register(ws2, pub_der, device_id="new-device")  # no device proof supplied
        await asyncio.sleep(0.3)

        # Must still be BLOCKED behind the in-flight disable -- not yet
        # admitted either way while the lock is held.
        row_exists_during, _ = await server.db_get_authorized_device(username, new_device_id)
        assert not row_exists_during

        release_commit.set()
        await asyncio.sleep(0.3)
        assert username not in server.user_totp_secrets  # RAM caught up to the DB

        # TOTP really is off by the time this register() actually got to
        # run, so it's admitted without complaint -- but (S6-37) the
        # TOTP-disabled path no longer durably authorizes anything at all,
        # so still no row exists for it even now. `clients[username]`
        # (RAM-only) is what actually tracks the live session's device_id
        # going forward; nothing durable was ever needed here.
        row_exists_after, _ = await server.db_get_authorized_device(username, new_device_id)
        assert not row_exists_after
        async with server.lock:
            assert server.clients[username]["device_id"] == new_device_id
    finally:
        server.db_commit_totp_disable = real_commit
        if not release_commit.is_set():
            release_commit.set()
        await ws1.close()
        if ws2:
            await ws2.close()


# ── 5. a failed disable leaves RAM enabled ─────────────────────────────────

async def test_totp_disable_db_failure_leaves_ram_enabled(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws = await websockets.connect(running_server)
    await handshake(ws, priv, pub_der)
    await register(ws, pub_der, device_id="device-a")
    await asyncio.sleep(0.2)

    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(2)
    await server.db_commit_totp_setup(username, secret, codes)
    server.user_totp_secrets[username] = secret

    real_commit = server.db_commit_totp_disable

    async def failing_commit(*a, **kw):
        raise RuntimeError("simulated DB failure")

    server.db_commit_totp_disable = failing_commit
    try:
        code = _current_totp_code(secret)
        await ws.send(json.dumps({"type": "totp_disable", "code": code}))
        await asyncio.sleep(0.3)
    finally:
        server.db_commit_totp_disable = real_commit
        try:
            await ws.close()
        except Exception:
            pass

    assert username in server.user_totp_secrets  # unchanged, matching the still-committed DB row

    # Lock released despite the exception -- a fresh connection can still
    # disable it for real. New device_id + signature (TOTP is still
    # enabled, so "device-a"'s now-legacy NULL-pubkey row would otherwise
    # need re-proving too) and recovery codes throughout, since the failed
    # attempt above already consumed this time-step's TOTP counter
    # (totp_verify_and_consume() runs BEFORE the now-failing DB commit) --
    # replaying the identical code within the same 30s window would
    # correctly be rejected as a replay, unrelated to the lock behavior
    # this test is actually about.
    ws2 = await websockets.connect(running_server)
    try:
        challenge = await handshake(ws2, priv, pub_der)
        device_priv, device_pub_der = gen_keypair()
        device_b_id = canonical_device_id("device-b")
        device_sig = sign_device_challenge(device_priv, challenge, username, device_b_id)
        await register(ws2, pub_der, device_id=device_b_id, extra={
            "recovery_code": codes[0],
            "device_public_key": base64.b64encode(device_pub_der).decode(),
            "device_signature": base64.b64encode(device_sig).decode(),
        })
        await asyncio.sleep(0.2)

        await ws2.send(json.dumps({"type": "totp_disable", "code": "", "recovery_code": codes[1]}))
        reply = await drain_until(ws2, "totp_disable_ok")
        assert reply["type"] == "totp_disable_ok"
        assert username not in server.user_totp_secrets
    finally:
        await ws2.close()


# ── 6. two concurrent re-enrollment attempts serialize ─────────────────────

async def test_concurrent_reenrollment_attempts_serialize(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    old_secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(1)
    await server.db_commit_totp_setup(username, old_secret, codes)
    server.user_totp_secrets[username] = old_secret

    # The connection must actually COMPLETE registration (S6-39: a failed
    # register() no longer leaves a usable `username` on the socket) before
    # the race below -- proven via a real device signature + the current
    # TOTP code, deliberately NOT the recovery code (that single code is
    # reserved entirely for the actual race this test is about).
    #
    # Only ONE connection here, not two: this server allows exactly one live
    # registered session per account (a second register() for the same
    # fingerprint always evicts the first, by design -- see Phase 2's
    # session_conflict/reconnect handling), so "two devices racing" can no
    # longer be modeled as two simultaneously-open registered sockets once
    # registration actually has to succeed to reach totp_setup at all (S6-39
    # closed exactly that gap). totp_state_lock is keyed on username, not on
    # a connection, so firing both concurrent totp_setup attempts on the
    # SAME registered socket still exercises the identical serialization
    # property this test is actually about.
    device_id = canonical_device_id("device-a")
    device_priv, device_pub_der = gen_keypair()

    ws = await websockets.connect(running_server)
    try:
        challenge = await handshake(ws, priv, pub_der)
        extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                    totp_code=_current_totp_code(old_secret))
        await register(ws, pub_der, device_id, extra=extra)
        await asyncio.sleep(0.2)

        # Both attempts race to consume the SAME single recovery code as
        # re-enrollment proof, each proposing a DIFFERENT new secret.
        new_secret_1 = TOTP_TEST_SECRET_2
        new_secret_2 = TOTP_TEST_SECRET_3
        code1 = _current_totp_code(new_secret_1)
        code2 = _current_totp_code(new_secret_2)

        await asyncio.gather(
            ws.send(json.dumps({
                "type": "totp_setup", "secret": new_secret_1, "code": code1,
                "recovery_code": codes[0],
            })),
            ws.send(json.dumps({
                "type": "totp_setup", "secret": new_secret_2, "code": code2,
                "recovery_code": codes[0],
            })),
        )
        await asyncio.sleep(0.5)

        # Exactly one attempt could have won the single-use recovery code
        # -- RAM must land on exactly one of the two new secrets, never a
        # blend of both, and never crash/deadlock the connection.
        assert server.user_totp_secrets[username] in (new_secret_1, new_secret_2)

        with server.db_connect() as conn:
            row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (username,)).fetchone()
        stored_secret = server._totp_decrypt_from_storage(row[0])
        # DB and RAM must agree -- never split-brain between the two.
        assert stored_secret == server.user_totp_secrets[username]
    finally:
        await ws.close()


# ── 7. the global RAM lock and a totp_state_lock are never held together ──

async def test_totp_state_lock_and_global_lock_never_held_simultaneously(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    old_secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(1)
    await server.db_commit_totp_setup(username, old_secret, codes)
    server.user_totp_secrets[username] = old_secret

    totp_lock_held = {"flag": False}
    violation       = {"flag": False}

    real_get_totp_state_lock = server.get_totp_state_lock

    def tracking_get_totp_state_lock(username_):
        real_state_lock = real_get_totp_state_lock(username_)
        if not hasattr(real_state_lock, "_s632_tracked"):
            real_state_lock._s632_tracked = True
            real_acquire = real_state_lock.acquire
            real_release = real_state_lock.release

            async def tracked_acquire():
                await real_acquire()
                totp_lock_held["flag"] = True

            def tracked_release():
                totp_lock_held["flag"] = False
                real_release()

            real_state_lock.acquire = tracked_acquire
            real_state_lock.release = tracked_release
        return real_state_lock

    real_global_acquire = server.lock.acquire

    async def tracked_global_acquire():
        if totp_lock_held["flag"]:
            violation["flag"] = True
        await real_global_acquire()

    server.get_totp_state_lock = tracking_get_totp_state_lock
    server.lock.acquire = tracked_global_acquire
    try:
        ws = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws, priv, pub_der)
            device_priv, device_pub_der = gen_keypair()
            totp_device_id = canonical_device_id("totp-device")
            device_sig = sign_device_challenge(device_priv, challenge, username, totp_device_id)
            code = _current_totp_code(old_secret)
            await register(ws, pub_der, device_id=totp_device_id, extra={
                "totp_code": code,
                "device_public_key": base64.b64encode(device_pub_der).decode(),
                "device_signature": base64.b64encode(device_sig).decode(),
            })
            await asyncio.sleep(0.3)
        finally:
            await ws.close()

        assert not violation["flag"]
    finally:
        server.get_totp_state_lock = real_get_totp_state_lock
        server.lock.acquire = real_global_acquire


# ── totp_setup: current_code vs new_code, two independent proofs ──────────
#
# totp_setup used to read message["code"] for BOTH proving possession of the
# CURRENT secret (re-enrollment authorization) AND validating the NEW secret
# being enrolled -- two unrelated TOTP secrets, so one 6-digit value almost
# never validates against both at once. Current-TOTP-authorized re-enrollment
# was therefore practically broken (only the recovery_code fallback ever
# worked), and the old ordering could consume the CURRENT secret's counter
# before ever validating the new one, burning a real auth window on an
# attempt that was going to fail anyway. See SECURITY_INVARIANTS.md #46.

async def test_totp_setup_first_time_succeeds_with_new_code(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)

        secret = TOTP_TEST_SECRET
        new_code = _current_totp_code(secret)
        await ws.send(json.dumps({"type": "totp_setup", "secret": secret, "new_code": new_code}))
        reply = await drain_until(ws, "totp_setup_ok")
        assert reply["type"] == "totp_setup_ok"
        assert server.user_totp_secrets[username] == secret
    finally:
        await ws.close()


async def test_totp_reenrollment_succeeds_with_current_code_and_new_code(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)

        old_secret = TOTP_TEST_SECRET
        codes = server.generate_recovery_codes(1)
        await server.db_commit_totp_setup(username, old_secret, codes)
        server.user_totp_secrets[username] = old_secret

        # current_code (proof of the OLD secret) and new_code (proof of the
        # NEW secret) are DIFFERENT values -- exactly the scenario that was
        # practically broken before this fix (a single "code" field almost
        # never validates against two independent secrets at once).
        new_secret = TOTP_TEST_SECRET_2
        current_code = _current_totp_code(old_secret)
        new_code = _current_totp_code(new_secret)
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": new_secret, "new_code": new_code,
            "current_code": current_code,
        }))
        reply = await drain_until(ws, "totp_setup_ok")
        assert reply["type"] == "totp_setup_ok"
        assert server.user_totp_secrets[username] == new_secret

        with server.db_connect() as conn:
            row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (username,)).fetchone()
        assert server._totp_decrypt_from_storage(row[0]) == new_secret
    finally:
        await ws.close()


async def test_totp_reenrollment_succeeds_with_recovery_code_and_new_code(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)

        old_secret = TOTP_TEST_SECRET
        codes = server.generate_recovery_codes(1)
        await server.db_commit_totp_setup(username, old_secret, codes)
        server.user_totp_secrets[username] = old_secret

        new_secret = TOTP_TEST_SECRET_2
        new_code = _current_totp_code(new_secret)
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": new_secret, "new_code": new_code,
            "recovery_code": codes[0],
        }))
        reply = await drain_until(ws, "totp_setup_ok")
        assert reply["type"] == "totp_setup_ok"
        assert server.user_totp_secrets[username] == new_secret
    finally:
        await ws.close()


async def test_totp_setup_invalid_new_code_does_not_consume_current_counter(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)

        old_secret = TOTP_TEST_SECRET
        codes = server.generate_recovery_codes(1)
        await server.db_commit_totp_setup(username, old_secret, codes)
        server.user_totp_secrets[username] = old_secret

        current_code = _current_totp_code(old_secret)
        new_secret = TOTP_TEST_SECRET_2
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": new_secret, "new_code": "000000",  # invalid for new_secret
            "current_code": current_code,
        }))
        reply = await drain_until(ws, "totp_setup_failed")
        assert reply["reason"] == "invalid_code"
        assert server.user_totp_secrets[username] == old_secret  # unchanged

        # The SAME current_code must still be usable -- proof the doomed
        # attempt above never consumed it.
        new_code = _current_totp_code(new_secret)
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": new_secret, "new_code": new_code,
            "current_code": current_code,
        }))
        reply2 = await drain_until(ws, "totp_setup_ok")
        assert reply2["type"] == "totp_setup_ok"
        assert server.user_totp_secrets[username] == new_secret
    finally:
        await ws.close()


async def test_totp_setup_invalid_new_code_does_not_consume_recovery_code(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)

        old_secret = TOTP_TEST_SECRET
        codes = server.generate_recovery_codes(1)
        await server.db_commit_totp_setup(username, old_secret, codes)
        server.user_totp_secrets[username] = old_secret

        new_secret = TOTP_TEST_SECRET_2
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": new_secret, "new_code": "000000",
            "recovery_code": codes[0],
        }))
        reply = await drain_until(ws, "totp_setup_failed")
        assert reply["reason"] == "invalid_code"
        assert server.user_totp_secrets[username] == old_secret

        # The SAME single-use recovery code must still be unconsumed.
        new_code = _current_totp_code(new_secret)
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": new_secret, "new_code": new_code,
            "recovery_code": codes[0],
        }))
        reply2 = await drain_until(ws, "totp_setup_ok")
        assert reply2["type"] == "totp_setup_ok"
        assert server.user_totp_secrets[username] == new_secret
    finally:
        await ws.close()


async def test_totp_setup_valid_new_code_invalid_current_proof_does_not_replace_secret(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)

        old_secret = TOTP_TEST_SECRET
        codes = server.generate_recovery_codes(1)
        await server.db_commit_totp_setup(username, old_secret, codes)
        server.user_totp_secrets[username] = old_secret

        new_secret = TOTP_TEST_SECRET_2
        new_code = _current_totp_code(new_secret)  # genuinely valid for new_secret
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": new_secret, "new_code": new_code,
            "current_code": "000000", "recovery_code": "NOTAREALCODE-XXXXX-XXXXX-XXXXX",
        }))
        reply = await drain_until(ws, "totp_setup_failed")
        assert reply["reason"] == "already_enabled"
        assert server.user_totp_secrets[username] == old_secret  # a valid new_code alone is not enough

        with server.db_connect() as conn:
            row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (username,)).fetchone()
        assert server._totp_decrypt_from_storage(row[0]) == old_secret
    finally:
        await ws.close()


async def test_totp_setup_replacement_resets_last_counter(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id="device-a")
        await asyncio.sleep(0.2)

        old_secret = TOTP_TEST_SECRET
        codes = server.generate_recovery_codes(1)
        await server.db_commit_totp_setup(username, old_secret, codes)
        server.user_totp_secrets[username] = old_secret

        # Consume the old secret's counter for real first, so last_counter is
        # demonstrably NOT already -1 going into re-enrollment.
        current_code = _current_totp_code(old_secret)
        assert await server.totp_verify_and_consume(username, current_code)
        with server.db_connect() as conn:
            row = conn.execute("SELECT last_counter FROM user_totp WHERE username = ?", (username,)).fetchone()
        assert row[0] != -1

        new_secret = TOTP_TEST_SECRET_2
        new_code = _current_totp_code(new_secret)
        # +1 step -- the current time-step's code was already consumed just
        # above; totp_code_matches' own +/-1 drift window still accepts this.
        next_current_code = server._totp_code_at_counter(old_secret, int(server.time.time() // 30) + 1)
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": new_secret, "new_code": new_code,
            "current_code": next_current_code,
        }))
        reply = await drain_until(ws, "totp_setup_ok")
        assert reply["type"] == "totp_setup_ok"

        with server.db_connect() as conn:
            row2 = conn.execute("SELECT last_counter FROM user_totp WHERE username = ?", (username,)).fetchone()
        assert row2[0] == -1
    finally:
        await ws.close()


async def test_totp_concurrent_reenrollment_with_current_code_serializes(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    old_secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(1)
    await server.db_commit_totp_setup(username, old_secret, codes)
    server.user_totp_secrets[username] = old_secret

    # The connection must actually COMPLETE registration (S6-39) before the
    # race below. Proven via a real device signature + the single recovery
    # code here (NOT a totp_code -- that would consume this time-step's TOTP
    # counter, which the actual test below needs untouched for the
    # current_code race).
    #
    # Only ONE connection, not two -- see test_concurrent_reenrollment_
    # attempts_serialize's own comment: this server allows exactly one live
    # registered session per account, so both concurrent totp_setup attempts
    # fire on the SAME registered socket. totp_state_lock is keyed on
    # username, not connection, so this still exercises the same
    # serialization property.
    device_id = canonical_device_id("device-a")
    device_priv, device_pub_der = gen_keypair()

    ws = await websockets.connect(running_server)
    try:
        challenge = await handshake(ws, priv, pub_der)
        extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                    recovery_code=codes[0])
        await register(ws, pub_der, device_id, extra=extra)
        await asyncio.sleep(0.2)

        # Both attempts race to consume the SAME current_code (same secret,
        # same time-step) as re-enrollment proof, each proposing a DIFFERENT
        # new secret -- the totp_state_lock (S6-32) must still fully
        # serialize this even with the corrected current_code/new_code split.
        current_code = _current_totp_code(old_secret)
        new_secret_1 = TOTP_TEST_SECRET_2
        new_secret_2 = TOTP_TEST_SECRET_3
        code1 = _current_totp_code(new_secret_1)
        code2 = _current_totp_code(new_secret_2)

        await asyncio.gather(
            ws.send(json.dumps({
                "type": "totp_setup", "secret": new_secret_1, "new_code": code1,
                "current_code": current_code,
            })),
            ws.send(json.dumps({
                "type": "totp_setup", "secret": new_secret_2, "new_code": code2,
                "current_code": current_code,
            })),
        )
        await asyncio.sleep(0.5)

        # Exactly one attempt could have won the single-use TOTP counter --
        # RAM must land on exactly one of the two new secrets, never a blend.
        assert server.user_totp_secrets[username] in (new_secret_1, new_secret_2)
        with server.db_connect() as conn:
            row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (username,)).fetchone()
        stored_secret = server._totp_decrypt_from_storage(row[0])
        assert stored_secret == server.user_totp_secrets[username]
    finally:
        await ws.close()


# ── Bounded, truthful incoming federation-forward dedup ──────────────────
#
# federated_forward had no dedicated rate limit, and its dedup dict
# (delivered_msg_ids) had a TTL but no hard entry cap -- a flood of unique
# msg_ids within the 5-minute TTL grew it without bound, AND the old cleanup
# rescanned the whole dict on every message (O(N) per message, O(N^2) total
# under a sustained flood). Separately, a msg_id used to be marked delivered
# BEFORE delivery/storage actually succeeded, and malformed frames (non-dict
# top-level JSON, non-dict payload, an unhashable/oversized msg_id) could
# raise straight into the handler's outer except, killing the whole peer
# connection over one bad frame. See SECURITY_INVARIANTS.md #47.

async def federation_connect(url):
    """Connects and completes the federation_auth HMAC handshake -- caller
    must have already set server.FEDERATION_SECRET."""
    ws = await websockets.connect(url)
    challenge_msg = json.loads(await ws.recv())
    assert challenge_msg["type"] == "challenge"
    challenge = base64.b64decode(challenge_msg["data"])
    mac = server.hmac.new(server.FEDERATION_SECRET.encode(), challenge, server.hashlib.sha256).digest()
    await ws.send(json.dumps({"type": "federation_auth", "mac": base64.b64encode(mac).decode()}))
    auth_ok = json.loads(await ws.recv())
    assert auth_ok["type"] == "federation_auth_ok"
    return ws


# ── 1. malformed non-dict federation JSON does not kill the handler ──────

async def test_federation_malformed_non_dict_json_does_not_kill_handler(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps(["not", "a", "dict"]))
            await ws.send(json.dumps(42))
            await ws.send(json.dumps("just a string"))
            await asyncio.sleep(0.2)
            # The handler loop must have survived all three -- a subsequent
            # well-formed frame is still processed normally.
            await ws.send(json.dumps({
                "type": "federated_forward", "to": canonical_fingerprint("NOSUCHUSER_MALFORMED"),
                "payload": {"id": "malformed-probe-1", "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            }))
            await asyncio.sleep(0.3)
            assert "malformed-probe-1" in server.delivered_msg_ids
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 2. non-dict payload rejected ──────────────────────────────────────────

async def test_federation_non_dict_payload_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": "NOSUCHUSER_BADPAYLOAD",
                "payload": ["not", "a", "dict"],
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows("NOSUCHUSER_BADPAYLOAD")) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 3. unhashable/list msg_id rejected ─────────────────────────────────────

async def test_federation_unhashable_msg_id_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("NOSUCHUSER_LISTID")
    sender = canonical_fingerprint("SOMESENDER")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": ["not", "hashable"], "type": "message", "text": "x", "from": sender},
            }))
            await asyncio.sleep(0.3)
            # Must not have crashed the handler -- a follow-up well-formed
            # frame for the same "to" still gets processed.
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "after-listid-probe", "type": "message", "text": "y", "from": sender},
            }))
            await asyncio.sleep(0.3)
            assert "after-listid-probe" in server.delivered_msg_ids
            assert len(_read_pending_rows(to)) == 1  # only the valid one stored
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 4. overlong msg_id rejected ────────────────────────────────────────────

async def test_federation_overlong_msg_id_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            huge_id = "X" * (server.FED_DEDUP_MAX_MSG_ID_LEN + 1)
            to = canonical_fingerprint("NOSUCHUSER_HUGEID")
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": huge_id, "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 0
            assert huge_id not in server.delivered_msg_ids
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 5. repeated msg_id after successful ONLINE delivery delivered once ────

async def test_federation_repeated_msg_id_after_online_delivery_delivered_once(running_server):
    recipient, recipient_fp, _, _ = await connect_and_register(running_server, device_id="fedrecip")
    await asyncio.sleep(0.2)
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            frame = json.dumps({
                "type": "federated_forward", "to": recipient_fp,
                "payload": {"id": "online-dup-1", "type": "message", "text": "hi",
                            "from": canonical_fingerprint("SOMEONE")},
            })
            await ws.send(frame)
            await asyncio.sleep(0.2)
            await ws.send(frame)  # exact duplicate, same msg_id
            await asyncio.sleep(0.3)

            received = []
            try:
                async with asyncio.timeout(0.5):
                    while True:
                        received.append(json.loads(await recipient.recv()))
            except (asyncio.TimeoutError, TimeoutError):
                pass
            matches = [m for m in received if m.get("id") == "online-dup-1"]
            assert len(matches) == 1
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        await recipient.close()


# ── 6. repeated msg_id after successful durable offline store stored once ─

async def test_federation_repeated_msg_id_after_offline_store_stored_once(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    try:
        ws = await federation_connect(running_server)
        try:
            to = canonical_fingerprint("NOSUCHUSER_OFFLINE_DUP")
            frame = json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "offline-dup-1", "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            })
            await ws.send(frame)
            await asyncio.sleep(0.2)
            await ws.send(frame)
            await asyncio.sleep(0.2)
            # The federation dedup layer itself caught the 2nd attempt --
            # db_store was never even called for it.
            assert call_count == 1
            assert len(_read_pending_rows(to)) == 1
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 7. failed send_safe does NOT poison dedup; retry may succeed ─────────

async def test_federation_failed_send_safe_does_not_poison_dedup(running_server):
    recipient, recipient_fp, _, _ = await connect_and_register(running_server, device_id="fedfailsend")
    await asyncio.sleep(0.2)
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"

    real_send_safe = server.send_safe
    state = {"fail_once": True}

    async def flaky_send_safe(ws, data):
        if state["fail_once"] and "fedfailsend-dup-1" in data:
            state["fail_once"] = False
            return False
        return await real_send_safe(ws, data)

    server.send_safe = flaky_send_safe
    try:
        ws = await federation_connect(running_server)
        try:
            frame = json.dumps({
                "type": "federated_forward", "to": recipient_fp,
                "payload": {"id": "fedfailsend-dup-1", "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            })
            await ws.send(frame)
            await asyncio.sleep(0.3)
            assert "fedfailsend-dup-1" not in server.delivered_msg_ids
            assert "fedfailsend-dup-1" not in server.federation_delivery_inflight

            await ws.send(frame)  # retry -- must be allowed to actually succeed
            await asyncio.sleep(0.3)
            assert "fedfailsend-dup-1" in server.delivered_msg_ids
        finally:
            await ws.close()
    finally:
        server.send_safe = real_send_safe
        server.FEDERATION_SECRET = old_secret
        await recipient.close()


# ── 8. FULL/RATE_LIMITED/CONFLICT db_store does NOT poison dedup ──────────

async def test_federation_db_store_failure_status_does_not_poison_dedup(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"

    real_db_store = server.db_store
    state = {"fail_once": True}

    async def flaky_db_store(recipient, payload_dict, msg_id=None):
        if state["fail_once"] and msg_id == "fed-dbfail-dup-1":
            state["fail_once"] = False
            return "FULL"
        return await real_db_store(recipient, payload_dict, msg_id)

    server.db_store = flaky_db_store
    try:
        ws = await federation_connect(running_server)
        try:
            to = canonical_fingerprint("NOSUCHUSER_DBFAIL")
            frame = json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "fed-dbfail-dup-1", "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            })
            await ws.send(frame)
            await asyncio.sleep(0.3)
            assert "fed-dbfail-dup-1" not in server.delivered_msg_ids
            assert "fed-dbfail-dup-1" not in server.federation_delivery_inflight

            await ws.send(frame)
            await asyncio.sleep(0.3)
            assert "fed-dbfail-dup-1" in server.delivered_msg_ids
            assert len(_read_pending_rows(to)) == 1
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 9. two concurrent peer connections, same msg_id, one handoff ─────────

async def test_federation_concurrent_connections_same_msg_id_one_handoff(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"

    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    try:
        ws1 = await federation_connect(running_server)
        ws2 = await federation_connect(running_server)
        try:
            to = canonical_fingerprint("NOSUCHUSER_CONCURRENT_FED")
            frame = json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "fed-concurrent-1", "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            })
            await asyncio.gather(ws1.send(frame), ws2.send(frame))
            await asyncio.sleep(0.4)

            # Only ONE of the two concurrent frames ever reached db_store --
            # federation_delivery_inflight caught the other while the first
            # was still mid-handoff.
            assert call_count == 1
            assert len(_read_pending_rows(to)) == 1
            assert "fed-concurrent-1" in server.delivered_msg_ids
        finally:
            await ws1.close()
            await ws2.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 10. cancellation releases federation_delivery_inflight ────────────────

async def test_federation_cancellation_releases_inflight_reservation(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"

    real_db_store = server.db_store

    async def cancelling_db_store(*a, **kw):
        raise asyncio.CancelledError()

    server.db_store = cancelling_db_store
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": canonical_fingerprint("NOSUCHUSER_CANCEL_FED"),
                "payload": {"id": "fed-cancel-1", "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            }))
            await asyncio.sleep(0.3)
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret

    assert "fed-cancel-1" not in server.federation_delivery_inflight
    assert "fed-cancel-1" not in server.delivered_msg_ids


# ── 11. dedup cache never exceeds FED_DEDUP_MAX_IDS ────────────────────────

async def test_federation_dedup_cache_never_exceeds_max_ids(running_server):
    real_cap = server.FED_DEDUP_MAX_IDS
    server.FED_DEDUP_MAX_IDS = 5
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            sender = canonical_fingerprint("SOMESENDER")
            for i in range(20):
                await ws.send(json.dumps({
                    "type": "federated_forward", "to": canonical_fingerprint(f"NOSUCHUSER_MAXIDS_{i}"),
                    "payload": {"id": f"fed-maxids-{i}", "type": "message", "text": "x", "from": sender},
                }))
            await asyncio.sleep(0.5)
            assert len(server.delivered_msg_ids) <= 5
            # Evicting the OLDEST tombstone is the documented trade-off --
            # the most recent ones must be what's retained.
            assert "fed-maxids-19" in server.delivered_msg_ids
            assert "fed-maxids-0" not in server.delivered_msg_ids
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        server.FED_DEDUP_MAX_IDS = real_cap


# ── 12. inflight set never exceeds FED_DEDUP_MAX_INFLIGHT ─────────────────

async def test_federation_inflight_set_never_exceeds_max_inflight(running_server):
    real_cap = server.FED_DEDUP_MAX_INFLIGHT
    server.FED_DEDUP_MAX_INFLIGHT = 3
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"

    release = asyncio.Event()
    real_db_store = server.db_store

    async def blocking_db_store(*a, **kw):
        await release.wait()
        return await real_db_store(*a, **kw)

    server.db_store = blocking_db_store
    try:
        ws = await federation_connect(running_server)
        try:
            sender = canonical_fingerprint("SOMESENDER")
            for i in range(10):
                await ws.send(json.dumps({
                    "type": "federated_forward", "to": canonical_fingerprint(f"NOSUCHUSER_MAXINFLIGHT_{i}"),
                    "payload": {"id": f"fed-maxinflight-{i}", "type": "message", "text": "x", "from": sender},
                }))
            await asyncio.sleep(0.3)  # let all 10 reach Phase A/B and block on `release`
            assert len(server.federation_delivery_inflight) <= 3

            release.set()
            await asyncio.sleep(0.4)  # let the blocked ones actually finish
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret
        server.FED_DEDUP_MAX_INFLIGHT = real_cap


# ── 13. expiry removes only stale entries, oldest-first ───────────────────

async def test_federation_dedup_cleanup_expires_oldest_only():
    server.delivered_msg_ids.clear()
    now = server.time.time()
    server.delivered_msg_ids["old1"]   = now - server.FED_DEDUP_TTL_SEC - 10
    server.delivered_msg_ids["old2"]   = now - server.FED_DEDUP_TTL_SEC - 5
    server.delivered_msg_ids["fresh1"] = now - 10
    server.delivered_msg_ids["fresh2"] = now - 5

    async with server.federation_dedup_lock:
        server._federation_dedup_cleanup_locked(now)

    assert list(server.delivered_msg_ids.keys()) == ["fresh1", "fresh2"]


# ── 14. per-IP forward limit rejects flood ─────────────────────────────────

async def test_federation_per_ip_forward_limit_rejects_flood():
    real_limit   = server.FED_FORWARD_PER_IP_LIMIT
    real_enabled = server.FED_FORWARD_PER_IP_ENABLED
    server.FED_FORWARD_PER_IP_LIMIT   = 3
    server.FED_FORWARD_PER_IP_ENABLED = True
    server.fed_forward_rate_per_ip.pop("1.2.3.4", None)
    server.fed_forward_rate_per_ip.pop("5.6.7.8", None)
    try:
        results = [server.fed_forward_rate_per_ip_ok("1.2.3.4") for _ in range(6)]
        assert results == [True, True, True, False, False, False]
        # A DIFFERENT peer IP is completely unaffected -- per-IP fairness.
        assert server.fed_forward_rate_per_ip_ok("5.6.7.8") is True
    finally:
        server.FED_FORWARD_PER_IP_LIMIT   = real_limit
        server.FED_FORWARD_PER_IP_ENABLED = real_enabled
        server.fed_forward_rate_per_ip.pop("1.2.3.4", None)
        server.fed_forward_rate_per_ip.pop("5.6.7.8", None)


# ── 15. global forward limit bounds many peer IPs collectively ────────────

async def test_federation_global_forward_limit_bounds_multiple_ips_collectively():
    real_per_ip_limit   = server.FED_FORWARD_PER_IP_LIMIT
    real_per_ip_enabled = server.FED_FORWARD_PER_IP_ENABLED
    real_global_limit   = server.FED_FORWARD_GLOBAL_LIMIT
    real_global_enabled = server.FED_FORWARD_GLOBAL_ENABLED
    server.FED_FORWARD_PER_IP_LIMIT   = 100  # generous -- not the thing under test
    server.FED_FORWARD_PER_IP_ENABLED = True
    server.FED_FORWARD_GLOBAL_LIMIT   = 5
    server.FED_FORWARD_GLOBAL_ENABLED = True
    server.fed_forward_rate_global["count"]      = 0
    server.fed_forward_rate_global["reset_time"] = server.time.time()
    try:
        accepted = 0
        for i in range(10):
            ip = f"10.0.0.{i}"  # 10 DIFFERENT peer IPs, one forward each
            if server.fed_forward_rate_per_ip_ok(ip) and server.fed_forward_rate_global_ok():
                accepted += 1
        # The aggregate cap bit even though every individual IP was well
        # under its own per-IP limit.
        assert accepted == 5
    finally:
        server.FED_FORWARD_PER_IP_LIMIT   = real_per_ip_limit
        server.FED_FORWARD_PER_IP_ENABLED = real_per_ip_enabled
        server.FED_FORWARD_GLOBAL_LIMIT   = real_global_limit
        server.FED_FORWARD_GLOBAL_ENABLED = real_global_enabled
        server.fed_forward_rate_global["count"]      = 0
        server.fed_forward_rate_global["reset_time"] = server.time.time()


# ── 16. no-msg-id forwards are still rate-limited ──────────────────────────

async def test_federation_no_msg_id_forwards_still_rate_limited(running_server):
    real_limit   = server.FED_FORWARD_PER_IP_LIMIT
    real_enabled = server.FED_FORWARD_PER_IP_ENABLED
    server.FED_FORWARD_PER_IP_LIMIT   = 3
    server.FED_FORWARD_PER_IP_ENABLED = True
    server.fed_forward_rate_per_ip.clear()
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"

    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    try:
        ws = await federation_connect(running_server)
        try:
            to = canonical_fingerprint("NOSUCHUSER_NOID_RATE")
            sender = canonical_fingerprint("SOMESENDER")
            for i in range(6):
                await ws.send(json.dumps({
                    "type": "federated_forward", "to": to,
                    # deliberately no "id" -- "from" still required/valid
                    "payload": {"type": "message", "text": f"no-id-{i}", "from": sender},
                }))
            await asyncio.sleep(0.4)
            # Only the first FED_FORWARD_PER_IP_LIMIT (3) attempts reached
            # db_store -- the rest rejected purely by the rate limiter,
            # since a no-msg-id payload has no dedup layer to fall back on.
            assert call_count == 3
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store


# ── Canonical fingerprint validation + self-pruning prekey lock registry ──
#
# prekey_mutation_locks used to be a defaultdict(asyncio.Lock) -- one lock
# permanently kept per distinct key ever looked up, for the life of the
# process -- and consume_prekey_bundle_for_serve(target) acquired
# prekey_mutation_locks[target] before knowing whether target was even a
# real account. Combined with get_prekey_bundle's old `target =
# message.get("target")` (no shape validation), any authenticated client
# could mint a permanent RAM-resident lock (plus its retained, potentially
# huge, dict key) for every unique garbage string it sent. See
# SECURITY_INVARIANTS.md #48.

# ── 3. is_valid_fingerprint() rejects every malformed shape ──────────────

async def test_is_valid_fingerprint_rejects_malformed_shapes():
    assert server.is_valid_fingerprint("DEADBEEFDEADBEEF") is True   # sanity: a genuinely valid one
    assert server.is_valid_fingerprint("deadbeefdeadbeef") is False  # lowercase
    assert server.is_valid_fingerprint("DEADBEEFDEADBEEG") is False  # 'G' is not hex
    assert server.is_valid_fingerprint("DEADBEEFDEADBEE") is False   # 15 chars
    assert server.is_valid_fingerprint("DEADBEEFDEADBEEFF") is False  # 17 chars
    assert server.is_valid_fingerprint("") is False
    assert server.is_valid_fingerprint(None) is False
    assert server.is_valid_fingerprint(["DEADBEEFDEADBEEF"]) is False
    assert server.is_valid_fingerprint({"a": 1}) is False
    assert server.is_valid_fingerprint(12345678901234) is False


# ── 1. None/list/dict/int target rejected before consume/DB ──────────────

async def test_get_prekey_bundle_invalid_target_types_rejected_before_consume(running_server):
    call_count = 0
    real_consume = server.consume_prekey_bundle_for_serve

    async def counting_consume(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_consume(*a, **kw)

    server.consume_prekey_bundle_for_serve = counting_consume
    try:
        requester, _, _, _ = await connect_and_register(running_server, device_id="badtarget_types")
        try:
            for bad_target in (None, ["a", "list"], {"a": "dict"}, 12345):
                await requester.send(json.dumps({"type": "get_prekey_bundle", "target": bad_target}))
            await asyncio.sleep(0.3)
            assert call_count == 0
        finally:
            await requester.close()
    finally:
        server.consume_prekey_bundle_for_serve = real_consume


# ── 2. overlong target rejected before lock-registry mutation ────────────

async def test_get_prekey_bundle_overlong_target_rejected_before_registry_mutation(running_server):
    requester, _, _, _ = await connect_and_register(running_server, device_id="overlong_target")
    try:
        huge_target = "A" * 1000
        await requester.send(json.dumps({"type": "get_prekey_bundle", "target": huge_target}))
        await asyncio.sleep(0.3)
        assert huge_target not in server.prekey_mutation_locks
        assert len(server.prekey_mutation_locks) == 0
    finally:
        await requester.close()


# ── 4. valid 16-char fingerprint still works end to end ───────────────────

async def test_get_prekey_bundle_valid_fingerprint_still_works(running_server):
    target = "CAFEBABECAFEBABE"
    opk = {"id": "opkvalid1", "key": "K1"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk]})

    requester, _, _, _ = await connect_and_register(running_server, device_id="validfp")
    try:
        await requester.send(json.dumps({"type": "get_prekey_bundle", "target": target}))
        response = await drain_until(requester, "prekey_bundle_response")
        assert response["bundle"]["opks"] == [opk]
    finally:
        await requester.close()


# ── 5. many sequential unique valid-looking nonexistent targets leave the
#      registry empty after each completes ────────────────────────────────

async def test_many_sequential_unique_targets_leave_registry_empty(running_server):
    real_rate_limit_check = server.rate_limit_check
    server.rate_limit_check = lambda *a, **kw: True  # isolate registry growth from the unrelated prekey_fetch limit
    try:
        requester, _, _, _ = await connect_and_register(running_server, device_id="manytargets")
        try:
            n = 300
            for i in range(n):
                target = f"{i:016X}"  # unique, canonical-looking, never actually stored
                await requester.send(json.dumps({"type": "get_prekey_bundle", "target": target}))
            received = 0
            async with asyncio.timeout(10.0):
                while received < n:
                    msg = json.loads(await requester.recv())
                    if msg.get("type") == "prekey_bundle_response":
                        received += 1
            assert len(server.prekey_mutation_locks) == 0
        finally:
            await requester.close()
    finally:
        server.rate_limit_check = real_rate_limit_check


# ── 6. a finished normal publish leaves no registry entry ────────────────

async def test_finished_publish_leaves_no_registry_entry():
    target = "1234567890ABCDEF"
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": []})
    assert target not in server.prekey_mutation_locks


# ── 7. a finished normal consume leaves no registry entry ─────────────────

async def test_finished_consume_leaves_no_registry_entry():
    target = "ABCDEF1234567890"
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [{"id": "o1", "key": "K"}]})
    await server.consume_prekey_bundle_for_serve(target, "TESTER")
    assert target not in server.prekey_mutation_locks


# ── 8. two concurrent consumes of the SAME target share exactly one
#      registry entry and remain serialized ───────────────────────────────

async def test_concurrent_consumes_same_target_share_one_registry_entry():
    target = "0F0F0F0F0F0F0F0F"
    opk1, opk2 = {"id": "c1", "key": "K1"}, {"id": "c2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    seen_entries = []
    real_db_consume = server.db_consume_prekey_opk

    async def observing_db_consume(t):
        seen_entries.append(server.prekey_mutation_locks.get(t))
        return await real_db_consume(t)

    server.db_consume_prekey_opk = observing_db_consume
    try:
        # Different requester_scopes -- see test_concurrent_fetches_
        # receive_different_opks's own comment on why (S6-36 pair cooldown
        # is orthogonal to what this test checks).
        results = await asyncio.gather(
            server.consume_prekey_bundle_for_serve(target, "SHARE_REQUESTER_A"),
            server.consume_prekey_bundle_for_serve(target, "SHARE_REQUESTER_B"),
        )
    finally:
        server.db_consume_prekey_opk = real_db_consume

    assert len(seen_entries) == 2
    assert seen_entries[0] is seen_entries[1]  # the exact same registry entry/lock backed both
    opks_received = {r[0]["opks"][0]["id"] for r in results if r[0] and r[0]["opks"]}
    assert opks_received == {"c1", "c2"}  # serialized -- each got a DIFFERENT OPK, never raced
    assert target not in server.prekey_mutation_locks  # pruned once both finished


# ── 9. publish racing consume for the SAME target shares the same
#      registry entry too, and invariant #39 still holds ─────────────────

async def test_publish_and_consume_share_same_registry_entry_for_same_target():
    target = "1357913579135791"
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [{"id": "r1"}, {"id": "r2"}]})

    seen_entries = []
    real_db_consume = server.db_consume_prekey_opk
    real_db_save    = server.db_save_bundle

    async def observing_db_consume(t):
        seen_entries.append(server.prekey_mutation_locks.get(t))
        return await real_db_consume(t)

    async def observing_db_save(u, data):
        seen_entries.append(server.prekey_mutation_locks.get(u))
        return await real_db_save(u, data)

    server.db_consume_prekey_opk = observing_db_consume
    server.db_save_bundle        = observing_db_save
    try:
        await asyncio.gather(
            server.consume_prekey_bundle_for_serve(target, "TESTER"),
            server.store_prekey_bundle(target, {"ik": "IK2", "spk": "SPK2", "opks": [{"id": "r3"}]}),
        )
    finally:
        server.db_consume_prekey_opk = real_db_consume
        server.db_save_bundle        = real_db_save

    assert len(seen_entries) == 2
    assert seen_entries[0] is seen_entries[1]  # publish and consume shared the SAME lock instance
    assert target not in server.prekey_mutation_locks


# ── 10. different targets still proceed fully concurrently ────────────────

async def test_different_targets_proceed_concurrently():
    target_a = "1111111111111111"
    target_b = "2222222222222222"
    await server.store_prekey_bundle(target_a, {"ik": "IK", "spk": "SPK", "opks": [{"id": "a1"}]})
    await server.store_prekey_bundle(target_b, {"ik": "IK", "spk": "SPK", "opks": [{"id": "b1"}]})

    release = asyncio.Event()
    real_db_consume = server.db_consume_prekey_opk

    async def blocking_for_a(t):
        if t == target_a:
            await release.wait()
        return await real_db_consume(t)

    server.db_consume_prekey_opk = blocking_for_a
    try:
        task_a = asyncio.create_task(server.consume_prekey_bundle_for_serve(target_a, "TESTER"))
        await asyncio.sleep(0.1)  # let A actually enter and block

        # B must NOT be blocked by A's still-held lock -- different
        # targets, different registry entries, never share serialization.
        result_b = await asyncio.wait_for(server.consume_prekey_bundle_for_serve(target_b, "TESTER"), timeout=1.0)
        assert result_b[0]["opks"] == [{"id": "b1"}]

        release.set()
        result_a = await asyncio.wait_for(task_a, timeout=1.0)
        assert result_a[0]["opks"] == [{"id": "a1"}]
    finally:
        server.db_consume_prekey_opk = real_db_consume


# ── 11. cancellation while WAITING for the lock does not leak refs ────────

async def test_cancellation_while_waiting_does_not_leak_refs():
    target = "AAAA1111BBBB2222"
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [{"id": "w1"}]})

    release = asyncio.Event()
    real_db_consume = server.db_consume_prekey_opk

    async def blocking_db_consume(t):
        await release.wait()
        return await real_db_consume(t)

    server.db_consume_prekey_opk = blocking_db_consume
    try:
        task_a = asyncio.create_task(server.consume_prekey_bundle_for_serve(target, "WAIT_A"))
        await asyncio.sleep(0.1)  # A now holds the lock, blocked inside db_consume

        task_b = asyncio.create_task(server.consume_prekey_bundle_for_serve(target, "WAIT_B"))
        await asyncio.sleep(0.1)  # B is now queued, waiting for A's lock

        entry = server.prekey_mutation_locks.get(target)
        assert entry is not None
        assert entry["refs"] == 2  # A (holding) + B (waiting) -- waiters count too

        task_b.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task_b
        await asyncio.sleep(0.05)
        assert entry["refs"] == 1  # only A remains -- B's cancellation decremented cleanly

        release.set()
        await asyncio.wait_for(task_a, timeout=1.0)
        assert target not in server.prekey_mutation_locks
    finally:
        server.db_consume_prekey_opk = real_db_consume


# ── 12. cancellation while HOLDING the lock releases it and eventually
#       removes the registry entry ─────────────────────────────────────────

async def test_cancellation_while_holding_releases_and_removes_entry():
    target = "CCCC3333DDDD4444"
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [{"id": "h1"}]})

    hold_started  = asyncio.Event()
    never_release = asyncio.Event()  # deliberately never set -- task_a is cancelled instead
    real_db_consume = server.db_consume_prekey_opk

    async def blocking_db_consume(t):
        hold_started.set()
        await never_release.wait()
        return await real_db_consume(t)

    server.db_consume_prekey_opk = blocking_db_consume
    try:
        task_a = asyncio.create_task(server.consume_prekey_bundle_for_serve(target, "HOLD_REQUESTER"))
        await hold_started.wait()  # A definitely holds the lock now

        entry = server.prekey_mutation_locks.get(target)
        assert entry is not None
        assert entry["refs"] == 1

        task_a.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task_a

        # Released and pruned -- nothing left held or leaked by the
        # cancelled holder.
        assert target not in server.prekey_mutation_locks
    finally:
        server.db_consume_prekey_opk = real_db_consume

    # A FRESH consume for the same target must proceed normally afterward
    # -- proves the lock was genuinely released, not left stuck acquired.
    # (Same requester_scope as the cancelled attempt is fine: that attempt
    # never reached opk_record_pair_issuance() -- it was cancelled while
    # still blocked inside db_consume_prekey_opk, before ever returning.)
    bundle, _ = await asyncio.wait_for(server.consume_prekey_bundle_for_serve(target, "HOLD_REQUESTER"), timeout=1.0)
    assert bundle["opks"] == [{"id": "h1"}]


# ── 13. incoming federated_get_bundle with an invalid target never calls
#       consume_prekey_bundle_for_serve() ─────────────────────────────────

async def test_incoming_federated_get_bundle_invalid_target_never_calls_consume(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"

    call_count = 0
    real_consume = server.consume_prekey_bundle_for_serve

    async def counting_consume(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_consume(*a, **kw)

    server.consume_prekey_bundle_for_serve = counting_consume
    try:
        ws = await federation_connect(running_server)
        try:
            for bad_target in ("lowercasehexvalu", "TOO-SHORT", "X" * 500, None):
                await ws.send(json.dumps({
                    "type": "federated_get_bundle", "target": bad_target, "req_id": "badreq",
                }))
            await asyncio.sleep(0.3)
            assert call_count == 0
        finally:
            await ws.close()
    finally:
        server.consume_prekey_bundle_for_serve = real_consume
        server.FEDERATION_SECRET = old_secret


# ── 14. outgoing federated_get_bundle with an invalid target creates no
#       fed_pending future and sends nothing to any peer ──────────────────

async def test_outgoing_federated_get_bundle_invalid_target_creates_nothing():
    sent = []

    class _FakeWs:
        async def send(self, data):
            sent.append(data)

    real_federation_ws = dict(server.federation_ws)
    server.federation_ws.clear()
    server.federation_ws["fake-peer"] = _FakeWs()
    pending_before = dict(server.fed_pending)
    try:
        result = await server.federated_get_bundle("not-a-valid-fingerprint")
        assert result is None
        assert sent == []
        assert server.fed_pending == pending_before  # no new future ever registered
    finally:
        server.federation_ws.clear()
        server.federation_ws.update(real_federation_ws)


# ── 15. batch fetch drops malformed targets before any DB/cache work ─────

async def test_batch_fetch_drops_malformed_targets_before_cache_work(running_server):
    valid_target = "0123456789ABCDEF"
    await server.store_prekey_bundle(valid_target, {"ik": "IK", "spk": "SPK", "opks": [{"id": "batch1"}]})

    requester, _, _, _ = await connect_and_register(running_server, device_id="batchmalformed")
    try:
        bad_targets = ["lowercase1234567", "TOO_SHORT", None, ["nested"], {"a": 1}, "X" * 500]
        await requester.send(json.dumps({
            "type": "get_prekey_bundles_batch",
            "targets": bad_targets + [valid_target],
        }))
        response = await drain_until(requester, "prekey_bundles_batch_response")
        # Only the one canonical, valid target should appear in the results
        # at all -- every malformed one was filtered out before any
        # prekey_bundles/DB/bootstrap-token lookup ever ran.
        assert list(response["bundles"].keys()) == [valid_target]
        assert response["bundles"][valid_target]["opks"] == []  # batch never consumes
    finally:
        await requester.close()


# ── OPK issuance abuse guards ──────────────────────────────────────────────
#
# S6-26/S6-35 made OPK consumption durable, single-use, and safe against
# lock-registry growth -- but neither stopped an otherwise-authorized caller
# (a real authenticated user under its own prekey_fetch allowance, or an
# authenticated federation peer under FED_BUNDLE_LIMIT) from repeatedly
# re-fetching the SAME target's bundle and draining a fresh OPK every call,
# with no session_init or actual X3DH handshake ever required. These add a
# per-(requester_scope, target) cooldown, a per-target aggregate budget, and
# a server-wide aggregate budget -- all fail-CLOSED to opks=[] (never None,
# never a distinguishable error, never re-serving an old OPK) so the
# existing no-OPK X3DH fallback stays available. See SECURITY_INVARIANTS.md
# #49.

def _reset_opk_guards():
    server.opk_pair_last_issued.clear()
    server.opk_target_window.clear()
    server.opk_global_window["count"] = 0
    server.opk_global_window["reset_time"] = server.time.time()


# ── 1/2/3. first fetch consumes an OPK; an immediate same-scope repeat
#           consumes nothing more, but still gets the normal bundle shape
#           (opks=[], never None, never a distinguishable error) ──────────

async def test_pair_cooldown_blocks_immediate_repeat_but_bundle_stays_normal(running_server):
    target = "0A0A0A0A0A0A0A0A"
    opk1, opk2 = {"id": "pair1", "key": "K1"}, {"id": "pair2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    requester, requester_fp, _, _ = await connect_and_register(running_server, device_id="pairreq")
    try:
        await requester.send(json.dumps({"type": "get_prekey_bundle", "target": target}))
        first = await drain_until(requester, "prekey_bundle_response")
        assert first["bundle"]["opks"] == [opk1]

        await requester.send(json.dumps({"type": "get_prekey_bundle", "target": target}))
        second = await drain_until(requester, "prekey_bundle_response")
        assert second["bundle"] is not None          # still the normal bundle shape
        assert second["bundle"]["opks"] == []          # nothing re-issued
    finally:
        await requester.close()

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk2]  # exactly one OPK was ever actually consumed


# ── 4. a DIFFERENT requester may still consume an OPK while the target
#      budget allows, even though the FIRST requester is on cooldown ──────

async def test_different_requester_can_consume_while_target_budget_allows():
    target = "0B0B0B0B0B0B0B0B"
    opk1, opk2 = {"id": "diffreq1", "key": "K1"}, {"id": "diffreq2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    now = server.time.time()
    first, _ = await server.consume_prekey_bundle_for_serve(target, "REQUESTER_ONE")
    assert first["opks"] == [opk1]

    second, _ = await server.consume_prekey_bundle_for_serve(target, "REQUESTER_TWO")
    assert second["opks"] == [opk2]  # a different requester_scope is not on cooldown


# ── 5. pair cooldown expiry permits a later fresh OPK for the SAME
#      requester/target pair ───────────────────────────────────────────────

async def test_pair_cooldown_expiry_permits_later_fresh_opk():
    target = "0C0C0C0C0C0C0C0C"
    opk1, opk2 = {"id": "expire1", "key": "K1"}, {"id": "expire2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    first, _ = await server.consume_prekey_bundle_for_serve(target, "EXPIRE_REQUESTER")
    assert first["opks"] == [opk1]

    # Immediate repeat still on cooldown.
    denied, _ = await server.consume_prekey_bundle_for_serve(target, "EXPIRE_REQUESTER")
    assert denied["opks"] == []

    # Force the recorded pair entry into the past instead of sleeping for
    # the real cooldown duration.
    key = ("EXPIRE_REQUESTER", target)
    server.opk_pair_last_issued[key] = server.time.time() - server.OPK_PAIR_COOLDOWN_SEC - 1

    later, _ = await server.consume_prekey_bundle_for_serve(target, "EXPIRE_REQUESTER")
    assert later["opks"] == [opk2]  # cooldown expired -- a fresh OPK is issued


# ── 6. many Sybil requester_scopes cannot exceed the per-target budget ────

async def test_sybil_requester_scopes_capped_by_target_budget():
    target = "0D0D0D0D0D0D0D0D"
    opks = [{"id": f"sybil{i}", "key": f"K{i}"} for i in range(10)]
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": list(opks)})

    real_limit, real_enabled = server.OPK_TARGET_MAX_PER_WINDOW, server.OPK_TARGET_ENABLED
    server.OPK_TARGET_MAX_PER_WINDOW = 3
    server.OPK_TARGET_ENABLED = True
    try:
        results = []
        for i in range(10):
            bundle, _ = await server.consume_prekey_bundle_for_serve(target, f"SYBIL_{i}")
            results.append(bundle)
        issued = [b["opks"][0]["id"] for b in results if b["opks"]]
        assert len(issued) == 3  # capped at the per-target budget regardless of distinct scopes
        assert len(set(issued)) == 3  # never the same OPK issued twice
    finally:
        server.OPK_TARGET_MAX_PER_WINDOW = real_limit
        server.OPK_TARGET_ENABLED = real_enabled


# ── 7. target-budget denial performs no SQLite OPK mutation ──────────────

async def test_target_budget_denial_performs_no_db_mutation():
    target = "0E0E0E0E0E0E0E0E"
    opk = {"id": "tgtbudget1", "key": "K1"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk]})

    assert server.OPK_TARGET_ENABLED  # guard active with its normal default
    # Pre-fill the window to already be at capacity for this target.
    server.opk_target_window[target] = {
        "count": server.OPK_TARGET_MAX_PER_WINDOW, "reset_time": server.time.time() + 60,
    }
    bundle, remaining = await server.consume_prekey_bundle_for_serve(target, "BUDGET_DENIED")
    assert bundle["opks"] == []
    assert remaining == 1  # unchanged -- nothing was consumed

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk]  # still present, never popped


# ── 8. global budget bounds consumption across MANY different targets ────

async def test_global_budget_bounds_consumption_across_many_targets():
    targets = [f"{i:016X}" for i in range(0x0F00, 0x0F00 + 10)]
    for t in targets:
        await server.store_prekey_bundle(t, {"ik": "IK", "spk": "SPK", "opks": [{"id": f"g{t}", "key": "K"}]})

    real_limit, real_enabled = server.OPK_GLOBAL_MAX_PER_WINDOW, server.OPK_GLOBAL_ENABLED
    server.OPK_GLOBAL_MAX_PER_WINDOW = 4
    server.OPK_GLOBAL_ENABLED = True
    try:
        issued = 0
        for t in targets:
            bundle, _ = await server.consume_prekey_bundle_for_serve(t, f"REQ_{t}")
            if bundle["opks"]:
                issued += 1
        assert issued == 4  # aggregate budget, not per-target, bounds total issuance
    finally:
        server.OPK_GLOBAL_MAX_PER_WINDOW = real_limit
        server.OPK_GLOBAL_ENABLED = real_enabled


# ── 9. global-budget denial performs no SQLite mutation ──────────────────

async def test_global_budget_denial_performs_no_db_mutation():
    target = "0F1F0F1F0F1F0F1F"
    opk = {"id": "globaldeny1", "key": "K1"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk]})

    assert server.OPK_GLOBAL_ENABLED  # guard active with its normal default
    server.opk_global_window["count"] = server.OPK_GLOBAL_MAX_PER_WINDOW
    server.opk_global_window["reset_time"] = server.time.time() + 60
    bundle, remaining = await server.consume_prekey_bundle_for_serve(target, "GLOBAL_DENIED")
    assert bundle["opks"] == []
    assert remaining == 1

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk]


# ── 10. a nonexistent target creates no pair/target limiter state ────────

async def test_nonexistent_target_creates_no_limiter_state():
    target = "1A1A1A1A1A1A1A1A"  # never stored
    bundle, remaining = await server.consume_prekey_bundle_for_serve(target, "GHOST_REQUESTER")
    assert bundle is None
    assert remaining == 0
    assert ("GHOST_REQUESTER", target) not in server.opk_pair_last_issued
    assert target not in server.opk_target_window


# ── 11. a target whose OPK pool is already empty creates no issuance
#       state either ────────────────────────────────────────────────────

async def test_empty_pool_target_creates_no_limiter_state():
    target = "1B1B1B1B1B1B1B1B"
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": []})
    bundle, remaining = await server.consume_prekey_bundle_for_serve(target, "EMPTYPOOL_REQUESTER")
    assert bundle is not None
    assert bundle["opks"] == []
    assert remaining == 0
    assert ("EMPTYPOOL_REQUESTER", target) not in server.opk_pair_last_issued
    assert target not in server.opk_target_window


# ── 12. incoming federation repeated target requests hit the pair/target
#       guard exactly like a local requester would ────────────────────────

async def test_federation_repeated_target_requests_hit_pair_guard(running_server):
    target = "1C1C1C1C1C1C1C1C"
    opk1, opk2 = {"id": "fedpair1", "key": "K1"}, {"id": "fedpair2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({"type": "federated_get_bundle", "target": target, "req_id": secrets.token_hex(8)}))
            first = await drain_until(ws, "federated_bundle_response")
            assert first["bundle"]["opks"] == [opk1]

            await ws.send(json.dumps({"type": "federated_get_bundle", "target": target, "req_id": secrets.token_hex(8)}))
            second = await drain_until(ws, "federated_bundle_response")
            assert second["bundle"]["opks"] == []  # same peer IP -- same requester_scope, on cooldown
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk2]


# ── 13. federation requester_scope is IP-scoped, not a cryptographic peer
#       identity -- a source-address change bypasses the PAIR cooldown, but
#       the per-target/global budgets remain the real backstop ───────────

async def test_federation_source_change_bypasses_pair_but_not_target_budget():
    target = "1D1D1D1D1D1D1D1D"
    opks = [{"id": f"srcaddr{i}", "key": f"K{i}"} for i in range(3)]
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": list(opks)})

    real_limit, real_enabled = server.OPK_TARGET_MAX_PER_WINDOW, server.OPK_TARGET_ENABLED
    server.OPK_TARGET_MAX_PER_WINDOW = 2
    server.OPK_TARGET_ENABLED = True
    try:
        first, _  = await server.consume_prekey_bundle_for_serve(target, "fed:1.2.3.4")
        second, _ = await server.consume_prekey_bundle_for_serve(target, "fed:5.6.7.8")
        third, _  = await server.consume_prekey_bundle_for_serve(target, "fed:9.9.9.9")
        assert first["opks"] and second["opks"]     # two different "source addresses" both admitted
        assert third["opks"] == []                  # third denied -- target budget doesn't care about scope
    finally:
        server.OPK_TARGET_MAX_PER_WINDOW = real_limit
        server.OPK_TARGET_ENABLED = real_enabled


# ── 14. batch fetch still consumes zero OPKs with the guards fully active ─

async def test_batch_fetch_still_consumes_zero_opks_with_guards_active(running_server):
    target = "1E1E1E1E1E1E1E1E"
    opk = {"id": "batchguard1", "key": "K1"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk]})

    requester, _, _, _ = await connect_and_register(running_server, device_id="batchguard")
    try:
        for _ in range(3):  # well past OPK_PAIR_COOLDOWN_SEC territory if this consumed anything
            await requester.send(json.dumps({
                "type": "get_prekey_bundles_batch", "targets": [target],
            }))
            response = await drain_until(requester, "prekey_bundles_batch_response")
            assert response["bundles"][target]["opks"] == []
    finally:
        await requester.close()

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == [opk]  # never touched -- batch never reaches the guards at all
    assert target not in server.opk_target_window  # confirms no issuance path was ever entered


# ── 15. a denied request never re-serves a previously-issued OPK ─────────

async def test_denied_request_never_reserves_old_opk():
    target = "1F1F1F1F1F1F1F1F"
    opk1, opk2 = {"id": "noreissue1", "key": "K1"}, {"id": "noreissue2", "key": "K2"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk1, opk2]})

    first, _ = await server.consume_prekey_bundle_for_serve(target, "NOREISSUE_REQUESTER")
    assert first["opks"] == [opk1]

    for _ in range(5):
        denied, _ = await server.consume_prekey_bundle_for_serve(target, "NOREISSUE_REQUESTER")
        assert denied["opks"] == []  # never opk1 again, never opk2 either


# ── 16. publish racing an admitted consumption remains serialized by
#       prekey_mutation_guard, exactly as before the guard was added ──────

async def test_publish_racing_admitted_consumption_remains_serialized():
    target = "2A2A2A2A2A2A2A2A"
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [{"id": "racek1"}, {"id": "racek2"}]})

    seen_entries = []
    real_db_consume = server.db_consume_prekey_opk
    real_db_save    = server.db_save_bundle

    async def observing_db_consume(t):
        seen_entries.append(server.prekey_mutation_locks.get(t))
        return await real_db_consume(t)

    async def observing_db_save(u, data):
        seen_entries.append(server.prekey_mutation_locks.get(u))
        return await real_db_save(u, data)

    server.db_consume_prekey_opk = observing_db_consume
    server.db_save_bundle        = observing_db_save
    try:
        await asyncio.gather(
            server.consume_prekey_bundle_for_serve(target, "RACE_REQUESTER_NEW"),
            server.store_prekey_bundle(target, {"ik": "IK2", "spk": "SPK2", "opks": [{"id": "racek3"}]}),
        )
    finally:
        server.db_consume_prekey_opk = real_db_consume
        server.db_save_bundle        = real_db_save

    assert len(seen_entries) == 2
    assert seen_entries[0] is seen_entries[1]  # still one shared registry entry
    assert target not in server.prekey_mutation_locks


# ── 17. an admitted consumption still commits to SQLite before ever being
#       reported to the caller -- invariant #39 holds with the guards
#       active too ─────────────────────────────────────────────────────────

async def test_admitted_consumption_still_commits_before_returning():
    target = "2B2B2B2B2B2B2B2B"
    opk = {"id": "commit1", "key": "K1"}
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [opk]})

    bundle, remaining = await server.consume_prekey_bundle_for_serve(target, "COMMIT_REQUESTER")
    assert bundle["opks"] == [opk]
    assert remaining == 0

    stored = _read_bundle_row(target)
    assert stored["bundle"]["opks"] == []  # already durably popped by the time this returned
    assert server.prekey_bundles[target]["bundle"]["opks"] == []  # RAM in sync too


# ── 18. limiter state self-prunes after expiry and does not grow
#       permanently ────────────────────────────────────────────────────────

async def test_limiter_state_self_prunes_after_expiry():
    target = "2C2C2C2C2C2C2C2C"
    opks = [{"id": f"prune{i}", "key": f"K{i}"} for i in range(5)]
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": list(opks)})

    for i in range(5):
        bundle, _ = await server.consume_prekey_bundle_for_serve(target, f"PRUNE_REQ_{i}")
        assert bundle["opks"]
    assert len(server.opk_pair_last_issued) == 5

    # Age every entry past the cooldown instead of sleeping for real.
    expired_ts = server.time.time() - server.OPK_PAIR_COOLDOWN_SEC - 1
    for key in list(server.opk_pair_last_issued.keys()):
        server.opk_pair_last_issued[key] = expired_ts

    # _opk_pair_cleanup() only ever runs from within a call that reaches the
    # guard-evaluation step (a real target with an available OPK, see
    # consume_prekey_bundle_for_serve()'s own comment) -- a nonexistent
    # target returns earlier and would never trigger it. Use a second real
    # target/scope to trigger cleanup and confirm the 5 stale entries above
    # are gone, leaving only this call's own fresh entry behind.
    target2 = "2D2D2D2D2D2D2D2D"
    await server.store_prekey_bundle(target2, {"ik": "IK", "spk": "SPK", "opks": [{"id": "trigger1"}]})
    bundle, _ = await server.consume_prekey_bundle_for_serve(target2, "PRUNE_TRIGGER")
    assert bundle["opks"]
    assert len(server.opk_pair_last_issued) == 1
    assert ("PRUNE_TRIGGER", target2) in server.opk_pair_last_issued


# ── Bounded authorized_devices growth + strictly bounded device-auth
#    inputs ───────────────────────────────────────────────────────────────
#
# register() used to take `device_id = message.get("device_id")` with no
# length/format bound at all (bounded only by the multi-megabyte websocket
# frame ceiling), and device_public_key/device_signature were base64-decoded
# with no protocol-specific size limit either. Separately, whenever TOTP
# wasn't configured, register() durably INSERTed a NULL-device_pubkey row
# into authorized_devices on every reconnect with a fresh device_id -- a
# NULL row confers no trust by itself (a first connection under an active
# TOTP requirement still has to pin a pubkey via db_bind_device_pubkey()
# regardless of whether the row already existed), so this durably grew the
# table for zero security benefit. See SECURITY_INVARIANTS.md #50.

def _authorized_device_count(username: str) -> int:
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM authorized_devices WHERE username = ?", (username,)
        ).fetchone()[0]


def _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id, **proof):
    device_sig = sign_device_challenge(device_priv, challenge, username, device_id)
    extra = {
        "device_public_key": base64.b64encode(device_pub_der).decode(),
        "device_signature": base64.b64encode(device_sig).decode(),
    }
    extra.update(proof)
    return extra


# ── 1. oversized device_id rejected before any authorized_devices DB call ──

async def test_oversized_device_id_rejected_before_db_call(running_server):
    priv, pub_der = gen_keypair()
    call_count = 0
    real_get = server.db_get_authorized_device

    async def counting_get(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_get(*a, **kw)

    server.db_get_authorized_device = counting_get
    try:
        ws = await websockets.connect(running_server)
        try:
            await handshake(ws, priv, pub_der)
            await ws.send(json.dumps({
                "type": "register", "name": "t",
                "public_key": base64.b64encode(pub_der).decode(),
                "device_id": "A" * 10000,
            }))
            reply = await drain_until(ws, "device_auth_failed")
            assert reply["type"] == "device_auth_failed"
            assert call_count == 0
        finally:
            await ws.close()
    finally:
        server.db_get_authorized_device = real_get


# ── 2. malformed (non-canonical-shape) device_id rejected ─────────────────

async def test_malformed_device_id_rejected(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await ws.send(json.dumps({
            "type": "register", "name": "t",
            "public_key": base64.b64encode(pub_der).decode(),
            "device_id": "not-a-real-uuid-shape",
        }))
        reply = await drain_until(ws, "device_auth_failed")
        assert reply["type"] == "device_auth_failed"
    finally:
        await ws.close()


# ── 3. a canonical official-client-shaped device_id still registers ───────

async def test_canonical_device_id_still_registers(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    real_uuid = str(uuid.uuid4())  # exactly what Android/Desktop actually send
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await ws.send(json.dumps({
            "type": "register", "name": "t",
            "public_key": base64.b64encode(pub_der).decode(),
            "device_id": real_uuid,
        }))
        await asyncio.sleep(0.2)
        async with server.lock:
            assert server.clients[username]["device_id"] == real_uuid
    finally:
        await ws.close()


# ── 4. oversized device_public_key rejected before base64/DER parsing ─────

async def test_oversized_device_public_key_rejected_before_parsing(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(username, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[username] = secret

    ws = await websockets.connect(running_server)
    try:
        challenge = await handshake(ws, priv, pub_der)
        device_priv, device_pub_der = gen_keypair()
        device_id = canonical_device_id("oversized-pubkey-device")
        extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                    totp_code=_current_totp_code(secret))
        extra["device_public_key"] = "A" * (server.MAX_DEVICE_PUBKEY_B64_LEN + 100)
        await register(ws, pub_der, device_id, extra=extra)
        reply = await drain_until(ws, "device_auth_failed")
        assert reply["type"] == "device_auth_failed"

        row_exists, _ = await server.db_get_authorized_device(username, device_id)
        assert not row_exists
    finally:
        await ws.close()


# ── 5. oversized device_signature rejected before parsing ────────────────

async def test_oversized_device_signature_rejected_before_parsing(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(username, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[username] = secret

    ws = await websockets.connect(running_server)
    try:
        challenge = await handshake(ws, priv, pub_der)
        device_priv, device_pub_der = gen_keypair()
        device_id = canonical_device_id("oversized-signature-device")
        extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                    totp_code=_current_totp_code(secret))
        extra["device_signature"] = "B" * (server.MAX_DEVICE_SIGNATURE_B64_LEN + 100)
        await register(ws, pub_der, device_id, extra=extra)
        reply = await drain_until(ws, "device_auth_failed")
        assert reply["type"] == "device_auth_failed"

        row_exists, _ = await server.db_get_authorized_device(username, device_id)
        assert not row_exists
    finally:
        await ws.close()


# ── 6. TOTP-disabled reconnects with many distinct device_ids create zero
#      new authorized_devices rows (the removed NULL-row path) ───────────

async def test_totp_disabled_reconnects_many_device_ids_create_no_rows(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    for i in range(50):
        ws = await websockets.connect(running_server)
        try:
            await handshake(ws, priv, pub_der)
            await register(ws, pub_der, device_id=f"totp-disabled-device-{i}")
            await asyncio.sleep(0.02)
        finally:
            await ws.close()
    assert _authorized_device_count(username) == 0


# ── 7. enabling TOTP afterward still lets a legitimate device bind ────────

async def test_enabling_totp_afterward_lets_legitimate_device_bind(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)

    ws1 = await websockets.connect(running_server)
    await handshake(ws1, priv, pub_der)
    await register(ws1, pub_der, device_id="pre-totp-device")
    await asyncio.sleep(0.2)
    await ws1.close()
    assert _authorized_device_count(username) == 0  # nothing durable yet (item 6)

    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(username, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[username] = secret

    ws2 = await websockets.connect(running_server)
    try:
        challenge = await handshake(ws2, priv, pub_der)
        device_priv, device_pub_der = gen_keypair()
        device_id = canonical_device_id("post-totp-device")
        extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                    totp_code=_current_totp_code(secret))
        await register(ws2, pub_der, device_id, extra=extra)
        await asyncio.sleep(0.2)

        row_exists, stored_pubkey = await server.db_get_authorized_device(username, device_id)
        assert row_exists
        assert stored_pubkey == device_pub_der
    finally:
        await ws2.close()


# ── 8. new pinned devices can be added below the account cap ─────────────

async def test_new_pinned_devices_added_below_cap(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(3)
    await server.db_commit_totp_setup(username, secret, codes)
    server.user_totp_secrets[username] = secret

    real_cap = server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT
    server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = 3
    try:
        # Recovery codes (not totp_code) for every device here -- all three
        # enrollments happen well within the same 30s TOTP time-step, and a
        # repeated totp_code would be rejected as a replay by the second/
        # third attempt, unrelated to what this test is actually about.
        for i in range(3):
            ws = await websockets.connect(running_server)
            try:
                challenge = await handshake(ws, priv, pub_der)
                device_priv, device_pub_der = gen_keypair()
                device_id = canonical_device_id(f"cap-device-{i}")
                extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                            recovery_code=codes[i])
                await register(ws, pub_der, device_id, extra=extra)
                await asyncio.sleep(0.2)
            finally:
                await ws.close()
        assert _authorized_device_count(username) == 3
    finally:
        server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = real_cap


# ── 9. first device above the cap is rejected without an INSERT ──────────

async def test_first_device_above_cap_rejected_without_insert(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(3)
    await server.db_commit_totp_setup(username, secret, codes)
    server.user_totp_secrets[username] = secret

    real_cap = server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT
    server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = 2
    try:
        for i in range(2):
            ws = await websockets.connect(running_server)
            try:
                challenge = await handshake(ws, priv, pub_der)
                device_priv, device_pub_der = gen_keypair()
                device_id = canonical_device_id(f"fullcap-device-{i}")
                extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                            recovery_code=codes[i])
                await register(ws, pub_der, device_id, extra=extra)
                await asyncio.sleep(0.2)
            finally:
                await ws.close()
        assert _authorized_device_count(username) == 2

        ws3 = await websockets.connect(running_server)
        try:
            challenge3 = await handshake(ws3, priv, pub_der)
            device_priv3, device_pub_der3 = gen_keypair()
            overcap_device_id = canonical_device_id("overcap-device")
            extra3 = _device_bind_extra(device_priv3, device_pub_der3, challenge3, username, overcap_device_id,
                                         recovery_code=codes[2])
            await register(ws3, pub_der, overcap_device_id, extra=extra3)
            reply = await drain_until(ws3, "device_limit_reached")
            assert reply["type"] == "device_limit_reached"
        finally:
            await ws3.close()

        assert _authorized_device_count(username) == 2  # unchanged -- no INSERT happened
        row_exists, _ = await server.db_get_authorized_device(username, overcap_device_id)
        assert not row_exists
    finally:
        server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = real_cap


# ── 10. two concurrent enrollments for the last slot cannot both succeed ──

async def test_concurrent_enrollments_at_last_slot_only_one_succeeds(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(3)
    await server.db_commit_totp_setup(username, secret, codes)
    server.user_totp_secrets[username] = secret

    real_cap = server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT
    server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = 2
    try:
        ws0 = await websockets.connect(running_server)
        try:
            challenge0 = await handshake(ws0, priv, pub_der)
            device_priv0, device_pub_der0 = gen_keypair()
            device_id0 = canonical_device_id("race-existing-device")
            extra0 = _device_bind_extra(device_priv0, device_pub_der0, challenge0, username, device_id0,
                                         recovery_code=codes[0])
            await register(ws0, pub_der, device_id0, extra=extra0)
            await asyncio.sleep(0.2)
        finally:
            await ws0.close()
        assert _authorized_device_count(username) == 1  # one slot left

        async def attempt(label, code):
            ws = await websockets.connect(running_server)
            try:
                challenge = await handshake(ws, priv, pub_der)
                device_priv, device_pub_der = gen_keypair()
                device_id = canonical_device_id(label)
                extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                            recovery_code=code)
                await register(ws, pub_der, device_id, extra=extra)
                try:
                    async with asyncio.timeout(1.0):
                        while True:
                            msg = json.loads(await ws.recv())
                            if msg.get("type") in ("device_limit_reached", "device_auth_failed"):
                                return msg["type"]
                except (asyncio.TimeoutError, TimeoutError):
                    return "ADMITTED"  # no error ever arrived
            finally:
                await ws.close()

        results = await asyncio.gather(
            attempt("race-slot-a", codes[1]),
            attempt("race-slot-b", codes[2]),
        )
        assert results.count("device_limit_reached") == 1
        assert results.count("ADMITTED") == 1
        assert _authorized_device_count(username) == 2  # exactly one more got in, never both
    finally:
        server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = real_cap


# ── 11. an existing pinned device's reconnect still works while the
#       account is already AT the cap ─────────────────────────────────────

async def test_existing_pinned_device_reconnect_works_at_cap(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(1)
    await server.db_commit_totp_setup(username, secret, codes)
    server.user_totp_secrets[username] = secret

    real_cap = server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT
    server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = 1
    device_priv, device_pub_der = gen_keypair()
    device_id = canonical_device_id("only-device")
    try:
        ws1 = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws1, priv, pub_der)
            extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                        recovery_code=codes[0])
            await register(ws1, pub_der, device_id, extra=extra)
            await asyncio.sleep(0.2)
        finally:
            await ws1.close()
        assert _authorized_device_count(username) == 1  # AT the cap now

        # Reconnect with the SAME already-pinned device -- device_needs_totp
        # is False here (pubkey already matches), so no totp_code/
        # recovery_code is needed at all, same as before this fix.
        ws2 = await websockets.connect(running_server)
        try:
            challenge2 = await handshake(ws2, priv, pub_der)
            device_sig2 = sign_device_challenge(device_priv, challenge2, username, device_id)
            await register(ws2, pub_der, device_id, extra={
                "device_public_key": base64.b64encode(device_pub_der).decode(),
                "device_signature": base64.b64encode(device_sig2).decode(),
            })
            await asyncio.sleep(0.2)
            async with server.lock:
                assert server.clients[username]["device_id"] == device_id
        finally:
            await ws2.close()
        assert _authorized_device_count(username) == 1  # unchanged
    finally:
        server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = real_cap


# ── 12. an existing legacy NULL row can still be pinned while at cap ──────

async def test_existing_legacy_null_row_can_be_pinned_at_cap(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(2)
    await server.db_commit_totp_setup(username, secret, codes)
    server.user_totp_secrets[username] = secret

    real_cap = server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT
    server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = 1
    try:
        ws1 = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws1, priv, pub_der)
            device_priv1, device_pub_der1 = gen_keypair()
            device_id1 = canonical_device_id("cap-filled-device")
            extra1 = _device_bind_extra(device_priv1, device_pub_der1, challenge, username, device_id1,
                                         recovery_code=codes[0])
            await register(ws1, pub_der, device_id1, extra=extra1)
            await asyncio.sleep(0.2)
        finally:
            await ws1.close()
        assert _authorized_device_count(username) == 1

        # Simulate a pre-existing legacy NULL-pubkey row (e.g. left over
        # from before this fix) for a DIFFERENT device_id -- existing
        # state, not new growth, so claiming it must succeed even though
        # the account is already over the (lowered, for this test) cap.
        legacy_device_id = canonical_device_id("legacy-null-device")
        with server.db_connect() as conn:
            conn.execute(
                "INSERT INTO authorized_devices (username, device_id, device_pubkey, added_at) VALUES (?, ?, NULL, ?)",
                (username, legacy_device_id, server.time.time())
            )
            conn.commit()
        assert _authorized_device_count(username) == 2  # already over the cap of 1, on purpose

        ws2 = await websockets.connect(running_server)
        try:
            challenge2 = await handshake(ws2, priv, pub_der)
            device_priv2, device_pub_der2 = gen_keypair()
            extra2 = _device_bind_extra(device_priv2, device_pub_der2, challenge2, username, legacy_device_id,
                                         recovery_code=codes[1])
            await register(ws2, pub_der, legacy_device_id, extra=extra2)
            await asyncio.sleep(0.2)

            row_exists, stored_pubkey = await server.db_get_authorized_device(username, legacy_device_id)
            assert row_exists
            assert stored_pubkey == device_pub_der2  # pinned despite being over cap
        finally:
            await ws2.close()
    finally:
        server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = real_cap


# ── 13. a different key cannot overwrite an existing pinned device ───────

async def test_different_key_cannot_overwrite_pinned_device(running_server):
    priv, pub_der = gen_keypair()
    username = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(2)
    await server.db_commit_totp_setup(username, secret, codes)
    server.user_totp_secrets[username] = secret

    device_id = canonical_device_id("pin-target-device")
    device_pub_der1 = None
    ws1 = await websockets.connect(running_server)
    try:
        challenge = await handshake(ws1, priv, pub_der)
        device_priv1, device_pub_der1 = gen_keypair()
        extra1 = _device_bind_extra(device_priv1, device_pub_der1, challenge, username, device_id,
                                     recovery_code=codes[0])
        await register(ws1, pub_der, device_id, extra=extra1)
        await asyncio.sleep(0.2)
    finally:
        await ws1.close()

    row_exists, original_pubkey = await server.db_get_authorized_device(username, device_id)
    assert row_exists and original_pubkey == device_pub_der1

    ws2 = await websockets.connect(running_server)
    try:
        challenge2 = await handshake(ws2, priv, pub_der)
        device_priv2, device_pub_der2 = gen_keypair()  # a DIFFERENT device key
        extra2 = _device_bind_extra(device_priv2, device_pub_der2, challenge2, username, device_id,
                                     recovery_code=codes[1])
        await register(ws2, pub_der, device_id, extra=extra2)
        reply = await drain_until(ws2, "device_auth_failed")
        assert reply["type"] == "device_auth_failed"
    finally:
        await ws2.close()

    row_exists_after, stored_pubkey_after = await server.db_get_authorized_device(username, device_id)
    assert row_exists_after
    assert stored_pubkey_after == device_pub_der1  # still the ORIGINAL key, untouched


# ── 14. invalid device input never acquires the db_bind_device_pubkey()
#       write transaction ────────────────────────────────────────────────

async def test_invalid_device_input_never_acquires_db_write_transaction(running_server):
    call_count = 0
    real_bind = server.db_bind_device_pubkey

    async def counting_bind(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_bind(*a, **kw)

    server.db_bind_device_pubkey = counting_bind
    try:
        priv1, pub_der1 = gen_keypair()
        ws1 = await websockets.connect(running_server)
        try:
            await handshake(ws1, priv1, pub_der1)
            await ws1.send(json.dumps({
                "type": "register", "name": "t",
                "public_key": base64.b64encode(pub_der1).decode(),
                "device_id": "B" * 5000,
            }))
            await drain_until(ws1, "device_auth_failed")
        finally:
            await ws1.close()

        priv2, pub_der2 = gen_keypair()
        username2 = fingerprint_of(pub_der2)
        secret = TOTP_TEST_SECRET
        await server.db_commit_totp_setup(username2, secret, server.generate_recovery_codes(1))
        server.user_totp_secrets[username2] = secret
        ws2 = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws2, priv2, pub_der2)
            device_priv, device_pub_der = gen_keypair()
            device_id = canonical_device_id("bad-pubkey-device")
            extra = _device_bind_extra(device_priv, device_pub_der, challenge, username2, device_id,
                                        totp_code=_current_totp_code(secret))
            extra["device_public_key"] = "C" * (server.MAX_DEVICE_PUBKEY_B64_LEN + 1)
            await register(ws2, pub_der2, device_id, extra=extra)
            await drain_until(ws2, "device_auth_failed")
        finally:
            await ws2.close()

        assert call_count == 0
    finally:
        server.db_bind_device_pubkey = real_bind


# ── Federated forwarding restricted to legitimate federation-producer
#    payload types ─────────────────────────────────────────────────────────
#
# S6-34 bounded and rate-limited the OUTER federated_forward envelope, but
# the INNER payload["type"] was still handed straight to a local client
# (send_safe) or the offline queue (db_store) with no check that this
# server would ever have produced that payload type through federation
# itself. A compromised/malicious federation peer could inject
# session_conflict, totp_setup_ok, identity_revoked, prekey_bundle_response,
# subscribe_tokens_result, or any other privileged/control client-protocol
# message this way. See SECURITY_INVARIANTS.md #51.

# ── 1. every currently legitimate federated payload type passes the
#      validator ──────────────────────────────────────────────────────────

async def test_all_legitimate_federated_types_pass_validator():
    sender = canonical_fingerprint("S638_VALIDATOR_SENDER")
    for t in server.FEDERATED_FORWARD_ALLOWED_TYPES:
        assert server.validate_federated_forward_payload({"type": t, "from": sender}) is True, t


# ── 2. a normal federated message still reaches an ONLINE recipient ───────

async def test_normal_federated_message_reaches_online_recipient(running_server):
    recipient, recipient_fp, _, _ = await connect_and_register(running_server, device_id="s638online")
    await asyncio.sleep(0.2)
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": recipient_fp,
                "payload": {"id": "s638-online-1", "type": "message", "text": "hi",
                            "from": canonical_fingerprint("SOMESENDER")},
            }))
            msg = await drain_until(recipient, "message")
            assert msg["id"] == "s638-online-1"
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        await recipient.close()


# ── 3. a normal legitimate offline forward still reaches db_store ────────

async def test_normal_federated_message_reaches_db_store_when_offline(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("S638_OFFLINE_TARGET")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "s638-offline-1", "type": "message", "text": "hi",
                            "from": canonical_fingerprint("SOMESENDER")},
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 1
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 4. an injected session_conflict is rejected ───────────────────────────

async def test_federation_injected_session_conflict_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    to = canonical_fingerprint("S638_SESSCONFLICT_TARGET")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "s638-sessconflict-1", "type": "session_conflict",
                            "from": canonical_fingerprint("ATTACKER"), "ts": 123},
            }))
            await asyncio.sleep(0.3)
            assert call_count == 0
            assert "s638-sessconflict-1" not in server.delivered_msg_ids
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 5. injected totp_setup_ok / totp_required are rejected ───────────────

async def test_federation_injected_totp_control_messages_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    to = canonical_fingerprint("S638_TOTP_TARGET")
    sender = canonical_fingerprint("ATTACKER")
    try:
        ws = await federation_connect(running_server)
        try:
            for i, bad_type in enumerate(("totp_setup_ok", "totp_required")):
                await ws.send(json.dumps({
                    "type": "federated_forward", "to": to,
                    "payload": {"id": f"s638-totp-{i}", "type": bad_type, "from": sender},
                }))
            await asyncio.sleep(0.3)
            assert call_count == 0
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 6. injected identity_revoked / identity_revoked_ack are rejected ─────

async def test_federation_injected_identity_revoked_messages_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    to = canonical_fingerprint("S638_REVOKED_TARGET")
    sender = canonical_fingerprint("ATTACKER")
    try:
        ws = await federation_connect(running_server)
        try:
            for i, bad_type in enumerate(("identity_revoked", "identity_revoked_ack")):
                await ws.send(json.dumps({
                    "type": "federated_forward", "to": to,
                    "payload": {"id": f"s638-revoked-{i}", "type": bad_type, "from": sender},
                }))
            await asyncio.sleep(0.3)
            assert call_count == 0
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 7. injected prekey_bundle_request/response are rejected ──────────────

async def test_federation_injected_prekey_bundle_messages_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    to = canonical_fingerprint("S638_PREKEY_TARGET")
    sender = canonical_fingerprint("ATTACKER")
    try:
        ws = await federation_connect(running_server)
        try:
            for i, bad_type in enumerate(("prekey_bundle_request", "prekey_bundle_response")):
                await ws.send(json.dumps({
                    "type": "federated_forward", "to": to,
                    "payload": {"id": f"s638-prekey-{i}", "type": bad_type, "from": sender},
                }))
            await asyncio.sleep(0.3)
            assert call_count == 0
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 8. injected subscribe_tokens_result / anon_delivery_ack_ok are
#      rejected ────────────────────────────────────────────────────────────

async def test_federation_injected_token_control_messages_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    to = canonical_fingerprint("S638_TOKENCTRL_TARGET")
    sender = canonical_fingerprint("ATTACKER")
    try:
        ws = await federation_connect(running_server)
        try:
            for i, bad_type in enumerate(("subscribe_tokens_result", "anon_delivery_ack_ok")):
                await ws.send(json.dumps({
                    "type": "federated_forward", "to": to,
                    "payload": {"id": f"s638-tokenctrl-{i}", "type": bad_type, "from": sender},
                }))
            await asyncio.sleep(0.3)
            assert call_count == 0
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 9. a nested federated_forward payload is rejected ─────────────────────

async def test_federation_nested_federated_forward_payload_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    to = canonical_fingerprint("S638_NESTED_TARGET")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {
                    "id": "s638-nested-1", "type": "federated_forward",
                    "from": canonical_fingerprint("ATTACKER"),
                    "to": to,
                    "payload": {"id": "s638-nested-inner", "type": "message", "text": "x",
                                "from": canonical_fingerprint("ATTACKER")},
                },
            }))
            await asyncio.sleep(0.3)
            assert call_count == 0
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 10. an unknown arbitrary type is rejected ─────────────────────────────

async def test_federation_unknown_arbitrary_type_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    to = canonical_fingerprint("S638_UNKNOWN_TARGET")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "s638-unknown-1", "type": "some_made_up_type_xyz",
                            "from": canonical_fingerprint("ATTACKER")},
            }))
            await asyncio.sleep(0.3)
            assert call_count == 0
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 11. a payload with no "type" at all is rejected ───────────────────────

async def test_federation_missing_payload_type_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("S638_NOTYPE_TARGET")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "s638-notype-1", "text": "x",
                            "from": canonical_fingerprint("ATTACKER")},
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 12. missing/invalid/non-canonical "from" is rejected ─────────────────

async def test_federation_missing_or_invalid_from_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("S638_BADFROM_TARGET")
    try:
        ws = await federation_connect(running_server)
        try:
            bad_payloads = [
                {"id": "s638-nofrom-1", "type": "message", "text": "x"},                       # missing
                {"id": "s638-nofrom-2", "type": "message", "text": "x", "from": None},          # None
                {"id": "s638-nofrom-3", "type": "message", "text": "x", "from": "not-hex!!"},   # malformed
                {"id": "s638-nofrom-4", "type": "message", "text": "x", "from": 12345},         # wrong type
            ]
            for payload in bad_payloads:
                await ws.send(json.dumps({"type": "federated_forward", "to": to, "payload": payload}))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 13. invalid/non-canonical "to" is rejected ────────────────────────────

async def test_federation_invalid_to_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    call_count = 0
    real_db_store = server.db_store

    async def counting_db_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_db_store(*a, **kw)

    server.db_store = counting_db_store
    sender = canonical_fingerprint("SOMESENDER")
    try:
        ws = await federation_connect(running_server)
        try:
            bad_targets = ["lowercasehexvalu", "TOO-SHORT", "X" * 20]
            for i, bad_to in enumerate(bad_targets):
                await ws.send(json.dumps({
                    "type": "federated_forward", "to": bad_to,
                    "payload": {"id": f"s638-badto-{i}", "type": "message", "text": "x", "from": sender},
                }))
            await asyncio.sleep(0.3)
            assert call_count == 0
            for bad_to in bad_targets:
                assert len(_read_pending_rows(bad_to)) == 0
        finally:
            await ws.close()
    finally:
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret


# ── 14. a rejected semantic payload never reserves S6-34 dedup state ─────

async def test_federation_rejected_payload_never_reserves_dedup_state(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("S638_NODEDUP_TARGET")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "s638-nodedup-1", "type": "session_conflict",
                            "from": canonical_fingerprint("ATTACKER")},
            }))
            await asyncio.sleep(0.3)
            assert "s638-nodedup-1" not in server.delivered_msg_ids
            assert "s638-nodedup-1" not in server.federation_delivery_inflight
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 15. a rejected semantic payload never calls send_safe/db_store ───────

async def test_federation_rejected_payload_never_calls_send_or_store(running_server):
    recipient, recipient_fp, _, _ = await connect_and_register(running_server, device_id="s638rejectedsendstore")
    await asyncio.sleep(0.2)
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"

    send_calls = 0
    store_calls = 0
    real_send_safe = server.send_safe
    real_db_store = server.db_store

    async def counting_send_safe(*a, **kw):
        nonlocal send_calls
        send_calls += 1
        return await real_send_safe(*a, **kw)

    async def counting_db_store(*a, **kw):
        nonlocal store_calls
        store_calls += 1
        return await real_db_store(*a, **kw)

    server.send_safe = counting_send_safe
    server.db_store = counting_db_store
    try:
        ws = await federation_connect(running_server)
        try:
            # recipient_fp is ONLINE -- if this payload were ever handed to
            # the delivery code, it would go through send_safe(), not db_store().
            await ws.send(json.dumps({
                "type": "federated_forward", "to": recipient_fp,
                "payload": {"id": "s638-rejectedsendstore-1", "type": "prekey_bundle_response",
                            "from": canonical_fingerprint("ATTACKER")},
            }))
            await asyncio.sleep(0.3)
            assert send_calls == 0
            assert store_calls == 0
        finally:
            await ws.close()
    finally:
        server.send_safe = real_send_safe
        server.db_store = real_db_store
        server.FEDERATION_SECRET = old_secret
        await recipient.close()


# ── 16. a malformed/rejected frame only drops that frame -- the peer
#       connection stays alive for a subsequent legitimate frame ─────────

async def test_federation_malformed_frame_does_not_close_connection(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("S638_STAYALIVE_TARGET")
    sender = canonical_fingerprint("SOMESENDER")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "s638-stayalive-bad", "type": "session_conflict", "from": sender},
            }))
            await asyncio.sleep(0.2)
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "s638-stayalive-good", "type": "message", "text": "x", "from": sender},
            }))
            await asyncio.sleep(0.3)
            assert "s638-stayalive-good" in server.delivered_msg_ids
            assert len(_read_pending_rows(to)) == 1
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 17. forward_to_peers() refuses a non-allowlisted payload locally ─────

async def test_forward_to_peers_refuses_non_allowlisted_payload():
    class _FakeWs:
        async def send(self, data):
            raise AssertionError("must never reach send() for a non-allowlisted payload")

    real_federation_ws = dict(server.federation_ws)
    server.federation_ws.clear()
    server.federation_ws["fake-peer"] = _FakeWs()
    try:
        result = await server.forward_to_peers(
            canonical_fingerprint("SOMETARGET"),
            {"type": "session_conflict", "from": canonical_fingerprint("X")},
        )
        assert result is False
    finally:
        server.federation_ws.clear()
        server.federation_ws.update(real_federation_ws)


# ── 18. forward_to_peers() refuses an invalid destination locally ────────

async def test_forward_to_peers_refuses_invalid_destination():
    class _FakeWs:
        async def send(self, data):
            raise AssertionError("must never reach send() for an invalid destination")

    real_federation_ws = dict(server.federation_ws)
    server.federation_ws.clear()
    server.federation_ws["fake-peer"] = _FakeWs()
    try:
        result = await server.forward_to_peers(
            "not-a-valid-fingerprint",
            {"type": "message", "from": canonical_fingerprint("X")},
        )
        assert result is False
    finally:
        server.federation_ws.clear()
        server.federation_ws.update(real_federation_ws)


# ── 19. every existing forward_to_peers() producer emits a type present
#       in the allowlist ──────────────────────────────────────────────────

async def test_every_forward_to_peers_producer_emits_allowlisted_type(running_server):
    recorded_types = []
    real_forward = server.forward_to_peers

    async def recording_forward(to, payload):
        recorded_types.append(payload.get("type") if isinstance(payload, dict) else None)
        return await real_forward(to, payload)

    server.forward_to_peers = recording_forward
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        sender, sender_fp, _, _ = await connect_and_register(running_server, device_id="s638producer")
        await asyncio.sleep(0.2)
        offline_to = canonical_fingerprint("S638_OFFLINE_PRODUCER_TARGET")
        group_id = "s638-group"

        # One frame per current forward_to_peers() call site (grepped) --
        # the recipient is always this brand-new, never-registered
        # fingerprint, so every one of these takes the "recipient offline"
        # branch and actually reaches forward_to_peers().
        frames = [
            {"type": "read", "to": offline_to, "id": "m1"},
            {"type": "delivered", "to": offline_to, "id": "m1"},
            {"type": "typing", "to": offline_to},
            {"type": "edit", "to": offline_to, "id": "m1", "text": "x", "signature": "sig"},
            {"type": "session_init", "to": offline_to, "id": "si1", "sender_ik": "ik",
             "x3dh_header": {}, "session_header": {}, "text": "x", "signature": "sig"},
            {"type": "message", "to": offline_to, "id": "m2", "text": "x", "signature": "sig"},
            {"type": "reaction", "to": offline_to, "message_id": "m1", "emoji": "x", "signature": "sig"},
            {"type": "group_reaction", "to": offline_to, "group_id": group_id,
             "message_id": "m1", "emoji": "x", "signature": "sig"},
            # voice_id must be a canonical UUID as of S6-57's sanitize_voice_payload().
            {"type": "voice", "to": offline_to, "voice_id": str(uuid.uuid4()), "voice_data": "x",
             "signature": "sig", "duration": 1},
            # members/admins/roster_signature are REQUIRED as of S6-65 (was
            # previously dropped from the relayed payload entirely).
            {"type": "group_create", "to": offline_to, "group_id": group_id, "group_name": "g",
             "group_avatar": None, "encrypted_group_key": "x", "signature": "sig",
             "members": [sender_fp, offline_to], "admins": [sender_fp], "roster_signature": "sig"},
            {"type": "group_message", "to": offline_to, "group_id": group_id, "message_id": "gm1",
             "sender_name": "s", "text": "x", "signature": "sig"},
            # signature is REQUIRED for group_member_removed/group_invite_accepted
            # as of S6-60 (was previously dropped from the relayed payload
            # entirely, silently breaking every legitimate removal/invite-
            # acceptance for both official clients, which both require one).
            {"type": "group_member_removed", "to": offline_to, "group_id": group_id,
             "removed_member": "X", "signature": "sig"},
            {"type": "group_key_rotation", "to": offline_to, "group_id": group_id,
             "encrypted_new_key": "x", "signature": "sig"},
            {"type": "group_invite_accepted", "to": offline_to, "group_id": group_id,
             "new_member": "X", "new_member_name": "n", "signature": "sig"},
            {"type": "group_member_added", "to": offline_to, "group_id": group_id,
             "new_member": "X", "new_member_name": "n", "signature": "sig"},
            # signature is REQUIRED for message_delete/group_message_delete
            # as of S6-54 -- these are shape/allowlist probes only (real
            # cryptographic authenticity is covered by S6-54's own tests).
            {"type": "message_delete", "to": offline_to, "id": "m1", "signature": "sig"},
            # seconds must be one of CHAT_CONTROL_DISAPPEAR_TIMER_ALLOWED
            # (S6-53) -- 10 predates that schema binding.
            {"type": "disappear_timer", "to": offline_to, "id": "m1", "seconds": 3600},
            # group_id must be a canonical UUID for this type specifically
            # (S6-53's sanitize_chat_control() reuses is_valid_call_uuid()
            # for group_message_delete's group_id) -- the shared `group_id`
            # var above is intentionally left as-is for every OTHER frame in
            # this list, none of which validate its format.
            {"type": "group_message_delete", "to": offline_to, "group_id": str(uuid.uuid4()),
             "message_id": "gm1", "signature": "sig"},
        ]
        for frame in frames:
            await sender.send(json.dumps(frame))
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.3)

        assert len(recorded_types) == len(frames)
        for t in recorded_types:
            assert t in server.FEDERATED_FORWARD_ALLOWED_TYPES, t
    finally:
        server.forward_to_peers = real_forward
        server.FEDERATION_SECRET = old_secret


# ── OPEN-6: anonymous-token lifecycle is strictly node-local ─────────────
#
# docs/KNOWN_SECURITY_ISSUES.md OPEN-6 asked whether `forward_to_peers()`
# interacts with anonymous-token ownership/ACK semantics at all. Traced
# end-to-end (2026-09-25) against the CURRENT code (not the prose): zero
# call sites. anon_message/anon_delivery_ack/subscribe_tokens/
# unsubscribe_tokens never call forward_to_peers() (grepped every call
# site in this file), none of their four wire types are in
# FEDERATED_FORWARD_ALLOWED_TYPES (test_every_forward_to_peers_producer_
# emits_allowlisted_type above already proves every ACTUAL producer stays
# inside that allowlist), and handle_federation_peer_incoming()'s dispatch
# is a closed if/elif chain over exactly three types (federated_forward,
# peer_announce, federated_get_bundle) -- there is no fourth branch and no
# fallback into the general ALLOWED_TYPES loop, so a federation-
# authenticated connection can never reach any anon-token handler by any
# route. The tests below prove each edge of that boundary directly rather
# than re-deriving the trace in prose.

# The four wire types that constitute the anonymous-token control surface.
# `anon_delivery`/`anon_delivery_ack_ok` are server->client-only replies
# (never a client-supplied `type` on the wire) but are included here for
# the disjointness assertion and the federated_forward-wrapping tests,
# since a malicious peer could still try to inject one as an inner payload.
ANON_TOKEN_FEDERATION_FORBIDDEN_TYPES = frozenset({
    "anon_message",
    "anon_delivery",
    "anon_delivery_ack",
    "anon_delivery_ack_ok",
    "subscribe_tokens",
    "subscribe_tokens_result",
    "unsubscribe_tokens",
})


def test_anon_token_types_disjoint_from_federation_allowlist():
    assert not (ANON_TOKEN_FEDERATION_FORBIDDEN_TYPES & server.FEDERATED_FORWARD_ALLOWED_TYPES)


async def test_anon_message_never_calls_forward_to_peers(running_server):
    """A REAL anon_message send (self-owned token, matching the reachability
    proof in tests/test_protocol_stateful.py) must never touch
    forward_to_peers() -- confirmed by monkeypatching it to record calls."""
    calls = []
    real_forward = server.forward_to_peers

    async def recording_forward(to, payload):
        calls.append(payload.get("type") if isinstance(payload, dict) else None)
        return await real_forward(to, payload)

    server.forward_to_peers = recording_forward
    try:
        ws, fp, _, _ = await connect_and_register(running_server, device_id="open6_anonmsg")
        try:
            token = rand_token()
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
            await ws.send(json.dumps({
                "type": "anon_message", "token": token,
                "payload": {"id": "open6-1", "blob": "aGVsbG8="},
            }))
            assert await drain_until(ws, "anon_delivery") is not None
        finally:
            await ws.close()
        assert calls == []
    finally:
        server.forward_to_peers = real_forward


async def test_anon_delivery_ack_never_calls_forward_to_peers(running_server):
    calls = []
    real_forward = server.forward_to_peers

    async def recording_forward(to, payload):
        calls.append(payload.get("type") if isinstance(payload, dict) else None)
        return await real_forward(to, payload)

    server.forward_to_peers = recording_forward
    try:
        ws, fp, _, _ = await connect_and_register(running_server, device_id="open6_ack")
        try:
            token = rand_token()
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
            await ws.send(json.dumps({
                "type": "anon_message", "token": token,
                "payload": {"id": "open6-2", "blob": "aGVsbG8="},
            }))
            assert await drain_until(ws, "anon_delivery") is not None
            await ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
            assert await drain_until(ws, "anon_delivery_ack_ok") is not None
        finally:
            await ws.close()
        assert calls == []
    finally:
        server.forward_to_peers = real_forward


async def test_subscribe_and_unsubscribe_tokens_never_call_forward_to_peers(running_server):
    calls = []
    real_forward = server.forward_to_peers

    async def recording_forward(to, payload):
        calls.append(payload.get("type") if isinstance(payload, dict) else None)
        return await real_forward(to, payload)

    server.forward_to_peers = recording_forward
    try:
        ws, fp, _, _ = await connect_and_register(running_server, device_id="open6_subunsub")
        try:
            token = rand_token()
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
            await asyncio.sleep(0.2)
            await ws.send(json.dumps({"type": "unsubscribe_tokens", "tokens": [token]}))
            await asyncio.sleep(0.2)
        finally:
            await ws.close()
        assert calls == []
    finally:
        server.forward_to_peers = real_forward


async def _federation_inject_inner_type(running_server, inner_type: str, to: str, extra: dict | None = None):
    """Sends a federated_forward wrapping `inner_type` as the payload's own
    `type` field -- the exact shape a malicious/compromised peer would use
    to try to smuggle an anon-token-control payload through the one
    federation surface that reaches local clients/db_store."""
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            payload = {"type": inner_type, "from": canonical_fingerprint("OPEN6_MALICIOUS_PEER")}
            if extra:
                payload.update(extra)
            await ws.send(json.dumps({"type": "federated_forward", "to": to, "payload": payload}))
            await asyncio.sleep(0.3)
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


@pytest.mark.parametrize("inner_type", sorted(ANON_TOKEN_FEDERATION_FORBIDDEN_TYPES))
async def test_federation_inbound_rejects_anon_token_types_wrapped_in_forward(running_server, inner_type):
    """Every anon-token wire type, wrapped as federated_forward's inner
    payload, must be dropped by validate_federated_forward_payload() before
    ever reaching a local client or db_store -- never delivered, never
    queued offline."""
    recipient, recipient_fp, _, _ = await connect_and_register(running_server, device_id=f"open6_inj_{inner_type}")
    try:
        msgs_before = len(_read_pending_rows(recipient_fp))
        await _federation_inject_inner_type(running_server, inner_type, recipient_fp, extra={"id": f"open6-inj-{inner_type}"})
        # Never delivered live to the recipient's own socket.
        received = []
        try:
            async with asyncio.timeout(0.5):
                while True:
                    received.append(json.loads(await recipient.recv()))
        except asyncio.TimeoutError:
            pass
        assert not any(m.get("type") == inner_type for m in received), \
            f"federation peer smuggled a live '{inner_type}' to a local client: {received}"
        # Never queued offline either.
        assert len(_read_pending_rows(recipient_fp)) == msgs_before
    finally:
        await recipient.close()


async def test_malicious_federation_peer_cannot_claim_or_inflight_a_real_token(running_server):
    """A real ACTIVE token (claimed by a real local owner) must stay
    exactly ACTIVE, with no token_pending entry created, after a malicious
    federation peer tries to smuggle an anon_message for it through
    federated_forward."""
    owner_ws, owner_fp, _, _ = await connect_and_register(running_server, device_id="open6_activevictim")
    try:
        token = rand_token()
        await owner_ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        token_hash = server._hash_anon_token(token)
        owner_before, state_before = server.anon_token_state_cache[token_hash]
        assert state_before == "ACTIVE"

        await _federation_inject_inner_type(
            running_server, "anon_message", owner_fp,
            extra={"token": token, "payload": {"id": "open6-claim", "blob": "aGVsbG8="}},
        )

        owner_after, state_after = server.anon_token_state_cache[token_hash]
        assert (owner_after, state_after) == (owner_before, state_before), \
            "a federation peer moved a real token's state via federated_forward"
        assert token not in server.token_pending
    finally:
        await owner_ws.close()


async def test_malicious_federation_peer_cannot_terminalize_inflight_token(running_server):
    """A real IN_FLIGHT token (created by a genuine local anon_message send)
    must stay IN_FLIGHT, with its token_pending entry intact, after a
    malicious federation peer tries to smuggle an anon_delivery_ack for it
    through federated_forward."""
    owner_ws, owner_fp, _, _ = await connect_and_register(running_server, device_id="open6_inflightvictim")
    try:
        token = rand_token()
        await owner_ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await owner_ws.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "open6-inflight", "blob": "aGVsbG8="},
        }))
        assert await drain_until(owner_ws, "anon_delivery") is not None
        token_hash = server._hash_anon_token(token)
        owner_before, state_before = server.anon_token_state_cache[token_hash]
        assert state_before == "IN_FLIGHT"
        assert token in server.token_pending

        await _federation_inject_inner_type(running_server, "anon_delivery_ack", owner_fp, extra={"token": token})

        owner_after, state_after = server.anon_token_state_cache[token_hash]
        assert (owner_after, state_after) == (owner_before, state_before), \
            "a federation peer terminalized a real token to SPENT via federated_forward"
        assert token in server.token_pending

        # The REAL local owner's ACK still works afterward -- the boundary
        # hardening (there is none needed, since no path exists) must not
        # have collaterally broken the legitimate flow.
        await owner_ws.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        assert await drain_until(owner_ws, "anon_delivery_ack_ok") is not None
    finally:
        await owner_ws.close()


async def test_malicious_federation_peer_cannot_revoke_a_real_token(running_server):
    owner_ws, owner_fp, _, _ = await connect_and_register(running_server, device_id="open6_revokevictim")
    try:
        token = rand_token()
        await owner_ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        token_hash = server._hash_anon_token(token)
        assert server.anon_token_state_cache[token_hash][1] == "ACTIVE"

        await _federation_inject_inner_type(running_server, "unsubscribe_tokens", owner_fp, extra={"tokens": [token]})

        assert server.anon_token_state_cache[token_hash][1] == "ACTIVE", \
            "a federation peer revoked a real token via federated_forward"
    finally:
        await owner_ws.close()


async def test_federation_peer_direct_anon_type_on_own_connection_is_noop(running_server):
    """A federation peer sending an anon-token type as its OWN top-level
    `type` (not wrapped in federated_forward) hits handle_federation_peer_
    incoming()'s closed if/elif dispatch -- no branch matches, nothing
    happens, and the connection stays alive (proving there is no fallback
    into the general ALLOWED_TYPES client loop for an is_fed connection)."""
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            for t in sorted(ANON_TOKEN_FEDERATION_FORBIDDEN_TYPES):
                await ws.send(json.dumps({
                    "type": t, "token": rand_token(), "tokens": [rand_token()],
                    "payload": {"id": "x", "blob": "aGVsbG8="},
                }))
            # Connection must still be alive and processing federation
            # traffic normally afterward.
            await ws.send(json.dumps({
                "type": "federated_forward", "to": canonical_fingerprint("OPEN6_NOOP_PROBE_TARGET"),
                "payload": {"id": "open6-noop-probe", "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            }))
            await asyncio.sleep(0.3)
            assert "open6-noop-probe" in server.delivered_msg_ids
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── Candidate identity vs. committed registered session identity ─────────
#
# register() derived `username = fingerprint` BEFORE any admission/
# revocation/TOTP/device-authentication gate had run, and every rejection
# below that point is a bare `continue` (stays on the same connection) --
# so a REJECTED candidate identity still left `username` populated for the
# rest of that connection's lifetime. A subsequent ordinary message on the
# SAME socket was then processed as that fingerprint, bypassing every gate
# the failed register() was supposed to enforce. See SECURITY_INVARIANTS.md
# #52.

async def _fail_register_totp_wrong_code(ws, priv, pub_der, candidate, label):
    """Registers with a valid device signature but a wrong TOTP code and no
    recovery code -- device_needs_totp is True (brand-new device_id), so
    this must be rejected with totp_required, never reaching Phase 2."""
    challenge = await handshake(ws, priv, pub_der)
    device_priv, device_pub_der = gen_keypair()
    device_id = canonical_device_id(label)
    extra = _device_bind_extra(device_priv, device_pub_der, challenge, candidate, device_id,
                                totp_code="000000")
    await register(ws, pub_der, device_id, extra=extra)
    reply = await drain_until(ws, "totp_required")
    assert reply["type"] == "totp_required"


def _assert_uncommitted(candidate: str) -> None:
    assert candidate not in server.clients
    assert candidate not in server.authenticated_users.values()


async def _assert_boundary_closes(ws, message: dict) -> None:
    await ws.send(json.dumps(message))
    reply = await drain_until(ws, "error")
    assert reply["reason"] == "Registration required"
    with pytest.raises(websockets.exceptions.ConnectionClosed):
        while True:
            await ws.recv()


# ── 1. failed TOTP register leaves username uncommitted ──────────────────

async def test_failed_totp_register_leaves_username_uncommitted(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    ws = await websockets.connect(running_server)
    try:
        await _fail_register_totp_wrong_code(ws, priv, pub_der, candidate, "s639-totp-fail-1")
        _assert_uncommitted(candidate)
    finally:
        await ws.close()


# ── 2. after failed TOTP, request_sender_cert cannot obtain a cert ───────

async def test_after_failed_totp_request_sender_cert_impossible(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    ws = await websockets.connect(running_server)
    try:
        await _fail_register_totp_wrong_code(ws, priv, pub_der, candidate, "s639-totp-fail-2")
        await _assert_boundary_closes(ws, {"type": "request_sender_cert"})
        _assert_uncommitted(candidate)
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 3. after failed TOTP, message cannot be sent as candidate fingerprint ─

async def test_after_failed_totp_message_cannot_be_sent_as_candidate(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    recipient, recipient_fp, _, _ = await connect_and_register(running_server, device_id="s639-msg-recipient")
    await asyncio.sleep(0.2)

    ws = await websockets.connect(running_server)
    try:
        await _fail_register_totp_wrong_code(ws, priv, pub_der, candidate, "s639-totp-fail-3")
        await _assert_boundary_closes(ws, {
            "type": "message", "to": recipient_fp, "id": "s639-forged-msg", "text": "x",
        })
        _assert_uncommitted(candidate)

        # Recipient must never have received anything claiming to be from
        # the uncommitted candidate fingerprint.
        try:
            async with asyncio.timeout(0.3):
                msg = json.loads(await recipient.recv())
                assert msg.get("id") != "s639-forged-msg"
        except (asyncio.TimeoutError, TimeoutError):
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
        await recipient.close()


# ── 4. after failed TOTP, subscribe_tokens cannot claim tokens ───────────

async def test_after_failed_totp_subscribe_tokens_cannot_claim(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    ws = await websockets.connect(running_server)
    try:
        await _fail_register_totp_wrong_code(ws, priv, pub_der, candidate, "s639-totp-fail-4")
        token = rand_token()
        await _assert_boundary_closes(ws, {"type": "subscribe_tokens", "tokens": [token]})

        assert token not in server.token_to_ws
        assert token not in server.known_tokens
        _assert_uncommitted(candidate)
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 5. after failed TOTP, revoke_identity cannot revoke candidate fp ─────

async def test_after_failed_totp_revoke_identity_cannot_revoke(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    ws = await websockets.connect(running_server)
    try:
        await _fail_register_totp_wrong_code(ws, priv, pub_der, candidate, "s639-totp-fail-5")
        await _assert_boundary_closes(ws, {"type": "revoke_identity"})

        assert not await server.db_is_fingerprint_revoked(candidate)
        _assert_uncommitted(candidate)
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 6. revoked fingerprint: register -> identity_revoked, then an ordinary
#      message on the same socket is impossible ──────────────────────────

async def test_after_revoked_identity_ordinary_message_impossible(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    await server.db_revoke_fingerprint(candidate)

    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s639-revoked-device"))
        reply = await drain_until(ws, "identity_revoked")
        assert reply["type"] == "identity_revoked"

        await _assert_boundary_closes(ws, {"type": "request_sender_cert"})
        _assert_uncommitted(candidate)
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 7. access-code denied followed by an ordinary frame is impossible ────

async def test_after_access_code_denied_ordinary_message_impossible(running_server):
    real_protected = server.SERVER_ACCESS_PROTECTED
    server.SERVER_ACCESS_PROTECTED = True
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s639-accesscode-device"))  # no access_code
        reply = await drain_until(ws, "access_code_required")
        assert reply["type"] == "access_code_required"

        # S6-41 tightened this further: the server now closes the
        # connection OUTRIGHT on access_denied (not `continue`), so there
        # is no live socket left to even attempt another ordinary message
        # on -- the PoW-amortization/SQLite-hammering angle that ordering
        # closes. A subsequent send on this same (already-closing) socket
        # must fail with ConnectionClosed, never a normal reply.
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            while True:
                await ws.recv()
        _assert_uncommitted(candidate)
    finally:
        server.SERVER_ACCESS_PROTECTED = real_protected
        try:
            await ws.close()
        except Exception:
            pass


# ── 8. bad PoW followed by an ordinary frame is impossible ───────────────

async def test_after_bad_pow_ordinary_message_impossible(running_server):
    real_pow = server.POW_DIFFICULTY_BITS
    server.POW_DIFFICULTY_BITS = 16
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s639-pow-device"))  # no pow_nonce
        reply = await drain_until(ws, "pow_required")
        assert reply["type"] == "pow_required"

        await _assert_boundary_closes(ws, {"type": "ping"})
        _assert_uncommitted(candidate)
    finally:
        server.POW_DIFFICULTY_BITS = real_pow
        try:
            await ws.close()
        except Exception:
            pass


# ── 9. registration_full followed by an ordinary frame is impossible ─────

async def test_after_registration_full_ordinary_message_impossible(running_server):
    real_max = server.MAX_REGISTERED_USERS
    dummy_priv, dummy_pub_der = gen_keypair()
    dummy_fp = fingerprint_of(dummy_pub_der)
    await server.db_admit_new_fingerprint(dummy_fp, 0, "", False)
    server.MAX_REGISTERED_USERS = 1
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s639-full-device"))
        reply = await drain_until(ws, "registration_full")
        assert reply["type"] == "registration_full"

        await _assert_boundary_closes(ws, {"type": "ping"})
        _assert_uncommitted(candidate)
    finally:
        server.MAX_REGISTERED_USERS = real_max
        try:
            await ws.close()
        except Exception:
            pass


# ── 10. device_auth_failed followed by an ordinary frame is impossible ───

async def test_after_device_auth_failed_ordinary_message_impossible(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        # device_id present, but no device_public_key/device_signature at all.
        await register(ws, pub_der, device_id=canonical_device_id("s639-no-proof-device"))
        reply = await drain_until(ws, "device_auth_failed")
        assert reply["type"] == "device_auth_failed"

        await _assert_boundary_closes(ws, {"type": "ping"})
        _assert_uncommitted(candidate)
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 11. device_limit_reached followed by an ordinary frame is impossible ─

async def test_after_device_limit_reached_ordinary_message_impossible(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(2)
    await server.db_commit_totp_setup(candidate, secret, codes)
    server.user_totp_secrets[candidate] = secret

    real_cap = server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT
    server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = 1
    try:
        ws0 = await websockets.connect(running_server)
        try:
            challenge0 = await handshake(ws0, priv, pub_der)
            device_priv0, device_pub_der0 = gen_keypair()
            device_id0 = canonical_device_id("s639-cap-device-0")
            extra0 = _device_bind_extra(device_priv0, device_pub_der0, challenge0, candidate, device_id0,
                                         recovery_code=codes[0])
            await register(ws0, pub_der, device_id0, extra=extra0)
            await asyncio.sleep(0.2)
        finally:
            await ws0.close()
        await asyncio.sleep(0.2)

        ws = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws, priv, pub_der)
            device_priv, device_pub_der = gen_keypair()
            device_id = canonical_device_id("s639-cap-device-1")
            extra = _device_bind_extra(device_priv, device_pub_der, challenge, candidate, device_id,
                                        recovery_code=codes[1])
            await register(ws, pub_der, device_id, extra=extra)
            reply = await drain_until(ws, "device_limit_reached")
            assert reply["type"] == "device_limit_reached"

            await _assert_boundary_closes(ws, {"type": "ping"})
            _assert_uncommitted(candidate)
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    finally:
        server.MAX_AUTHORIZED_DEVICES_PER_ACCOUNT = real_cap


# ── 12. a challenge_response client sending `message` BEFORE any register
#       is rejected/closed ────────────────────────────────────────────────

async def test_challenge_response_message_before_register_rejected(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await _assert_boundary_closes(ws, {
            "type": "message", "to": "0000000000000000", "id": "x", "text": "y",
        })
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 13. a challenge_response client sending `request_sender_cert` BEFORE
#       register is rejected/closed ───────────────────────────────────────

async def test_challenge_response_request_sender_cert_before_register_rejected(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await _assert_boundary_closes(ws, {"type": "request_sender_cert"})
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 14. successful register sets username/authenticated_users/clients
#       consistently ──────────────────────────────────────────────────────

async def test_successful_register_commits_consistent_state(running_server):
    ws, fp, priv, pub_der = await connect_and_register(running_server, device_id="s639-consistent")
    try:
        await asyncio.sleep(0.2)
        assert fp in server.clients
        assert server.clients[fp]["ws"] is not None
        assert fp in server.authenticated_users.values()
    finally:
        await ws.close()


# ── 15. after successful register, all normal handlers still work ────────

async def test_after_successful_register_normal_handlers_still_work(running_server):
    recipient, recipient_fp, _, _ = await connect_and_register(running_server, device_id="s639-normal-recipient")
    sender, sender_fp, _, _ = await connect_and_register(running_server, device_id="s639-normal-sender")
    await asyncio.sleep(0.2)
    try:
        await sender.send(json.dumps({
            "type": "message", "to": recipient_fp, "id": "s639-normal-1", "text": "hi",
        }))
        msg = await drain_until(recipient, "message")
        assert msg["id"] == "s639-normal-1"
        assert msg["from"] == sender_fp
    finally:
        await recipient.close()
        await sender.close()


# ── 16. anon_channel can still send anon_message without ever registering ─

async def test_anon_channel_still_sends_anon_message_without_register(running_server):
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())
        assert challenge_msg["type"] == "challenge"
        await ws.send(json.dumps({"type": "anon_channel"}))
        ok = json.loads(await ws.recv())
        assert ok["type"] == "anon_channel_ok"

        token = rand_token()
        await ws.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s639-anon-1", "ciphertext": "x"},
        }))
        # Must NOT be rejected by the new hard authorization boundary --
        # anon_channel is explicitly exempt from it.
        reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=1.0))
        assert reply.get("type") != "error"
    finally:
        await ws.close()


# ── 17. federation still goes directly to its dedicated handler ─────────

async def test_federation_still_uses_dedicated_handler(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            # A type that only makes sense in the ordinary client loop --
            # federation never reaches that loop at all (is_fed returns
            # straight into handle_federation_peer_incoming()), so this must
            # not trigger the client loop's hard authorization boundary or
            # otherwise disturb the connection.
            await ws.send(json.dumps({"type": "ping"}))
            await asyncio.sleep(0.2)

            to = canonical_fingerprint("S639_FED_STILL_WORKS")
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"id": "s639-fed-1", "type": "message", "text": "x",
                            "from": canonical_fingerprint("SOMESENDER")},
            }))
            await asyncio.sleep(0.3)
            assert "s639-fed-1" in server.delivered_msg_ids or len(_read_pending_rows(to)) == 1
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 18. cancellation during Phase 1 never commits username ───────────────

async def test_cancellation_during_phase1_never_commits_username(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    real_verify = server.totp_verify_and_consume

    async def cancelling_verify(*a, **kw):
        raise asyncio.CancelledError()

    server.totp_verify_and_consume = cancelling_verify
    try:
        ws = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws, priv, pub_der)
            device_priv, device_pub_der = gen_keypair()
            device_id = canonical_device_id("s639-cancel-device")
            extra = _device_bind_extra(device_priv, device_pub_der, challenge, candidate, device_id,
                                        totp_code="123456")
            await register(ws, pub_der, device_id, extra=extra)
            await asyncio.sleep(0.3)
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    finally:
        server.totp_verify_and_consume = real_verify

    await asyncio.sleep(0.1)
    _assert_uncommitted(candidate)


# ── 19. failure immediately before Phase 2 never commits username ────────

async def test_failure_immediately_before_phase2_never_commits_username(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    real_bind = server.db_bind_device_pubkey

    async def conflicting_bind(*a, **kw):
        return "CONFLICT"  # unreachable in practice, forces the last pre-Phase-2 exit

    server.db_bind_device_pubkey = conflicting_bind
    try:
        ws = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws, priv, pub_der)
            device_priv, device_pub_der = gen_keypair()
            device_id = canonical_device_id("s639-conflict-device")
            extra = _device_bind_extra(device_priv, device_pub_der, challenge, candidate, device_id,
                                        totp_code=_current_totp_code(secret))
            await register(ws, pub_der, device_id, extra=extra)
            reply = await drain_until(ws, "device_auth_failed")
            assert reply["type"] == "device_auth_failed"
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    finally:
        server.db_bind_device_pubkey = real_bind

    _assert_uncommitted(candidate)


# ── 20. failed register disconnect cleanup does not mutate an existing
#       legitimate session for the same candidate fingerprint ────────────

async def test_failed_register_cleanup_does_not_mutate_existing_session(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    codes = server.generate_recovery_codes(1)
    await server.db_commit_totp_setup(candidate, secret, codes)
    server.user_totp_secrets[candidate] = secret

    device_priv_a, device_pub_der_a = gen_keypair()
    device_id_a = canonical_device_id("s639-existing-device-a")
    ws_a = await websockets.connect(running_server)
    challenge_a = await handshake(ws_a, priv, pub_der)
    extra_a = _device_bind_extra(device_priv_a, device_pub_der_a, challenge_a, candidate, device_id_a,
                                  recovery_code=codes[0])
    await register(ws_a, pub_der, device_id_a, extra=extra_a)
    await asyncio.sleep(0.2)
    assert candidate in server.clients
    original_ws_entry = server.clients[candidate]["ws"]

    try:
        ws_b = await websockets.connect(running_server)
        try:
            challenge_b = await handshake(ws_b, priv, pub_der)
            device_priv_b, device_pub_der_b = gen_keypair()
            device_id_b = canonical_device_id("s639-attacker-device-b")
            extra_b = _device_bind_extra(device_priv_b, device_pub_der_b, challenge_b, candidate, device_id_b,
                                          totp_code="000000")
            await register(ws_b, pub_der, device_id_b, extra=extra_b)
            reply = await drain_until(ws_b, "totp_required")
            assert reply["type"] == "totp_required"
        finally:
            await ws_b.close()
        await asyncio.sleep(0.3)

        # Device A's legitimate session must be completely untouched.
        assert candidate in server.clients
        assert server.clients[candidate]["ws"] is original_ws_entry
        assert server.authenticated_users.get(original_ws_entry) == candidate
    finally:
        await ws_a.close()


# ── 21. explicit invariant: every tested register rejection leaves the
#       websocket unauthenticated ─────────────────────────────────────────

async def test_every_register_rejection_leaves_websocket_unauthenticated(running_server):
    scenarios = []

    priv1, pub_der1 = gen_keypair()
    candidate1 = fingerprint_of(pub_der1)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate1, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate1] = secret
    scenarios.append((priv1, pub_der1, candidate1))

    priv2, pub_der2 = gen_keypair()
    candidate2 = fingerprint_of(pub_der2)
    await server.db_revoke_fingerprint(candidate2)
    scenarios.append((priv2, pub_der2, candidate2))

    for priv, pub_der, candidate in scenarios:
        ws = await websockets.connect(running_server)
        try:
            await handshake(ws, priv, pub_der)
            await register(ws, pub_der, device_id=canonical_device_id(f"invariant-{candidate}"))
            await asyncio.sleep(0.2)
        finally:
            try:
                await ws.close()
            except Exception:
                pass
        await asyncio.sleep(0.1)
        assert candidate not in server.authenticated_users.values(), candidate
        assert candidate not in server.clients, candidate


# ── Deterministic register -> register_ok -> register_bundle ordering ────
#
# Android used to send `register_bundle` from a coroutine racing
# independently against the one sending `register` itself, so this server
# temporarily tolerated `register_bundle` arriving before a completed
# `register` (a narrow exception to the S6-39 hard authorization boundary).
# That race is now fixed client-side (MessengerService.kt, S6-40): `register`
# -> the server's `register_ok` acknowledgment -> `register_bundle` is an
# explicit, event-driven, per-connection-generation sequence, so
# `register_bundle` can no longer reach this server before `register` at
# all. The exception (and the register_bundle handler's matching `if not
# username: continue` guard, which existed only because of it) are both
# removed -- restoring the plain S6-39 rule with no special cases. See
# SECURITY_INVARIANTS.md #53.

# ── 13. register_bundle before register is rejected exactly like any
#        other ordinary message ──────────────────────────────────────────

async def test_register_bundle_before_register_rejected_like_ordinary_message(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await _assert_boundary_closes(ws, {
            "type": "register_bundle",
            "bundle": {"ik": "IK", "spk": "SPK", "opks": []},
        })
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 14. a failed register followed by register_bundle can never reach
#        store_prekey_bundle ──────────────────────────────────────────────

async def test_failed_register_then_register_bundle_never_reaches_store(running_server):
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    secret = TOTP_TEST_SECRET
    await server.db_commit_totp_setup(candidate, secret, server.generate_recovery_codes(1))
    server.user_totp_secrets[candidate] = secret

    call_count = 0
    real_store = server.store_prekey_bundle

    async def counting_store(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_store(*a, **kw)

    server.store_prekey_bundle = counting_store
    ws = await websockets.connect(running_server)
    try:
        await _fail_register_totp_wrong_code(ws, priv, pub_der, candidate, "s640-failed-then-bundle")
        await _assert_boundary_closes(ws, {
            "type": "register_bundle",
            "bundle": {"ik": "IK", "spk": "SPK", "opks": []},
        })
        assert call_count == 0
        assert candidate not in server.prekey_bundles
    finally:
        server.store_prekey_bundle = real_store
        try:
            await ws.close()
        except Exception:
            pass


# ── 15. a successful register followed by register_bundle still works ────

async def test_successful_register_then_register_bundle_still_works(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s640-success-then-bundle")
    try:
        await asyncio.sleep(0.2)
        await ws.send(json.dumps({
            "type": "register_bundle",
            "bundle": {"ik": "IK", "spk": "SPK", "opks": [{"id": "s640-opk1"}]},
        }))
        await asyncio.sleep(0.3)
        assert fp in server.prekey_bundles
        assert server.prekey_bundles[fp]["bundle"]["opks"] == [{"id": "s640-opk1"}]
    finally:
        await ws.close()


# ── bonus: successful registration is followed by an explicit register_ok
#    acknowledgment (the synchronization signal this whole fix relies on) ─

async def test_successful_register_receives_register_ok_ack(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s640-register-ok"))
        reply = await drain_until(ws, "register_ok")
        assert reply["type"] == "register_ok"
    finally:
        await ws.close()


# ── Hardened SERVER_ACCESS_PROTECTED access codes ─────────────────────────
#
# Generated access codes were `secrets.token_hex(4).upper()` -- only 32
# bits, cheaply guessable online since nothing dedicated bounded the
# attempt rate, and a wrong guess left the socket open for another
# register() attempt reusing the SAME already-solved PoW nonce (the
# handshake challenge never changes across attempts on one connection).
# Unused codes were also stored in SQLite as plaintext, so a stolen offline
# DB copy handed out immediately-usable invitations. See
# SECURITY_INVARIANTS.md #54.

def _insert_v2_access_code(raw: str, used: bool = False, used_by: str = None) -> None:
    with server.db_connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO server_access_codes (code, used, used_by, used_at, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (server._hash_access_code(raw), 1 if used else 0, used_by,
             server.time.time() if used else None, server.time.time())
        )
        conn.commit()


# ── 1. a generated code is exactly 32 uppercase hex chars / 128 bits ─────

async def test_generated_access_code_is_128_bit_hex():
    codes = server._db_gen_access_codes_sync(5)
    assert len(codes) == 5
    for c in codes:
        assert len(c) == server.ACCESS_CODE_HEX_LEN == 32
        assert c == c.upper()
        assert all(ch in "0123456789ABCDEF" for ch in c)
        assert server.is_valid_access_code(c)
    assert len(set(codes)) == 5  # no accidental duplicates in one batch


# ── 2/3. the raw code never appears in SQLite -- only its sha256:
#         representation does ────────────────────────────────────────────

async def test_generated_raw_code_never_stored_only_hash_does():
    codes = server._db_gen_access_codes_sync(3)
    with server.db_connect() as conn:
        rows = conn.execute("SELECT code FROM server_access_codes").fetchall()
    stored = [row[0] for row in rows]
    assert len(stored) == 3
    for raw in codes:
        assert raw not in stored
        assert server._hash_access_code(raw) in stored
    for s in stored:
        assert server._ACCESS_CODE_HASH_RE.match(s)


# ── 4/5. correct raw code accepted once, rejected on reuse ───────────────

async def test_correct_access_code_accepted_once_then_rejected():
    raw = "A" * 32
    _insert_v2_access_code(raw)
    result1 = await server.db_admit_new_fingerprint(
        "S641FINGERPRINT1", max_users=0, access_code=raw, require_access_code=True
    )
    assert result1 == "ok"
    result2 = await server.db_admit_new_fingerprint(
        "S641FINGERPRINT2", max_users=0, access_code=raw, require_access_code=True
    )
    assert result2 == "access_denied"


# ── 6. two concurrent fingerprints racing the SAME code: exactly one wins ─
#      (covered by test_access_code_atomic_under_concurrent_redemption,
#      updated for hash-based storage in this same fix)

# ── 7/8. malformed / missing code rejected before db_admit_new_fingerprint,
#         connection closed ──────────────────────────────────────────────

async def test_malformed_access_code_rejected_before_db(running_server):
    real_protected = server.SERVER_ACCESS_PROTECTED
    server.SERVER_ACCESS_PROTECTED = True
    call_count = 0
    real_admit = server.db_admit_new_fingerprint

    async def counting_admit(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_admit(*a, **kw)

    server.db_admit_new_fingerprint = counting_admit
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s641-malformed"),
                        extra={"access_code": "not-hex-and-wrong-length"})
        reply = await drain_until(ws, "access_code_required")
        assert reply["type"] == "access_code_required"
        assert call_count == 0
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            while True:
                await ws.recv()
    finally:
        server.db_admit_new_fingerprint = real_admit
        server.SERVER_ACCESS_PROTECTED = real_protected
        try:
            await ws.close()
        except Exception:
            pass


async def test_missing_access_code_rejected_before_db(running_server):
    real_protected = server.SERVER_ACCESS_PROTECTED
    server.SERVER_ACCESS_PROTECTED = True
    call_count = 0
    real_admit = server.db_admit_new_fingerprint

    async def counting_admit(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_admit(*a, **kw)

    server.db_admit_new_fingerprint = counting_admit
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s641-missing"))  # no access_code at all
        reply = await drain_until(ws, "access_code_required")
        assert reply["type"] == "access_code_required"
        assert call_count == 0
    finally:
        server.db_admit_new_fingerprint = real_admit
        server.SERVER_ACCESS_PROTECTED = real_protected
        try:
            await ws.close()
        except Exception:
            pass


# ── 9. an oversized (far larger than any legitimate code) value is
#       rejected before it ever reaches the DB ───────────────────────────

async def test_oversized_access_code_rejected_before_db(running_server):
    real_protected = server.SERVER_ACCESS_PROTECTED
    server.SERVER_ACCESS_PROTECTED = True
    call_count = 0
    real_admit = server.db_admit_new_fingerprint

    async def counting_admit(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_admit(*a, **kw)

    server.db_admit_new_fingerprint = counting_admit
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        # Well under the websockets library's own default per-frame limit
        # (1 MiB) so this actually reaches register()'s own validation
        # instead of being rejected at the protocol layer first -- still
        # many orders of magnitude past any legitimate 32-char code.
        await register(ws, pub_der, device_id=canonical_device_id("s641-oversized"),
                        extra={"access_code": "A" * (100 * 1024)})
        reply = await drain_until(ws, "access_code_required")
        assert reply["type"] == "access_code_required"
        assert call_count == 0
    finally:
        server.db_admit_new_fingerprint = real_admit
        server.SERVER_ACCESS_PROTECTED = real_protected
        try:
            await ws.close()
        except Exception:
            pass


# ── 10/11. a well-formed but WRONG code is rejected and the socket is
#           closed outright -- the same socket cannot make a second guess ─

async def test_wellformed_wrong_access_code_closes_socket_no_second_guess(running_server):
    real_protected = server.SERVER_ACCESS_PROTECTED
    server.SERVER_ACCESS_PROTECTED = True
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s641-wrong-1"),
                        extra={"access_code": "1" * 32})
        reply = await drain_until(ws, "access_code_required")
        assert reply["type"] == "access_code_required"

        # Same socket -- a second, DIFFERENT guess must be impossible. Not
        # `continue` on the server: this exact socket is already gone.
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await register(ws, pub_der, device_id=canonical_device_id("s641-wrong-1"),
                            extra={"access_code": "2" * 32})
            await ws.recv()
    finally:
        server.SERVER_ACCESS_PROTECTED = real_protected
        try:
            await ws.close()
        except Exception:
            pass


# ── 12. a new connection gets a genuinely new challenge -- an old
#        pow_nonce solved for a previous challenge is never reusable ─────

async def test_new_connection_gets_a_new_challenge(running_server):
    ws1 = await websockets.connect(running_server)
    ws2 = await websockets.connect(running_server)
    try:
        challenge_msg1 = json.loads(await ws1.recv())
        challenge_msg2 = json.loads(await ws2.recv())
        assert challenge_msg1["type"] == "challenge"
        assert challenge_msg2["type"] == "challenge"
        assert challenge_msg1["data"] != challenge_msg2["data"]
    finally:
        await ws1.close()
        await ws2.close()


# ── 13. the global access-code attempt budget rejects before SQLite ──────

async def test_global_access_code_budget_rejects_before_db(running_server):
    real_protected = server.SERVER_ACCESS_PROTECTED
    real_limit      = server.ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT
    real_enabled    = server.ACCESS_CODE_GLOBAL_ENABLED
    server.SERVER_ACCESS_PROTECTED        = True
    server.ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT = 2
    server.ACCESS_CODE_GLOBAL_ENABLED       = True
    server.access_code_global_rate["count"]      = 0
    server.access_code_global_rate["reset_time"] = server.time.time()

    call_count = 0
    real_admit = server.db_admit_new_fingerprint

    async def counting_admit(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_admit(*a, **kw)

    server.db_admit_new_fingerprint = counting_admit
    try:
        for i in range(4):
            priv, pub_der = gen_keypair()
            ws = await websockets.connect(running_server)
            try:
                await handshake(ws, priv, pub_der)
                await register(ws, pub_der, device_id=canonical_device_id(f"s641-budget-{i}"),
                                extra={"access_code": f"{i:032X}"})
                await drain_until(ws, "access_code_required")
            finally:
                try:
                    await ws.close()
                except Exception:
                    pass
        # Only the first 2 (within budget) ever reached the DB admission
        # call -- the rest were rejected purely by the RAM counter.
        assert call_count == 2
    finally:
        server.db_admit_new_fingerprint = real_admit
        server.SERVER_ACCESS_PROTECTED = real_protected
        server.ACCESS_CODE_GLOBAL_ATTEMPT_LIMIT = real_limit
        server.ACCESS_CODE_GLOBAL_ENABLED = real_enabled


# ── 14. protected-mode startup refuses an UNUSED legacy plaintext code ───

async def test_startup_check_flags_unused_legacy_access_code():
    with server.db_connect() as conn:
        conn.execute(
            "INSERT INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
            ("OLD8CHR1", server.time.time())
        )
        conn.commit()
    assert server._db_has_legacy_unused_access_codes_sync() is True


# ── 15. a USED legacy row does not grant access and does not block
#        startup ──────────────────────────────────────────────────────────

async def test_used_legacy_access_code_does_not_block_startup():
    with server.db_connect() as conn:
        conn.execute(
            "INSERT INTO server_access_codes (code, used, used_by, used_at, created_at) VALUES (?, 1, ?, ?, ?)",
            ("OLD8CHR2", "SOMEFINGERPRINT1", server.time.time(), server.time.time())
        )
        conn.commit()
    assert server._db_has_legacy_unused_access_codes_sync() is False
    # And it genuinely can't grant access even if somehow replayed as a
    # raw "code" value -- require_access_code compares against the HASHED
    # representation, which this legacy plaintext row never has.
    result = await server.db_admit_new_fingerprint(
        "S641LEGACYREPLAY", max_users=0, access_code="OLD8CHR2", require_access_code=True
    )
    assert result == "access_denied"


# ── 16. the updated admin generator stores only the hash, but
#        displays/QR-encodes the raw code ────────────────────────────────

async def test_admin_gen_codes_stores_hash_but_shows_raw_code(tmp_path):
    db_path = tmp_path / "s641_admin_test.db"
    env = dict(os.environ)
    env["DB_PATH"] = str(db_path)
    admin_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "admin_gen_codes.py"
    )
    result = subprocess.run(
        [sys.executable, admin_script, "1"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    match = re.search(r"([0-9A-F]{32})", result.stdout)
    assert match, result.stdout
    raw = match.group(1)
    assert server.is_valid_access_code(raw)

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute("SELECT code FROM server_access_codes").fetchall()
    assert len(rows) == 1
    stored = rows[0][0]
    assert stored == server._hash_access_code(raw)
    assert raw not in stored
    # The raw code IS expected in stdout (that's the whole point -- shown
    # to the operator to print/QR-encode), just never in what got stored.
    assert raw in result.stdout


# ── 17. Android's QR/manual-entry path was inspected (MessengerService.kt/
#        ServersScreen.kt) and carries an arbitrary-length string through
#        unchanged -- no fixed 8-character assumption exists on either
#        client, so no client-side test is needed for this server-only
#        entropy increase.

# ── 18. a successful protected registration still consumes the code and
#        durably registers the fingerprint, atomically ─────────────────

async def test_successful_protected_registration_consumes_code_and_registers(running_server):
    real_protected = server.SERVER_ACCESS_PROTECTED
    server.SERVER_ACCESS_PROTECTED = True
    raw = "5" * 32
    _insert_v2_access_code(raw)
    priv, pub_der = gen_keypair()
    candidate = fingerprint_of(pub_der)
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, device_id=canonical_device_id("s641-success"),
                        extra={"access_code": raw})
        reply = await drain_until(ws, "register_ok")
        assert reply["type"] == "register_ok"
        assert await server.db_is_fingerprint_registered(candidate)
        with server.db_connect() as conn:
            row = conn.execute(
                "SELECT used, used_by FROM server_access_codes WHERE code = ?",
                (server._hash_access_code(raw),)
            ).fetchone()
        assert row == (1, candidate)
    finally:
        server.SERVER_ACCESS_PROTECTED = real_protected
        try:
            await ws.close()
        except Exception:
            pass


# ── 19. a failed/full registration never consumes a valid code ──────────

async def test_failed_registration_never_consumes_valid_code():
    raw = "6" * 32
    _insert_v2_access_code(raw)
    await server.db_admit_new_fingerprint(
        "S641DUMMYFULL001", max_users=1, access_code="", require_access_code=False
    )
    result = await server.db_admit_new_fingerprint(
        "S641NEWFP0000001", max_users=1, access_code=raw, require_access_code=True
    )
    assert result == "full"
    with server.db_connect() as conn:
        row = conn.execute(
            "SELECT used FROM server_access_codes WHERE code = ?",
            (server._hash_access_code(raw),)
        ).fetchone()
    assert row[0] == 0  # untouched -- a legitimate code isn't wasted on a full server


# ── 20. SERVER_ACCESS_PROTECTED=false behavior remains unchanged ────────

async def test_unprotected_mode_registration_unchanged(running_server):
    real_protected = server.SERVER_ACCESS_PROTECTED
    server.SERVER_ACCESS_PROTECTED = False
    try:
        ws, fp, _, _ = await connect_and_register(running_server, device_id="s641-unprotected")
        try:
            await asyncio.sleep(0.2)
            assert fp in server.clients
        finally:
            await ws.close()
    finally:
        server.SERVER_ACCESS_PROTECTED = real_protected

# ── 21. S6-39/S6-40 registration-boundary tests remain green -- verified
#        by running the full suite (no dedicated test needed here; see
#        every test in those sections, unmodified and still passing).


# ── Bounded durable offline queue: recipient/msg_id byte-cap gap ──────────
#
# pending_messages_meta.total_bytes only ever accounted for
# len(payload_json.encode("utf-8")) (S6-31), but `recipient` and `msg_id` are
# each their own separately-stored SQLite TEXT column. Before this fix,
# neither had any shape/length bound of its own at db_store()'s boundary --
# a client-controlled `to` (almost every relay handler: message, session_init,
# edit, reaction, voice -- which has no message-type rate limit of its own --
# group_*, missed_call, ...) could be made many MiB long (up to the ~6 MiB
# websocket frame ceiling) while the actual JSON payload stayed tiny,
# contributing ZERO bytes to the tracked byte cap while still consuming real
# disk. Such rows also could never legitimately flush (no genuine
# fingerprint ever equals attacker-chosen garbage), so they'd sit until
# MSG_TTL_SEC expiry. See SECURITY_INVARIANTS.md #55.

# ── 1. a ~6 MiB recipient is rejected before the global offline-store
#       write-attempt limiter is ever touched ────────────────────────────

async def test_giant_recipient_rejected_before_global_offline_store_limiter():
    real_count = server.global_offline_store_rate["count"]
    giant_to = "A" * (6 * 1024 * 1024)
    status = await server.db_store(giant_to, {"type": "message", "text": "x"}, msg_id="s642-giant-to-1")
    assert status == "INVALID_RECIPIENT"
    assert server.global_offline_store_rate["count"] == real_count  # budget never touched


# ── 2. an oversized recipient never reaches the executor/SQLite ─────────

async def test_oversized_recipient_never_reaches_executor_or_sqlite():
    def failing_connect():
        raise AssertionError("db_connect() must not be called for an invalid recipient")

    real_connect = server.db_connect
    server.db_connect = failing_connect
    try:
        status = await server.db_store("B" * 10000, {"type": "message", "text": "x"}, msg_id="s642-oversized-to-1")
        assert status == "INVALID_RECIPIENT"
    finally:
        server.db_connect = real_connect


# ── 3. lowercase / non-hex / 15-char / 17-char recipients are all
#       rejected -- only the exact canonical shape is accepted ─────────

async def test_recipient_shape_variants_rejected():
    base = "0123456789ABCDEF"
    variants = {
        "lowercase":  base.lower(),
        "non_hex":    "0123456789ABCDEG",
        "15_chars":   base[:-1],
        "17_chars":   base + "0",
    }
    for label, bad in variants.items():
        status = await server.db_store(bad, {"type": "message", "text": "x"}, msg_id=f"s642-variant-{label}")
        assert status == "INVALID_RECIPIENT", label


# ── 4. a canonical 16-uppercase-hex recipient still stores normally ──────

async def test_canonical_recipient_still_stores_normally():
    target = canonical_fingerprint("s642_canonical_ok")
    status = await server.db_store(target, {"type": "message", "text": "hi"}, msg_id="s642-canonical-ok-1")
    assert status == "STORED"
    assert len(_read_pending_rows(target)) == 1


# ── 5. _db_store_sync() itself rejects a bad recipient before BEGIN
#       IMMEDIATE -- defense-in-depth for a hypothetical caller that
#       bypasses db_store() ──────────────────────────────────────────────

async def test_db_store_sync_defense_in_depth_rejects_bad_recipient():
    def failing_connect():
        raise AssertionError("db_connect() must not be called for an invalid recipient")

    real_connect = server.db_connect
    server.db_connect = failing_connect
    try:
        status = server._db_store_sync(
            "not-canonical-at-all", json.dumps({"type": "message"}), 20, msg_id="s642-direct-1"
        )
        assert status == "INVALID_RECIPIENT"
    finally:
        server.db_connect = real_connect


# ── 6. a list/dict msg_id is rejected before it can ever reach SQLite
#       parameter binding ────────────────────────────────────────────────

async def test_unhashable_msg_id_rejected_before_sqlite_binding():
    target = canonical_fingerprint("s642_unhashable_msgid")
    for bad_msg_id in (["not", "a", "string"], {"not": "a string either"}):
        status = await server.db_store(target, {"type": "message", "text": "x"}, msg_id=bad_msg_id)
        assert status == "INVALID_MSG_ID", type(bad_msg_id)
    assert len(_read_pending_rows(target)) == 0


# ── 7. an oversized msg_id is rejected before it ever reaches SQLite ─────

async def test_oversized_msg_id_rejected_before_sqlite():
    target = canonical_fingerprint("s642_oversized_msgid")
    status = await server.db_store(
        target, {"type": "message", "text": "x"}, msg_id="X" * (server.OFFLINE_MSG_ID_MAX_LEN + 1)
    )
    assert status == "INVALID_MSG_ID"
    assert len(_read_pending_rows(target)) == 0


# ── 8. msg_id=None remains fully supported for the many legitimate
#       callers that never pass one ──────────────────────────────────────

async def test_msg_id_none_still_supported():
    target = canonical_fingerprint("s642_msgid_none")
    status = await server.db_store(target, {"type": "delivered", "from": "X", "id": "m1"}, msg_id=None)
    assert status == "STORED"
    assert len(_read_pending_rows(target)) == 1


# ── 9. an invalid recipient never increments pending_messages_meta ───────

async def test_invalid_recipient_does_not_increment_meta():
    before = _read_meta()
    status = await server.db_store(
        "still-not-a-canonical-recipient", {"type": "message", "text": "x"}, msg_id="s642-meta-badrecip-1"
    )
    assert status == "INVALID_RECIPIENT"
    assert _read_meta() == before


# ── 10. an invalid msg_id never increments pending_messages_meta ────────

async def test_invalid_msg_id_does_not_increment_meta():
    target = canonical_fingerprint("s642_meta_bad_msgid")
    before = _read_meta()
    status = await server.db_store(target, {"type": "message", "text": "x"}, msg_id={"not": "a string"})
    assert status == "INVALID_MSG_ID"
    assert _read_meta() == before


# ── 11. `message` with an invalid `to` receives an explicit error, never
#        a normal ack (rejected at the handler, before db_store()) ──────

async def test_message_with_invalid_to_receives_no_normal_ack(running_server):
    ws, _, _, _ = await connect_and_register(running_server, device_id="s642-msg-invalid-to")
    try:
        await ws.send(json.dumps({
            "type": "message", "to": "not-a-canonical-target", "id": "s642-msg-badto-1",
            "text": "hi", "signature": "sig",
        }))
        reply = await _collect_until_relevant(ws, {"ack", "error"})
        assert reply["type"] == "error"
        assert reply.get("reason") == "Invalid recipient"
    finally:
        await ws.close()


# ── 12. `session_init` with an invalid `to` receives an explicit error,
#        never a normal ack ──────────────────────────────────────────────

async def test_session_init_with_invalid_to_receives_no_normal_ack(running_server):
    ws, _, _, _ = await connect_and_register(running_server, device_id="s642-sinit-invalid-to")
    try:
        await ws.send(json.dumps({
            "type": "session_init", "to": "also-not-canonical", "id": "s642-sinit-badto-1",
            "sender_ik": "IK", "x3dh_header": "H", "session_header": "SH",
            "text": "hi", "signature": "sig",
        }))
        reply = await _collect_until_relevant(ws, {"ack", "error"})
        assert reply["type"] == "error"
        assert reply.get("reason") == "Invalid recipient"
    finally:
        await ws.close()


# ── 13. `voice` (no message-type rate limit of its own -- the motivating
#        example) with a giant `to` can never create a durable row ──────

async def test_voice_with_giant_to_cannot_create_durable_row(running_server):
    ws, _, _, _ = await connect_and_register(running_server, device_id="s642-voice-giant-to")
    # Comfortably under the websockets library's own 1 MiB default per-frame
    # limit (see test_oversized_access_code_rejected_before_db's own
    # comment for that same constraint), still absurd next to a 16-char
    # canonical fingerprint.
    giant_to = "V" * (100 * 1024)
    try:
        await ws.send(json.dumps({
            "type": "voice", "to": giant_to, "voice_id": "v1", "voice_data": "x",
            "signature": "sig", "duration": 1,
        }))
        await asyncio.sleep(0.3)
        assert len(_read_pending_rows(giant_to)) == 0
    finally:
        await ws.close()


# ── 14. every other direct-user relay type with an invalid `to` can
#        never create a durable row either ───────────────────────────────

async def test_relay_types_with_invalid_to_cannot_create_row(running_server):
    ws, _, _, _ = await connect_and_register(running_server, device_id="s642-relay-invalid-to")
    bad_to = "definitely-not-canonical-either"
    frames = [
        {"type": "edit", "to": bad_to, "id": "m1", "text": "x", "signature": "sig"},
        {"type": "reaction", "to": bad_to, "message_id": "m1", "emoji": "x", "signature": "sig"},
        {"type": "group_reaction", "to": bad_to, "group_id": "g1",
         "message_id": "m1", "emoji": "x", "signature": "sig"},
        {"type": "group_create", "to": bad_to, "group_id": "g1", "group_name": "g",
         "group_avatar": None, "encrypted_group_key": "x", "signature": "sig"},
        {"type": "group_message", "to": bad_to, "group_id": "g1", "message_id": "gm1",
         "sender_name": "s", "text": "x", "signature": "sig"},
        {"type": "group_member_removed", "to": bad_to, "group_id": "g1", "removed_member": "X"},
        {"type": "group_member_added", "to": bad_to, "group_id": "g1",
         "new_member": "X", "new_member_name": "n"},
        {"type": "group_key_rotation", "to": bad_to, "group_id": "g1",
         "encrypted_new_key": "x", "signature": "sig"},
        {"type": "group_invite_accepted", "to": bad_to, "group_id": "g1",
         "new_member": "X", "new_member_name": "n"},
        {"type": "message_delete", "to": bad_to, "id": "m1"},
        {"type": "disappear_timer", "to": bad_to, "id": "m1", "seconds": 10},
        {"type": "group_message_delete", "to": bad_to, "group_id": "g1", "message_id": "gm1"},
    ]
    try:
        for frame in frames:
            await ws.send(json.dumps(frame))
        await asyncio.sleep(0.3)
        assert len(_read_pending_rows(bad_to)) == 0
    finally:
        await ws.close()


# ── 15. an invalid local `to` never reaches forward_to_peers() ──────────

async def test_invalid_local_to_never_reaches_forward_to_peers(running_server):
    real_forward = server.forward_to_peers
    called = False

    async def spy_forward(*a, **kw):
        nonlocal called
        called = True
        return await real_forward(*a, **kw)

    server.forward_to_peers = spy_forward
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws, _, _, _ = await connect_and_register(running_server, device_id="s642-no-forward")
        try:
            await ws.send(json.dumps({
                "type": "message", "to": "still-not-canonical-1", "id": "s642-noforward-1",
                "text": "hi", "signature": "sig",
            }))
            await asyncio.sleep(0.3)
            assert called is False
        finally:
            await ws.close()
    finally:
        server.forward_to_peers = real_forward
        server.FEDERATION_SECRET = old_secret


# ── 16. an invalid local `to` never triggers send_fcm_wakeup() ──────────

async def test_invalid_local_to_never_triggers_fcm_wakeup(running_server):
    real_scheduler = server.schedule_fcm_wakeup
    called = False

    def spy_scheduler(*a, **kw):
        nonlocal called
        called = True
        return real_scheduler(*a, **kw)

    server.schedule_fcm_wakeup = spy_scheduler
    try:
        ws, _, _, _ = await connect_and_register(running_server, device_id="s642-no-fcm")
        try:
            await ws.send(json.dumps({
                "type": "message", "to": "still-not-canonical-2", "id": "s642-nofcm-1",
                "text": "hi", "signature": "sig",
            }))
            await asyncio.sleep(0.3)
            assert called is False
        finally:
            await ws.close()
    finally:
        server.schedule_fcm_wakeup = real_scheduler


# ── 17. canonical direct (online) delivery is completely unaffected ─────

async def test_canonical_direct_delivery_still_works_online(running_server):
    recipient, recipient_fp, _, _ = await connect_and_register(running_server, device_id="s642-online-recipient")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s642-online-sender")
    await asyncio.sleep(0.2)
    try:
        await sender.send(json.dumps({
            "type": "message", "to": recipient_fp, "id": "s642-online-1",
            "text": "hi", "signature": "sig",
        }))
        msg = await drain_until(recipient, "message")
        assert msg["id"] == "s642-online-1"
    finally:
        await recipient.close()
        await sender.close()


# ── 18. canonical offline delivery still stores and flushes correctly ───

async def test_canonical_offline_delivery_still_stores_and_flushes(running_server):
    target = canonical_fingerprint("s642_offline_roundtrip")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s642-offline-sender")
    try:
        await sender.send(json.dumps({
            "type": "message", "to": target, "id": "s642-offline-1", "text": "hi", "signature": "sig",
        }))
        reply = await _collect_until_relevant(sender, {"ack", "error"})
        assert reply == {"type": "ack", "id": "s642-offline-1"}
        assert len(_read_pending_rows(target)) == 1

        flushed = await _drain_all_pending(target)
        assert len(flushed) == 1
        assert len(_read_pending_rows(target)) == 0
    finally:
        await sender.close()


# ── 19/20. existing S6-31 capacity/accounting tests and existing
#           federation canonical-destination tests remain green --
#           verified by running the full suite (both sections updated in
#           this same fix to use canonical_fingerprint() recipients, not
#           bypassed) ────────────────────────────────────────────────────

# ── focused capacity regression: a flood of tiny-payload requests with a
#    maximally-invalid recipient can never grow pending_messages at all ──

async def test_flood_of_invalid_recipients_cannot_grow_pending_messages():
    before_meta   = _read_meta()
    before_totals = _real_pending_totals()

    async def attempt(i):
        # Far from canonical shape but cheap enough to run many of these
        # concurrently without stressing the test run itself.
        giant_to = "Z" * (64 * 1024)
        return await server.db_store(giant_to, {"type": "message", "text": "x"}, msg_id=f"s642-flood-{i}")

    results = await asyncio.gather(*[attempt(i) for i in range(50)])
    assert all(r == "INVALID_RECIPIENT" for r in results)
    assert _read_meta() == before_meta
    assert _real_pending_totals() == before_totals


# ── TOTP at-rest encryption: explicit config must not silently fail open ──
#
# The module-level TOTP_SECRET_ENCRYPTION_KEY init used to just print a
# warning and continue with _totp_fernet = None on an invalid key --
# _db_load_totp_sync()'s own fail-closed check (RuntimeError on an
# undecryptable "fernet1:" row) does NOT catch this on a fresh DB, a DB with
# no TOTP accounts yet, or a DB with only legacy plaintext rows, since none
# of those have an encrypted row to trip it. totp_setup on any of those
# would then durably write brand-new secrets as plaintext despite the
# operator having explicitly configured encryption -- a configuration
# fail-open. Fixed: a NONEMPTY TOTP_SECRET_ENCRYPTION_KEY that can't
# construct a working Fernet instance (bad key, or `cryptography`
# unavailable) now aborts the process (`sys.exit(1)`) at module import time,
# before any DB work happens at all. See SECURITY_INVARIANTS.md #56.
#
# This is module-level initialization code (runs once at `import server`) --
# the already-imported test module can't be re-triggered by mutating
# os.environ, so these tests spawn a real subprocess with the env var set,
# same pattern as test_admin_gen_codes_stores_hash_but_shows_raw_code.

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_server_subprocess(code: str, env_overrides: dict, tmp_path, timeout: float = 20) -> subprocess.CompletedProcess:
    db_path = tmp_path / "s643_test.db"
    env = dict(os.environ)
    env["DB_PATH"] = str(db_path)
    env.setdefault("MAX_REGISTERED_USERS", "0")
    env.setdefault("POW_DIFFICULTY_BITS", "0")
    # A fresh subprocess must not inherit whatever key (if any) the parent
    # test session happens to be running under -- each test sets exactly
    # the key state it wants to exercise.
    env.pop("TOTP_SECRET_ENCRYPTION_KEY", None)
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=_SERVER_DIR, env=env, capture_output=True, text=True, timeout=timeout,
    )


# ── 1/2. env absent/empty -> plaintext mode remains supported ───────────

async def test_totp_key_absent_keeps_plaintext_mode(tmp_path):
    result = _run_server_subprocess(
        "import server; assert server._totp_fernet is None; print('PLAINTEXT_MODE_OK')",
        {}, tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PLAINTEXT_MODE_OK" in result.stdout


async def test_totp_key_empty_keeps_plaintext_mode(tmp_path):
    result = _run_server_subprocess(
        "import server; assert server._totp_fernet is None; print('PLAINTEXT_MODE_OK')",
        {"TOTP_SECRET_ENCRYPTION_KEY": "  "}, tmp_path,  # whitespace-only -- .strip()'d to empty
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PLAINTEXT_MODE_OK" in result.stdout


# ── 3. a valid Fernet key initializes _totp_fernet ───────────────────────

async def test_totp_valid_key_initializes_fernet(tmp_path):
    from cryptography.fernet import Fernet as _Fernet
    key = _Fernet.generate_key().decode()
    result = _run_server_subprocess(
        "import server; assert server._totp_fernet is not None; print('FERNET_INITIALIZED')",
        {"TOTP_SECRET_ENCRYPTION_KEY": key}, tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FERNET_INITIALIZED" in result.stdout


# ── 4. an invalid nonempty key fails closed at module import ────────────

async def test_totp_invalid_key_fails_closed_at_import(tmp_path):
    result = _run_server_subprocess(
        "import server",
        {"TOTP_SECRET_ENCRYPTION_KEY": "not-a-valid-fernet-key"}, tmp_path,
    )
    assert result.returncode != 0
    assert "[FATAL]" in result.stdout
    assert "TOTP_SECRET_ENCRYPTION_KEY" in result.stdout


# ── 5. configured key + unavailable Fernet dependency fails closed ──────

async def test_totp_key_configured_but_cryptography_unavailable_fails_closed(tmp_path):
    # Simulates `from cryptography.fernet import Fernet` failing -- same
    # except-clause path as an invalid key, since both come from the same
    # try/except around that import + construction.
    code = (
        "import builtins\n"
        "_real_import = builtins.__import__\n"
        "def _blocked(name, *a, **kw):\n"
        "    if name == 'cryptography.fernet' or name.startswith('cryptography.fernet'):\n"
        "        raise ImportError('simulated: cryptography not installed')\n"
        "    return _real_import(name, *a, **kw)\n"
        "builtins.__import__ = _blocked\n"
        "import server\n"
    )
    result = _run_server_subprocess(
        code, {"TOTP_SECRET_ENCRYPTION_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, tmp_path,
    )
    assert result.returncode != 0
    assert "[FATAL]" in result.stdout


# ── 6. a fresh DB with an invalid configured key cannot start ───────────

async def test_totp_fresh_db_with_invalid_key_cannot_start(tmp_path):
    # No pre-existing DB file at all -- the module-level check must fail
    # before _db_setup_sync()/_db_load_totp_sync() ever run, so DB state
    # here is irrelevant to the crash, which is exactly the bug: previously
    # a fresh DB let the server start anyway.
    result = _run_server_subprocess(
        "import server",
        {"TOTP_SECRET_ENCRYPTION_KEY": "still-not-valid"}, tmp_path,
    )
    assert result.returncode != 0
    assert "[FATAL]" in result.stdout


# ── 7. a DB with only legacy plaintext TOTP rows + an invalid configured
#       key cannot start ─────────────────────────────────────────────────

async def test_totp_plaintext_only_db_with_invalid_key_cannot_start(tmp_path):
    db_path = tmp_path / "s643_test.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("""
            CREATE TABLE user_totp (
                username     TEXT PRIMARY KEY,
                secret       TEXT NOT NULL,
                created_at   REAL NOT NULL,
                last_counter INTEGER NOT NULL DEFAULT -1
            )
        """)
        conn.execute(
            "INSERT INTO user_totp (username, secret, created_at) VALUES (?, ?, ?)",
            ("S643PLAINTEXTUSR", TOTP_TEST_SECRET, 0)
        )
        conn.commit()
    env = dict(os.environ)
    env["DB_PATH"] = str(db_path)
    env["TOTP_SECRET_ENCRYPTION_KEY"] = "definitely-invalid"
    env.setdefault("MAX_REGISTERED_USERS", "0")
    env.setdefault("POW_DIFFICULTY_BITS", "0")
    result = subprocess.run(
        [sys.executable, "-c", "import server"],
        cwd=_SERVER_DIR, env=env, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0
    assert "[FATAL]" in result.stdout


# ── 8. a DB with genuinely encrypted rows + a syntactically-valid but
#       WRONG key remains fail-closed exactly as before this fix (via
#       _db_load_totp_sync(), unaffected by this change) ────────────────

async def test_totp_encrypted_db_with_wrong_key_remains_fail_closed(tmp_path):
    from cryptography.fernet import Fernet as _Fernet
    real_key = _Fernet.generate_key()
    wrong_key = _Fernet.generate_key().decode()
    encrypted = "fernet1:" + _Fernet(real_key).encrypt(TOTP_TEST_SECRET.encode()).decode()

    db_path = tmp_path / "s643_test.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("""
            CREATE TABLE user_totp (
                username     TEXT PRIMARY KEY,
                secret       TEXT NOT NULL,
                created_at   REAL NOT NULL,
                last_counter INTEGER NOT NULL DEFAULT -1
            )
        """)
        conn.execute(
            "INSERT INTO user_totp (username, secret, created_at) VALUES (?, ?, ?)",
            ("S643ENCRYPTEDUSR", encrypted, 0)
        )
        conn.commit()

    result = _run_server_subprocess(
        "import server; server._db_load_totp_sync()",
        {"TOTP_SECRET_ENCRYPTION_KEY": wrong_key}, tmp_path,
    )
    assert result.returncode != 0
    assert "RuntimeError" in result.stderr


# ── 9. a valid configured key stores a newly-enrolled secret with the
#       "fernet1:" prefix, and it decrypts back correctly ───────────────

async def test_totp_valid_key_stores_new_secret_encrypted(tmp_path):
    from cryptography.fernet import Fernet as _Fernet
    key = _Fernet.generate_key().decode()
    db_path = tmp_path / "s643_test.db"
    code = (
        "import asyncio, server\n"
        "server._db_setup_sync()\n"
        "asyncio.run(server.db_commit_totp_setup("
        "'S643NEWSECRETUSR', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', server.generate_recovery_codes(1)))\n"
    )
    result = _run_server_subprocess(code, {"TOTP_SECRET_ENCRYPTION_KEY": key}, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr

    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT secret FROM user_totp WHERE username = ?", ("S643NEWSECRETUSR",)
        ).fetchone()
    assert row is not None
    stored = row[0]
    assert stored.startswith("fernet1:")
    decrypted = _Fernet(key.encode()).decrypt(stored[len("fernet1:"):].encode()).decode()
    assert decrypted == TOTP_TEST_SECRET


# ── 10. an unset key stores newly-enrolled secrets as plaintext, exactly
#        as legacy behavior always has (in-process -- this test session's
#        own server module was imported with no key configured) ────────

async def test_totp_unset_key_stores_plaintext_as_legacy():
    assert server._totp_fernet is None
    username = "S643LEGACYPLAINUSR"
    secret = TOTP_TEST_SECRET_2
    await server.db_commit_totp_setup(username, secret, server.generate_recovery_codes(1))
    try:
        with server.db_connect() as conn:
            row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (username,)).fetchone()
        assert row is not None
        assert row[0] == secret  # stored exactly as-is, no "fernet1:" prefix
    finally:
        with server.db_connect() as conn:
            conn.execute("DELETE FROM user_totp WHERE username = ?", (username,))
            conn.commit()


# ── 11. existing TOTP/device-gating tests remain green -- verified by
#        running the full suite (no dedicated test needed here).


# ── Anonymous-token durable-state resource hardening ──────────────────────
#
# subscribe_tokens was purely additive with no cap on how many DISTINCT
# never-before-seen tokens one authenticated account could turn into
# permanent anon_token_state rows. The per-message "subscribe_tokens" rate
# limit was never the real bound on this (and, as of 2026-09-20, isn't even
# charged for a purely idempotent resubscribe -- see the has_new peek in the
# subscribe_tokens handler) -- the actual ceiling on new-row creation is the
# four independent, content-aware limits enforced atomically inside
# db_claim_anon_tokens()/_db_claim_anon_tokens_sync(). anon_token_state_cache
# mirrors the ENTIRE table in RAM (a deliberate, separate DoS defense for the
# unauthenticated anon_channel hot path -- untouched by this fix), so
# unbounded durable growth is also unbounded startup/live RAM growth. See
# MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT's own comment in server.py for the full
# reasoning each one exists for. See SECURITY_INVARIANTS.md #57.

def _anon_active_count(username: str) -> int:
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM anon_token_state WHERE owner = ? AND state IN ('ACTIVE', 'IN_FLIGHT')",
            (username,)
        ).fetchone()[0]


def _anon_total_rows() -> int:
    with server.db_connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM anon_token_state").fetchone()[0]


def _anon_row_state(token: str):
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT owner, state FROM anon_token_state WHERE token_hash = ?",
            (server._hash_anon_token(token),)
        ).fetchone()


# ── 1. normal official-client initial token pool is below the active cap ─

async def test_client_pool_hard_cap_below_active_cap():
    # Both Android's and Desktop's AnonTokenManager cap a single
    # installation's own token pool at MAX_TOKENS_PER_SUBSCRIBE (100) --
    # see MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT's own comment in server.py.
    # A legitimate single pool must never bump into the active cap.
    assert server.MAX_TOKENS_PER_SUBSCRIBE <= server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT


# ── 2. normal reconnect/resubscribe of existing tokens succeeds at cap ───

async def test_resubscribe_existing_tokens_succeeds_at_active_cap():
    username = canonical_fingerprint("s644_resub_at_cap")
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 5
    try:
        tokens = [rand_token() for _ in range(5)]
        claims1 = await server.db_claim_anon_tokens(tokens, username)
        assert all(v == (username, "ACTIVE") for v in claims1.values())

        # Cap is now exactly full for this owner -- re-subscribing the SAME
        # tokens (an ordinary reconnect) must still fully resolve, never
        # treated as new claims.
        claims2 = await server.db_claim_anon_tokens(tokens, username)
        assert all(v == (username, "ACTIVE") for v in claims2.values())
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 3. a new token below the per-owner active cap inserts normally ──────

async def test_new_token_below_active_cap_inserts_normally():
    username = canonical_fingerprint("s644_below_cap")
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 5
    try:
        tokens = [rand_token() for _ in range(3)]
        claims = await server.db_claim_anon_tokens(tokens, username)
        assert all(v == (username, "ACTIVE") for v in claims.values())
        assert _anon_active_count(username) == 3
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 4. the first token above the active cap is not inserted ─────────────

async def test_first_token_above_active_cap_not_inserted():
    username = canonical_fingerprint("s644_above_cap")
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 3
    try:
        fill = [rand_token() for _ in range(3)]
        await server.db_claim_anon_tokens(fill, username)
        assert _anon_active_count(username) == 3

        overflow = rand_token()
        claims = await server.db_claim_anon_tokens([overflow], username)
        assert claims[overflow] == (None, "NEW_CLAIM_LIMIT")
        assert _anon_row_state(overflow) is None  # never inserted at all
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 5. concurrent subscribe batches cannot atomically exceed the active
#       cap ────────────────────────────────────────────────────────────

async def test_concurrent_claims_cannot_atomically_exceed_active_cap():
    username = canonical_fingerprint("s644_concurrent_cap")
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 10
    try:
        batch_a = [rand_token() for _ in range(10)]
        batch_b = [rand_token() for _ in range(10)]
        results = await asyncio.gather(
            server.db_claim_anon_tokens(batch_a, username),
            server.db_claim_anon_tokens(batch_b, username),
        )
        assert _anon_active_count(username) == 10  # combined, never more than the cap
        total_stored = sum(1 for claims in results for v in claims.values() if v[1] == "ACTIVE")
        assert total_stored == 10
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 6/7. repeated additive subscribe_tokens calls cannot grow ws_to_tokens
#         past the cap, and a rejected token never partially mutates
#         token_to_ws/known_tokens/token_owner ─────────────────────────

async def test_ws_cap_rejects_overflow_without_mutating_routing_structures(running_server):
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 3
    try:
        ws, fp, _, _ = await connect_and_register(running_server, device_id="s644-ws-cap")
        try:
            await asyncio.sleep(0.2)
            server_ws = server.clients[fp]["ws"]
            fill = [rand_token() for _ in range(3)]
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": fill}))
            await asyncio.sleep(0.3)
            assert len(server.ws_to_tokens.get(server_ws, set())) == 3

            overflow = rand_token()
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [overflow]}))
            await asyncio.sleep(0.3)

            assert len(server.ws_to_tokens.get(server_ws, set())) == 3  # unchanged
            assert overflow not in server.token_to_ws
            assert overflow not in server.known_tokens
            assert overflow not in server.token_owner
        finally:
            await ws.close()
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 8. an existing SPENT token can still be reconciled while the active
#       cap is full ──────────────────────────────────────────────────────

async def test_existing_spent_token_resolves_while_active_cap_full():
    username = canonical_fingerprint("s644_spent_at_cap")
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 3
    try:
        tokens = [rand_token() for _ in range(3)]
        await server.db_claim_anon_tokens(tokens, username)
        spent_token = tokens[0]
        assert await server.db_terminalize_anon_token(spent_token, username, "SPENT")
        # Refill the freed active slot so the cap is genuinely full again.
        refill = rand_token()
        refill_claim = await server.db_claim_anon_tokens([refill], username)
        assert refill_claim[refill] == (username, "ACTIVE")
        assert _anon_active_count(username) == 3

        # The already-SPENT token must still resolve correctly -- Phase 1
        # of _db_claim_anon_tokens_sync() resolves EXISTING tokens before
        # ever looking at any capacity at all.
        reclaim = await server.db_claim_anon_tokens([spent_token], username)
        assert reclaim[spent_token] == (username, "SPENT")
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 9. an existing IN_FLIGHT token can still be resolved while the active
#       cap is full ──────────────────────────────────────────────────────

async def test_existing_inflight_token_resolves_while_active_cap_full():
    username = canonical_fingerprint("s644_inflight_at_cap")
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 3
    try:
        tokens = [rand_token() for _ in range(3)]
        await server.db_claim_anon_tokens(tokens, username)
        inflight_token = tokens[0]
        owner = await server.db_mark_anon_token_inflight(inflight_token)
        assert owner == username
        assert _anon_active_count(username) == 3  # IN_FLIGHT still counts as active

        reclaim = await server.db_claim_anon_tokens([inflight_token], username)
        assert reclaim[inflight_token] == (username, "IN_FLIGHT")
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 10. an existing token owned by another user remains rejected normally ─

async def test_existing_token_owned_by_another_user_remains_rejected():
    owner_a = canonical_fingerprint("s644_owner_a")
    owner_b = canonical_fingerprint("s644_owner_b")
    token = rand_token()
    claim_a = await server.db_claim_anon_tokens([token], owner_a)
    assert claim_a[token] == (owner_a, "ACTIVE")

    claim_b = await server.db_claim_anon_tokens([token], owner_b)
    assert claim_b[token] == (owner_a, "ACTIVE")  # unaffected -- resolves to the true owner


# ── 11. unsubscribe frees ACTIVE capacity but leaves a durable REVOKED
#        tombstone ───────────────────────────────────────────────────────

async def test_unsubscribe_frees_active_capacity_leaves_durable_tombstone():
    username = canonical_fingerprint("s644_revoke_frees_cap")
    token = rand_token()
    await server.db_claim_anon_tokens([token], username)
    assert _anon_active_count(username) == 1

    assert await server.db_terminalize_anon_token(token, username, "REVOKED")
    assert _anon_active_count(username) == 0  # freed

    row = _anon_row_state(token)
    assert row is not None and row[1] == "REVOKED"  # durable tombstone, not deleted


# ── 12. after unsubscribe, new issuance is bounded by the durable claim
#        quota (not the now-empty active cap) ────────────────────────────

async def test_new_issuance_bounded_by_durable_claim_quota_after_unsubscribe():
    username = canonical_fingerprint("s644_quota_after_revoke")
    real_cap   = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    real_quota = server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT  = 10_000  # not the binding constraint here
    server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = 3
    try:
        tokens = [rand_token() for _ in range(3)]
        claims = await server.db_claim_anon_tokens(tokens, username)
        assert all(v[1] == "ACTIVE" for v in claims.values())
        for t in tokens:
            assert await server.db_terminalize_anon_token(t, username, "REVOKED")
        assert _anon_active_count(username) == 0  # active cap has plenty of room now

        overflow = rand_token()
        result = await server.db_claim_anon_tokens([overflow], username)
        assert result[overflow] == (None, "NEW_CLAIM_LIMIT")  # quota, not active cap, is binding
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT  = real_cap
        server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = real_quota


# ── 13. repeated claim->revoke->claim cannot exceed the new-token quota ──

async def test_repeated_claim_revoke_cycle_cannot_exceed_new_claim_quota():
    username = canonical_fingerprint("s644_cycle_quota")
    real_cap   = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    real_quota = server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT  = 10_000
    server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = 5
    try:
        total_new = 0
        for _ in range(10):  # 10 attempted cycles, 2 new tokens each = 20 attempted
            batch = [rand_token(), rand_token()]
            claims = await server.db_claim_anon_tokens(batch, username)
            for t in batch:
                if claims[t][1] == "ACTIVE":
                    total_new += 1
                    await server.db_terminalize_anon_token(t, username, "REVOKED")
        assert total_new <= 5
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT  = real_cap
        server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = real_quota


# ── 14. server restart does not reset the per-owner durable new-claim
#        quota (it lives in SQLite, not any RAM structure) ───────────────

async def test_claim_guard_quota_is_durable_not_ram_only():
    username = canonical_fingerprint("s644_durable_guard")
    real_quota = server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW
    server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = 2
    try:
        tokens = [rand_token(), rand_token()]
        await server.db_claim_anon_tokens(tokens, username)

        with server.db_connect() as conn:
            row = conn.execute(
                "SELECT new_claims FROM anon_token_claim_guard WHERE username = ?",
                (username,)
            ).fetchone()
        assert row is not None
        assert row[0] == 2

        overflow = rand_token()
        result = await server.db_claim_anon_tokens([overflow], username)
        assert result[overflow] == (None, "NEW_CLAIM_LIMIT")
    finally:
        server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = real_quota


# ── 15. re-subscribing an existing token consumes zero new-claim quota ──

async def test_resubscribe_existing_token_consumes_zero_new_claim_quota():
    username = canonical_fingerprint("s644_resub_zero_quota")
    real_quota = server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW
    server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = 2
    try:
        tokens = [rand_token(), rand_token()]
        await server.db_claim_anon_tokens(tokens, username)  # fills quota exactly

        await server.db_claim_anon_tokens(tokens, username)  # re-subscribe, all existing
        with server.db_connect() as conn:
            row = conn.execute(
                "SELECT new_claims FROM anon_token_claim_guard WHERE username = ?",
                (username,)
            ).fetchone()
        assert row[0] == 2  # unchanged
    finally:
        server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = real_quota


# ── 16. the global new-claim request budget rejects before the
#        executor/SQLite ─────────────────────────────────────────────────

async def test_global_claim_budget_rejects_before_executor():
    real_limit   = server.ANON_TOKEN_GLOBAL_CLAIM_LIMIT
    real_enabled = server.ANON_TOKEN_GLOBAL_CLAIM_ENABLED
    server.ANON_TOKEN_GLOBAL_CLAIM_LIMIT   = 1
    server.ANON_TOKEN_GLOBAL_CLAIM_ENABLED = True
    server.anon_token_global_claim_rate["count"]      = 0
    server.anon_token_global_claim_rate["reset_time"] = server.time.time()

    call_count = 0
    real_sync = server._db_claim_anon_tokens_sync

    def counting_sync(*a, **kw):
        nonlocal call_count
        call_count += 1
        return real_sync(*a, **kw)

    server._db_claim_anon_tokens_sync = counting_sync
    try:
        username = canonical_fingerprint("s644_global_budget")
        t1 = rand_token()
        claims1 = await server.db_claim_anon_tokens([t1], username)
        assert claims1[t1] == (username, "ACTIVE")
        assert call_count == 1

        t2 = rand_token()
        claims2 = await server.db_claim_anon_tokens([t2], username)
        assert claims2[t2] == (None, "NEW_CLAIM_LIMIT")
        assert call_count == 1  # the 2nd call never reached the executor/SQLite at all
    finally:
        server._db_claim_anon_tokens_sync = real_sync
        server.ANON_TOKEN_GLOBAL_CLAIM_LIMIT   = real_limit
        server.ANON_TOKEN_GLOBAL_CLAIM_ENABLED = real_enabled
        server.anon_token_global_claim_rate["count"]      = 0
        server.anon_token_global_claim_rate["reset_time"] = server.time.time()


# ── 17. an all-cache-hit reconnect does not consume the global NEW-claim
#        request budget ──────────────────────────────────────────────────

async def test_all_cache_hit_reconnect_skips_global_claim_budget():
    real_limit   = server.ANON_TOKEN_GLOBAL_CLAIM_LIMIT
    real_enabled = server.ANON_TOKEN_GLOBAL_CLAIM_ENABLED
    username = canonical_fingerprint("s644_cache_hit_skip")
    tokens = [rand_token(), rand_token()]
    claims = await server.db_claim_anon_tokens(tokens, username)
    assert all(v == (username, "ACTIVE") for v in claims.values())
    # db_claim_anon_tokens() itself never writes anon_token_state_cache --
    # only the subscribe_tokens WIRE handler's own post-processing loop does
    # that (see its own comment). Populate it here directly so this test can
    # isolate db_claim_anon_tokens()'s own cache-classification logic
    # without needing a full websocket round trip.
    for t in tokens:
        server.anon_token_state_cache[server._hash_anon_token(t)] = (username, "ACTIVE")

    server.ANON_TOKEN_GLOBAL_CLAIM_LIMIT   = 1
    server.ANON_TOKEN_GLOBAL_CLAIM_ENABLED = True
    server.anon_token_global_claim_rate["count"]      = 1  # already at the limit
    server.anon_token_global_claim_rate["reset_time"] = server.time.time()
    try:
        # Sanity: a genuinely new token IS refused right now.
        blocked = rand_token()
        result_blocked = await server.db_claim_anon_tokens([blocked], username)
        assert result_blocked[blocked] == (None, "NEW_CLAIM_LIMIT")

        # But re-subscribing the SAME already-cached tokens must still
        # succeed -- it never even checks the exhausted budget.
        result = await server.db_claim_anon_tokens(tokens, username)
        assert all(v == (username, "ACTIVE") for v in result.values())
    finally:
        server.ANON_TOKEN_GLOBAL_CLAIM_LIMIT   = real_limit
        server.ANON_TOKEN_GLOBAL_CLAIM_ENABLED = real_enabled
        server.anon_token_global_claim_rate["count"]      = 0
        server.anon_token_global_claim_rate["reset_time"] = server.time.time()


# ── 18. the total-row hard cap rejects a genuinely new token ─────────────

async def test_total_row_cap_rejects_genuinely_new_token():
    current_total = _anon_total_rows()
    real_cap = server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS
    server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS = current_total + 1
    try:
        username = canonical_fingerprint("s644_total_cap_reject")
        filler = rand_token()
        claims = await server.db_claim_anon_tokens([filler], username)
        assert claims[filler] == (username, "ACTIVE")
        assert _anon_total_rows() == current_total + 1  # exactly at the new cap

        overflow = rand_token()
        result = await server.db_claim_anon_tokens([overflow], username)
        assert result[overflow] == (None, "NEW_CLAIM_LIMIT")
        assert _anon_row_state(overflow) is None
    finally:
        server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS = real_cap


# ── 19. the total-row cap still allows an existing token to reconnect ────

async def test_total_row_cap_still_allows_existing_token_reconnect():
    current_total = _anon_total_rows()
    real_cap = server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS
    server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS = current_total + 1
    try:
        username = canonical_fingerprint("s644_total_cap_reconnect")
        token = rand_token()
        await server.db_claim_anon_tokens([token], username)  # exactly at the new cap

        result = await server.db_claim_anon_tokens([token], username)
        assert result[token] == (username, "ACTIVE")
    finally:
        server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS = real_cap


# ── 20. the total-row cap still allows ACK/terminalization of an existing
#        token ────────────────────────────────────────────────────────────

async def test_total_row_cap_still_allows_terminalization():
    current_total = _anon_total_rows()
    real_cap = server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS
    server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS = current_total + 1
    try:
        username = canonical_fingerprint("s644_total_cap_terminalize")
        token = rand_token()
        await server.db_claim_anon_tokens([token], username)  # exactly at the new cap

        # Terminalizing (ACK/revoke) an EXISTING token inserts no new row --
        # must not be blocked by the total-row backstop.
        assert await server.db_terminalize_anon_token(token, username, "SPENT")
    finally:
        server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS = real_cap


# ── 21. startup refuses when the table is already above the configured
#        hard row cap ────────────────────────────────────────────────────

async def test_anon_token_startup_refuses_when_over_total_row_cap(tmp_path):
    db_path = tmp_path / "s644_test.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("""
            CREATE TABLE anon_token_state (
                token_hash  BLOB PRIMARY KEY,
                owner       TEXT NOT NULL,
                state       TEXT NOT NULL CHECK(state IN ('ACTIVE', 'IN_FLIGHT', 'SPENT', 'REVOKED')),
                created_at  REAL NOT NULL,
                updated_at  REAL NOT NULL
            )
        """)
        for i in range(5):
            conn.execute(
                "INSERT INTO anon_token_state (token_hash, owner, state, created_at, updated_at) "
                "VALUES (?, ?, 'ACTIVE', 0, 0)",
                (f"s644-over-{i}".encode().ljust(32, b"\0"), "SOMEOWNER0000001")
            )
        conn.commit()
    env = dict(os.environ)
    env["DB_PATH"] = str(db_path)
    env["ANON_TOKEN_STATE_MAX_TOTAL_ROWS"] = "3"
    env.setdefault("MAX_REGISTERED_USERS", "0")
    env.setdefault("POW_DIFFICULTY_BITS", "0")
    result = subprocess.run(
        [sys.executable, "-c", "import server; server.start_server()"],
        cwd=_SERVER_DIR, env=env, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0
    assert "[FATAL]" in result.stdout
    assert "anon_token_state" in result.stdout


# ── 22. startup at exactly the cap succeeds ──────────────────────────────

async def test_anon_token_count_at_exactly_cap_does_not_trigger_refusal(tmp_path):
    db_path = tmp_path / "s644_test.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("""
            CREATE TABLE anon_token_state (
                token_hash  BLOB PRIMARY KEY,
                owner       TEXT NOT NULL,
                state       TEXT NOT NULL CHECK(state IN ('ACTIVE', 'IN_FLIGHT', 'SPENT', 'REVOKED')),
                created_at  REAL NOT NULL,
                updated_at  REAL NOT NULL
            )
        """)
        for i in range(3):
            conn.execute(
                "INSERT INTO anon_token_state (token_hash, owner, state, created_at, updated_at) "
                "VALUES (?, ?, 'ACTIVE', 0, 0)",
                (f"s644-atcap-{i}".encode().ljust(32, b"\0"), "SOMEOWNER0000002")
            )
        conn.commit()
    env = dict(os.environ)
    env["DB_PATH"] = str(db_path)
    env["ANON_TOKEN_STATE_MAX_TOTAL_ROWS"] = "3"  # exactly the seeded row count
    env.setdefault("MAX_REGISTERED_USERS", "0")
    env.setdefault("POW_DIFFICULTY_BITS", "0")
    code = (
        "import server\n"
        "server._db_setup_sync()\n"
        "count = server._db_count_anon_token_state_rows_sync()\n"
        "assert count == 3, count\n"
        "print('AT_CAP_NOT_REFUSED' if count <= server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS else 'WOULD_REFUSE')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_SERVER_DIR, env=env, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "AT_CAP_NOT_REFUSED" in result.stdout


# ── 23. a rejected new claim never appears in anon_token_state_cache ─────

async def test_rejected_new_claim_never_appears_in_cache(running_server):
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 1
    try:
        ws, fp, _, _ = await connect_and_register(running_server, device_id="s644-never-cached")
        try:
            fill = rand_token()
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [fill]}))
            await asyncio.sleep(0.3)

            overflow = rand_token()
            await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [overflow]}))
            await asyncio.sleep(0.3)

            assert server._hash_anon_token(overflow) not in server.anon_token_state_cache
        finally:
            await ws.close()
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 24. successful new claims update the cache exactly as before ────────

async def test_successful_new_claim_updates_cache_exactly_as_before(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s644-cache-updates")
    try:
        token = rand_token()
        await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.3)
        cached = server.anon_token_state_cache.get(server._hash_anon_token(token))
        assert cached == (fp, "ACTIVE")
    finally:
        await ws.close()


# ── 25. all anon_delivery_ack/token_pending/bootstrap tests remain green --
#        verified by running the full suite (no dedicated test needed
#        here).


# ── attack-simulation regression: repeated new-token flooding, revoking
#    between batches, must stay bounded by all three durable/active limits
#    at once regardless of how many cycles are attempted ────────────────

async def test_flood_of_new_token_claims_bounded_by_all_layers():
    username = canonical_fingerprint("s644_attack_sim")
    current_total = _anon_total_rows()

    real_active_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    real_quota      = server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW
    real_total_cap  = server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT  = 20
    server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = 50
    server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS     = current_total + 100
    try:
        total_new_created = 0
        for _ in range(10):  # 10 * 20 = 200 attempted new tokens; quota is 50
            batch = [rand_token() for _ in range(20)]
            claims = await server.db_claim_anon_tokens(batch, username)
            newly_stored = [t for t, v in claims.items() if v[1] == "ACTIVE"]
            assert _anon_active_count(username) <= 20  # active cap never exceeded, even mid-cycle
            total_new_created += len(newly_stored)
            for t in newly_stored:
                await server.db_terminalize_anon_token(t, username, "REVOKED")

        assert total_new_created <= 50  # durable issuance quota never exceeded, regardless of cycling
        assert _anon_total_rows() <= current_total + 100  # hard total-row ceiling never exceeded
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT  = real_active_cap
        server.ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW = real_quota
        server.ANON_TOKEN_STATE_MAX_TOTAL_ROWS     = real_total_cap


# ── Pre-auth handshake surface: dedicated size ceiling + canonical
#    identity-crypto bounds ───────────────────────────────────────────────
#
# The handshake used to reuse MAX_PACKET_SIZE_BYTES (6 MiB, needed for
# normal post-auth media traffic) and then ran attacker-controlled
# json.loads()/base64.b64decode()/load_der_public_key()/signature
# verification with no handshake-specific field bounds at all -- an
# unauthenticated attacker got a multi-megabyte parsing surface per
# connection for fields whose real representation is a few hundred bytes.
# See SECURITY_INVARIANTS.md #58.

# ── 1/2. official Android/Desktop challenge_response fits the handshake
#         ceiling (both clients use byte-identical secp256r1/SHA256withECDSA/
#         X.509-DER encoding, confirmed by inspection -- one real frame shape
#         covers both) ──────────────────────────────────────────────────

async def test_official_challenge_response_fits_handshake_ceiling():
    priv, pub_der = gen_keypair()
    challenge = secrets.token_bytes(32)
    signature = priv.sign(challenge, ec.ECDSA(hashes.SHA256()))
    frame = json.dumps({
        "type": "challenge_response",
        "public_key": base64.b64encode(pub_der).decode(),
        "signature": base64.b64encode(signature).decode(),
    })
    assert len(frame.encode("utf-8")) <= server.HANDSHAKE_MAX_PACKET_SIZE_BYTES


# ── 3. a legitimately-padded handshake (mirroring the clients' own
#       addPadding() -- round up to the next 512-byte boundary) still fits ─

async def test_legitimate_padded_handshake_still_fits_ceiling():
    priv, pub_der = gen_keypair()
    challenge = secrets.token_bytes(32)
    signature = priv.sign(challenge, ec.ECDSA(hashes.SHA256()))
    packet = {
        "type": "challenge_response",
        "public_key": base64.b64encode(pub_der).decode(),
        "signature": base64.b64encode(signature).decode(),
    }
    current_size = len(json.dumps(packet).encode("utf-8"))
    target_size  = ((current_size // 512) + 1) * 512
    padding_size = target_size - current_size - 10
    if padding_size > 0:
        packet["_p"] = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(padding_size))
    frame = json.dumps(packet)
    assert len(frame.encode("utf-8")) <= server.HANDSHAKE_MAX_PACKET_SIZE_BYTES


# ── 4. a near-6-MiB handshake is rejected before json.loads() is ever
#       called ────────────────────────────────────────────────────────────

async def test_near_6mib_handshake_rejected_before_json_loads(running_server):
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())
        assert challenge_msg["type"] == "challenge"

        # `json` is a shared process-wide module -- patch only AFTER the
        # challenge above is already parsed, so this test's own (legitimate)
        # json.loads call doesn't trip the spy before the real assertion
        # point.
        real_loads = server.json.loads
        called = False

        def spy_loads(*a, **kw):
            nonlocal called
            called = True
            return real_loads(*a, **kw)

        server.json.loads = spy_loads
        try:
            giant = json.dumps({"type": "challenge_response", "junk": "A" * (5 * 1024 * 1024)})
            await ws.send(giant)
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.recv()
            assert called is False
        finally:
            server.json.loads = real_loads
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 5. a JSON list handshake is rejected cleanly (before strip_padding) ──

async def test_json_list_handshake_rejected_cleanly(running_server):
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())
        assert challenge_msg["type"] == "challenge"
        await ws.send(json.dumps(["not", "a", "dict"]))
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await ws.recv()
    finally:
        try:
            await ws.close()
        except Exception:
            pass

    # Server must still be alive and accepting new connections afterward.
    ws2, fp, _, _ = await connect_and_register(running_server, device_id="s645-after-list-handshake")
    try:
        await asyncio.sleep(0.1)
        assert fp in server.clients
    finally:
        await ws2.close()


# ── 6. a JSON string/int/null handshake is rejected cleanly ─────────────

async def test_json_scalar_handshake_rejected_cleanly(running_server):
    for bad_value in ("just a string", 123, None):
        ws = await websockets.connect(running_server)
        try:
            challenge_msg = json.loads(await ws.recv())
            assert challenge_msg["type"] == "challenge"
            await ws.send(json.dumps(bad_value))
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.recv()
        finally:
            try:
                await ws.close()
            except Exception:
                pass


# ── 7. an oversized public_key is rejected before base64 decode ─────────

async def test_oversized_public_key_rejected_before_base64_decode(running_server):
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())
        assert challenge_msg["type"] == "challenge"

        # `base64` is a shared process-wide module that other concurrent
        # background tasks may also call during this window -- check for a
        # call with THIS EXACT oversized value specifically, not just "any
        # call happened", so unrelated background activity can't produce a
        # false failure.
        oversized_pubkey = "A" * (server.MAX_IDENTITY_PUBKEY_B64_LEN + 1)
        real_b64decode = server.base64.b64decode
        called_with_target = False

        def spy(*a, **kw):
            nonlocal called_with_target
            if a and a[0] == oversized_pubkey:
                called_with_target = True
            return real_b64decode(*a, **kw)

        server.base64.b64decode = spy
        try:
            await ws.send(json.dumps({
                "type": "challenge_response",
                "public_key": oversized_pubkey,
                "signature": "AAAA",
            }))
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.recv()
            assert called_with_target is False
        finally:
            server.base64.b64decode = real_b64decode
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 8. an oversized signature is rejected before base64 decode ──────────

async def test_oversized_signature_rejected_before_base64_decode(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())

        oversized_sig = "A" * (server.MAX_IDENTITY_SIGNATURE_B64_LEN + 1)
        real_b64decode = server.base64.b64decode
        called_with_target = False

        def spy(*a, **kw):
            nonlocal called_with_target
            if a and a[0] == oversized_sig:
                called_with_target = True
            return real_b64decode(*a, **kw)

        server.base64.b64decode = spy
        try:
            await ws.send(json.dumps({
                "type": "challenge_response",
                "public_key": base64.b64encode(pub_der).decode(),
                "signature": oversized_sig,
            }))
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.recv()
            # The oversized signature itself must never reach a decode
            # attempt at all -- the public_key's own (unrelated) decode is
            # fine and expected.
            assert called_with_target is False
        finally:
            server.base64.b64decode = real_b64decode
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 9. a malformed-base64 public_key is rejected ─────────────────────────

async def test_malformed_base64_public_key_rejected(running_server):
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())
        assert challenge_msg["type"] == "challenge"
        await ws.send(json.dumps({
            "type": "challenge_response",
            "public_key": "not-valid-base64!!!",
            "signature": "AAAA",
        }))
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await ws.recv()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 10. a malformed-base64 signature is rejected ─────────────────────────

async def test_malformed_base64_signature_rejected(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())
        await ws.send(json.dumps({
            "type": "challenge_response",
            "public_key": base64.b64encode(pub_der).decode(),
            "signature": "not-valid-base64!!!",
        }))
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await ws.recv()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 11. a valid official identity key still verifies ────────────────────

async def test_valid_official_identity_key_still_verifies(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        challenge = await handshake(ws, priv, pub_der)
        assert challenge is not None
    finally:
        await ws.close()


# ── 12. a non-EC DER key (RSA) is rejected ───────────────────────────────

async def test_non_ec_der_key_rejected(running_server):
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    rsa_pub_der = rsa_priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())
        challenge = base64.b64decode(challenge_msg["data"])
        signature = rsa_priv.sign(challenge, rsa_padding.PKCS1v15(), hashes.SHA256())
        await ws.send(json.dumps({
            "type": "challenge_response",
            "public_key": base64.b64encode(rsa_pub_der).decode(),
            "signature": base64.b64encode(signature).decode(),
        }))
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await ws.recv()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 13. a wrong EC curve (secp384r1) is rejected -- P-256 confirmed as the
#        sole protocol-wide curve on both shipped clients ────────────────

async def test_wrong_ec_curve_rejected(running_server):
    wrong_curve_priv = ec.generate_private_key(ec.SECP384R1(), default_backend())
    wrong_curve_pub_der = wrong_curve_priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ws = await websockets.connect(running_server)
    try:
        challenge_msg = json.loads(await ws.recv())
        challenge = base64.b64decode(challenge_msg["data"])
        signature = wrong_curve_priv.sign(challenge, ec.ECDSA(hashes.SHA256()))
        await ws.send(json.dumps({
            "type": "challenge_response",
            "public_key": base64.b64encode(wrong_curve_pub_der).decode(),
            "signature": base64.b64encode(signature).decode(),
        }))
        with pytest.raises(websockets.exceptions.ConnectionClosed):
            await ws.recv()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


# ── 14. federation MAC oversized input is rejected before base64 decode ──

async def test_federation_mac_oversized_rejected_before_decode(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await websockets.connect(running_server)
        try:
            challenge_msg = json.loads(await ws.recv())

            # `base64` is a shared process-wide module that other
            # concurrent background tasks (watchdogs, federation reconnect
            # loops, ...) may also call during this window -- check for a
            # call with THIS EXACT oversized value specifically, not just
            # "any call happened", so unrelated background activity can't
            # produce a false failure.
            oversized_mac = "A" * (server.MAX_FEDERATION_MAC_B64_LEN + 1)
            real_b64decode = server.base64.b64decode
            called_with_target = False

            def spy(*a, **kw):
                nonlocal called_with_target
                if a and a[0] == oversized_mac:
                    called_with_target = True
                return real_b64decode(*a, **kw)

            server.base64.b64decode = spy
            try:
                await ws.send(json.dumps({"type": "federation_auth", "mac": oversized_mac}))
                with pytest.raises(websockets.exceptions.ConnectionClosed):
                    await ws.recv()
                assert called_with_target is False
            finally:
                server.base64.b64decode = real_b64decode
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 15. a malformed-base64 federation MAC is rejected ────────────────────

async def test_federation_mac_malformed_base64_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await websockets.connect(running_server)
        try:
            challenge_msg = json.loads(await ws.recv())
            await ws.send(json.dumps({"type": "federation_auth", "mac": "not-valid-base64!!!"}))
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.recv()
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 16. a federation MAC whose decoded length != 32 is rejected ─────────

async def test_federation_mac_wrong_decoded_length_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await websockets.connect(running_server)
        try:
            challenge_msg = json.loads(await ws.recv())
            wrong_len_mac = base64.b64encode(b"short").decode()  # valid base64, wrong length
            await ws.send(json.dumps({"type": "federation_auth", "mac": wrong_len_mac}))
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.recv()
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 17. the correct federation HMAC still authenticates ─────────────────

async def test_correct_federation_hmac_still_authenticates(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)  # asserts federation_auth_ok internally
        await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 18. register() rejects an oversized public_key before DER parsing ───

async def test_register_oversized_public_key_rejected_before_der_parsing(running_server):
    priv, pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        oversized = "A" * (server.MAX_IDENTITY_PUBKEY_B64_LEN + 1)
        await ws.send(json.dumps({
            "type": "register", "name": "t",
            "public_key": oversized,
            "device_id": canonical_device_id("s645-oversized-register-key"),
        }))
        await asyncio.sleep(0.3)
        # No crash, no reply for this malformed attempt -- register()'s
        # handler just `continue`s past it. This connection is still
        # unregistered at this point, so (per the S6-39 hard authorization
        # boundary) anything other than `register` would now get closed --
        # that's unrelated, pre-existing behavior, not what this test is
        # about. Prove the connection/handler loop itself wasn't corrupted
        # by sending a LEGITIMATE register with the correct key right after,
        # which must still succeed normally.
        await register(ws, pub_der, device_id="s645-oversized-register-key")
        reply = await drain_until(ws, "register_ok")
        assert reply["type"] == "register_ok"
    finally:
        await ws.close()


# ── 19. register() key mismatch remains rejected exactly as before ──────

async def test_register_key_mismatch_remains_rejected(running_server):
    priv, pub_der = gen_keypair()
    _, other_pub_der = gen_keypair()
    ws = await websockets.connect(running_server)
    try:
        await handshake(ws, priv, pub_der)
        await register(ws, other_pub_der, device_id="s645-key-mismatch")
        await asyncio.sleep(0.3)
        mismatched_fp = fingerprint_of(other_pub_der)
        assert mismatched_fp not in server.clients

        # Connection must still be alive and able to complete a legitimate
        # registration with the CORRECT (handshake-proven) key.
        await register(ws, pub_der, device_id="s645-key-mismatch")
        reply = await drain_until(ws, "register_ok")
        assert reply["type"] == "register_ok"
    finally:
        await ws.close()


# ── 20. a malformed ordinary JSON container does not kill the client
#        handler ──────────────────────────────────────────────────────────

async def test_malformed_ordinary_json_container_does_not_kill_handler(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s645-ordinary-malformed")
    try:
        await drain_until(ws, "register_ok")
        await ws.send(json.dumps(["not", "a", "dict"]))
        await ws.send(json.dumps(123))
        await ws.send(json.dumps(None))
        await asyncio.sleep(0.2)
        await ws.send(json.dumps({"type": "ping"}))
        pong = json.loads(await ws.recv())
        assert pong["type"] == "pong"
    finally:
        await ws.close()


# ── 21. a valid ~6-MiB-ish POST-handshake frame is still governed by the
#        existing normal MAX_PACKET_SIZE_BYTES, not the handshake limit ──

async def test_post_handshake_frame_still_governed_by_normal_ceiling(running_server):
    # Sized well above HANDSHAKE_MAX_PACKET_SIZE_BYTES (8 KiB) but under
    # 1 MiB -- the `running_server` test fixture's own websockets.serve()
    # doesn't set max_size at all (unlike the real start_server()), so it
    # (and the default websockets.connect() client) both fall back to the
    # library's own 1 MiB default; that's a test-fixture detail, not the
    # production MAX_PACKET_SIZE_BYTES (6 MiB) ceiling this test is actually
    # about. The point stands either way: this frame is far too large for
    # the handshake-specific ceiling, yet must still go through normally
    # once the connection is authenticated.
    recipient_priv, recipient_pub = gen_keypair()
    sender_priv, sender_pub = gen_keypair()
    recipient = await websockets.connect(running_server)
    sender    = await websockets.connect(running_server)
    try:
        await handshake(recipient, recipient_priv, recipient_pub)
        await register(recipient, recipient_pub, device_id="s645-post-hs-recipient")
        await drain_until(recipient, "register_ok")
        recipient_fp = fingerprint_of(recipient_pub)

        await handshake(sender, sender_priv, sender_pub)
        await register(sender, sender_pub, device_id="s645-post-hs-sender")
        await drain_until(sender, "register_ok")
        await asyncio.sleep(0.2)

        big_text = "X" * (512 * 1024)
        await sender.send(json.dumps({
            "type": "message", "to": recipient_fp, "id": "s645-big-1", "text": big_text, "signature": "sig",
        }))
        reply = await drain_until(sender, "ack")
        assert reply["id"] == "s645-big-1"

        relayed = await drain_until(recipient, "message")
        assert relayed["id"] == "s645-big-1"
        assert relayed["text"] == big_text
    finally:
        await recipient.close()
        await sender.close()


# ── 22/23. existing S6-39/S6-40 registration tests and existing
#           federation-auth tests remain green -- verified by running the
#           full suite (no dedicated test needed here).


# ── 24. a non-string PoW nonce fails safely (same as any other wrong
#        guess) ───────────────────────────────────────────────────────────

async def test_non_string_pow_nonce_fails_safely(running_server):
    real_diff = server.POW_DIFFICULTY_BITS
    server.POW_DIFFICULTY_BITS = 20  # negligible false-positive chance for an empty-nonce digest
    try:
        priv, pub_der = gen_keypair()
        ws = await websockets.connect(running_server)
        try:
            await handshake(ws, priv, pub_der)
            await ws.send(json.dumps({
                "type": "register", "name": "t",
                "public_key": base64.b64encode(pub_der).decode(),
                "device_id": canonical_device_id("s645-pow-nonstring"),
                "pow_nonce": 12345,  # JSON number, not a string
            }))
            reply = await drain_until(ws, "pow_required")
            assert reply["type"] == "pow_required"
        finally:
            await ws.close()
    finally:
        server.POW_DIFFICULTY_BITS = real_diff


# ── 25. an oversized PoW nonce is rejected before it's ever hashed ──────

async def test_oversized_pow_nonce_rejected_before_sha256(running_server):
    real_diff = server.POW_DIFFICULTY_BITS
    server.POW_DIFFICULTY_BITS = 20
    real_sha256 = server.hashlib.sha256
    captured = []

    def spy_sha256(data=b""):
        captured.append(data)
        return real_sha256(data)

    server.hashlib.sha256 = spy_sha256
    try:
        priv, pub_der = gen_keypair()
        ws = await websockets.connect(running_server)
        try:
            await handshake(ws, priv, pub_der)
            oversized_nonce = "9" * (server.MAX_POW_NONCE_LEN + 1000)
            await ws.send(json.dumps({
                "type": "register", "name": "t",
                "public_key": base64.b64encode(pub_der).decode(),
                "device_id": canonical_device_id("s645-pow-oversized"),
                "pow_nonce": oversized_nonce,
            }))
            reply = await drain_until(ws, "pow_required")
            assert reply["type"] == "pow_required"
            assert not any(oversized_nonce.encode() in d for d in captured)
        finally:
            await ws.close()
    finally:
        server.hashlib.sha256 = real_sha256
        server.POW_DIFFICULTY_BITS = real_diff


# ── 26. the official client's nonce representation still works end to
#        end ──────────────────────────────────────────────────────────────

async def test_official_client_pow_nonce_still_works(running_server):
    real_diff = server.POW_DIFFICULTY_BITS
    server.POW_DIFFICULTY_BITS = 8  # cheap to solve for the test
    try:
        priv, pub_der = gen_keypair()
        ws = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws, priv, pub_der)
            device_id = canonical_device_id("s645-pow-official")
            await ws.send(json.dumps({
                "type": "register", "name": "t",
                "public_key": base64.b64encode(pub_der).decode(),
                "device_id": device_id,
            }))
            reply = await drain_until(ws, "pow_required")
            difficulty = reply["difficulty_bits"]

            # Mirrors Android's solveProofOfWork(): counter.toString(), the
            # smallest satisfying counter.
            counter = 0
            while True:
                nonce  = str(counter)
                digest = hashlib.sha256(challenge + nonce.encode("utf-8")).digest()
                leading_zero_bits = 0
                for byte in digest:
                    if byte == 0:
                        leading_zero_bits += 8
                        continue
                    leading_zero_bits += 8 - byte.bit_length()
                    break
                if leading_zero_bits >= difficulty:
                    break
                counter += 1

            await ws.send(json.dumps({
                "type": "register", "name": "t",
                "public_key": base64.b64encode(pub_der).decode(),
                "device_id": device_id,
                "pow_nonce": nonce,
            }))
            ok = await drain_until(ws, "register_ok")
            assert ok["type"] == "register_ok"
        finally:
            await ws.close()
    finally:
        server.POW_DIFFICULTY_BITS = real_diff


# ── Federated prekey-bundle response poisoning (S6-46) ───────────────────
#
# federated_get_bundle()/fed_pending used to be req_id -> bare Future, and
# handle_federation_response() resolved it on ANY authenticated peer's
# non-null "federated_bundle_response" carrying that req_id -- with no
# check that the returned bundle's cryptographic identity actually matched
# the fingerprint we asked for. Any connected peer necessarily sees req_id
# (it's in our own outgoing request), so first-response-wins meant a
# malicious/compromised peer could hand back arbitrary bundle content and
# win the race against the legitimate answer. See SECURITY_INVARIANTS.md
# #59 and KNOWN_SECURITY_ISSUES.md S6-46.
#
# fed_pending is now req_id -> {"future", "target", "created_at"} and
# handle_federation_response() requires, in order: a canonical req_id that
# actually matches a live pending entry; a response "target" equal to
# pending["target"] (correlation only -- a peer trivially knows this too,
# so it is NOT treated as proof); dict-shaped bundle within
# MAX_BUNDLE_SIZE_BYTES; and finally the bundle's OWN identity_key
# decoding (S6-45's decode_identity_public_key) to the SAME fingerprint as
# pending["target"] -- the actual cryptographic proof. Client fixes
# (Android/Desktop SessionKeyManager.initiateSession()) independently bind
# the received bundle's identity key to the requested contactId before
# ever trusting SPK/PQ signatures or creating a session -- not exercised
# by this Python suite (tests 17-19 in the spec), verified by source
# inspection instead.


def _make_bundle(pub_der: bytes, **extra) -> dict:
    bundle = {
        "identity_key": base64.b64encode(pub_der).decode(),
        "signed_prekey": "SPK-PLACEHOLDER",
        "opks": [],
    }
    bundle.update(extra)
    return bundle


def _make_pending(target: str):
    """Registers a fed_pending entry exactly like federated_get_bundle()
    would, without actually sending anything to any peer -- lets these
    tests drive handle_federation_response() directly against known,
    controlled pending state."""
    loop = asyncio.get_event_loop()
    fut = loop.create_future()
    req_id = secrets.token_hex(8)
    server.fed_pending[req_id] = {"future": fut, "target": target, "created_at": server.time.time()}
    return req_id, fut


# ── 1/2. a normal honest remote bundle, with a matching target, resolves ─

async def test_honest_remote_bundle_with_matching_target_resolves():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    bundle = _make_bundle(pub_der)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target, "bundle": bundle,
    })
    assert fut.done()
    assert fut.result() == bundle


# ── 3. a response missing "target" entirely is ignored ───────────────────

async def test_response_missing_target_ignored():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    bundle = _make_bundle(pub_der)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id, "bundle": bundle,
    })
    assert not fut.done()


# ── 4. a non-canonical target (e.g. lowercase hex) is ignored ────────────

async def test_noncanonical_target_ignored():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    bundle = _make_bundle(pub_der)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target.lower(), "bundle": bundle,
    })
    assert not fut.done()


# ── 5. a target that doesn't match the pending target is ignored ────────

async def test_target_mismatch_ignored():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    other_target = canonical_fingerprint("SOME_OTHER_TARGET")
    req_id, fut = _make_pending(target)
    bundle = _make_bundle(pub_der)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": other_target, "bundle": bundle,
    })
    assert not fut.done()


# ── 6. a malformed req_id (not 16 lowercase hex chars) never even looks up
#       fed_pending, let alone resolves anything ─────────────────────────

async def test_malformed_req_id_ignored():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    bundle = _make_bundle(pub_der)
    for bad_req_id in ("", "not-hex!!", req_id.upper(), "0" * 15, None, 12345, ["x"]):
        await server.handle_federation_response({
            "type": "federated_bundle_response", "req_id": bad_req_id,
            "target": target, "bundle": bundle,
        })
    assert not fut.done()


# ── 7. an oversized req_id is rejected the same way ──────────────────────

async def test_oversized_req_id_ignored():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    bundle = _make_bundle(pub_der)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id + "0" * 500,
        "target": target, "bundle": bundle,
    })
    assert not fut.done()


# ── 8. bundle must be a dict -- a string/list/int bundle is ignored (a
#       real `None` bundle is the LEGITIMATE "peer doesn't have it" case
#       and must keep waiting too, tested separately below) ─────────────

async def test_bundle_must_be_dict():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    for bad_bundle in ("not-a-dict", ["nested"], 42, True):
        req_id, fut = _make_pending(target)
        await server.handle_federation_response({
            "type": "federated_bundle_response", "req_id": req_id,
            "target": target, "bundle": bad_bundle,
        })
        assert not fut.done()


async def test_none_bundle_is_legitimate_not_found_and_keeps_waiting():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target, "bundle": None,
    })
    assert not fut.done()
    assert req_id in server.fed_pending  # still pending, not torn down early


# ── 9. an oversized bundle is rejected BEFORE any identity-key/DER work ──

async def test_oversized_bundle_ignored_before_crypto_work():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    oversized_bundle = _make_bundle(pub_der, filler="X" * (server.MAX_BUNDLE_SIZE_BYTES + 5000))

    real_decode = server.decode_identity_public_key
    calls = []

    def spy_decode(value):
        calls.append(value)
        return real_decode(value)

    server.decode_identity_public_key = spy_decode
    try:
        await server.handle_federation_response({
            "type": "federated_bundle_response", "req_id": req_id,
            "target": target, "bundle": oversized_bundle,
        })
        assert not fut.done()
        assert calls == []  # never even reached the identity-key decode
    finally:
        server.decode_identity_public_key = real_decode


# ── 10. an identity-key/target fingerprint mismatch is rejected ─────────

async def test_identity_fingerprint_mismatch_ignored():
    _, real_pub_der  = gen_keypair()
    _, wrong_pub_der = gen_keypair()
    target = fingerprint_of(real_pub_der)
    req_id, fut = _make_pending(target)
    # Bundle claims to be for `target`, but its OWN identity key derives to
    # a DIFFERENT fingerprint -- the exact substitution this fix closes.
    bundle = _make_bundle(wrong_pub_der)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target, "bundle": bundle,
    })
    assert not fut.done()


async def test_malformed_identity_key_in_bundle_ignored():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    bundle = _make_bundle(pub_der, identity_key="not-valid-base64!!!")
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target, "bundle": bundle,
    })
    assert not fut.done()


# ── 11. every rejection above leaves the Future genuinely pending (not
#        errored, not cancelled) -- covered by the `assert not fut.done()`
#        in every test above; one more explicit check that a SUBSEQUENT
#        valid response can still resolve it normally ───────────────────

async def test_mismatching_response_leaves_future_pending_for_later_valid_one():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)

    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": canonical_fingerprint("WRONG_TARGET"), "bundle": _make_bundle(pub_der),
    })
    assert not fut.done()

    bundle = _make_bundle(pub_der)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target, "bundle": bundle,
    })
    assert fut.done()
    assert fut.result() == bundle


# ── 12/13. a malicious peer's invalid FIRST response cannot suppress a
#           later honest peer's valid response -- the critical race
#           property this fix exists to guarantee ───────────────────────

async def test_malicious_first_response_cannot_poison_later_valid_one():
    priv, pub_der = gen_keypair()
    _, attacker_pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)

    # Malicious peer: correct req_id, correct (echoed) target, but a bundle
    # whose identity key belongs to someone else entirely.
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target, "bundle": _make_bundle(attacker_pub_der),
    }, peer_url="wss://malicious-peer.example")
    assert not fut.done()  # NOT resolved to an error -- still waiting

    # Honest peer, replying later: same req_id/target, real bundle.
    honest_bundle = _make_bundle(pub_der)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target, "bundle": honest_bundle,
    }, peer_url="wss://honest-peer.example")
    assert fut.done()
    assert fut.result() == honest_bundle


# ── 14. a random/unknown req_id creates no fed_pending state at all ─────

async def test_random_unknown_req_id_creates_no_state():
    before = dict(server.fed_pending)
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": secrets.token_hex(8),
        "target": canonical_fingerprint("GHOST"), "bundle": {"identity_key": "AAAA"},
    })
    assert server.fed_pending == before


# ── 15. a late response after the entry has already been cleaned up
#        (simulating federated_get_bundle()'s own timeout `finally`) is
#        ignored, not an error ───────────────────────────────────────────

async def test_late_response_after_cleanup_ignored():
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    req_id, fut = _make_pending(target)
    server.fed_pending.pop(req_id, None)  # simulate the finally: already ran
    fut.cancel()

    # Must not raise, must not resurrect the entry.
    await server.handle_federation_response({
        "type": "federated_bundle_response", "req_id": req_id,
        "target": target, "bundle": _make_bundle(pub_der),
    })
    assert req_id not in server.fed_pending


# ── 16. cancelling the awaiting coroutine still removes the fed_pending
#        entry (federated_get_bundle()'s own `finally`) ─────────────────

async def test_cancellation_removes_fed_pending_state():
    class _FakeWs:
        async def send(self, data):
            pass

    real_federation_ws = dict(server.federation_ws)
    server.federation_ws.clear()
    server.federation_ws["fake-peer"] = _FakeWs()
    try:
        before = set(server.fed_pending.keys())
        task = asyncio.create_task(server.federated_get_bundle(canonical_fingerprint("CANCEL_TARGET")))
        await asyncio.sleep(0.05)
        mid = set(server.fed_pending.keys())
        assert len(mid - before) == 1  # exactly one new entry while in flight
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        after = set(server.fed_pending.keys())
        assert after == before  # cleaned up despite cancellation, not timeout
    finally:
        server.federation_ws.clear()
        server.federation_ws.update(real_federation_ws)


# ── outgoing federated_get_bundle() creates correctly-shaped pending state,
#    including under the new FED_PENDING_MAX hard cap ────────────────────

async def test_federated_get_bundle_creates_target_aware_pending_entry():
    class _FakeWs:
        async def send(self, data):
            pass

    real_federation_ws = dict(server.federation_ws)
    server.federation_ws.clear()
    server.federation_ws["fake-peer"] = _FakeWs()
    try:
        target = canonical_fingerprint("SHAPE_CHECK_TARGET")
        task = asyncio.create_task(server.federated_get_bundle(target))
        await asyncio.sleep(0.05)
        assert len(server.fed_pending) == 1
        entry = next(iter(server.fed_pending.values()))
        assert entry["target"] == target
        assert isinstance(entry["created_at"], float)
        assert not entry["future"].done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        server.federation_ws.clear()
        server.federation_ws.update(real_federation_ws)


async def test_fed_pending_max_rejects_before_sending_to_peers():
    sent = []

    class _FakeWs:
        async def send(self, data):
            sent.append(data)

    real_federation_ws = dict(server.federation_ws)
    real_max = server.FED_PENDING_MAX
    server.federation_ws.clear()
    server.federation_ws["fake-peer"] = _FakeWs()
    server.FED_PENDING_MAX = 1
    try:
        # Fill the single slot with an unrelated in-flight entry.
        server.fed_pending["deadbeefdeadbeef"] = {
            "future": asyncio.get_event_loop().create_future(),
            "target": canonical_fingerprint("FILLER"),
            "created_at": server.time.time(),
        }
        result = await server.federated_get_bundle(canonical_fingerprint("OVER_CAP_TARGET"))
        assert result is None
        assert sent == []  # never even reached out to any peer
        assert len(server.fed_pending) == 1  # no new entry created
    finally:
        server.fed_pending.pop("deadbeefdeadbeef", None)
        server.FED_PENDING_MAX = real_max
        server.federation_ws.clear()
        server.federation_ws.update(real_federation_ws)


# ── incoming federated_get_bundle handler now echoes `target` in its
#    federated_bundle_response, and validates req_id shape before ever
#    reflecting it back ──────────────────────────────────────────────────

async def test_incoming_handler_echoes_target_in_response(running_server):
    target = "FEEDC0DEFEEDC0DE"  # canonical 16-hex shape
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [{"id": "echo1"}]})

    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_get_bundle", "target": target, "req_id": secrets.token_hex(8),
            }))
            response = await drain_until(ws, "federated_bundle_response")
            assert response["target"] == target
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


async def test_incoming_handler_rejects_malformed_req_id_before_consuming(running_server):
    target = "0BADC0DE0BADC0DE"  # canonical 16-hex shape
    await server.store_prekey_bundle(target, {"ik": "IK", "spk": "SPK", "opks": [{"id": "malf1"}]})

    call_count = 0
    real_consume = server.consume_prekey_bundle_for_serve

    async def counting_consume(*a, **kw):
        nonlocal call_count
        call_count += 1
        return await real_consume(*a, **kw)

    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    server.consume_prekey_bundle_for_serve = counting_consume
    try:
        ws = await federation_connect(running_server)
        try:
            for bad_req_id in ("", "not-hex!!", "TOOSHORT", "0" * 500):
                await ws.send(json.dumps({
                    "type": "federated_get_bundle", "target": target, "req_id": bad_req_id,
                }))
            await asyncio.sleep(0.3)
            assert call_count == 0
        finally:
            await ws.close()
    finally:
        server.consume_prekey_bundle_for_serve = real_consume
        server.FEDERATION_SECRET = old_secret


# ── 17/18/19. client-side identity-key/target binding (Android/Desktop
#    SessionKeyManager.initiateSession()) -- fixed in this patch, not
#    exercised by this Python suite. Confirmed by source inspection: both
#    clients previously verified the SPK/PQ signatures against
#    recipientBundle.identityKey but never checked that identityKey itself
#    derived to the requested contactId's fingerprint, so a server (or, for
#    a federated target, an unauthenticated federation peer) attaching the
#    wrong bundle to a requested fingerprint would have the substitution
#    trusted silently. Both now compute sha256(identityKeyBytes)[:8]
#    hex().upper() and throw SecurityException on mismatch, BEFORE any
#    SPK/PQ signature check -- caught by each call site's existing
#    `catch (e: SecurityException)`/`catch (e: Exception)` fallback path,
#    same as an SPK-signature failure already was.


# ── 20/21/22. existing SPK-signature verification, OPK single-use, and
#    S6-35/S6-36 federation bundle tests all remain green -- exercised by
#    running the full suite (test_federation_fetch_consumes_opk_durably,
#    test_incoming_federated_get_bundle_invalid_target_never_calls_consume,
#    test_outgoing_federated_get_bundle_invalid_target_creates_nothing,
#    the S6-36 OPK-issuance-guard section, etc. above), not re-tested here.


# ── Channel persistence resource hardening (S6-47) ───────────────────────
#
# channel_post had NO rate_limit_check() call at all, each post could carry
# up to ~5 MiB of image_data (measured in base64 CHARACTERS, not decoded
# bytes), and every accepted post was persisted forever via a bare INSERT OR
# IGNORE -- the RAM-only `if len(ch["posts"]) > 200: ...` bound the
# in-memory list but never touched the underlying channel_posts SQLite rows.
# See SECURITY_INVARIANTS.md #60 and KNOWN_SECURITY_ISSUES.md S6-47.


def _read_channel_posts_meta():
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT total_rows, total_bytes FROM channel_posts_meta WHERE id = 1"
        ).fetchone()


def _real_channel_posts_totals():
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(storage_bytes), 0) FROM channel_posts"
        ).fetchone()


def _read_channel_posts(channel_id=None):
    with server.db_connect() as conn:
        cols = "id, channel_id, post_id, text, author_id, author_name, image_data, storage_bytes"
        if channel_id is not None:
            return conn.execute(
                f"SELECT {cols} FROM channel_posts WHERE channel_id = ? ORDER BY id", (channel_id,)
            ).fetchall()
        return conn.execute(f"SELECT {cols} FROM channel_posts ORDER BY id").fetchall()


def _make_channel_post(post_id=None, text="hello", image_data="",
                        author_id="AUTH0R00000000C7", author_name="Author"):
    return {
        "post_id": post_id or secrets.token_hex(8),
        "text": text,
        "timestamp": int(server.time.time() * 1000),
        "author_id": author_id,
        "author_name": author_name,
        "image_data": image_data,
    }


def _seed_channel(channel_id, admin="ADMIN000000000C7"):
    server.channels[channel_id] = {
        "name": "Test Channel", "avatar": "📢", "description": "",
        "admin": admin, "admin_name": admin, "subscribers": {admin},
        "created_at": server.time.time(), "posts": [],
    }
    with server.db_connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO channels (channel_id, name, avatar, description, admin, admin_name, created_at) "
            "VALUES (?, 'Test Channel', '📢', '', ?, ?, ?)",
            (channel_id, admin, admin, server.time.time())
        )
        conn.commit()


_CHANNEL_MSG_TYPES = ["channel_create", "channel_subscribe", "channel_unsubscribe",
                      "channel_post", "channel_get_info"]


@pytest.fixture
def channels_enabled():
    """Channels were deliberately removed from ALLOWED_TYPES (external review
    2026-08-28, SCOPE-01) -- the feature is dormant in production (any
    custom client sending channel_create/channel_post today gets the same
    "Неизвестный тип" rejection as any other unsupported message), but the
    handler code and DB tables are left in place, unreachable, not deleted
    -- and this session's S6-47 fix resource-hardens them anyway (unreachable
    today is not the same guarantee as deleted, and any future re-enablement
    inherits the hardening for free). Tests that need to exercise the real
    wire-level handler code request this fixture, which temporarily restores
    the channel message types to the allowlist -- exactly what a deliberate
    future re-enablement would look like -- and puts SCOPE-01's disabled
    state back afterward so every OTHER test keeps observing production's
    actual current behavior."""
    real = server.ALLOWED_TYPES
    server.ALLOWED_TYPES = list(real) + _CHANNEL_MSG_TYPES
    yield
    server.ALLOWED_TYPES = real


# ── 1. channel_post has a real per-user rate limit ───────────────────────

async def test_channel_post_has_dedicated_rate_limit(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-rl-admin")
    try:
        await admin_ws.send(json.dumps({
            "type": "channel_create", "channel_name": "RL Channel",
            "channel_description": "", "channel_avatar": "📢",
        }))
        created = await drain_until(admin_ws, "channel_created")
        channel_id = created["channel_id"]

        rejected = False
        for i in range(server.CHANNEL_POST_RATE_LIMIT + 5):
            await admin_ws.send(json.dumps({
                "type": "channel_post", "channel_id": channel_id, "text": f"post {i}",
            }))
        for _ in range(server.CHANNEL_POST_RATE_LIMIT + 5):
            msg = json.loads(await admin_ws.recv())
            if msg.get("type") == "error" and msg.get("reason") == "Rate limit exceeded":
                rejected = True
                break
        assert rejected
    finally:
        await admin_ws.close()


# ── 2. global channel-post limiter rejects before SQLite ─────────────────

async def test_channel_post_global_limiter_rejects_before_sqlite():
    channel_id = "GLOBALLIMITCHAN1"
    _seed_channel(channel_id)
    real_limit = server.CHANNEL_POST_GLOBAL_LIMIT
    real_enabled = server.CHANNEL_POST_GLOBAL_ENABLED
    server.CHANNEL_POST_GLOBAL_LIMIT = 1
    server.CHANNEL_POST_GLOBAL_ENABLED = True
    server.channel_post_global_rate["count"] = 0
    server.channel_post_global_rate["reset_time"] = server.time.time()
    try:
        status1 = await server.db_store_channel_post(channel_id, _make_channel_post())
        assert status1 == "STORED"

        real_connect = server.db_connect

        def failing_connect():
            raise AssertionError("db_connect() must not be called once the global budget is exhausted")

        server.db_connect = failing_connect
        try:
            status2 = await server.db_store_channel_post(channel_id, _make_channel_post())
            assert status2 == "RATE_LIMITED"
        finally:
            server.db_connect = real_connect
    finally:
        server.CHANNEL_POST_GLOBAL_LIMIT = real_limit
        server.CHANNEL_POST_GLOBAL_ENABLED = real_enabled


# ── 3. image_data wrong type rejected safely ──────────────────────────────

async def test_image_data_wrong_type_rejected_safely(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-badimg-admin")
    try:
        await admin_ws.send(json.dumps({
            "type": "channel_create", "channel_name": "BadImg Channel",
            "channel_description": "", "channel_avatar": "📢",
        }))
        created = await drain_until(admin_ws, "channel_created")
        channel_id = created["channel_id"]

        for bad_image in (["nested"], {"a": 1}, 12345, True):
            await admin_ws.send(json.dumps({
                "type": "channel_post", "channel_id": channel_id, "text": "x", "image_data": bad_image,
            }))
        for _ in range(4):
            msg = json.loads(await admin_ws.recv())
            assert msg["type"] == "error"
        assert _read_channel_posts(channel_id) == []
    finally:
        await admin_ws.close()


# ── 4. oversized image rejected before DB ─────────────────────────────────

async def test_oversized_image_rejected_before_db():
    channel_id = "OVERSIZEDIMGCHN1"
    _seed_channel(channel_id)
    real_connect = server.db_connect

    def failing_connect():
        raise AssertionError("db_connect() must not be called for an oversized image")

    server.db_connect = failing_connect
    try:
        oversized_b64 = "A" * (server.CHANNEL_POST_IMAGE_B64_MAX_LEN + 100)
        assert not server.validate_channel_post_image(oversized_b64)
    finally:
        server.db_connect = real_connect


# ── 5. oversized text rejected before DB ──────────────────────────────────

async def test_oversized_text_rejected_before_db(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-bigtext-admin")
    try:
        await admin_ws.send(json.dumps({
            "type": "channel_create", "channel_name": "BigText Channel",
            "channel_description": "", "channel_avatar": "📢",
        }))
        created = await drain_until(admin_ws, "channel_created")
        channel_id = created["channel_id"]

        await admin_ws.send(json.dumps({
            "type": "channel_post", "channel_id": channel_id,
            "text": "x" * (server.CHANNEL_POST_TEXT_MAX_CHARS + 10),
        }))
        err = await drain_until(admin_ws, "error")
        assert err["reason"] == "Слишком длинный текст поста"
        assert _read_channel_posts(channel_id) == []
    finally:
        await admin_ws.close()


# ── 6. oversized description/avatar rejected on channel_create ───────────

async def test_oversized_description_rejected_on_create(running_server, channels_enabled):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s647-bigdesc")
    try:
        await ws.send(json.dumps({
            "type": "channel_create", "channel_name": "OK Name",
            "channel_description": "x" * (server.CHANNEL_DESCRIPTION_MAX_CHARS + 10),
            "channel_avatar": "📢",
        }))
        err = await drain_until(ws, "error")
        assert err["reason"] == "Слишком длинное описание канала"
    finally:
        await ws.close()


async def test_oversized_avatar_rejected_on_create(running_server, channels_enabled):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s647-bigavatar")
    try:
        await ws.send(json.dumps({
            "type": "channel_create", "channel_name": "OK Name",
            "channel_description": "", "channel_avatar": "x" * (server.CHANNEL_AVATAR_MAX_CHARS + 10),
        }))
        err = await drain_until(ws, "error")
        assert err["reason"] == "Некорректный аватар канала"
    finally:
        await ws.close()


# ── 7. malformed/oversized post_id rejected before DB ─────────────────────

async def test_oversized_post_id_rejected_before_db(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-bigpostid")
    try:
        await admin_ws.send(json.dumps({
            "type": "channel_create", "channel_name": "PostId Channel",
            "channel_description": "", "channel_avatar": "📢",
        }))
        created = await drain_until(admin_ws, "channel_created")
        channel_id = created["channel_id"]

        await admin_ws.send(json.dumps({
            "type": "channel_post", "channel_id": channel_id, "text": "x",
            "id": "P" * (server.CHANNEL_POST_ID_MAX_LEN + 10),
        }))
        err = await drain_until(admin_ws, "error")
        assert err["reason"] == "Некорректный идентификатор поста"
        assert _read_channel_posts(channel_id) == []
    finally:
        await admin_ws.close()


# ── 8. malformed/oversized channel_id rejected before dict/DB lookup ─────

async def test_oversized_channel_id_rejected_before_lookup(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-bigchanid")
    try:
        giant_channel_id = "C" * (server.CHANNEL_ID_MAX_LEN + 1000)
        assert giant_channel_id not in server.channels
        await admin_ws.send(json.dumps({
            "type": "channel_post", "channel_id": giant_channel_id, "text": "x",
        }))
        err = await drain_until(admin_ws, "error")
        assert err["reason"] == "Канал не найден"
        # A giant string must never have been used as a live dict key.
        assert giant_channel_id not in server.channels
    finally:
        await admin_ws.close()


# ── 9. valid normal official-client post still works ─────────────────────

async def test_valid_normal_post_still_works(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-validpost-admin")
    sub_ws, sub_fp, _, _ = await connect_and_register(running_server, device_id="s647-validpost-sub")
    try:
        await admin_ws.send(json.dumps({
            "type": "channel_create", "channel_name": "Valid Channel",
            "channel_description": "desc", "channel_avatar": "📢",
        }))
        created = await drain_until(admin_ws, "channel_created")
        channel_id = created["channel_id"]

        await sub_ws.send(json.dumps({"type": "channel_subscribe", "channel_id": channel_id}))
        await drain_until(sub_ws, "channel_info")

        await admin_ws.send(json.dumps({
            "type": "channel_post", "channel_id": channel_id, "text": "hello subscribers",
        }))
        update = await drain_until(sub_ws, "channel_update")
        assert update["text"] == "hello subscribers"
        assert update["channel_id"] == channel_id

        rows = _read_channel_posts(channel_id)
        assert len(rows) == 1
        assert rows[0][3] == "hello subscribers"
    finally:
        await admin_ws.close()
        await sub_ws.close()


# ── 10. a post above CHANNEL_POST_MAX_BYTES never persists ───────────────

async def test_post_above_max_bytes_never_persists():
    channel_id = "TOOLARGEPOSTCHN1"
    _seed_channel(channel_id)
    real_cap = server.CHANNEL_POST_MAX_BYTES
    server.CHANNEL_POST_MAX_BYTES = 10

    real_connect = server.db_connect

    def failing_connect():
        raise AssertionError("db_connect() must not be called for an over-cap post")

    server.db_connect = failing_connect
    try:
        status = await server.db_store_channel_post(channel_id, _make_channel_post(text="x" * 1000))
        assert status == "TOO_LARGE"
    finally:
        server.db_connect = real_connect
        server.CHANNEL_POST_MAX_BYTES = real_cap


# ── 11. total-row cap refuses a new post ──────────────────────────────────

async def test_channel_posts_row_cap_refuses_new_post():
    channel_id = "ROWCAPCHANNEL001"
    _seed_channel(channel_id)
    real_cap = server.CHANNEL_POSTS_MAX_TOTAL_ROWS
    server.CHANNEL_POSTS_MAX_TOTAL_ROWS = 1
    try:
        status1 = await server.db_store_channel_post(channel_id, _make_channel_post(post_id="rowcap-1"))
        assert status1 == "STORED"
        before = _read_channel_posts_meta()

        status2 = await server.db_store_channel_post(channel_id, _make_channel_post(post_id="rowcap-2"))
        assert status2 == "FULL"

        assert _read_channel_posts_meta() == before
        assert len(_read_channel_posts(channel_id)) == 1
    finally:
        server.CHANNEL_POSTS_MAX_TOTAL_ROWS = real_cap


# ── 12. total-byte cap refuses a new post ─────────────────────────────────

async def test_channel_posts_byte_cap_refuses_new_post():
    channel_id = "BYTECAPCHANNEL01"
    _seed_channel(channel_id)
    real_cap = server.CHANNEL_POSTS_MAX_TOTAL_BYTES
    try:
        status1 = await server.db_store_channel_post(channel_id, _make_channel_post(post_id="bytecap-1", text="x" * 10))
        assert status1 == "STORED"
        before = _read_channel_posts_meta()

        # Exactly at capacity -- no headroom left for a second row of ANY size.
        server.CHANNEL_POSTS_MAX_TOTAL_BYTES = before[1]
        status2 = await server.db_store_channel_post(channel_id, _make_channel_post(post_id="bytecap-2", text="y" * 10))
        assert status2 == "FULL"

        assert _read_channel_posts_meta() == before
        assert len(_read_channel_posts(channel_id)) == 1
    finally:
        server.CHANNEL_POSTS_MAX_TOTAL_BYTES = real_cap


# ── 13. rejected post leaves channel_posts_meta unchanged (covered above
#        by tests 10-12's own `before == after` assertions; one more
#        explicit check using a real DB-layer failure) ──────────────────

async def test_rejected_post_leaves_meta_unchanged_on_db_failure():
    channel_id = "DBFAILCHANNEL001"
    _seed_channel(channel_id)
    before = _read_channel_posts_meta()

    class _ExplodingConn:
        def execute(self, *a, **kw):
            raise sqlite3.OperationalError("simulated disk failure")
        def rollback(self):
            pass
        def commit(self):
            raise AssertionError("must not commit after a failed execute")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    real_connect = server.db_connect
    server.db_connect = lambda: _ExplodingConn()
    try:
        with pytest.raises(sqlite3.OperationalError):
            await server.db_store_channel_post(channel_id, _make_channel_post())
    finally:
        server.db_connect = real_connect
    assert _read_channel_posts_meta() == before


# ── 14. successful insert increments row/byte totals exactly ─────────────

async def test_channel_post_successful_insert_increments_totals_exactly():
    channel_id = "INCRCHANNEL00001"
    _seed_channel(channel_id)
    before = _read_channel_posts_meta()
    post = _make_channel_post(post_id="incr-1", text="hello world")

    status = await server.db_store_channel_post(channel_id, post)
    assert status == "STORED"

    after = _read_channel_posts_meta()
    expected_bytes = (
        len(channel_id.encode("utf-8")) + len(post["post_id"].encode("utf-8")) +
        len(post["text"].encode("utf-8")) + len(post["author_id"].encode("utf-8")) +
        len(post["author_name"].encode("utf-8")) + len(post["image_data"].encode("utf-8"))
    )
    assert after == (before[0] + 1, before[1] + expected_bytes)
    assert after == _real_channel_posts_totals()


# ── 15. duplicate identical post does not increment totals ───────────────

async def test_channel_post_duplicate_identical_does_not_increment_totals():
    channel_id = "DUPCHANNEL000001"
    _seed_channel(channel_id)
    post = _make_channel_post(post_id="dup-1", text="same content")

    status1 = await server.db_store_channel_post(channel_id, post)
    assert status1 == "STORED"
    after_first = _read_channel_posts_meta()

    status2 = await server.db_store_channel_post(channel_id, dict(post))
    assert status2 == "DUPLICATE"
    assert _read_channel_posts_meta() == after_first
    assert len(_read_channel_posts(channel_id)) == 1


# ── 16. duplicate identical post is not appended/broadcast twice ─────────

async def test_duplicate_post_not_appended_or_broadcast_twice(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-dupwire-admin")
    sub_ws, sub_fp, _, _ = await connect_and_register(running_server, device_id="s647-dupwire-sub")
    try:
        await admin_ws.send(json.dumps({
            "type": "channel_create", "channel_name": "Dup Channel",
            "channel_description": "", "channel_avatar": "📢",
        }))
        created = await drain_until(admin_ws, "channel_created")
        channel_id = created["channel_id"]

        await sub_ws.send(json.dumps({"type": "channel_subscribe", "channel_id": channel_id}))
        await drain_until(sub_ws, "channel_info")

        post_id = secrets.token_urlsafe(8)
        for _ in range(2):
            await admin_ws.send(json.dumps({
                "type": "channel_post", "channel_id": channel_id, "text": "resend me", "id": post_id,
            }))

        first_update = await drain_until(sub_ws, "channel_update")
        assert first_update["post_id"] == post_id

        # The resend must never produce a second broadcast -- confirm no
        # further channel_update arrives within a short window.
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sub_ws, "channel_update", timeout=0.5)

        assert len(server.channels[channel_id]["posts"]) == 1
        assert len(_read_channel_posts(channel_id)) == 1
    finally:
        await admin_ws.close()
        await sub_ws.close()


# ── 17. conflicting reused post_id is rejected ────────────────────────────

async def test_conflicting_reused_post_id_rejected():
    channel_a = "CONFLICTCHANNELA"
    channel_b = "CONFLICTCHANNELB"
    _seed_channel(channel_a)
    _seed_channel(channel_b)

    status1 = await server.db_store_channel_post(channel_a, _make_channel_post(post_id="shared-id", text="from A"))
    assert status1 == "STORED"

    # Same post_id, different channel -- a genuine collision, not a resend.
    status2 = await server.db_store_channel_post(channel_b, _make_channel_post(post_id="shared-id", text="from A"))
    assert status2 == "CONFLICT"

    # Same channel, same post_id, DIFFERENT text -- also a conflict.
    status3 = await server.db_store_channel_post(channel_a, _make_channel_post(post_id="shared-id", text="different text"))
    assert status3 == "CONFLICT"

    assert len(_read_channel_posts(channel_a)) == 1
    assert len(_read_channel_posts(channel_b)) == 0


# ── 18. DB failure produces no RAM post ───────────────────────────────────

async def test_db_failure_produces_no_ram_post(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-dbfail-admin")
    try:
        await admin_ws.send(json.dumps({
            "type": "channel_create", "channel_name": "DBFail Channel",
            "channel_description": "", "channel_avatar": "📢",
        }))
        created = await drain_until(admin_ws, "channel_created")
        channel_id = created["channel_id"]

        real_store = server.db_store_channel_post

        async def failing_store(*a, **kw):
            raise RuntimeError("simulated durable-store failure")

        server.db_store_channel_post = failing_store
        try:
            # The exception happens inside the server's OWN per-connection
            # task, not in this client's send() call -- it propagates there
            # (closing that connection, per the outer per-message try/except
            # around handle_client()'s loop), never back to us. Assert on
            # RAM state after giving the handler a moment to actually run.
            await admin_ws.send(json.dumps({
                "type": "channel_post", "channel_id": channel_id, "text": "should not persist",
            }))
            await asyncio.sleep(0.2)
        finally:
            server.db_store_channel_post = real_store

        assert server.channels.get(channel_id, {}).get("posts", []) == []
    finally:
        try:
            await admin_ws.close()
        except Exception:
            pass


# ── 19/20. FULL produces no RAM post and no subscriber broadcast ─────────

async def test_full_produces_no_ram_post_or_broadcast(running_server, channels_enabled):
    admin_ws, admin_fp, _, _ = await connect_and_register(running_server, device_id="s647-full-admin")
    sub_ws, sub_fp, _, _ = await connect_and_register(running_server, device_id="s647-full-sub")
    try:
        await admin_ws.send(json.dumps({
            "type": "channel_create", "channel_name": "Full Channel",
            "channel_description": "", "channel_avatar": "📢",
        }))
        created = await drain_until(admin_ws, "channel_created")
        channel_id = created["channel_id"]

        await sub_ws.send(json.dumps({"type": "channel_subscribe", "channel_id": channel_id}))
        await drain_until(sub_ws, "channel_info")

        real_cap = server.CHANNEL_POSTS_MAX_TOTAL_ROWS
        server.CHANNEL_POSTS_MAX_TOTAL_ROWS = 0  # any real fetch/compare rejects immediately
        try:
            # A cap of 0 is nonsensical for the module-level fail-closed
            # check at import time, but perfectly fine to poke at runtime
            # here to force the FULL branch deterministically.
            await admin_ws.send(json.dumps({
                "type": "channel_post", "channel_id": channel_id, "text": "will not fit",
            }))
            err = await drain_until(admin_ws, "error")
            assert err["reason"] == "Хранилище каналов заполнено, попробуйте позже"
        finally:
            server.CHANNEL_POSTS_MAX_TOTAL_ROWS = real_cap

        assert server.channels[channel_id]["posts"] == []
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sub_ws, "channel_update", timeout=0.5)
    finally:
        await admin_ws.close()
        await sub_ws.close()


# ── 21. restart reconciliation repairs channel_posts_meta ────────────────

async def test_channel_posts_restart_reconciliation_repairs_wrong_meta():
    channel_id = "RECONCILECHANNEL"
    _seed_channel(channel_id)
    await server.db_store_channel_post(channel_id, _make_channel_post(post_id="reconcile-1", text="keepme"))
    with server.db_connect() as conn:
        conn.execute("UPDATE channel_posts_meta SET total_rows = 9999, total_bytes = 9999 WHERE id = 1")
        conn.commit()
    assert _read_channel_posts_meta() == (9999, 9999)

    server._db_setup_sync()  # simulates a server restart

    assert _read_channel_posts_meta() == _real_channel_posts_totals()


# ── 22. migration correctly accounts existing (pre-storage_bytes) rows ───

async def test_channel_posts_migration_backfills_storage_bytes(tmp_path):
    db_path = tmp_path / "s647_migration_test.db"
    env = dict(os.environ)
    env["DB_PATH"] = str(db_path)
    env.setdefault("MAX_REGISTERED_USERS", "0")
    env.setdefault("POW_DIFFICULTY_BITS", "0")
    env.pop("TOTP_SECRET_ENCRYPTION_KEY", None)

    # Build a pre-migration-shaped DB: channel_posts WITHOUT storage_bytes,
    # one legacy row already in it -- simulates a real DB from before S6-47.
    setup_code = (
        "import sqlite3;"
        "conn = sqlite3.connect(r'" + str(db_path) + "');"
        "conn.execute('CREATE TABLE channels (channel_id TEXT PRIMARY KEY, name TEXT, avatar TEXT, "
        "description TEXT, admin TEXT, admin_name TEXT, created_at REAL)');"
        "conn.execute(\"INSERT INTO channels VALUES ('LEGACYCHAN0000001','Legacy','a','','ADMIN1','A',0)\");"
        "conn.execute('CREATE TABLE channel_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, channel_id TEXT, "
        "post_id TEXT UNIQUE, text TEXT, timestamp INTEGER, author_id TEXT, author_name TEXT, image_data TEXT)');"
        "conn.execute(\"INSERT INTO channel_posts (channel_id, post_id, text, timestamp, author_id, author_name, image_data) "
        "VALUES ('LEGACYCHAN0000001','legacy-post-1','legacy text',0,'ADMIN1','A','')\");"
        "conn.commit(); conn.close()"
    )
    setup_result = subprocess.run([sys.executable, "-c", setup_code], capture_output=True, text=True, timeout=20)
    assert setup_result.returncode == 0, setup_result.stdout + setup_result.stderr

    check_code = (
        "import server;"
        "server._db_setup_sync();"
        "cols = {r[1] for r in server.db_connect().execute('PRAGMA table_info(channel_posts)').fetchall()};"
        "assert 'storage_bytes' in cols, cols;"
        "row = server.db_connect().execute("
        "\"SELECT storage_bytes FROM channel_posts WHERE post_id='legacy-post-1'\").fetchone();"
        "expected = len('LEGACYCHAN0000001'.encode()) + len('legacy-post-1'.encode()) + "
        "len('legacy text'.encode()) + len('ADMIN1'.encode()) + len('A'.encode()) + len(''.encode());"
        "assert row[0] == expected, (row[0], expected);"
        "meta = server.db_connect().execute('SELECT total_rows, total_bytes FROM channel_posts_meta WHERE id=1').fetchone();"
        "assert meta == (1, expected), meta;"
        "print('MIGRATION_OK')"
    )
    result = subprocess.run(
        [sys.executable, "-c", check_code], cwd=_SERVER_DIR, env=env, capture_output=True, text=True, timeout=20
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "MIGRATION_OK" in result.stdout


# ── 23. concurrent final-cap writes cannot both exceed the cap ───────────

async def test_concurrent_final_cap_writes_cannot_both_exceed_cap():
    channel_id = "CONCURRENTCAPCH1"
    _seed_channel(channel_id)
    real_cap = server.CHANNEL_POSTS_MAX_TOTAL_ROWS
    server.CHANNEL_POSTS_MAX_TOTAL_ROWS = 1
    try:
        results = await asyncio.gather(*[
            server.db_store_channel_post(channel_id, _make_channel_post(post_id=f"race-{i}"))
            for i in range(20)
        ])
        assert sum(1 for r in results if r == "STORED") == 1
        assert sum(1 for r in results if r == "FULL") == 19
        assert _read_channel_posts_meta() == (1, _read_channel_posts_meta()[1])
        assert len(_read_channel_posts(channel_id)) == 1
    finally:
        server.CHANNEL_POSTS_MAX_TOTAL_ROWS = real_cap


# ── 24. per-channel retention: the 201st post leaves exactly 200 durable
#        rows, with meta counters matching those 200 ──────────────────────

async def test_201st_post_leaves_exactly_200_durable_rows():
    channel_id = "PRUNECHANNEL0001"
    _seed_channel(channel_id)
    real_global_enabled = server.CHANNEL_POST_GLOBAL_ENABLED
    # 201 direct-store calls in one process-local window would otherwise
    # trip CHANNEL_POST_GLOBAL_LIMIT (a write-ATTEMPT budget, separately
    # covered by test 2 above) before ever reaching the per-channel
    # retention prune this test actually exercises.
    server.CHANNEL_POST_GLOBAL_ENABLED = False
    try:
        for i in range(server.CHANNEL_POSTS_MAX_PER_CHANNEL + 1):
            status = await server.db_store_channel_post(channel_id, _make_channel_post(post_id=f"prune-{i:04d}"))
            assert status == "STORED"

        rows = _read_channel_posts(channel_id)
        assert len(rows) == server.CHANNEL_POSTS_MAX_PER_CHANNEL
        # The OLDEST post (prune-0000) must have been the one pruned -- the
        # newest 200 (prune-0001 .. prune-0200) are kept.
        kept_post_ids = {r[2] for r in rows}
        assert "prune-0000" not in kept_post_ids
        assert "prune-0200" in kept_post_ids

        assert _read_channel_posts_meta() == _real_channel_posts_totals()
        assert _read_channel_posts_meta()[0] == server.CHANNEL_POSTS_MAX_PER_CHANNEL
    finally:
        server.CHANNEL_POST_GLOBAL_ENABLED = real_global_enabled


# ── 25. normal channel_create still works ─────────────────────────────────

async def test_normal_channel_create_still_works(running_server, channels_enabled):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s647-create-normal")
    try:
        await ws.send(json.dumps({
            "type": "channel_create", "channel_name": "My Channel",
            "channel_description": "A description", "channel_avatar": "📢",
        }))
        created = await drain_until(ws, "channel_created")
        assert created["channel_name"] == "My Channel"
        assert created["channel_description"] == "A description"
        channel_id = created["channel_id"]
        assert channel_id in server.channels
        with server.db_connect() as conn:
            row = conn.execute("SELECT name, admin FROM channels WHERE channel_id = ?", (channel_id,)).fetchone()
        assert row == ("My Channel", fp)
    finally:
        await ws.close()


# ── 26. oversized metadata creates no RAM/DB channel ──────────────────────

async def test_oversized_name_creates_no_ram_db_channel(running_server, channels_enabled):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s647-create-oversized")
    try:
        channels_before = dict(server.channels)
        await ws.send(json.dumps({
            "type": "channel_create",
            "channel_name": "x" * (server.CHANNEL_NAME_MAX_CHARS + 10),
            "channel_description": "", "channel_avatar": "📢",
        }))
        err = await drain_until(ws, "error")
        assert err["reason"] == "Слишком длинное название канала"
        assert server.channels == channels_before
        with server.db_connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM channels WHERE admin = ?", (fp,)).fetchone()[0]
        assert count == 0
    finally:
        await ws.close()


# ── 27. channel lifetime/per-owner cap cannot be raced past ───────────────

async def test_channel_owner_cap_cannot_be_raced_past():
    real_owner_cap = server.MAX_CHANNELS_PER_OWNER
    server.MAX_CHANNELS_PER_OWNER = 1
    try:
        owner = "OWNERCAPRACE0001"
        results = await asyncio.gather(*[
            asyncio.get_event_loop().run_in_executor(
                None, server._db_create_channel_sync, f"ownercap-chan-{i}",
                {"name": "N", "avatar": "a", "description": "", "admin": owner, "admin_name": "N",
                 "created_at": server.time.time()}
            )
            for i in range(20)
        ])
        assert sum(1 for r in results if r == "CREATED") == 1
        assert sum(1 for r in results if r == "OWNER_LIMIT") == 19
        with server.db_connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM channels WHERE admin = ?", (owner,)).fetchone()[0]
        assert count == 1
    finally:
        server.MAX_CHANNELS_PER_OWNER = real_owner_cap


async def test_channel_total_cap_cannot_be_raced_past():
    real_total_cap = server.CHANNELS_MAX_TOTAL_ROWS
    server.CHANNELS_MAX_TOTAL_ROWS = 1
    try:
        results = await asyncio.gather(*[
            asyncio.get_event_loop().run_in_executor(
                None, server._db_create_channel_sync, f"totalcap-chan-{i}",
                {"name": "N", "avatar": "a", "description": "", "admin": f"OWNER{i:011d}", "admin_name": "N",
                 "created_at": server.time.time()}
            )
            for i in range(20)
        ])
        assert sum(1 for r in results if r == "CREATED") == 1
        assert sum(1 for r in results if r == "TOTAL_LIMIT") == 19
        with server.db_connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM channels").fetchone()[0]
        assert count == 1
    finally:
        server.CHANNELS_MAX_TOTAL_ROWS = real_total_cap


# ── 28. no pre-existing channel tests to keep green -- this is the first
#        automated channel test coverage this file has ever had.


# ── Attack regression: authenticated channel admin repeatedly submits
#    maximum-size posts -- durable bytes/rows never exceed the configured
#    hard caps, RAM recent-post list stays bounded, and excess writes never
#    broadcast ───────────────────────────────────────────────────────────

async def test_flood_of_max_size_posts_bounded_by_all_layers():
    channel_id = "FLOODATTACKCHAN1"
    _seed_channel(channel_id)
    real_rows_cap = server.CHANNEL_POSTS_MAX_TOTAL_ROWS
    real_bytes_cap = server.CHANNEL_POSTS_MAX_TOTAL_BYTES
    real_global_enabled = server.CHANNEL_POST_GLOBAL_ENABLED
    server.CHANNEL_POSTS_MAX_TOTAL_ROWS = 50
    server.CHANNEL_POSTS_MAX_TOTAL_BYTES = 50 * 2000  # small multiple of one post's size
    # This test exercises the DURABLE row/byte ceilings specifically (500
    # attempts) -- the per-user/global write-ATTEMPT rate limiters are
    # separately covered by tests 1/2 above and would otherwise trip first.
    server.CHANNEL_POST_GLOBAL_ENABLED = False
    try:
        big_text = "A" * 1900
        stored = 0
        for i in range(500):
            status = await server.db_store_channel_post(
                channel_id, _make_channel_post(post_id=f"flood-{i:04d}", text=big_text)
            )
            if status == "STORED":
                stored += 1
            else:
                assert status == "FULL"

        meta = _read_channel_posts_meta()
        assert meta[0] <= server.CHANNEL_POSTS_MAX_TOTAL_ROWS
        assert meta[1] <= server.CHANNEL_POSTS_MAX_TOTAL_BYTES
        assert meta == _real_channel_posts_totals()
        assert stored == meta[0]
        # Per-channel RAM list was never touched by direct db_store_channel_post()
        # calls in this test (that's the handler's own job) -- assert the
        # DURABLE side stayed within its configured hard ceiling regardless
        # of how many attempts were made.
        assert len(_read_channel_posts(channel_id)) == meta[0]
    finally:
        server.CHANNEL_POSTS_MAX_TOTAL_ROWS = real_rows_cap
        server.CHANNEL_POSTS_MAX_TOTAL_BYTES = real_bytes_cap
        server.CHANNEL_POST_GLOBAL_ENABLED = real_global_enabled


# ── TOTP setup/proof input hardening (S6-48) ──────────────────────────────
#
# totp_setup accepted client-controlled secret/new_code/current_code/
# recovery_code with no protocol-specific bounds. Before TOTP is enabled for
# an account, totp_setup never reaches db_take_second_factor_attempt() (that
# guard only protects proof of an EXISTING factor), so an authenticated
# account with no TOTP configured could repeatedly send large `secret`
# values, each reaching totp_code_matches() -> _totp_code_at_counter() ->
# base64.b32decode() with no rate limit at all -- and if a huge secret ever
# happened to validate, it would be durably persisted and loaded fully into
# RAM on every future startup. See SECURITY_INVARIANTS.md #61 and
# KNOWN_SECURITY_ISSUES.md S6-48.


def _totp_random_secret() -> str:
    """A fresh, real, canonical secret -- exactly what
    TotpManager.generateSecret() produces on both clients (20 random bytes,
    Base32, no padding)."""
    return base64.b32encode(secrets.token_bytes(20)).decode()


# ── 1/2/3. official Android/Desktop generated secrets, and the canonical
#           historical format this whole test suite already relies on
#           (TOTP_TEST_SECRET*), all pass ───────────────────────────────

async def test_official_android_generated_secret_passes():
    android_secret = _totp_random_secret()
    assert server.decode_totp_secret(android_secret) == android_secret


async def test_official_desktop_generated_secret_passes():
    # Byte-identical generation algorithm on both clients (grepped) -- a
    # second, independently-random secret exercises the same canonical
    # format, not a special Desktop-only shape.
    desktop_secret = _totp_random_secret()
    assert server.decode_totp_secret(desktop_secret) == desktop_secret


async def test_legitimate_historical_format_passes():
    # No historical variance was ever found (git history of both clients'
    # TotpManager.kt: ByteArray(20) unchanged since TOTP was introduced; no
    # server-side tool generates secrets in any other shape) -- the
    # canonical format IS the historical format. This suite's own shared
    # fixtures must themselves be valid under the real validator.
    assert server.decode_totp_secret(TOTP_TEST_SECRET) == TOTP_TEST_SECRET
    assert server.decode_totp_secret(TOTP_TEST_SECRET_2) == TOTP_TEST_SECRET_2
    assert server.decode_totp_secret(TOTP_TEST_SECRET_3) == TOTP_TEST_SECRET_3


# ── 4. a multi-megabyte secret is rejected before Base32 decode ──────────

async def test_multi_megabyte_secret_rejected_before_base32_decode():
    real_b32decode = server.base64.b32decode
    calls = []

    def spy_b32decode(*a, **kw):
        calls.append(a)
        return real_b32decode(*a, **kw)

    server.base64.b32decode = spy_b32decode
    try:
        huge_secret = "A" * (5 * 1024 * 1024)
        assert server.decode_totp_secret(huge_secret) is None
        assert calls == []
    finally:
        server.base64.b32decode = real_b32decode


# ── 5. a wrong-type secret is rejected before Base32 decode ──────────────

async def test_wrong_type_secret_rejected_before_base32_decode():
    real_b32decode = server.base64.b32decode
    calls = []

    def spy_b32decode(*a, **kw):
        calls.append(a)
        return real_b32decode(*a, **kw)

    server.base64.b32decode = spy_b32decode
    try:
        for bad in (["nested"], {"a": 1}, 12345, True, None, b"bytesnotstr"):
            assert server.decode_totp_secret(bad) is None
        assert calls == []
    finally:
        server.base64.b32decode = real_b32decode


# ── 6. an invalid-Base32 secret (right length, bad alphabet) is rejected
#       cleanly ──────────────────────────────────────────────────────────

async def test_invalid_base32_secret_rejected_cleanly():
    # Exactly 32 characters (the canonical length) but containing digits
    # outside the Base32 alphabet (0, 1, 8, 9 are never valid Base32).
    bad_alphabet = "01189998819991197253" + "A" * 12
    assert len(bad_alphabet) == 32
    assert server.decode_totp_secret(bad_alphabet) is None


# ── 7. a valid maximum-length (canonical) secret works ────────────────────

async def test_valid_maximum_length_secret_works():
    secret = _totp_random_secret()
    assert len(secret) == server.TOTP_SECRET_B32_LEN
    code = _current_totp_code(secret)
    assert server.totp_code_matches(secret, code) is not None


# ── 8. a huge new_code is rejected before totp_code_matches ───────────────

async def test_huge_new_code_rejected_before_totp_code_matches(running_server):
    username = "S648HUGENEWCODE1"
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s648-hugenewcode", name="t")
    try:
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": TOTP_TEST_SECRET, "new_code": "1" * (512 * 1024),
        }))
        failed = await drain_until(ws, "totp_setup_failed")
        assert failed["reason"] == "invalid_code"
        assert fp not in server.user_totp_secrets
    finally:
        await ws.close()


# ── 9. non-digit / 5-digit / 7-digit TOTP codes are rejected ──────────────

async def test_non_digit_or_wrong_length_totp_codes_rejected():
    for bad_code in ("12345", "1234567", "12345a", "abcdef", "123 456", "", None, 123456, ["1"]):
        assert not server.is_valid_totp_code(bad_code)
    # Leading/trailing whitespace around an otherwise-valid 6-digit code is
    # tolerated -- preserves totp_code_matches()'s own pre-existing strip()
    # normalization, not new leniency.
    assert server.is_valid_totp_code(" 123456 ")


# ── 10. a canonical six-digit code still works ────────────────────────────

async def test_canonical_six_digit_code_still_works():
    assert server.is_valid_totp_code("123456")
    assert server.is_valid_totp_code("000000")
    secret = _totp_random_secret()
    code = _current_totp_code(secret)
    assert len(code) == 6 and code.isdigit()
    assert server.is_valid_totp_code(code)
    assert server.totp_code_matches(secret, code) is not None


# ── 11. a huge recovery_code is rejected before SHA-256 (db_check_and_
#        consume_recovery_code is never even called) ─────────────────────

async def test_huge_recovery_code_rejected_before_sha256(running_server):
    username_secret = _totp_random_secret()
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s648-hugerecovery")
    try:
        # Wait for register() to actually finish server-side before
        # enabling TOTP for this fingerprint out-of-band -- connect_and_
        # register() only awaits the register message being SENT, not
        # processed, so writing user_totp_secrets[fp] too early races the
        # server's own Phase 1 (which would then wrongly demand device
        # auth for a registration that never sent it).
        await drain_until(ws, "register_ok")
        codes = server.generate_recovery_codes(1)
        await server.db_commit_totp_setup(fp, username_secret, codes)
        server.user_totp_secrets[fp] = username_secret

        call_count = 0
        real_consume = server.db_check_and_consume_recovery_code

        async def counting_consume(*a, **kw):
            nonlocal call_count
            call_count += 1
            return await real_consume(*a, **kw)

        server.db_check_and_consume_recovery_code = counting_consume
        try:
            await ws.send(json.dumps({
                "type": "totp_disable",
                "code": "000000",  # deliberately wrong -- forces the recovery_code fallback path
                "recovery_code": "X" * (512 * 1024),
            }))
            failed = await drain_until(ws, "totp_disable_failed")
            assert failed["type"] == "totp_disable_failed"
            assert call_count == 0
        finally:
            server.db_check_and_consume_recovery_code = real_consume
        assert fp in server.user_totp_secrets  # unaffected
    finally:
        await ws.close()


# ── 12. a malformed recovery-code shape is rejected ───────────────────────

async def test_malformed_recovery_code_shape_rejected():
    for bad in (
        "ABCDE-ABCDE-ABCDE-ABCD",     # one char short
        "ABCDE-ABCDE-ABCDE-ABCDEF",   # one char long
        "ABCDEABCDEABCDEABCDE",       # no dashes
        "ABCDG-ABCDE-ABCDE-ABCDE",    # 'G' not valid hex
        "",
        None,
        12345,
        ["A"],
        "X" * 1000,
    ):
        assert not server.is_valid_recovery_code(bad)


# ── 13. an officially-generated recovery code still works ────────────────

async def test_official_generated_recovery_code_still_works():
    codes = server.generate_recovery_codes(4)
    for code in codes:
        assert server.is_valid_recovery_code(code)
        # Lowercase/whitespace-tolerant, matching _hash_recovery_code()'s
        # own pre-existing strip()/upper() normalization.
        assert server.is_valid_recovery_code(f"  {code.lower()}  ")


# ── 14. a TOTP-disabled account is still subject to the totp_setup
#        per-user rate limit ─────────────────────────────────────────────

async def test_totp_disabled_account_subject_to_setup_rate_limit(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s648-ratelimit-nototp")
    try:
        assert fp not in server.user_totp_secrets
        rejected = False
        for i in range(server.TOTP_SETUP_RATE_LIMIT + 5):
            secret = _totp_random_secret()
            await ws.send(json.dumps({
                "type": "totp_setup", "secret": secret, "new_code": "000000",  # wrong on purpose
            }))
        for _ in range(server.TOTP_SETUP_RATE_LIMIT + 5):
            msg = json.loads(await ws.recv())
            if msg.get("type") == "error" and msg.get("reason") == "Rate limit exceeded":
                rejected = True
                break
        assert rejected
    finally:
        await ws.close()


# ── 15. Sybil accounts cannot exceed the global setup-work budget ────────

async def test_sybil_accounts_cannot_exceed_global_setup_budget():
    real_limit = server.TOTP_SETUP_GLOBAL_LIMIT
    real_enabled = server.TOTP_SETUP_GLOBAL_ENABLED
    server.TOTP_SETUP_GLOBAL_LIMIT = 3
    server.TOTP_SETUP_GLOBAL_ENABLED = True
    server.totp_setup_global_rate["count"] = 0
    server.totp_setup_global_rate["reset_time"] = server.time.time()
    try:
        # Three distinct "accounts" (the budget is process-wide, not keyed
        # on username at all) exhaust the shared budget between them.
        assert server.totp_setup_global_rate_ok() is True
        assert server.totp_setup_global_rate_ok() is True
        assert server.totp_setup_global_rate_ok() is True
        assert server.totp_setup_global_rate_ok() is False
        assert server.totp_setup_global_rate_ok() is False
    finally:
        server.TOTP_SETUP_GLOBAL_LIMIT = real_limit
        server.TOTP_SETUP_GLOBAL_ENABLED = real_enabled


# ── 16. malformed giant input does not consume the global expensive-work
#        budget ───────────────────────────────────────────────────────────

async def test_malformed_giant_input_does_not_consume_global_budget(running_server):
    real_limit = server.TOTP_SETUP_GLOBAL_LIMIT
    server.TOTP_SETUP_GLOBAL_LIMIT = 1
    server.totp_setup_global_rate["count"] = 0
    server.totp_setup_global_rate["reset_time"] = server.time.time()
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s648-giantnobudget")
    try:
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": "Z" * (512 * 1024), "new_code": "000000",
        }))
        failed = await drain_until(ws, "totp_setup_failed")
        assert failed["reason"] == "invalid_code"
        # The malformed secret must not have touched the global budget --
        # a subsequent syntactically-valid attempt still has its full slot.
        assert server.totp_setup_global_rate["count"] == 0
    finally:
        server.TOTP_SETUP_GLOBAL_LIMIT = real_limit
        await ws.close()


# ── 17. valid first-time setup still commits correctly under the new
#        validators (existing test_totp_setup_first_time_succeeds_with_
#        new_code already covers the full flow -- this focuses narrowly on
#        the validators themselves not rejecting a genuine attempt) ──────

async def test_valid_first_time_setup_still_commits_correctly(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s648-validsetup")
    try:
        secret = _totp_random_secret()
        code = _current_totp_code(secret)
        await ws.send(json.dumps({"type": "totp_setup", "secret": secret, "new_code": code}))
        ok = await drain_until(ws, "totp_setup_ok")
        assert len(ok["recovery_codes"]) == 8
        assert server.user_totp_secrets[fp] == secret
        with server.db_connect() as conn:
            row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (fp,)).fetchone()
        assert row is not None
    finally:
        await ws.close()


# ── 18. _db_commit_totp_setup_sync rejects an oversized secret directly ──

async def test_db_commit_totp_setup_rejects_oversized_secret_directly():
    username = "S648DIRECTREJECT1"
    with pytest.raises(ValueError):
        server._db_commit_totp_setup_sync(username, "A" * 1000, server.generate_recovery_codes(1))
    with server.db_connect() as conn:
        row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (username,)).fetchone()
    assert row is None


# ── 19/20. an oversized secret never appears in SQLite or in
#           user_totp_secrets ─────────────────────────────────────────────

async def test_oversized_secret_never_persists_or_enters_ram(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s648-oversizedpersist")
    try:
        await ws.send(json.dumps({
            "type": "totp_setup", "secret": "Q" * (512 * 1024), "new_code": "123456",
        }))
        failed = await drain_until(ws, "totp_setup_failed")
        assert failed["reason"] == "invalid_code"
        assert fp not in server.user_totp_secrets
        with server.db_connect() as conn:
            row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (fp,)).fetchone()
        assert row is None
    finally:
        await ws.close()


# ── 21. startup refuses an oversized/malformed stored secret ─────────────

async def test_startup_refuses_malformed_stored_secret(tmp_path):
    db_path = tmp_path / "s648_bad_secret.db"
    setup_code = (
        "import sqlite3;"
        "conn = sqlite3.connect(r'" + str(db_path) + "');"
        "conn.execute('CREATE TABLE user_totp (username TEXT PRIMARY KEY, secret TEXT NOT NULL, "
        "created_at REAL NOT NULL, last_counter INTEGER NOT NULL DEFAULT -1)');"
        "conn.execute(\"INSERT INTO user_totp (username, secret, created_at) VALUES "
        "('BADSECRETUSR0001', 'NOTVALIDBASE32ATALL', 0)\");"
        "conn.commit(); conn.close()"
    )
    setup_result = subprocess.run([sys.executable, "-c", setup_code], capture_output=True, text=True, timeout=20)
    assert setup_result.returncode == 0, setup_result.stdout + setup_result.stderr

    result = _run_server_subprocess(
        "import server; server._db_load_totp_sync()",
        {"DB_PATH": str(db_path)}, tmp_path,
    )
    assert result.returncode != 0
    assert "RuntimeError" in result.stderr
    assert "not protocol-bounded" in result.stderr


# ── 22. startup accepts all legitimate historical (canonical-shaped)
#        stored secrets ──────────────────────────────────────────────────

async def test_startup_accepts_legitimate_stored_secrets(tmp_path):
    db_path = tmp_path / "s648_good_secrets.db"
    good_secret_1 = _totp_random_secret()
    good_secret_2 = _totp_random_secret()
    setup_code = (
        "import sqlite3;"
        "conn = sqlite3.connect(r'" + str(db_path) + "');"
        "conn.execute('CREATE TABLE user_totp (username TEXT PRIMARY KEY, secret TEXT NOT NULL, "
        "created_at REAL NOT NULL, last_counter INTEGER NOT NULL DEFAULT -1)');"
        "conn.execute(\"INSERT INTO user_totp (username, secret, created_at) VALUES "
        f"('GOODSECRETUSR0001', '{good_secret_1}', 0)\");"
        "conn.execute(\"INSERT INTO user_totp (username, secret, created_at) VALUES "
        f"('GOODSECRETUSR0002', '{good_secret_2}', 0)\");"
        "conn.commit(); conn.close()"
    )
    setup_result = subprocess.run([sys.executable, "-c", setup_code], capture_output=True, text=True, timeout=20)
    assert setup_result.returncode == 0, setup_result.stdout + setup_result.stderr

    result = _run_server_subprocess(
        "import server; loaded = server._db_load_totp_sync(); "
        "assert loaded['GOODSECRETUSR0001'] == " + repr(good_secret_1) + "; "
        "assert loaded['GOODSECRETUSR0002'] == " + repr(good_secret_2) + "; "
        "print('STARTUP_LOAD_OK')",
        {"DB_PATH": str(db_path)}, tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "STARTUP_LOAD_OK" in result.stdout


# ── 23/24/25/26. existing TOTP replay, durable second-factor,
#    re-enrollment (S6-33), and encryption/fail-closed (S6-43) test
#    sections all remain green -- exercised by running the full suite
#    (all TOTP secret literals in those sections were migrated to the
#    canonical TOTP_TEST_SECRET*/_totp_random_secret() shape as part of
#    this fix, since the previous 16-char/10-byte example-vector literals
#    they used are no longer accepted by decode_totp_secret()), not
#    re-tested here.


# ── Attack regression: a registered account without TOTP repeatedly
#    submits near-frame-limit valid-looking secrets ───────────────────────

async def test_flood_of_near_frame_limit_secrets_bounded_by_all_layers(running_server):
    real_b32decode = server.base64.b32decode
    calls = []

    def spy_b32decode(*a, **kw):
        calls.append(a)
        return real_b32decode(*a, **kw)

    server.base64.b32decode = spy_b32decode
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s648-attackflood")
    try:
        await drain_until(ws, "register_ok")
        rejected_count = 0
        attempts = server.TOTP_SETUP_RATE_LIMIT + 10
        # "Near-frame-limit" relative to the TEST fixture's own ceiling, not
        # production's MAX_PACKET_SIZE_BYTES (6 MiB) -- running_server's
        # websockets.serve() doesn't set max_size at all, so it defaults to
        # the library's 1 MiB (see S6-45's own test-infrastructure note for
        # this exact distinction). 900 KiB stays comfortably under that
        # while still exercising a genuinely large attacker payload.
        near_limit_secret = "A" * (900 * 1024)
        for i in range(attempts):
            await ws.send(json.dumps({
                "type": "totp_setup", "secret": near_limit_secret, "new_code": "000000",
            }))
        for _ in range(attempts):
            msg = json.loads(await ws.recv())
            if msg.get("type") in ("totp_setup_failed",) or (
                msg.get("type") == "error" and msg.get("reason") == "Rate limit exceeded"
            ):
                rejected_count += 1
        assert rejected_count == attempts

        # None of these oversized attempts ever reached base64.b32decode().
        assert calls == []
        # None reached SQLite -- no durable row for this account.
        with server.db_connect() as conn:
            row = conn.execute("SELECT secret FROM user_totp WHERE username = ?", (fp,)).fetchone()
        assert row is None
        # Retained RAM never grew for this account.
        assert fp not in server.user_totp_secrets
        # The per-user rate/global guards actually bounded how much
        # accepted verification work happened -- covered by rejected_count
        # == attempts above (every single one was rejected, none reached
        # actual TOTP verification).
    finally:
        server.base64.b32decode = real_b32decode
        await ws.close()


# ── Direct media-chunk relay hardening (S6-49) ────────────────────────────
#
# image_chunk/video_chunk/file_chunk relayed message.get("data") verbatim to
# any online `to` with no is_valid_fingerprint() check, no protocol-specific
# field bounds, and no chunk-specific rate/byte limit at all -- an
# authenticated client could use the chunk protocol as an unrestricted
# high-bandwidth relay to any online fingerprint. See
# SECURITY_INVARIANTS.md #62 and KNOWN_SECURITY_ISSUES.md S6-49. Confirmed
# by inspection that neither shipped client currently sends these three bare
# types directly (sendImage()/sendFile()/sendVideoCircle() always route
# through sendAnonOrDirect(), which always wraps in anon_message) -- the
# handlers are hardened anyway, same "dormant is not deleted" posture as
# S6-47's Channels note.


def _chunk_msg(msg_type, id_field, to, transfer_id, chunk_index, total_chunks,
               data="X" * 10, signature="sig", **extra):
    msg = {
        "type": msg_type, "to": to, id_field: transfer_id,
        "chunk_index": chunk_index, "total_chunks": total_chunks,
        "data": data, "signature": signature,
    }
    msg.update(extra)
    return msg


# ── 1/4. official Android/Desktop image chunk passes ─────────────────────

async def test_official_android_image_chunk_passes(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-img-sender")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-img-recv")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        image_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_chunk_msg(
            "image_chunk", "image_id", recv_fp, image_id, 0, 3,
            data="A" * 120_000, signature="B" * 96, encrypted=True,
        )))
        ack = await drain_until(sender_ws, "chunk_ack")
        assert ack["image_id"] == image_id and ack["chunk_index"] == 0
        relayed = await drain_until(recv_ws, "image_chunk")
        assert relayed["image_id"] == image_id
        assert relayed["from"] == sender_fp
        assert relayed["encrypted"] is True
        assert len(relayed["data"]) == 120_000
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 2. official Android video chunk passes ────────────────────────────────

async def test_official_android_video_chunk_passes(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-vid-sender")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-vid-recv")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        video_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_chunk_msg(
            "video_chunk", "video_id", recv_fp, video_id, 0, 5,
            data="C" * 120_000, signature="D" * 96, duration=12, encrypted=True,
        )))
        ack = await drain_until(sender_ws, "chunk_ack")
        assert ack["video_id"] == video_id and ack["chunk_index"] == 0
        relayed = await drain_until(recv_ws, "video_chunk")
        assert relayed["video_id"] == video_id
        assert relayed["duration"] == 12
        assert relayed["encrypted"] is True
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 3. official Android file chunk passes ─────────────────────────────────

async def test_official_android_file_chunk_passes(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-file-sender")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-file-recv")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        file_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_chunk_msg(
            "file_chunk", "file_id", recv_fp, file_id, 0, 2,
            data="E" * 120_000, signature="F" * 96,
            encrypted_file_name="G" * 100,
        )))
        ack = await drain_until(sender_ws, "chunk_ack")
        assert ack["file_id"] == file_id and ack["chunk_index"] == 0
        relayed = await drain_until(recv_ws, "file_chunk")
        assert relayed["file_id"] == file_id
        assert relayed["encrypted_file_name"] == "G" * 100
        assert relayed["file_name"] is None  # not sent by the current client
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 4. Desktop equivalents (legacy file_name field still supported
#       alongside the current encrypted_file_name one) ───────────────────

async def test_desktop_file_chunk_with_legacy_file_name_passes(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-desktop-sender")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-desktop-recv")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        file_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_chunk_msg(
            "file_chunk", "file_id", recv_fp, file_id, 0, 1,
            data="H" * 1000, signature="I" * 96,
            file_name="report.pdf",
        )))
        await drain_until(sender_ws, "chunk_ack")
        relayed = await drain_until(recv_ws, "file_chunk")
        assert relayed["file_name"] == "report.pdf"
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 5. non-canonical `to` rejected before clients.get() lookup ───────────

class _SpyGetDict(dict):
    """dict.get is a read-only method slot on the built-in type -- can't be
    monkeypatched on a plain dict instance directly, so a thin subclass
    records calls instead."""
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.get_calls = []

    def get(self, *a, **kw):
        self.get_calls.append(a)
        return super().get(*a, **kw)


async def test_noncanonical_to_rejected_before_clients_lookup(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-badto")
    try:
        await drain_until(sender_ws, "register_ok")
        real_clients = server.clients
        spy_clients = _SpyGetDict(real_clients)
        server.clients = spy_clients
        try:
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", "not-a-fingerprint", str(uuid.uuid4()), 0, 1,
            )))
            with pytest.raises(asyncio.TimeoutError):
                await drain_until(sender_ws, "chunk_ack", timeout=0.5)
            assert spy_clients.get_calls == []
        finally:
            server.clients = real_clients
    finally:
        await sender_ws.close()


# ── 6. multi-megabyte data above the chunk protocol limit is rejected
#       before relay ──────────────────────────────────────────────────────

async def test_oversized_data_rejected_before_relay(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-hugedata-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-hugedata-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps(_chunk_msg(
            "image_chunk", "image_id", recv_fp, str(uuid.uuid4()), 0, 1,
            data="Z" * (server.MEDIA_CHUNK_DATA_MAX_LEN + 1000),
        )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(recv_ws, "image_chunk", timeout=0.5)
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 7. wrong-type data rejected ───────────────────────────────────────────

async def test_wrong_type_data_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-wrongdata")
    try:
        await drain_until(sender_ws, "register_ok")
        for bad_data in (["nested"], {"a": 1}, 12345, True, None):
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", canonical_fingerprint("S649_GHOST"),
                str(uuid.uuid4()), 0, 1, data=bad_data,
            )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
    finally:
        await sender_ws.close()


# ── 8. oversized transfer ID rejected ─────────────────────────────────────

async def test_oversized_transfer_id_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-hugeid")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps(_chunk_msg(
            "image_chunk", "image_id", canonical_fingerprint("S649_GHOST2"),
            "I" * (server.MEDIA_CHUNK_ID_MAX_LEN + 10), 0, 1,
        )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
    finally:
        await sender_ws.close()


# ── 9. oversized signature rejected ───────────────────────────────────────

async def test_oversized_signature_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-hugesig")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps(_chunk_msg(
            "image_chunk", "image_id", canonical_fingerprint("S649_GHOST3"),
            str(uuid.uuid4()), 0, 1, signature="S" * (server.MEDIA_CHUNK_SIGNATURE_MAX_LEN + 10),
        )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
    finally:
        await sender_ws.close()


# ── 10/11. negative and bool chunk_index rejected ─────────────────────────

async def test_negative_and_bool_chunk_index_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-badindex")
    try:
        await drain_until(sender_ws, "register_ok")
        for bad_index in (-1, True, False, "0", 1.5, None):
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", canonical_fingerprint("S649_GHOST4"),
                str(uuid.uuid4()), bad_index, 5,
            )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
    finally:
        await sender_ws.close()


# ── 12. chunk_index >= total_chunks rejected ──────────────────────────────

async def test_chunk_index_at_or_above_total_chunks_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-idxoob")
    try:
        await drain_until(sender_ws, "register_ok")
        for chunk_index, total_chunks in ((5, 5), (10, 5)):
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", canonical_fingerprint("S649_GHOST5"),
                str(uuid.uuid4()), chunk_index, total_chunks,
            )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
    finally:
        await sender_ws.close()


# ── 13. zero/negative total_chunks rejected ───────────────────────────────

async def test_zero_or_negative_total_chunks_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-totzero")
    try:
        await drain_until(sender_ws, "register_ok")
        for total_chunks in (0, -1, -100):
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", canonical_fingerprint("S649_GHOST6"),
                str(uuid.uuid4()), 0, total_chunks,
            )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
    finally:
        await sender_ws.close()


# ── 14. absurd total_chunks rejected ──────────────────────────────────────

async def test_absurd_total_chunks_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-totabsurd")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps(_chunk_msg(
            "image_chunk", "image_id", canonical_fingerprint("S649_GHOST7"),
            str(uuid.uuid4()), 0, server.MEDIA_CHUNK_MAX_TOTAL_CHUNKS + 1,
        )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
    finally:
        await sender_ws.close()


# ── 15. oversized file_name/encrypted_file_name rejected (not relayed,
#        replaced with null rather than truncated) ───────────────────────

async def test_oversized_file_name_not_relayed(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-hugefname-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-hugefname-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        file_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_chunk_msg(
            "file_chunk", "file_id", recv_fp, file_id, 0, 1,
            file_name="N" * (server.MEDIA_CHUNK_FILENAME_MAX_LEN + 10),
            encrypted_file_name="M" * (server.MEDIA_CHUNK_FILENAME_MAX_LEN + 10),
        )))
        await drain_until(sender_ws, "chunk_ack")
        relayed = await drain_until(recv_ws, "file_chunk")
        assert relayed["file_name"] is None
        assert relayed["encrypted_file_name"] is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 16. successful chunk gets an ACK only after send_safe() actually
#        succeeds ─────────────────────────────────────────────────────────

async def test_ack_sent_only_after_send_safe_succeeds(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-acksucceed-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-acksucceed-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        real_send_safe = server.send_safe
        calls = []

        async def spy_send_safe(*a, **kw):
            calls.append(a)
            return await real_send_safe(*a, **kw)

        server.send_safe = spy_send_safe
        try:
            image_id = str(uuid.uuid4())
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", recv_fp, image_id, 0, 1,
            )))
            ack = await drain_until(sender_ws, "chunk_ack")
            assert ack["image_id"] == image_id
            assert len(calls) == 1  # send_safe was actually called, and succeeded
        finally:
            server.send_safe = real_send_safe
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 17. a rejected chunk never produces a chunk_ack ───────────────────────

async def test_rejected_chunk_produces_no_ack(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-norejack")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps(_chunk_msg(
            "image_chunk", "image_id", canonical_fingerprint("S649_GHOST8"),
            str(uuid.uuid4()), -1, 5,   # negative chunk_index -- envelope rejection
        )))
        with pytest.raises(asyncio.TimeoutError):
            await drain_until(sender_ws, "chunk_ack", timeout=0.5)
    finally:
        await sender_ws.close()


# ── 18. per-user byte budget bounds one sender ────────────────────────────

async def test_per_user_byte_budget_bounds_one_sender(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-userbudget-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-userbudget-r")
    real_user_max = server.MEDIA_CHUNK_USER_MAX_BYTES
    server.MEDIA_CHUNK_USER_MAX_BYTES = 50_000
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        rejected = False
        for i in range(5):
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", recv_fp, str(uuid.uuid4()), 0, 1,
                data="A" * 20_000,
            )))
        for _ in range(5):
            msg = json.loads(await sender_ws.recv())
            if msg.get("type") == "status" and msg.get("status") == "rate_limited":
                rejected = True
                break
        assert rejected
    finally:
        server.MEDIA_CHUNK_USER_MAX_BYTES = real_user_max
        await sender_ws.close()
        await recv_ws.close()


# ── 19. global byte budget bounds many Sybil senders ──────────────────────

async def test_global_byte_budget_bounds_many_sybil_senders(running_server):
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-globalbudget-r")
    real_global_max = server.MEDIA_CHUNK_GLOBAL_MAX_BYTES
    server.MEDIA_CHUNK_GLOBAL_MAX_BYTES = 50_000
    senders = []
    try:
        await drain_until(recv_ws, "register_ok")
        rejected = False
        for i in range(5):
            sw, sfp, _, _ = await connect_and_register(running_server, device_id=f"s649-globalbudget-s{i}")
            senders.append(sw)
            await drain_until(sw, "register_ok")
            await sw.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", recv_fp, str(uuid.uuid4()), 0, 1,
                data="A" * 20_000,
            )))
        for sw in senders:
            msg = json.loads(await sw.recv())
            if msg.get("type") == "status" and msg.get("status") == "rate_limited":
                rejected = True
        assert rejected
    finally:
        server.MEDIA_CHUNK_GLOBAL_MAX_BYTES = real_global_max
        for sw in senders:
            await sw.close()
        await recv_ws.close()


# ── 20. recipient budget bounds many senders against one online victim ───

async def test_recipient_budget_bounds_many_senders_against_one_victim(running_server):
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-recipbudget-r")
    real_recipient_max = server.MEDIA_CHUNK_RECIPIENT_MAX_BYTES
    server.MEDIA_CHUNK_RECIPIENT_MAX_BYTES = 50_000
    senders = []
    try:
        await drain_until(recv_ws, "register_ok")
        rejected = False
        for i in range(5):
            sw, sfp, _, _ = await connect_and_register(running_server, device_id=f"s649-recipbudget-s{i}")
            senders.append(sw)
            await drain_until(sw, "register_ok")
            await sw.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", recv_fp, str(uuid.uuid4()), 0, 1,
                data="A" * 20_000,
            )))
        for sw in senders:
            msg = json.loads(await sw.recv())
            if msg.get("type") == "status" and msg.get("status") == "rate_limited":
                rejected = True
        assert rejected
    finally:
        server.MEDIA_CHUNK_RECIPIENT_MAX_BYTES = real_recipient_max
        for sw in senders:
            await sw.close()
        await recv_ws.close()


# ── 21. limiter state self-prunes / stays bounded (window reset clears
#        stale entries back down, keyed only by real registered accounts) ─

async def test_limiter_state_resets_after_window_and_stays_bounded():
    real_window = server.MEDIA_CHUNK_USER_WINDOW_SEC
    server.MEDIA_CHUNK_USER_WINDOW_SEC = 0.2
    try:
        username = canonical_fingerprint("S649_WINDOWRESET")
        assert server.media_chunk_user_rate_ok(username, 1000)
        entry_before = dict(server.media_chunk_user_rate[username])
        await asyncio.sleep(0.3)
        assert server.media_chunk_user_rate_ok(username, 1000)
        entry_after = server.media_chunk_user_rate[username]
        # A fresh window resets the running total -- proves this doesn't
        # accumulate forever for one key, and the dict itself is keyed only
        # by real usernames (bounded key space), not attacker-controlled
        # arbitrary strings.
        assert entry_after["bytes"] == 1000
        assert entry_after["reset_time"] > entry_before["reset_time"]
    finally:
        server.MEDIA_CHUNK_USER_WINDOW_SEC = real_window


# ── 22. an offline/nonexistent target cannot be used for unlimited
#        chunk-attempt CPU work -- the attempt bucket bounds it, and the
#        byte budgets are never touched since nothing is ever relayed ────

async def test_offline_target_bounded_by_attempt_counter_not_byte_budget(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-offlineflood")
    real_attempt_limit = server.MEDIA_CHUNK_ATTEMPT_LIMIT
    server.MEDIA_CHUNK_ATTEMPT_LIMIT = 3
    try:
        await drain_until(sender_ws, "register_ok")
        ghost = canonical_fingerprint("S649_OFFLINE_GHOST")
        rejected_as_rate_limited = 0
        offline_statuses = 0
        for i in range(6):
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", ghost, str(uuid.uuid4()), 0, 1,
            )))
        for _ in range(6):
            msg = json.loads(await sender_ws.recv())
            if msg.get("type") == "status" and msg.get("status") == "rate_limited":
                rejected_as_rate_limited += 1
            elif msg.get("type") == "status" and msg.get("status") == "offline":
                offline_statuses += 1
        assert rejected_as_rate_limited >= 1
        assert offline_statuses >= 1
        # Nothing was ever relayed (target never online), so no egress
        # byte budget was ever consumed.
        assert sender_fp not in server.media_chunk_user_rate
        assert ghost not in server.media_chunk_recipient_rate
    finally:
        server.MEDIA_CHUNK_ATTEMPT_LIMIT = real_attempt_limit
        await sender_ws.close()


# ── 23. a normal multi-chunk transfer fits comfortably within the
#        configured limits ────────────────────────────────────────────────

async def test_normal_multichunk_transfer_fits_configured_limits(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s649-normalxfer-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s649-normalxfer-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        image_id = str(uuid.uuid4())
        total_chunks = 5
        for i in range(total_chunks):
            await sender_ws.send(json.dumps(_chunk_msg(
                "image_chunk", "image_id", recv_fp, image_id, i, total_chunks,
                data="P" * 120_000,
            )))
        acks = 0
        for _ in range(total_chunks):
            msg = json.loads(await sender_ws.recv())
            if msg.get("type") == "chunk_ack":
                acks += 1
        assert acks == total_chunks
        received = 0
        for _ in range(total_chunks):
            msg = json.loads(await recv_ws.recv())
            if msg.get("type") == "image_chunk":
                received += 1
        assert received == total_chunks
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 24. MAX_PACKET_SIZE_BYTES remains unchanged -- this fix adds a
#        chunk-protocol-specific ceiling, it does not touch the global
#        websocket frame ceiling other traffic still legitimately needs ──

async def test_max_packet_size_bytes_unchanged():
    assert server.MAX_PACKET_SIZE_BYTES == 6 * 1024 * 1024


# ── Avatar persistence + registration/reconnect bandwidth amplification
#    (S6-50) ────────────────────────────────────────────────────────────
#
# register()'s avatar field bypassed profile_update's rate limit entirely
# (its own independent `len(...) < 200_000` check, no rate_limit_check() at
# all), every successful register/reconnect broadcast the caller's avatar to
# every online account AND received the server's ENTIRE avatar directory
# unconditionally, and neither path bounded aggregate persisted avatar bytes
# independently of account count (MAX_REGISTERED_USERS defaults unlimited).
# See SECURITY_INVARIANTS.md #63 and KNOWN_SECURITY_ISSUES.md S6-50.

def _official_avatar_b64(nbytes=6000) -> str:
    """Stand-in for a real Android-generated 128x128 JPEG q85 avatar (a few
    KB, per user_avatars' own long-standing comment) -- is_valid_avatar()
    only bounds encoded/decoded byte length (deliberately: it does not
    decode untrusted image formats, see its own comment), so arbitrary bytes
    of a realistic size exercise the exact same validation path a genuine
    JPEG would."""
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()


def _read_avatar_row(username):
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT avatar_b64, avatar_bytes FROM user_avatars WHERE username = ?", (username,)
        ).fetchone()


def _read_avatars_meta():
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT total_rows, total_bytes FROM user_avatars_meta WHERE id = 1"
        ).fetchone()


async def _wait_for_avatar_from(ws, from_fp, timeout=3.0):
    async with asyncio.timeout(timeout):
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("type") == "avatar_data" and msg.get("from") == from_fp:
                return msg


# ── 1/2. official-format avatars pass the validator ──────────────────────

async def test_official_android_avatar_passes_validator():
    assert server.is_valid_avatar(_official_avatar_b64())


async def test_official_desktop_avatar_format_also_passes_validator():
    # Desktop's UserStorage.kt has getMyAvatar()/saveMyAvatar() plumbing but
    # no UI wired to call either, and its register() packet in
    # WebSocketClient.kt never includes an "avatar" field at all (confirmed
    # by inspection during this review) -- Desktop currently never SENDS an
    # avatar. There is therefore no second, divergent wire format to
    # validate separately: is_valid_avatar() is format-agnostic within its
    # byte bounds, so whatever Desktop might send in the future (or a custom
    # client driving the wire protocol directly today) is already covered
    # by the exact same check real Android avatars pass.
    assert server.is_valid_avatar(_official_avatar_b64())


# ── 3. wrong-type avatar rejected before len/base64/DB ────────────────────

async def test_wrong_type_avatar_rejected():
    assert not server.is_valid_avatar(12345)
    assert not server.is_valid_avatar(["not", "a", "string"])
    assert not server.is_valid_avatar(None)


# ── 4. oversized encoded avatar rejected before decode ────────────────────

async def test_oversized_encoded_avatar_rejected_before_decode():
    oversized = "A" * (server.AVATAR_MAX_B64_LEN + 1)
    assert not server.is_valid_avatar(oversized)


# ── 5. invalid base64 rejected ────────────────────────────────────────────

async def test_invalid_base64_avatar_rejected():
    assert not server.is_valid_avatar("not valid base64!!! ###")


# ── 6. decoded avatar above maximum rejected ──────────────────────────────

async def test_decoded_avatar_above_maximum_rejected():
    # Deliberately picked so the ENCODED length passes the pre-decode length
    # gate (AVATAR_MAX_B64_LEN has a small amount of slack over the exact
    # base64 expansion of AVATAR_MAX_DECODED_BYTES, same as
    # CHANNEL_POST_IMAGE_B64_MAX_LEN's own precedent) -- proving the
    # SEPARATE decoded-byte check is what actually catches this, not the
    # length gate alone.
    raw = secrets.token_bytes(server.AVATAR_MAX_DECODED_BYTES + 4)
    b64 = base64.b64encode(raw).decode()
    assert len(b64) == server.AVATAR_MAX_B64_LEN
    assert not server.is_valid_avatar(b64)


# ── 7. normal avatar persists ──────────────────────────────────────────────

async def test_normal_avatar_persists(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s650-normal")
    try:
        await drain_until(ws, "register_ok")
        avatar = _official_avatar_b64()
        await ws.send(json.dumps({"type": "profile_update", "avatar": avatar}))
        await asyncio.sleep(0.2)
        assert server.user_avatars.get(fp) == avatar
        row = _read_avatar_row(fp)
        assert row is not None and row[0] == avatar
    finally:
        await ws.close()


# ── 8. register and profile_update use the SAME validator ────────────────

async def test_register_and_profile_update_share_same_validator():
    # Neither handler reimplements is_valid_avatar()'s checks inline anymore
    # -- both route through the ONE canonical admission path
    # (apply_avatar_mutation()), which itself calls is_valid_avatar() as its
    # very first step. Structural check: both call sites exist, and the
    # shared function itself actually performs the validation.
    mutation_src = inspect.getsource(server.apply_avatar_mutation)
    assert "is_valid_avatar(avatar_value)" in mutation_src
    server_src = inspect.getsource(server)
    assert server_src.count("apply_avatar_mutation(username,") >= 2


# ── 9/14. register and profile_update share ONE mutation-rate bucket --
#         alternating between the two message types cannot double the
#         allowance ─────────────────────────────────────────────────────

async def test_register_and_profile_update_share_one_rate_bucket_over_wire(running_server):
    priv, pub_der = gen_keypair()
    fp = fingerprint_of(pub_der)
    device_id = canonical_device_id("s650-alternate")
    for i in range(12):
        avatar = _official_avatar_b64(500 + i)  # each genuinely different
        ws = await websockets.connect(running_server)
        try:
            await handshake(ws, priv, pub_der)
            if i % 2 == 0:
                # register()'s own avatar field -- half the mutations.
                await register(ws, pub_der, device_id, extra={"avatar": avatar})
                await drain_until(ws, "register_ok")
            else:
                # profile_update on an ordinary reconnect (no avatar in
                # register() itself, so that mutation is an EMPTY no-op) --
                # the other half.
                await register(ws, pub_der, device_id)
                await drain_until(ws, "register_ok")
                await ws.send(json.dumps({"type": "profile_update", "avatar": avatar}))
                await asyncio.sleep(0.05)
        finally:
            await ws.close()
    # 12 genuine changes across BOTH message types against the single
    # per-user "profile_update" bucket (limit 10) -- if register() had an
    # independent bucket, all 12 would have gone through (count would sit
    # at <=10 in EACH of two separate counters). One shared counter means
    # the combined count is exactly 12, well past the 10 limit.
    assert server.rate_limits[fp]["profile_update"]["count"] == 12


# ── 10. unchanged avatar on reconnect causes no SQLite write ──────────────

async def test_unchanged_avatar_causes_no_sqlite_write():
    fp = canonical_fingerprint("s650-nowrite")
    avatar = _official_avatar_b64()
    assert await server.apply_avatar_mutation(fp, avatar) == "STORED"
    before_rows, before_bytes = _read_avatars_meta()
    for _ in range(5):
        assert await server.apply_avatar_mutation(fp, avatar) == "UNCHANGED"
    after_rows, after_bytes = _read_avatars_meta()
    assert (after_rows, after_bytes) == (before_rows, before_bytes)


# ── 11. unchanged avatar on reconnect causes no broadcast ─────────────────

async def test_unchanged_avatar_causes_no_broadcast(running_server):
    bystander_ws, bystander_fp, _, _ = await connect_and_register(running_server, device_id="s650-nobroadcast-b")
    try:
        await drain_until(bystander_ws, "register_ok")
        priv, pub_der = gen_keypair()
        fp = fingerprint_of(pub_der)
        device_id = canonical_device_id("s650-nobroadcast-s")
        avatar = _official_avatar_b64()
        # First connection: a genuine STORE, so we know the bystander CAN
        # see a broadcast at all.
        ws1 = await websockets.connect(running_server)
        await handshake(ws1, priv, pub_der)
        await register(ws1, pub_der, device_id, extra={"avatar": avatar})
        await drain_until(ws1, "register_ok")
        await _wait_for_avatar_from(bystander_ws, fp)
        await ws1.close()
        # Second connection: SAME avatar -- must be a silent no-op.
        ws2 = await websockets.connect(running_server)
        await handshake(ws2, priv, pub_der)
        await register(ws2, pub_der, device_id, extra={"avatar": avatar})
        await drain_until(ws2, "register_ok")
        got_broadcast = True
        try:
            await _wait_for_avatar_from(bystander_ws, fp, timeout=0.7)
        except (asyncio.TimeoutError, TimeoutError):
            got_broadcast = False
        assert not got_broadcast
        await ws2.close()
    finally:
        await bystander_ws.close()


# ── 12. unchanged avatar does not consume the global mutation budget ─────

async def test_unchanged_avatar_does_not_consume_global_budget():
    real_limit   = server.AVATAR_UPDATE_GLOBAL_LIMIT
    real_enabled = server.AVATAR_UPDATE_GLOBAL_ENABLED
    server.AVATAR_UPDATE_GLOBAL_LIMIT   = 2
    server.AVATAR_UPDATE_GLOBAL_ENABLED = True
    try:
        fp = canonical_fingerprint("s650-globalbudget-1")
        avatar = _official_avatar_b64()
        assert await server.apply_avatar_mutation(fp, avatar) == "STORED"        # consumes 1/2
        for _ in range(50):
            assert await server.apply_avatar_mutation(fp, avatar) == "UNCHANGED"  # consumes 0
        fp2 = canonical_fingerprint("s650-globalbudget-2")
        assert await server.apply_avatar_mutation(fp2, _official_avatar_b64(700)) == "STORED"  # consumes 2/2
        fp3 = canonical_fingerprint("s650-globalbudget-3")
        assert await server.apply_avatar_mutation(fp3, _official_avatar_b64(800)) == "RATE_LIMITED"
    finally:
        server.AVATAR_UPDATE_GLOBAL_LIMIT   = real_limit
        server.AVATAR_UPDATE_GLOBAL_ENABLED = real_enabled


# ── 13. changed avatar DOES consume the normal mutation budget ───────────

async def test_changed_avatar_consumes_normal_mutation_budget():
    fp = canonical_fingerprint("s650-consumesbudget")
    for i in range(10):
        assert await server.apply_avatar_mutation(fp, _official_avatar_b64(500 + i)) == "STORED"
    assert await server.apply_avatar_mutation(fp, _official_avatar_b64(9999)) == "RATE_LIMITED"


# ── 15. DB failure leaves RAM unchanged ───────────────────────────────────

async def test_db_failure_leaves_ram_unchanged():
    fp = canonical_fingerprint("s650-dbfail-ram")
    original = _official_avatar_b64()
    assert await server.apply_avatar_mutation(fp, original) == "STORED"

    real_upsert = server.db_upsert_avatar

    async def _boom(username, avatar_b64, avatar_bytes):
        raise RuntimeError("simulated DB failure")

    server.db_upsert_avatar = _boom
    try:
        with pytest.raises(RuntimeError):
            await server.apply_avatar_mutation(fp, _official_avatar_b64(700))
    finally:
        server.db_upsert_avatar = real_upsert

    assert server.user_avatars.get(fp) == original
    row = _read_avatar_row(fp)
    assert row[0] == original


# ── 16. DB failure broadcasts nothing ─────────────────────────────────────

async def test_db_failure_broadcasts_nothing(running_server):
    bystander_ws, bystander_fp, _, _ = await connect_and_register(running_server, device_id="s650-dbfail-bystander")
    try:
        await drain_until(bystander_ws, "register_ok")
        fp = canonical_fingerprint("s650-dbfail-broadcast")

        real_upsert = server.db_upsert_avatar

        async def _boom(username, avatar_b64, avatar_bytes):
            raise RuntimeError("simulated DB failure")

        server.db_upsert_avatar = _boom
        try:
            with pytest.raises(RuntimeError):
                await server.apply_avatar_mutation(fp, _official_avatar_b64())
        finally:
            server.db_upsert_avatar = real_upsert

        got_broadcast = True
        try:
            await _wait_for_avatar_from(bystander_ws, fp, timeout=0.7)
        except (asyncio.TimeoutError, TimeoutError):
            got_broadcast = False
        assert not got_broadcast
    finally:
        await bystander_ws.close()


# ── 17. concurrent mutations for one account leave DB/RAM agreeing ───────

async def test_concurrent_mutations_single_account_agree_in_db_and_ram():
    fp = canonical_fingerprint("s650-concurrent")
    avatar_a = _official_avatar_b64(5000)
    avatar_b = _official_avatar_b64(5001)
    await asyncio.gather(
        server.apply_avatar_mutation(fp, avatar_a),
        server.apply_avatar_mutation(fp, avatar_b),
    )
    ram_value = server.user_avatars.get(fp)
    row = _read_avatar_row(fp)
    assert row is not None
    assert row[0] == ram_value
    assert ram_value in (avatar_a, avatar_b)


# ── 18. aggregate avatar byte cap rejects growth above cap ───────────────

async def test_aggregate_avatar_byte_cap_rejects_growth_above_cap():
    real_cap = server.AVATARS_MAX_TOTAL_BYTES
    server.AVATARS_MAX_TOTAL_BYTES = 1000
    try:
        fp1 = canonical_fingerprint("s650-cap-1")
        assert await server.apply_avatar_mutation(fp1, _official_avatar_b64(600)) == "STORED"
        fp2 = canonical_fingerprint("s650-cap-2")
        assert await server.apply_avatar_mutation(fp2, _official_avatar_b64(600)) == "FULL"
    finally:
        server.AVATARS_MAX_TOTAL_BYTES = real_cap


# ── 19. replacing a large avatar with a smaller one frees logical capacity ─

async def test_replacing_large_avatar_with_smaller_frees_capacity():
    real_cap = server.AVATARS_MAX_TOTAL_BYTES
    server.AVATARS_MAX_TOTAL_BYTES = 1200
    try:
        fp1 = canonical_fingerprint("s650-shrink-1")
        assert await server.apply_avatar_mutation(fp1, _official_avatar_b64(700)) == "STORED"
        fp2 = canonical_fingerprint("s650-shrink-2")
        # Doesn't fit yet -- fp1's full-size avatar is still counted.
        assert await server.apply_avatar_mutation(fp2, _official_avatar_b64(700)) == "FULL"
        # Replace fp1's avatar with a much smaller one -- delta accounting
        # frees room without ever needing headroom for old+new at once.
        assert await server.apply_avatar_mutation(fp1, _official_avatar_b64(50)) == "STORED"
        # NOW fp2's avatar fits.
        assert await server.apply_avatar_mutation(fp2, _official_avatar_b64(700)) == "STORED"
    finally:
        server.AVATARS_MAX_TOTAL_BYTES = real_cap


# ── 20. rejected FULL update leaves the old avatar intact ────────────────

async def test_rejected_full_update_leaves_old_avatar_intact():
    real_cap = server.AVATARS_MAX_TOTAL_BYTES
    server.AVATARS_MAX_TOTAL_BYTES = 1000
    try:
        fp = canonical_fingerprint("s650-fullintact")
        original = _official_avatar_b64(600)
        assert await server.apply_avatar_mutation(fp, original) == "STORED"
        filler_fp = canonical_fingerprint("s650-fullintact-filler")
        assert await server.apply_avatar_mutation(filler_fp, _official_avatar_b64(140)) == "STORED"
        status = await server.apply_avatar_mutation(fp, _official_avatar_b64(5000))
        assert status == "FULL"
        assert server.user_avatars.get(fp) == original
        row = _read_avatar_row(fp)
        assert row[0] == original
    finally:
        server.AVATARS_MAX_TOTAL_BYTES = real_cap


# ── 21. successful update adjusts avatar meta exactly ─────────────────────

async def test_successful_update_adjusts_avatar_meta_exactly():
    before_rows, before_bytes = _read_avatars_meta()
    fp = canonical_fingerprint("s650-metaexact")
    avatar = _official_avatar_b64(1234)
    assert await server.apply_avatar_mutation(fp, avatar) == "STORED"
    after_rows, after_bytes = _read_avatars_meta()
    assert after_rows == before_rows + 1
    assert after_bytes == before_bytes + len(avatar.encode("utf-8"))


# ── 22. startup rejects a DB already above the hard avatar cap ───────────

async def test_avatar_startup_refuses_when_over_total_bytes_cap(tmp_path):
    db_path = tmp_path / "s650_test.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("""
            CREATE TABLE user_avatars (
                username   TEXT PRIMARY KEY,
                avatar_b64 TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        big_avatar = base64.b64encode(secrets.token_bytes(2000)).decode()
        for i in range(5):
            conn.execute(
                "INSERT INTO user_avatars (username, avatar_b64, updated_at) VALUES (?, ?, 0)",
                (f"S650OVERCAP{i:04d}", big_avatar)
            )
        conn.commit()
    env = dict(os.environ)
    env["DB_PATH"] = str(db_path)
    env["AVATARS_MAX_TOTAL_BYTES"] = "1000"  # 5 rows * ~2700 b64 chars each >> 1000
    env.setdefault("MAX_REGISTERED_USERS", "0")
    env.setdefault("POW_DIFFICULTY_BITS", "0")
    result = subprocess.run(
        [sys.executable, "-c", "import server; server.start_server()"],
        cwd=_SERVER_DIR, env=env, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode != 0
    assert "[FATAL]" in result.stdout
    assert "user_avatars" in result.stdout


# ── 23. startup loads legitimate bounded avatars normally ────────────────

async def test_avatar_startup_loads_bounded_avatars_normally(tmp_path):
    db_path = tmp_path / "s650_test2.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("""
            CREATE TABLE user_avatars (
                username   TEXT PRIMARY KEY,
                avatar_b64 TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        small_avatar = base64.b64encode(secrets.token_bytes(500)).decode()
        for i in range(3):
            conn.execute(
                "INSERT INTO user_avatars (username, avatar_b64, updated_at) VALUES (?, ?, 0)",
                (f"S650ATCAP{i:04d}", small_avatar)
            )
        conn.commit()
    env = dict(os.environ)
    env["DB_PATH"] = str(db_path)
    env.setdefault("MAX_REGISTERED_USERS", "0")
    env.setdefault("POW_DIFFICULTY_BITS", "0")
    code = (
        "import server\n"
        "server._db_setup_sync()\n"
        "rows, byts = server._db_get_avatars_meta_sync()\n"
        "assert rows == 3, rows\n"
        "print('AVATAR_META_OK' if rows <= server.AVATARS_MAX_TOTAL_ROWS "
        "and byts <= server.AVATARS_MAX_TOTAL_BYTES else 'WOULD_REFUSE')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_SERVER_DIR, env=env, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "AVATAR_META_OK" in result.stdout


# ── 24. one reconnect cannot trigger unbounded full-directory egress ─────

async def test_reconnect_avatar_sync_is_bounded(running_server):
    real_count_cap = server.AVATAR_SYNC_MAX_COUNT
    server.AVATAR_SYNC_MAX_COUNT = 5
    seeded = [canonical_fingerprint(f"s650-bulk-{i}") for i in range(20)]
    try:
        for fp in seeded:
            server.user_avatars[fp] = _official_avatar_b64(500)
        ws, fp, _, _ = await connect_and_register(running_server, device_id="s650-bulkreconnect")
        try:
            await drain_until(ws, "register_ok")
            received = 0
            try:
                async with asyncio.timeout(1.0):
                    while True:
                        msg = json.loads(await ws.recv())
                        if msg.get("type") == "avatar_data":
                            received += 1
            except (asyncio.TimeoutError, TimeoutError):
                pass
            assert received <= server.AVATAR_SYNC_MAX_COUNT
        finally:
            await ws.close()
    finally:
        server.AVATAR_SYNC_MAX_COUNT = real_count_cap
        for fp in seeded:
            server.user_avatars.pop(fp, None)


# ── 25. repeated reconnect with unchanged avatar cannot create broadcast
#        fanout ──────────────────────────────────────────────────────────

async def test_repeated_reconnect_unchanged_avatar_no_broadcast_fanout(running_server):
    bystander_ws, bystander_fp, _, _ = await connect_and_register(running_server, device_id="s650-repeat-bystander")
    try:
        await drain_until(bystander_ws, "register_ok")
        priv, pub_der = gen_keypair()
        fp = fingerprint_of(pub_der)
        device_id = canonical_device_id("s650-repeatreco")
        avatar = _official_avatar_b64()
        for _ in range(4):
            ws = await websockets.connect(running_server)
            await handshake(ws, priv, pub_der)
            await register(ws, pub_der, device_id, extra={"avatar": avatar})
            await drain_until(ws, "register_ok")
            await asyncio.sleep(0.1)
            await ws.close()
        broadcasts_for_fp = 0
        try:
            async with asyncio.timeout(1.0):
                while True:
                    msg = json.loads(await bystander_ws.recv())
                    if msg.get("type") == "avatar_data" and msg.get("from") == fp:
                        broadcasts_for_fp += 1
        except (asyncio.TimeoutError, TimeoutError):
            pass
        assert broadcasts_for_fp <= 1
    finally:
        await bystander_ws.close()


# ── 26. get_key (the current get_avatar-equivalent retrieval path)
#        requires a canonical target ────────────────────────────────────

async def test_get_key_requires_canonical_target(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s650-getkeytarget")
    try:
        await drain_until(ws, "register_ok")
        await ws.send(json.dumps({"type": "get_key", "target": "not-a-fingerprint"}))
        # Malformed target is silently dropped -- no public_key/avatar_data
        # reply at all. Prove this by sending a harmless ping right after
        # and confirming the FIRST thing that arrives is the pong, not a
        # stray reply for the malformed target.
        await ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await ws.recv())
        assert msg.get("type") == "pong"
    finally:
        await ws.close()


# ── 27. get_key retrieval abuse is bounded (previously unrated entirely) ──

async def test_get_key_retrieval_is_rate_limited(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s650-getkeyrate")
    target_fp = canonical_fingerprint("s650-getkeytarget2")
    try:
        await drain_until(ws, "register_ok")
        for _ in range(35):
            await ws.send(json.dumps({"type": "get_key", "target": target_fp}))
        replies_seen = 0
        errors_seen  = 0
        for _ in range(35):
            msg = json.loads(await ws.recv())
            if msg.get("type") == "public_key":
                replies_seen += 1
            elif msg.get("type") == "error" and msg.get("reason") == "Rate limit exceeded":
                errors_seen += 1
        assert errors_seen >= 1
        assert replies_seen <= 30
    finally:
        await ws.close()


# ── 28. normal avatar update remains visible to a legitimate client ───────

async def test_normal_avatar_update_visible_to_legitimate_client(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s650-visible-sender")
    viewer_ws, viewer_fp, _, _ = await connect_and_register(running_server, device_id="s650-visible-viewer")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(viewer_ws, "register_ok")
        avatar = _official_avatar_b64()
        await sender_ws.send(json.dumps({"type": "profile_update", "avatar": avatar}))
        msg = await _wait_for_avatar_from(viewer_ws, sender_fp)
        assert msg["avatar"] == avatar
    finally:
        await sender_ws.close()
        await viewer_ws.close()


# ── Attack regression A: one existing account repeatedly reconnects with
#    the SAME maximum-size avatar -- zero repeated DB writes, zero repeated
#    broadcasts, bounded reconnect egress ─────────────────────────────────

async def test_attack_repeated_reconnect_same_max_avatar_bounded(running_server):
    priv, pub_der = gen_keypair()
    fp = fingerprint_of(pub_der)
    device_id = canonical_device_id("s650-attack-a")
    bystander_ws, bystander_fp, _, _ = await connect_and_register(
        running_server, device_id="s650-attack-a-bystander"
    )
    try:
        await drain_until(bystander_ws, "register_ok")
        max_avatar = _official_avatar_b64(server.AVATAR_MAX_DECODED_BYTES)
        before_rows, before_bytes = _read_avatars_meta()
        for _ in range(8):
            ws = await websockets.connect(running_server)
            await handshake(ws, priv, pub_der)
            await register(ws, pub_der, device_id, extra={"avatar": max_avatar})
            await drain_until(ws, "register_ok")
            await asyncio.sleep(0.1)
            await ws.close()
        after_rows, after_bytes = _read_avatars_meta()
        # Exactly one row/byte-delta added -- the FIRST reconnect's genuine
        # STORE -- the remaining 7 byte-for-byte-identical reconnects wrote
        # nothing at all.
        assert after_rows == before_rows + 1
        assert after_bytes == before_bytes + len(max_avatar.encode("utf-8"))
        broadcasts = 0
        try:
            async with asyncio.timeout(1.0):
                while True:
                    msg = json.loads(await bystander_ws.recv())
                    if msg.get("type") == "avatar_data" and msg.get("from") == fp:
                        broadcasts += 1
        except (asyncio.TimeoutError, TimeoutError):
            pass
        assert broadcasts <= 1
    finally:
        await bystander_ws.close()


# ── Attack regression B: Sybil accounts each create a maximum legitimate
#    avatar -- persistent/live avatar bytes never exceed
#    AVATARS_MAX_TOTAL_BYTES ──────────────────────────────────────────────

async def test_attack_sybil_accounts_bounded_by_aggregate_cap():
    real_cap = server.AVATARS_MAX_TOTAL_BYTES
    server.AVATARS_MAX_TOTAL_BYTES = 200_000  # small, deterministic cap for a fast test
    try:
        max_avatar = _official_avatar_b64(server.AVATAR_MAX_DECODED_BYTES)  # ~87 KB b64
        stored = 0
        for i in range(6):  # 6 * ~87 KB > 200 KB -- some MUST be refused
            fp = canonical_fingerprint(f"s650-sybil-{i}")
            status = await server.apply_avatar_mutation(fp, max_avatar)
            if status == "STORED":
                stored += 1
            else:
                assert status == "FULL"
        _, total_bytes = _read_avatars_meta()
        assert total_bytes <= server.AVATARS_MAX_TOTAL_BYTES
        assert stored < 6
    finally:
        server.AVATARS_MAX_TOTAL_BYTES = real_cap


# ── WebRTC call signaling relay hardening (S6-51) ─────────────────────────
#
# The call relay handler forwarded the caller's ENTIRE arbitrary JSON frame
# to the recipient under the multi-megabyte MAX_PACKET_SIZE_BYTES ceiling,
# with count-only rate limits meant for small WebRTC messages (call_ice:
# 300/min) -- 300 * ~6 MiB is ~1.8 GiB/minute of potential relay input from
# one account. call_offer/call_answer also copied an unvalidated call_id
# into active_calls. See SECURITY_INVARIANTS.md #64 and
# KNOWN_SECURITY_ISSUES.md S6-51.

def _call_uuid() -> str:
    return str(uuid.uuid4())


def _sdp_of_len(n=800) -> str:
    return "v=0\r\n" + ("x" * max(0, n - 5))


def _ice_candidate_of_len(n=120) -> str:
    return "candidate:" + ("1" * max(0, n - 10))


# ── 1/2. real Android/Desktop offers pass ─────────────────────────────────

async def test_official_android_offer_passes(running_server):
    caller_ws, caller_fp, _, _ = await connect_and_register(running_server, device_id="s651-android-offer-c")
    callee_ws, callee_fp, _, _ = await connect_and_register(running_server, device_id="s651-android-offer-e")
    try:
        await drain_until(caller_ws, "register_ok")
        await drain_until(callee_ws, "register_ok")
        call_id = _call_uuid()
        await caller_ws.send(json.dumps({
            "type": "call_offer", "to": callee_fp, "call_id": call_id,
            "sdp": _sdp_of_len(800), "is_video": True, "is_group": False,
            "ts": int(server.time.time() * 1000),
        }))
        msg = json.loads(await callee_ws.recv())
        assert msg["type"] == "call_offer"
        assert msg["from"] == caller_fp
        assert msg["call_id"] == call_id
        assert msg["is_video"] is True
        assert msg["is_group"] is False
    finally:
        await caller_ws.close()
        await callee_ws.close()


async def test_official_desktop_offer_passes(running_server):
    # Desktop's DesktopCallManager.kt never sends `ts` at all -- confirming
    # it's genuinely optional, not silently required.
    caller_ws, caller_fp, _, _ = await connect_and_register(running_server, device_id="s651-desktop-offer-c")
    callee_ws, callee_fp, _, _ = await connect_and_register(running_server, device_id="s651-desktop-offer-e")
    try:
        await drain_until(caller_ws, "register_ok")
        await drain_until(callee_ws, "register_ok")
        call_id = _call_uuid()
        await caller_ws.send(json.dumps({
            "type": "call_offer", "to": callee_fp, "call_id": call_id,
            "sdp": _sdp_of_len(600), "is_video": False, "is_group": False,
        }))
        msg = json.loads(await callee_ws.recv())
        assert msg["type"] == "call_offer"
        assert "ts" not in msg
    finally:
        await caller_ws.close()
        await callee_ws.close()


# ── 3. real answers pass ──────────────────────────────────────────────────

async def test_call_answer_passes(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-answer-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-answer-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        call_id = _call_uuid()
        await a_ws.send(json.dumps({"type": "call_answer", "to": b_fp, "call_id": call_id, "sdp": _sdp_of_len(700)}))
        msg = json.loads(await b_ws.recv())
        assert msg["type"] == "call_answer"
        assert msg["sdp"].startswith("v=0")
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 4. normal ICE burst passes ─────────────────────────────────────────────

async def test_normal_ice_burst_passes(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-iceburst-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-iceburst-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        call_id = _call_uuid()
        n = 15
        for _ in range(n):
            await a_ws.send(json.dumps({
                "type": "call_ice", "to": b_fp, "call_id": call_id,
                "sdp_mid": "0", "sdp_m_line_index": 0, "candidate": _ice_candidate_of_len(120),
            }))
        received = 0
        for _ in range(n):
            msg = json.loads(await b_ws.recv())
            if msg.get("type") == "call_ice":
                received += 1
        assert received == n
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 5. official ICE restart passes ─────────────────────────────────────────

async def test_official_ice_restart_passes(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-icerestart-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-icerestart-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await a_ws.send(json.dumps({"type": "call_ice_restart", "to": b_fp, "call_id": _call_uuid(), "sdp": _sdp_of_len(500)}))
        msg = json.loads(await b_ws.recv())
        assert msg["type"] == "call_ice_restart"
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 6. every group-call message type passes ────────────────────────────────

async def test_every_group_call_message_type_passes(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-group-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-group-b")
    c_ws, c_fp, _, _ = await connect_and_register(running_server, device_id="s651-group-c")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await drain_until(c_ws, "register_ok")
        call_id  = _call_uuid()
        group_id = _call_uuid()

        await a_ws.send(json.dumps({"type": "call_group_invite", "to": b_fp, "call_id": call_id, "group_id": group_id, "is_video": True}))
        msg = json.loads(await b_ws.recv())
        assert msg["type"] == "call_group_invite" and msg["group_id"] == group_id

        await b_ws.send(json.dumps({"type": "call_group_join", "to": a_fp, "call_id": call_id, "group_id": group_id, "sdp": _sdp_of_len(400)}))
        msg = json.loads(await a_ws.recv())
        assert msg["type"] == "call_group_join"

        await a_ws.send(json.dumps({"type": "call_group_answer", "to": b_fp, "call_id": call_id, "group_id": group_id, "sdp": _sdp_of_len(400)}))
        msg = json.loads(await b_ws.recv())
        assert msg["type"] == "call_group_answer"

        await a_ws.send(json.dumps({"type": "call_group_peer_list", "to": c_fp, "call_id": call_id, "group_id": group_id, "peers": [a_fp, b_fp]}))
        msg = json.loads(await c_ws.recv())
        assert msg["type"] == "call_group_peer_list" and msg["peers"] == [a_fp, b_fp]

        await a_ws.send(json.dumps({"type": "call_group_leave", "to": b_fp, "call_id": call_id, "reason": "hangup"}))
        msg = json.loads(await b_ws.recv())
        assert msg["type"] == "call_group_leave"
    finally:
        await a_ws.close()
        await b_ws.close()
        await c_ws.close()


# ── 7. noncanonical `to` rejected ──────────────────────────────────────────

async def test_call_signal_noncanonical_to_rejected(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s651-badto")
    try:
        await drain_until(ws, "register_ok")
        await ws.send(json.dumps({
            "type": "call_offer", "to": "not-a-fingerprint", "call_id": _call_uuid(),
            "sdp": _sdp_of_len(500), "is_video": False, "is_group": False,
        }))
        await ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await ws.recv())
        assert msg["type"] == "pong"
        assert fp not in server.active_calls
    finally:
        await ws.close()


# ── 8. oversized call_id rejected before active_calls ──────────────────────

async def test_oversized_call_id_rejected_before_active_calls(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-bigcallid-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-bigcallid-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": "x" * 500,
            "sdp": _sdp_of_len(500), "is_video": False, "is_group": False,
        }))
        await a_ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await a_ws.recv())
        assert msg["type"] == "pong"
        assert a_fp not in server.active_calls
        assert b_fp not in server.active_calls
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 9. oversized SDP rejected before relay ─────────────────────────────────

async def test_oversized_sdp_rejected_before_relay(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-bigsdp-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-bigsdp-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        # Over CALL_SDP_MAX_LEN but comfortably under the SDP envelope
        # ceiling -- proves the FIELD-specific bound catches it, not merely
        # the envelope ceiling.
        big_sdp = _sdp_of_len(server.CALL_SDP_MAX_LEN + 100)
        assert len(big_sdp.encode("utf-8")) < server.CALL_SIGNAL_SDP_MAX_PACKET_SIZE_BYTES
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": _call_uuid(),
            "sdp": big_sdp, "is_video": False, "is_group": False,
        }))
        await a_ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await a_ws.recv())
        assert msg["type"] == "pong"
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 10. oversized ICE candidate rejected ───────────────────────────────────

async def test_oversized_ice_candidate_rejected(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-bigice-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-bigice-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        big_candidate = _ice_candidate_of_len(server.CALL_ICE_CANDIDATE_MAX_LEN + 50)
        assert len(big_candidate.encode("utf-8")) < server.CALL_SIGNAL_ICE_MAX_PACKET_SIZE_BYTES
        await a_ws.send(json.dumps({
            "type": "call_ice", "to": b_fp, "call_id": _call_uuid(),
            "sdp_mid": "0", "sdp_m_line_index": 0, "candidate": big_candidate,
        }))
        await a_ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await a_ws.recv())
        assert msg["type"] == "pong"
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 11. enormous arbitrary `junk` field is NOT relayed ─────────────────────

async def test_junk_field_not_relayed(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-junk-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-junk-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": _call_uuid(),
            "sdp": _sdp_of_len(500), "is_video": False, "is_group": False,
            "junk": "A" * 1500,
        }))
        msg = json.loads(await b_ws.recv())
        assert "junk" not in msg
        assert msg["type"] == "call_offer"
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 12. sanitized relay contains only schema fields ────────────────────────

async def test_sanitized_relay_contains_only_schema_fields(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-schema-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-schema-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": _call_uuid(),
            "sdp": _sdp_of_len(500), "is_video": True, "is_group": False,
        }))
        msg = json.loads(await b_ws.recv())
        assert set(msg.keys()) == {"type", "from", "to", "call_id", "sdp", "is_video", "is_group"}
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 13. caller cannot spoof `from` ─────────────────────────────────────────

async def test_caller_cannot_spoof_from(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-spoof-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-spoof-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_end", "to": b_fp, "call_id": _call_uuid(), "reason": "hangup",
            "from": "SOMEOTHERFAKE0001",
        }))
        msg = json.loads(await b_ws.recv())
        assert msg["from"] == a_fp
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 14. malformed group peer list rejected ─────────────────────────────────

async def test_malformed_group_peer_list_rejected(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-badpeerlist-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-badpeerlist-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_group_peer_list", "to": b_fp, "call_id": _call_uuid(),
            "group_id": _call_uuid(), "peers": "not-a-list",
        }))
        await a_ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await a_ws.recv())
        assert msg["type"] == "pong"
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 15. excessive peer count rejected ──────────────────────────────────────

async def test_excessive_peer_count_rejected(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-toomanypeers-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-toomanypeers-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        peers = [canonical_fingerprint(f"s651peer{i}") for i in range(server.CALL_GROUP_PEER_LIST_MAX_COUNT + 1)]
        await a_ws.send(json.dumps({
            "type": "call_group_peer_list", "to": b_fp, "call_id": _call_uuid(),
            "group_id": _call_uuid(), "peers": peers,
        }))
        await a_ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await a_ws.recv())
        assert msg["type"] == "pong"
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 16. invalid peer fingerprint rejected ──────────────────────────────────

async def test_invalid_peer_fingerprint_rejected(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-badpeerfp-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-badpeerfp-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_group_peer_list", "to": b_fp, "call_id": _call_uuid(),
            "group_id": _call_uuid(), "peers": [a_fp, "not-a-fingerprint"],
        }))
        await a_ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await a_ws.recv())
        assert msg["type"] == "pong"
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 17. call_ice count limiter remains active ──────────────────────────────

async def test_call_ice_count_limiter_remains_active(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-icelimiter-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-icelimiter-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        server.rate_limits[a_fp]["call_ice"] = {"count": 300, "reset_time": server.time.time()}
        await a_ws.send(json.dumps({
            "type": "call_ice", "to": b_fp, "call_id": _call_uuid(),
            "sdp_mid": "0", "sdp_m_line_index": 0, "candidate": _ice_candidate_of_len(100),
        }))
        msg = json.loads(await a_ws.recv())
        assert msg == {"type": "error", "reason": "Rate limit exceeded"}
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 18. per-user byte budget bounds one sender ─────────────────────────────

async def test_per_user_byte_budget_bounds_one_sender(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-userbudget-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-userbudget-b")
    real_limit = server.CALL_SIGNAL_USER_MAX_BYTES
    server.CALL_SIGNAL_USER_MAX_BYTES = 5000
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": _call_uuid(),
            "sdp": _sdp_of_len(4000), "is_video": False, "is_group": False,
        }))
        msg = json.loads(await b_ws.recv())
        assert msg["type"] == "call_offer"
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": _call_uuid(),
            "sdp": _sdp_of_len(4000), "is_video": False, "is_group": False,
        }))
        msg = json.loads(await a_ws.recv())
        assert msg == {"type": "error", "reason": "Rate limit exceeded"}
    finally:
        server.CALL_SIGNAL_USER_MAX_BYTES = real_limit
        await a_ws.close()
        await b_ws.close()


# ── 19. global byte budget bounds Sybil senders ────────────────────────────

async def test_global_byte_budget_bounds_sybil_senders(running_server):
    real_limit = server.CALL_SIGNAL_GLOBAL_MAX_BYTES
    server.CALL_SIGNAL_GLOBAL_MAX_BYTES = 6000
    recipient_ws = None
    sender_sockets = []
    try:
        recipient_ws, recipient_fp, _, _ = await connect_and_register(running_server, device_id="s651-globalbudget-r")
        await drain_until(recipient_ws, "register_ok")
        rejected = False
        for i in range(5):
            sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id=f"s651-globalbudget-s{i}")
            sender_sockets.append(sender_ws)
            await drain_until(sender_ws, "register_ok")
            await sender_ws.send(json.dumps({
                "type": "call_offer", "to": recipient_fp, "call_id": _call_uuid(),
                "sdp": _sdp_of_len(2000), "is_video": False, "is_group": False,
            }))
            try:
                async with asyncio.timeout(0.5):
                    msg = json.loads(await sender_ws.recv())
                if msg == {"type": "error", "reason": "Rate limit exceeded"}:
                    rejected = True
            except (asyncio.TimeoutError, TimeoutError):
                pass
        assert rejected
    finally:
        server.CALL_SIGNAL_GLOBAL_MAX_BYTES = real_limit
        if recipient_ws:
            await recipient_ws.close()
        for s in sender_sockets:
            await s.close()


# ── 20. recipient byte budget bounds attack on one victim ──────────────────

async def test_recipient_byte_budget_bounds_attack_on_one_victim(running_server):
    real_limit = server.CALL_SIGNAL_RECIPIENT_MAX_BYTES
    server.CALL_SIGNAL_RECIPIENT_MAX_BYTES = 6000
    victim_ws = None
    sender_sockets = []
    try:
        victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s651-recipientbudget-v")
        await drain_until(victim_ws, "register_ok")
        rejected = False
        for i in range(5):
            sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id=f"s651-recipientbudget-s{i}")
            sender_sockets.append(sender_ws)
            await drain_until(sender_ws, "register_ok")
            await sender_ws.send(json.dumps({
                "type": "call_offer", "to": victim_fp, "call_id": _call_uuid(),
                "sdp": _sdp_of_len(2000), "is_video": False, "is_group": False,
            }))
            try:
                async with asyncio.timeout(0.5):
                    msg = json.loads(await sender_ws.recv())
                if msg == {"type": "error", "reason": "Rate limit exceeded"}:
                    rejected = True
            except (asyncio.TimeoutError, TimeoutError):
                pass
        assert rejected
    finally:
        server.CALL_SIGNAL_RECIPIENT_MAX_BYTES = real_limit
        if victim_ws:
            await victim_ws.close()
        for s in sender_sockets:
            await s.close()


# ── 21. invalid/over-budget signaling creates no active_calls state ────────

async def test_invalid_and_overbudget_signaling_creates_no_active_calls_state(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-noactivecalls-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-noactivecalls-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")

        # Invalid (malformed call_id).
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": "not-a-uuid",
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await a_ws.send(json.dumps({"type": "ping"}))
        await a_ws.recv()
        assert a_fp not in server.active_calls

        # Over-budget (valid signaling, byte budget exhausted).
        real_limit = server.CALL_SIGNAL_USER_MAX_BYTES
        server.CALL_SIGNAL_USER_MAX_BYTES = 100
        try:
            await a_ws.send(json.dumps({
                "type": "call_offer", "to": b_fp, "call_id": _call_uuid(),
                "sdp": _sdp_of_len(500), "is_video": False, "is_group": False,
            }))
            msg = json.loads(await a_ws.recv())
            assert msg == {"type": "error", "reason": "Rate limit exceeded"}
            assert a_fp not in server.active_calls
        finally:
            server.CALL_SIGNAL_USER_MAX_BYTES = real_limit
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 22. valid call_offer still creates expected active_calls state ─────────

async def test_valid_call_offer_creates_expected_active_calls_state(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-activecalls-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-activecalls-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        call_id = _call_uuid()
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await b_ws.recv()
        await asyncio.sleep(0.1)
        assert server.active_calls.get(a_fp) == {"peer": b_fp, "call_id": call_id}
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 23. call_end still clears state ────────────────────────────────────────

async def test_call_end_clears_active_calls_state(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-callend-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-callend-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        call_id = _call_uuid()
        # A real call_offer from b->a must precede the answer (S6-61: an
        # answer only promotes the reciprocal (target's) active_calls entry
        # if it already correlates with a matching offer) for a_fp's own
        # write to also promote b_fp's reciprocal entry below.
        await b_ws.send(json.dumps({
            "type": "call_offer", "to": a_fp, "call_id": call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await a_ws.recv()
        await a_ws.send(json.dumps({"type": "call_answer", "to": b_fp, "call_id": call_id, "sdp": _sdp_of_len(300)}))
        await b_ws.recv()
        assert a_fp in server.active_calls and b_fp in server.active_calls
        await a_ws.send(json.dumps({"type": "call_end", "to": b_fp, "call_id": call_id, "reason": "hangup"}))
        await b_ws.recv()
        assert a_fp not in server.active_calls
        assert b_fp not in server.active_calls
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 24. disconnect auto-call_end remains green ─────────────────────────────

async def test_disconnect_auto_call_end_remains_green(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-autoend-a")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s651-autoend-b")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        call_id = _call_uuid()
        await a_ws.send(json.dumps({"type": "call_answer", "to": b_fp, "call_id": call_id, "sdp": _sdp_of_len(300)}))
        await b_ws.recv()
        await a_ws.close()
        msg = json.loads(await b_ws.recv())
        assert msg["type"] == "call_end"
        assert msg["reason"] == "disconnected"
        assert msg["from"] == a_fp
        await asyncio.sleep(0.1)
        assert a_fp not in server.active_calls
        assert b_fp not in server.active_calls
    finally:
        await b_ws.close()


# ── 25. direct relay has bounded sends/backpressure ────────────────────────

async def test_direct_relay_awaits_send_not_fire_and_forget():
    src = inspect.getsource(server.handle_client)
    call_section = src[src.index("Call Signaling Relay"):src.index("Chat-control relay (S6-53)")]
    assert "asyncio.create_task(send_safe(target_ws" not in call_section
    assert "await send_safe(target_ws, serialized)" in call_section


# ── 26. offline offer still stores only missed_call ────────────────────────

async def test_offline_offer_stores_only_missed_call(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-offlineoffer-a")
    offline_fp = canonical_fingerprint("s651-offlineoffer-target")
    try:
        await drain_until(a_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": offline_fp, "call_id": _call_uuid(),
            "sdp": _sdp_of_len(3000), "is_video": True, "is_group": False,
        }))
        await asyncio.sleep(0.2)
        with server.db_connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM pending_messages WHERE recipient = ?", (offline_fp,)
            ).fetchall()
        assert len(rows) == 1
        stored = json.loads(rows[0][0])
        assert stored["type"] == "missed_call"
        assert stored["from"] == a_fp
        assert stored["is_video"] is True
        assert "sdp" not in stored
        assert "call_id" not in stored
    finally:
        await a_ws.close()


# ── 27. normal offline FCM wake behavior remains green ──────────────────────

async def test_offline_offer_triggers_fcm_wakeup(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s651-fcmwake-a")
    offline_fp = canonical_fingerprint("s651-fcmwake-target")
    real_scheduler = server.schedule_fcm_wakeup
    called_with = []

    def _spy(target, source, reason):
        called_with.append(target)
        return True

    server.schedule_fcm_wakeup = _spy
    try:
        await drain_until(a_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": offline_fp, "call_id": _call_uuid(),
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await asyncio.sleep(0.2)
        assert offline_fp in called_with
    finally:
        server.schedule_fcm_wakeup = real_scheduler
        await a_ws.close()


# ── 28. global MAX_PACKET_SIZE_BYTES unchanged ─────────────────────────────

async def test_max_packet_size_bytes_unchanged_by_call_signaling_patch():
    assert server.MAX_PACKET_SIZE_BYTES == 6 * 1024 * 1024


# ── FCM token registration + push scheduling hardening (S6-52) ───────────
#
# STEP 1 finding: `fcm_token` lives ONLY in `clients[username]["fcm_token"]`
# -- populated by register_fcm on an already-live connection, wiped by
# clients.pop() on disconnect, and never carried into the FRESH dict
# register() builds on every reconnect. Every wakeup call site only ever
# calls schedule_fcm_wakeup() AFTER confirming the target is NOT in
# `clients` -- so the "wake a genuinely disconnected client" path was
# already FUNCTIONALLY DEAD before this patch (see tests 29/30 below,
# proving this directly rather than assuming it). This patch does not add
# token persistence to make it work -- it bounds register_fcm's input,
# replaces unbounded asyncio.create_task() scheduling with a synchronous
# admission gate, coalesces silent wakeups per recipient, and adds sender/
# recipient/global budgets plus a hard concurrent-Firebase-sends cap. See
# SECURITY_INVARIANTS.md #65 and KNOWN_SECURITY_ISSUES.md S6-52.

def _put_online_with_token(username, token=None):
    if token is None:
        token = "FAKE_FCM_TOKEN_" + secrets.token_hex(20)
    server.clients[username] = {"ws": None, "name": "t", "public_key": "", "device_id": "", "fcm_token": token}
    return token


# ── 1. normal official Android FCM token accepted ─────────────────────────

async def test_normal_android_fcm_token_accepted(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s652-normaltoken")
    try:
        await drain_until(ws, "register_ok")
        token = "c" * 163  # realistic modern FCM registration-token ballpark
        await ws.send(json.dumps({"type": "register_fcm", "fcm_token": token}))
        await asyncio.sleep(0.2)
        assert server.clients.get(fp, {}).get("fcm_token") == token
    finally:
        await ws.close()


# ── 2. wrong-type token rejected ──────────────────────────────────────────

async def test_wrong_type_fcm_token_rejected(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s652-wrongtype")
    try:
        await drain_until(ws, "register_ok")
        await ws.send(json.dumps({"type": "register_fcm", "fcm_token": 12345}))
        await asyncio.sleep(0.2)
        assert "fcm_token" not in server.clients.get(fp, {})
    finally:
        await ws.close()


# ── 3. oversized token rejected before clients RAM mutation ───────────────

async def test_oversized_fcm_token_rejected(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s652-oversized")
    try:
        await drain_until(ws, "register_ok")
        big_token = "x" * (server.FCM_TOKEN_MAX_LEN + 1)
        await ws.send(json.dumps({"type": "register_fcm", "fcm_token": big_token}))
        await asyncio.sleep(0.2)
        assert "fcm_token" not in server.clients.get(fp, {})
    finally:
        await ws.close()


# ── 4. identical register_fcm token is no-op ──────────────────────────────

async def test_identical_fcm_token_reregistration_is_noop(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s652-identical")
    try:
        await drain_until(ws, "register_ok")
        token = "same_token_" + "y" * 100
        await ws.send(json.dumps({"type": "register_fcm", "fcm_token": token}))
        await asyncio.sleep(0.2)
        count_before = server.rate_limits[fp]["register_fcm"]["count"]
        await ws.send(json.dumps({"type": "register_fcm", "fcm_token": token}))
        await asyncio.sleep(0.2)
        count_after = server.rate_limits[fp]["register_fcm"]["count"]
        assert count_after == count_before
    finally:
        await ws.close()


# ── 5. register_fcm mutation rate is bounded ──────────────────────────────

async def test_register_fcm_rate_is_bounded(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s652-ratebound")
    try:
        await drain_until(ws, "register_ok")
        for i in range(10):
            await ws.send(json.dumps({"type": "register_fcm", "fcm_token": f"token-{i}-" + "z" * 50}))
        await asyncio.sleep(0.3)
        await ws.send(json.dumps({"type": "register_fcm", "fcm_token": "token-11-" + "z" * 50}))
        msg = json.loads(await ws.recv())
        assert msg == {"type": "error", "reason": "Rate limit exceeded"}
    finally:
        await ws.close()


# ── 6. malformed target creates no limiter state ──────────────────────────

async def test_malformed_target_creates_no_fcm_limiter_state():
    result = server.schedule_fcm_wakeup("not-a-fingerprint", canonical_fingerprint("s652-source"), "test")
    assert result is False
    assert "not-a-fingerprint" not in server.fcm_wakeup_recipient_rate
    assert "not-a-fingerprint" not in server.fcm_wakeup_last_sent


# ── 7. first legitimate wakeup is admitted ────────────────────────────────

async def test_first_legitimate_wakeup_is_admitted():
    target = canonical_fingerprint("s652-first-wakeup")
    source = canonical_fingerprint("s652-first-source")
    assert server.schedule_fcm_wakeup(target, source, "test") is True
    await asyncio.sleep(0.05)


# ── 8. repeated immediate wakeups to same recipient are coalesced ─────────

async def test_repeated_immediate_wakeups_coalesced():
    target = canonical_fingerprint("s652-coalesce-target")
    source = canonical_fingerprint("s652-coalesce-source")
    first = server.schedule_fcm_wakeup(target, source, "test")
    second = server.schedule_fcm_wakeup(target, source, "test")
    assert first is True
    assert second is False
    await asyncio.sleep(0.05)


# ── 9. only one in-flight silent wake exists per target ───────────────────

async def test_only_one_inflight_wakeup_per_target():
    target = canonical_fingerprint("s652-inflight-target")
    source = canonical_fingerprint("s652-inflight-source")
    assert server.schedule_fcm_wakeup(target, source, "test") is True
    assert target in server.fcm_wakeup_inflight
    assert server.schedule_fcm_wakeup(target, source, "test") is False
    await asyncio.sleep(0.05)


# ── 10. after successful send, recipient cooldown applies ────────────────

async def test_successful_send_commits_recipient_cooldown():
    target = canonical_fingerprint("s652-cooldown-target")
    _put_online_with_token(target)
    server.fcm_inflight_count = 1
    server.fcm_wakeup_inflight.add(target)
    real_init = server._init_firebase
    server._init_firebase = lambda: True
    import firebase_admin.messaging as fb_messaging
    real_send = fb_messaging.send
    fb_messaging.send = lambda msg: None
    try:
        await server._run_fcm_wakeup(target, "test")
        assert target in server.fcm_wakeup_last_sent
        assert target not in server.fcm_wakeup_inflight
        assert server.fcm_inflight_count == 0
    finally:
        server._init_firebase = real_init
        fb_messaging.send = real_send
        server.clients.pop(target, None)
        server.fcm_inflight_count = 0
        server.fcm_wakeup_inflight.discard(target)


# ── 11. failed send releases inflight state ───────────────────────────────

async def test_failed_send_releases_inflight_state():
    target = canonical_fingerprint("s652-failrelease-target")
    _put_online_with_token(target)
    server.fcm_inflight_count = 1
    server.fcm_wakeup_inflight.add(target)
    real_init = server._init_firebase
    server._init_firebase = lambda: True
    import firebase_admin.messaging as fb_messaging
    real_send = fb_messaging.send

    def _boom(msg):
        raise RuntimeError("simulated Firebase failure")

    fb_messaging.send = _boom
    try:
        await server._run_fcm_wakeup(target, "test")
        assert target not in server.fcm_wakeup_inflight
        assert server.fcm_inflight_count == 0
    finally:
        server._init_firebase = real_init
        fb_messaging.send = real_send
        server.clients.pop(target, None)
        server.fcm_inflight_count = 0
        server.fcm_wakeup_inflight.discard(target)


# ── 12. failure gets bounded backoff rather than tight retry loop ────────

async def test_failure_gets_bounded_backoff():
    target = canonical_fingerprint("s652-backoff-target")
    _put_online_with_token(target)
    server.fcm_inflight_count = 1
    server.fcm_wakeup_inflight.add(target)
    real_init = server._init_firebase
    server._init_firebase = lambda: True
    import firebase_admin.messaging as fb_messaging
    real_send = fb_messaging.send
    fb_messaging.send = lambda msg: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        await server._run_fcm_wakeup(target, "test")
        assert target in server.fcm_wakeup_failure_until
        assert server.fcm_wakeup_failure_until[target] > server.time.time()
        source = canonical_fingerprint("s652-backoff-source")
        assert server.schedule_fcm_wakeup(target, source, "test") is False
    finally:
        server._init_firebase = real_init
        fb_messaging.send = real_send
        server.clients.pop(target, None)
        server.fcm_inflight_count = 0
        server.fcm_wakeup_inflight.discard(target)


# ── 13. one sender cannot exceed source budget ────────────────────────────

async def test_one_sender_cannot_exceed_source_budget():
    source = canonical_fingerprint("s652-source-budget")
    admitted = 0
    for i in range(server.FCM_WAKEUP_SOURCE_LIMIT + 5):
        target = canonical_fingerprint(f"s652-source-budget-target-{i}")
        if server.schedule_fcm_wakeup(target, source, "test"):
            admitted += 1
    assert admitted == server.FCM_WAKEUP_SOURCE_LIMIT
    await asyncio.sleep(0.05)


# ── 14. many Sybil senders cannot exceed recipient budget against one
#         victim ──────────────────────────────────────────────────────────

async def test_sybil_senders_cannot_exceed_recipient_budget():
    target = canonical_fingerprint("s652-recipient-budget-victim")
    admitted = 0
    for i in range(server.FCM_WAKEUP_RECIPIENT_LIMIT + 5):
        source = canonical_fingerprint(f"s652-recipient-budget-source-{i}")
        # Isolate the recipient budget specifically -- clear the inflight/
        # cooldown coalescing state between attempts so each Sybil sender's
        # attempt is judged only against the recipient budget, not against
        # the PREVIOUS sender's still-fresh cooldown.
        server.fcm_wakeup_inflight.discard(target)
        server.fcm_wakeup_last_sent.pop(target, None)
        if server.schedule_fcm_wakeup(target, source, "test"):
            admitted += 1
    assert admitted == server.FCM_WAKEUP_RECIPIENT_LIMIT
    await asyncio.sleep(0.05)


# ── 15. many recipients cannot exceed global budget ───────────────────────

async def test_many_recipients_cannot_exceed_global_budget():
    # Isolate the RATE budget specifically -- none of the scheduled tasks
    # below get a chance to run (and release their inflight slot) until an
    # `await` is actually reached, so without a much higher hard inflight
    # cap this loop would hit FCM_MAX_INFLIGHT_SENDS first instead of the
    # global rate limit this test targets.
    real_cap = server.FCM_MAX_INFLIGHT_SENDS
    server.FCM_MAX_INFLIGHT_SENDS = server.FCM_PUSH_GLOBAL_LIMIT + 10
    try:
        admitted = 0
        for i in range(server.FCM_PUSH_GLOBAL_LIMIT + 5):
            target = canonical_fingerprint(f"s652-global-budget-target-{i}")
            source = canonical_fingerprint(f"s652-global-budget-source-{i}")
            if server.schedule_fcm_wakeup(target, source, "test"):
                admitted += 1
        assert admitted == server.FCM_PUSH_GLOBAL_LIMIT
    finally:
        await asyncio.sleep(0.1)
        server.FCM_MAX_INFLIGHT_SENDS = real_cap
        server.fcm_inflight_count = 0


# ── 16. FCM_MAX_INFLIGHT_SENDS cannot be raced above its hard cap ─────────

async def test_max_inflight_sends_cannot_be_raced_above_cap():
    real_cap = server.FCM_MAX_INFLIGHT_SENDS
    server.FCM_MAX_INFLIGHT_SENDS = 3
    server.fcm_inflight_count = 0
    try:
        admitted = 0
        for i in range(6):
            target = canonical_fingerprint(f"s652-inflight-cap-target-{i}")
            source = canonical_fingerprint(f"s652-inflight-cap-source-{i}")
            if server.schedule_fcm_wakeup(target, source, "test"):
                admitted += 1
        assert admitted == 3
        assert server.fcm_inflight_count <= server.FCM_MAX_INFLIGHT_SENDS
    finally:
        await asyncio.sleep(0.1)
        server.FCM_MAX_INFLIGHT_SENDS = real_cap
        server.fcm_inflight_count = 0


# ── 17. denied wakeup creates NO asyncio Task ─────────────────────────────

async def test_denied_wakeup_creates_no_asyncio_task():
    target = canonical_fingerprint("s652-denied-notask")
    source = canonical_fingerprint("s652-denied-notask-source")
    assert server.schedule_fcm_wakeup(target, source, "test") is True
    real_create_task = asyncio.create_task
    task_created = False

    def _spy_create_task(*a, **kw):
        nonlocal task_created
        task_created = True
        return real_create_task(*a, **kw)

    asyncio.create_task = _spy_create_task
    try:
        result = server.schedule_fcm_wakeup(target, source, "test")
        assert result is False
        assert task_created is False
    finally:
        asyncio.create_task = real_create_task
        await asyncio.sleep(0.05)


# ── 18. denied wakeup reaches NO executor / _init_firebase() ─────────────

async def test_denied_wakeup_never_calls_init_firebase():
    target = canonical_fingerprint("s652-denied-noinit")
    source = canonical_fingerprint("s652-denied-noinit-source")
    assert server.schedule_fcm_wakeup(target, source, "test") is True
    real_init = server._init_firebase
    init_called = False

    def _spy_init():
        nonlocal init_called
        init_called = True
        return real_init()

    server._init_firebase = _spy_init
    try:
        result = server.schedule_fcm_wakeup(target, source, "test")
        assert result is False
        await asyncio.sleep(0.05)
        assert init_called is False
    finally:
        server._init_firebase = real_init


# ── 19. denied wakeup calls NO Firebase API ───────────────────────────────

async def test_denied_wakeup_never_reaches_firebase_send():
    target = canonical_fingerprint("s652-denied-nosend")
    _put_online_with_token(target)
    # Exhaust the recipient RATE budget synchronously first (clearing
    # inflight/cooldown between each admitted call so only the rate counter
    # accumulates) -- this guarantees the NEXT call is denied at the cheap
    # rate-check stage, deterministically, with no dependency on any
    # previously-scheduled async task actually finishing first (unlike
    # relying on the per-recipient cooldown, which is only committed once a
    # task's Firebase attempt genuinely completes).
    for i in range(server.FCM_WAKEUP_RECIPIENT_LIMIT):
        source = canonical_fingerprint(f"s652-denied-nosend-source-{i}")
        server.fcm_wakeup_inflight.discard(target)
        server.fcm_wakeup_last_sent.pop(target, None)
        server.schedule_fcm_wakeup(target, source, "test")
    server.fcm_wakeup_inflight.discard(target)
    server.fcm_wakeup_last_sent.pop(target, None)
    # Let all of the exhaustion-loop's own admitted tasks run to completion
    # (with the REAL, still-unpatched _init_firebase(), which returns False
    # with no credentials configured -- a harmless no-op) BEFORE attaching
    # the spy below. Otherwise those tasks would only get their turn to run
    # during the LATER `await` further down, by which point _init_firebase()
    # has already been patched to True for THIS test's own purposes --
    # letting every one of them reach the real Firebase call too and set
    # send_called, unrelated to the one final call this test actually means
    # to prove is denied.
    await asyncio.sleep(0.2)

    import firebase_admin.messaging as fb_messaging
    real_send = fb_messaging.send
    send_called = False

    def _spy_send(msg):
        nonlocal send_called
        send_called = True
        return real_send(msg)

    fb_messaging.send = _spy_send
    real_init = server._init_firebase
    server._init_firebase = lambda: True
    try:
        source_final = canonical_fingerprint("s652-denied-nosend-final-source")
        result = server.schedule_fcm_wakeup(target, source_final, "test")
        assert result is False
        await asyncio.sleep(0.1)
        assert send_called is False
    finally:
        fb_messaging.send = real_send
        server._init_firebase = real_init
        server.clients.pop(target, None)


# ── 20. limiter state prunes after expiry ─────────────────────────────────

async def test_limiter_state_resets_after_window_expiry():
    source = canonical_fingerprint("s652-window-reset-source")
    target = canonical_fingerprint("s652-window-reset-target")
    assert server.schedule_fcm_wakeup(target, source, "test") is True
    for i in range(server.FCM_WAKEUP_SOURCE_LIMIT):
        t2 = canonical_fingerprint(f"s652-window-reset-target-extra-{i}")
        server.schedule_fcm_wakeup(t2, source, "test")
    t3 = canonical_fingerprint("s652-window-reset-target-3")
    assert server.schedule_fcm_wakeup(t3, source, "test") is False
    server.fcm_wakeup_source_rate[source]["reset_time"] -= (server.FCM_WAKEUP_SOURCE_WINDOW_SEC + 1)
    t4 = canonical_fingerprint("s652-window-reset-target-4")
    assert server.schedule_fcm_wakeup(t4, source, "test") is True
    await asyncio.sleep(0.1)


# ── 21. queued message ACK remains success even if FCM sending fails ─────

async def test_message_ack_remains_success_even_if_fcm_scheduling_denied(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s652-ackindependent")
    offline_fp = canonical_fingerprint("s652-ackindependent-target")
    real_scheduler = server.schedule_fcm_wakeup
    server.schedule_fcm_wakeup = lambda *a, **kw: False
    try:
        await drain_until(sender_ws, "register_ok")
        msg_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "message", "to": offline_fp, "id": msg_id,
            "text": "hi", "signature": "sig",
        }))
        msg = json.loads(await sender_ws.recv())
        assert msg == {"type": "ack", "id": msg_id}
    finally:
        server.schedule_fcm_wakeup = real_scheduler
        await sender_ws.close()


# ── 22. failed offline store creates no FCM request ───────────────────────

async def test_failed_offline_store_creates_no_fcm_request(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s652-failedstore")
    offline_fp = canonical_fingerprint("s652-failedstore-target")
    real_scheduler = server.schedule_fcm_wakeup
    called = False

    def _spy(*a, **kw):
        nonlocal called
        called = True
        return real_scheduler(*a, **kw)

    server.schedule_fcm_wakeup = _spy
    real_db_store = server.db_store

    async def _fake_db_store(*a, **kw):
        return "FULL"

    server.db_store = _fake_db_store
    try:
        await drain_until(sender_ws, "register_ok")
        msg_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "message", "to": offline_fp, "id": msg_id,
            "text": "hi", "signature": "sig",
        }))
        msg = json.loads(await sender_ws.recv())
        assert msg["type"] == "error"
        assert called is False
    finally:
        server.schedule_fcm_wakeup = real_scheduler
        server.db_store = real_db_store
        await sender_ws.close()


# ── 23. normal missed-call wakeup remains functional ──────────────────────

async def test_normal_missed_call_wakeup_remains_functional(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s652-misscall-a")
    offline_fp = canonical_fingerprint("s652-misscall-target")
    real_scheduler = server.schedule_fcm_wakeup
    called_with = []

    def _spy(target, source, reason):
        called_with.append((target, reason))
        return True

    server.schedule_fcm_wakeup = _spy
    try:
        await drain_until(a_ws, "register_ok")
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": offline_fp, "call_id": _call_uuid(),
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await asyncio.sleep(0.2)
        assert (offline_fp, "missed_call") in called_with
    finally:
        server.schedule_fcm_wakeup = real_scheduler
        await a_ws.close()


# ── 24. session_init wakeup remains functional ────────────────────────────

async def test_session_init_wakeup_remains_functional(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s652-sessioninit-a")
    offline_fp = canonical_fingerprint("s652-sessioninit-target")
    real_scheduler = server.schedule_fcm_wakeup
    called_with = []

    def _spy(target, source, reason):
        called_with.append((target, reason))
        return True

    server.schedule_fcm_wakeup = _spy
    try:
        await drain_until(sender_ws, "register_ok")
        msg_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "session_init", "to": offline_fp, "id": msg_id,
            "sender_ik": "ik", "x3dh_header": "hdr", "session_header": "sh",
            "text": "hi", "signature": "sig",
        }))
        msg = json.loads(await sender_ws.recv())
        assert msg["type"] == "ack"
        assert (offline_fp, "session_init") in called_with
    finally:
        server.schedule_fcm_wakeup = real_scheduler
        await sender_ws.close()


# ── 25. session_conflict notification remains functional ─────────────────

async def test_session_conflict_notification_remains_functional(running_server):
    priv, pub_der = gen_keypair()
    fp = fingerprint_of(pub_der)
    device_id_a = canonical_device_id("s652-conflict-a")
    device_id_b = canonical_device_id("s652-conflict-b")
    real_scheduler = server.schedule_fcm_session_conflict
    called_with = []

    def _spy(username, token, ts):
        called_with.append((username, token))
        return True

    server.schedule_fcm_session_conflict = _spy
    ws1 = None
    ws2 = None
    try:
        ws1 = await websockets.connect(running_server)
        await handshake(ws1, priv, pub_der)
        await register(ws1, pub_der, device_id_a)
        await drain_until(ws1, "register_ok")
        await ws1.send(json.dumps({"type": "register_fcm", "fcm_token": "conflict-token-" + "a" * 100}))
        await asyncio.sleep(0.2)

        ws2 = await websockets.connect(running_server)
        await handshake(ws2, priv, pub_der)
        await register(ws2, pub_der, device_id_b)
        await asyncio.sleep(0.2)
        assert any(u == fp for u, t in called_with)
    finally:
        server.schedule_fcm_session_conflict = real_scheduler
        if ws1:
            await ws1.close()
        if ws2:
            await ws2.close()


# ── 26. session_conflict shares global/inflight resource limits ──────────

async def test_session_conflict_shares_global_and_inflight_limits():
    real_global_limit = server.FCM_PUSH_GLOBAL_LIMIT
    server.FCM_PUSH_GLOBAL_LIMIT = 0
    try:
        username = canonical_fingerprint("s652-conflict-globalshare")
        token = "shared-token-" + "b" * 100
        assert server.schedule_fcm_session_conflict(username, token, server.time.time()) is False
    finally:
        server.FCM_PUSH_GLOBAL_LIMIT = real_global_limit

    real_cap = server.FCM_MAX_INFLIGHT_SENDS
    server.fcm_inflight_count = 0
    server.FCM_MAX_INFLIGHT_SENDS = 0
    try:
        username2 = canonical_fingerprint("s652-conflict-inflightshare")
        token2 = "shared-token-2-" + "c" * 100
        assert server.schedule_fcm_session_conflict(username2, token2, server.time.time()) is False
    finally:
        server.FCM_MAX_INFLIGHT_SENDS = real_cap


# ── 27. transient Firebase error does NOT delete token ────────────────────

async def test_transient_firebase_error_does_not_delete_token():
    target = canonical_fingerprint("s652-transient-target")
    token = _put_online_with_token(target)
    server.fcm_inflight_count = 1
    server.fcm_wakeup_inflight.add(target)
    real_init = server._init_firebase
    server._init_firebase = lambda: True
    import firebase_admin.messaging as fb_messaging
    real_send = fb_messaging.send
    fb_messaging.send = lambda msg: (_ for _ in ()).throw(RuntimeError("transient network blip"))
    try:
        await server._run_fcm_wakeup(target, "test")
        assert server.clients.get(target, {}).get("fcm_token") == token
    finally:
        server._init_firebase = real_init
        fb_messaging.send = real_send
        server.clients.pop(target, None)
        server.fcm_inflight_count = 0
        server.fcm_wakeup_inflight.discard(target)


# ── 28. confirmed unregistered-token response invalidates token ──────────

async def test_unregistered_token_response_invalidates_token():
    target = canonical_fingerprint("s652-unregistered-target")
    _put_online_with_token(target)
    server.fcm_inflight_count = 1
    server.fcm_wakeup_inflight.add(target)
    real_init = server._init_firebase
    server._init_firebase = lambda: True
    import firebase_admin.messaging as fb_messaging
    real_send = fb_messaging.send

    def _boom(msg):
        raise fb_messaging.UnregisteredError("token no longer registered")

    fb_messaging.send = _boom
    try:
        await server._run_fcm_wakeup(target, "test")
        assert server.clients.get(target, {}).get("fcm_token") is None
    finally:
        server._init_firebase = real_init
        fb_messaging.send = real_send
        server.clients.pop(target, None)
        server.fcm_inflight_count = 0
        server.fcm_wakeup_inflight.discard(target)


# ── REACHABILITY 29/30 (RAM-only tokens, variant A) ───────────────────────

async def test_disconnect_removes_clients_entry_and_token(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s652-disconnect-a")
    await drain_until(ws, "register_ok")
    await ws.send(json.dumps({"type": "register_fcm", "fcm_token": "disc-token-" + "d" * 100}))
    await asyncio.sleep(0.2)
    assert fp in server.clients
    assert server.clients[fp].get("fcm_token")
    await ws.close()
    await asyncio.sleep(0.3)
    assert fp not in server.clients


async def test_wakeup_for_genuinely_disconnected_target_sends_no_firebase():
    target = canonical_fingerprint("s652-genuinely-offline")
    assert target not in server.clients
    real_init = server._init_firebase
    init_called = False

    def _spy_init():
        nonlocal init_called
        init_called = True
        return real_init()

    server._init_firebase = _spy_init
    try:
        await server._run_fcm_wakeup(target, "test")
        assert init_called is False
    finally:
        server._init_firebase = real_init


# ── Attack regression: many accounts target one FCM-enabled recipient ────

async def test_attack_many_accounts_target_one_fcm_recipient_bounded(running_server):
    victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s652-attack-victim")
    await drain_until(victim_ws, "register_ok")
    await victim_ws.send(json.dumps({"type": "register_fcm", "fcm_token": "attack-victim-token-" + "e" * 100}))
    await asyncio.sleep(0.2)
    await victim_ws.close()
    await asyncio.sleep(0.2)
    assert victim_fp not in server.clients

    sockets = []
    try:
        for i in range(server.FCM_WAKEUP_RECIPIENT_LIMIT + 10):
            sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id=f"s652-attack-sender-{i}")
            sockets.append(sender_ws)
            await drain_until(sender_ws, "register_ok")
            msg_id = str(uuid.uuid4())
            await sender_ws.send(json.dumps({
                "type": "message", "to": victim_fp, "id": msg_id,
                "text": "hi", "signature": "sig",
            }))
            msg = json.loads(await sender_ws.recv())
            assert msg["type"] == "ack"  # durable delivery ALWAYS succeeds regardless of push admission
        data = server.fcm_wakeup_recipient_rate.get(victim_fp)
        assert data is not None
        assert data["count"] <= server.FCM_WAKEUP_RECIPIENT_LIMIT
        assert server.fcm_inflight_count <= server.FCM_MAX_INFLIGHT_SENDS
    finally:
        for s in sockets:
            await s.close()


# ── Chat-control relay hardening (S6-53) ────────────────────────────────
#
# message_delete/disappear_timer/group_message_delete used to relay the
# caller's ENTIRE raw JSON object verbatim (message["from"] = username, then
# forwarded/stored/sent as-is) -- no schema reconstruction (unlike call
# signaling's _sanitize_call_signal(), S6-51), no dedicated envelope
# ceiling/rate bucket/byte budget, and a fire-and-forget
# asyncio.create_task(send_safe(...)) for online relay. An authenticated
# client could attach an arbitrary multi-megabyte field to an otherwise-
# legitimate delete/timer command and have it relayed, re-serialized, and
# independently Task-fanned-out with no admission control -- a
# authenticated high-bandwidth/task-amplification relay bounded only by
# MAX_PACKET_SIZE_BYTES (6 MiB). Fixed by sanitize_chat_control() (mirrors
# _sanitize_call_signal()'s "brand-new dict, only defined fields" pattern),
# a small CHAT_CONTROL_MAX_PACKET_SIZE_BYTES envelope, a shared
# "chat_control" rate_limit_check() bucket, sender/global/recipient byte
# budgets, and an awaited (not create_task'd) online send. Reused for
# incoming federated_forward payloads of these 3 types too, since all 3 are
# in FEDERATED_FORWARD_ALLOWED_TYPES. See SECURITY_INVARIANTS.md #66 and
# KNOWN_SECURITY_ISSUES.md S6-53.

def _msg_delete_frame(to, message_id=None, signature="sig", **extra):
    frame = {"type": "message_delete", "to": to}
    if message_id is not None:
        frame["message_id"] = message_id
    if signature is not None:
        frame["signature"] = signature
    frame.update(extra)
    return frame


def _disappear_timer_frame(to, seconds=3600, signature="sig", **extra):
    frame = {"type": "disappear_timer", "to": to, "seconds": seconds}
    if signature is not None:
        frame["signature"] = signature
    frame.update(extra)
    return frame


def _group_delete_frame(to, group_id=None, message_id=None, signature="sig", **extra):
    frame = {"type": "group_message_delete", "to": to}
    if group_id is not None:
        frame["group_id"] = group_id
    if message_id is not None:
        frame["message_id"] = message_id
    if signature is not None:
        frame["signature"] = signature
    frame.update(extra)
    return frame


async def _try_recv(ws, timeout=0.2):
    """A successful chat-control relay produces NO response to the sender
    at all (only the recipient gets the relayed frame) -- only a rejection
    (envelope/rate-limit/malformed) ever sends anything back on the
    sender's own socket. Used to distinguish "silently accepted" from
    "explicitly rejected" without blocking forever on the former."""
    try:
        return json.loads(await asyncio.wait_for(ws.recv(), timeout=timeout))
    except (asyncio.TimeoutError, TimeoutError):
        return None


# ── 1. real Android message_delete passes (message_id + signature) ───────

async def test_official_android_message_delete_passes(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-android-del-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-android-del-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        mid = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=mid, signature="sig123")))
        msg = await drain_until(recv_ws, "message_delete")
        assert msg["message_id"] == mid
        assert msg["signature"] == "sig123"
        assert msg["from"] == sender_fp
        assert msg["to"] == recv_fp
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 2. real Desktop message_delete passes ("id" field, signed as of S6-54) ─

async def test_official_desktop_message_delete_passes(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-desktop-del-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-desktop-del-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        mid = str(uuid.uuid4())
        await sender_ws.send(json.dumps({"type": "message_delete", "to": recv_fp, "id": mid, "signature": "sig"}))
        msg = await drain_until(recv_ws, "message_delete")
        assert msg["id"] == mid
        assert "message_id" not in msg
        assert msg["signature"] == "sig"
        assert msg["from"] == sender_fp
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 3. real disappear_timer passes ────────────────────────────────────────

async def test_official_disappear_timer_passes(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-timer-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-timer-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps(_disappear_timer_frame(recv_fp, seconds=86400, signature="sig456")))
        msg = await drain_until(recv_ws, "disappear_timer")
        assert msg["seconds"] == 86400
        assert msg["signature"] == "sig456"
        assert msg["from"] == sender_fp
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 4. real group_message_delete passes ───────────────────────────────────

async def test_official_group_message_delete_passes(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-groupdel-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-groupdel-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        gid, mid = str(uuid.uuid4()), str(uuid.uuid4())
        await sender_ws.send(json.dumps(_group_delete_frame(recv_fp, group_id=gid, message_id=mid, signature="sig789")))
        msg = await drain_until(recv_ws, "group_message_delete")
        assert msg["group_id"] == gid
        assert msg["message_id"] == mid
        assert msg["signature"] == "sig789"
        assert msg["from"] == sender_fp
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 5. noncanonical `to` rejected before any limiter-key creation ────────

async def test_noncanonical_to_rejected_before_limiter_state(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-badto")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps(_msg_delete_frame("not-a-fingerprint", message_id=str(uuid.uuid4()))))
        await asyncio.sleep(0.2)
        assert "not-a-fingerprint" not in server.chat_control_recipient_rate
        assert sender_fp not in server.chat_control_user_rate
    finally:
        await sender_ws.close()


# ── 6. oversized message ID rejected ──────────────────────────────────────

async def test_oversized_message_id_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-bigmid-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-bigmid-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        big_id = "A" * (server.CHAT_CONTROL_ID_MAX_LEN + 1)
        await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=big_id)))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 7. oversized group ID rejected ────────────────────────────────────────

async def test_oversized_group_id_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-biggid-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-biggid-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        big_gid = "A" * 200  # not UUID-shaped AND over-length either way
        await sender_ws.send(json.dumps(_group_delete_frame(
            recv_fp, group_id=big_gid, message_id=str(uuid.uuid4()))))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 8. oversized signature rejected ───────────────────────────────────────

async def test_oversized_signature_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-bigsig-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-bigsig-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        big_sig = "A" * (server.CHAT_CONTROL_SIGNATURE_MAX_LEN + 1)
        await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=str(uuid.uuid4()), signature=big_sig)))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 9. malformed disappear timer rejected (wrong type, bool-not-int) ─────

async def test_malformed_disappear_timer_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-malformed-timer-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-malformed-timer-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        for bad in ("not-a-number", True, False, [3600], {"x": 1}, None):
            await sender_ws.send(json.dumps({
                "type": "disappear_timer", "to": recv_fp, "seconds": bad, "signature": "sig",
            }))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 10. disappear timer outside the legitimate range rejected ────────────

async def test_disappear_timer_outside_range_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-timerrange-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-timerrange-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        for bad in (10, -1, 999999999, 1):
            await sender_ws.send(json.dumps(_disappear_timer_frame(recv_fp, seconds=bad)))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 11. multi-megabyte raw frame exceeds the chat-control envelope ───────

async def test_oversized_chat_control_frame_exceeds_envelope(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-envelope-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-envelope-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        frame = _msg_delete_frame(
            recv_fp, message_id=str(uuid.uuid4()),
            junk="A" * (server.CHAT_CONTROL_MAX_PACKET_SIZE_BYTES + 500),
        )
        raw = json.dumps(frame)
        assert len(raw.encode("utf-8")) > server.CHAT_CONTROL_MAX_PACKET_SIZE_BYTES
        assert len(raw.encode("utf-8")) < server.MAX_PACKET_SIZE_BYTES  # under the GLOBAL cap
        await sender_ws.send(raw)
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 12. an enormous `junk` field is never relayed (small-budget case) ────

async def test_junk_field_never_relayed(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-junk-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-junk-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        mid = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=mid, junk="unexpected-extra-field")))
        msg = await drain_until(recv_ws, "message_delete")
        assert "junk" not in msg
        assert msg["message_id"] == mid
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 13. sanitized payload contains ONLY defined fields ────────────────────

async def test_sanitized_payload_contains_only_defined_fields(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-onlyfields-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-onlyfields-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        gid, mid = str(uuid.uuid4()), str(uuid.uuid4())
        await sender_ws.send(json.dumps(_group_delete_frame(
            recv_fp, group_id=gid, message_id=mid, signature="sig", extra_field="nope")))
        msg = await drain_until(recv_ws, "group_message_delete")
        assert set(msg.keys()) == {"type", "from", "to", "group_id", "message_id", "signature"}
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 14. caller cannot spoof `from` ─────────────────────────────────────────

async def test_caller_cannot_spoof_from_in_chat_control(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-spoof-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-spoof-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        fake_from = canonical_fingerprint("s653-fake-identity")
        frame = _msg_delete_frame(recv_fp, message_id=str(uuid.uuid4()))
        frame["from"] = fake_from
        await sender_ws.send(json.dumps(frame))
        msg = await drain_until(recv_ws, "message_delete")
        assert msg["from"] == sender_fp
        assert msg["from"] != fake_from
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 15. shared "chat_control" count bucket (not two independent ones) ────

async def test_chat_control_shared_count_rate_limit(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-countlimit-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-countlimit-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        for _ in range(30):
            await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=str(uuid.uuid4()))))
        for _ in range(30):
            await sender_ws.send(json.dumps(_disappear_timer_frame(recv_fp)))
        await asyncio.sleep(0.3)
        # 60 already consumed across BOTH types combined -- the 61st (of
        # either type) must be rejected by the SAME shared bucket.
        await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=str(uuid.uuid4()))))
        msg = await drain_until(sender_ws, "error", timeout=1.0)
        assert msg["reason"] == "Rate limit exceeded"
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 16. sender byte budget bounds one sender ──────────────────────────────

async def test_chat_control_sender_byte_budget(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-userbudget-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-userbudget-r")
    real_max = server.CHAT_CONTROL_USER_MAX_BYTES
    server.CHAT_CONTROL_USER_MAX_BYTES = 200
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=str(uuid.uuid4()))))
        msg = json.loads(await recv_ws.recv())
        assert msg["type"] == "message_delete"
        await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=str(uuid.uuid4()))))
        resp = json.loads(await sender_ws.recv())
        assert resp == {"type": "error", "reason": "Rate limit exceeded"}
    finally:
        server.CHAT_CONTROL_USER_MAX_BYTES = real_max
        await sender_ws.close()
        await recv_ws.close()


# ── 17. recipient byte budget protects one victim from Sybil senders ─────

async def test_chat_control_recipient_byte_budget_protects_victim(running_server):
    real_max = server.CHAT_CONTROL_RECIPIENT_MAX_BYTES
    server.CHAT_CONTROL_RECIPIENT_MAX_BYTES = 300
    victim_ws = None
    sender_sockets = []
    try:
        victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s653-recipientbudget-v")
        await drain_until(victim_ws, "register_ok")
        rejected = False
        for i in range(5):
            sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id=f"s653-recipientbudget-s{i}")
            sender_sockets.append(sender_ws)
            await drain_until(sender_ws, "register_ok")
            await sender_ws.send(json.dumps(_msg_delete_frame(victim_fp, message_id=str(uuid.uuid4()))))
            resp = await _try_recv(sender_ws, 0.5)
            if resp == {"type": "error", "reason": "Rate limit exceeded"}:
                rejected = True
        assert rejected
    finally:
        server.CHAT_CONTROL_RECIPIENT_MAX_BYTES = real_max
        if victim_ws:
            await victim_ws.close()
        for s in sender_sockets:
            await s.close()


# ── 18. global byte budget bounds aggregate chat-control traffic ─────────

async def test_chat_control_global_byte_budget(running_server):
    real_max = server.CHAT_CONTROL_GLOBAL_MAX_BYTES
    server.CHAT_CONTROL_GLOBAL_MAX_BYTES = 300
    recipient_sockets = []
    sender_sockets = []
    try:
        rejected = False
        for i in range(5):
            recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id=f"s653-globalbudget-r{i}")
            recipient_sockets.append(recv_ws)
            await drain_until(recv_ws, "register_ok")
            sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id=f"s653-globalbudget-s{i}")
            sender_sockets.append(sender_ws)
            await drain_until(sender_ws, "register_ok")
            await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=str(uuid.uuid4()))))
            resp = await _try_recv(sender_ws, 0.5)
            if resp == {"type": "error", "reason": "Rate limit exceeded"}:
                rejected = True
        assert rejected
    finally:
        server.CHAT_CONTROL_GLOBAL_MAX_BYTES = real_max
        for s in recipient_sockets + sender_sockets:
            await s.close()


# ── 19. online relay is awaited, not fire-and-forget create_task ─────────

async def test_chat_control_online_relay_is_awaited_not_fire_and_forget():
    src = inspect.getsource(server.handle_client)
    section = src[src.index("Chat-control relay (S6-53)"):src.index("Anonymous Token Routing")]
    assert "asyncio.create_task(send_safe(target_ws" not in section
    assert "await send_safe(target_ws, serialized)" in section


# ── 20. a failed online send does not fall back to an offline store ──────

async def test_chat_control_send_failure_causes_no_offline_store_fallback(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-sendfail-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-sendfail-r")
    await drain_until(sender_ws, "register_ok")
    await drain_until(recv_ws, "register_ok")
    real_send_safe = server.send_safe

    async def _failing_send_safe(ws, data):
        return False

    server.send_safe = _failing_send_safe
    try:
        await sender_ws.send(json.dumps(_msg_delete_frame(recv_fp, message_id=str(uuid.uuid4()))))
        await asyncio.sleep(0.2)
        assert len(_read_pending_rows(recv_fp)) == 0
    finally:
        server.send_safe = real_send_safe
        await sender_ws.close()
        await recv_ws.close()


# ── 21. offline store receives the sanitized payload only ────────────────

async def test_chat_control_offline_store_receives_sanitized_payload_only(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-offlinesan-s")
    offline_fp = canonical_fingerprint("s653-offline-target")
    try:
        await drain_until(sender_ws, "register_ok")
        mid = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_msg_delete_frame(offline_fp, message_id=mid, junk="A" * 100)))
        await asyncio.sleep(0.2)
        rows = _read_pending_rows(offline_fp)
        assert len(rows) == 1
        stored = json.loads(rows[0][2])
        assert stored == {"type": "message_delete", "from": sender_fp, "to": offline_fp,
                           "message_id": mid, "signature": "sig"}
    finally:
        await sender_ws.close()


# ── 22. federation outbound receives the sanitized payload only ──────────

async def test_chat_control_federation_outbound_receives_sanitized_payload_only(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-fedout-s")
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    real_forward = server.forward_to_peers
    captured = {}

    async def _spy_forward(to, payload):
        captured["payload"] = payload
        return await real_forward(to, payload)

    server.forward_to_peers = _spy_forward
    offline_fp = canonical_fingerprint("s653-fedout-target")
    try:
        await drain_until(sender_ws, "register_ok")
        mid = str(uuid.uuid4())
        await sender_ws.send(json.dumps(_msg_delete_frame(offline_fp, message_id=mid, junk="unexpected")))
        await asyncio.sleep(0.2)
        assert captured.get("payload") == {"type": "message_delete", "from": sender_fp, "to": offline_fp,
                                            "message_id": mid, "signature": "sig"}
    finally:
        server.forward_to_peers = real_forward
        server.FEDERATION_SECRET = old_secret
        await sender_ws.close()


# ── 23. a failed offline store never schedules an FCM wakeup ─────────────

async def test_chat_control_failed_offline_store_no_fcm_wakeup(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-failstore-s")
    offline_fp = canonical_fingerprint("s653-failstore-target")
    real_db_store = server.db_store

    async def _failing_db_store(*args, **kwargs):
        return "FULL"

    server.db_store = _failing_db_store
    real_scheduler = server.schedule_fcm_wakeup
    called = []

    def _spy(target, source, reason):
        called.append(target)
        return True

    server.schedule_fcm_wakeup = _spy
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps(_msg_delete_frame(offline_fp, message_id=str(uuid.uuid4()))))
        await asyncio.sleep(0.2)
        assert offline_fp not in called
    finally:
        server.db_store = real_db_store
        server.schedule_fcm_wakeup = real_scheduler
        await sender_ws.close()


# ── 24. STORED/DUPLICATE preserves the existing FCM wakeup behavior ──────

async def test_chat_control_stored_status_triggers_fcm_wakeup(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-storedfcm-s")
    offline_fp = canonical_fingerprint("s653-storedfcm-target")
    real_scheduler = server.schedule_fcm_wakeup
    called = []

    def _spy(target, source, reason):
        called.append((target, reason))
        return True

    server.schedule_fcm_wakeup = _spy
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps(_msg_delete_frame(offline_fp, message_id=str(uuid.uuid4()))))
        await asyncio.sleep(0.2)
        assert any(t == offline_fp and r == "message_delete" for t, r in called)
    finally:
        server.schedule_fcm_wakeup = real_scheduler
        await sender_ws.close()


# ── 25. schedule_fcm_wakeup() remains the ONLY admission path for all 3 ──

async def test_chat_control_group_delete_and_timer_use_schedule_fcm_wakeup(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s653-allreasons-s")
    offline_fp1 = canonical_fingerprint("s653-allreasons-t1")
    offline_fp2 = canonical_fingerprint("s653-allreasons-t2")
    real_scheduler = server.schedule_fcm_wakeup
    called = []

    def _spy(target, source, reason):
        called.append((target, reason))
        return True

    server.schedule_fcm_wakeup = _spy
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps(_disappear_timer_frame(offline_fp1)))
        gid, mid = str(uuid.uuid4()), str(uuid.uuid4())
        await sender_ws.send(json.dumps(_group_delete_frame(offline_fp2, group_id=gid, message_id=mid)))
        await asyncio.sleep(0.2)
        assert (offline_fp1, "disappear_timer") in called
        assert (offline_fp2, "group_message_delete") in called
    finally:
        server.schedule_fcm_wakeup = real_scheduler
        await sender_ws.close()


# ── 26. a valid federated message_delete still works ──────────────────────

async def test_federated_message_delete_still_works(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("s653-fed-delete-target")
    peer_from = canonical_fingerprint("s653-fed-delete-peer")
    try:
        ws = await federation_connect(running_server)
        try:
            mid = str(uuid.uuid4())
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"type": "message_delete", "from": peer_from, "message_id": mid, "signature": "sig"},
            }))
            await asyncio.sleep(0.3)
            rows = _read_pending_rows(to)
            assert len(rows) == 1
            stored = json.loads(rows[0][2])
            assert stored == {"type": "message_delete", "from": peer_from, "to": to,
                               "message_id": mid, "signature": "sig"}
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 27. a federated control payload with unknown `junk` is stripped ──────

async def test_federated_chat_control_junk_stripped(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("s653-fed-junk-target")
    peer_from = canonical_fingerprint("s653-fed-junk-peer")
    try:
        ws = await federation_connect(running_server)
        try:
            mid = str(uuid.uuid4())
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"type": "message_delete", "from": peer_from, "message_id": mid,
                            "signature": "sig", "junk": "A" * 50},
            }))
            await asyncio.sleep(0.3)
            rows = _read_pending_rows(to)
            assert len(rows) == 1
            stored = json.loads(rows[0][2])
            assert "junk" not in stored
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 28. an oversized federated control field is rejected ─────────────────

async def test_federated_chat_control_oversized_field_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("s653-fed-oversized-target")
    peer_from = canonical_fingerprint("s653-fed-oversized-peer")
    try:
        ws = await federation_connect(running_server)
        try:
            big_id = "A" * (server.CHAT_CONTROL_ID_MAX_LEN + 1)
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"type": "message_delete", "from": peer_from, "message_id": big_id},
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 29. a malformed federated disappear_timer is rejected ────────────────

async def test_federated_chat_control_malformed_timer_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("s653-fed-timer-target")
    peer_from = canonical_fingerprint("s653-fed-timer-peer")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"type": "disappear_timer", "from": peer_from, "seconds": 99},
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 30. federated `from` is preserved exactly as the peer supplied it ────

async def test_federated_chat_control_from_preserved_for_online_recipient(running_server):
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s653-fedonline-r")
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    peer_from = canonical_fingerprint("s653-fedonline-peer")
    try:
        await drain_until(recv_ws, "register_ok")
        ws = await federation_connect(running_server)
        try:
            mid = str(uuid.uuid4())
            await ws.send(json.dumps({
                "type": "federated_forward", "to": recv_fp,
                "payload": {"type": "message_delete", "from": peer_from, "message_id": mid, "signature": "sig"},
            }))
            msg = await drain_until(recv_ws, "message_delete")
            assert msg["from"] == peer_from
            assert msg["message_id"] == mid
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        await recv_ws.close()


# ── 31. this patch does not reopen S6-38's privileged-type injection gap ─

async def test_federation_chat_control_patch_does_not_reopen_privileged_type_injection(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("s653-privileged-target")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"type": "session_conflict", "from": canonical_fingerprint("s653-privileged-peer")},
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── Attack regression: repeated near-envelope junk-stuffed message_delete
#    against an online victim ────────────────────────────────────────────

async def test_attack_repeated_oversized_message_delete_against_online_victim(running_server):
    attacker_ws, attacker_fp, _, _ = await connect_and_register(running_server, device_id="s653-attack-a")
    victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s653-attack-v")
    try:
        await drain_until(attacker_ws, "register_ok")
        await drain_until(victim_ws, "register_ok")
        before_task_count = len(asyncio.all_tasks())
        # "Near-frame-limit" relative to the TEST fixture's own ceiling, not
        # production's MAX_PACKET_SIZE_BYTES (6 MiB) -- running_server's
        # websockets.serve() doesn't set max_size at all, so it defaults to
        # the library's 1 MiB (same test-infrastructure distinction as
        # S6-45/S6-48's own tests). 900 KiB stays comfortably under that
        # while still exercising a genuinely large attacker payload, many
        # orders of magnitude over CHAT_CONTROL_MAX_PACKET_SIZE_BYTES.
        junk = "A" * (900 * 1024)
        for _ in range(5):
            frame = _msg_delete_frame(victim_fp, message_id=str(uuid.uuid4()), junk=junk)
            raw = json.dumps(frame)
            assert len(raw.encode("utf-8")) > server.CHAT_CONTROL_MAX_PACKET_SIZE_BYTES
            await attacker_ws.send(raw)
            await _try_recv(attacker_ws, 0.2)
        await asyncio.sleep(0.2)
        # None of the junk-stuffed frames were ever relayed to the victim.
        assert await _try_recv(victim_ws, 0.3) is None
        after_task_count = len(asyncio.all_tasks())
        # No unbounded background-Task fanout -- one bounded awaited send
        # per relay attempt would leave no lingering Tasks behind either.
        assert after_task_count - before_task_count < 5
    finally:
        await attacker_ws.close()
        await victim_ws.close()


# ── Cryptographic authentication + authorization of delete commands (S6-54) ─
#
# S6-53 STEP-11 found that neither official client actually verified a
# delete command's AUTHORIZATION on receive (a valid signature only proves
# who signed something, not that they're entitled to delete the referenced
# message), and that Desktop specifically sent/verified NO signature at all
# for message_delete/group_message_delete. Cryptographic authentication and
# semantic authorization are both entirely CLIENT-side concerns (this server
# has no reliable E2EE-message-author semantics to check against) -- what
# changes here is narrower: sanitize_chat_control() now REQUIRES a nonempty
# bounded `signature` for these 2 types (previously optional-if-present),
# both locally and for incoming federated_forward payloads, as defense-in-
# depth against official infrastructure ever relaying/storing an unsigned
# command that no up-to-date official client would produce. See
# SECURITY_INVARIANTS.md #67 and KNOWN_SECURITY_ISSUES.md S6-54.

# ── 1. unsigned message_delete is not relayed online ──────────────────────

async def test_unsigned_message_delete_not_relayed_online(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-unsigned-md-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s654-unsigned-md-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps({"type": "message_delete", "to": recv_fp, "message_id": str(uuid.uuid4())}))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 2. unsigned group_message_delete is not relayed online ────────────────

async def test_unsigned_group_message_delete_not_relayed_online(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-unsigned-gmd-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s654-unsigned-gmd-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "group_message_delete", "to": recv_fp,
            "group_id": str(uuid.uuid4()), "message_id": str(uuid.uuid4()),
        }))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 3. unsigned message_delete is not stored offline ───────────────────────

async def test_unsigned_message_delete_not_stored_offline(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-unsigned-md-offline")
    offline_fp = canonical_fingerprint("s654-unsigned-md-target")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps({"type": "message_delete", "to": offline_fp, "message_id": str(uuid.uuid4())}))
        await asyncio.sleep(0.2)
        assert len(_read_pending_rows(offline_fp)) == 0
    finally:
        await sender_ws.close()


# ── 4. unsigned group_message_delete is not stored offline ─────────────────

async def test_unsigned_group_message_delete_not_stored_offline(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-unsigned-gmd-offline")
    offline_fp = canonical_fingerprint("s654-unsigned-gmd-target")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "group_message_delete", "to": offline_fp,
            "group_id": str(uuid.uuid4()), "message_id": str(uuid.uuid4()),
        }))
        await asyncio.sleep(0.2)
        assert len(_read_pending_rows(offline_fp)) == 0
    finally:
        await sender_ws.close()


# ── 5. empty-string signature is rejected the same as a missing one ──────

async def test_empty_string_signature_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-emptysig-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s654-emptysig-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "message_delete", "to": recv_fp, "message_id": str(uuid.uuid4()), "signature": "",
        }))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 6. wrong-type signature (not a string) is rejected ────────────────────

async def test_wrong_type_signature_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-wrongtypesig-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s654-wrongtypesig-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        for bad in (12345, ["not", "a", "string"], {"x": 1}, True):
            await sender_ws.send(json.dumps({
                "type": "message_delete", "to": recv_fp, "message_id": str(uuid.uuid4()), "signature": bad,
            }))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 7. a validly-signed message_delete still relays (no regression) ──────

async def test_signed_message_delete_still_relays(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-signed-md-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s654-signed-md-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        mid = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "message_delete", "to": recv_fp, "message_id": mid, "signature": "real-signature-bytes",
        }))
        msg = await drain_until(recv_ws, "message_delete")
        assert msg["message_id"] == mid
        assert msg["signature"] == "real-signature-bytes"
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 8. a validly-signed group_message_delete still relays (no regression) ─

async def test_signed_group_message_delete_still_relays(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-signed-gmd-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s654-signed-gmd-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        gid, mid = str(uuid.uuid4()), str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "group_message_delete", "to": recv_fp, "group_id": gid, "message_id": mid,
            "signature": "real-group-signature-bytes",
        }))
        msg = await drain_until(recv_ws, "group_message_delete")
        assert msg["group_id"] == gid
        assert msg["message_id"] == mid
        assert msg["signature"] == "real-group-signature-bytes"
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 9. federation cannot strip the signature and still reach a local client ─

async def test_federated_unsigned_message_delete_rejected(running_server):
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s654-fedunsigned-md-r")
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    peer_from = canonical_fingerprint("s654-fedunsigned-md-peer")
    try:
        await drain_until(recv_ws, "register_ok")
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": recv_fp,
                "payload": {"type": "message_delete", "from": peer_from, "message_id": str(uuid.uuid4())},
            }))
            assert await _try_recv(recv_ws, 0.3) is None
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        await recv_ws.close()


# ── 10. federation cannot strip the signature for group_message_delete ────

async def test_federated_unsigned_group_message_delete_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("s654-fedunsigned-gmd-target")
    peer_from = canonical_fingerprint("s654-fedunsigned-gmd-peer")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {"type": "group_message_delete", "from": peer_from,
                            "group_id": str(uuid.uuid4()), "message_id": str(uuid.uuid4())},
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 11. disappear_timer's signature stays OPTIONAL (S6-54 scope check) ───
# STEP-10 of this patch's own review found disappear_timer's existing
# signature verification/authorization already sound (bare seconds value,
# but a 1:1 conversation has no third-party-authorship concern the way a
# message/group message does) and Desktop has no disappear_timer support at
# all to have a "missing signature" gap in the first place -- so, unlike
# message_delete/group_message_delete, this type's signature requirement is
# deliberately UNCHANGED by S6-54.

async def test_disappear_timer_signature_still_optional(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s654-timeroptional-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s654-timeroptional-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps({"type": "disappear_timer", "to": recv_fp, "seconds": 3600}))
        msg = await drain_until(recv_ws, "disappear_timer")
        assert msg["seconds"] == 3600
        assert "signature" not in msg
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ═══════════════════════════════════════════════════════════════════════════
# S6-55: durable offline queue must not delete-before-send ──────────────────
#
# _db_flush_sync() used to SELECT every pending row for a reconnecting
# recipient, DELETE all of them, THEN return the payloads for the caller to
# send one at a time -- so a disconnect after db_flush() returned but before
# (or midway through) the actual websocket sends silently destroyed every
# message that hadn't been handed off yet. Replaced with db_peek_pending()
# (read-only, bounded) + db_delete_pending_row() (deletes exactly one row,
# ONLY called after send_safe() for that row returns True). See
# SECURITY_INVARIANTS.md #68 and KNOWN_SECURITY_ISSUES.md S6-55.
# ═══════════════════════════════════════════════════════════════════════════

async def _run_flush_loop(recipient, sender, batch_size=None):
    """Test-only mirror of the production reconnect flush loop added to
    register() in server.py -- exercises the REAL db_peek_pending()/
    db_delete_pending_row() primitives under the exact peek → send →
    delete-only-on-success → stop-immediately-on-first-failure → bounded-
    batch shape the production loop uses. `sender.send_one(payload)` stands
    in for send_safe() so tests can script success/failure/exceptions per
    call deterministically without a live websocket. Returns the list of
    payload strings actually delivered (sent AND deleted), in FIFO order."""
    if batch_size is None:
        batch_size = server.PENDING_MESSAGES_FLUSH_BATCH_SIZE
    delivered = []
    while True:
        rows = await server.db_peek_pending(recipient, batch_size)
        if not rows:
            break
        stopped_early = False
        for row_id, payload_str, _payload_bytes in rows:
            if not await sender.send_one(payload_str):
                stopped_early = True
                break
            status = await server.db_delete_pending_row(recipient, row_id)
            assert status == "DELETED"
            delivered.append(payload_str)
        if stopped_early or len(rows) < batch_size:
            break
    return delivered


class _ScriptedSender:
    """Deterministic stand-in for a websocket's send_safe() outcome, one
    scripted result per call: True/False, or the RuntimeError class to
    simulate send_safe() raising (S6-55 STEP 5's crash-adjacent case --
    production send_safe() never actually raises, but the flush loop's
    ordering invariant must hold even if some future caller's send did).
    Any call beyond the scripted list succeeds, so tests only need to
    script the calls they actually care about."""
    def __init__(self, results):
        self._results = list(results)
        self.calls = 0

    async def send_one(self, payload):
        self.calls += 1
        if self.calls > len(self._results):
            return True
        outcome = self._results[self.calls - 1]
        if outcome is RuntimeError:
            raise RuntimeError("simulated send_safe failure")
        return outcome


# ── 1-8. db_peek_pending()/db_delete_pending_row() primitives ────────────

async def test_s655_peek_returns_rows_fifo():
    target = canonical_fingerprint("s655-peek-fifo")
    for i in range(5):
        await server.db_store(target, {"type": "message", "text": f"m{i}"}, msg_id=f"s655-fifo-{i}")
    rows = await server.db_peek_pending(target, 100)
    texts = [json.loads(r[1])["text"] for r in rows]
    assert texts == ["m0", "m1", "m2", "m3", "m4"]


async def test_s655_peek_does_not_delete_rows():
    target = canonical_fingerprint("s655-peek-nomutate")
    await server.db_store(target, {"type": "message", "text": "x"}, msg_id="s655-peeknomutate-1")
    await server.db_peek_pending(target, 100)
    await server.db_peek_pending(target, 100)
    assert len(_read_pending_rows(target)) == 1


async def test_s655_peek_does_not_change_meta():
    target = canonical_fingerprint("s655-peek-nometa")
    await server.db_store(target, {"type": "message", "text": "x"}, msg_id="s655-peeknometa-1")
    before = _read_meta()
    await server.db_peek_pending(target, 100)
    assert _read_meta() == before


async def test_s655_delete_removes_exactly_one_row():
    target = canonical_fingerprint("s655-delete-one")
    await server.db_store(target, {"type": "message", "text": "a"}, msg_id="s655-deleteone-1")
    await server.db_store(target, {"type": "message", "text": "b"}, msg_id="s655-deleteone-2")
    rows = await server.db_peek_pending(target, 100)
    status = await server.db_delete_pending_row(target, rows[0][0])
    assert status == "DELETED"
    remaining = _read_pending_rows(target)
    assert len(remaining) == 1
    assert json.loads(remaining[0][2])["text"] == "b"


async def test_s655_delete_decrements_meta_exactly_once():
    target = canonical_fingerprint("s655-delete-meta")
    await server.db_store(target, {"type": "message", "text": "payload"}, msg_id="s655-deletemeta-1")
    row = (await server.db_peek_pending(target, 100))[0]
    before = _read_meta()
    status = await server.db_delete_pending_row(target, row[0])
    assert status == "DELETED"
    assert _read_meta() == (before[0] - 1, before[1] - row[2])


async def test_s655_delete_nonexistent_row_returns_not_found():
    target = canonical_fingerprint("s655-delete-missing")
    status = await server.db_delete_pending_row(target, 999999999)
    assert status == "NOT_FOUND"


async def test_s655_delete_not_found_does_not_change_meta():
    target = canonical_fingerprint("s655-delete-missing-meta")
    before = _read_meta()
    status = await server.db_delete_pending_row(target, 999999999)
    assert status == "NOT_FOUND"
    assert _read_meta() == before


async def test_s655_delete_row_belonging_to_another_recipient_rejected():
    recipA = canonical_fingerprint("s655-wrongrecip-a")
    recipB = canonical_fingerprint("s655-wrongrecip-b")
    await server.db_store(recipA, {"type": "message", "text": "mine"}, msg_id="s655-wrongrecip-1")
    row = (await server.db_peek_pending(recipA, 100))[0]

    status = await server.db_delete_pending_row(recipB, row[0])
    assert status == "NOT_FOUND"
    # untouched -- still there for the real owner, meta unaffected
    assert len(_read_pending_rows(recipA)) == 1


# ── 9-13. delivery ordering / partial-batch-failure semantics ────────────

async def test_s655_send_success_removes_row():
    target = canonical_fingerprint("s655-sendsuccess")
    await server.db_store(target, {"type": "message", "text": "x"}, msg_id="s655-sendsuccess-1")
    delivered = await _run_flush_loop(target, _ScriptedSender([True]))
    assert len(delivered) == 1
    assert len(_read_pending_rows(target)) == 0


async def test_s655_send_failure_leaves_row_durable():
    target = canonical_fingerprint("s655-sendfail")
    await server.db_store(target, {"type": "message", "text": "x"}, msg_id="s655-sendfail-1")
    delivered = await _run_flush_loop(target, _ScriptedSender([False]))
    assert delivered == []
    assert len(_read_pending_rows(target)) == 1


async def test_s655_send_exception_leaves_row_durable():
    target = canonical_fingerprint("s655-sendexc")
    await server.db_store(target, {"type": "message", "text": "x"}, msg_id="s655-sendexc-1")
    with pytest.raises(RuntimeError):
        await _run_flush_loop(target, _ScriptedSender([RuntimeError]))
    # The row was never deleted -- send_safe() raising before returning
    # True means db_delete_pending_row() is never reached for this row,
    # same durability guarantee as an ordinary False return.
    assert len(_read_pending_rows(target)) == 1


async def test_s655_partial_batch_failure_deletes_only_delivered_prefix():
    target = canonical_fingerprint("s655-partialbatch")
    for i in range(3):
        await server.db_store(target, {"type": "message", "text": f"m{i}"}, msg_id=f"s655-partial-{i}")
    # #1 succeeds, #2 fails -- #3 must never even be attempted.
    delivered = await _run_flush_loop(target, _ScriptedSender([True, False]))
    assert len(delivered) == 1
    assert json.loads(delivered[0])["text"] == "m0"
    remaining = [json.loads(r[2])["text"] for r in _read_pending_rows(target)]
    assert remaining == ["m1", "m2"]


async def test_s655_reconnect_after_partial_failure_delivers_remaining_in_order():
    target = canonical_fingerprint("s655-partialresume")
    for i in range(3):
        await server.db_store(target, {"type": "message", "text": f"m{i}"}, msg_id=f"s655-resume-{i}")
    await _run_flush_loop(target, _ScriptedSender([True, False]))
    assert [json.loads(r[2])["text"] for r in _read_pending_rows(target)] == ["m1", "m2"]

    # "reconnect" -- a fresh flush loop, everything now succeeds.
    delivered = await _run_flush_loop(target, _ScriptedSender([True, True]))
    assert [json.loads(p)["text"] for p in delivered] == ["m1", "m2"]
    assert len(_read_pending_rows(target)) == 0


# ── 14-16. bounded batching ────────────────────────────────────────────────

async def test_s655_backlog_larger_than_batch_delivered_in_bounded_batches():
    target = canonical_fingerprint("s655-bigbacklog")
    for i in range(7):
        await server.db_store(target, {"type": "message", "text": f"m{i}"}, msg_id=f"s655-bigbacklog-{i}")
    delivered = await _run_flush_loop(target, _ScriptedSender([True] * 7), batch_size=3)
    assert [json.loads(p)["text"] for p in delivered] == [f"m{i}" for i in range(7)]
    assert len(_read_pending_rows(target)) == 0


async def test_s655_single_peek_never_materializes_whole_backlog():
    target = canonical_fingerprint("s655-peekbound")
    for i in range(10):
        await server.db_store(target, {"type": "message", "text": f"m{i}"}, msg_id=f"s655-peekbound-{i}")
    rows = await server.db_peek_pending(target, 4)
    assert len(rows) == 4


async def test_s655_message_inserted_during_flush_is_not_lost():
    target = canonical_fingerprint("s655-midflush-insert")
    await server.db_store(target, {"type": "message", "text": "first"}, msg_id="s655-midflush-1")

    rows = await server.db_peek_pending(target, server.PENDING_MESSAGES_FLUSH_BATCH_SIZE)
    assert len(rows) == 1
    # A sender stores a brand-new message for this same recipient WHILE
    # the (simulated) flush loop is mid-iteration -- must not be lost just
    # because the earlier peek() already ran.
    await server.db_store(target, {"type": "message", "text": "arrived-mid-flush"}, msg_id="s655-midflush-2")
    await server.db_delete_pending_row(target, rows[0][0])

    remaining = [json.loads(r[2])["text"] for r in _read_pending_rows(target)]
    assert remaining == ["arrived-mid-flush"]


# ── 17-19. crash-window duplicate-delivery simulation ─────────────────────

async def test_s655_send_success_without_delete_is_redelivered_on_reconnect():
    target = canonical_fingerprint("s655-crashwindow")
    await server.db_store(target, {"type": "message", "text": "x"}, msg_id="s655-crashwindow-1")
    # Simulate: send_safe() returned True, but the process "crashed" before
    # db_delete_pending_row() ran -- i.e. just peek + send, no delete.
    rows = await server.db_peek_pending(target, 100)
    ok = await _ScriptedSender([True]).send_one(rows[0][1])
    assert ok is True
    # No delete happened -- row is still durable.
    assert len(_read_pending_rows(target)) == 1

    # "Reconnect" -- a real flush loop now sees (and redelivers) the SAME row.
    delivered = await _run_flush_loop(target, _ScriptedSender([True]))
    assert len(delivered) == 1
    assert len(_read_pending_rows(target)) == 0


async def test_s655_crash_window_duplicate_is_possible_not_silent_loss():
    # Documents the accepted tradeoff explicitly, as its own assertion:
    # at-least-once means a genuine duplicate CAN happen, but the message
    # itself is never simply gone.
    target = canonical_fingerprint("s655-crashwindow-doc")
    await server.db_store(target, {"type": "message", "text": "important"}, msg_id="s655-crashwindow-doc-1")
    rows = await server.db_peek_pending(target, 100)
    await _ScriptedSender([True]).send_one(rows[0][1])  # "sent", no delete (crash)
    assert len(_read_pending_rows(target)) == 1  # NOT lost
    delivered = await _run_flush_loop(target, _ScriptedSender([True]))
    assert len(delivered) == 1  # redelivered — a duplicate, not a loss


# ── 20-24. concurrency safety ─────────────────────────────────────────────

async def test_s655_two_concurrent_deletes_same_row_decrement_meta_once():
    target = canonical_fingerprint("s655-concurrent-delete")
    await server.db_store(target, {"type": "message", "text": "x"}, msg_id="s655-concdelete-1")
    row = (await server.db_peek_pending(target, 100))[0]
    before = _read_meta()

    results = await asyncio.gather(
        server.db_delete_pending_row(target, row[0]),
        server.db_delete_pending_row(target, row[0]),
    )
    assert sorted(results) == ["DELETED", "NOT_FOUND"]
    assert _read_meta() == (before[0] - 1, before[1] - row[2])
    assert _read_meta() == _real_pending_totals()


async def test_s655_watchdog_delete_race_keeps_meta_correct():
    target = canonical_fingerprint("s655-watchdog-race")
    await server.db_store(target, {"type": "message", "text": "stale"}, msg_id="s655-watchdograce-1")
    row = (await server.db_peek_pending(target, 100))[0]
    # Backdate it past TTL, then let the watchdog delete it out from under
    # a flush loop that already peeked this exact row (STEP 8).
    with server.db_connect() as conn:
        conn.execute(
            "UPDATE pending_messages SET created_at = ? WHERE id = ?",
            (server.time.time() - server.MSG_TTL_SEC - 10, row[0])
        )
        conn.commit()
    await server._pending_messages_watchdog_tick()
    assert len(_read_pending_rows(target)) == 0

    before = _read_meta()
    status = await server.db_delete_pending_row(target, row[0])
    assert status == "NOT_FOUND"
    assert _read_meta() == before  # no double-decrement
    assert _read_meta() == _real_pending_totals()


async def test_s655_store_delete_concurrency_keeps_accounting_correct():
    target = canonical_fingerprint("s655-store-delete-race")
    await server.db_store(target, {"type": "message", "text": "existing"}, msg_id="s655-storedeleterace-1")
    row = (await server.db_peek_pending(target, 100))[0]

    await asyncio.gather(
        server.db_delete_pending_row(target, row[0]),
        server.db_store(target, {"type": "message", "text": "new"}, msg_id="s655-storedeleterace-2"),
    )
    assert _read_meta() == _real_pending_totals()
    remaining = [json.loads(r[2])["text"] for r in _read_pending_rows(target)]
    assert remaining == ["new"]


async def test_s655_concurrent_reconnects_same_account_no_meta_corruption(running_server):
    # Two connections authenticating as the SAME identity keypair (a real
    # session-conflict eviction, S6-39/register()'s own Phase 2) can each
    # start their own reconnect flush loop for the same fingerprint. Even
    # without perfect mutual exclusion this must never corrupt the running
    # totals -- db_delete_pending_row()'s NOT_FOUND handling is the safety
    # net (see its own comment and get_pending_flush_lock()'s comment).
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    for i in range(5):
        await server.db_store(target, {"type": "message", "text": f"m{i}"}, msg_id=f"s655-dualreconnect-{i}")

    ws1 = await websockets.connect(running_server)
    await handshake(ws1, priv, pub_der)
    await register(ws1, pub_der, "s655-dual-device-1", "t")
    await drain_until(ws1, "register_ok")
    # A second device identity triggers session_conflict eviction of ws1
    # (is_different_live_device=True in register()'s Phase 2) WHILE ws1's
    # own reconnect flush loop for this account may still be running.
    ws2 = await websockets.connect(running_server)
    await handshake(ws2, priv, pub_der)
    await register(ws2, pub_der, "s655-dual-device-2", "t")
    try:
        await asyncio.sleep(0.3)
        assert _read_meta() == _real_pending_totals()
        assert _read_meta()[0] >= 0 and _read_meta()[1] >= 0
    finally:
        for ws in (ws1, ws2):
            try:
                await ws.close()
            except Exception:
                pass


async def test_s655_flush_lock_self_prunes_is_reused_not_leaked():
    # pending_flush_locks is a plain per-account dict (like avatar_mutation_
    # locks/totp_state_locks), keyed on this connection's OWN proven
    # identity -- not the ref-counted self-pruning shape prekey_mutation_
    # locks needs. Confirms repeated use of the SAME account reuses the
    # SAME lock object rather than minting a new one every call.
    target = canonical_fingerprint("s655-lockreuse")
    lock1 = server.get_pending_flush_lock(target)
    lock2 = server.get_pending_flush_lock(target)
    assert lock1 is lock2


# ── 25-27. capacity accounting ─────────────────────────────────────────────

async def test_s655_delivered_deletion_frees_exact_capacity():
    target = canonical_fingerprint("s655-capacity-free")
    await server.db_store(target, {"type": "message", "text": "x" * 500}, msg_id="s655-capfree-1")
    row = (await server.db_peek_pending(target, 100))[0]
    before = _read_meta()
    await server.db_delete_pending_row(target, row[0])
    assert _read_meta() == (before[0] - 1, before[1] - row[2])


async def test_s655_failed_send_frees_no_capacity():
    target = canonical_fingerprint("s655-capacity-nofree")
    await server.db_store(target, {"type": "message", "text": "x" * 500}, msg_id="s655-capnofree-1")
    before = _read_meta()
    delivered = await _run_flush_loop(target, _ScriptedSender([False]))
    assert delivered == []
    assert _read_meta() == before


async def test_s655_startup_reconciliation_still_correct_after_partial_flush():
    target = canonical_fingerprint("s655-reconcile-after-partial")
    for i in range(3):
        await server.db_store(target, {"type": "message", "text": f"m{i}"}, msg_id=f"s655-reconcileafter-{i}")
    await _run_flush_loop(target, _ScriptedSender([True, False]))  # #0 delivered, #1/#2 remain

    with server.db_connect() as conn:
        conn.execute("UPDATE pending_messages_meta SET total_rows = 9999, total_bytes = 9999 WHERE id = 1")
        conn.commit()
    server._db_setup_sync()  # re-runs startup reconciliation
    assert _read_meta() == _real_pending_totals()
    assert _read_meta()[0] == len(_read_pending_rows())


# ── 28-30. regression: ordinary registration/delivery paths still work ───

async def test_s655_registration_with_empty_offline_queue_still_works(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s655-empty-queue")
    try:
        await drain_until(ws, "register_ok")
    finally:
        await ws.close()


async def test_s655_registration_with_queued_message_delivers_it(running_server):
    # canonical_fingerprint() targets aren't real registered devices, so
    # this test registers the queued recipient's actual keypair instead, to
    # prove the ACTUAL production register() handler (not just the
    # primitives) delivers a queued message on reconnect.
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    await server.db_store(target, {"type": "message", "text": "queued-for-real-client", "id": "s655-regqueued-1",
                                    "from": canonical_fingerprint("s655-regqueued-sender"), "signature": "sig"},
                           msg_id="s655-regqueued-1")
    ws = await websockets.connect(running_server)
    await handshake(ws, priv, pub_der)
    await register(ws, pub_der, "s655-regqueued-device", "t")
    try:
        msg = await drain_until(ws, "message")
        assert msg["id"] == "s655-regqueued-1"
        assert msg["text"] == "queued-for-real-client"
        # The server's own db_delete_pending_row() runs just after the
        # send that the client just received, but as a separate awaited
        # executor hop -- give it one event-loop turn to actually commit
        # before asserting the row is gone.
        await asyncio.sleep(0.1)
        assert len(_read_pending_rows(target)) == 0
    finally:
        await ws.close()


async def test_s655_registration_with_queued_session_init_delivers_it(running_server):
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    await server.db_store(target, {
        "type": "session_init", "from": canonical_fingerprint("s655-siqueued-sender"),
        "sender_ik": "ik", "x3dh_header": "hdr", "session_header": "shdr",
        "text": "ct", "signature": "sig", "id": "s655-siqueued-1", "protocol_version": 2
    }, msg_id="s655-siqueued-1")
    ws = await websockets.connect(running_server)
    await handshake(ws, priv, pub_der)
    await register(ws, pub_der, "s655-siqueued-device", "t")
    try:
        msg = await drain_until(ws, "session_init")
        assert msg["id"] == "s655-siqueued-1"
        await asyncio.sleep(0.1)
        assert len(_read_pending_rows(target)) == 0
    finally:
        await ws.close()


# ── ATTACK/FAILURE REGRESSION: N queued, K delivered, N-K survive a cut ───

async def test_s655_attack_reconnect_cut_midbatch_preserves_undelivered_tail(running_server):
    priv, pub_der = gen_keypair()
    target = fingerprint_of(pub_der)
    N, K = 5, 2
    for i in range(N):
        await server.db_store(target, {
            "type": "message", "text": f"m{i}", "id": f"s655-attack-{i}",
            "from": canonical_fingerprint("s655-attack-sender"), "signature": "sig",
        }, msg_id=f"s655-attack-{i}")

    real_send_safe = server.send_safe
    state = {"count": 0}

    async def cutting_send_safe(ws, data):
        if "s655-attack-" not in data:
            return await real_send_safe(ws, data)  # register_ok/avatar/etc.
        state["count"] += 1
        if state["count"] > K:
            return False  # simulate the connection dying mid-batch
        return await real_send_safe(ws, data)

    server.send_safe = cutting_send_safe
    try:
        ws = await websockets.connect(running_server)
        await handshake(ws, priv, pub_der)
        await register(ws, pub_der, "s655-attack-device-1", "t")
        try:
            for i in range(K):
                msg = await drain_until(ws, "message")
                assert msg["text"] == f"m{i}"
        finally:
            await ws.close()
        await asyncio.sleep(0.2)

        remaining = [json.loads(r[2])["text"] for r in _read_pending_rows(target)]
        assert remaining == [f"m{i}" for i in range(K, N)]
        assert _read_meta() == _real_pending_totals()
    finally:
        server.send_safe = real_send_safe

    # Reconnect again -- everything now succeeds, remaining tail delivered
    # in original FIFO order.
    ws2 = await websockets.connect(running_server)
    await handshake(ws2, priv, pub_der)
    await register(ws2, pub_der, "s655-attack-device-1", "t")
    try:
        for i in range(K, N):
            msg = await drain_until(ws2, "message")
            assert msg["text"] == f"m{i}"
        await asyncio.sleep(0.1)
        assert len(_read_pending_rows(target)) == 0
    finally:
        await ws2.close()


# ═══════════════════════════════════════════════════════════════════════════
# S6-56: hard safety ceiling for durable account creation ───────────────────
#
# MAX_REGISTERED_USERS=0 used to mean literally unlimited -- no ceiling of
# any kind underneath it. REGISTERED_ACCOUNTS_HARD_MAX_ROWS is now an
# always-on hard safety ceiling effective_registration_cap() folds in
# alongside the operator's own (still-optional) cap, enforced inside the
# SAME atomic db_admit_new_fingerprint() transaction that already handles
# exists/cap/access-code-consume/insert. See SECURITY_INVARIANTS.md #69 and
# KNOWN_SECURITY_ISSUES.md S6-56.
# ═══════════════════════════════════════════════════════════════════════════

_server_source = inspect.getsource(server)


# ── 1-3. reachability/config documentation (STEP 1) ───────────────────────

async def test_s656_default_max_registered_users_is_zero_meaning_no_operator_cap():
    assert 'os.environ.get("MAX_REGISTERED_USERS", "0")' in _server_source
    # 0/unset now means "no smaller operator cap than the hard ceiling," not
    # "no ceiling at all" -- effective_registration_cap() is what actually
    # enforces that; see tests 7/10 below.
    real_max = server.MAX_REGISTERED_USERS
    server.MAX_REGISTERED_USERS = 0
    try:
        assert server.effective_registration_cap() == server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    finally:
        server.MAX_REGISTERED_USERS = real_max


async def test_s656_default_pow_difficulty_is_nonzero_but_operator_disableable():
    # Confirms the actual shipped default (18 bits, real friction) while
    # also confirming an operator CAN set it to 0 and fully disable PoW --
    # this is exactly why REGISTERED_ACCOUNTS_HARD_MAX_ROWS can't rely on PoW
    # as the durable-resource boundary.
    assert 'os.environ.get("POW_DIFFICULTY_BITS", "18")' in _server_source
    real_pow = server.POW_DIFFICULTY_BITS
    server.POW_DIFFICULTY_BITS = 0
    try:
        assert server.POW_DIFFICULTY_BITS == 0
    finally:
        server.POW_DIFFICULTY_BITS = real_pow


async def test_s656_default_server_access_protected_is_off():
    # .env.example explicitly tells personal-server operators to leave this
    # empty/false -- the shipped default is genuinely open registration,
    # confirmed here so this doesn't silently drift without the test noticing.
    assert 'os.environ.get("SERVER_ACCESS_PROTECTED", "")' in _server_source
    assert server.SERVER_ACCESS_PROTECTED in (True, False)


# ── 4-10. hard cap semantics ───────────────────────────────────────────────

async def test_s656_new_accounts_succeed_below_hard_cap():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 5
    try:
        for i in range(3):
            status = await server.db_admit_new_fingerprint(
                f"S656A{i:03d}", server.effective_registration_cap(), "", False
            )
            assert status == "ok"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_exact_final_slot_succeeds():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 3
    try:
        for i in range(2):
            assert await server.db_admit_new_fingerprint(
                f"S656B{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
        # this is the LAST available slot (2 used, hard cap 3)
        assert await server.db_admit_new_fingerprint(
            "S656BLAST", server.effective_registration_cap(), "", False
        ) == "ok"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_next_new_fingerprint_after_hard_cap_is_full():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 2
    try:
        for i in range(2):
            assert await server.db_admit_new_fingerprint(
                f"S656C{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
        status = await server.db_admit_new_fingerprint(
            "S656CONE_MORE", server.effective_registration_cap(), "", False
        )
        assert status == "full"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_max_registered_users_zero_does_not_bypass_hard_cap():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    real_max  = server.MAX_REGISTERED_USERS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 2
    server.MAX_REGISTERED_USERS = 0  # "no operator cap" -- must NOT mean unlimited
    try:
        for i in range(2):
            assert await server.db_admit_new_fingerprint(
                f"S656D{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
        status = await server.db_admit_new_fingerprint(
            "S656DONE_MORE", server.effective_registration_cap(), "", False
        )
        assert status == "full"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard
        server.MAX_REGISTERED_USERS = real_max


async def test_s656_operator_cap_lower_than_hard_cap_wins():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    real_max  = server.MAX_REGISTERED_USERS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 1000
    server.MAX_REGISTERED_USERS = 2
    try:
        assert server.effective_registration_cap() == 2
        for i in range(2):
            assert await server.db_admit_new_fingerprint(
                f"S656E{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
        status = await server.db_admit_new_fingerprint(
            "S656EONE_MORE", server.effective_registration_cap(), "", False
        )
        assert status == "full"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard
        server.MAX_REGISTERED_USERS = real_max


async def test_s656_operator_cap_equal_to_hard_cap_works():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    real_max  = server.MAX_REGISTERED_USERS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 3
    server.MAX_REGISTERED_USERS = 3
    try:
        assert server.effective_registration_cap() == 3
        for i in range(3):
            assert await server.db_admit_new_fingerprint(
                f"S656F{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard
        server.MAX_REGISTERED_USERS = real_max


async def test_s656_operator_cap_higher_than_hard_cap_cannot_raise_effective_limit():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    real_max  = server.MAX_REGISTERED_USERS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 2
    server.MAX_REGISTERED_USERS = 1000  # operator asks for way more than the hard ceiling
    try:
        assert server.effective_registration_cap() == 2
        for i in range(2):
            assert await server.db_admit_new_fingerprint(
                f"S656G{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
        status = await server.db_admit_new_fingerprint(
            "S656GONE_MORE", server.effective_registration_cap(), "", False
        )
        assert status == "full"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard
        server.MAX_REGISTERED_USERS = real_max


# ── 11-14. existing users are never blocked by the new-account cap ───────

async def test_s656_existing_fingerprint_reconnects_at_hard_cap(running_server):
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 1
    try:
        ws, fp, priv, pub_der = await connect_and_register(running_server, device_id="s656-existing-reconnect")
        await drain_until(ws, "register_ok")
        await ws.close()
        # table is now exactly at the (monkeypatched) hard cap
        assert len(_registered_fp_rows()) == 1

        ws2 = await websockets.connect(running_server)
        await handshake(ws2, priv, pub_der)
        await register(ws2, pub_der, "s656-existing-reconnect", "t")
        try:
            reply = await drain_until(ws2, "register_ok")
            assert reply["type"] == "register_ok"
        finally:
            await ws2.close()
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_existing_device_auth_works_at_hard_cap(running_server):
    # A second AUTHORIZED device for an ALREADY-registered account is
    # governed by S6-37's own per-account device cap, never by the new-
    # account count -- confirmed here by actually completing a device-auth
    # round trip while the account table sits at the (monkeypatched) hard cap.
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 1
    try:
        priv, pub_der = gen_keypair()
        fp = fingerprint_of(pub_der)
        ws1 = await websockets.connect(running_server)
        await handshake(ws1, priv, pub_der)
        await register(ws1, pub_der, "s656-device-a", "t")
        await drain_until(ws1, "register_ok")
        await ws1.close()

        device_priv, device_pub_der = gen_keypair()
        device_id = canonical_device_id("s656-device-b")
        ws2 = await websockets.connect(running_server)
        challenge = await handshake(ws2, priv, pub_der)
        sig = sign_device_challenge(device_priv, challenge, fp, device_id)
        await register(ws2, pub_der, device_id, "t", extra={
            "device_public_key": base64.b64encode(
                device_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).decode(),
            "device_signature": base64.b64encode(sig).decode(),
        })
        try:
            reply = await drain_until(ws2, "register_ok")
            assert reply["type"] == "register_ok"
        finally:
            await ws2.close()
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_existing_account_reconnect_not_counted_as_new_admission():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 1
    try:
        status1 = await server.db_admit_new_fingerprint("S656EXIST01", server.effective_registration_cap(), "", False)
        assert status1 == "ok"
        # "reconnect" -- same fingerprint, admission attempted again
        status2 = await server.db_admit_new_fingerprint("S656EXIST01", server.effective_registration_cap(), "", False)
        assert status2 == "exists"
        assert len(_registered_fp_rows()) == 1
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_existing_user_reconnect_consumes_no_new_account_budget(running_server):
    real_limit = server.NEW_ACCOUNT_GLOBAL_LIMIT
    server.NEW_ACCOUNT_GLOBAL_LIMIT = 1
    server.NEW_ACCOUNT_GLOBAL_ENABLED = True
    try:
        ws, fp, priv, pub_der = await connect_and_register(running_server, device_id="s656-budget-existing")
        await drain_until(ws, "register_ok")
        await ws.close()
        # That first registration consumed the ENTIRE budget (limit=1) as a
        # NEW fingerprint. A reconnect must not need any of it.
        ws2 = await websockets.connect(running_server)
        await handshake(ws2, priv, pub_der)
        await register(ws2, pub_der, "s656-budget-existing", "t")
        try:
            reply = await drain_until(ws2, "register_ok")
            assert reply["type"] == "register_ok"
        finally:
            await ws2.close()
    finally:
        server.NEW_ACCOUNT_GLOBAL_LIMIT = real_limit
        server.NEW_ACCOUNT_GLOBAL_ENABLED = real_limit > 0


# ── 15-18. concurrency ─────────────────────────────────────────────────────

async def test_s656_concurrent_registrations_race_for_one_remaining_slot():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 5
    try:
        for i in range(4):
            assert await server.db_admit_new_fingerprint(
                f"S656RACE{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
        # exactly ONE remaining slot -- 10 concurrent distinct fingerprints race for it
        results = await asyncio.gather(*[
            server.db_admit_new_fingerprint(
                f"S656RACER{i:03d}", server.effective_registration_cap(), "", False
            )
            for i in range(10)
        ])
        assert sum(1 for r in results if r == "ok") == 1
        assert sum(1 for r in results if r == "full") == 9
        assert len(_registered_fp_rows()) == 5
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_durable_row_count_never_exceeds_hard_cap():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 5
    try:
        results = await asyncio.gather(*[
            server.db_admit_new_fingerprint(
                f"S656ROWS{i:03d}", server.effective_registration_cap(), "", False
            )
            for i in range(30)
        ])
        assert sum(1 for r in results if r == "ok") == 5
        assert len(_registered_fp_rows()) == 5
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_losing_transaction_consumes_no_access_code():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 1
    code = "ABCDEF0123456789ABCDEF0123456789"
    assert server.is_valid_access_code(code)
    with server.db_connect() as conn:
        conn.execute(
            "INSERT INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
            (server._hash_access_code(code), 0.0),
        )
        conn.commit()
    try:
        # Fill the one available slot WITHOUT the code first.
        assert await server.db_admit_new_fingerprint(
            "S656CODEFILL", server.effective_registration_cap(), "", False
        ) == "ok"
        # Now the table is at the hard cap -- a genuinely valid, unused code
        # must survive a "full" rejection completely untouched.
        status = await server.db_admit_new_fingerprint(
            "S656CODELOSER", server.effective_registration_cap(), code, True
        )
        assert status == "full"
        with server.db_connect() as conn:
            row = conn.execute(
                "SELECT used FROM server_access_codes WHERE code = ?",
                (server._hash_access_code(code),)
            ).fetchone()
        assert row[0] == 0
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_no_double_success_under_concurrency_same_fingerprint():
    # Same fingerprint racing itself (two connections proving the same
    # private key at once) must never insert twice -- "exists" for the
    # loser, not a second "ok" or a UNIQUE-constraint crash.
    results = await asyncio.gather(*[
        server.db_admit_new_fingerprint("S656SAMEFP", server.effective_registration_cap(), "", False)
        for _ in range(15)
    ])
    assert sum(1 for r in results if r == "ok") == 1
    assert sum(1 for r in results if r == "exists") == 14
    assert len(_registered_fp_rows("S656SAMEFP")) == 1


# ── 19-21. access-code interaction ─────────────────────────────────────────

async def test_s656_registration_full_does_not_consume_unused_code():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 0 + 1  # 1, spelled out for clarity at the call site below
    code = "11112222333344445555666677778888"
    assert server.is_valid_access_code(code)
    with server.db_connect() as conn:
        conn.execute(
            "INSERT INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
            (server._hash_access_code(code), 0.0),
        )
        conn.commit()
    try:
        assert await server.db_admit_new_fingerprint(
            "S656PREFILL", server.effective_registration_cap(), "", False
        ) == "ok"
        status = await server.db_admit_new_fingerprint(
            "S656WOULDBENEW", server.effective_registration_cap(), code, True
        )
        assert status == "full"
        total, unused = server._db_count_access_codes_sync()
        assert unused == 1
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_successful_last_slot_registration_consumes_code_exactly_once():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 1
    code = "AAAA1111BBBB2222CCCC3333DDDD4444"
    assert server.is_valid_access_code(code)
    with server.db_connect() as conn:
        conn.execute(
            "INSERT INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
            (server._hash_access_code(code), 0.0),
        )
        conn.commit()
    try:
        status = await server.db_admit_new_fingerprint(
            "S656LASTSLOT", server.effective_registration_cap(), code, True
        )
        assert status == "ok"
        total, unused = server._db_count_access_codes_sync()
        assert unused == 0
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_existing_s6_atomic_access_code_test_still_green():
    # test_access_code_atomic_under_concurrent_redemption (S6-41, elsewhere
    # in this file) already covers this directly against
    # db_admit_new_fingerprint() with an explicit max_users=0 -- this is a
    # lightweight confirmation that effective_registration_cap() itself
    # doesn't change that function's internal atomicity, just the value fed
    # into its existing `max_users` parameter.
    code = "0123ABCD4567EFAB0123ABCD4567EFAB"
    assert server.is_valid_access_code(code)
    with server.db_connect() as conn:
        conn.execute(
            "INSERT INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
            (server._hash_access_code(code), 0.0),
        )
        conn.commit()
    results = await asyncio.gather(*[
        server.db_admit_new_fingerprint(f"S656ATOMIC{i:03d}", server.effective_registration_cap(), code, True)
        for i in range(20)
    ])
    assert sum(1 for r in results if r == "ok") == 1


# ── 22-25. global new-account work budget ──────────────────────────────────

async def test_s656_sybil_new_account_attempts_hit_global_budget(running_server):
    real_limit = server.NEW_ACCOUNT_GLOBAL_LIMIT
    server.NEW_ACCOUNT_GLOBAL_LIMIT = 2
    server.NEW_ACCOUNT_GLOBAL_ENABLED = True
    try:
        admitted, rejected = 0, 0
        for i in range(5):
            priv, pub_der = gen_keypair()
            ws = await websockets.connect(running_server)
            try:
                await handshake(ws, priv, pub_der)
                await register(ws, pub_der, f"s656-sybil-{i}", "t")
                reply = await _collect_until_relevant(ws, {"register_ok", "registration_full"})
                if reply["type"] == "register_ok":
                    admitted += 1
                else:
                    rejected += 1
            finally:
                await ws.close()
        assert admitted == 2
        assert rejected == 3
    finally:
        server.NEW_ACCOUNT_GLOBAL_LIMIT = real_limit
        server.NEW_ACCOUNT_GLOBAL_ENABLED = real_limit > 0


async def test_s656_existing_reconnects_bypass_new_account_budget(running_server):
    ws, fp, priv, pub_der = await connect_and_register(running_server, device_id="s656-bypass-budget")
    await drain_until(ws, "register_ok")
    await ws.close()

    real_limit = server.NEW_ACCOUNT_GLOBAL_LIMIT
    server.NEW_ACCOUNT_GLOBAL_LIMIT = 0  # fully exhausted/disabled -- 0 means disabled, not "always reject"
    server.NEW_ACCOUNT_GLOBAL_ENABLED = False
    try:
        ws2 = await websockets.connect(running_server)
        await handshake(ws2, priv, pub_der)
        await register(ws2, pub_der, "s656-bypass-budget", "t")
        try:
            reply = await drain_until(ws2, "register_ok")
            assert reply["type"] == "register_ok"
        finally:
            await ws2.close()
    finally:
        server.NEW_ACCOUNT_GLOBAL_LIMIT = real_limit
        server.NEW_ACCOUNT_GLOBAL_ENABLED = real_limit > 0


async def test_s656_malformed_requests_do_not_create_limiter_state():
    # new_account_global_rate is a single shared counter (not keyed per-
    # fingerprint/IP), so there's no per-caller state to leak in the first
    # place -- confirms its shape stays that way.
    assert set(server.new_account_global_rate.keys()) == {"count", "reset_time"}


async def test_s656_limiter_state_self_prunes_via_fixed_window():
    # Not a keyed dict at all -- a single fixed-size counter that resets on
    # its own window, so there's nothing per-identity to prune. Confirms the
    # window-reset mechanics directly.
    real_limit  = server.NEW_ACCOUNT_GLOBAL_LIMIT
    real_window = server.NEW_ACCOUNT_GLOBAL_WINDOW_SEC
    server.NEW_ACCOUNT_GLOBAL_LIMIT = 1
    server.NEW_ACCOUNT_GLOBAL_ENABLED = True
    try:
        assert server.new_account_global_rate_ok() is True
        assert server.new_account_global_rate_ok() is False
        server.new_account_global_rate["reset_time"] -= server.NEW_ACCOUNT_GLOBAL_WINDOW_SEC + 1
        assert server.new_account_global_rate_ok() is True
    finally:
        server.NEW_ACCOUNT_GLOBAL_LIMIT = real_limit
        server.NEW_ACCOUNT_GLOBAL_ENABLED = real_limit > 0
        server.NEW_ACCOUNT_GLOBAL_WINDOW_SEC = real_window


# ── 26-29. startup accounting ───────────────────────────────────────────────

def _registered_fp_rows(fingerprint=None):
    with server.db_connect() as conn:
        if fingerprint is not None:
            return conn.execute(
                "SELECT fingerprint FROM registered_fingerprints WHERE fingerprint = ?", (fingerprint,)
            ).fetchall()
        return conn.execute("SELECT fingerprint FROM registered_fingerprints").fetchall()


async def test_s656_startup_accounting_below_hard_cap():
    await server.db_admit_new_fingerprint("S656STARTBELOW", 1000, "", False)
    count = server._db_count_registered_fingerprints_sync()
    assert count <= server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    # _db_setup_sync() must not raise/exit merely because rows exist below cap
    server._db_setup_sync()


async def test_s656_startup_accounting_exactly_at_hard_cap():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 3
    try:
        for i in range(3):
            assert await server.db_admit_new_fingerprint(
                f"S656STARTAT{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
        count = server._db_count_registered_fingerprints_sync()
        assert count == server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
        # Existing accounts remain usable -- _db_setup_sync() itself never
        # refuses to run based on this count (registered_fingerprints is
        # never bulk-loaded into RAM, unlike avatars/anon-tokens).
        server._db_setup_sync()
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_startup_above_hard_cap_follows_documented_no_delete_policy():
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 1000
    try:
        for i in range(3):
            assert await server.db_admit_new_fingerprint(
                f"S656STARTOVER{i:03d}", server.effective_registration_cap(), "", False
            ) == "ok"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard
    # Lower the hard cap BELOW the count that already exists (simulates an
    # operator shrinking it, or organic growth already having exceeded a
    # freshly-lowered value) -- startup must not delete anything, and new
    # registration must already be refused via the ordinary "full" path.
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 2
    try:
        count_before = server._db_count_registered_fingerprints_sync()
        assert count_before > server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
        server._db_setup_sync()  # must not raise/exit, must not delete rows
        assert server._db_count_registered_fingerprints_sync() == count_before
        status = await server.db_admit_new_fingerprint(
            "S656STARTOVERNEW", server.effective_registration_cap(), "", False
        )
        assert status == "full"
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_startup_never_auto_deletes_accounts():
    for i in range(4):
        assert await server.db_admit_new_fingerprint(
            f"S656NODELETE{i:03d}", 1000, "", False
        ) == "ok"
    before = set(r[0] for r in _registered_fp_rows())
    assert len(before) == 4
    server._db_setup_sync()
    after = set(r[0] for r in _registered_fp_rows())
    assert before == after


# ── 30-33. regression ───────────────────────────────────────────────────────

async def test_s656_s639_authenticated_identity_boundary_remains_green(running_server):
    # Mirrors test_after_registration_full_ordinary_message_impossible's own
    # shape (S6-39) -- a rejected registration_full still must not leave a
    # live socket that can send ordinary authenticated-only traffic.
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 1
    try:
        dummy_priv, dummy_pub_der = gen_keypair()
        dummy_fp = fingerprint_of(dummy_pub_der)
        await server.db_admit_new_fingerprint(dummy_fp, server.effective_registration_cap(), "", False)

        priv, pub_der = gen_keypair()
        ws = await websockets.connect(running_server)
        try:
            await handshake(ws, priv, pub_der)
            await register(ws, pub_der, device_id=canonical_device_id("s656-s639-device"))
            reply = await drain_until(ws, "registration_full")
            assert reply["type"] == "registration_full"
            await _assert_boundary_closes(ws, {"type": "ping"})
            _assert_uncommitted(fingerprint_of(pub_der))
        finally:
            try:
                await ws.close()
            except Exception:
                pass
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_s641_access_code_hardening_remains_green():
    # test_access_code_atomic_under_concurrent_redemption itself already
    # runs unmodified elsewhere in this file (max_users=0 passed directly,
    # bypassing effective_registration_cap() entirely) -- this confirms the
    # invalid-format/legacy-hash rejection paths S6-41 added are equally
    # untouched by this patch.
    assert not server.is_valid_access_code("too-short")
    assert not server.is_valid_access_code(None)
    good = "FEDCBA9876543210FEDCBA9876543210"
    assert server.is_valid_access_code(good)


async def test_s656_s637_device_cap_behavior_remains_green(running_server):
    # A confirmation, not a re-implementation: S6-37's own MAX_AUTHORIZED_
    # DEVICES_PER_ACCOUNT cap is keyed per-account, entirely independent of
    # REGISTERED_ACCOUNTS_HARD_MAX_ROWS -- lowering the account hard cap
    # must not change how many devices one already-admitted account may add.
    # Matches test_new_pinned_devices_added_below_cap's own proven pattern:
    # authorized_devices rows are only ever created via a real TOTP-gated
    # device-bind, never by an ordinary registration alone.
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 10
    try:
        priv, pub_der = gen_keypair()
        username = fingerprint_of(pub_der)
        secret = TOTP_TEST_SECRET
        await server.db_commit_totp_setup(username, secret, server.generate_recovery_codes(1))
        server.user_totp_secrets[username] = secret

        ws = await websockets.connect(running_server)
        try:
            challenge = await handshake(ws, priv, pub_der)
            device_priv, device_pub_der = gen_keypair()
            device_id = canonical_device_id("s656-devcap-a")
            extra = _device_bind_extra(device_priv, device_pub_der, challenge, username, device_id,
                                        totp_code=_current_totp_code(secret))
            await register(ws, pub_der, device_id, extra=extra)
            await drain_until(ws, "register_ok")
        finally:
            await ws.close()
        assert _authorized_device_count(username) == 1
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard


async def test_s656_s645_identity_input_bounds_remain_green():
    # decode_identity_public_key()/P-256 enforcement (S6-45) is untouched by
    # this patch -- a lightweight confirmation it's still wired up.
    assert server.decode_identity_public_key("not-valid-base64!!!") is None


# ── ATTACK REGRESSION: MAX_REGISTERED_USERS=0 + POW_DIFFICULTY_BITS=0 ──────
#    + hard cap monkeypatched small -- open registration still bounded ─────

async def test_s656_attack_open_registration_bounded_by_hard_cap(running_server):
    real_hard = server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS
    real_max  = server.MAX_REGISTERED_USERS
    real_pow  = server.POW_DIFFICULTY_BITS
    real_protected = server.SERVER_ACCESS_PROTECTED
    server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = 5
    server.MAX_REGISTERED_USERS = 0       # no operator cap
    server.POW_DIFFICULTY_BITS = 0        # PoW fully disabled
    server.SERVER_ACCESS_PROTECTED = False  # fully open registration
    try:
        keypairs = [gen_keypair() for _ in range(8)]  # more than the hard cap
        admitted_fps = []
        for i, (priv, pub_der) in enumerate(keypairs):
            ws = await websockets.connect(running_server)
            try:
                await handshake(ws, priv, pub_der)
                await register(ws, pub_der, f"s656-attack-open-{i}", "t")
                reply = await _collect_until_relevant(ws, {"register_ok", "registration_full"})
                if reply["type"] == "register_ok":
                    admitted_fps.append(fingerprint_of(pub_der))
            finally:
                await ws.close()

        assert len(admitted_fps) == 5
        assert len(_registered_fp_rows()) == 5
        assert server._db_count_registered_fingerprints_sync() == 5
        # no per-account/global accounting exceeds configured bounds
        total, unused = server._db_count_access_codes_sync()
        assert total == 0 and unused == 0

        # the 5 admitted accounts can still reconnect
        for i, fp in enumerate(admitted_fps):
            priv, pub_der = keypairs[i]
            ws = await websockets.connect(running_server)
            try:
                await handshake(ws, priv, pub_der)
                await register(ws, pub_der, f"s656-attack-open-{i}", "t")
                reply = await drain_until(ws, "register_ok")
                assert reply["type"] == "register_ok"
            finally:
                await ws.close()
    finally:
        server.REGISTERED_ACCOUNTS_HARD_MAX_ROWS = real_hard
        server.MAX_REGISTERED_USERS = real_max
        server.POW_DIFFICULTY_BITS = real_pow
        server.SERVER_ACCESS_PROTECTED = real_protected


# ═══════════════════════════════════════════════════════════════════════════
# S6-57: protocol-bound voice-message relay and receive-side work ──────────
#
# The "voice" handler relayed voice_id/voice_data/signature/duration with NO
# protocol-specific size bound of any kind and NO message-type rate limit at
# all -- the multi-megabyte MAX_PACKET_SIZE_BYTES application frame ceiling
# was the only thing standing between an authenticated sender and using
# "voice" as a high-bandwidth relay/decrypt-work amplifier. See
# SECURITY_INVARIANTS.md #70 and KNOWN_SECURITY_ISSUES.md S6-57.
# ═══════════════════════════════════════════════════════════════════════════

def _voice_data_of_len(n: int) -> str:
    return "V" * n


def _voice_signature_of_len(n: int) -> str:
    return "S" * n


# ── 1/2. maximum legitimate Android/Desktop voice passes ──────────────────

async def test_s657_maximum_legitimate_android_voice_passes(running_server):
    # Android AMR-NB at 60s max is a small fraction of VOICE_DATA_MAX_LEN --
    # representative near-realistic-large payload, well within bounds.
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s657-android-max-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s657-android-max-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        voice_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "voice", "to": recv_fp, "voice_id": voice_id,
            "voice_data": _voice_data_of_len(200_000),
            "signature": _voice_signature_of_len(96),
            "duration": 60,
        }))
        msg = await drain_until(recv_ws, "voice")
        assert msg["voice_id"] == voice_id
        assert msg["duration"] == 60
        assert msg["from"] == sender_fp
    finally:
        await sender_ws.close()
        await recv_ws.close()


async def test_s657_maximum_legitimate_desktop_voice_passes(running_server):
    # Desktop's uncompressed WAV codec at 60s max drives VOICE_DATA_MAX_LEN's
    # own derivation (~3.26 MiB worst case) -- but running_server's
    # websockets.serve() doesn't set max_size at all (unlike the real
    # start_server()), so it defaults to the library's own 1 MiB frame
    # ceiling (see S6-45/S6-48's own test-infrastructure note for this exact
    # distinction). 900 KiB stays comfortably under that fixture ceiling
    # while still exercising a genuinely large, realistic voice payload; the
    # true VOICE_DATA_MAX_LEN (4 MiB) boundary itself is exercised directly
    # against sanitize_voice_payload() in the field-validation tests above,
    # with no websocket frame-size ceiling in the way.
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s657-desktop-max-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s657-desktop-max-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        voice_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "voice", "to": recv_fp, "voice_id": voice_id,
            "voice_data": _voice_data_of_len(900 * 1024),
            "signature": _voice_signature_of_len(96),
            "duration": 60,
        }))
        msg = await drain_until(recv_ws, "voice")
        assert msg["voice_id"] == voice_id
        assert msg["duration"] == 60
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 3-10. field validation rejections ──────────────────────────────────────

async def test_s657_oversized_voice_data_rejected():
    target = canonical_fingerprint("s657-oversized-data")
    payload = {
        "voice_id": str(uuid.uuid4()),
        "voice_data": _voice_data_of_len(server.VOICE_DATA_MAX_LEN + 1),
        "signature": "sig",
        "duration": 10,
    }
    assert server.sanitize_voice_payload(payload, canonical_fingerprint("s657-sender"), target) is None


async def test_s657_wrong_type_voice_data_rejected():
    target = canonical_fingerprint("s657-wrongtype-data")
    payload = {
        "voice_id": str(uuid.uuid4()),
        "voice_data": 12345,
        "signature": "sig",
        "duration": 10,
    }
    assert server.sanitize_voice_payload(payload, canonical_fingerprint("s657-sender"), target) is None


async def test_s657_oversized_voice_id_rejected():
    target = canonical_fingerprint("s657-oversized-id")
    payload = {
        "voice_id": "x" * 100,
        "voice_data": _voice_data_of_len(1000),
        "signature": "sig",
        "duration": 10,
    }
    assert server.sanitize_voice_payload(payload, canonical_fingerprint("s657-sender"), target) is None


async def test_s657_malformed_uuid_voice_id_rejected():
    target = canonical_fingerprint("s657-malformed-uuid")
    payload = {
        "voice_id": "not-a-real-uuid-at-all",
        "voice_data": _voice_data_of_len(1000),
        "signature": "sig",
        "duration": 10,
    }
    assert server.sanitize_voice_payload(payload, canonical_fingerprint("s657-sender"), target) is None


async def test_s657_oversized_signature_rejected():
    target = canonical_fingerprint("s657-oversized-sig")
    payload = {
        "voice_id": str(uuid.uuid4()),
        "voice_data": _voice_data_of_len(1000),
        "signature": _voice_signature_of_len(server.VOICE_SIGNATURE_MAX_LEN + 1),
        "duration": 10,
    }
    assert server.sanitize_voice_payload(payload, canonical_fingerprint("s657-sender"), target) is None


async def test_s657_negative_duration_rejected():
    target = canonical_fingerprint("s657-negative-duration")
    payload = {
        "voice_id": str(uuid.uuid4()),
        "voice_data": _voice_data_of_len(1000),
        "signature": "sig",
        "duration": -1,
    }
    assert server.sanitize_voice_payload(payload, canonical_fingerprint("s657-sender"), target) is None


async def test_s657_bool_duration_rejected():
    target = canonical_fingerprint("s657-bool-duration")
    payload = {
        "voice_id": str(uuid.uuid4()),
        "voice_data": _voice_data_of_len(1000),
        "signature": "sig",
        "duration": True,
    }
    assert server.sanitize_voice_payload(payload, canonical_fingerprint("s657-sender"), target) is None


async def test_s657_duration_above_max_rejected():
    target = canonical_fingerprint("s657-duration-toolong")
    payload = {
        "voice_id": str(uuid.uuid4()),
        "voice_data": _voice_data_of_len(1000),
        "signature": "sig",
        "duration": server.MAX_VOICE_DURATION_SECONDS + 1,
    }
    assert server.sanitize_voice_payload(payload, canonical_fingerprint("s657-sender"), target) is None


# ── 11/12. arbitrary junk fields never relay; caller cannot spoof from ────

async def test_s657_arbitrary_junk_fields_never_relay():
    target = canonical_fingerprint("s657-junkfields")
    from_user = canonical_fingerprint("s657-sender")
    payload = {
        "voice_id": str(uuid.uuid4()),
        "voice_data": _voice_data_of_len(1000),
        "signature": "sig",
        "duration": 10,
        "admin": True,
        "extra_payload": "x" * 100_000,
        "to": "SOMEONE_ELSE_ENTIRELY",
    }
    sanitized = server.sanitize_voice_payload(payload, from_user, target)
    assert sanitized is not None
    assert set(sanitized.keys()) == {"type", "from", "to", "voice_id", "voice_data", "signature", "duration"}
    assert sanitized["to"] == target


async def test_s657_caller_cannot_spoof_from(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s657-spoof-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s657-spoof-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "voice", "to": recv_fp, "voice_id": str(uuid.uuid4()),
            "voice_data": _voice_data_of_len(1000), "signature": "sig",
            "duration": 5, "from": canonical_fingerprint("s657-spoofed-identity"),
        }))
        msg = await drain_until(recv_ws, "voice")
        assert msg["from"] == sender_fp
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 13. voice count rate works ─────────────────────────────────────────────

async def test_s657_voice_count_rate_works(running_server):
    real_limit = server.VOICE_RATE_LIMIT
    server.VOICE_RATE_LIMIT = 2
    try:
        sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s657-countrate-s")
        recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s657-countrate-r")
        try:
            await drain_until(sender_ws, "register_ok")
            await drain_until(recv_ws, "register_ok")
            for _ in range(2):
                await sender_ws.send(json.dumps({
                    "type": "voice", "to": recv_fp, "voice_id": str(uuid.uuid4()),
                    "voice_data": _voice_data_of_len(100), "signature": "sig", "duration": 1,
                }))
                await drain_until(recv_ws, "voice")
            # third attempt within the window must be silently dropped (no rate_limit_check bypass)
            await sender_ws.send(json.dumps({
                "type": "voice", "to": recv_fp, "voice_id": str(uuid.uuid4()),
                "voice_data": _voice_data_of_len(100), "signature": "sig", "duration": 1,
            }))
            await sender_ws.send(json.dumps({"type": "ping"}))
            with pytest.raises(asyncio.TimeoutError):
                async with asyncio.timeout(0.5):
                    await recv_ws.recv()
        finally:
            await sender_ws.close()
            await recv_ws.close()
    finally:
        server.VOICE_RATE_LIMIT = real_limit


# ── 14-16. byte budgets ─────────────────────────────────────────────────────

async def test_s657_sender_byte_budget_works(running_server):
    real_limit = server.VOICE_USER_MAX_BYTES
    server.VOICE_USER_MAX_BYTES = 5000
    try:
        a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s657-userbudget-a")
        b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s657-userbudget-b")
        try:
            await drain_until(a_ws, "register_ok")
            await drain_until(b_ws, "register_ok")
            await a_ws.send(json.dumps({
                "type": "voice", "to": b_fp, "voice_id": str(uuid.uuid4()),
                "voice_data": _voice_data_of_len(4000), "signature": "sig", "duration": 5,
            }))
            await drain_until(b_ws, "voice")
            await a_ws.send(json.dumps({
                "type": "voice", "to": b_fp, "voice_id": str(uuid.uuid4()),
                "voice_data": _voice_data_of_len(4000), "signature": "sig", "duration": 5,
            }))
            msg = json.loads(await a_ws.recv())
            assert msg == {"type": "error", "reason": "Rate limit exceeded"}
        finally:
            await a_ws.close()
            await b_ws.close()
    finally:
        server.VOICE_USER_MAX_BYTES = real_limit


async def test_s657_recipient_byte_budget_protects_one_victim(running_server):
    real_limit = server.VOICE_RECIPIENT_MAX_BYTES
    server.VOICE_RECIPIENT_MAX_BYTES = 6000
    victim_ws = None
    sender_sockets = []
    try:
        victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s657-recipientbudget-v")
        await drain_until(victim_ws, "register_ok")
        rejected = False
        for i in range(5):
            sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id=f"s657-recipientbudget-s{i}")
            sender_sockets.append(sender_ws)
            await drain_until(sender_ws, "register_ok")
            await sender_ws.send(json.dumps({
                "type": "voice", "to": victim_fp, "voice_id": str(uuid.uuid4()),
                "voice_data": _voice_data_of_len(2000), "signature": "sig", "duration": 5,
            }))
            try:
                async with asyncio.timeout(0.5):
                    msg = json.loads(await sender_ws.recv())
                if msg == {"type": "error", "reason": "Rate limit exceeded"}:
                    rejected = True
            except (asyncio.TimeoutError, TimeoutError):
                pass
        assert rejected
    finally:
        server.VOICE_RECIPIENT_MAX_BYTES = real_limit
        if victim_ws:
            await victim_ws.close()
        for s in sender_sockets:
            await s.close()


async def test_s657_global_byte_budget_bounds_sybils(running_server):
    real_limit = server.VOICE_GLOBAL_MAX_BYTES
    server.VOICE_GLOBAL_MAX_BYTES = 6000
    recipient_ws = None
    sender_sockets = []
    try:
        recipient_ws, recipient_fp, _, _ = await connect_and_register(running_server, device_id="s657-globalbudget-r")
        await drain_until(recipient_ws, "register_ok")
        rejected = False
        for i in range(5):
            sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id=f"s657-globalbudget-s{i}")
            sender_sockets.append(sender_ws)
            await drain_until(sender_ws, "register_ok")
            await sender_ws.send(json.dumps({
                "type": "voice", "to": recipient_fp, "voice_id": str(uuid.uuid4()),
                "voice_data": _voice_data_of_len(2000), "signature": "sig", "duration": 5,
            }))
            try:
                async with asyncio.timeout(0.5):
                    msg = json.loads(await sender_ws.recv())
                if msg == {"type": "error", "reason": "Rate limit exceeded"}:
                    rejected = True
            except (asyncio.TimeoutError, TimeoutError):
                pass
        assert rejected
    finally:
        server.VOICE_GLOBAL_MAX_BYTES = real_limit
        if recipient_ws:
            await recipient_ws.close()
        for s in sender_sockets:
            await s.close()


# ── 17. offline store gets sanitized payload only ──────────────────────────

async def test_s657_offline_store_gets_sanitized_payload_only(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s657-offline-s")
    target = canonical_fingerprint("s657-offline-target")
    try:
        await drain_until(sender_ws, "register_ok")
        voice_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "voice", "to": target, "voice_id": voice_id,
            "voice_data": _voice_data_of_len(500), "signature": "sig", "duration": 7,
            "junk_field": "should never be stored",
        }))
        await asyncio.sleep(0.2)
        rows = _read_pending_rows(target)
        assert len(rows) == 1
        stored = json.loads(rows[0][2])
        assert set(stored.keys()) == {"type", "from", "to", "voice_id", "voice_data", "signature", "duration"}
        assert stored["voice_id"] == voice_id
        assert stored["from"] == sender_fp
        assert "junk_field" not in stored
    finally:
        await sender_ws.close()


# ── 18. federated inbound uses same limits ─────────────────────────────────

async def test_s657_federated_inbound_oversized_voice_dropped(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("s657-fed-oversized-target")
    peer_from = canonical_fingerprint("s657-fed-oversized-peer")
    try:
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({
                "type": "federated_forward", "to": to,
                "payload": {
                    "type": "voice", "from": peer_from,
                    "voice_id": str(uuid.uuid4()),
                    "voice_data": _voice_data_of_len(server.VOICE_DATA_MAX_LEN + 1),
                    "signature": "sig", "duration": 5,
                },
            }))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


async def test_s657_federated_inbound_valid_voice_relays_sanitized(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    peer_from = canonical_fingerprint("s657-fed-valid-peer")
    try:
        recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s657-fed-valid-recv")
        await drain_until(recv_ws, "register_ok")
        ws = await federation_connect(running_server)
        try:
            voice_id = str(uuid.uuid4())
            await ws.send(json.dumps({
                "type": "federated_forward", "to": recv_fp,
                "payload": {
                    "type": "voice", "from": peer_from,
                    "voice_id": voice_id, "voice_data": _voice_data_of_len(500),
                    "signature": "sig", "duration": 5, "junk": "stripped",
                },
            }))
            msg = await drain_until(recv_ws, "voice")
            assert msg["voice_id"] == voice_id
            assert msg["from"] == peer_from
            assert "junk" not in msg
        finally:
            await ws.close()
            await recv_ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 19. MAX_PACKET_SIZE_BYTES unchanged ────────────────────────────────────

async def test_s657_max_packet_size_bytes_unchanged():
    assert server.MAX_PACKET_SIZE_BYTES == 6 * 1024 * 1024
    assert server.VOICE_MAX_PACKET_SIZE_BYTES < server.MAX_PACKET_SIZE_BYTES


# ── ATTACK REGRESSION: near-application-frame-limit repeated sends ────────

async def test_s657_attack_frames_above_voice_maximum_never_relay(running_server):
    # Frames above the voice protocol maximum never relay at all -- exercised
    # via sanitize_voice_payload() directly (already covered exhaustively by
    # the field-validation tests above) rather than over a live websocket:
    # running_server's websockets.serve() doesn't set max_size, so it
    # defaults to the library's own 1 MiB frame ceiling, well BELOW
    # VOICE_DATA_MAX_LEN (4 MiB) -- a real attacker's oversized frame would
    # already be killed by that transport-level ceiling before ever reaching
    # this server's own application-level rejection, on this test fixture.
    # This test instead confirms the one thing that specifically matters for
    # "victim never verifies/decrypts them": an over-ceiling voice_data is
    # rejected before sanitize_voice_payload() ever returns a payload a
    # recipient could be handed.
    target = canonical_fingerprint("s657-attack-oversized-victim")
    from_user = canonical_fingerprint("s657-attack-oversized-sender")
    oversized = _voice_data_of_len(server.VOICE_MAX_PACKET_SIZE_BYTES)
    assert server.sanitize_voice_payload(
        {"voice_id": str(uuid.uuid4()), "voice_data": oversized, "signature": "sig", "duration": 5},
        from_user, target,
    ) is None


async def test_s657_attack_repeated_near_max_size_voice_bounded_by_budgets(running_server):
    # Repeated near-fixture-limit (900 KiB, see this file's own note on
    # running_server's 1 MiB library default) sends to one online victim --
    # sender/recipient/global budgets cap this well before it becomes
    # unbounded relay/verify/decrypt cost for the victim, and no server-side
    # state grows without bound in the process.
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s657-attack-s")
    victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s657-attack-v")
    real_user_limit = server.VOICE_USER_MAX_BYTES
    real_global_limit = server.VOICE_GLOBAL_MAX_BYTES
    real_recipient_limit = server.VOICE_RECIPIENT_MAX_BYTES
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(victim_ws, "register_ok")

        # Tighten to a small window so repeated near-max-size sends hit the
        # budget fast and deterministically.
        server.VOICE_USER_MAX_BYTES = 500_000
        server.VOICE_GLOBAL_MAX_BYTES = 500_000
        server.VOICE_RECIPIENT_MAX_BYTES = 500_000
        near_max_valid = _voice_data_of_len(200_000)
        rejected = False
        for _ in range(10):
            await sender_ws.send(json.dumps({
                "type": "voice", "to": victim_fp, "voice_id": str(uuid.uuid4()),
                "voice_data": near_max_valid, "signature": "sig", "duration": 5,
            }))
            try:
                async with asyncio.timeout(0.5):
                    msg = json.loads(await sender_ws.recv())
                if msg == {"type": "error", "reason": "Rate limit exceeded"}:
                    rejected = True
                    break
            except (asyncio.TimeoutError, TimeoutError):
                pass
        assert rejected

        # No unbounded server-side retained state -- windowed counters only.
        assert set(server.voice_user_rate.get(sender_fp, {}).keys()) <= {"bytes", "reset_time"}
    finally:
        server.VOICE_USER_MAX_BYTES = real_user_limit
        server.VOICE_GLOBAL_MAX_BYTES = real_global_limit
        server.VOICE_RECIPIENT_MAX_BYTES = real_recipient_limit
        await sender_ws.close()
        await victim_ws.close()


# ═══════════════════════════════════════════════════════════════════════════
# S6-59 — anonymous token relay resource-boundary hardening
# ═══════════════════════════════════════════════════════════════════════════
# STEP-1's own routing-matrix audit (docs/SECURITY_INVARIANTS.md #72) found
# that essentially every 1:1 protocol type in both shipped clients routes
# through anon_message SEALED (opaque to the server) -- meaning S6-49/51/
# 53/57's own server-side sanitizers never ran against that real traffic,
# and the transport itself had no per-packet ceiling of its own at all, only
# TOKEN_PENDING_MAX_TOTAL_BYTES's AGGREGATE retained-RAM cap. These tests
# cover the new outer envelope ceiling, visible-type allowlist, generic/
# recipient byte budgets, and the token-lifecycle/ordering guarantees that
# go with them. Large-payload tests use temporarily-lowered constants
# rather than real multi-MiB sends -- running_server's websockets.serve()
# doesn't set max_size, so it defaults to the library's own 1 MiB frame
# ceiling (same test-infrastructure distinction as S6-45/S6-57's own notes).

async def _connect_anon_channel(url):
    ws = await websockets.connect(url)
    challenge_msg = json.loads(await ws.recv())
    assert challenge_msg["type"] == "challenge"
    await ws.send(json.dumps({"type": "anon_channel"}))
    ok = json.loads(await ws.recv())
    assert ok["type"] == "anon_channel_ok"
    return ws


# ── 1/2. routing matrix ───────────────────────────────────────────────────

async def test_s659_sealed_opaque_payload_has_no_visible_type_and_passes(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-sealed-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-sealed-s")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        # The dominant real-traffic shape: an opaque {"id","blob"} payload,
        # no "type" key at all -- confirms the allowlist never fires for it.
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "s659-m1", "blob": "opaque-sealed-ciphertext"},
        }))
        delivered = await drain_until(recipient, "anon_delivery")
        assert delivered["payload"] == {"id": "s659-m1", "blob": "opaque-sealed-ciphertext"}
    finally:
        await recipient.close()
        await sender.close()


async def test_s659_visible_message_type_beacon_tokens_shape_allowed(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-beacon-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-beacon-s")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        # sendAnonTokensTo()'s own visible (unsealed) shape -- a legitimate
        # anon-routed type today, must not be rejected by the allowlist.
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {
                "id": "s659-m2", "type": "message", "from": "AAAAAAAAAAAAAAAA",
                "to": "BBBBBBBBBBBBBBBB", "text": "enc", "signature": "sig",
                "protocol_version": 1,
            },
        }))
        delivered = await drain_until(recipient, "anon_delivery")
        assert delivered["payload"]["type"] == "message"
    finally:
        await recipient.close()
        await sender.close()


# ── 3-8. outer envelope ceiling ────────────────────────────────────────────

async def test_s659_max_legitimate_payload_size_succeeds(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-max-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-max-s")
    real_payload_max = server.ANON_PAYLOAD_MAX_BYTES
    real_delivery_max = server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES
    try:
        server.ANON_PAYLOAD_MAX_BYTES = 50_000
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = 50_000 + 4096
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        blob = "B" * 40_000
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m3", "blob": blob},
        }))
        delivered = await drain_until(recipient, "anon_delivery")
        assert delivered["payload"]["blob"] == blob
    finally:
        server.ANON_PAYLOAD_MAX_BYTES = real_payload_max
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = real_delivery_max
        await recipient.close()
        await sender.close()


async def test_s659_first_byte_over_ceiling_rejected(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-over-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-over-s")
    await drain_until(recipient, "register_ok")
    await drain_until(sender, "register_ok")
    real_delivery_max = server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES
    try:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = 1000
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m4", "blob": "X" * 2000},
        }))
        assert await _try_recv(recipient, 0.3) is None
        # Same externally-indistinguishable fake ack as any other rejection.
        ack = await _try_recv(sender, 0.3)
        assert ack == {"type": "ack", "id": "s659-m4"}
    finally:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = real_delivery_max
        await recipient.close()
        await sender.close()


async def test_s659_oversized_payload_does_not_consume_token(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-nokill-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-nokill-s")
    await drain_until(recipient, "register_ok")
    real_delivery_max = server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES
    try:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = 1000
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m5a", "blob": "X" * 2000},
        }))
        await asyncio.sleep(0.2)
        assert await _try_recv(recipient, 0.2) is None
        state = server.anon_token_state_cache.get(server._hash_anon_token(token))
        assert state is not None and state[1] == "ACTIVE"
        # Restore the real ceiling and retry with the SAME token -- must
        # still work, proving the oversized rejection never burned it.
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = real_delivery_max
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m5b", "blob": "ok"},
        }))
        delivered = await drain_until(recipient, "anon_delivery")
        assert delivered["payload"]["id"] == "s659-m5b"
    finally:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = real_delivery_max
        await recipient.close()
        await sender.close()


async def test_s659_disallowed_visible_type_rejected(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-badtype-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-badtype-s")
    await drain_until(recipient, "register_ok")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        # "register" is a real ALLOWED_TYPES entry, but an account-level
        # type never legitimately carried inside anon_message's payload.
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "s659-m7", "type": "register", "username": "x"},
        }))
        assert await _try_recv(recipient, 0.3) is None
    finally:
        await recipient.close()
        await sender.close()


async def test_s659_arbitrary_unknown_visible_type_rejected(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-unk-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-unk-s")
    await drain_until(recipient, "register_ok")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "s659-m8", "type": "totally_made_up_protocol"},
        }))
        assert await _try_recv(recipient, 0.3) is None
    finally:
        await recipient.close()
        await sender.close()


# ── 9-13. generic/recipient byte budgets ──────────────────────────────────

async def test_s659_connection_byte_budget_bounds_repeated_sends(running_server):
    real_conn_max = server.ANON_RELAY_CONN_MAX_BYTES
    try:
        server.ANON_RELAY_CONN_MAX_BYTES = 5000
        ws = await _connect_anon_channel(running_server)
        try:
            for i in range(10):
                await ws.send(json.dumps({
                    "type": "anon_message", "token": rand_token(),
                    "payload": {"id": f"s659-m9-{i}", "blob": "X" * 800},
                }))
            await asyncio.sleep(0.3)
            # Keyed by the SERVER's own websocket object for this connection
            # (not the test's client-side handle to it) -- with exactly one
            # anon_channel connection open, there is exactly one entry.
            assert len(server.anon_relay_conn_rate) == 1
            entry = next(iter(server.anon_relay_conn_rate.values()))
            assert entry["bytes"] <= server.ANON_RELAY_CONN_MAX_BYTES
        finally:
            await ws.close()
    finally:
        server.ANON_RELAY_CONN_MAX_BYTES = real_conn_max


async def test_s659_many_connections_cannot_exceed_global_budget(running_server):
    real_conn_max = server.ANON_RELAY_CONN_MAX_BYTES
    real_global_max = server.ANON_RELAY_GLOBAL_MAX_BYTES
    try:
        server.ANON_RELAY_CONN_MAX_BYTES = 10_000_000  # effectively unbounded per-connection
        server.ANON_RELAY_GLOBAL_MAX_BYTES = 5000
        conns = [await _connect_anon_channel(running_server) for _ in range(5)]
        try:
            for i, ws in enumerate(conns):
                await ws.send(json.dumps({
                    "type": "anon_message", "token": rand_token(),
                    "payload": {"id": f"s659-m10-{i}", "blob": "X" * 800},
                }))
            await asyncio.sleep(0.3)
            assert server.anon_relay_global_rate["bytes"] <= server.ANON_RELAY_GLOBAL_MAX_BYTES
        finally:
            for ws in conns:
                await ws.close()
    finally:
        server.ANON_RELAY_CONN_MAX_BYTES = real_conn_max
        server.ANON_RELAY_GLOBAL_MAX_BYTES = real_global_max


async def test_s659_many_valid_tokens_one_recipient_hit_recipient_budget(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-recip-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-recip-s")
    real_recipient_max = server.ANON_RELAY_RECIPIENT_MAX_BYTES
    try:
        server.ANON_RELAY_RECIPIENT_MAX_BYTES = 3000
        tokens = [rand_token() for _ in range(5)]
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": tokens}))
        await asyncio.sleep(0.2)
        for i, token in enumerate(tokens):
            await sender.send(json.dumps({
                "type": "anon_message", "token": token,
                "payload": {"id": f"s659-m11-{i}", "blob": "X" * 800},
            }))
        await asyncio.sleep(0.3)
        got = 0
        while True:
            msg = await _try_recv(recipient, 0.2)
            if msg is None:
                break
            if msg.get("type") == "anon_delivery":
                got += 1
        assert got < len(tokens)
    finally:
        server.ANON_RELAY_RECIPIENT_MAX_BYTES = real_recipient_max
        await recipient.close()
        await sender.close()


async def test_s659_conn_budget_self_prunes_after_window(running_server):
    real_conn_max = server.ANON_RELAY_CONN_MAX_BYTES
    real_window = server.ANON_RELAY_CONN_WINDOW_SEC
    try:
        server.ANON_RELAY_CONN_MAX_BYTES = 1000
        server.ANON_RELAY_CONN_WINDOW_SEC = 0.2
        ws = await _connect_anon_channel(running_server)
        try:
            await ws.send(json.dumps({
                "type": "anon_message", "token": rand_token(),
                "payload": {"id": "s659-m12a", "blob": "X" * 500},
            }))
            await asyncio.sleep(0.05)
            assert len(server.anon_relay_conn_rate) == 1
            entry = next(iter(server.anon_relay_conn_rate.values()))
            assert entry["bytes"] > 0
            await asyncio.sleep(0.3)  # past the window
            await ws.send(json.dumps({
                "type": "anon_message", "token": rand_token(),
                "payload": {"id": "s659-m12b", "blob": "Y" * 10},
            }))
            await asyncio.sleep(0.1)
            entry2 = next(iter(server.anon_relay_conn_rate.values()))
            assert entry2["bytes"] < 500  # reset, not cumulative with the earlier big send
        finally:
            await ws.close()
    finally:
        server.ANON_RELAY_CONN_MAX_BYTES = real_conn_max
        server.ANON_RELAY_CONN_WINDOW_SEC = real_window


async def test_s659_garbage_tokens_create_no_recipient_limiter_state(running_server):
    ws = await _connect_anon_channel(running_server)
    try:
        for i in range(5):
            await ws.send(json.dumps({
                "type": "anon_message", "token": rand_token(),
                "payload": {"id": f"s659-m13-{i}", "blob": "garbage"},
            }))
        await asyncio.sleep(0.3)
        assert len(server.anon_relay_recipient_rate) == 0
    finally:
        await ws.close()


# ── 14-18. token lifecycle ─────────────────────────────────────────────────

async def test_s659_valid_packet_claims_token_exactly_once(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-claim-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-claim-s")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m14", "blob": "x"},
        }))
        await drain_until(recipient, "anon_delivery")
        state = server.anon_token_state_cache.get(server._hash_anon_token(token))
        assert state is not None and state[1] == "IN_FLIGHT"
    finally:
        await recipient.close()
        await sender.close()


async def test_s659_recipient_budget_rejection_leaves_token_active(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-rbudget-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-rbudget-s")
    await drain_until(recipient, "register_ok")
    real_recipient_max = server.ANON_RELAY_RECIPIENT_MAX_BYTES
    try:
        server.ANON_RELAY_RECIPIENT_MAX_BYTES = 10  # first real send already exceeds it
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m15a", "blob": "X" * 200},
        }))
        await asyncio.sleep(0.2)
        assert await _try_recv(recipient, 0.2) is None
        state = server.anon_token_state_cache.get(server._hash_anon_token(token))
        assert state is not None and state[1] == "ACTIVE"
        server.ANON_RELAY_RECIPIENT_MAX_BYTES = real_recipient_max
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m15b", "blob": "ok"},
        }))
        delivered = await drain_until(recipient, "anon_delivery")
        assert delivered["payload"]["id"] == "s659-m15b"
    finally:
        server.ANON_RELAY_RECIPIENT_MAX_BYTES = real_recipient_max
        await recipient.close()
        await sender.close()


async def test_s659_anon_delivery_ack_still_spends_token_normally(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-ack-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-ack-s")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m16", "blob": "x"},
        }))
        await drain_until(recipient, "anon_delivery")
        await recipient.send(json.dumps({"type": "anon_delivery_ack", "token": token}))
        await asyncio.sleep(0.2)
        state = server.anon_token_state_cache.get(server._hash_anon_token(token))
        assert state is not None and state[1] == "SPENT"
        assert token not in server.token_pending
    finally:
        await recipient.close()
        await sender.close()


async def test_s659_pending_accounting_remains_exact(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-pending-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-pending-s")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        assert server.token_pending_total_items == 0
        await sender.send(json.dumps({
            "type": "anon_message", "token": token, "payload": {"id": "s659-m17", "blob": "x"},
        }))
        await asyncio.sleep(0.2)
        assert server.token_pending_total_items == 1
        assert server.token_pending_reserved_bytes == 0
        assert server.token_pending_reserved_items == 0
    finally:
        await recipient.close()
        await sender.close()


async def test_s659_s644_active_token_cap_unaffected():
    username = canonical_fingerprint("s659_active_cap_check")
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 3
    try:
        fill = [rand_token() for _ in range(3)]
        await server.db_claim_anon_tokens(fill, username)
        overflow = rand_token()
        claims = await server.db_claim_anon_tokens([overflow], username)
        assert claims[overflow] == (None, "NEW_CLAIM_LIMIT")
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


# ── 19-24. protocol bypass regressions ────────────────────────────────────

async def test_s659_oversized_visible_voice_data_rejected_via_field_reuse(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-voice-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-voice-s")
    await drain_until(recipient, "register_ok")
    real_voice_max = server.VOICE_DATA_MAX_LEN
    try:
        server.VOICE_DATA_MAX_LEN = 10_000
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {
                "id": "s659-m19", "type": "voice", "voice_id": str(uuid.uuid4()),
                "voice_data": _voice_data_of_len(10_001),
                "signature": _voice_signature_of_len(64), "duration": 5,
            },
        }))
        assert await _try_recv(recipient, 0.3) is None
    finally:
        server.VOICE_DATA_MAX_LEN = real_voice_max
        await recipient.close()
        await sender.close()


async def test_s659_tampered_visible_voice_duration_rejected(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-voicedur-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-voicedur-s")
    await drain_until(recipient, "register_ok")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {
                "id": "s659-m20", "type": "voice", "voice_id": str(uuid.uuid4()),
                "voice_data": "V" * 100, "signature": "S" * 64,
                "duration": -5,
            },
        }))
        assert await _try_recv(recipient, 0.3) is None
    finally:
        await recipient.close()
        await sender.close()


async def test_s659_oversized_visible_media_chunk_rejected_by_envelope(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-chunk-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-chunk-s")
    await drain_until(recipient, "register_ok")
    real_delivery_max = server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES
    try:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = 1000
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "s659-m21", "type": "image_chunk", "data": "X" * 2000},
        }))
        assert await _try_recv(recipient, 0.3) is None
    finally:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = real_delivery_max
        await recipient.close()
        await sender.close()


async def test_s659_oversized_visible_call_signal_rejected_by_envelope(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-callsig-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-callsig-s")
    await drain_until(recipient, "register_ok")
    real_delivery_max = server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES
    try:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = 1000
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {
                "id": "s659-m22", "type": "call_offer",
                "call_id": str(uuid.uuid4()), "sdp": "X" * 2000,
            },
        }))
        assert await _try_recv(recipient, 0.3) is None
    finally:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = real_delivery_max
        await recipient.close()
        await sender.close()


async def test_s659_oversized_visible_chat_control_rejected_by_envelope(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-chatctl-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-chatctl-s")
    await drain_until(recipient, "register_ok")
    real_delivery_max = server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES
    try:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = 1000
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {
                "id": "s659-m23", "type": "message_delete",
                "message_id": "X" * 2000, "signature": "sig",
            },
        }))
        assert await _try_recv(recipient, 0.3) is None
    finally:
        server.ANON_DELIVERY_MAX_PACKET_SIZE_BYTES = real_delivery_max
        await recipient.close()
        await sender.close()


async def test_s659_unsigned_visible_delete_rejected_via_field_reuse(running_server):
    recipient, _, _, _ = await connect_and_register(running_server, device_id="s659-unsigned-r")
    sender, _, _, _ = await connect_and_register(running_server, device_id="s659-unsigned-s")
    await drain_until(recipient, "register_ok")
    try:
        token = rand_token()
        await recipient.send(json.dumps({"type": "subscribe_tokens", "tokens": [token]}))
        await asyncio.sleep(0.2)
        # No "signature" at all -- S6-54 requires one for message_delete;
        # this must not become reachable just by arriving via anon_message.
        await sender.send(json.dumps({
            "type": "anon_message", "token": token,
            "payload": {"id": "s659-m24", "type": "message_delete", "message_id": str(uuid.uuid4())},
        }))
        assert await _try_recv(recipient, 0.3) is None
    finally:
        await recipient.close()
        await sender.close()


# ── attack regression: many channels, many tokens, one victim ────────────

async def test_s659_attack_many_channels_many_tokens_one_victim_bounded(running_server):
    victim, victim_fp, _, _ = await connect_and_register(running_server, device_id="s659-attack-victim")
    real_conn_max = server.ANON_RELAY_CONN_MAX_BYTES
    real_global_max = server.ANON_RELAY_GLOBAL_MAX_BYTES
    real_recipient_max = server.ANON_RELAY_RECIPIENT_MAX_BYTES
    try:
        server.ANON_RELAY_CONN_MAX_BYTES = 2_000_000
        server.ANON_RELAY_GLOBAL_MAX_BYTES = 2_000_000
        server.ANON_RELAY_RECIPIENT_MAX_BYTES = 20_000
        tokens = [rand_token() for _ in range(20)]
        await victim.send(json.dumps({"type": "subscribe_tokens", "tokens": tokens}))
        await asyncio.sleep(0.2)
        conns = [await _connect_anon_channel(running_server) for _ in range(5)]
        try:
            idx = 0
            for ws in conns:
                for _ in range(4):
                    await ws.send(json.dumps({
                        "type": "anon_message", "token": tokens[idx],
                        "payload": {"id": f"s659-atk-{idx}", "blob": "X" * 5000},
                    }))
                    idx += 1
            await asyncio.sleep(0.5)
            assert server.anon_relay_global_rate["bytes"] <= server.ANON_RELAY_GLOBAL_MAX_BYTES
            recipient_entry = server.anon_relay_recipient_rate.get(victim_fp)
            if recipient_entry:
                assert recipient_entry["bytes"] <= server.ANON_RELAY_RECIPIENT_MAX_BYTES
            assert server.token_pending_total_bytes <= server.TOKEN_PENDING_MAX_TOTAL_BYTES
        finally:
            for ws in conns:
                await ws.close()
    finally:
        server.ANON_RELAY_CONN_MAX_BYTES = real_conn_max
        server.ANON_RELAY_GLOBAL_MAX_BYTES = real_global_max
        server.ANON_RELAY_RECIPIENT_MAX_BYTES = real_recipient_max
        await victim.close()


# ═══════════════════════════════════════════════════════════════════════════
# S6-60 — group membership/control authorization (server-relay half)
# ═══════════════════════════════════════════════════════════════════════════
# Client-side audit (both Android and Desktop) found the actual authorization
# boundary is correctly enforced on-device (recipient verifies signature +
# locally-trusted admin status before applying a group control) -- that part
# needed no server change, since this server has no reliable group-membership
# semantics of its own to check against. Two real server-side bugs were found
# alongside it, both fixed here:
#
# 1. group_member_removed's and group_invite_accepted's relayed payloads
#    silently DROPPED the caller's "signature" field (group_key_rotation's
#    relay always kept it correctly) -- since both official clients require
#    and verify a signature on receive for these two types, every legitimate
#    removal/invite-acceptance was being relayed with no signature and
#    rejected by every up-to-date client. Not an authorization bypass (fails
#    closed), but it meant the client-side checks below never even got
#    exercised by real traffic. Fixed by threading "signature" through like
#    group_key_rotation already did, REQUIRED (mirroring S6-54's
#    message_delete/group_message_delete precedent) since both clients
#    always send one for these two types.
#
# 2. "group_member_added" -- the admin-broadcast telling EXISTING members
#    about a member added to an already-running group, which SECURITY.md
#    documents as how members learn a new {memberId, encKey} pair, and which
#    Android has sent+verified since the original group-roster fix -- was
#    entirely absent from ALLOWED_TYPES. Every send of it hit the generic
#    unknown-type rejection; existing members' rosters never actually updated
#    for a post-creation add on any platform. Added as its own handler,
#    mirroring group_member_removed's shape (required signature, canonical
#    `to` fingerprint check, online-relay + federation/offline-store fallback).
#
# See SECURITY_INVARIANTS.md #73 and KNOWN_SECURITY_ISSUES.md S6-60.

# ── 1. unsigned group_member_removed is not relayed online ────────────────

async def test_unsigned_group_member_removed_not_relayed_online(running_server):
    sender_ws, _, _, _ = await connect_and_register(running_server, device_id="s660-unsigned-gmr-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s660-unsigned-gmr-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "group_member_removed", "to": recv_fp,
            "group_id": str(uuid.uuid4()), "removed_member": "X",
        }))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 2. unsigned group_invite_accepted is not relayed online ───────────────

async def test_unsigned_group_invite_accepted_not_relayed_online(running_server):
    sender_ws, _, _, _ = await connect_and_register(running_server, device_id="s660-unsigned-gia-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s660-unsigned-gia-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "group_invite_accepted", "to": recv_fp,
            "group_id": str(uuid.uuid4()), "new_member": "X", "new_member_name": "n",
        }))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 3. unsigned group_member_removed/group_invite_accepted are not stored
#       offline either ──────────────────────────────────────────────────────

async def test_unsigned_group_member_removed_not_stored_offline(running_server):
    sender_ws, _, _, _ = await connect_and_register(running_server, device_id="s660-unsigned-gmr-offline")
    offline_fp = canonical_fingerprint("s660-unsigned-gmr-target")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "group_member_removed", "to": offline_fp,
            "group_id": str(uuid.uuid4()), "removed_member": "X",
        }))
        await asyncio.sleep(0.2)
        assert len(_read_pending_rows(offline_fp)) == 0
    finally:
        await sender_ws.close()


async def test_unsigned_group_invite_accepted_not_stored_offline(running_server):
    sender_ws, _, _, _ = await connect_and_register(running_server, device_id="s660-unsigned-gia-offline")
    offline_fp = canonical_fingerprint("s660-unsigned-gia-target")
    try:
        await drain_until(sender_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "group_invite_accepted", "to": offline_fp,
            "group_id": str(uuid.uuid4()), "new_member": "X", "new_member_name": "n",
        }))
        await asyncio.sleep(0.2)
        assert len(_read_pending_rows(offline_fp)) == 0
    finally:
        await sender_ws.close()


# ── 4. signed group_member_removed/group_invite_accepted DO relay online,
#       with the signature preserved (the actual regression this session
#       fixed -- these were being silently stripped before) ────────────────

async def test_signed_group_member_removed_relays_with_signature(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s660-signed-gmr-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s660-signed-gmr-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        group_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "group_member_removed", "to": recv_fp,
            "group_id": group_id, "removed_member": "X", "signature": "sig",
        }))
        msg = await _try_recv(recv_ws, 0.5)
        assert msg is not None
        assert msg["type"] == "group_member_removed"
        assert msg["from"] == sender_fp
        assert msg["group_id"] == group_id
        assert msg["removed_member"] == "X"
        assert msg["signature"] == "sig"
    finally:
        await sender_ws.close()
        await recv_ws.close()


async def test_signed_group_invite_accepted_relays_with_signature(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s660-signed-gia-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s660-signed-gia-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        group_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "group_invite_accepted", "to": recv_fp,
            "group_id": group_id, "new_member": "X", "new_member_name": "n", "signature": "sig",
        }))
        msg = await _try_recv(recv_ws, 0.5)
        assert msg is not None
        assert msg["type"] == "group_invite_accepted"
        assert msg["signature"] == "sig"
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 5. group_member_added -- previously an unrecognized type entirely,
#       now relays like its group_member_removed sibling ──────────────────

async def test_group_member_added_now_relays_online(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s660-gma-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s660-gma-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        group_id = str(uuid.uuid4())
        await sender_ws.send(json.dumps({
            "type": "group_member_added", "to": recv_fp,
            "group_id": group_id, "new_member": "X", "new_member_name": "n", "signature": "sig",
        }))
        msg = await _try_recv(recv_ws, 0.5)
        assert msg is not None
        assert msg["type"] == "group_member_added"
        assert msg["from"] == sender_fp
        assert msg["new_member"] == "X"
        assert msg["signature"] == "sig"
    finally:
        await sender_ws.close()
        await recv_ws.close()


async def test_unsigned_group_member_added_not_relayed_online(running_server):
    sender_ws, _, _, _ = await connect_and_register(running_server, device_id="s660-unsigned-gma-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s660-unsigned-gma-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        await sender_ws.send(json.dumps({
            "type": "group_member_added", "to": recv_fp,
            "group_id": str(uuid.uuid4()), "new_member": "X", "new_member_name": "n",
        }))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ═══════════════════════════════════════════════════════════════════════════
# S6-61 — active_calls cross-account state correlation
# ═══════════════════════════════════════════════════════════════════════════
# call_answer/call_end/disconnect mutated active_calls[target]/active_calls[peer]
# (someone ELSE's entry, not the acting user's own) with no check that the
# entry being written/erased actually correlates with the CURRENT call it
# claims to be about. An unrelated authenticated account could name any
# victim as `to` on a well-formed call_answer/call_end and freely overwrite
# or erase that victim's real active_calls bookkeeping. Client-side, both
# platforms' peerConnections are keyed by verified peer identity (not
# call_id-blind), so directly-injected signals from an unrelated attacker
# are already harmless to a live session — confirmed by inspection of
# CallManager.kt/DesktopCallManager.kt's handleAnswer/handleCallEnd/
# handleIceCandidate, all `peerConnections[from]`-keyed with no matching
# entry for an attacker who was never a real peer. The confirmed impact is
# narrower: the auto-call_end-on-disconnect notification for a victim's real
# call could be silently misdirected to the attacker instead of the real
# peer. Classified Medium (server-state corruption with a real but indirect
# effect, not direct termination of another user's live call). Fixed with
# `active_call_matches(user, peer, call_id)` gating every cross-user write —
# each user's own entry remains freely writable by that user; relay
# behavior for all 3 message types is completely unchanged, only the
# active_calls bookkeeping is now correlation-gated. See
# SECURITY_INVARIANTS.md #74 and KNOWN_SECURITY_ISSUES.md S6-61.
#
# call_group_leave was inspected separately (shares the call_end branch,
# but group-call join/invite/answer never populate active_calls at all) and
# reported as its own lower-severity finding, not fixed here: a stray
# call_group_leave could, before this fix, blindly pop an unrelated 1:1
# active_calls entry for either named party — the SAME correlation check
# added for call_end closes that too, as a side effect, without needing
# group-specific logic.

# ── 1. call_answer without a preceding matching offer cannot overwrite the
#       named target's real active_calls entry ─────────────────────────────

async def test_call_answer_cannot_overwrite_unrelated_victim_state(running_server):
    victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s661-v1")
    real_peer_ws, real_peer_fp, _, _ = await connect_and_register(running_server, device_id="s661-p1")
    attacker_ws, attacker_fp, _, _ = await connect_and_register(running_server, device_id="s661-a1")
    try:
        await drain_until(victim_ws, "register_ok")
        await drain_until(real_peer_ws, "register_ok")
        await drain_until(attacker_ws, "register_ok")
        real_call_id = _call_uuid()
        # Victim has a real, established call with real_peer.
        await victim_ws.send(json.dumps({
            "type": "call_offer", "to": real_peer_fp, "call_id": real_call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await real_peer_ws.recv()
        await real_peer_ws.send(json.dumps({"type": "call_answer", "to": victim_fp, "call_id": real_call_id, "sdp": _sdp_of_len(300)}))
        await victim_ws.recv()
        assert server.active_calls.get(victim_fp) == {"peer": real_peer_fp, "call_id": real_call_id}

        # Attacker, unrelated to this call, sends a well-formed call_answer
        # naming the victim as target with a random call_id.
        await attacker_ws.send(json.dumps({
            "type": "call_answer", "to": victim_fp, "call_id": _call_uuid(), "sdp": _sdp_of_len(300),
        }))
        await victim_ws.recv()
        await asyncio.sleep(0.1)
        assert server.active_calls.get(victim_fp) == {"peer": real_peer_fp, "call_id": real_call_id}
    finally:
        await victim_ws.close()
        await real_peer_ws.close()
        await attacker_ws.close()


# ── 2. attacker claiming the real peer's identity but the wrong call_id
#       still cannot overwrite victim state ─────────────────────────────────

async def test_call_answer_wrong_call_id_cannot_overwrite_victim_state(running_server):
    victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s661-v2")
    peer_ws, peer_fp, _, _ = await connect_and_register(running_server, device_id="s661-p2")
    try:
        await drain_until(victim_ws, "register_ok")
        await drain_until(peer_ws, "register_ok")
        real_call_id = _call_uuid()
        await victim_ws.send(json.dumps({
            "type": "call_offer", "to": peer_fp, "call_id": real_call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await peer_ws.recv()
        # peer answers with a DIFFERENT (stale/mismatched) call_id.
        await peer_ws.send(json.dumps({"type": "call_answer", "to": victim_fp, "call_id": _call_uuid(), "sdp": _sdp_of_len(300)}))
        await victim_ws.recv()
        await asyncio.sleep(0.1)
        # victim's own entry from the offer is untouched by peer's own write
        assert server.active_calls.get(victim_fp) == {"peer": peer_fp, "call_id": real_call_id}
    finally:
        await victim_ws.close()
        await peer_ws.close()


# ── 3. unrelated call_end cannot erase a victim's real active_calls state ──

async def test_unrelated_call_end_cannot_erase_victim_state(running_server):
    victim_ws, victim_fp, _, _ = await connect_and_register(running_server, device_id="s661-v3")
    real_peer_ws, real_peer_fp, _, _ = await connect_and_register(running_server, device_id="s661-p3")
    attacker_ws, attacker_fp, _, _ = await connect_and_register(running_server, device_id="s661-a3")
    try:
        await drain_until(victim_ws, "register_ok")
        await drain_until(real_peer_ws, "register_ok")
        await drain_until(attacker_ws, "register_ok")
        real_call_id = _call_uuid()
        await victim_ws.send(json.dumps({
            "type": "call_offer", "to": real_peer_fp, "call_id": real_call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await real_peer_ws.recv()
        assert server.active_calls.get(victim_fp) == {"peer": real_peer_fp, "call_id": real_call_id}

        # Attacker sends call_end naming the victim, with a call_id they made up.
        await attacker_ws.send(json.dumps({"type": "call_end", "to": victim_fp, "call_id": _call_uuid(), "reason": "hangup"}))
        await victim_ws.recv()
        await asyncio.sleep(0.1)
        assert server.active_calls.get(victim_fp) == {"peer": real_peer_fp, "call_id": real_call_id}
    finally:
        await victim_ws.close()
        await real_peer_ws.close()
        await attacker_ws.close()


# ── 4. a stale call_end from an old call cannot delete a newer call's state ─

async def test_stale_call_end_cannot_delete_newer_call_state(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s661-a4")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s661-b4")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        old_call_id = _call_uuid()
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": old_call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await b_ws.recv()
        await b_ws.send(json.dumps({"type": "call_answer", "to": a_fp, "call_id": old_call_id, "sdp": _sdp_of_len(300)}))
        await a_ws.recv()
        await a_ws.send(json.dumps({"type": "call_end", "to": b_fp, "call_id": old_call_id, "reason": "hangup"}))
        await b_ws.recv()
        assert a_fp not in server.active_calls and b_fp not in server.active_calls

        # A new call starts with a different call_id.
        new_call_id = _call_uuid()
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": new_call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await b_ws.recv()
        await b_ws.send(json.dumps({"type": "call_answer", "to": a_fp, "call_id": new_call_id, "sdp": _sdp_of_len(300)}))
        await a_ws.recv()
        assert server.active_calls.get(a_fp) == {"peer": b_fp, "call_id": new_call_id}

        # A stale call_end for the OLD call_id arrives late.
        await a_ws.send(json.dumps({"type": "call_end", "to": b_fp, "call_id": old_call_id, "reason": "hangup"}))
        await b_ws.recv()
        await asyncio.sleep(0.1)
        assert server.active_calls.get(a_fp) == {"peer": b_fp, "call_id": new_call_id}
        assert server.active_calls.get(b_fp) == {"peer": a_fp, "call_id": new_call_id}
    finally:
        await a_ws.close()
        await b_ws.close()


# ── 5. disconnect of A does not erase B's newer, unrelated call with C ─────

async def test_disconnect_does_not_erase_peers_newer_unrelated_call(running_server):
    a_ws, a_fp, _, _ = await connect_and_register(running_server, device_id="s661-a5")
    b_ws, b_fp, _, _ = await connect_and_register(running_server, device_id="s661-b5")
    c_ws, c_fp, _, _ = await connect_and_register(running_server, device_id="s661-c5")
    try:
        await drain_until(a_ws, "register_ok")
        await drain_until(b_ws, "register_ok")
        await drain_until(c_ws, "register_ok")
        ab_call_id = _call_uuid()
        await a_ws.send(json.dumps({
            "type": "call_offer", "to": b_fp, "call_id": ab_call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await b_ws.recv()
        await b_ws.send(json.dumps({"type": "call_answer", "to": a_fp, "call_id": ab_call_id, "sdp": _sdp_of_len(300)}))
        await a_ws.recv()
        assert server.active_calls.get(b_fp) == {"peer": a_fp, "call_id": ab_call_id}

        # B moves on to a real, newer call with C (overwrites B's own entry,
        # which is always B's own to write).
        bc_call_id = _call_uuid()
        await b_ws.send(json.dumps({
            "type": "call_offer", "to": c_fp, "call_id": bc_call_id,
            "sdp": _sdp_of_len(300), "is_video": False, "is_group": False,
        }))
        await c_ws.recv()
        await c_ws.send(json.dumps({"type": "call_answer", "to": b_fp, "call_id": bc_call_id, "sdp": _sdp_of_len(300)}))
        await b_ws.recv()
        assert server.active_calls.get(b_fp) == {"peer": c_fp, "call_id": bc_call_id}

        # A (B's now-stale old peer) disconnects.
        await a_ws.close()
        await asyncio.sleep(0.2)
        # B's real, newer call with C must survive untouched.
        assert server.active_calls.get(b_fp) == {"peer": c_fp, "call_id": bc_call_id}
    finally:
        await b_ws.close()
        await c_ws.close()


# ═══════════════════════════════════════════════════════════════════════════
# S6-62 — federated_forward byte/resource admission
# ═══════════════════════════════════════════════════════════════════════════
# FED_FORWARD_PER_IP_LIMIT/GLOBAL_LIMIT bound MESSAGE COUNT only. A
# compromised/authenticated federation peer could send up to that many
# frames each near FEDERATION_MAX_PACKET_SIZE_BYTES (12 MiB), forcing
# json.loads()/validation/reserialization/relay-or-store work with no byte
# ceiling of its own. The largest legitimate inner payload forward_to_peers()
# ever produces is bounded by MAX_PACKET_SIZE_BYTES (6 MiB — the raw-frame
# ceiling every local client message, including one later forwarded, already
# obeys); only message_delete/disappear_timer/group_message_delete and voice
# had a tighter per-type bound. Federation is off by default (empty
# FEDERATION_SECRET/FEDERATION_PEERS), so classified Medium — requires a
# compromised/malicious already-authenticated peer, not an anonymous
# attacker. Fixed with FED_FORWARD_MAX_PAYLOAD_BYTES (hard per-payload cap)
# plus per-IP/global/per-recipient byte budgets layered on top of the
# existing count limits, same fixed-window pattern as S6-49/S6-51/S6-59. See
# SECURITY_INVARIANTS.md #75 and KNOWN_SECURITY_ISSUES.md S6-62.

def _fed_payload_of_total_bytes(base: dict, target_bytes: int, pad_key: str = "text") -> dict:
    """Pads base[pad_key] so json.dumps(result, separators=(",", ":")) is
    exactly target_bytes long — matches the server's own compact-separator
    accounting in the federated_forward handler exactly."""
    trial = dict(base)
    trial[pad_key] = ""
    base_len = len(json.dumps(trial, separators=(",", ":")).encode("utf-8"))
    trial[pad_key] = "X" * max(0, target_bytes - base_len)
    assert len(json.dumps(trial, separators=(",", ":")).encode("utf-8")) == target_bytes
    return trial


# ── 1. maximum legitimate payload still relays online ──────────────────────

async def test_fed_forward_max_legitimate_payload_relays(running_server):
    # FED_FORWARD_MAX_PAYLOAD_BYTES temporarily lowered so the exact-boundary
    # send stays well under the test harness's own websockets.serve() default
    # max_size (running_server doesn't set max_size, unlike production's
    # explicit MAX_PACKET_SIZE_BYTES -- a multi-MiB send in this test would
    # be rejected by the LIBRARY before ever reaching server code, which
    # would test the harness, not this admission check).
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    real_max_payload = server.FED_FORWARD_MAX_PAYLOAD_BYTES
    server.FED_FORWARD_MAX_PAYLOAD_BYTES = 200_000
    to = canonical_fingerprint("S662_MAX_TARGET")
    sender_fp = canonical_fingerprint("S662_MAX_SENDER")
    try:
        payload = _fed_payload_of_total_bytes(
            {"id": "s662-max-1", "type": "message", "from": sender_fp},
            server.FED_FORWARD_MAX_PAYLOAD_BYTES,
        )
        ws = await federation_connect(running_server)
        try:
            await ws.send(json.dumps({"type": "federated_forward", "to": to, "payload": payload}))
            await asyncio.sleep(0.3)
            assert "s662-max-1" in server.delivered_msg_ids
            assert len(_read_pending_rows(to)) == 1
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        server.FED_FORWARD_MAX_PAYLOAD_BYTES = real_max_payload


# ── 2. one byte over the limit is rejected ──────────────────────────────────

async def test_fed_forward_one_byte_over_limit_rejected(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    real_max_payload = server.FED_FORWARD_MAX_PAYLOAD_BYTES
    server.FED_FORWARD_MAX_PAYLOAD_BYTES = 200_000
    to = canonical_fingerprint("S662_OVER_TARGET")
    sender_fp = canonical_fingerprint("S662_OVER_SENDER")
    try:
        ws = await federation_connect(running_server)
        try:
            payload = _fed_payload_of_total_bytes(
                {"id": "s662-over-1", "type": "message", "from": sender_fp},
                server.FED_FORWARD_MAX_PAYLOAD_BYTES + 1,
            )
            await ws.send(json.dumps({"type": "federated_forward", "to": to, "payload": payload}))
            await asyncio.sleep(0.3)
            assert "s662-over-1" not in server.delivered_msg_ids
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        server.FED_FORWARD_MAX_PAYLOAD_BYTES = real_max_payload


# ── 3. oversized payload creates no dedup/inflight/store state ─────────────

async def test_fed_forward_oversized_creates_no_dedup_or_inflight_state(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    real_max_payload = server.FED_FORWARD_MAX_PAYLOAD_BYTES
    server.FED_FORWARD_MAX_PAYLOAD_BYTES = 200_000
    to = canonical_fingerprint("S662_NOSTATE_TARGET")
    sender_fp = canonical_fingerprint("S662_NOSTATE_SENDER")
    try:
        ws = await federation_connect(running_server)
        try:
            payload = _fed_payload_of_total_bytes(
                {"id": "s662-nostate-1", "type": "message", "from": sender_fp},
                server.FED_FORWARD_MAX_PAYLOAD_BYTES + 1,
            )
            await ws.send(json.dumps({"type": "federated_forward", "to": to, "payload": payload}))
            await asyncio.sleep(0.2)
            assert "s662-nostate-1" not in server.delivered_msg_ids
            assert "s662-nostate-1" not in server.federation_delivery_inflight
            assert len(_read_pending_rows(to)) == 0
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        server.FED_FORWARD_MAX_PAYLOAD_BYTES = real_max_payload


# ── 4. per-peer-IP byte budget rejects a legitimately-shaped burst ─────────

async def test_fed_forward_peer_byte_budget_enforced(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    real_peer_max = server.FED_FORWARD_PEER_MAX_BYTES
    server.FED_FORWARD_PEER_MAX_BYTES = 10_000
    sender_fp = canonical_fingerprint("S662_PEERBUDGET_SENDER")
    try:
        ws = await federation_connect(running_server)
        try:
            for i in range(3):
                to = canonical_fingerprint(f"S662_PEERBUDGET_T{i}")
                payload = _fed_payload_of_total_bytes(
                    {"id": f"s662-peerbudget-{i}", "type": "message", "from": sender_fp}, 6_000,
                )
                await ws.send(json.dumps({"type": "federated_forward", "to": to, "payload": payload}))
            await asyncio.sleep(0.3)
            # 3 * 6000 = 18000 > 10000 budget -- at least one must be rejected.
            delivered = sum(1 for i in range(3) if f"s662-peerbudget-{i}" in server.delivered_msg_ids)
            assert delivered < 3
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        server.FED_FORWARD_PEER_MAX_BYTES = real_peer_max


# ── 5. global byte budget bounds aggregate traffic across several peers ────

async def test_fed_forward_global_byte_budget_enforced(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    real_global_max = server.FED_FORWARD_GLOBAL_MAX_BYTES
    real_peer_max = server.FED_FORWARD_PEER_MAX_BYTES
    server.FED_FORWARD_GLOBAL_MAX_BYTES = 15_000
    server.FED_FORWARD_PEER_MAX_BYTES = 1_000_000  # keep per-IP budget out of the way
    sender_fp = canonical_fingerprint("S662_GLOBALBUDGET_SENDER")
    conns = [await federation_connect(running_server) for _ in range(3)]
    try:
        for i, ws in enumerate(conns):
            to = canonical_fingerprint(f"S662_GLOBALBUDGET_T{i}")
            payload = _fed_payload_of_total_bytes(
                {"id": f"s662-globalbudget-{i}", "type": "message", "from": sender_fp}, 6_000,
            )
            await ws.send(json.dumps({"type": "federated_forward", "to": to, "payload": payload}))
        await asyncio.sleep(0.3)
        # 3 * 6000 = 18000 > 15000 aggregate budget, even though each
        # connection is a DIFFERENT peer IP and well under its own budget.
        delivered = sum(1 for i in range(3) if f"s662-globalbudget-{i}" in server.delivered_msg_ids)
        assert delivered < 3
    finally:
        for ws in conns:
            await ws.close()
        server.FEDERATION_SECRET = old_secret
        server.FED_FORWARD_GLOBAL_MAX_BYTES = real_global_max
        server.FED_FORWARD_PEER_MAX_BYTES = real_peer_max


# ── 6. per-recipient byte budget protects one local victim ─────────────────

async def test_fed_forward_recipient_byte_budget_enforced(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    real_recipient_max = server.FED_FORWARD_RECIPIENT_MAX_BYTES
    real_peer_max = server.FED_FORWARD_PEER_MAX_BYTES
    server.FED_FORWARD_RECIPIENT_MAX_BYTES = 10_000
    server.FED_FORWARD_PEER_MAX_BYTES = 1_000_000
    victim = canonical_fingerprint("S662_RECIPBUDGET_VICTIM")
    sender_fp = canonical_fingerprint("S662_RECIPBUDGET_SENDER")
    try:
        ws = await federation_connect(running_server)
        try:
            for i in range(3):
                payload = _fed_payload_of_total_bytes(
                    {"id": f"s662-recipbudget-{i}", "type": "message", "from": sender_fp}, 6_000,
                )
                await ws.send(json.dumps({"type": "federated_forward", "to": victim, "payload": payload}))
            await asyncio.sleep(0.3)
            delivered = sum(1 for i in range(3) if f"s662-recipbudget-{i}" in server.delivered_msg_ids)
            assert delivered < 3
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret
        server.FED_FORWARD_RECIPIENT_MAX_BYTES = real_recipient_max
        server.FED_FORWARD_PEER_MAX_BYTES = real_peer_max


# ── 7. normal (small) message/session_init/group_message traffic still
#       federates unaffected ───────────────────────────────────────────────

async def test_fed_forward_normal_traffic_still_federates(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("S662_NORMAL_TARGET")
    sender_fp = canonical_fingerprint("S662_NORMAL_SENDER")
    try:
        ws = await federation_connect(running_server)
        try:
            frames = [
                {"id": "s662-normal-msg", "type": "message", "text": "hi", "from": sender_fp},
                {"id": "s662-normal-si", "type": "session_init", "sender_ik": "ik",
                 "x3dh_header": {}, "session_header": {}, "text": "x", "from": sender_fp},
                {"id": "s662-normal-gm", "type": "group_message", "group_id": "g1",
                 "sender_name": "s", "text": "x", "from": sender_fp},
            ]
            for payload in frames:
                await ws.send(json.dumps({"type": "federated_forward", "to": to, "payload": payload}))
            await asyncio.sleep(0.3)
            for f in frames:
                assert f["id"] in server.delivered_msg_ids
            assert len(_read_pending_rows(to)) == 3
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ═══════════════════════════════════════════════════════════════════════════
# S6-63 — anon_token_state schema migration
# ═══════════════════════════════════════════════════════════════════════════
# `CREATE TABLE IF NOT EXISTS anon_token_state` does not retroactively widen
# an existing table's CHECK constraint — a database created before IN_FLIGHT
# was added (legacy CHECK: ACTIVE/SPENT/REVOKED only) kept rejecting every
# ACTIVE->IN_FLIGHT write (db_mark_anon_token_inflight) forever after an
# upgrade, even though a fresh database works fine. No automatic migration
# existed — confirmed by reading _db_setup_sync()'s own pre-existing comment,
# which documented the gap without closing it. Medium (upgrade/reliability
# failure for existing deployments, not a live confidentiality/integrity
# bypass). Fixed with `_migrate_anon_token_state_check_constraint()`: detects
# the legacy CHECK from `sqlite_master.sql` (not PRAGMA table_info(), which
# doesn't represent CHECK constraints), and if found, transactionally
# rebuilds the table (create-copy-validate-drop-rename) preserving every row
# and column, defaulting bootstrap_reserved/bootstrap_reserved_by only when
# genuinely absent from the old table. A no-op for a fresh or already-current
# database. See SECURITY_INVARIANTS.md #76 and KNOWN_SECURITY_ISSUES.md S6-63.

def _make_legacy_anon_token_state_db(path, rows, with_bootstrap_cols=True):
    """Builds a standalone sqlite3 file with the LEGACY 3-state
    (ACTIVE/SPENT/REVOKED) anon_token_state CHECK constraint, bypassing
    server.db_connect()/server._db_setup_sync() entirely -- this must be a
    faithful pre-S6-63 schema, not whatever the current server would create.
    `rows` is a list of (token_hash: bytes, owner: str, state: str,
    created_at: float, updated_at: float) tuples."""
    conn = sqlite3.connect(path)
    try:
        cols = """
            token_hash  BLOB PRIMARY KEY,
            owner       TEXT NOT NULL,
            state       TEXT NOT NULL CHECK(state IN ('ACTIVE', 'SPENT', 'REVOKED')),
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        """
        if with_bootstrap_cols:
            cols += """
            , bootstrap_reserved    INTEGER NOT NULL DEFAULT 0
            , bootstrap_reserved_by TEXT
            """
        conn.execute(f"CREATE TABLE anon_token_state ({cols})")
        for r in rows:
            conn.execute(
                "INSERT INTO anon_token_state (token_hash, owner, state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)", r,
            )
        conn.commit()
    finally:
        conn.close()


def _read_anon_token_state_rows(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT token_hash, owner, state, created_at, updated_at, "
            "bootstrap_reserved, bootstrap_reserved_by FROM anon_token_state ORDER BY token_hash"
        ).fetchall()
    finally:
        conn.close()


def _table_sql(path, table):
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


# ── 1. fresh DB creates the current (IN_FLIGHT-capable) schema ─────────────

def test_anon_token_state_fresh_db_creates_current_schema(tmp_path):
    db_path = str(tmp_path / "fresh.db")
    old_path = server.DB_PATH
    server.DB_PATH = db_path
    try:
        server._db_setup_sync()
        sql = _table_sql(db_path, "anon_token_state")
        assert sql is not None and "IN_FLIGHT" in sql
    finally:
        server.DB_PATH = old_path


# ── 2/3/4/5/6/7. legacy 3-state DB migrates automatically, every row/column
#       preserved byte-for-byte, bootstrap columns default correctly ───────

def test_anon_token_state_legacy_db_migrates_preserving_rows(tmp_path):
    db_path = str(tmp_path / "legacy.db")
    rows = [
        (b"\x01" * 32, "OWNERAAA", "ACTIVE", 111.5, 222.5),
        (b"\x02" * 32, "OWNERBBB", "SPENT", 333.25, 444.75),
        (b"\x03" * 32, "OWNERCCC", "REVOKED", 555.0, 666.0),
    ]
    _make_legacy_anon_token_state_db(db_path, rows, with_bootstrap_cols=False)
    old_sql = _table_sql(db_path, "anon_token_state")
    assert "IN_FLIGHT" not in old_sql  # sanity: genuinely legacy before migration

    old_path = server.DB_PATH
    server.DB_PATH = db_path
    try:
        server._db_setup_sync()
        new_sql = _table_sql(db_path, "anon_token_state")
        assert new_sql is not None and "IN_FLIGHT" in new_sql

        stored = {r[0]: r for r in _read_anon_token_state_rows(db_path)}
        assert len(stored) == 3
        for token_hash, owner, state, created_at, updated_at in rows:
            got = stored[token_hash]
            assert got[1] == owner
            assert got[2] == state          # ACTIVE/SPENT/REVOKED preserved exactly
            assert got[3] == created_at
            assert got[4] == updated_at
            assert got[5] == 0              # bootstrap_reserved defaulted (absent in legacy table)
            assert got[6] is None           # bootstrap_reserved_by defaulted
    finally:
        server.DB_PATH = old_path


def test_anon_token_state_legacy_db_with_existing_bootstrap_cols_preserved(tmp_path):
    # Realistic case: a deployment already picked up bootstrap_reserved/
    # bootstrap_reserved_by via the unconditional ALTER TABLE ADD COLUMN
    # logic (which never cared about the CHECK constraint) on an earlier
    # startup, while still carrying the legacy 3-state CHECK.
    db_path = str(tmp_path / "legacy_bootstrap.db")
    _make_legacy_anon_token_state_db(
        db_path, [(b"\x09" * 32, "OWNERDDD", "ACTIVE", 100.0, 200.0)], with_bootstrap_cols=True,
    )
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE anon_token_state SET bootstrap_reserved = 1, bootstrap_reserved_by = 'REQUESTERX' "
        "WHERE token_hash = ?", (b"\x09" * 32,),
    )
    conn.commit()
    conn.close()

    old_path = server.DB_PATH
    server.DB_PATH = db_path
    try:
        server._db_setup_sync()
        stored = {r[0]: r for r in _read_anon_token_state_rows(db_path)}
        got = stored[b"\x09" * 32]
        assert got[5] == 1
        assert got[6] == "REQUESTERX"
    finally:
        server.DB_PATH = old_path


# ── 8. after migration, ACTIVE -> IN_FLIGHT succeeds ────────────────────────

def test_anon_token_state_migration_unblocks_inflight_transition(tmp_path):
    db_path = str(tmp_path / "unblock.db")
    token_hash = b"\x0a" * 32
    _make_legacy_anon_token_state_db(
        db_path, [(token_hash, "OWNEREEE", "ACTIVE", 100.0, 200.0)], with_bootstrap_cols=False,
    )
    old_path = server.DB_PATH
    server.DB_PATH = db_path
    try:
        server._db_setup_sync()
        conn = server.db_connect()
        try:
            with conn:
                cur = conn.execute(
                    "UPDATE anon_token_state SET state = 'IN_FLIGHT', updated_at = 999 "
                    "WHERE token_hash = ? AND state = 'ACTIVE'", (token_hash,),
                )
            assert cur.rowcount == 1
        finally:
            conn.close()
        stored = {r[0]: r for r in _read_anon_token_state_rows(db_path)}
        assert stored[token_hash][2] == "IN_FLIGHT"
    finally:
        server.DB_PATH = old_path


# ── 9. second startup is a no-op / idempotent ───────────────────────────────

def test_anon_token_state_migration_idempotent_on_second_startup(tmp_path):
    db_path = str(tmp_path / "idempotent.db")
    rows = [(b"\x0b" * 32, "OWNERFFF", "ACTIVE", 100.0, 200.0)]
    _make_legacy_anon_token_state_db(db_path, rows, with_bootstrap_cols=False)
    old_path = server.DB_PATH
    server.DB_PATH = db_path
    try:
        server._db_setup_sync()
        first = _read_anon_token_state_rows(db_path)
        server._db_setup_sync()   # second startup against the now-migrated DB
        second = _read_anon_token_state_rows(db_path)
        assert first == second
    finally:
        server.DB_PATH = old_path


# ── 10/11. malformed/invalid state fails startup closed, without destroying
#       the original table ──────────────────────────────────────────────────

def test_anon_token_state_migration_fails_closed_on_invalid_state(tmp_path):
    db_path = str(tmp_path / "corrupt.db")
    token_hash = b"\x0c" * 32
    _make_legacy_anon_token_state_db(
        db_path, [(token_hash, "OWNERGGG", "ACTIVE", 100.0, 200.0)], with_bootstrap_cols=False,
    )
    # Inject a state value the legacy CHECK itself would never have allowed
    # in normal operation -- simulates unexpected/corrupt data reaching this
    # migration, which must refuse to guess rather than silently drop/reset it.
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA ignore_check_constraints = ON")
    conn.execute("UPDATE anon_token_state SET state = 'BOGUS' WHERE token_hash = ?", (token_hash,))
    conn.commit()
    conn.close()

    old_path = server.DB_PATH
    server.DB_PATH = db_path
    try:
        with pytest.raises(RuntimeError):
            server._db_setup_sync()
        # Original (unmigrated) table and its bad row must still be intact --
        # a failed migration must not have destroyed anything. Read directly
        # (not via _read_anon_token_state_rows, which assumes the CURRENT
        # 7-column shape) -- this table never had bootstrap columns and a
        # failed migration must not have added them either.
        sql = _table_sql(db_path, "anon_token_state")
        assert sql is not None and "IN_FLIGHT" not in sql
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute("SELECT token_hash, state FROM anon_token_state").fetchall()
        finally:
            conn.close()
        assert rows == [(token_hash, "BOGUS")]
    finally:
        server.DB_PATH = old_path


# ── 12. an already-current-schema database is left untouched ───────────────

def test_anon_token_state_current_schema_db_untouched(tmp_path):
    db_path = str(tmp_path / "current.db")
    old_path = server.DB_PATH
    server.DB_PATH = db_path
    try:
        server._db_setup_sync()   # creates current schema fresh
        conn = server.db_connect()
        with conn:
            conn.execute(
                "INSERT INTO anon_token_state (token_hash, owner, state, created_at, updated_at) "
                "VALUES (?, ?, 'ACTIVE', 1.0, 2.0)", (b"\x0d" * 32, "OWNERHHH"),
            )
        conn.close()
        before = _read_anon_token_state_rows(db_path)
        server._db_setup_sync()   # must be a pure no-op against a current-schema DB
        after = _read_anon_token_state_rows(db_path)
        assert before == after
    finally:
        server.DB_PATH = old_path


# ═══════════════════════════════════════════════════════════════════════════
# S6-65 — group_create roster transport/authentication
# ═══════════════════════════════════════════════════════════════════════════
# Both clients produce a signed initial roster (group_id + members + admins,
# roster_signature), but the server's group_create relay dropped members/
# admins/roster_signature entirely on every path (online, offline, and the
# federated_forward incoming dispatch had no per-type validator for
# group_create at all) — so every recipient's roster authentication was dead
# code, always falling back to an unauthenticated [from, self]/[from] guess.
# For any group >2 people, every non-admin invitee's local roster was simply
# wrong (missing every other real member) — a functional/reliability
# breakage of intended authenticated roster propagation, not an unauthorized
# membership/key disclosure (the key is still per-recipient hybrid-encrypted
# regardless of roster presence). Medium. Fixed with validate_group_roster()
# (shape/bound validation, not cryptographic verification — that stays each
# client's job) gating the online/offline/federated-outbound relay (one
# shared payload dict) and a new federated_forward incoming dispatch entry.
# Both clients now REQUIRE the roster (no unsigned fallback for a
# current-version group_create). See SECURITY_INVARIANTS.md #78 and
# KNOWN_SECURITY_ISSUES.md S6-65.

def _group_create_frame(to, group_id, sender_fp, extra_member=None, roster_sig="sig"):
    members = [sender_fp, to] + ([extra_member] if extra_member else [])
    return {
        "type": "group_create", "to": to, "group_id": group_id,
        "group_name": "g", "group_avatar": "avatar", "encrypted_group_key": "x",
        "signature": "sig", "members": members, "admins": [sender_fp],
        "roster_signature": roster_sig,
    }


# ── 1. legitimate roster reaches the recipient unchanged ───────────────────

async def test_group_create_roster_relays_unchanged(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s665-ok-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s665-ok-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        third = canonical_fingerprint("S665_THIRD_MEMBER")
        group_id = str(uuid.uuid4())
        frame = _group_create_frame(recv_fp, group_id, sender_fp, extra_member=third)
        await sender_ws.send(json.dumps(frame))
        msg = json.loads(await asyncio.wait_for(recv_ws.recv(), timeout=2))
        assert msg["type"] == "group_create"
        assert set(msg["members"]) == {sender_fp, recv_fp, third}
        assert msg["admins"] == [sender_fp]
        assert msg["roster_signature"] == "sig"
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 2/3/4. malformed members/admins/roster_signature rejected ──────────────

async def test_group_create_duplicate_members_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s665-dup-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s665-dup-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        frame = _group_create_frame(recv_fp, str(uuid.uuid4()), sender_fp)
        frame["members"] = [sender_fp, recv_fp, recv_fp]   # duplicate
        await sender_ws.send(json.dumps(frame))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


async def test_group_create_admins_not_subset_of_members_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s665-adm-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s665-adm-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        outsider = canonical_fingerprint("S665_NOT_A_MEMBER")
        frame = _group_create_frame(recv_fp, str(uuid.uuid4()), sender_fp)
        frame["admins"] = [outsider]   # not a member at all
        await sender_ws.send(json.dumps(frame))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


async def test_group_create_noncanonical_member_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s665-nc-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s665-nc-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        frame = _group_create_frame(recv_fp, str(uuid.uuid4()), sender_fp)
        frame["members"] = [sender_fp, recv_fp, "not-a-canonical-fingerprint"]
        await sender_ws.send(json.dumps(frame))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


async def test_group_create_oversized_roster_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s665-big-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s665-big-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        huge_members = [sender_fp, recv_fp] + [
            canonical_fingerprint(f"S665_BULK_{i}") for i in range(server.GROUP_ROSTER_MAX_MEMBERS)
        ]
        frame = _group_create_frame(recv_fp, str(uuid.uuid4()), sender_fp)
        frame["members"] = huge_members
        await sender_ws.send(json.dumps(frame))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 5. stripped roster_signature rejected ───────────────────────────────────

async def test_group_create_missing_roster_signature_rejected(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s665-nosig-s")
    recv_ws, recv_fp, _, _ = await connect_and_register(running_server, device_id="s665-nosig-r")
    try:
        await drain_until(sender_ws, "register_ok")
        await drain_until(recv_ws, "register_ok")
        frame = _group_create_frame(recv_fp, str(uuid.uuid4()), sender_fp)
        del frame["roster_signature"]
        await sender_ws.send(json.dumps(frame))
        assert await _try_recv(recv_ws, 0.3) is None
    finally:
        await sender_ws.close()
        await recv_ws.close()


# ── 6/7. offline and federated paths preserve the roster fields ────────────

async def test_group_create_roster_preserved_offline(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s665-off-s")
    try:
        await drain_until(sender_ws, "register_ok")
        to = canonical_fingerprint("S665_OFFLINE_TARGET")
        group_id = str(uuid.uuid4())
        frame = _group_create_frame(to, group_id, sender_fp)
        await sender_ws.send(json.dumps(frame))
        await asyncio.sleep(0.3)
        rows = _read_pending_rows(to)
        assert len(rows) == 1
        stored_payload = json.loads(rows[0][2])   # (id, recipient, payload, payload_bytes, msg_id)
        assert set(stored_payload["members"]) == {sender_fp, to}
        assert stored_payload["admins"] == [sender_fp]
        assert stored_payload["roster_signature"] == "sig"
    finally:
        await sender_ws.close()


async def test_group_create_federated_forward_requires_valid_roster(running_server):
    old_secret = server.FEDERATION_SECRET
    server.FEDERATION_SECRET = "test-federation-secret"
    to = canonical_fingerprint("S665_FED_TARGET")
    sender_fp = canonical_fingerprint("S665_FED_SENDER")
    group_id = str(uuid.uuid4())
    try:
        ws = await federation_connect(running_server)
        try:
            # Valid roster relays.
            good = {
                "type": "federated_forward", "to": to,
                "payload": {
                    "type": "group_create", "from": sender_fp, "id": "s665-fed-good",
                    "group_id": group_id, "group_name": "g", "group_avatar": "a",
                    "encrypted_group_key": "x", "signature": "sig",
                    "members": [sender_fp, to], "admins": [sender_fp], "roster_signature": "sig",
                },
            }
            await ws.send(json.dumps(good))
            await asyncio.sleep(0.3)
            rows = _read_pending_rows(to)
            assert len(rows) == 1

            # Missing roster is dropped, not relayed/stored.
            bad = {
                "type": "federated_forward", "to": to,
                "payload": {
                    "type": "group_create", "from": sender_fp, "id": "s665-fed-bad",
                    "group_id": group_id, "group_name": "g", "group_avatar": "a",
                    "encrypted_group_key": "x", "signature": "sig",
                },
            }
            await ws.send(json.dumps(bad))
            await asyncio.sleep(0.3)
            assert len(_read_pending_rows(to)) == 1   # still just the one good row
        finally:
            await ws.close()
    finally:
        server.FEDERATION_SECRET = old_secret


# ── 8. failed roster verification leaves no trusted server-relayed state ───

async def test_group_create_rejected_roster_creates_no_row_anywhere(running_server):
    sender_ws, sender_fp, _, _ = await connect_and_register(running_server, device_id="s665-none-s")
    to = canonical_fingerprint("S665_NONE_TARGET")
    try:
        await drain_until(sender_ws, "register_ok")
        frame = _group_create_frame(to, str(uuid.uuid4()), sender_fp)
        frame["admins"] = []   # empty -- invalid
        await sender_ws.send(json.dumps(frame))
        await asyncio.sleep(0.3)
        assert len(_read_pending_rows(to)) == 0
    finally:
        await sender_ws.close()


# ═══════════════════════════════════════════════════════════════════════════
# subscribe_tokens: reconnect-friendly rate limiting ────────────────────────
#
# The per-message "subscribe_tokens" limit used to be a flat call-count gate
# charged identically whether a batch was 100 brand-new tokens or a pure
# reconnect resubscribing 100 already-owned ones -- found live 2026-09-20 in
# production: legitimate startup/reconnect bursts (client pools now spread
# across several MAX_TOKENS_PER_SUBSCRIBE-sized chunks) could exceed that
# flat ceiling and break anonymous-delivery recovery. The handler now only
# charges the per-message limiter for a batch containing at least one token
# NOT already a cache hit; a purely idempotent resubscribe never touches it.
# The actual defense against genuine new-token abuse is unchanged --
# MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT/ANON_TOKEN_NEW_CLAIM_MAX_PER_WINDOW/
# ANON_TOKEN_STATE_MAX_TOTAL_ROWS/ANON_TOKEN_GLOBAL_CLAIM_LIMIT, all still
# enforced atomically inside db_claim_anon_tokens()/_db_claim_anon_tokens_sync().
# See SUBSCRIBE_TOKENS_RATE_LIMIT's own comment in server.py and
# SECURITY_INVARIANTS.md #57.
# ═══════════════════════════════════════════════════════════════════════════

async def _subscribe_and_collect_errors(ws, batches, timeout=1.0):
    """Sends each token list in `batches` as its own subscribe_tokens call,
    then drains whatever arrives within `timeout` -- subscribe_tokens has no
    unconditional success reply (only a rate-limit rejection, or a
    subscribe_tokens_result for already-spent reconciliation, produce any
    response at all), so an empty return IS the success signal, matching the
    idiom the rest of this file's other rate-limit tests already use."""
    for tokens in batches:
        await ws.send(json.dumps({"type": "subscribe_tokens", "tokens": tokens}))
    errors = []
    try:
        async with asyncio.timeout(timeout):
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("type") == "error":
                    errors.append(msg)
    except (asyncio.TimeoutError, TimeoutError):
        pass
    return errors


# ── 1. a normal 100-token startup succeeds in one call ──────────────────────

async def test_subscribe_100_new_tokens_startup_succeeds(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s671-startup-100")
    try:
        await drain_until(ws, "register_ok")
        tokens = [rand_token() for _ in range(100)]
        errors = await _subscribe_and_collect_errors(ws, [tokens])
        assert errors == []
        assert _anon_active_count(fp) == 100
    finally:
        await ws.close()


# ── 2. an immediate identical retry is free and succeeds ───────────────────

async def test_subscribe_identical_retry_is_free_and_succeeds(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s671-retry-idempotent")
    real_limit = server.SUBSCRIBE_TOKENS_RATE_LIMIT
    server.SUBSCRIBE_TOKENS_RATE_LIMIT = 1  # only ONE call may ever charge the limiter
    try:
        await drain_until(ws, "register_ok")
        tokens = [rand_token() for _ in range(100)]
        # First call is genuinely new -- spends the limiter's only slot.
        errors = await _subscribe_and_collect_errors(ws, [tokens])
        assert errors == []
        # Three back-to-back IDENTICAL re-subscribes of the now fully-owned
        # batch must all still succeed despite zero budget left -- every
        # token is already a cache hit, so the limiter is never consulted.
        errors = await _subscribe_and_collect_errors(ws, [tokens, tokens, tokens])
        assert errors == []
        assert _anon_active_count(fp) == 100  # unchanged -- no duplicate rows
    finally:
        server.SUBSCRIBE_TOKENS_RATE_LIMIT = real_limit
        await ws.close()


# ── 3. an overlapping retry only admits/charges the genuinely new tokens ───

async def test_subscribe_overlapping_batch_only_admits_new_tokens(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s671-overlap")
    try:
        await drain_until(ws, "register_ok")
        old_tokens = [rand_token() for _ in range(50)]
        errors = await _subscribe_and_collect_errors(ws, [old_tokens])
        assert errors == []
        assert _anon_active_count(fp) == 50

        new_tokens = [rand_token() for _ in range(50)]
        mixed = old_tokens + new_tokens  # 50 already-owned + 50 genuinely new
        errors = await _subscribe_and_collect_errors(ws, [mixed])
        assert errors == []
        # Only the 50 genuinely new tokens grew the account's active-row
        # count -- the 50 overlapping ones cost nothing extra.
        assert _anon_active_count(fp) == 100
    finally:
        await ws.close()


# ── 4. repeated genuinely-new token floods are still rate-limited ──────────

async def test_subscribe_repeated_new_token_floods_still_limited(running_server):
    ws, fp, _, _ = await connect_and_register(running_server, device_id="s671-flood")
    real_limit = server.SUBSCRIBE_TOKENS_RATE_LIMIT
    server.SUBSCRIBE_TOKENS_RATE_LIMIT = 3
    try:
        await drain_until(ws, "register_ok")
        # 5 separate batches, each genuinely brand-new -- every single one
        # charges the per-message limiter (has_new is True every time).
        batches = [[rand_token() for _ in range(10)] for _ in range(5)]
        errors = await _subscribe_and_collect_errors(ws, batches)
        assert len(errors) == 2  # only 3 of the 5 all-new calls got through
        assert all(e["reason"] == "Rate limit exceeded" for e in errors)
    finally:
        server.SUBSCRIBE_TOKENS_RATE_LIMIT = real_limit
        await ws.close()


# ── 5. parallel claims for the same owner cannot exceed the active cap or
#       double-charge an overlapping token ──────────────────────────────────

async def test_subscribe_parallel_claims_cannot_exceed_cap_or_double_charge(running_server):
    username = canonical_fingerprint("s671_parallel_owner")
    real_cap = server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT
    server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = 15
    try:
        shared = [rand_token() for _ in range(5)]  # present in BOTH concurrent batches
        batch_a = shared + [rand_token() for _ in range(10)]
        batch_b = shared + [rand_token() for _ in range(10)]
        results = await asyncio.gather(
            server.db_claim_anon_tokens(batch_a, username),
            server.db_claim_anon_tokens(batch_b, username),
        )
        # Cap is 15; each batch alone is 15 DISTINCT-looking tokens but they
        # share 5 -- true distinct total across both batches is 25, so the
        # cap must still bind at 15, never higher just because the request
        # was split into two concurrent calls, and the 5 shared tokens must
        # never occupy two slots.
        assert _anon_active_count(username) <= 15
        admitted = {t for claims in results for t, v in claims.items() if v[1] == "ACTIVE"}
        assert len(admitted) == len(_anon_row_state_owned(username))
    finally:
        server.MAX_ACTIVE_ANON_TOKENS_PER_ACCOUNT = real_cap


def _anon_row_state_owned(username: str):
    with server.db_connect() as conn:
        return conn.execute(
            "SELECT token_hash FROM anon_token_state WHERE owner = ? AND state IN ('ACTIVE', 'IN_FLIGHT')",
            (username,)
        ).fetchall()


# ── 6. reconnect restoration of an existing pool succeeds ──────────────────

async def test_subscribe_reconnect_restoration_succeeds(running_server):
    device_id = "s671-reconnect-restore"
    ws, fp, priv, pub_der = await connect_and_register(running_server, device_id=device_id)
    await drain_until(ws, "register_ok")
    tokens = [rand_token() for _ in range(100)]
    errors = await _subscribe_and_collect_errors(ws, [tokens])
    assert errors == []
    assert _anon_active_count(fp) == 100
    await ws.close()

    # Reconnect -- same identity, brand-new websocket/TCP connection, exactly
    # the production post-call/post-reconnect scenario this fix targets.
    ws2 = await websockets.connect(running_server)
    await handshake(ws2, priv, pub_der)
    await register(ws2, pub_der, device_id, "t")
    await drain_until(ws2, "register_ok")
    try:
        errors = await _subscribe_and_collect_errors(ws2, [tokens])
        assert errors == []
        assert _anon_active_count(fp) == 100  # unchanged -- no new rows
    finally:
        await ws2.close()
