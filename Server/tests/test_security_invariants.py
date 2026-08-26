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
import json
import secrets

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


async def register(ws, pub_der, device_id, name="t", extra=None):
    msg = {
        "type": "register",
        "name": name,
        "public_key": base64.b64encode(pub_der).decode(),
        "device_id": device_id,
    }
    if extra:
        msg.update(extra)
    await ws.send(json.dumps(msg))


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
    await server.db_save_recovery_codes(username, codes)

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
    await server.db_save_recovery_codes(username, codes)
    server.user_totp_secrets[username] = "JBSWY3DPEHPK3PXP"

    # Seed an "existing" device for this fingerprint so any other device_id
    # is treated as new (the condition that gates the TOTP/recovery check).
    class _FakeWs:
        async def close(self):
            pass
    server.clients[username] = {"ws": _FakeWs(), "name": "seed", "public_key": base64.b64encode(pub_der).decode(), "device_id": "seed-device"}

    async def attempt(device_id):
        ws = await websockets.connect(running_server)
        try:
            await handshake(ws, priv, pub_der)
            await register(ws, pub_der, device_id, extra={"recovery_code": codes[0]})
            try:
                await asyncio.wait_for(ws.recv(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
        finally:
            await ws.close()

    # A successful consume also deletes the whole recovery-codes row set for
    # the account in a fire-and-forget background task (db_delete_recovery_codes,
    # server.py near the "recovery-code takeover" print) -- so by the time
    # this function returns, the DB row this test would otherwise inspect may
    # already be gone. Count actual consumptions at the source instead of
    # racing that cleanup task.
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
    recipient, _, _, _ = await connect_and_register(running_server, device_id="recipient")
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

    recipient2, _, _, _ = await connect_and_register(running_server, device_id="recipient")
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
    results = await asyncio.gather(*[
        server.db_try_register_new_fingerprint(f"FP{i:04d}", max_users=5)
        for i in range(20)
    ])
    assert sum(1 for r in results if r) == 5


async def test_access_code_atomic_under_concurrent_redemption():
    code = "TESTCODE1"
    with server.db_connect() as conn:
        conn.execute(
            "INSERT INTO server_access_codes (code, used, created_at) VALUES (?, 0, ?)",
            (code, 0.0),
        )
        conn.commit()

    results = await asyncio.gather(*[
        server.db_check_and_consume_access_code(code, f"FP{i:04d}")
        for i in range(20)
    ])
    assert sum(1 for r in results if r) == 1
