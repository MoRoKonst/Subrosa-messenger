# Audit Setup

*Reproducible local environment for an external reviewer — no production credentials, no real
user data, no external runtime services or production infrastructure required. Internet access
*is* required to resolve build/package dependencies (pip, Gradle) unless you're working from a
pre-populated local cache. If a step here doesn't work as written, that's a bug in this document,
not something to work around silently — please report it.*

Companion to [AUDIT_TARGET.md](AUDIT_TARGET.md) (which commit/tag this describes) and
[SCOPE.md](SCOPE.md) (what to prioritize once running).

---

## 1. Clone at the audit target

```bash
git clone https://github.com/MoRoKonst/Subrosa-messenger.git
cd Subrosa-messenger
git checkout audit-2026-08
```

## 2. Server — Profile A: minimal local protocol environment (no TLS, no real deployment)

This profile is enough for reviewing protocol logic, concurrency, and application-layer security
(scope items 1–8). It deliberately runs with every optional hardening control **off** — see
Profile B below for the settings a real production deployment should actually use, and
[KNOWN_SECURITY_ISSUES.md](KNOWN_SECURITY_ISSUES.md)'s default-vs-hardened table for which control
maps to which threat.

Requires **Python 3.11+** (the server depends on `websockets>=17.0.1`, which requires it).

```bash
cd Server
python3 --version   # confirm >= 3.11
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements-lock.txt
```

`requirements.txt` uses `>=` ranges (deployment flexibility) — resolving it today and resolving it
in a month can silently produce a different dependency graph. `requirements-lock.txt` pins the
exact versions actually verified against [AUDIT_TARGET.md](AUDIT_TARGET.md); use it, not
`requirements.txt`, when reproducibility matters. It does not yet pin hashes
(`pip install --require-hashes`) — a known gap, not yet closed.

No `.env` file is required for a local, unauthenticated test instance — `SERVER_ACCESS_PROTECTED`,
`DB_ENCRYPTION_KEY_HEX`, `TOTP_SECRET_ENCRYPTION_KEY`, and federation are all opt-in (see
`Server/.env.example` for what each does and why it's off by default). Start it in dev mode
(plaintext WebSocket, no TLS — fine for local review, never for a real deployment):

```bash
python3 server.py --dev
```

This listens on `ws://localhost:9000`. You should see:

```
[DB] Хранилище сообщений: messages.db (НЕ зашифровано)
[*] WebSocket сервер запущен
[*] Режим: DEV (без TLS)
```

**Optional: exercise the harder-to-reach code paths.** These env vars gate specific behavior
covered in [SCOPE.md](SCOPE.md) items 6 and 8 — set them before starting the server if you want to
reproduce that behavior specifically:

```bash
MAX_REGISTERED_USERS=5 POW_DIFFICULTY_BITS=18 python3 server.py --dev   # registration cap + PoW
SERVER_ACCESS_PROTECTED=true SERVER_ACCESS_CODE_COUNT=5 python3 server.py --dev   # access-code gate
```

## 2b. Server — Profile B: production-equivalent hardened environment

Profile A above intentionally runs with every opt-in control disabled, which is fine for protocol
review but understates what a real deployment looks like — reviewing *only* Profile A risks
concluding a mitigation "doesn't really apply" when it's simply off by default. Run this instead
to review deployment-security posture (scope item 9–10, and the composite DB-theft-plus-recovery-
code scenario in [THREAT_MODEL.md § F](THREAT_MODEL.md#f-attacker-with-offline-access-to-the-servers-database-stolen-disk-backup-hosting-provider-access)):

```bash
export DB_ENCRYPTION_KEY_HEX=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export TOTP_SECRET_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export SERVER_ACCESS_PROTECTED=true
export SERVER_ACCESS_CODE_COUNT=5
export MAX_REGISTERED_USERS=100
export POW_DIFFICULTY_BITS=18
python3 server.py --dev   # still no TLS locally -- see note below
```

TLS itself isn't practical to reproduce in a throwaway local Profile B (it needs a real
certificate and, in production, sits behind Cloudflare/nginx — see `docs/DEPLOY.md`/`docs/DOCKER.md`
for the actual production TLS setup). Everything else above matches what a real deployment should
run with.

| Control | Default | Profile B / recommended production |
|---|---|---|
| TLS | N/A locally (`--dev`) | Required — see `docs/DEPLOY.md` |
| DB encryption (SQLCipher) | Off | On (`DB_ENCRYPTION_KEY_HEX`) |
| TOTP secret encryption | Off | On (`TOTP_SECRET_ENCRYPTION_KEY`) |
| Registration PoW | Off (`POW_DIFFICULTY_BITS=0`) | On, deployment-specific difficulty |
| Registration cap | Off (`MAX_REGISTERED_USERS=0` = unlimited) | Deployment-specific |
| Server access gate | Off | Deployment-specific (private/business deployments) |

## 3. Android client — build and point at the local server

```bash
cd ..   # repo root
```

The client's server address is configured at runtime (Servers screen in-app), not at build time —
build a normal debug APK:

```bash
./gradlew assembleDebug
```

Install on a device/emulator (`adb install app/build/outputs/apk/debug/app-debug.apk`), or launch
via Android Studio. On first run, add a server via the in-app "Servers" screen pointing at
`ws://<your-machine-IP>:9000` (an emulator reaches the host machine at `10.0.2.2:9000`; a physical
device needs the host's LAN IP and the same network).

`google-services.json` is not required to build or run — the Google Services / FCM plugin is
conditionally applied only if that file exists (`app/build.gradle.kts`), so push notifications are
simply unavailable in this setup, everything else works normally.

## 4. Create test accounts and reproduce protocol flows

Registration happens automatically on first launch — the app generates a fresh EC keypair and
registers with the server, no separate "create account" step or external test data needed. Repeat
on a second device/emulator instance (or a second app data directory) to get two accounts that can
message each other.

To reproduce a specific flow from [SCOPE.md](SCOPE.md)'s priority list:

- **Invite/first-contact**: Profile screen → share invite code/QR → second account → Add Contact →
  paste code. Exercises the anonymous-mailbox bootstrap
  ([SECURITY.md § Invite Codes](SECURITY.md#invite-codes)).
- **Device-gated TOTP + recovery**: enable TOTP from Settings, note the recovery codes shown once,
  then try registering the *same* identity under a new `device_id` (e.g. reinstall + restore from
  backup) — the server should require a TOTP code, and a recovery code should work once and then
  invalidate the rest ([SECURITY.md § Device-Gated TOTP](SECURITY.md#device-gated-totp--recovery-codes)).
- **Group creation/removal/rotation**: create a group with 3 accounts, remove one member, confirm
  (via server-side logging, or a debug build) that the removed member's client never receives the
  post-rotation key — this is the invariant `GroupManagerTest.kt` covers at the storage-state
  level; reproducing it live confirms the full `MessengerService.rotateGroupKey()` network path
  too, which that test doesn't reach (see [THREAT_MODEL.md § C](THREAT_MODEL.md#c-removed-group-member)).
- **Backup/restore**: Settings → Backup → export (requires TOTP enabled first) → reinstall → import
  on the "new" device — should require the backup password and, if `totp_enabled` was true, a
  current TOTP code.

## 5. Run the automated security regression tests

**Server (Python, pytest):**

```bash
cd Server
pip install -r requirements-dev.txt
pytest tests -v
```

8 tests covering recovery-code atomicity, registration-cap atomicity, anonymous-token ACK
ownership, `token_pending` survival across disconnect, revoked-fingerprint rejection, and
spent-token replay rejection — see `Server/tests/test_security_invariants.py` docstring and
`docs/CI_SAST_PLAN.md` for what each maps to.

**Android (Kotlin, JUnit + Robolectric — no emulator needed for this suite):**

```bash
./gradlew testDebugUnitTest
```

9 tests covering `GroupManager`'s internal authorization check and the removed-member/rotated-key
invariant — see `app/src/test/java/com/example/test/GroupManagerTest.kt`.

**Full CI pipeline** (build, lint, SAST, secret scan, dependency review) runs on every push/PR —
see `.github/workflows/` and `docs/CI_SAST_PLAN.md` for what's configured, or just check the
Actions tab at the audit-target commit for a live green/red status.

## 6. Reading order for context, not just running code

If you want the design intent before diving into `Server/server.py` (2900+ lines) or the Android
client (25k+ lines across `app/src/main/java/com/example/test/`):

1. [SECURITY_MODEL.md](SECURITY_MODEL.md) — what's protected, explicit non-goals.
2. [THREAT_MODEL.md](THREAT_MODEL.md) — attacker classes, what stops each one, residual risk.
3. [SCOPE.md](SCOPE.md) — priority order for this specific review.
4. [SECURITY.md](SECURITY.md) — implementation detail: algorithms, key formats, the full
   Known Limitations history (29 items, each with root cause and fix, where fixed).
5. [ARCHITECTURE.md](ARCHITECTURE.md) — component/data-flow overview.
6. [MESSAGE_DELIVERY.md](MESSAGE_DELIVERY.md) — the `token_pending` TTL/cleanup/retry/federation
   contract in full, referenced from scope item 4.
