# Audit Target

*The frozen reference point for the first external audit. If you're reviewing this project later
than the date below, ask for a fresh `AUDIT_TARGET.md` rather than assuming `main` still matches
this — the whole point of this file is to stop the target from moving mid-review.*

| Field | Value |
|---|---|
| Repository | https://github.com/MoRoKonst/Subrosa-messenger |
| Commit | whatever `git rev-parse audit-2026-08` resolves to — this file is committed *before* the tag is cut, so it can't name its own final hash without a chicken-and-egg problem. The last functional/code change before this doc-only tag-prep commit was `cf524e7`. |
| Tag | `audit-2026-08` |
| Android `versionCode` / `versionName` | 3 / 1.0 |
| Server version | not independently versioned — tracked by commit hash above (`Server/server.py`) |
| Dependencies lock state | `Server/requirements.txt` pins minimum versions (`>=`), not exact — see `git log -- Server/requirements.txt` at this commit for what was actually installed when this tag was cut. Android dependencies are exact-pinned in `app/build.gradle.kts` / `gradle/libs.versions.toml`. |
| CI status at this commit | All required checks green (Build, Semgrep SAST, CodeQL × 2, Server syntax check, Server security regression tests, Gitleaks) — see the Actions run for this commit. |
| Date | 2026-08-27 |

## What's included at this commit

- Android client (`app/`) — Kotlin/Compose, AGP 9.1.1, compileSdk 37.
- Server (`Server/server.py`) — Python/asyncio/websockets 17.x.
- CI/SAST pipeline — see `docs/CI_SAST_PLAN.md` for what's configured and why.
- Security regression tests — `Server/tests/test_security_invariants.py` (8 protocol-level
  invariants) and `app/src/test/java/com/example/test/GroupManagerTest.kt` (9 group-authorization/
  rotation invariants, Robolectric-backed).
- `docs/SECURITY_MODEL.md`, `docs/THREAT_MODEL.md`, `docs/SCOPE.md`, `docs/AUDIT_SETUP.md`,
  `docs/KNOWN_SECURITY_ISSUES.md` — written same session as this tag, cross-checked against the
  actual code rather than summarized from prose.

## Explicitly not included / known-incomplete at this commit

- Desktop client — not published in this repository (`/desktop/` gitignored).
- Protocol-level attack scripting (fuzzing / negative-input test suite) — see `docs/TODO.md`,
  "Протокольное тестирование сервера" — not started.
- `websockets` 12→17 / production-VPS Python 3.10→3.11 migration — done and verified live this
  session, but not captured in any automated CI check (a manual VPS operation, out of CI's reach
  by nature).

## How to reproduce this exact state

```
git clone https://github.com/MoRoKonst/Subrosa-messenger.git
cd Subrosa-messenger
git checkout audit-2026-08
```
