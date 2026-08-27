# Audit Target

*The frozen reference point for the first external audit. If you're reviewing this project later
than the date below, ask for a fresh `AUDIT_TARGET.md` rather than assuming `main` still matches
this — the whole point of this file is to stop the target from moving mid-review.*

**Tag immutability policy (external review 2026-08-27, DOC-06):** this tag was moved twice during
internal prep — first to include `AUDIT_SETUP.md`/`KNOWN_SECURITY_ISSUES.md`, then again to
include a real security fix (recovery-code entropy, see Known Issues below) found by a
documentation-level review before this package was ever handed to an actual external auditor.
Both moves happened before external handoff, which is the only reason they're acceptable — moving
a tag *after* an auditor has started reviewing it is not okay. **Going forward: once this tag is
actually sent to an external reviewer, it does not move again.** Anything found after that point
gets a new tag (`audit-2026-08-rc2`, or `audit-2026-09` for a later full re-review), never a
rewrite of this one.

| Field | Value |
|---|---|
| Repository | https://github.com/MoRoKonst/Subrosa-messenger |
| Commit | see `git rev-list -n 1 audit-2026-08` at handoff time — intentionally not hardcoded here to avoid the self-referential chicken-and-egg problem of a file needing to name the commit it's part of. |
| Tag | `audit-2026-08` |
| Android `versionCode` / `versionName` | 3 / 1.0 |
| Server version | not independently versioned — tracked by commit hash above (`Server/server.py`) |
| Dependencies lock state | `Server/requirements-lock.txt` — exact pinned versions, verified against both a clean local install and the actual production VPS. `Server/requirements.txt` (the deployment-facing file) still uses `>=` ranges deliberately; use the lock file when reproducibility matters, per [AUDIT_SETUP.md](AUDIT_SETUP.md). Android dependencies are exact-pinned in `app/build.gradle.kts` / `gradle/libs.versions.toml` already. |
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
  actual code rather than summarized from prose. Revised once already after an external
  documentation-level review (2026-08-27) found real issues — see
  `docs/KNOWN_SECURITY_ISSUES.md`'s "This session" section for what changed, including one actual
  code fix (recovery-code entropy, 40→80 bits) that review surfaced, not just a wording issue.
- `Server/requirements-lock.txt` — exact dependency versions, added after the same review flagged
  that `>=`-ranged `requirements.txt` alone doesn't make a tagged commit's dependency graph
  reproducible.

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
