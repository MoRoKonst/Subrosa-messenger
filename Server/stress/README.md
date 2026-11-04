# Server/stress — adversarial stress/load harness

Third system, alongside two that already existed:

| System | Role | Target |
|---|---|---|
| `Server/pentest_local_server.py` | Human-readable manual attack demo | A throwaway server the operator starts themselves |
| `subrosa_doctor.py` | Read-only **deployment** validation (TLS, firewall, DB encryption, ...) | A live VPS, safe to run against production |
| `Server/stress/` (this directory) | Automated adversarial fuzz/state-machine/stress testing | Its **own** isolated subprocess only |

Don't merge these. `pentest_local_server.py` stays a small, manually-run set of
end-to-end attack scenarios — it is not meant to become a fuzz engine or a load
generator. `subrosa_doctor.py` stays strictly read-only and safe to run against
a live deployment. This directory is the only one of the three that generates
real adversarial/load traffic, and it is hard-restricted to a server process it
started itself.

The related but separate test suites under `Server/tests/`:

- `test_security_invariants.py` — 650+ in-process regression tests, one per
  documented invariant.
- `test_protocol_negative.py` — protocol type coverage assertion, baseline
  reachability proof, top-level frame fuzzing, Hypothesis-driven per-field
  negative mutation. This is what closes (or leaves open) OPEN-3 in
  `docs/KNOWN_SECURITY_ISSUES.md`.
- `test_protocol_stateful.py` — valid-shaped packets sent in an invalid
  connection/protocol state.
- `test_protocol_concurrency.py` — races on operations whose security depends
  on atomicity (anon-token claim/inflight/ack/revoke, registration cap).
- `protocol_harness.py` / `protocol_cases.py` — shared infrastructure both the
  test suites above and this stress harness import from.

## Safety model

Every server this harness talks to is started by
`Server/tests/protocol_harness.ManagedServer`:

- bound to `127.0.0.1` on a freshly-picked free port (never `0.0.0.0`, never a
  fixed port) — see `SafetyViolation`/`assert_loopback_host` in
  `protocol_harness.py`;
- a brand-new temp-directory SQLite DB, asserted to resolve under the OS temp
  root before anything starts (`assert_temp_db_path`) — refuses a path that
  looks like a production default (`messages.db`, `beacon.db`, `subrosa.db`)
  even if it happened to be under temp;
- a minimal, explicitly-built child environment (`PATH`/`SYSTEMROOT`/etc. only)
  — **not** `os.environ.copy()` — so no production secret
  (`FEDERATION_SECRET`, `DB_ENCRYPTION_KEY_HEX`, `TOTP_SECRET_ENCRYPTION_KEY`,
  Firebase credentials, ...) that happens to be set in the parent shell can
  ever reach the child process;
- no `FEDERATION_SECRET` → no outgoing federation connections, no real peers;
- no `GOOGLE_APPLICATION_CREDENTIALS` → no real FCM sends;
- PoW/registration caps left at production defaults unless a specific test
  deliberately overrides them (e.g. the registration-cap race test sets
  `MAX_REGISTERED_USERS=3` on its own dedicated server instance).

`stress_server.py` never accepts a `--host`/`--target` flag. There is no
supported way to point this at a remote or production server — if you want
that, use `pentest_local_server.py` against a server you started yourself and
understand the consequences of.

## Running

```
python stress_server.py --profile smoke
python stress_server.py --profile ci
python stress_server.py --profile deep --allow-heavy-local-stress
python stress_server.py --profile smoke --scenario anon_token_stress
```

| Profile | Intent | Concurrent clients (roughly) | Duration |
|---|---|---|---|
| `smoke` | Before every commit | ~10 | seconds |
| `ci` | Normal CI | ~40 | ~10s per scenario |
| `deep` | Manual/local, sustained | up to 150 | ~30s per scenario |

`deep` (or anything else requesting more than `HEAVY_THRESHOLD_CLIENTS=60`
concurrent clients) refuses to run without `--allow-heavy-local-stress` —
the harness will not accidentally spawn a large coroutine storm on a
developer machine just because a profile asked for one.

## Scenarios

- **`connection_churn`** — connect-then-disconnect at various points
  (challenge-only, post-handshake, post-register, register→reconnect loop),
  bounded by a semaphore.
- **`anon_token_stress`** — per-client subscribe→send(self)→ack cycles, decoy
  tokens, and same-token replay attempts, checking the wire-observable
  invariant "exactly one real delivery per legit token, zero for
  decoys/replays" under concurrent multi-client load.
- **`mixed_traffic_with_canary`** — a healthy canary pair keeps doing real
  message round-trips throughout, while malicious clients concurrently send
  malformed frames, floods, and bad-owner/unknown-token ACKs. The only hard
  FAIL oracle: canary success rate dropping below `min_canary_success_rate`
  (default 80%) — i.e. malicious load measurably starving a healthy flow.

## What this suite does NOT claim

Per the numbers each scenario prints: these are measurements taken on one
local development machine, under a specific artificial traffic pattern, at a
specific profile's client count/duration. They are not a production capacity
claim, not "DoS-proof," not "race-free," and not "fully fuzzed" in any
absolute sense — see `docs/KNOWN_SECURITY_ISSUES.md`'s OPEN-3 entry for
exactly what negative/fuzz coverage does and doesn't exist yet.

## Not implemented in this pass

The following items from this suite's original design brief are explicitly
**NOT RUN / NOT IMPLEMENTED** as of 2026-09-25 — listed here rather than
silently omitted:

- Registration/auth/rate-limit stress beyond the one concurrency-cap test in
  `test_protocol_concurrency.py` (section 16/17 of the brief: PoW-enabled
  load, per-category rate-limit exhaustion sweep across every bucket).
- Offline-queue (`pending_messages`) and prekey-publish stress scenarios
  (sections 14/15).
- Federation stress against local fake peers (section 19) — federation is
  disabled (`FEDERATION_SECRET` unset) in every scenario here; OPEN-6/OPEN-12
  in `KNOWN_SECURITY_ISSUES.md` remain untraced/untested by this suite.
- Event-loop responsiveness percentiles as a dedicated probe (section 22) —
  `mixed_traffic_with_canary`'s canary latency is a rough proxy, not a direct
  event-loop-lag measurement.
- DB contention/integrity-check pass, server-restart-with-durable-state
  recovery test, and repeated-cycle memory-leak detection (sections 25/27/21).
- Failure injection (section 26).

Extending this suite with any of the above should follow the same pattern:
add a scenario function to `stress_scenarios.py` (or a new
`test_protocol_*.py` for anything that's really a correctness assertion
rather than a load scenario), reuse `protocol_harness.py`'s helpers, and wire
it into `stress_server.py`'s `all_scenarios` dict / the relevant profile.
