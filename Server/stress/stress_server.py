#!/usr/bin/env python3
"""
Adversarial stress/load CLI for the Subrosa server. A THIRD system,
distinct from pentest_local_server.py (manual attack demo) and
subrosa_doctor.py (read-only deployment check) -- see README.md.

SAFETY: always starts its OWN server.py subprocess bound to loopback with
a temp DB (Server/tests/protocol_harness.ManagedServer) -- never accepts a
--host/--target flag pointing anywhere else. There is deliberately no way
to point this at a remote or production server.

Usage:
    python stress_server.py --profile smoke
    python stress_server.py --profile ci
    python stress_server.py --profile deep --allow-heavy-local-stress
    python stress_server.py --profile smoke --scenario connection_churn
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import protocol_harness as ph  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stress_metrics import ScenarioReport, print_final_summary, suite_exit_code  # noqa: E402
import stress_scenarios as scenarios  # noqa: E402

PROFILES = {
    # name: (churn_clients, churn_duration, anon_clients, anon_tokens_per_client, mixed_malicious, mixed_duration)
    "smoke": dict(churn_clients=10, churn_duration=3.0, anon_clients=5, anon_tokens=5,
                  mixed_malicious=3, mixed_duration=3.0, concurrency=10),
    "ci": dict(churn_clients=40, churn_duration=8.0, anon_clients=15, anon_tokens=10,
               mixed_malicious=8, mixed_duration=8.0, concurrency=15),
    "deep": dict(churn_clients=150, churn_duration=30.0, anon_clients=40, anon_tokens=25,
                 mixed_malicious=25, mixed_duration=30.0, concurrency=25),
}

# Hard caps on what this tool will do even under --profile deep, unless the
# operator explicitly opts in -- see spec section 33 ("configurable safety
# caps for the tester itself").
HEAVY_THRESHOLD_CLIENTS = 60


async def run(profile: str, scenario_filter: str | None, allow_heavy: bool):
    params = PROFILES[profile]
    heaviest = max(params["churn_clients"], params["anon_clients"], params["mixed_malicious"])
    if heaviest > HEAVY_THRESHOLD_CLIENTS and not allow_heavy:
        print(f"[ABORT] profile '{profile}' requests up to {heaviest} concurrent clients, "
              f"above the default safety threshold ({HEAVY_THRESHOLD_CLIENTS}). "
              f"Re-run with --allow-heavy-local-stress to proceed.")
        sys.exit(2)

    print(f"[*] Starting isolated loopback server (profile={profile})...")
    srv = ph.ManagedServer(pow_difficulty_bits="0")
    srv.start()
    print(f"[*] Server up: {srv.url} (pid={srv.pid}, db={srv.db_path})")

    reports: list[ScenarioReport] = []
    stop_sampler = asyncio.Event()
    sampler = ph.ResourceSampler(srv.pid, interval=0.5)
    sampler_task = asyncio.create_task(sampler.run(stop_sampler))

    all_scenarios = {
        "connection_churn": lambda r: scenarios.connection_churn(
            srv.url, r, clients=params["churn_clients"], duration=params["churn_duration"],
            concurrency=params["concurrency"]),
        "anon_token_stress": lambda r: scenarios.anon_token_stress(
            srv.url, r, clients=params["anon_clients"], tokens_per_client=params["anon_tokens"],
            concurrency=params["concurrency"]),
        "mixed_traffic_with_canary": lambda r: scenarios.mixed_traffic_with_canary(
            srv.url, r, malicious_clients=params["mixed_malicious"], duration=params["mixed_duration"]),
    }

    try:
        for name, runner in all_scenarios.items():
            if scenario_filter and name != scenario_filter:
                continue
            report = ScenarioReport(name=name)
            try:
                await runner(report)
            except Exception as e:
                report.unexpected_errors += 1
                report.notes.append(f"scenario-level exception: {e!r}")
            if not srv.is_alive():
                report.invariant_violations.append("server process died during this scenario")
            report.finalize()
            report.print()
            reports.append(report)
    finally:
        stop_sampler.set()
        await sampler_task
        final_summary = sampler.summary()
        print(f"\n[*] Process resource summary (whole run): {final_summary}")
        srv.stop()
        print(f"[*] Server stopped. Alive={srv.is_alive()}")

    print_final_summary(reports)
    # Non-zero for INCONCLUSIVE too (exit 2), not just FAIL (exit 1) — see
    # print_final_summary()'s docstring for the green-while-testing-nothing
    # bug this closes.
    return suite_exit_code(reports)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=list(PROFILES), default="smoke")
    ap.add_argument("--scenario", choices=["connection_churn", "anon_token_stress", "mixed_traffic_with_canary"],
                     default=None, help="Run only this scenario (default: all).")
    ap.add_argument("--allow-heavy-local-stress", action="store_true",
                     help="Required to run profiles requesting more than "
                          f"{HEAVY_THRESHOLD_CLIENTS} concurrent clients.")
    args = ap.parse_args()
    exit_code = asyncio.run(run(args.profile, args.scenario, args.allow_heavy_local_stress))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
