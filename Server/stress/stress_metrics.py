"""
Report collection for the stress harness. Deliberately dumb: a scenario
function fills in a ScenarioReport as it runs, this module only knows how
to summarize/print it. See README.md for the "performance numbers are not
security claims" posture this module's output format is meant to enforce
-- every printed report says "measured on this test environment", never a
capacity claim.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import protocol_harness as ph  # noqa: E402


@dataclass
class ScenarioReport:
    name: str
    attempted: int = 0
    succeeded: int = 0
    rejected_expected: int = 0     # rate-limited / capacity-full / otherwise correctly refused
    unexpected_errors: int = 0
    invariant_violations: list[str] = field(default_factory=list)
    latencies_sec: list[float] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    resource_summary: dict | None = None
    status: str = "NOT RUN"  # PASS / FAIL / INCONCLUSIVE / NOT RUN

    def finalize(self):
        if self.invariant_violations:
            self.status = "FAIL"
        elif self.attempted == 0:
            self.status = "INCONCLUSIVE"
        else:
            self.status = "PASS"
        return self

    def print(self):
        print(f"\n=== Scenario: {self.name} ===")
        print(f"  Attempted:            {self.attempted}")
        print(f"  Succeeded:            {self.succeeded}")
        print(f"  Rejected (expected):  {self.rejected_expected}")
        print(f"  Unexpected errors:    {self.unexpected_errors}")
        if self.latencies_sec:
            pct = ph.percentiles(self.latencies_sec)
            print(f"  Latency (ms):         p50={pct['p50']} p95={pct['p95']} p99={pct['p99']} max={pct['max']} (n={pct['count']})")
        if self.resource_summary:
            r = self.resource_summary
            print(f"  Peak RSS:             {r.get('peak_rss_mb')} MiB (final {r.get('final_rss_mb')} MiB)")
            print(f"  Peak CPU:             {r.get('peak_cpu_pct')}%")
        for n in self.notes:
            print(f"  Note: {n}")
        print(f"  Invariant violations: {len(self.invariant_violations)}")
        for v in self.invariant_violations:
            print(f"    - {v}")
        print(f"  STATUS: {self.status}")
        print("  (Measured on this local test environment/profile only -- not a production capacity claim.)")


def print_final_summary(reports: list[ScenarioReport]):
    """INCONCLUSIVE is a non-success and says so in the headline.

    Found 2026-11-03: `finalize()` already detected "this scenario attempted
    nothing" correctly and the per-scenario block printed
    `STATUS: INCONCLUSIVE`, but this summary only ever counted FAIL — so a run
    where two of three scenarios did ZERO work still printed
    `RESULT: PASS (3/3 scenario(s))`, and stress_server.py exited 0. A CI job
    wired to that is green while testing nothing, which is the one failure
    mode this directory's README explicitly does not want.

    FAIL and INCONCLUSIVE are kept DISTINCT rather than collapsed: they mean
    different things (a violated invariant vs a test that never ran) and need
    different responses.
    """
    print("\n" + "=" * 60)
    print("STRESS SUITE SUMMARY")
    print("=" * 60)
    for r in reports:
        print(f"  {r.status:14s} {r.name}")
    failed = [r for r in reports if r.status == "FAIL"]
    inconclusive = [r for r in reports if r.status in ("INCONCLUSIVE", "NOT RUN")]
    print("=" * 60)
    if failed:
        print(f"RESULT: FAIL ({len(failed)}/{len(reports)} scenario(s) failed"
              + (f", {len(inconclusive)} inconclusive)" if inconclusive else ")"))
    elif inconclusive:
        names = ", ".join(r.name for r in inconclusive)
        print(f"RESULT: INCONCLUSIVE ({len(inconclusive)}/{len(reports)} scenario(s) "
              f"attempted nothing: {names})")
        print("        Nothing failed, but nothing was proven either — treat as a "
              "broken run, not a pass.")
    else:
        print(f"RESULT: PASS ({len(reports)}/{len(reports)} scenario(s))")


def suite_exit_code(reports: list[ScenarioReport]) -> int:
    """2 = a scenario did no work, 1 = an invariant was violated, 0 = pass.
    Distinct codes so a caller can tell "broken run" from "real failure"."""
    if any(r.status == "FAIL" for r in reports):
        return 1
    if any(r.status in ("INCONCLUSIVE", "NOT RUN") for r in reports):
        return 2
    return 0
