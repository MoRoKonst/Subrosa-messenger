# Security Release Process

*Created 2026-08-30. Scoped honestly for what this project actually is: a solo-maintained,
self-hosted product sold as paid support to law firms (see [PRICING.md](PRICING.md)), not a
project with a security team or a 24/7 rotation. The goal here is a process real enough to
actually follow under pressure, not one that looks impressive on paper and gets skipped the
first time there's a real finding.*

## Scope

This process applies to security-relevant findings in:
- `Server/server.py` and anything else deployed on a customer's server
- The Android client (`app/`) and Desktop client
- The deployment configs (`deploy/`, `docs/DOCKER.md`/`DEPLOY.md`)

It does not apply to non-security bugs (crashes, UI issues, etc.) — those follow the normal
issue tracker / `docs/TODO.md` workflow, no embargo or disclosure process needed.

## Severity levels

| Level | Definition | Example |
|---|---|---|
| **Critical** | Remotely exploitable, breaks message confidentiality or authentication with no user action required | A crypto flaw that lets the server (or a network attacker) read message content; an auth bypass that lets an attacker register under someone else's fingerprint |
| **High** | Breaks a documented security property, but requires a specific precondition (local access, a compromised contact, a misconfiguration) | A metadata leak like [item 31/32's history](SECURITY.md) before they were fixed; a privilege-escalation path in `GroupManager` |
| **Medium** | Weakens a defense-in-depth layer without breaking the core guarantee it backs up | A rate-limit bypass that doesn't itself leak data; a padding gap that narrows but doesn't eliminate traffic-analysis resistance |
| **Low** | Deviation from a documented invariant with no practical exploit path found, or a hardening gap already listed under [Known Limitations](SECURITY.md#known-limitations) | Most entries in `docs/SECURITY_INVARIANTS.md` failing in a way that requires an already-privileged attacker |

Severity is assigned by the maintainer at triage time, using judgment against this table — it is
a starting point, not a rigid formula. When in doubt, treat it as more severe until proven
otherwise; downgrading later is cheap, upgrading a public disclosure after the fact is not.

## Reporting a vulnerability

There is currently no dedicated `security@` inbox or PGP key — for now, report privately via a
[GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories) on this
repository, or a direct message to the maintainer through an existing customer support channel.
**Do not open a public GitHub issue for a Critical or High finding** — that is a disclosure, not
a report.

*(Setting up a dedicated `security@` address and a published PGP key is a real gap in this
process — flagged here rather than silently assumed to already exist. Should happen before this
document is pointed to from a public-facing page.)*

## Embargo period

- **Critical**: fix developed and deployed to the maintainer's own reference infrastructure
  immediately on confirmation; **all self-hosting customers notified directly** (email/existing
  support channel) with the fix and an upgrade deadline **before** any public disclosure,
  changelog entry, or commit message that would let an outside observer reconstruct the issue.
  Target: notify customers within 72 hours of confirming the report is real.
- **High**: same private-notification-first approach, target within 7 days of confirmation.
- **Medium/Low**: fixed in the normal release cadence, documented in
  `SECURITY_CHANGELOG.md`/`KNOWN_SECURITY_ISSUES.md` as usual — no embargo needed, since these
  don't hand an attacker an immediately exploitable path.

**Why private notification before public disclosure, specifically for a self-hosted product**:
unlike a SaaS the maintainer operates, each firm runs its own server — a public disclosure (even
a vague one) starts a countdown before every unpatched deployment is a known target, and the
maintainer cannot push a fix to a customer's server unilaterally. Customers must hear about a
Critical/High issue, and get the fix, before the issue becomes public knowledge, not after.

## What "supported" means

Given the solo-maintainer reality, there is no multi-version support matrix — **the only
supported version is the latest `main`**. A self-hosted deployment that hasn't been updated in a
long time is not covered by embargo-period notification in the same way (the maintainer has no
way to know an old, unpatched deployment still exists, unlike an active support customer). This
is a real limitation, not a hidden one — see the `Support_Maintenance_Agreement.md` for what an
active subscription actually commits to versus what running the open-source code alone does not.

## Process, step by step

1. **Triage**: confirm the report reproduces, assign a severity level (table above).
2. **Fix**: developed against `main`, following the project's existing verification bar — a fix
   isn't "done" until it's actually been run (compiled/tested), not just eyeballed (see this
   project's own repeated "not just `ast.parse`" pattern in `docs/TODO.md` for why that bar
   exists).
3. **Regression test**: for Critical/High findings, add a test to
   `Server/tests/test_security_invariants.py` (or the Android equivalent) that would have caught
   it — the project already tracks its 8 core security invariants this way; a Critical/High
   finding is exactly the kind of thing that belongs as invariant #9, #10, etc.
4. **Notify** (Critical/High only): customers first, per the embargo section above.
5. **Publish**: after the embargo window (or immediately, for Medium/Low), document in
   `SECURITY_CHANGELOG.md` with the same level of detail this project already uses for its own
   self-found issues — dated, with root cause and fix described, not just "security fix."
6. **Credit**: the reporter is credited by name (if they want to be) in the changelog entry,
   unless they ask to stay anonymous.

## Compromised-key procedure

If the server's TLS key, the sender-certificate signing key
(`secrets/sender_cert_signing_key.pem`, see [SECURITY.md item 32](SECURITY.md)), or a customer's
identity key material is suspected compromised:

1. Rotate the key immediately on the affected deployment — TLS cert reissue, or
   `secrets/sender_cert_signing_key.pem` deletion (server regenerates a fresh one on next start,
   per `_load_or_create_cert_signing_key()`).
2. Treat this as Critical severity regardless of how the compromise happened — a compromised
   signing key silently defeats the guarantee it backs (TLS pin or sealed-sender cert
   verification) with no other symptom.
3. Notify affected customers per the Critical-severity embargo timeline above — they need to
   know their pinned key changed, or client builds with the old pin will hard-fail (pinning is
   deliberately fail-closed, see `CertificatePinner`/`SenderCertManager` scope notes in
   `SECURITY.md`).

---

*This document itself should be revisited the first time it's actually used for a real report —
a process nobody has exercised is a guess, not a plan. Update this file with anything that turned
out to be missing or wrong the first time.*
