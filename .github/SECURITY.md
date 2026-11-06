# Security Policy

This is the **vulnerability reporting policy**. For how the system is designed —
threat model, key hierarchy, protocol — see
[docs/SECURITY.md](../docs/SECURITY.md). For what is already known to be wrong,
see [docs/KNOWN_SECURITY_ISSUES.md](../docs/KNOWN_SECURITY_ISSUES.md) before
reporting, so neither of us spends time on a finding that is already recorded.

## Reporting

**Preferred:** GitHub private vulnerability reporting — the *Report a
vulnerability* button on the [Security
tab](https://github.com/MoRoKonst/Subrosa-messenger/security). It is private
until we publish, it threads, and it does not depend on an inbox being watched.

**Alternative:** `security@subrosamessenger.com`.

Please do **not** open a public issue for a vulnerability, and do not report it
through the app itself — the app is the thing under discussion.

## What to expect

This is a single-maintainer project, and the timelines below are what one person
can actually honour rather than what sounds reassuring:

| | Target |
|---|---|
| Acknowledgement of your report | 72 hours |
| Initial assessment (valid / not / need more) | 7 days |
| Fix or a dated plan for one | 90 days from acknowledgement |

If a report goes unanswered past those windows, escalate by opening a public
issue that says only "unanswered security report, sent `<date>`" — with no
detail. That is a legitimate way to get attention and will not be treated as a
violation of this policy.

## Scope

**In scope**

- The Android client in `app/` and the desktop client in `desktop/`.
- The server in `Server/`, and the deployment configuration in `deploy/`.
- The cryptographic protocol itself — session establishment, the ratchet, the
  post-quantum hybrid, group keys, the backup container. Design flaws are as
  welcome as implementation bugs, and are more valuable.
- The anti-forensic features behaving differently from their documentation:
  duress password, decoy mode, wipe levels, the tamper canary. A claim in
  `docs/SECURITY.md` that does not hold is a valid report even with no memory
  corruption anywhere near it.

**Out of scope**

- The production server at `api.subrosamessenger.com`: do not test against it.
  Run your own instance — `docs/DEPLOY.md` and `docs/DOCKER.md` cover it. Load
  testing or availability attacks against the live service are not authorised
  and are not what this policy invites.
- Findings that require an already-compromised device (root, an active
  debugger, a malicious keyboard or accessibility service), unless you can show
  they break a guarantee this project actually claims. The documented threat
  model deliberately excludes a compromised endpoint; see "Out of scope" in
  `docs/SECURITY.md`.
- Anything already in `docs/KNOWN_SECURITY_ISSUES.md`. Those are recorded with
  their reasoning; if you disagree with a recorded decision, that is a
  discussion, not a vulnerability report — open a public issue for it.
- Automated scanner output with no demonstrated impact, missing hardening
  headers on static pages, and reports whose entire content is a CVSS score.

## Rewards

**There is no bug bounty.** This project has no revenue yet and promising
payment it cannot make would be worse than saying so. What is offered instead:

- Credit in the fix commit and in the release notes, under whatever name or
  handle you choose, or no credit if you prefer.
- A CVE requested on your behalf where one is warranted.
- An honest writeup of the finding in `docs/KNOWN_SECURITY_ISSUES.md`,
  including the parts that are unflattering. Every entry in that file follows
  that rule already.

If that changes, this section changes with it.

## Safe harbour

If you follow this policy — report privately, stay off the production server,
use only accounts and instances you control, do not access or exfiltrate
anyone else's data, and give the timelines above a chance — then as far as this
project is concerned your research is authorised and welcome, and no action
will be sought against you for it.

Two honest limits on that promise: it binds this project only, not third
parties whose infrastructure you might touch on the way, and it cannot
override the law where you or the project operate.

## Disclosure

Coordinated, and the default is that findings get published. Once a fix ships —
or at 90 days, whichever comes first — the finding goes into
`docs/KNOWN_SECURITY_ISSUES.md` with its severity and residual risk. If you
want to publish your own writeup, that is yours to do; tell us the date so the
fix and the writeup do not surprise each other. If a fix is going to take
longer than 90 days you will be told why, in writing, before the deadline
rather than after it.
