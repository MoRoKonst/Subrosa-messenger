# Consulting

I do security-focused engineering work on Android applications, open-source
release pipelines, and self-hosted communications infrastructure.

The simplest way to judge whether that is worth your money is to read this
repository. It is not a portfolio assembled to impress — it is the ordinary
working record of a project, including the parts that went wrong.
[`docs/KNOWN_SECURITY_ISSUES.md`](KNOWN_SECURITY_ISSUES.md) lists every defect
found in it, who found it, how severe it actually was rather than how severe it
sounded, and how it was verified afterwards. Several entries are mistakes I
made and then caught.

---

## What I do

### Android application security review

A bounded review of a shipped or pre-release Android app, delivered as a
written report: what I found, how reachable each issue actually is, and what to
do about it in priority order.

Not a certificate, and I will not pretend otherwise. One person reading code
carefully for a week finds a particular class of problem — the kind that lives
in the gap between what the code says and what it does. Recent examples from
this project, all found that way:

- A release build writing every correspondent's identity and message timing to
  the device log, because logging was never stripped. Present in a published
  APK, confirmed by searching the shipped bytecode rather than the source.
- "Disappearing messages" that restarted their own timer every time the chat
  was reopened, so a message set to vanish after an hour never did.
- A signature-tamper check reading a build flag from the wrong library
  entirely, because of an accidental IDE auto-import.
- 33 MB of native binaries shipped in every download for a library no code
  referenced.

**Typical scope:** one app, one platform, 3–5 working days.

### Open-source release and supply-chain hygiene

Getting a project to the point where a stranger can verify what you ship
instead of trusting you: reproducible or at least verifiable builds, F-Droid
packaging, dependency and repository audit, CI that actually tests what you
distribute rather than reporting green on a subset.

Concrete recent work, all in this repository's history: splitting a build so it
links no proprietary libraries, removing dependency repositories nothing
resolved from, adding the missing half of a CI pipeline that had been reporting
success while never compiling 24,000 lines of shipped client code.

**Typical scope:** 2–5 working days depending on how far the build is from
being reproducible by someone else.

### Self-hosted secure communications

Deploying and hardening a communications server you control, on infrastructure
registered to you. This is where Subrosa itself fits, but the work is mostly
independent of it: TLS, firewalling, at-rest encryption, backup handling,
access control, and an honest written account of what the result does and does
not protect against.

**Typical scope:** 1–3 days for a deployment, plus optional ongoing support.

---

## How I work

**Fixed scope, fixed price, agreed before I start.** If the work turns out to
be larger than scoped, I tell you before doing it, not after.

**You get the reasoning, not just the conclusion.** Every finding comes with
how I verified it and how severe it genuinely is. A report that inflates
everything to Critical is useless, because you cannot act on it.

**I will tell you when something is not a problem.** Several items in this
project's own issue register are recorded as "investigated, not a
vulnerability, here is why" — that is worth as much as a finding.

**Work on open-source code goes back upstream** unless there is a specific
reason it should not.

---

## What I am not

- Not a certification body. I cannot give you a compliance sign-off.
- Not a penetration tester. I read code and configurations; I do not run
  engagements against live infrastructure.
- Not a substitute for a funded audit by an established firm, if that is what
  your situation requires. If it is, I will say so.

---

## Rates

Day rate and fixed-price quotes on request, agreed per engagement before any
work starts. First engagements are priced lower in exchange for permission to
reference them — I am building a track record, and pretending otherwise would
waste your time and mine.

---

## Contact

Write with a short description of what you have and what you are worried
about. If it is not something I can do well, I will say so rather than take the
work.

📧 **developer@beacon-app.org**

(Beacon was this project's earlier name. The address is current and monitored;
the domain simply predates the rename.)
