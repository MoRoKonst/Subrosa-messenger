# Subrosa — Pricing

Subrosa's source code is free and open. What a subscription buys is the operational layer a firm handling sensitive matters actually needs: painless deployment, security kept under watch, and a named support and security contact when something goes wrong.

Pricing is **per firm, not per user**. You run the server; create as many accounts as you need. What you pay for is the scope of support and operation.

---

## Plans

### 🟢 Solo — $199 / month
For a solo practitioner or a small team.

- Ready-to-run Docker deployment with hands-on help for your first setup
- Security updates and threat advisories
- Support for one server instance
- Direct help for one designated administrator on your side
- Email support, response within 48 hours

### 🔵 Firm — $499 / month
For a law firm, NGO, newsroom, or investigative team.

- Everything in Solo
- Priority support, response within 24 hours
- Production setup assistance (TLS, firewall, backups)
- Help configuring workstations for your whole team
- Annual Deployment Security Review (see scope below)
- Threat-model consultation tailored to your work

### ⚫ Managed — from $999 / month
For teams without in-house IT.

- Everything in Firm
- **The server runs on your own cloud account**, registered under your firm's name (AWS, Hetzner, DigitalOcean, or your choice)
- We receive scoped access solely to deploy, monitor, and update — nothing more
- Monitoring, backups, and patching during business hours (UTC+7) come with the response times listed above. Outside those hours, we still respond to critical issues as fast as we can — we just don't promise a fixed response time for that window
- You never touch the technical layer — and you always own the infrastructure and the data
- 12-month minimum commitment — onboarding a managed cloud deployment has real setup cost on our side

> With Managed, the infrastructure is legally and physically yours. If you ever want us gone, you revoke access and the server keeps running. We operate it; we never own it. Pricing starts at $999 and scales with infrastructure complexity and required support hours — quoted after a short call about your setup. Offered to a limited number of clients at a time, so response times stay meaningful.

**Why the jump from Firm's $499 to Managed's $999+, not a smaller step:** Firm is a support subscription — you still run your own server. Managed means we're the on-call party for infrastructure we don't control the timezone or workload of; a thin markup there would either force 24/7 availability we can't actually deliver as a small team, or quietly under-deliver on it. The price reflects the real cost of that responsibility, not padding.

---

## One-time services

| Service | Price | When |
|---|---|---|
| Turnkey setup (one-time) | $200–300 | Solo plan with full "done-for-you" installation |
| Deployment Security Review | $300–500 | Annual, for compliance peace of mind |
| Team onboarding (async: video + docs) | $150 | When rolling out to a firm |

**What "Deployment Security Review" means** — a review of *your specific deployment's* configuration: TLS setup, firewall rules, server hardening, access controls, backup handling, and whether you're running current, unpatched code. It is not a source-code security audit of the Subrosa codebase itself (the code is open — anyone, including an independent third party your firm hires, can audit that directly) and not a penetration test. If your compliance process requires a formal code audit or pentest, that's a separate, explicitly-scoped engagement.

---

## Annual billing

Pay annually and get roughly two months free (pay for 10, get 12):

- **Solo:** $1,990 / year (vs. $2,388)
- **Firm:** $4,990 / year (vs. $5,988)

---

## Common questions

**Why pay if the code is free?**
The code is open so you can verify it and trust no one on their word. A subscription is what the code cannot give you: deployment without spending your own time, security updates as new threats emerge, and a named support and security contact when something goes wrong. You're not paying for software — you're paying to not have to run it yourself. (See the Support & Maintenance Agreement for exactly what "responsibility" means in scope and liability terms — this page describes the service, that document is the binding one.)

**What if you disappear?**
The code is open and the server is yours. Even if Subrosa vanished tomorrow, your infrastructure keeps running, and any developer can maintain it. You are never locked in.

**Isn't this expensive for our practice?**
A single leak of privileged communication is a disciplinary matter and a lost client. A subscription is insurance against a scenario that costs orders of magnitude more.

**Can you build a custom feature for us, like a translation to another language?**
Yes, for a separately quoted fee scoped to the request. The one condition: once built, it's merged back into the open-source codebase and becomes available to every Subrosa deployment — we don't maintain private forks or client-exclusive functionality. That's what keeps the project a single auditable codebase instead of fragmenting into untrusted variants, and it means your firm's contribution benefits every other firm running Subrosa, not just yours.

---

## Getting started

1. Reply and we'll send a short architecture overview and a quick-start guide.
2. Deploy a trial instance via Docker (~15 minutes) — we provide the guide and help.
3. Run a pilot internally. If it's a fit, we set up billing and a service agreement.

Everything can be handled over email — no call required.
