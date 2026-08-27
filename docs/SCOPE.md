# Audit Scope

*What the first external security audit of Subrosa Messenger should prioritize, and what's
deliberately excluded. Written to be handed to an auditor alongside
[AUDIT_TARGET.md](AUDIT_TARGET.md), [THREAT_MODEL.md](THREAT_MODEL.md), and
[SECURITY_MODEL.md](SECURITY_MODEL.md).*

"Review everything" is not a scope. This document exists so the auditor spends time on the
highest-risk, least-independently-verified parts of the system, rather than reconstructing
priority from the codebase.

## Priority order

1. **Cryptographic protocol / key lifecycle** — X3DH + PQ-hybrid (ML-KEM-768) initial agreement,
   Double Ratchet, group-key distribution and rotation. See
   [SECURITY.md § Cryptographic Design](SECURITY.md#cryptographic-design).
2. **Device registration / recovery / revoke** — challenge-response identity binding, device-gated
   TOTP, recovery-code atomicity. See
   [SECURITY.md § Authentication](SECURITY.md#authentication),
   [THREAT_MODEL.md § D](THREAT_MODEL.md#d-stolen-or-compromised-device--stolen-backup).
3. **Group membership and key rotation** — `GroupManager` authorization, removed-member exclusion
   from rotated keys. See [THREAT_MODEL.md § B, C](THREAT_MODEL.md).
4. **Message delivery / ACK / pending state** — `token_pending` lifecycle, ACK ownership, replay
   rejection. See [THREAT_MODEL.md § A, B](THREAT_MODEL.md).
5. **Authentication / authorization** — server handshake, per-message-type authorization in
   `Server/server.py`.
6. **Replay protection** — anonymous token single-use (`spent_tokens`), recovery/access-code
   single-use.
7. **Async concurrency / database atomicity** — `Server/server.py`'s `asyncio.Lock()` usage,
   `BEGIN IMMEDIATE` transactions for registration cap and code redemption. See
   `Server/tests/test_security_invariants.py` for what's already regression-tested.
8. **Rate limiting / abuse controls** — per-message-type limits, PoW on new-identity registration,
   `MAX_REGISTERED_USERS`.
9. **Security-critical Android key storage** — Storage Master Key double-encryption, AndroidKeyStore
   usage. See [SECURITY.md § Double Encryption at Rest](SECURITY.md#double-encryption-at-rest-smk).
10. **Server trust boundaries** — what the server can see/change vs. what it cryptographically
    cannot. See [THREAT_MODEL.md § E, F](THREAT_MODEL.md).

## What this scope explicitly does not prioritize

Not because these don't matter, but because they carry less risk relative to the areas above, or
have already-known, documented limitations that don't need re-discovery:

- UI polish / visual bugs.
- Non-security analytics.
- Marketing site / README / pitch-deck copy (separately reviewed for overclaiming this session,
  see `docs/TODO.md`'s documentation section).
- Legacy/unused code paths already identified as dead (Channels feature — disabled at the UI layer,
  see `ARCHITECTURE.md`).
- Anonymous-routing metadata leaks already self-identified and documented as residual risk, not
  claimed as solved — see [SECURITY.md Known Limitations #11–12](SECURITY.md#known-limitations)
  and [THREAT_MODEL.md § E](THREAT_MODEL.md#e-compromised-or-malicious-server-operator). Confirming
  or extending this analysis is welcome, but it's a known-imperfect area, not a surprise finding.
- Desktop client — functionally mature but not yet published in this repository
  (`/desktop/` is gitignored); a static audit of it is a separate, not-yet-started item in
  `docs/TODO.md`.

## Out of scope entirely (see [SECURITY_MODEL.md](SECURITY_MODEL.md) for the full non-goals list)

- IP-address anonymity from the server (no default Tor/mixnet routing).
- Defense against a fully compromised, unlocked endpoint with live RAM access.
- Timing-based traffic correlation.
- Supply-chain integrity of a distributed APK (no reproducible-build verification yet).
