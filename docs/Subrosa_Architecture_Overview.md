# Subrosa — Architecture & Security Overview

**Self-hosted encrypted messaging for firms that cannot afford a leak.**

*A concise technical overview for IT and security teams evaluating Subrosa for privileged communication.*

*Last verified against commit: `aeb1ddf` (2026-08-23) — cross-checked against `SECURITY.md`, the source of truth for this project's actual security posture. If claims here and in `SECURITY.md` ever disagree, `SECURITY.md` is correct.*

---

## 1. The Problem: Encryption Is Solved, Metadata Is Not

Modern messengers (Signal, WhatsApp) encrypt message *content* well. That is not where privileged communication leaks.

The exposure is **metadata** — the record of *who* communicated with *whom*, *when*, and *how often*. This data:

- Is held by a third party (Meta, a cloud provider) outside your control
- Is subject to subpoena, government request, or breach — often **without notice to you or your client**
- Can compromise a client even when no message content is ever read. A pattern of contact between a defense lawyer and a specific individual, at specific times, is itself discoverable evidence.

For a law firm, metadata held by a third party is an **unmanaged liability**.

---

## 2. What Subrosa Does Differently

Subrosa is a **self-hosted** messenger. Your firm runs the server, and message content and the vast majority of routing metadata never leave it. The one narrow, optional exception is covered in [3.2](#32-metadata-protection--anonymous-routing) below.

| Property | Signal / WhatsApp | Subrosa |
|---|---|---|
| Message content encrypted (E2EE) | ✅ | ✅ |
| Server operator | Third party | **Your firm** |
| Metadata (who↔whom) visible to server | ✅ Yes | ⚠️ **Anonymously routed for nearly everything — documented exceptions below** |
| Data at rest on a seized device | Single-layer | **Double-encrypted** |
| Duress / panic protection | ❌ | ✅ **Silent wipe** |
| Auditable source | Partial | ✅ **Open-source Android client and server** (a feature-complete desktop client exists but isn't published yet) |

---

## 3. Security Architecture

### 3.1 Message Encryption — Double Ratchet, Extended

Subrosa uses **X3DH key agreement and the Double Ratchet algorithm** — the same peer-reviewed, industry-standard construction that underpins Signal, not a homegrown replacement. This provides:

- **End-to-end encryption** — only the participating devices can read messages
- **Forward secrecy** — a compromised key cannot decrypt past messages
- **Break-in recovery** — the protocol self-heals after a key compromise

Around that standard core, Subrosa adds two extensions. The first, a hybrid post-quantum key exchange (ML-KEM-768 alongside the classical exchange), follows the same design reasoning as Signal's own published PQXDH — it isn't an invented approach, though this project's specific implementation of it (built independently, not using Signal's own libsignal code) hasn't itself been independently audited. The second, the anonymous token-routing/mailbox layer in 3.2, *is* original protocol-design work by this project, not derived from Signal or another peer-reviewed anonymity standard, and likewise unaudited — see `SECURITY.md` for the exact scope of what has and hasn't been reviewed.

### 3.2 Metadata Protection — Anonymous Routing

The server routes messages using **anonymous tokens**, not sender→recipient pairs, for 1:1 text, calls, reactions, edits, and file/voice/video transfer. It doesn't see a mapping of who a message is *for* on that traffic. The sender's identity is still visible per connection — sending requires an authenticated session, same as with any server-mediated messenger, Signal included — but that identity can no longer be tied to a specific recipient for the traffic types above, so the firm's communication graph (who talks to whom) can't be reconstructed from server logs or routing tables for most day-to-day use.

Two documented, narrow exceptions, disclosed here rather than left for an audit to find:

- **Group calls** are always routed directly (fingerprint-addressed), not anonymized — a deliberate trade-off, not an oversight, made after anonymized group-call signaling proved unreliable in testing. 1:1 calls do not have this exception.
- **Contact-list padding cost**: when a client needs to fetch someone's prekey bundle to start (or resume) a session, it disguises the real request among decoy requests drawn from its own contact list, so the server can't tell which one is real. That protection has a cost: the server sees the requester's *full contact list* as padding during that fetch. This is a real, structural property of the anonymization scheme, not a bug — full technical detail and residual gaps are in `SECURITY.md`, item 11.

### 3.3 Push Notifications — Optional, Third-Party (Firebase Cloud Messaging)

Android kills background services without a system-level wake mechanism, so reliable delivery while the app isn't in the foreground needs a push provider — Subrosa uses Firebase Cloud Messaging (FCM), the same mechanism nearly every Android app relies on for this. This is genuinely a third party (Google) in the data path, and worth being explicit about rather than glossing over:

- FCM carries **no message content** — pushes are silent wake-up signals (or, for missed-call and session-conflict alerts, minimal operational metadata), never plaintext or ciphertext of a conversation.
- Google does see, at minimum, a recipient's FCM token and the timing of a push to that device — a limited signal, but a real one, and it is a third party your firm does not control.
- **FCM is optional at the server level**: if `GOOGLE_APPLICATION_CREDENTIALS` isn't configured on your deployment, the server's FCM code path is inert and no push is ever sent — background delivery then depends entirely on the app's own reconnect behavior instead. This is a real deployment choice with a real reliability trade-off, not a toggle we'd recommend blindly flipping off for a working desk phone replacement, but it exists for firms whose policy requires it.

### 3.4 Data at Rest — Double Encryption

Local data on each device is protected by **two independent encryption layers**:

1. The OS-backed encrypted store (Android Keystore / hardware-backed)
2. A separate **Storage Master Key** derived from the user's password (PBKDF2, 300,000 iterations) and independently wrapped in hardware

The Storage Master Key is held in memory only while the app is actively unlocked, and is zeroed the moment either the phone's own screen lock or the app's separate auto-lock timer fires — a device seized after either of those has triggered (including simply having been screen-locked at some point since last use) does not surrender message history without the password. A device seized *mid-use*, with the app still actively open and unlocked at that exact moment, is a narrower and honestly-acknowledged exception: the key is genuinely resident in RAM until lock triggers, and extracting it in that window requires a further compromise (root or an exploit capable of a memory dump) — see `SECURITY.md`, Known Limitations item 2, for the precise scope of that gap.

### 3.5 Duress Protection — Panic Password

A user under coercion can enter a **duress password**. Instead of unlocking, it silently and irreversibly wipes all sensitive data in the background while showing a plausible decoy — with no visible indication that a wipe occurred.

### 3.6 Threat Detection

The client detects and warns on a compromised environment — rooted device, active debugger, injection frameworks (Frida/Xposed), or emulator — before sensitive data is exposed.

---

## 4. Deployment

Subrosa is designed to be deployed by your own IT team, on your own infrastructure, with no dependency on us.

- **Server:** a single Python asyncio WebSocket process. Docker is the documented quick-start path (`docker compose up`, roughly **15 minutes** for a standard deployment); a plain `systemd`-managed process behind `nginx` works identically and is what our own reference deployment runs.
- **Requirements:** A Linux host and a TLS certificate. Optional TURN server for voice/video calls.
- **Clients:** Android (full-featured, published, open-source). A desktop client (Windows/macOS/Linux) exists and is feature-complete internally — including its own set of hardening beyond what Android needs (on-screen keyboard against hardware keyloggers, clipboard history/cloud-sync exclusion, secure temp-file deletion) — but is **not yet published**; treat it as unavailable until it ships.

Because the server is yours, there is no per-message dependency on a vendor, no data residency question, and no third-party outage that can take your firm's communication down.

---

## 5. Open Source & Auditability

The **Android client and server are open-source today**. Your IT or security team can:

- Read every line of the Android client and server code
- Verify there is no backdoor, telemetry, or hidden data exfiltration
- Build and deploy from source if firm policy requires it

The desktop client is feature-complete internally but not yet published to the repository — treat it as closed-source until it ships; this overview will be updated the day it's public.

Repository: **https://github.com/MoRoKonst/Subrosa-messenger**

For a firm handling privileged material, this auditability is not a bonus — it is the baseline requirement. You do not have to trust our word; you can verify.

---

## 6. What a Subscription Includes

The source is free. A Subrosa subscription covers the operational layer that a firm handling sensitive matters actually needs:

- **Deployment & onboarding support** — we get your server running and your team migrated
- **Security updates & advisories** — you are notified and patched when the threat landscape changes
- **Priority incident support** — a direct line if something goes wrong, with a defined response time
- **A named point of responsibility** — someone accountable, which matters when the communication carries professional and ethical weight
- **Optional managed hosting** — for firms without dedicated IT, we can run the server for you under agreement

In short: the code guarantees you *can* verify and control everything. The subscription guarantees you don't have to do it alone, and that someone is responsible when it counts.

---

## 7. Suggested Next Step

1. Review this overview and the source repository with your IT team.
2. Deploy a trial instance via Docker (~15 minutes) — we provide the quick-start guide.
3. Run it internally for a pilot group.

Everything can be handled over email — no call required. When you're ready, reply and we'll send the quick-start guide and trial credentials.

---

*Subrosa — you control the server, not a corporation.*
