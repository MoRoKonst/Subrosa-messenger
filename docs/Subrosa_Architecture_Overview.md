# Subrosa — Architecture & Security Overview

**Self-hosted encrypted messaging for firms that cannot afford a leak.**

*A concise technical overview for IT and security teams evaluating Subrosa for privileged communication.*

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

Subrosa is a **self-hosted** messenger. Your firm runs the server. No third party — including us — ever holds your data or metadata.

| Property | Signal / WhatsApp | Subrosa |
|---|---|---|
| Message content encrypted (E2EE) | ✅ | ✅ |
| Server operator | Third party | **Your firm** |
| Metadata (who↔whom) visible to server | ✅ Yes | ❌ **No — anonymously routed** |
| Data at rest on a seized device | Single-layer | **Double-encrypted** |
| Duress / panic protection | ❌ | ✅ **Silent wipe** |
| Auditable source | Partial | ✅ **Fully open-source** |

---

## 3. Security Architecture

### 3.1 Message Encryption — Double Ratchet (Signal Protocol)

Subrosa uses the **Double Ratchet algorithm** with X3DH key agreement — the same proven cryptography that underpins Signal. This provides:

- **End-to-end encryption** — only the participating devices can read messages
- **Forward secrecy** — a compromised key cannot decrypt past messages
- **Break-in recovery** — the protocol self-heals after a key compromise

This is a peer-reviewed, industry-standard construction. It is not a homegrown scheme.

### 3.2 Metadata Protection — Anonymous Routing

The server routes messages using **anonymous tokens**, not sender→recipient pairs. It never sees a mapping of who a message is *for*. The sender's identity is still visible per connection — sending requires an authenticated session, same as with any server-mediated messenger, Signal included — but that identity can no longer be tied to a specific recipient, so the firm's communication graph (who talks to whom) can't be reconstructed from server logs or routing tables alone.

### 3.3 Data at Rest — Double Encryption

Local data on each device is protected by **two independent encryption layers**:

1. The OS-backed encrypted store (Android Keystore / hardware-backed)
2. A separate **Storage Master Key** derived from the user's password (PBKDF2, 300,000 iterations) and independently wrapped in hardware

A device seized in an unlocked state still does not surrender message history without the second factor. Keys are held in memory only and zeroed on lock.

### 3.4 Duress Protection — Panic Password

A user under coercion can enter a **duress password**. Instead of unlocking, it silently and irreversibly wipes all sensitive data in the background while showing a plausible decoy — with no visible indication that a wipe occurred.

### 3.5 Threat Detection

The client detects and warns on a compromised environment — rooted device, active debugger, injection frameworks (Frida/Xposed), or emulator — before sensitive data is exposed.

---

## 4. Deployment

Subrosa is designed to be deployed by your own IT team, on your own infrastructure, with no dependency on us.

- **Server:** Python asyncio WebSocket server, containerized
- **Setup:** `docker compose up` — approximately **15 minutes** for a standard deployment
- **Requirements:** A Linux host and a TLS certificate. Optional TURN server for voice/video calls.
- **Clients:** Android (full-featured). A desktop companion client is in development.

Because the server is yours, there is no per-message dependency on a vendor, no data residency question, and no third-party outage that can take your firm's communication down.

---

## 5. Open Source & Auditability

The core is **fully open-source**. Your IT or security team can:

- Read every line of the client and server code
- Verify there is no backdoor, telemetry, or hidden data exfiltration
- Build and deploy from source if firm policy requires it

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
