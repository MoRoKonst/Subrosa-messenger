# Beacon Messenger

A self-hosted end-to-end encrypted messenger for Android with metadata protection, anonymous routing, and advanced anti-forensics.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Privacy Architecture](#privacy-architecture)
- [Requirements](#requirements)
- [Docker Deployment (Recommended)](#docker-deployment-recommended)
- [Self-Hosting (Manual)](#self-hosting-manual)
- [Build Instructions](#build-instructions)
- [Quick Start](#quick-start)
- [Security Overview](#security-overview)
- [Documentation](#documentation)

---

## Overview

Beacon is a self-hosted encrypted messenger built for adversarial environments. Unlike most messengers that protect only message content, Beacon also protects **who talks to whom** — the social graph — through anonymous token routing, cover traffic, and Tor hidden service support.

The server never has access to plaintext messages, user identities, keys, or call content. All cryptographic operations happen on the client.

**Min Android:** 8.0 (API 26)  
**Target SDK:** 34  
**Language:** Kotlin (Jetpack Compose), Python 3 (server)

---

## Features

### Messaging
- One-to-one encrypted text messages
- Voice messages
- Image and file transfer (chunked, up to 6 MB per chunk)
- Disappearing messages with configurable TTL
- Message reactions, edit, delete
- Reply-to threading
- Read receipts and delivery status
- Message drafts

### Groups
- Encrypted group chats
- Per-group AES-256 key, distributed encrypted per member
- Admin and member roles
- Group descriptions and emoji avatars
- Key rotation on member removal

### Voice & Video Calls
- WebRTC peer-to-peer audio and video
- TURN relay over TCP (port 4433) for NAT traversal
- Call signaling via server — no media passes through server

### Contacts & Invitations
- ECDSA-signed invite codes with 7-day TTL
- QR code sharing
- Contact fingerprint verification (out-of-band MITM protection)
- Contact avatar (128×128 JPEG)

### Security
- Full Signal Protocol: X3DH key agreement + Double Ratchet v3 (DH + Symmetric Ratchet)
- Forward secrecy and break-in recovery on every message exchange
- Double encryption at rest: AndroidKeyStore + Storage Master Key (AES-256)
- Biometric unlock
- Panic password (triggers silent wipe on login attempt)
- Panic button notification (wipe accessible from locked screen)
- Three-level wipe: SOFT / HARD / NUCLEAR
- Decoy mode (post-wipe fake account)
- Dead Man's Switch with configurable check-in interval
- Paranoid Mode (logcat suppression, remote alert HTTP POST)
- Intrusion detection: proxy, user CA, VPN, ADB, developer options
- Anti-debugging checks
- Screen capture prevention (`FLAG_SECURE`)
- Root detection
- Certificate pinning

### Backup
- Full encrypted backup including identity keypair (preserves fingerprint across wipe+restore)
- AES-256-GCM + Argon2id (m=64 MB, t=3) — resistant to GPU brute-force
- Export to file or share sheet

---

## Privacy Architecture

Most messengers protect message *content* but not *metadata* — the server still sees who talks to whom, when, and how often. Beacon addresses this with four independent layers:

### 1. Anonymous Token Routing

Messages are addressed by single-use random tokens, not by user fingerprints. The server maintains only a `token → WebSocket` mapping with no identity binding. After delivery, tokens are discarded.

```
Standard:  { "from": "A1B2C3D4", "to": "9F8E7D6C", "text": "<encrypted>" }
Beacon:    { "type": "anon_message", "token": "e39f0134...", "payload": "<encrypted>" }
```

The server sees an anonymous blob — not a `from → to` pair. Note this hides the *recipient* side of the graph edge, not the sender: the server always knows which authenticated connection (i.e. which fingerprint) sent a given `anon_message`, since sending requires an authenticated WebSocket session. What it can no longer determine is who that message was *for*.

### 2. Anonymous Mailbox (First Contact)

The first message would normally reveal the `A → B` pair. Beacon solves this with an anonymous mailbox embedded in every invite code. Bob deposits an encrypted blob into Alice's mailbox; Alice fetches it along with 19 fake tags — the server cannot determine which tag is real.

### 3. Cover Traffic

Timing correlation attacks remain possible even without identity data. In Aggressive mode, Beacon sends a constant-rate stream (1 packet/sec); real messages replace noise packets. An observer sees a uniform stream regardless of actual communication.

| Mode | Interval | Traffic |
|---|---|---|
| Off | — | real messages only |
| Moderate | 1 packet / 5 sec | ~2–3 MB/hour |
| Aggressive | 1 packet / sec | ~20–30 MB/hour |

Noise packets are structurally identical to real messages — same type, random token, padded payload.

### 4. Tor Hidden Service

The server exposes a `.onion` address. Traffic travels entirely within the Tor network — no exit nodes, no IP exposure, no Cloudflare in the chain. The app uses Orbot and automatically selects the correct proxy mode for `.onion` vs clearnet addresses.

### Threat Model Summary

| Observer | Without Beacon | With Beacon |
|---|---|---|
| Server / leaked logs | `from → to` graph, content | Sender identity per connection still visible; recipient side hidden (anonymous blobs and tokens) |
| Malicious server operator | `from → to` graph, content | Token routing table (mitigated by self-hosting) |
| Sender's ISP | Server IP, timing, volume | Encrypted Tor traffic |
| Recipient's ISP | Server IP, timing, volume | Encrypted Tor traffic |
| Both ISPs simultaneously | Timing correlation | Statistically much harder (constant-rate) |
| Targeted attack (MITM, device) | Everything | Content protected by E2EE |

---

## Requirements

### Client
- Android 8.0+ (API 26)
- Google Play Services (optional, for push notifications)
- Orbot (optional, for Tor hidden service)
- Camera and microphone permissions for calls

### Server
- Python 3.10+
- `websockets` and `cryptography` libraries
- Accessible IP with port 443 (WSS via reverse proxy)
- TURN server for NAT traversal (coturn recommended)

---

## Docker Deployment (Recommended)

The easiest way to self-host Beacon is with Docker and Docker Compose.

**Quick Start:**
```bash
# 1. Clone repository
git clone https://github.com/MoRoKonst/beacon-messenger
cd beacon-messenger

# 2. Generate TLS certificates (development)
./generate-certs.sh

# 3. Configure environment
cp .env.example .env

# 4. Start server
docker compose up -d

# 5. Access at wss://your-domain/ws
```

**Features:**
- ✅ Single command deployment
- ✅ Automatic TLS termination (nginx)
- ✅ Data persistence (Docker volumes)
- ✅ Health checks built-in
- ✅ Production-ready configuration

**See [DOCKER.md](DOCKER.md) for:**
- Prerequisites and installation
- Configuration options
- TLS certificate setup
- Troubleshooting

**For production with Let's Encrypt, see [DEPLOY.md](DEPLOY.md)**

---

## Self-Hosting (Manual)

You can run your own Beacon server and connect the app to it — no recompilation needed.

**Note:** Docker deployment above is recommended. This section documents manual setup.

### 1. Deploy the server

**Without Docker:**

```bash
cd ForEXP
pip install websockets cryptography
python server.py --dev
```

### 2. Configure nginx (reverse proxy + TLS)

```nginx
location /ws {
    proxy_pass http://127.0.0.1:9000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;
}
```

### 3. Connect the app to your server

No rebuild required. In the app:

1. Go to **Profile → Servers**
2. Tap **+** to add a server
3. Enter your server hostname and port
4. Tap the server to switch — the app reconnects immediately

---

## Build Instructions

### Prerequisites
- Android Studio Hedgehog (2023.1) or newer
- JDK 17
- Android SDK with API 34

### Steps

```bash
git clone https://github.com/MoRoKonst/beacon-messenger
cd beacon-messenger

# Debug APK
./gradlew assembleDebug

# Release APK (requires signing config)
./gradlew assembleRelease
```

The release APK is output to `app/build/outputs/apk/release/`.

### Signing

```kotlin
signingConfigs {
    create("release") {
        storeFile = file("your-keystore.jks")
        storePassword = System.getenv("KEYSTORE_PASSWORD")
        keyAlias = "messenger"
        keyPassword = System.getenv("KEY_PASSWORD")
    }
}
```

---

## Quick Start

1. Install the APK from [Releases](https://github.com/MoRoKonst/beacon-messenger/releases).
2. Open the app and register a username and password.
3. Share your invite code with a contact (`beacon://invite?...`).
4. Verify your contact's fingerprint out-of-band (optional but recommended).
5. Start messaging.

**To use your own server:** see [Self-Hosting](#self-hosting), then add your server in **Profile → Servers**.

---

## Security Overview

| Layer | Mechanism |
|---|---|
| Transport | WSS (TLS 1.2+) with certificate pinning |
| Key agreement | X3DH (Identity Key + Signed Prekey + One-Time Prekey) |
| Message E2EE | Double Ratchet v3 — DH Ratchet + Symmetric Ratchet, AES-256-GCM |
| Forward secrecy | Per-message keys; break-in recovery on every DH step |
| Social graph | Anonymous token routing — server sees no `from → to` pairs |
| Timing | Constant-rate cover traffic (optional) |
| IP address | Tor hidden service via Orbot (optional) |
| At-rest (L1) | EncryptedSharedPreferences + AndroidKeyStore |
| At-rest (L2) | Storage Master Key, AES-256-GCM |
| Backup | AES-256-GCM + Argon2id (m=64 MB, t=3, p=1) |
| Key authentication | ECDSA (SHA256withECDSA) + out-of-band fingerprint verification |
| Invalid curve attack | EC point validation on all imported public keys |

See [SECURITY.md](SECURITY.md) for the full threat model and cryptographic specification.  
See [ARCHITECTURE.md](ARCHITECTURE.md) for the system design and module reference.

---

## Documentation

### Deployment & Hosting

| Document | Audience | Description |
|---|---|---|
| [DOCKER.md](DOCKER.md) | All (recommended) | Quick start with Docker — 5 minutes to running server |
| [DEPLOY.md](DEPLOY.md) | SysAdmins | Production deployment, Let's Encrypt, auto-renewal |
| [CHECKLIST.md](CHECKLIST.md) | DevOps | Pre/post deployment verification steps |

### Technical & Security

| Document | Audience | Description |
|---|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Developers | System design, module reference, data flows |
| [SECURITY.md](SECURITY.md) | Security analysts | Threat model, cryptographic design, anti-forensics |
| [CHANGEL_LOG.md](CHANGEL_LOG.md) | Developers | Engineering change log |
