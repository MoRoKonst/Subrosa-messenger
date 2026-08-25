# Subrosa Messenger

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
- [License](#license)

---

## Overview

Subrosa is a self-hosted encrypted messenger built for adversarial environments. Unlike most messengers that protect only message content, Subrosa also protects **who talks to whom** — the social graph — through anonymous token routing, cover traffic, and Tor hidden service support.

The server never has access to plaintext messages, private keys, or call content — all cryptographic operations happen on the client, and it doesn't learn who a given message is *for* (see [Privacy Architecture](#privacy-architecture) below for exactly what routing metadata it does and doesn't see). It does see each connection's authenticated public key/fingerprint at login, and persists which fingerprints have ever registered — that's not a civil identity, but it isn't nothing either; see [SECURITY.md](docs/SECURITY.md) for the precise threat model.

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
- X3DH key agreement + Double Ratchet v3 (DH + Symmetric Ratchet), extended with a hybrid post-quantum key exchange (ML-KEM-768) following the same reasoning as Signal's own published PQXDH design, plus anonymous token routing/mailbox on top. The ratchet and the PQ-hybrid *design* both trace back to Signal's own specifications; this project's own from-scratch *implementation* of the PQ hybrid (BouncyCastle-based, not libsignal) and the anonymous-routing/mailbox layer (an original protocol design, not from Signal) have not themselves been independently audited (see [SECURITY.md](docs/SECURITY.md))
- Forward secrecy and break-in recovery on every message exchange
- Double encryption at rest: AndroidKeyStore + Storage Master Key (AES-256)
- Biometric unlock
- Panic password (triggers silent wipe on login attempt)
- Panic button notification (wipe accessible from locked screen)
- Two-level wipe: HARD / NUCLEAR (a third, SOFT, existed early on and was removed — see `ARCHITECTURE.md`)
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

Most messengers protect message *content* but not *metadata* — the server still sees who talks to whom, when, and how often. Subrosa addresses this with four independent layers:

### 1. Anonymous Token Routing

Messages are addressed by single-use random tokens, not by user fingerprints. The server maintains only a `token → WebSocket` mapping with no identity binding. After delivery, tokens are discarded.

```
Standard:  { "from": "A1B2C3D4", "to": "9F8E7D6C", "text": "<encrypted>" }
Subrosa:    { "type": "anon_message", "token": "e39f0134...", "payload": "<encrypted>" }
```

The server sees an anonymous blob — not a `from → to` pair. Note this hides the *recipient* side of the graph edge, not the sender: the server always knows which authenticated connection (i.e. which fingerprint) sent a given `anon_message`, since sending requires an authenticated WebSocket session. What it can no longer determine is who that message was *for*.

Two documented exceptions: **group call signaling** always goes out directly (fingerprint-addressed), not through anon-token routing — a deliberate reliability trade-off, 1:1 calls don't have this exception. And the anti-fingerprinting mechanism used to fetch a contact's prekey bundle (padding the real request with decoys drawn from the requester's own contact list, since the server can't tell decoys from a real target otherwise) has a cost: the server sees the requester's full contact list during that fetch. See `SECURITY.md` items 11 and 18 for the full detail.

### 2. Anonymous Mailbox (First Contact)

The first message would normally reveal the `A → B` pair. Subrosa solves this with an anonymous mailbox embedded in every invite code. Bob deposits an encrypted blob into Alice's mailbox; Alice fetches it along with 19 fake tags — the server cannot determine which tag is real.

### 3. Cover Traffic

Timing correlation attacks remain possible even without identity data. In Aggressive mode, Subrosa sends a constant-rate stream (1 packet/sec); real messages replace noise packets. An observer sees a uniform stream regardless of actual communication.

| Mode | Interval | Traffic |
|---|---|---|
| Off | — | real messages only |
| Moderate | 1 packet / 5 sec | ~2–3 MB/hour |
| Aggressive | 1 packet / sec | ~20–30 MB/hour |

Noise packets are structurally identical to real messages — same type, random token, padded payload.

### 4. Tor Hidden Service

The server exposes a `.onion` address. Traffic travels entirely within the Tor network — no exit nodes, no IP exposure, no Cloudflare in the chain.

- **Android** uses Orbot and automatically selects the correct proxy mode for `.onion` vs clearnet addresses (Orbot's system-wide VPN mode vs its local SOCKS proxy).
- **Desktop** routes any `.onion` server URL through a local SOCKS5 proxy on `127.0.0.1:9050` (standard system Tor) or `127.0.0.1:9150` (Tor Browser's bundled tor), detected automatically. There's no VPN-mode ambiguity on desktop — you need Tor (the system service or Tor Browser) already running; the app does not launch it for you.

### Threat Model Summary

| Observer | Without Subrosa | With Subrosa |
|---|---|---|
| Server / leaked logs | `from → to` graph, content | Sender identity per connection still visible; recipient side hidden (anonymous blobs and tokens) |
| Malicious server operator | `from → to` graph, content | Token routing table, not `from → to` pairs or content — but this is not a cryptographic guarantee against the operator, it's a metadata-scope reduction. Self-hosting doesn't eliminate this risk, it changes *who* the operator is: run your own server and your firm holds that residual visibility instead of a third party, which is a real control benefit for a firm's own compliance posture, but the same server-side visibility exists whoever runs it |
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
- Desktop client: system Tor service or Tor Browser (optional, for `.onion` server URLs)

### Server
- Python 3.10+
- `websockets` and `cryptography` libraries
- Accessible IP with port 443 (WSS via reverse proxy)
- TURN server for NAT traversal (coturn recommended)

---

## Docker Deployment (Recommended)

The easiest way to self-host Subrosa is with Docker and Docker Compose.

**Quick Start:**
```bash
# 1. Clone repository
git clone https://github.com/MoRoKonst/Subrosa-messenger
cd Subrosa-messenger

# 2. Configure environment (template lives at repo root)
cp .env.example .env

# 3. All deployment files (Dockerfile, compose, nginx, certs) live in deploy/
cd deploy

# 4. Generate TLS certificates (development)
./generate-certs.sh

# 5. Start server
docker compose up -d

# 6. Access at wss://your-domain/ws
```

**Features:**
- ✅ Single command deployment
- ✅ Automatic TLS termination (nginx)
- ✅ Data persistence (Docker volumes)
- ✅ Health checks built-in
- ✅ Production-ready configuration

**See [DOCKER.md](docs/DOCKER.md) for:**
- Prerequisites and installation
- Configuration options
- TLS certificate setup
- Troubleshooting

**For production with Let's Encrypt, see [DEPLOY.md](docs/DEPLOY.md)**

---

## Self-Hosting (Manual)

You can run your own Subrosa server and connect the app to it — no recompilation needed.

**Note:** Docker deployment above is recommended. This section documents manual setup.

### 1. Deploy the server

**Without Docker:**

```bash
cd Server
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
git clone https://github.com/MoRoKonst/Subrosa-messenger
cd Subrosa-messenger

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

1. Install the APK from [Releases](https://github.com/MoRoKonst/Subrosa-messenger/releases).
2. Open the app and register a username and password.
3. Share your invite code with a contact (`bc:<base64url-encoded>`).
4. Verify your contact's fingerprint out-of-band (optional but recommended).
5. Start messaging.

**To use your own server:** see [Self-Hosting](#self-hosting), then add your server in **Profile → Servers**.

---

## Security Overview

| Layer | Mechanism |
|---|---|
| Transport | WSS (TLS 1.2+) with certificate pinning |
| Key agreement | Hybrid X3DH + ML-KEM-768 (post-quantum, harvest-now-decrypt-later resistant) |
| Message E2EE | Double Ratchet v3 — DH Ratchet + Symmetric Ratchet, AES-256-GCM |
| Forward secrecy | Per-message keys; break-in recovery on every DH step |
| Social graph | Anonymous token routing — server sees no `from → to` pairs, for 1:1 messages/calls/reactions/edits/files (group calls are a documented exception, see [above](#1-anonymous-token-routing)) |
| Timing | Constant-rate cover traffic (optional) |
| IP address | Tor hidden service — via Orbot (Android) or a local SOCKS5 proxy (Desktop), both optional |
| At-rest (L1) | EncryptedSharedPreferences + AndroidKeyStore |
| At-rest (L2) | Storage Master Key, AES-256-GCM |
| Backup | AES-256-GCM + Argon2id (m=64 MB, t=3, p=1) |
| Key authentication | ECDSA (SHA256withECDSA) + out-of-band fingerprint verification |
| Invalid curve attack | EC point validation on all imported public keys |

See [SECURITY.md](docs/SECURITY.md) for the full threat model and cryptographic specification.  
See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the system design and module reference.

---

## Documentation

### Deployment & Hosting

| Document | Audience | Description |
|---|---|---|
| [DOCKER.md](docs/DOCKER.md) | All (recommended) | Quick start with Docker — 5 minutes to running server |
| [DEPLOY.md](docs/DEPLOY.md) | SysAdmins | Production deployment, Let's Encrypt, auto-renewal |
| [CHECKLIST.md](docs/CHECKLIST.md) | DevOps | Pre/post deployment verification steps |

### Technical & Security

| Document | Audience | Description |
|---|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Developers | System design, module reference, data flows |
| [SECURITY.md](docs/SECURITY.md) | Security analysts | Threat model, cryptographic design, anti-forensics |
| [CHANGEL_LOG.md](docs/CHANGEL_LOG.md) | Developers | Engineering change log |

---

## License

Subrosa Messenger is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0) — see [LICENSE](LICENSE) for the full text.

In short: you're free to run, study, modify, and redistribute this software, including commercially. If you run a modified version as a network service that others interact with remotely (for example, hosting Subrosa for clients), AGPL-3.0 §13 requires you to make the corresponding source of your modified version available to those users, free of charge. Every official Subrosa client offers this by default via an in-app "Source code" link (Profile → About) pointing to this repository.
