# Subrosa Messenger — Docker Deployment Guide

This guide walks you through deploying Subrosa Messenger server using Docker and Docker Compose.

## Prerequisites

- **Docker** 20.10+
- **Docker Compose** 2.0+
- **OpenSSL** (for certificate generation)
- A Linux server (Ubuntu 20.04+ recommended) or Docker Desktop on Mac/Windows
- A domain name (for production TLS certificates)

## Fastest path: one script

Tested on 2026-11-19 on a clean Ubuntu 24.04 host (1 vCPU, 2 GB RAM). Each
command below was run as written, **with the fixes of the commit that added this
section** (before them the documented path did not build: stale pinned apt
package in the Dockerfile, a BOM that made nginx refuse its config).

```bash
sudo apt-get update && sudo apt-get install -y git openssl curl
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"     # then log out and back in
git clone https://github.com/MoRoKonst/Subrosa-messenger.git subrosa
cd subrosa/deploy
SERVER_URL=wss://your-domain bash install.sh
```

`install.sh` checks Docker, generates a **self-signed** certificate if
`deploy/certs/` has none (phones will not trust it: put a real one there, see
Production Deployment), creates `../.env` with a random `DB_ENCRYPTION_KEY_HEX`
(**back `.env` up separately from the database; without that key the data is
unreadable, and it cannot be added to an existing database later**), starts the
stack and waits for the healthcheck. Running it again changes nothing that
exists: `.env` and certificates are kept (verified by checksum).

Known limitation, found by this run: with `SERVER_ACCESS_PROTECTED=true` the
current `server.py` crashes at start (`UnboundLocalError: ... 'os'` in
`start_server()`), so access codes cannot be used yet and `install.sh` leaves
protection off. Until that is fixed, anyone who can reach the server can
register on it.

Not measured: a message delivered from a phone. What was verified is the
WebSocket handshake through nginx (the server's `challenge` frame arrives).

## Manual steps (same result, step by step)

All deployment files live in `deploy/`: `cd deploy`. The commands are
`docker compose` (v2); `docker-compose` with a hyphen does not exist on a fresh
install.

### 1. Generate Self-Signed Certificate

```bash
./generate-certs.sh
```

This creates `certs/cert.pem` and `certs/key.pem` (inside `deploy/`) for local testing.

### 2. Configure Environment

```bash
# .env.example lives at the repo root, one level up from deploy/
cp ../.env.example ../.env
nano ../.env
```

### 3. Build and Start Server

```bash
docker compose up -d --build
```

The server will:
- Start the Python WebSocket server on port 9000 (internal, published on 127.0.0.1 only)
- Start nginx reverse proxy on ports 80 (HTTP) and 443 (HTTPS)
- Create a persistent volume for data

### 4. Verify It's Running

```bash
docker compose ps
docker compose logs subrosa-server
```

You should see `subrosa-messenger-server` (healthy) and `subrosa-nginx` running.

### 5. Test WebSocket Connection

Connect a WebSocket client to `wss://<host>/ws` (certificate warnings apply
to the self-signed certificate). The server answers with a `{"type": "challenge", ...}` frame.

---

## Production Deployment

### 1. Obtain Real TLS Certificate

Use Let's Encrypt with Certbot:

```bash
apt-get install certbot python3-certbot-nginx -y

certbot certonly --standalone \
  -d your-domain.com \
  -d www.your-domain.com \
  --agree-tos \
  -n

# Copy certificates to certs/ directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ./certs/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem ./certs/key.pem
sudo chown $(whoami):$(whoami) ./certs/*.pem
```

### 2. Update .env for Production

```bash
# .env
SUBROSA_HOST=0.0.0.0
SUBROSA_PORT=9000
```

### 3. Configure Firewall

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP (Let's Encrypt renewal)
sudo ufw allow 443/tcp     # HTTPS
sudo ufw enable
```

### 4. Enable Auto-Renewal for Certificates

```bash
# Test renewal
certbot renew --dry-run

# Create renewal hook script
sudo tee /etc/letsencrypt/renewal-hooks/post/Subrosa-renewal.sh << 'EOF'
#!/bin/bash
cd /path/to/Subrosa/project
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ./certs/cert.pem
cp /etc/letsencrypt/live/your-domain.com/privkey.pem ./certs/key.pem
chown $USER:$USER ./certs/*.pem
docker-compose restart nginx
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/post/Subrosa-renewal.sh
```

### 5. Start Server

```bash
docker-compose up -d
docker-compose logs -f
```

---

## Server Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SUBROSA_HOST` | `0.0.0.0` | Server bind address |
| `SUBROSA_PORT` | `9000` | Server port (internal, not exposed) |
| `GOOGLE_APPLICATION_CREDENTIALS` | unset | Path to a Firebase service-account JSON — enables push notifications (FCM). See [Push Notifications](#push-notifications-fcm--deployment-profile) below before setting this. |

### Push Notifications (FCM) — Deployment Profile

Android kills background services without a system-level wake mechanism, so
reliable message delivery while the app isn't in the foreground needs a push
provider. Subrosa uses Firebase Cloud Messaging (FCM) for this — the same
mechanism nearly every Android app relies on. **This is a real, explicit
deployment choice, not a default you should leave unexamined**, because FCM
means Google is genuinely in the data path (it sees, at minimum, a
recipient's FCM token and the timing of a push — never message content,
which stays end-to-end encrypted, but it is still a third party your firm
does not control). Pick one of the two profiles below deliberately:

**Profile A — Standard (FCM enabled, recommended for most firms)**

```bash
# In the server's environment (systemd unit, docker-compose environment:,
# or .env — GOOGLE_APPLICATION_CREDENTIALS is a filesystem path, not a
# secret value, so it's fine in any of these):
GOOGLE_APPLICATION_CREDENTIALS=/opt/beacon/firebase-adminsdk.json
```

Copy the Firebase service-account JSON to the server, restrict its
permissions (`chmod 600`), and point this variable at it — `subrosa_doctor.py`
checks both that the file exists and that its permissions are restrictive.
Background message delivery is then reliable even when the app isn't in the
foreground, matching what users expect from a normal messaging app.

**Profile B — Strict No-Third-Party (no FCM)**

Leave `GOOGLE_APPLICATION_CREDENTIALS` unset entirely. The server's FCM code
path is then inert — no request to Google is ever made, no FCM token is ever
collected or stored. This is the right choice for a firm whose policy
requires zero third-party data-path dependencies, full stop, even a metadata-
only one.

**The trade-off, stated plainly, not glossed over**: without FCM, background
delivery depends entirely on the app maintaining its own WebSocket
connection and Android's willingness to keep that connection's service
alive — which Android does **not** guarantee on its own past a certain point
(manufacturer-specific background-kill policies, Doze mode, battery
optimization). In practice this means **messages sent while the recipient's
app has been backgrounded for a while may arrive late, only once the app is
next opened or the OS lets the background service reconnect** — not lost
(everything queues server-side and via the anonymous-token mailbox), but
materially less reliable as a live communication channel than Profile A.
This is a genuine reliability cost, not a toggle to flip off casually for a
"works like a normal messenger" expectation — but it is the correct choice
for a deployment where the zero-third-party requirement is non-negotiable.

Run [`Server/subrosa_doctor.py`](../Server/subrosa_doctor.py) after choosing
either profile — it reports which one is active and flags a misconfigured
Profile A (credentials path set but file missing, or overly permissive
file permissions).

### Data Persistence

- **SQLite database**: `/app/data/messages.db` (inside container)
- **Docker volume**: `subrosa-data` (persists across restarts)

### Resource Limits

For small deployments (50-100 users), default settings are fine. For larger:

```yaml
# In docker-compose.yml, add to subrosa-server service:
resources:
  limits:
    cpus: '2'
    memory: 2G
  reservations:
    cpus: '1'
    memory: 1G
```

---

## Maintenance

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f subrosa-server
docker-compose logs -f nginx
```

### Reading logs with a TOTP gate

`Server/admin_logs.py` is a standalone script (no dependency on the
messenger app or protocol) that wraps log reading behind a TOTP code, so
that even someone with shell access to the box can't read logs without
also having the authenticator. One-time setup, then use it instead of
`docker-compose logs` directly:

```bash
python3 Server/admin_logs.py setup                 # once, prints the secret — save it offline
python3 Server/admin_logs.py logs                    # prompts for the current code, then runs docker-compose logs
python3 Server/admin_logs.py logs --source file --log-file /var/log/subrosa/server.log
```

The secret lives in `~/.subrosa_admin_totp` (600 perms, override with
`SUBROSA_ADMIN_TOTP_FILE`), never in this repo. Losing it means running
`setup --force`, which itself requires the current code to overwrite —
there's no recovery path if both are lost, by design (same reasoning as
the backup-import TOTP in `docs/ISSUE_backup_identity_hijack.md`).

### Stop Server

```bash
docker-compose down
# Data persists in the subrosa-data volume
```

### Restart Server

```bash
docker-compose restart
```

### Update Server

**Back up the database first.** A migration runs at server start and some
schema changes cannot be undone; if the update goes wrong, the backup is the way
back. See *Database Backup* below, and do not skip it.

`deploy/upgrade.sh` does the whole sequence (record current commit, consistent
backup and read-back, pull, rebuild, wait for the healthcheck, print the
rollback commands if it fails):

```bash
bash deploy/upgrade.sh
```

> **Status:** run on a clean Ubuntu 24.04 host (2026-11-19): a successful update
> (about 4 s with a cached build), and a deliberately broken release, where the
> script stopped, printed the rollback commands, and running them verbatim
> brought the server back healthy. Not tested: pulling real new upstream commits.

Manual equivalent:

```bash
# 1. back up first (next section), then:
git pull
docker-compose build --no-cache
docker-compose up -d
```

The database carries a schema version stamp. If you roll back to an **older**
server while the database was already migrated by a newer one, the server
refuses to start with `[FATAL] database schema vN is newer than this server
(vM). Restore the pre-update backup (docs/DEPLOY.md) or run a newer server.`
and exit code 1. Restore the pre-update backup together with the old code (the
rollback commands `upgrade.sh` prints do this); do not just check out the old
code over the new database.

### Database Backup

**Never `cp` a running server's database.** It runs SQLite in WAL mode: recent
commits live in `messages.db-wal`, not in `messages.db`. Copying only the main
file silently drops them. This was measured (`Server/tests/test_db_backup.py`:
200 rows committed, a plain file copy of the main file did not contain all of
them). A copy made during a checkpoint can also be inconsistent, and you find
out when you need it.

`deploy/db_backup.py` uses SQLite's online-backup API, which gives a consistent
snapshot while the server keeps running, then reads the copy back with
`PRAGMA integrity_check` and deletes it if that fails. It honors
`DB_ENCRYPTION_KEY_HEX`.

On a plain (non-docker) install, tested:

```bash
python3 deploy/db_backup.py /opt/beacon/messages.db /opt/beacon/backups
```

In the docker-compose stack (tested, including an encrypted database; the
script is streamed in because the image contains only `server.py`):

```bash
cd deploy
docker compose exec -T subrosa-server python - /app/data/messages.db /app/data/backups < db_backup.py
```

The backup lands inside the same volume; copy it somewhere else
(`docker compose cp`), a backup in the volume you lose is no backup.
Restoring: stop the server, delete `messages.db-wal` and `messages.db-shm`, put
the backup in place as `messages.db`, start the server.

---

## Seats: who is on the server, and cutting someone off

`Server/admin_users.py` works directly on the SQLite file `server.py` uses
(`DB_PATH`), without a restart, like `admin_gen_codes.py`.

```bash
python3 Server/admin_users.py list                       # read-only
python3 Server/admin_users.py revoke 1A2B3C4D5E6F7A8B    # dry run: prints what it would do
python3 Server/admin_users.py revoke 1A2B3C4D5E6F7A8B --yes
```

`list` shows, per identity, a shortened fingerprint, the date it first
registered, how many devices are bound, whether TOTP is on and whether it was
revoked, plus the totals. Use `--full-fingerprints` to print them whole.

What `revoke` does: it is the same one-row insert a client makes with "I have
been compromised". Every connection attempt by that identity is refused
(`identity_revoked`), and a session that is **open right now** is cut by the
server's revoked-sessions sweep: the person receives `identity_revoked` and the
socket is closed within `REVOKED_SESSION_SWEEP_INTERVAL_SEC` (default 30 s;
measured 29.4 s on a local server). It also **frees the seat**:
`MAX_REGISTERED_USERS` is now counted against the identities that can still
connect, so a revoked one no longer occupies a place you paid for. The row
stays in `registered_fingerprints`, both because that fingerprint must never
be allowed back and because `REGISTERED_ACCOUNTS_HARD_MAX_ROWS` — the safety
ceiling on table growth — deliberately still counts it.

What `revoke` does **not** do: it does not delete that identity's queued
messages, device keys or TOTP state, and it does not cancel unused access
codes the person may still hold — with one, they could register a *new*
identity. Use `codes --delete` below for that.

Deleting their data: `revoke` alone leaves the revoked person's stored data in the
database (unreachable, but present). `revoke <fingerprint> --purge` (dry run
without `--yes`, which prints the row count per table) also deletes, in the same
transaction, their queued messages, prekey bundle, device keys, TOTP secret and
recovery codes and avatar — and nothing else; the capacity counters the server
keeps for those tables are recomputed in the same transaction. The fingerprint
stays registered **and revoked**. Messages they *sent* sit in other people's
queues and cannot be found (the server does not know senders). A running server
keeps bundle/avatar/TOTP copies in RAM: restart it after a purge. Tested on
databases built by the server's own schema and on a copy of a real one; not
tested through the docker stack.

Access codes: `admin_users.py codes` lists unused codes by the first characters
of their SHA-256 (the server stores only hashes, so a code can never be shown
again) and `codes --delete <prefix> [--yes]` removes an **unused** one (dry run
without `--yes`; used codes are never deleted). The server does **not** record
which code was given to which person, and deliberately never will: that would be
new data about people on the server. Keep that list on your side — when you
generate codes with `admin_gen_codes.py`, write down who gets which link.

By design this tool cannot show who talks to whom or what anyone sent: the
server does not know, and that is the property the product exists to provide.

The tool was tested on a copy of a database in a plain Python install. The
docker image copies only `server.py`, so the tool is not inside the container;
running it against the `subrosa-data` volume of the compose stack has not been
tested.

## Troubleshooting

**If something does not work, run this on the server and send us the output:**

```bash
sudo python3 Server/subrosa_doctor.py
```

It only reads local state (listening ports, config files, certificate dates,
`nginx -t`), connects to nothing, and prints setting *names* and paths but never
key values, message content or user data, so the output is safe to paste into an
email. It checks the failures this project has actually had: the server port
listening on a public interface (KL-25), an nginx config that does not load,
`DB_PATH` outside the mounted volume, a malformed `DB_ENCRYPTION_KEY_HEX`, and
an expired TLS certificate.

### Port Already in Use

```bash
# Check what's using ports 80 or 443
sudo lsof -i :80
sudo lsof -i :443

# Stop conflicting service (e.g., Apache)
sudo systemctl stop apache2
```

### nginx Won't Start

```bash
# Validate nginx config
docker-compose exec nginx nginx -t

# Check logs
docker-compose logs nginx
```

### Certificate Issues

```bash
# Verify certificate
openssl x509 -in certs/cert.pem -text -noout

# Check certificate expiry
openssl x509 -in certs/cert.pem -noout -dates
```

### WebSocket Connection Fails

1. Check firewall allows port 443
2. Verify nginx is running: `docker-compose ps`
3. Check logs: `docker-compose logs nginx`
4. Test connectivity: `openssl s_client -connect your-domain.com:443`

### WebSocket Returns 400 Behind Cloudflare (Fresh Zones)

If you're fronting your server with Cloudflare (proxied/orange-cloud DNS) instead of exposing it directly, watch out for this on newly created zones: every real WebSocket upgrade request (correct `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Version`, `Sec-WebSocket-Key` headers, verified with `python3 -m websockets` as well as curl) gets rejected with a generic Cloudflare-branded `400 Bad Request` ("Your browser sent an invalid request") — **before it ever reaches your origin**. Confirmed by origin logs (`journalctl`/nginx access log) showing no incoming connection at all for the failed request.

Ruled out (all were correctly configured, none fixed it):
- Origin TLS certificate, chain, and SNI routing — all valid (`openssl s_client -connect 127.0.0.1:<port> -servername your.domain -showcerts` confirmed a clean chain)
- Cloudflare **Network → WebSockets** toggle — enabled
- Cloudflare **Security → Bots → Bot Fight Mode** — disabled
- **Security Level** — default (automated)
- Missing `Origin` header on the client request — adding one made no difference
- Hostname (`api.` subdomain vs. root domain) — both failed identically, ruling out anything specific to an `api.`-style subdomain
- **Speed → Settings → HTTP/2 to Origin** — disabled, no change

What confirms the origin/nginx side is completely fine: connecting directly to the origin IP:port (bypassing Cloudflare entirely — switch the DNS record to DNS-only/grey-cloud temporarily) succeeds immediately with a real WebSocket upgrade.

**Workaround** to unblock testing/deployment immediately: temporarily switch the affected DNS record to **DNS-only** (grey cloud), and relax any `allow <cloudflare-ip-ranges>` restriction in nginx for that vhost so real clients can reach it. This exposes your origin IP directly (loses Cloudflare's DDoS/IP-hiding protection) — revert once resolved.

We did not find a definitive root cause, only a working bypass — our best guess is a propagation/feature-activation delay specific to freshly created Cloudflare zones, unconfirmed. If you figure out the actual fix, please update this section.

**Update — actual root cause found, unrelated to Cloudflare itself.** The real
problem was a stale `api.beacon-app.org:4430` server block left over from
before the domain rebrand, still sitting in the same `sites-available` file
as the correct `api.subrosamessenger.com:8443` block. Its certificate path no
longer existed, so `nginx -t` failed and **every** reload silently kept
serving the old, never-reloaded config — including for the correct vhost,
which looked fine on disk but was never actually loaded. `:4430` also isn't
one of Cloudflare's supported proxied HTTPS ports (443/2053/2083/2087/2096/
8443) in the first place, compounding the confusion. Fix: remove/comment out
the dead block, confirm `nginx -t` passes clean, reload, then switch the DNS
record back to proxied/orange-cloud on `:8443` — no Cloudflare-side setting
needed changing at all.

---

### Small pages load, large ones hang (path MTU blackhole)

Measured on this project's own server on 2026-11-19. Worth recognising fast,
because every layer you would normally suspect looks healthy:

- On the host, everything works. `curl -k https://127.0.0.1:4443/` returns the
  whole page in milliseconds.
- From outside, the TCP handshake completes and TLS negotiates — then the
  connection hangs with **zero bytes received**, but only when the response is
  large. A 404 (a few hundred bytes) comes back in the same conditions where a
  31 KB page never does.
- With Cloudflare in front it surfaces as **error 521**, which reads as "origin
  is down" and sends you to the wrong layer entirely. nginx's own stream log
  had already recorded Cloudflare's edge IPs with `sent=13420 dur=75s`: the
  origin answered, the answer never arrived.

Cause: path MTU discovery is blackholed upstream — full-size segments are
dropped and no ICMP "fragmentation needed" comes back, so the sender never
learns. Nothing on the origin reports a problem, because as far as it is
concerned the bytes went out.

The one-command way to tell this apart from SNI filtering or a dead origin:
ask for a nonexistent path (tiny response) and then the index page (large),
same host, same port. Small answers and large hangs means MTU. Both failing
means something else.

Fix:

```bash
sysctl -w net.ipv4.tcp_mtu_probing=1
iptables -t mangle -A POSTROUTING -o eth0 -p tcp   --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300
```

Persist both, or a reboot quietly brings the outage back — on our host that is
`/etc/sysctl.d/99-subrosa-mtu.conf` plus a one-shot systemd unit
(`subrosa-mss-clamp.service`). After the clamp, the 31 KB page went from never
arriving to 0.84 s.

---

## Security Recommendations

### 1. Use Strong TLS Certificates

- Don't use self-signed certs in production
- Use Let's Encrypt (free) or commercial CA
- Enable certificate auto-renewal

### 2. Enable Firewall

- Only expose ports 80 and 443
- SSH access from trusted IPs only
- Consider fail2ban for brute-force protection

### 3. Regular Updates

```bash
# Weekly: check for Docker/OS updates
docker pull nginx:1.25-alpine
docker pull python:3.11-slim

# Review new commits in this repository
git fetch origin
git log --oneline origin/main -10
```

### 5. Monitoring (Optional)

Add health checks to your monitoring system:

```bash
# Manual health check
curl -i https://your-domain.com/health || echo "Server offline"
```

---

## Contact & Support

For issues or questions:
- Check logs: `docker-compose logs`
- Review SECURITY.md for threat model
- Read ARCHITECTURE.md for technical details
- File issues on GitHub

---

## Quick Reference

```bash
# Start server
docker-compose up -d

# Stop server
docker-compose down

# View logs
docker-compose logs -f

# Restart specific service
docker-compose restart subrosa-server

# Rebuild after code changes
docker-compose build --no-cache && docker-compose up -d

# Enter server shell (debug)
docker-compose exec subrosa-server sh

# Backup database
docker run --rm -v subrosa-data:/data -v $(pwd):/backup \
  alpine:latest cp /data/messages.db /backup/backup.db
```
