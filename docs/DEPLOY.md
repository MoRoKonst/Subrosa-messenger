# Subrosa Messenger — Docker Deployment Guide

This guide walks you through deploying Subrosa Messenger server using Docker and Docker Compose.

## Prerequisites

- **Docker** 20.10+
- **Docker Compose** 2.0+
- **OpenSSL** (for certificate generation)
- A Linux server (Ubuntu 20.04+ recommended) or Docker Desktop on Mac/Windows
- A domain name (for production TLS certificates)

## Quick Start (Development)

### 1. Generate Self-Signed Certificate

```bash
./generate-certs.sh
```

This creates `certs/cert.pem` and `certs/key.pem` for local testing.

### 2. Configure Environment

```bash
cp .env.example .env
nano .env
```

### 3. Build and Start Server

```bash
docker-compose up -d
```

The server will:
- Start the Python WebSocket server on port 9000 (internal)
- Start nginx reverse proxy on ports 80 (HTTP) and 443 (HTTPS)
- Create a persistent volume for data

### 4. Verify It's Running

```bash
docker-compose logs -f Subrosa-server
docker-compose ps
```

You should see both `Subrosa-messenger-server` and `Subrosa-nginx` running.

### 5. Test WebSocket Connection

```bash
# From your local machine or Android app
# Connect to: wss://your-server-domain/ws
# (or wss://localhost/ws for local testing, ignoring cert warnings)
```

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

### Data Persistence

- **SQLite database**: `/app/data/Subrosa.db` (inside container)
- **Docker volume**: `Subrosa-data` (persists across restarts)

### Resource Limits

For small deployments (50-100 users), default settings are fine. For larger:

```yaml
# In docker-compose.yml, add to Subrosa-server service:
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
docker-compose logs -f Subrosa-server
docker-compose logs -f nginx
```

### Reading logs with a TOTP gate

`ForEXP/admin_logs.py` is a standalone script (no dependency on the
messenger app or protocol) that wraps log reading behind a TOTP code, so
that even someone with shell access to the box can't read logs without
also having the authenticator. One-time setup, then use it instead of
`docker-compose logs` directly:

```bash
python3 ForEXP/admin_logs.py setup                 # once, prints the secret — save it offline
python3 ForEXP/admin_logs.py logs                    # prompts for the current code, then runs docker-compose logs
python3 ForEXP/admin_logs.py logs --source file --log-file /var/log/subrosa/server.log
```

The secret lives in `~/.subrosa_admin_totp` (600 perms, override with
`SUBROSA_ADMIN_TOTP_FILE`), never in this repo. Losing it means running
`setup --force`, which itself requires the current code to overwrite —
there's no recovery path if both are lost, by design (same reasoning as
the backup-import TOTP in `docs/ISSUE_backup_identity_hijack.md`).

### Stop Server

```bash
docker-compose down
# Data persists in the Subrosa-data volume
```

### Restart Server

```bash
docker-compose restart
```

### Update Server

```bash
# Pull latest code
git pull

# Rebuild image
docker-compose build --no-cache

# Restart
docker-compose up -d
```

### Database Backup

```bash
# Extract database from volume
docker run --rm \
  -v Subrosa-data:/data \
  -v $(pwd):/backup \
  alpine:latest \
  cp /data/Subrosa.db /backup/Subrosa-backup-$(date +%Y%m%d).db

# File saved to ./Subrosa-backup-YYYYMMDD.db
```

---

## Troubleshooting

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
docker-compose restart Subrosa-server

# Rebuild after code changes
docker-compose build --no-cache && docker-compose up -d

# Enter server shell (debug)
docker-compose exec Subrosa-server sh

# Backup database
docker run --rm -v Subrosa-data:/data -v $(pwd):/backup \
  alpine:latest cp /data/Subrosa.db /backup/backup.db
```
