# Subrosa Messenger — Self-Hosting Setup

This directory contains everything needed to self-host a Subrosa Messenger server.

## What is Subrosa?

Subrosa is an end-to-end encrypted messenger with metadata protection. This deployment contains:
- **Python WebSocket server** for message relay and signaling
- **nginx reverse proxy** with TLS termination
- **Docker containerization** for easy deployment

See [README.md](../README.md) for full feature list and [SECURITY.md](../SECURITY.md) for threat model.

## Installation & Quick Start

### Step 1: Prerequisites

**Linux (Recommended)**:
```bash
# Ubuntu 20.04+
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin openssl curl
sudo usermod -aG docker $USER
newgrp docker
```

**macOS**:
```bash
# Install Docker Desktop from https://www.docker.com/products/docker-desktop
# Then install OpenSSL: brew install openssl
```

**Windows**:
```powershell
# Install Docker Desktop from https://www.docker.com/products/docker-desktop
# Enable WSL2 backend during installation
```

### Step 2: Generate Certificates

```bash
chmod +x generate-certs.sh
./generate-certs.sh
```

You'll see:
```
✓ Certificate generated successfully
  Certificate fingerprint (SHA256): ...
```

### Step 3: Configure

```bash
cp .env.example .env
# Edit .env in your favorite editor
nano .env
```

### Step 4: Start Server

```bash
docker compose up -d

# Wait ~10 seconds for services to start
sleep 10

# Verify running
docker compose ps
# You should see Subrosa-messenger-server and Subrosa-nginx both Up
```

### Step 5: Test Connection

**Linux/macOS**:
```bash
# Using websocat (install: brew install websocat or similar)
websocat --insecure wss://localhost/ws
# Type any text, should echo "Unknown command" if connection works
```

**Using browser console**:
```javascript
ws = new WebSocket("wss://localhost/ws");
ws.onmessage = msg => console.log(msg);
ws.send(JSON.stringify({type: "test"}));
```

---

## Production Deployment

For real-world use, follow [DEPLOY.md](DEPLOY.md):
1. Obtain real TLS certificate (Let's Encrypt free)
2. Configure firewall
3. Set up certificate auto-renewal
4. Enable monitoring

---

## File Structure

```
.
├── docker-compose.yml      # Service definitions
├── Dockerfile              # Python app image
├── nginx.conf              # Reverse proxy config
├── .env                    # Configuration (secrets)
├── .env.example            # Template for .env
├── generate-certs.sh       # TLS certificate generator
├── DEPLOY.md               # Production deployment guide
└── ForEXP/
    ├── server.py           # Subrosa WebSocket server
    └── requirements.txt    # Python dependencies
```

---

## Common Commands

```bash
# Start server (background)
docker compose up -d

# View logs
docker compose logs -f Subrosa-server

# Stop server
docker compose down

# Restart after config changes
docker compose restart

# Rebuild (after pulling code updates)
docker compose build --no-cache && docker compose up -d

# Access server shell (debug)
docker compose exec Subrosa-server sh

# Export database backup
docker run --rm \
  -v Subrosa-data:/data \
  -v $(pwd):/backup \
  alpine:latest \
  cp /data/Subrosa.db /backup/Subrosa-$(date +%Y%m%d_%H%M%S).db
```

---

## Networking

### Default (Docker-only)

- Server listens on `0.0.0.0:9000` inside container
- nginx on port 80 and 443
- Only local docker network used

### For Remote Access

If running on a VPS:

1. Firewall:
   ```bash
   sudo ufw allow 22/tcp    # SSH
   sudo ufw allow 80/tcp    # HTTP
   sudo ufw allow 443/tcp   # HTTPS
   sudo ufw enable
   ```

2. Update your domain DNS to point to server IP

3. Update nginx config if using non-standard domain (usually automatic)

4. Use real certificate from Let's Encrypt (see DEPLOY.md)

---

## Troubleshooting

### Services won't start

```bash
# Check Docker is running
docker ps

# Check logs
docker compose logs

# Check ports aren't in use
sudo lsof -i :80
sudo lsof -i :443
```

### Can't connect to WebSocket

1. Verify nginx is running: `docker compose ps`
2. Test TLS: `openssl s_client -connect localhost:443`
3. Check firewall: `sudo ufw status`
4. Review nginx logs: `docker compose logs nginx`

### High memory usage

Container defaults are reasonable. If needed, add to `docker-compose.yml`:
```yaml
services:
  Subrosa-server:
    resources:
      limits:
        memory: 1G
```

---

## Security Notes

### Before Production

- [ ] Use real TLS certificate (not self-signed)
- [ ] Enable firewall
- [ ] Run on isolated VPS or internal network
- [ ] Set up log rotation
- [ ] Plan backup strategy

### Ongoing

- Update Docker and images monthly
- Monitor disk space (SQLite database grows)
- Keep certificates renewed
- Review logs for attacks

---

## Performance

Typical resource usage on `docker-compose up -d`:
- **CPU**: < 5% idle, ~20% during messaging
- **RAM**: 150-300 MB
- **Storage**: 50 MB base + 1 KB per message + media files

For 100 concurrent users, recommend:
- 2 CPU cores minimum
- 2 GB RAM
- 20 GB storage

---

## Next Steps

1. Share `wss://your-domain/ws` with Android app users
2. Users register with username and password
3. Users share invite codes (`beacon://invite?...`) for new contacts
4. Messages, calls, and files flow encrypted end-to-end

See [README.md](../README.md) **Quick Start** section for client-side setup.

---

**Questions?** Check [SECURITY.md](../SECURITY.md) for threat model or [ARCHITECTURE.md](../ARCHITECTURE.md) for technical details.
