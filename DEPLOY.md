# Beacon Messenger — Docker Deployment Guide

This guide walks you through deploying Beacon Messenger server using Docker and Docker Compose.

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
docker-compose logs -f beacon-server
docker-compose ps
```

You should see both `beacon-messenger-server` and `beacon-nginx` running.

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
BEACON_HOST=0.0.0.0
BEACON_PORT=9000
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
sudo tee /etc/letsencrypt/renewal-hooks/post/beacon-renewal.sh << 'EOF'
#!/bin/bash
cd /path/to/beacon/project
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ./certs/cert.pem
cp /etc/letsencrypt/live/your-domain.com/privkey.pem ./certs/key.pem
chown $USER:$USER ./certs/*.pem
docker-compose restart nginx
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/post/beacon-renewal.sh
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
| `BEACON_HOST` | `0.0.0.0` | Server bind address |
| `BEACON_PORT` | `9000` | Server port (internal, not exposed) |

### Data Persistence

- **SQLite database**: `/app/data/beacon.db` (inside container)
- **Docker volume**: `beacon-data` (persists across restarts)

### Resource Limits

For small deployments (50-100 users), default settings are fine. For larger:

```yaml
# In docker-compose.yml, add to beacon-server service:
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
docker-compose logs -f beacon-server
docker-compose logs -f nginx
```

### Stop Server

```bash
docker-compose down
# Data persists in the beacon-data volume
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
  -v beacon-data:/data \
  -v $(pwd):/backup \
  alpine:latest \
  cp /data/beacon.db /backup/beacon-backup-$(date +%Y%m%d).db

# File saved to ./beacon-backup-YYYYMMDD.db
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
docker-compose restart beacon-server

# Rebuild after code changes
docker-compose build --no-cache && docker-compose up -d

# Enter server shell (debug)
docker-compose exec beacon-server sh

# Backup database
docker run --rm -v beacon-data:/data -v $(pwd):/backup \
  alpine:latest cp /data/beacon.db /backup/backup.db
```
