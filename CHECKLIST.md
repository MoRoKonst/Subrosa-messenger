# Beacon Messenger — Deployment Checklist

Use this checklist before deploying Beacon to production.

## Pre-Deployment (Development)

- [ ] Clone repository: `git clone https://github.com/MoRoKonst/beacon-messenger`
- [ ] Enter directory: `cd beacon-messenger`
- [ ] Verify Docker installed: `docker --version && docker compose version`
- [ ] Generate certificates: `./generate-certs.sh`
- [ ] Copy environment: `cp .env.example .env`
- [ ] Test locally: `docker compose up -d`
- [ ] Verify running: `docker compose ps`
- [ ] Check logs: `docker compose logs beacon-server`

## Production Deployment

### Server Infrastructure
- [ ] Rent VPS (2 CPU, 2 GB RAM minimum)
- [ ] Ubuntu 20.04 LTS or newer
- [ ] SSH access configured
- [ ] Firewall enabled (only ports 22, 80, 443)

### Domain & DNS
- [ ] Register domain (e.g., beacon.your-company.com)
- [ ] DNS A record points to VPS IP
- [ ] DNS propagated (wait 24h if needed)

### TLS Certificate
- [ ] Install certbot: `apt-get install certbot`
- [ ] Obtain certificate: `certbot certonly --standalone -d your-domain.com`
- [ ] Copy to certs/: See DEPLOY.md step 1
- [ ] Test certificate: `openssl x509 -in certs/cert.pem -text -noout`

### Security Configuration
- [ ] Change CHANNEL_ADMIN_SECRET: `openssl rand -hex 32`
- [ ] Update .env file
- [ ] Enable firewall: `ufw allow 22,80,443/tcp`
- [ ] Disable root SSH login (optional but recommended)

### Deployment
- [ ] Clone repository on VPS
- [ ] Pull latest: `git pull origin main`
- [ ] Generate certificates (or copy existing)
- [ ] Create .env with production secrets
- [ ] Build: `docker compose build`
- [ ] Start: `docker compose up -d`
- [ ] Wait 10 seconds
- [ ] Verify: `docker compose ps`

### Post-Deployment Testing
- [ ] Test TLS: `openssl s_client -connect your-domain:443 -servername your-domain`
- [ ] Test WebSocket: See DOCKER.md step 5
- [ ] Test from Android app: Enter server URL in app
- [ ] Test messaging between two test accounts
- [ ] Test file transfer (if implemented)
- [ ] Test voice/video calls

### Monitoring & Maintenance
- [ ] Set up log rotation (optional)
- [ ] Schedule daily backups: `docker run --rm ... cp /data/beacon.db ...`
- [ ] Monitor disk space: `docker compose exec beacon-server df -h`
- [ ] Set certificate renewal reminder (Let's Encrypt: 30 days before expiry)
- [ ] Weekly: `docker compose logs | grep -i error`
- [ ] Monthly: Update Docker images and test in staging

### Certificate Renewal (Monthly)
- [ ] Run: `certbot renew --dry-run`
- [ ] If successful, set up auto-renewal cron
- [ ] Or manually monthly: 
  ```bash
  certbot renew
  sudo cp /etc/letsencrypt/live/your-domain/fullchain.pem ./certs/cert.pem
  sudo cp /etc/letsencrypt/live/your-domain/privkey.pem ./certs/key.pem
  docker compose restart nginx
  ```

### Scaling (Optional, for 100+ users)
- [ ] Add resource limits to docker-compose.yml
- [ ] Monitor performance: `docker stats`
- [ ] Consider separate TURN server for calls
- [ ] Enable nginx caching (already in config)
- [ ] Add monitoring (Prometheus + Grafana)

## Rollback Plan
- [ ] Backup .env with secrets
- [ ] Backup certs/ directory
- [ ] Weekly full database backup
- [ ] If issues: `docker compose down && docker compose up -d`
- [ ] To restore from backup: restore beacon.db volume

## Security Hardening (Optional)
- [ ] Enable firewall rules: `ufw enable`
- [ ] Set up fail2ban: `apt-get install fail2ban`
- [ ] Configure SSH key only (no password)
- [ ] Disable ping: `ufw default deny incoming`
- [ ] Add monitoring/alerting for disk/CPU/memory
- [ ] Review nginx logs weekly for attacks

## Client Onboarding
- [ ] Document server URL: `wss://your-domain/ws`
- [ ] Create user guide for team
- [ ] Share this with clients: 
  - Server URL: `wss://your-domain/ws`
  - Expected fingerprint (security):
    ```
    Public Key SHA256 fingerprint:
    [run: openssl x509 -in certs/cert.pem -noout -fingerprint -sha256]
    ```
- [ ] Instruct on fingerprint verification (out-of-band)
- [ ] Provide panic password & wipe documentation

## Troubleshooting Reference

| Issue | Diagnosis | Solution |
|---|---|---|
| WebSocket won't connect | `docker compose logs nginx` | Check firewall, DNS, certificate |
| High memory | `docker stats` | Check concurrent connections |
| Disk full | `df -h` | Backup and clean old messages |
| Certificate expired | `openssl x509 -dates -noout -in certs/cert.pem` | Renew with certbot |
| Messages accumulating | `sqlite3 /path/to/beacon.db "SELECT COUNT(*) FROM messages"` | Archive old data |

## Support & Documentation

- Technical questions: See [ARCHITECTURE.md](ARCHITECTURE.md)
- Security & threat model: See [SECURITY.md](SECURITY.md)
- Deployment issues: See [DEPLOY.md](DEPLOY.md) and [DOCKER.md](DOCKER.md)
- Quick reference: See [README.md](README.md)

---

**After completing this checklist, your Beacon server is production-ready.**

Last updated: 2025-02-15
