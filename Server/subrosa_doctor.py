#!/usr/bin/env python3
"""
subrosa doctor — deployment diagnostic script.

Run this ON THE SERVER (VPS), after deploying/configuring, to catch the
class of mistake that has actually bitten this project before: port 9000
open to the whole internet while ufw was inactive, DB_PATH resolving
outside the mounted volume so data silently lived in the container's
writable layer, etc. Every check below corresponds to either a documented
invariant (docs/SECURITY_INVARIANTS.md) or a real incident recorded in
docs/TODO.md/SECURITY_CHANGELOG.md — this is not a generic hardening
checklist, it's specific to mistakes this deployment has actually made.

Read-only: never modifies anything, never sends data anywhere. Safe to run
repeatedly, including on a live production server.

Usage:
    python3 subrosa_doctor.py                  # auto-detects deployment style
    python3 subrosa_doctor.py --docker          # force docker-compose checks
    python3 subrosa_doctor.py --systemd         # force systemd checks
    DB_PATH=/opt/beacon/messages.db python3 subrosa_doctor.py

Exit code 0 if no FAIL, 1 if at least one FAIL (WARN/INFO don't affect it —
they're context, not necessarily problems).
"""
import argparse
import io
import os
import shutil
import socket
import subprocess
import sys
import time

# Same UTF-8 stdout reconfiguration as server.py/admin_gen_codes.py — without
# it, the em-dashes in the messages below break on a Windows console using a
# non-UTF-8 codepage (found by actually running this, not just eyeballing it).
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)

results = []  # (level, name, detail)


def report(level, name, detail=""):
    results.append((level, name, detail))
    print(f"[{level}] {name}" + (f" — {detail}" if detail else ""))


def run(cmd, timeout=5):
    """Best-effort shell-out; returns (ok, stdout) — never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, p.stdout
    except Exception as e:
        return False, str(e)


# ── Exposed ports / firewall ────────────────────────────────────────────

def check_firewall_and_port9000():
    ok, out = run(["ufw", "status"])
    if not ok:
        report("WARN", "ufw not available/queryable", "can't confirm firewall state on this OS — check manually")
    elif "inactive" in out.lower():
        report("FAIL", "ufw is INSTALLED but INACTIVE",
               "the exact incident that motivated this script (2026-08-2x): port 9000 was reachable "
               "from the whole internet, not just via nginx, because ufw was never enabled")
    elif "active" in out.lower():
        report("PASS", "ufw is active")
    else:
        report("WARN", "ufw status unclear", out.strip()[:200])

    # Is 9000 reachable directly (not just via nginx on 443)?
    port_open = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        port_open = s.connect_ex(("127.0.0.1", 9000)) == 0
        s.close()
    except Exception:
        pass
    if port_open:
        report("INFO", "port 9000 is listening locally",
               "expected if server.py is running — the question is whether ufw/cloud "
               "firewall also blocks it from the public interface (see ufw check above)")

    ok, out = run(["ss", "-tlnp"])
    if ok and ":9000" in out:
        if "0.0.0.0:9000" in out or "*:9000" in out:
            report("WARN", "server.py listening on all interfaces (0.0.0.0:9000)",
                   "normal for the docker-compose setup (nginx fronts it, ufw should still gate "
                   "9000 from outside) — abnormal if this is the systemd/beacon.service deployment, "
                   "which expects nginx as the only public entrypoint")


# ── TLS certificate ──────────────────────────────────────────────────────

def check_tls_cert():
    candidates = [
        "secrets/cert.pem",
        "/opt/beacon/secrets/cert.pem",
        "deploy/certs/cert.pem",
    ]
    cert_path = next((c for c in candidates if os.path.exists(c)), None)
    if not cert_path:
        report("WARN", "no cert.pem found in expected locations", ", ".join(candidates))
        return
    ok, out = run(["openssl", "x509", "-enddate", "-noout", "-in", cert_path])
    if not ok:
        report("WARN", "couldn't read certificate expiry", f"{cert_path}: {out.strip()[:200]}")
        return
    # out looks like "notAfter=Aug 30 00:00:00 2026 GMT"
    try:
        date_str = out.strip().split("=", 1)[1]
        expiry = time.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        days_left = int((time.mktime(expiry) - time.time()) / 86400)
        if days_left < 0:
            report("FAIL", f"TLS certificate EXPIRED", f"{cert_path}, {abs(days_left)} days ago")
        elif days_left < 14:
            report("FAIL", f"TLS certificate expires very soon", f"{cert_path}, {days_left} days left")
        elif days_left < 30:
            report("WARN", f"TLS certificate expires within a month", f"{cert_path}, {days_left} days left")
        else:
            report("PASS", f"TLS certificate valid", f"{cert_path}, {days_left} days left")
    except Exception as e:
        report("WARN", "couldn't parse certificate expiry date", str(e))


# ── DB encryption at rest ───────────────────────────────────────────────

def check_db_encryption():
    db_path = os.environ.get("DB_PATH", "messages.db")
    key_set = bool(os.environ.get("DB_ENCRYPTION_KEY_HEX", "").strip())
    if not os.path.exists(db_path):
        report("INFO", "no database file found yet", f"expected at {db_path} — server may not have run here")
        return
    with open(db_path, "rb") as f:
        header = f.read(16)
    is_plain_sqlite = header.startswith(b"SQLite format 3")
    if key_set and is_plain_sqlite:
        report("FAIL", "DB_ENCRYPTION_KEY_HEX is set but the DB file is plain, unencrypted SQLite",
               f"{db_path} — SQLCipher can't open a file written in plain format; this key is not "
               "actually protecting this file (see docs/SECURITY.md item 27's note on this exact trap)")
    elif key_set and not is_plain_sqlite:
        report("PASS", "DB appears encrypted (SQLCipher) and DB_ENCRYPTION_KEY_HEX is set")
    elif not key_set and is_plain_sqlite:
        report("WARN", "database is unencrypted at rest",
               f"{db_path} — opt-in via DB_ENCRYPTION_KEY_HEX (docs/SECURITY.md item 27); a stolen "
               "disk/backup is readable in plain text without it. Not necessarily wrong for every "
               "deployment (e.g. disk-level FDE already in place), but worth a deliberate decision.")
    else:
        report("WARN", "database file doesn't look like plain SQLite and no key is set",
               "unexpected — verify manually")


# ── TOTP secret encryption ──────────────────────────────────────────────

def check_totp_encryption():
    if os.environ.get("TOTP_SECRET_ENCRYPTION_KEY", "").strip():
        report("PASS", "TOTP_SECRET_ENCRYPTION_KEY is set")
    else:
        report("WARN", "TOTP_SECRET_ENCRYPTION_KEY not set",
               "TOTP secrets sit in the DB in plaintext at rest (server still needs the raw secret "
               "to verify codes at runtime either way — this only protects a copy of the DB file, "
               "see .env.example)")


# ── Backups ──────────────────────────────────────────────────────────────

def check_backups():
    candidates = ["/opt/beacon/backups", "backups", "/var/backups/subrosa"]
    found = next((c for c in candidates if os.path.isdir(c)), None)
    if not found:
        report("WARN", "no backup directory found in common locations",
               ", ".join(candidates) + " — confirm backups exist somewhere, this check can't see custom paths")
        return
    files = [os.path.join(found, f) for f in os.listdir(found)]
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        report("WARN", f"backup directory exists but is empty", found)
        return
    newest = max(files, key=os.path.getmtime)
    age_hours = (time.time() - os.path.getmtime(newest)) / 3600
    if age_hours > 48:
        report("WARN", "newest backup is more than 48h old", f"{newest}, {age_hours:.0f}h ago")
    else:
        report("PASS", "recent backup found", f"{newest}, {age_hours:.0f}h ago")


# ── FCM config ───────────────────────────────────────────────────────────

def check_fcm():
    cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not cred_path:
        report("INFO", "GOOGLE_APPLICATION_CREDENTIALS not set",
               "FCM push notifications disabled — fine if this deployment deliberately runs "
               "strict no-third-party (see docs/TODO.md's FCM deployment-profile item)")
    elif not os.path.exists(cred_path):
        report("FAIL", "GOOGLE_APPLICATION_CREDENTIALS is set but the file doesn't exist",
               cred_path)
    else:
        st = os.stat(cred_path)
        mode = oct(st.st_mode)[-3:]
        if mode not in ("600", "400"):
            report("WARN", "Firebase service-account file has loose permissions",
                   f"{cred_path} is {mode}, expected 600 — a private key readable by other local users")
        else:
            report("PASS", "FCM service-account file present with restrictive permissions", cred_path)


# ── File permissions on secrets ──────────────────────────────────────────

def check_secrets_permissions():
    secrets_dir = "secrets"
    if not os.path.isdir(secrets_dir):
        report("INFO", "no local secrets/ directory found here", "run from the server's working directory")
        return
    problems = []
    for fname in os.listdir(secrets_dir):
        path = os.path.join(secrets_dir, fname)
        if not os.path.isfile(path):
            continue
        mode = oct(os.stat(path).st_mode)[-3:]
        if mode not in ("600", "400", "640"):
            problems.append((path, mode))
    if problems:
        for path, mode in problems:
            report("WARN", f"secrets file has loose permissions", f"{path} is {mode}, expected 600")
    else:
        report("PASS", "secrets/ file permissions look reasonable")

    env_path = ".env"
    if os.path.exists(env_path):
        mode = oct(os.stat(env_path).st_mode)[-3:]
        if mode not in ("600", "400"):
            report("WARN", ".env has loose permissions", f"{env_path} is {mode}, expected 600 (contains secrets)")
        else:
            report("PASS", ".env permissions look reasonable")


# ── TURN config ──────────────────────────────────────────────────────────

def check_turn():
    turn_vars = ["TURN_SERVER", "TURN_USERNAME", "TURN_PASSWORD", "TURN_SECRET"]
    present = [v for v in turn_vars if os.environ.get(v, "").strip()]
    if not present:
        report("INFO", "no TURN_* environment variables set",
               "1:1 calls will rely on STUN/direct P2P only — may fail behind symmetric NAT; "
               "fine if this deployment doesn't use calls or accepts that limitation")
    else:
        report("INFO", f"TURN env vars present: {', '.join(present)}",
               "can't verify the TURN server itself is reachable from here without a live call test")


# ── Deployment-invariant sanity checks (things that were real incidents) ──

def check_ip_forwarding_invariant():
    """docs/SECURITY.md item 30 / docs/SECURITY_INVARIANTS.md #1 — server.py
    must never see real client IPs. Grep the nginx config actually in use
    for the specific headers that broke this before."""
    candidates = ["deploy/nginx.conf", "/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"]
    found = [c for c in candidates if os.path.exists(c)]
    if not found:
        report("INFO", "no nginx config found in common locations to check",
               ", ".join(candidates))
        return
    for path in found:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            continue
        # Look specifically for these headers being forwarded TOWARD the
        # subrosa upstream, not just present anywhere in the file (they're
        # expected/fine in a $remote_addr-based access_log context).
        suspicious = ("proxy_set_header X-Real-IP" in content or
                      "proxy_set_header X-Forwarded-For" in content)
        if suspicious:
            report("FAIL", f"nginx config forwards client IP headers to the backend",
                   f"{path} — this was a real, previously-fixed regression "
                   "(docs/SECURITY.md item 30); server.py must never receive these")
        else:
            report("PASS", f"nginx config does not forward IP headers to backend", path)


def check_db_path_volume_trap():
    """The exact docker-compose incident: DB_PATH unset -> messages.db
    resolves relative to WORKDIR, landing outside any mounted volume."""
    if not shutil.which("docker") and not os.path.exists("/.dockerenv"):
        return  # not a docker deployment, this check doesn't apply
    db_path = os.environ.get("DB_PATH", "")
    if not db_path:
        report("WARN", "DB_PATH is not set in a docker environment",
               "defaults to relative 'messages.db' — resolves inside the container's writable "
               "layer, NOT any mounted volume, unless WORKDIR itself happens to be the volume "
               "mount point. Data would be silently lost on container recreate (this exact bug "
               "was found and fixed in deploy/docker-compose.yml — see docs/TODO.md)")
    elif not db_path.startswith("/"):
        report("WARN", "DB_PATH is a relative path in a docker environment", db_path)
    else:
        report("PASS", f"DB_PATH is an absolute path", db_path)


def main():
    parser = argparse.ArgumentParser(description="Subrosa deployment diagnostic")
    parser.parse_args()

    print("subrosa doctor — read-only deployment diagnostic\n")

    check_firewall_and_port9000()
    check_tls_cert()
    check_db_encryption()
    check_totp_encryption()
    check_backups()
    check_fcm()
    check_secrets_permissions()
    check_turn()
    check_ip_forwarding_invariant()
    check_db_path_volume_trap()

    print("\n" + "=" * 60)
    fails = [r for r in results if r[0] == "FAIL"]
    warns = [r for r in results if r[0] == "WARN"]
    print(f"{len(fails)} FAIL, {len(warns)} WARN, {len(results) - len(fails) - len(warns)} PASS/INFO")
    if fails:
        print("\nFAIL items need attention before this is production-ready:")
        for _, name, detail in fails:
            print(f"  - {name}: {detail}")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
