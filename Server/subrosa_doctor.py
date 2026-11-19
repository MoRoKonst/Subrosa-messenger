#!/usr/bin/env python3
"""
subrosa doctor — deployment diagnostic script.

Run this ON THE SERVER (VPS), after deploying/configuring, to catch the
class of mistake that has actually bitten this project before. Each check
below corresponds to a failure that really happened (docs/KNOWN_SECURITY_ISSUES.md,
docs/DEPLOY.md), not to a generic hardening checklist:

  1. server listening on a public interface / firewall not up      (KL-25, twice)
  2. nginx config on disk is not the config actually loaded        (DEPLOY.md,
     "WebSocket Returns 400 Behind Cloudflare" — root cause was a failing `nginx -t`)
  3. DB_PATH points outside the mounted volume                     (docker-compose.yml, "found live")
  4. DB_ENCRYPTION_KEY_HEX malformed / sqlcipher missing           (server dies at start)
  5. TLS certificate expired or about to                           (DEPLOY.md renewal section)
  6. no protection against a path-MTU blackhole                    (DEPLOY.md, "Small pages load, large
     ones hang" — 2026-11-19: Cloudflare 521 while the origin was healthy)

Read-only: never modifies anything, never opens a connection to anything but
this machine's own port table and local files, never sends data anywhere.
Safe to run repeatedly, including on a live production server.

The output is meant to be pasted into a support email. It prints paths, port
numbers, day counts and the NAMES of settings — never the VALUE of any key,
secret or access code, never message content, fingerprints or user names.
(Server/tests/test_doctor.py plants canary secrets and fails if one is printed.)

It does NOT see: who talks to whom (the server deliberately does not know),
anything that needs root it was not given (run with sudo for ufw / nginx -t),
or the public internet's view of your server (nothing here connects outward —
use a phone on mobile data for that).

Usage:
    python3 subrosa_doctor.py
    sudo python3 subrosa_doctor.py        # lets it read ufw and run nginx -t
    DB_PATH=/opt/beacon/messages.db python3 subrosa_doctor.py

Reads ./.env (or ../.env) for variables that are not already set in the
environment; only the names of those variables are ever reported.

Exit code 0 if no FAIL, 1 if at least one FAIL (WARN/INFO don't affect it).
"""
import argparse
import calendar
import glob
import http.client
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time

results = []  # (level, name, detail)


def _utf8_stdout():
    # The em-dashes below break on a Windows console using a non-UTF-8
    # codepage. Done in main(), not at import, so importing this module (the
    # tests do) has no side effects on sys.stdout.
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)


def report(level, name, detail=""):
    results.append((level, name, detail))
    print(f"[{level}] {name}" + (f" — {detail}" if detail else ""))


def run(cmd, timeout=5):
    """Best-effort shell-out; returns (ok, stdout) — never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stdout or "") + ("" if p.returncode == 0 else (p.stderr or ""))
    except Exception as e:
        return False, str(e)


# ── .env fallback (values are NEVER printed) ────────────────────────────

ENV_FROM_FILE = set()


def load_dotenv_fallback():
    """Fill UNSET variables from ./.env or ../.env so the doctor sees what the
    docker/systemd deployment sees. Only names are ever reported."""
    for path in (".env", os.path.join("..", ".env")):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip().strip('"').strip("'")
                    if k and v and not os.environ.get(k):
                        os.environ[k] = v
                        ENV_FROM_FILE.add(k)
        except OSError:
            pass
        return


# ── 1. Exposed ports / firewall ─────────────────────────────────────────
# KL-25 happened twice because the CONFIG said loopback/firewalled while the
# REALITY was a public listener. So this reads what the OS says is listening.

def classify(addr):
    a = addr.strip("[]")
    if a in ("*", "0.0.0.0", "::", ""):
        return "all"
    if a.startswith("127.") or a in ("::1", "localhost"):
        return "loopback"
    return "specific"


_ADDR_PORT = re.compile(r"(\[[0-9a-fA-F:.]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|\*)[:.](\d+)")


def parse_listeners(text, port):
    """Addresses a TCP listener on `port` is bound to, from `ss -tln`, Linux
    `netstat -ltn`, macOS `netstat -an` or Windows `netstat -an` output."""
    found = []
    for line in text.splitlines():
        if "LISTEN" not in line.upper():
            continue
        for tok in line.split():
            m = _ADDR_PORT.fullmatch(tok)
            if m and int(m.group(2)) == port:
                found.append(m.group(1))
                break
    return found


def actual_listeners(port):
    for cmd in (["ss", "-tln"], ["netstat", "-ltn"], ["netstat", "-an"]):
        ok, out = run(cmd)
        if ok and out.strip():
            return parse_listeners(out, port), cmd[0]
    return None, None


def parse_docker_ports(text, port):
    """(container, host_addr, host_port) for each binding of container `port`."""
    res = []
    for line in text.splitlines():
        name, _, ports = line.partition("|")
        for m in re.finditer(r"(\[[0-9a-f:]+\]|[0-9.]+|::|\*):(\d+)->%d/tcp" % port, ports):
            res.append((name, m.group(1), int(m.group(2))))
    return res


def docker_published(port):
    ok, out = run(["docker", "ps", "--format", "{{.Names}}|{{.Ports}}"])
    return parse_docker_ports(out, port) if ok else None


def check_firewall_and_port9000():
    port = int(os.environ.get("SUBROSA_BIND_PORT", "9000") or "9000")
    configured = os.environ.get("SUBROSA_BIND_HOST", "0.0.0.0")

    ok, out = run(["ufw", "status"])
    ufw_active = None
    if not ok:
        report("WARN", "ufw not available/queryable",
               "needs root, or this is not a ufw host — check the firewall manually")
    elif "inactive" in out.lower():
        ufw_active = False
        report("FAIL", "ufw is INSTALLED but INACTIVE",
               "KL-25: the plaintext port was reachable from the whole internet because the "
               "firewall was never enabled")
    elif "active" in out.lower():
        ufw_active = True
        report("PASS", "ufw is active")
    else:
        report("WARN", "ufw status unclear")

    pub = docker_published(port)
    if pub:
        for name, host, hport in pub:
            if classify(host) == "all":
                report("FAIL", f"docker publishes port {port} on ALL interfaces",
                       f"{name}: {host}:{hport}->{port}. Docker's iptables rules bypass ufw, so the "
                       f"firewall does NOT protect this; publish as 127.0.0.1:{hport}:{port} (KL-25)")
            else:
                report("PASS", f"docker publishes port {port} on {host} only", name)
        return

    addrs, tool = actual_listeners(port)
    if addrs is None:
        report("WARN", "can't read the listening-ports table", "neither ss nor netstat is available")
        return
    if not addrs:
        report("WARN", f"nothing is listening on port {port} on this machine",
               "server not running, or SUBROSA_BIND_PORT differs, or it runs in a container this "
               "user cannot see (try sudo)")
        return
    kinds = {classify(a) for a in addrs}
    shown = ", ".join(sorted(set(addrs)))
    if kinds == {"loopback"}:
        report("PASS", f"port {port} is bound to loopback only", f"{shown} (read via {tool})")
    elif ufw_active:
        report("WARN", f"port {port} is bound to a non-loopback address ({shown}); ufw is the only barrier",
               "one layer only — the KL-25 fix that survived a host rebuild also set SUBROSA_BIND_HOST=127.0.0.1")
    else:
        report("FAIL", f"port {port} is bound to a non-loopback address ({shown}) and no active ufw was confirmed",
               "if this is the --dev (plaintext) server it is reachable from outside: set "
               "SUBROSA_BIND_HOST=127.0.0.1 and enable the firewall (KL-25)")
    if classify(configured) == "loopback" and "loopback" not in kinds:
        report("FAIL", "SUBROSA_BIND_HOST says loopback but the real listener is not",
               f"configured {configured}, actual {shown} — the config is not what is running (restart needed?)")


# ── 2. nginx: the config on disk vs the config actually loaded ───────────
# docs/DEPLOY.md "WebSocket Returns 400 Behind Cloudflare": the real cause was
# a stale server block with a missing certificate, so `nginx -t` failed, every
# reload silently kept the OLD config, and the new vhost "looked fine on disk".

CLOUDFLARE_HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}


def missing_nginx_certs(conf_text, exists=os.path.exists):
    return [m.group(1) for m in re.finditer(r"^\s*ssl_certificate(?:_key)?\s+([^;\s]+);", conf_text, re.M)
            if not exists(m.group(1))]


def check_nginx_loadable():
    exe = shutil.which("nginx")
    if not exe:
        return
    ok, out = run([exe, "-t"], timeout=10)
    if "permission denied" in out.lower():
        report("WARN", "nginx -t needs root to run", "re-run the doctor with sudo to check this")
    elif ok or "syntax is ok" in out:
        report("PASS", "nginx -t passes (the config on disk can actually be loaded)")
    else:
        lines = [l.strip() for l in out.splitlines() if "emerg" in l or "error" in l.lower()]
        report("FAIL", "nginx -t FAILS — reloads silently keep serving the OLD config",
               "; ".join(l[:160] for l in lines[:3]) or "run `nginx -t` for the reason")
    conf = "/etc/nginx/nginx.conf"
    if os.path.isfile(conf):
        try:
            text = open(conf, encoding="utf-8", errors="replace").read()
        except OSError:
            return
        for path in missing_nginx_certs(text):
            report("FAIL", "nginx config references a certificate file that does not exist", path)


# ── 5. TLS certificate ───────────────────────────────────────────────────

def parse_not_after(openssl_out):
    """'notAfter=Aug 30 00:00:00 2026 GMT' -> epoch seconds (UTC)."""
    date_str = openssl_out.strip().split("=", 1)[1]
    return calendar.timegm(time.strptime(date_str, "%b %d %H:%M:%S %Y %Z"))


def check_tls_cert():
    candidates = [
        "secrets/cert.pem",
        "/opt/beacon/secrets/cert.pem",
        "deploy/certs/cert.pem",
        "certs/cert.pem",
        "../deploy/certs/cert.pem",
    ]
    # Certbot's layout, which this list did not know about: on our own host the
    # real certificates are Let's Encrypt ones under /etc/letsencrypt, so the
    # check reported "no cert.pem found" on a deployment with two perfectly valid
    # certificates and never looked at their expiry -- the one thing it exists
    # for. Globbed rather than named, since the directory is the domain.
    candidates += sorted(glob.glob("/etc/letsencrypt/live/*/fullchain.pem"))
    cert_path = next((c for c in candidates if os.path.exists(c)), None)
    if not cert_path:
        report("WARN", "no cert.pem found in expected locations", ", ".join(candidates))
        return
    ok, out = run(["openssl", "x509", "-enddate", "-noout", "-in", cert_path])
    if not ok:
        report("WARN", "couldn't read certificate expiry", f"{cert_path} (is openssl installed?)")
        return
    try:
        days_left = int((parse_not_after(out) - time.time()) / 86400)  # truncates toward 0
    except Exception as e:
        report("WARN", "couldn't parse certificate expiry date", str(e)[:100])
        return
    if days_left < 0:
        report("FAIL", "TLS certificate EXPIRED", f"{cert_path}, {abs(days_left)} days ago — see DEPLOY.md, certificate renewal")
    elif days_left < 14:
        report("FAIL", "TLS certificate expires very soon", f"{cert_path}, {days_left} days left")
    elif days_left < 30:
        report("WARN", "TLS certificate expires within a month", f"{cert_path}, {days_left} days left")
    else:
        report("PASS", "TLS certificate valid", f"{cert_path}, {days_left} days left")


# ── 4. DB encryption key + at-rest state ─────────────────────────────────

def validate_db_key(value):
    """Mirror of server.py's startup check (hex parse) plus the 32-byte length
    the docs tell people to generate. Returns a problem string or None."""
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return "not a hex string — server.py exits at startup with [FATAL]"
    if len(raw) != 32:
        return f"decodes to {len(raw)} bytes, expected 32 (64 hex chars, `secrets.token_hex(32)`)"
    return None


def check_db_encryption():
    db_path = os.environ.get("DB_PATH", "messages.db")
    key = os.environ.get("DB_ENCRYPTION_KEY_HEX", "").strip()
    key_set = bool(key)
    if key_set:
        problem = validate_db_key(key)
        if problem:
            report("FAIL", "DB_ENCRYPTION_KEY_HEX is malformed", problem)
        else:
            report("PASS", "DB_ENCRYPTION_KEY_HEX is well-formed")
        try:
            import sqlcipher3  # noqa: F401
        except ImportError:
            if shutil.which("docker") and run(["docker", "inspect", "subrosa-messenger-server"], timeout=10)[0]:
                pass  # server runs in the container, which has its own packages; the host's Python is irrelevant
            else:
                report("FAIL", "DB_ENCRYPTION_KEY_HEX is set but the sqlcipher3 package is not installed",
                       "server.py exits at startup — pip install sqlcipher3-binary")
    if not os.path.exists(db_path):
        report("INFO", "no database file found yet",
               f"expected at {os.path.abspath(db_path)} — server may not have run here")
        return
    with open(db_path, "rb") as f:
        header = f.read(16)
    is_plain_sqlite = header.startswith(b"SQLite format 3")
    if key_set and is_plain_sqlite:
        report("FAIL", "DB_ENCRYPTION_KEY_HEX is set but the DB file is plain, unencrypted SQLite",
               f"{db_path} — SQLCipher can't open a file written in plain format; the key is not "
               "protecting this file (docs/SECURITY.md item 27)")
    elif key_set and not is_plain_sqlite:
        report("PASS", "DB appears encrypted (SQLCipher) and DB_ENCRYPTION_KEY_HEX is set")
    elif not key_set and is_plain_sqlite:
        report("WARN", "database is unencrypted at rest",
               f"{db_path} — opt-in via DB_ENCRYPTION_KEY_HEX (docs/SECURITY.md item 27); it cannot be "
               "added later to an existing database. Fine if disk-level encryption is in place.")
    else:
        report("WARN", "database file doesn't look like plain SQLite and no key is set",
               "unexpected — verify manually")


# ── 3. DB_PATH vs the mounted volume ─────────────────────────────────────

def parse_mountinfo(text):
    """Mount points listed in /proc/self/mountinfo (field 5)."""
    mounts = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) > 4:
            mounts.append(parts[4].replace("\\040", " "))
    return mounts


def under_mount(path, mounts):
    """True if `path` sits under a mount point other than '/'."""
    path = path.rstrip("/")
    return any(m != "/" and (path == m or path.startswith(m.rstrip("/") + "/")) for m in mounts)


def check_db_path_volume_trap():
    """The docker-compose incident: DB_PATH unset -> messages.db resolves
    relative to WORKDIR, inside the container's writable layer, and is lost
    on every container recreate."""
    db_path = os.environ.get("DB_PATH", "")
    in_container = os.path.exists("/.dockerenv")

    if in_container:
        abs_path = os.path.abspath(db_path or "messages.db")
        try:
            mounts = parse_mountinfo(open("/proc/self/mountinfo", encoding="utf-8").read())
        except OSError:
            mounts = None
        if mounts is None:
            report("WARN", "can't read /proc/self/mountinfo", "cannot verify DB_PATH is on a volume")
        elif under_mount(abs_path, mounts):
            report("PASS", "DB_PATH is on a mounted volume", abs_path)
        else:
            report("FAIL", "DB_PATH is NOT on a mounted volume — data lives in the container layer",
                   f"{abs_path} resolves outside every mount; it is lost when the container is recreated "
                   "(set DB_PATH=/app/data/messages.db, as deploy/docker-compose.yml does)")
        return

    if not shutil.which("docker"):
        return
    ok, out = run(["docker", "inspect", "subrosa-messenger-server"], timeout=10)
    if not ok:
        return  # no such container / no permission: not the compose deployment
    try:
        info = json.loads(out)[0]
        env = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in info["Config"]["Env"] if "=" in e}
        dests = [m["Destination"] for m in info.get("Mounts", [])]
        workdir = info["Config"].get("WorkingDir") or "/"
    except Exception:
        report("WARN", "couldn't parse `docker inspect` output for subrosa-messenger-server")
        return
    cpath = env.get("DB_PATH", "")
    if not cpath:
        report("FAIL", "container has no DB_PATH — database is in the writable layer",
               f"defaults to 'messages.db' under {workdir}, outside the volume; lost on recreate")
        return
    if not cpath.startswith("/"):
        cpath = os.path.join(workdir, cpath)
    if under_mount(cpath, dests):
        report("PASS", "container DB_PATH is inside a mounted volume", f"{cpath} (mounts: {', '.join(dests)})")
    else:
        report("FAIL", "container DB_PATH is NOT inside any mounted volume",
               f"{cpath}; mounts are {', '.join(dests) or 'none'} — data is lost when the container is recreated")


# ── 6. Path-MTU blackhole ────────────────────────────────────────────────
# DEPLOY.md, "Small pages load, large ones hang": full-size TCP segments are dropped upstream and no
# ICMP "fragmentation needed" returns, so small responses arrive and large ones never do. Every layer
# on the host looks healthy; Cloudflare shows 521. Two checks: (a) is the host protected against it
# (a missing protection is a WARN, never a FAIL — it is the absence of a safety net, not a fault);
# (b) does the origin itself serve a large response, on LOOPBACK ONLY. (b) cannot detect an MTU
# blackhole — loopback never crosses the bad link — but it is the discriminating test the DEPLOY.md
# section describes: "origin fine locally + big responses hang from outside" => suspect MTU.

MTU_DOC = "docs/DEPLOY.md, 'Small pages load, large ones hang'"


def parse_mtu_probing(text):
    """Value of net.ipv4.tcp_mtu_probing (0 off, 1 on after a blackhole, 2 always) or None."""
    try:
        return int(text.strip().split()[0])
    except (ValueError, IndexError):
        return None


def has_mss_clamp(text):
    """True if iptables/nft output contains a TCPMSS clamp (`-j TCPMSS --set-mss N`/`--clamp-mss-to-pmtu`, or nft `maxseg size`)."""
    return bool(re.search(r"TCPMSS|maxseg\s+size", text or ""))


def mtu_protection_verdict(probing, clamp):
    """probing: int or None; clamp: True / False / 'unknown' (couldn't read the firewall).
    Returns a list of (level, name, detail)."""
    out = []
    if probing:
        out.append(("PASS", f"TCP MTU probing is on (net.ipv4.tcp_mtu_probing={probing})", ""))
    if clamp is True:
        out.append(("PASS", "a TCPMSS clamp rule exists in the firewall", ""))
    if probing or clamp is True:
        return out
    if clamp == "unknown":
        out.append(("INFO", "tcp_mtu_probing is off and the firewall's mangle table could not be read",
                    "re-run with sudo to see whether a TCPMSS clamp exists"))
        return out
    out.append(("WARN", f"no protection against a path-MTU blackhole (tcp_mtu_probing={probing}, no TCPMSS clamp)",
                "not a fault by itself. If a small page loads from outside but a large one hangs (Cloudflare 521 while "
                f"the origin is fine): sysctl -w net.ipv4.tcp_mtu_probing=1 and clamp MSS — {MTU_DOC}"))
    return out


def check_mtu_protection():
    if not sys.platform.startswith("linux"):
        return
    try:
        probing = parse_mtu_probing(open("/proc/sys/net/ipv4/tcp_mtu_probing").read())
    except OSError:
        probing = None
    clamp = "unknown"
    for cmd in (["iptables", "-t", "mangle", "-S"], ["nft", "list", "ruleset"]):
        ok, out = run(cmd)
        if ok:
            clamp = has_mss_clamp(out)
            if clamp:
                break
    for item in mtu_protection_verdict(probing, clamp):
        report(*item)


def classify_size_probe(small, large):
    """small/large = (status, nbytes, seconds) or an Exception/None. Returns (level, name, detail) or None."""
    if small is None and large is None:
        return None                                    # nothing answered on loopback: not this check's business
    if small is None or isinstance(small, Exception):
        return None
    if large is None or isinstance(large, Exception):
        return ("FAIL", "the local web server answers a small request but a large one fails or hangs, even on loopback",
                f"{type(large).__name__ if large else 'no response'} — this is the origin itself (proxy buffers, temp dir "
                f"permissions, upstream), not the network path")
    status, n, secs = large
    if n < 4000:
        return ("INFO", "no large response on the local web server to compare against a small one",
                f"'/' returned {n} bytes (status {status}); if a big page hangs from outside, see {MTU_DOC}")
    return ("PASS", f"the local web server serves a large response fine on loopback ({n} bytes in {secs:.2f}s)",
            f"if the SAME page hangs from outside, the origin is not at fault: suspect path MTU — {MTU_DOC}")


def _http_get(port, path, use_tls, timeout=5):
    t0 = time.time()
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE                # loopback only; we are not validating identity here
        # Loopback-only probe of our own nginx with a self-signed/unverifiable certificate: the point is
        # "does a big response arrive", not "is this peer who it says" — nothing leaves this machine.
        # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
        conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "subrosa-doctor"})
        resp = conn.getresponse()
        body = resp.read(2_000_000)
        return (resp.status, len(body), time.time() - t0)
    finally:
        conn.close()


def check_local_size_probe():
    """Loopback only — never contacts anything outside this machine."""
    for port, tls in ((443, True), (4443, True), (8443, True), (80, False)):
        try:
            small = _http_get(port, "/subrosa-doctor-nonexistent-%d" % int(time.time()), tls)
        except Exception:
            continue                                   # nothing (TLS) listening here
        try:
            large = _http_get(port, "/", tls)
        except Exception as e:
            large = e
        res = classify_size_probe(small, large)
        if res:
            report(*res)
        return


# ── Other checks ─────────────────────────────────────────────────────────

def check_totp_encryption():
    if os.environ.get("TOTP_SECRET_ENCRYPTION_KEY", "").strip():
        report("PASS", "TOTP_SECRET_ENCRYPTION_KEY is set")
    else:
        report("WARN", "TOTP_SECRET_ENCRYPTION_KEY not set",
               "TOTP secrets sit in the DB in plaintext at rest (the server needs the raw secret "
               "at runtime either way — this only protects a copy of the DB file; see .env.example)")


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
        report("WARN", "backup directory exists but is empty", found)
        return
    newest = max(files, key=os.path.getmtime)
    age_hours = (time.time() - os.path.getmtime(newest)) / 3600
    if age_hours > 48:
        report("WARN", "newest backup is more than 48h old", f"{newest}, {age_hours:.0f}h ago")
    else:
        report("PASS", "recent backup found", f"{newest}, {age_hours:.0f}h ago")


def check_fcm():
    cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not cred_path:
        report("INFO", "GOOGLE_APPLICATION_CREDENTIALS not set",
               "FCM push notifications disabled — fine if this deployment deliberately runs "
               "strict no-third-party")
    elif not os.path.exists(cred_path):
        report("FAIL", "GOOGLE_APPLICATION_CREDENTIALS is set but the file doesn't exist", cred_path)
    else:
        mode = oct(os.stat(cred_path).st_mode)[-3:]
        if mode not in ("600", "400"):
            report("WARN", "Firebase service-account file has loose permissions",
                   f"{cred_path} is {mode}, expected 600")
        else:
            report("PASS", "FCM service-account file present with restrictive permissions", cred_path)


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
            report("WARN", "secrets file has loose permissions", f"{path} is {mode}, expected 600")
    else:
        report("PASS", "secrets/ file permissions look reasonable")

    env_path = ".env"
    if os.path.exists(env_path):
        mode = oct(os.stat(env_path).st_mode)[-3:]
        if mode not in ("600", "400"):
            report("WARN", ".env has loose permissions", f"{env_path} is {mode}, expected 600 (contains secrets)")
        else:
            report("PASS", ".env permissions look reasonable")


def check_turn():
    turn_vars = ["TURN_SERVER", "TURN_USERNAME", "TURN_PASSWORD", "TURN_SECRET"]
    present = [v for v in turn_vars if os.environ.get(v, "").strip()]
    if not present:
        report("INFO", "no TURN_* environment variables set",
               "1:1 calls will rely on STUN/direct P2P only — may fail behind symmetric NAT")
    else:
        report("INFO", f"TURN env vars present: {', '.join(present)}",
               "can't verify the TURN server itself is reachable from here")


def check_ip_forwarding_invariant():
    """docs/SECURITY.md item 30 / SECURITY_INVARIANTS.md #1 — server.py must
    never see real client IPs. Looks for the headers that broke this before."""
    candidates = ["deploy/nginx.conf", "/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"]
    found = [c for c in candidates if os.path.exists(c)]
    if not found:
        report("INFO", "no nginx config found in common locations to check", ", ".join(candidates))
        return
    for path in found:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            continue
        suspicious = ("proxy_set_header X-Real-IP" in content or
                      "proxy_set_header X-Forwarded-For" in content)
        if suspicious:
            report("FAIL", "nginx config forwards client IP headers to the backend",
                   f"{path} — a previously-fixed regression (docs/SECURITY.md item 30)")
        else:
            report("PASS", "nginx config does not forward IP headers to backend", path)


def main():
    parser = argparse.ArgumentParser(description="Subrosa deployment diagnostic (read-only, local only)")
    parser.parse_args()
    _utf8_stdout()
    load_dotenv_fallback()

    print("subrosa doctor — read-only deployment diagnostic")
    if ENV_FROM_FILE:
        print(f"(read {len(ENV_FROM_FILE)} setting(s) from .env: {', '.join(sorted(ENV_FROM_FILE))} — names only)")
    print()

    check_firewall_and_port9000()
    check_nginx_loadable()
    check_tls_cert()
    check_mtu_protection()
    check_local_size_probe()
    check_db_encryption()
    check_db_path_volume_trap()
    check_totp_encryption()
    check_backups()
    check_fcm()
    check_secrets_permissions()
    check_turn()
    check_ip_forwarding_invariant()

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
