"""
subrosa_doctor.py — parsers for the five real production failure modes, and the
"safe to paste into an email" property (no secret value ever printed).
No network, no Docker: pure parsing tests plus one subprocess run.
"""
import os
import subprocess
import sys
import time

import pytest

SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SERVER_DIR)
import subrosa_doctor as d  # noqa: E402  (import has no side effects on stdout)

SS_PUBLIC = """State  Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0      100          0.0.0.0:9000      0.0.0.0:*
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
"""
SS_LOOP = "LISTEN 0 100 127.0.0.1:9000 0.0.0.0:*\n"
NETSTAT_WIN = "  TCP    0.0.0.0:9000           0.0.0.0:0              LISTENING       4242\n" \
              "  TCP    [::]:9000              [::]:0                 LISTENING       4242\n" \
              "  TCP    127.0.0.1:9001         0.0.0.0:0              LISTENING       1\n"
NETSTAT_MAC = "tcp4       0      0  *.9000                 *.*                    LISTEN\n"


def test_listener_parsing_all_platform_formats():
    assert d.parse_listeners(SS_PUBLIC, 9000) == ["0.0.0.0"]
    assert d.parse_listeners(SS_LOOP, 9000) == ["127.0.0.1"]
    assert d.parse_listeners(NETSTAT_WIN, 9000) == ["0.0.0.0", "[::]"]
    assert d.parse_listeners(NETSTAT_MAC, 9000) == ["*"]
    assert d.parse_listeners(SS_PUBLIC, 9999) == []


def test_classify():
    assert d.classify("0.0.0.0") == d.classify("[::]") == d.classify("*") == "all"
    assert d.classify("127.0.0.1") == d.classify("[::1]") == "loopback"
    assert d.classify("203.0.113.7") == "specific"


def test_docker_published_ports():
    text = "subrosa-messenger-server|127.0.0.1:9000->9000/tcp\n" \
           "bad|0.0.0.0:9000->9000/tcp, :::9000->9000/tcp\n" \
           "subrosa-nginx|0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp\n"
    got = d.parse_docker_ports(text, 9000)
    assert ("subrosa-messenger-server", "127.0.0.1", 9000) in got
    assert ("bad", "0.0.0.0", 9000) in got
    assert all(g[0] != "subrosa-nginx" for g in got)


def test_nginx_missing_cert_is_found():
    conf = "server {\n  listen 4430 ssl;\n  ssl_certificate /nope/gone.pem;\n  ssl_certificate_key /nope/gone.key;\n}\n" \
           "server {\n  ssl_certificate /ok/fullchain.pem;\n}\n"
    missing = d.missing_nginx_certs(conf, exists=lambda p: p.startswith("/ok"))
    assert missing == ["/nope/gone.pem", "/nope/gone.key"]


def test_mountinfo_volume_detection():
    mi = "1 0 8:1 / / rw - overlay overlay rw\n" \
         "2 1 8:2 / /app/data rw - ext4 /dev/sda2 rw\n"
    mounts = d.parse_mountinfo(mi)
    assert d.under_mount("/app/data/messages.db", mounts)
    assert not d.under_mount("/app/messages.db", mounts)   # the real incident: relative DB_PATH under WORKDIR /app
    assert not d.under_mount("/anything", ["/"])


def test_db_key_validation_matches_server_startup():
    assert d.validate_db_key("ab" * 32) is None
    assert "hex" in d.validate_db_key("not-hex-at-all")
    assert "32" in d.validate_db_key("ab" * 16)


def test_cert_expiry_parse_is_utc_and_roundtrips():
    ts = d.parse_not_after("notAfter=Aug 30 00:00:00 2026 GMT")
    assert time.gmtime(ts)[:3] == (2026, 8, 30)


CANARIES = {
    "DB_ENCRYPTION_KEY_HEX": "c0ffee" * 10 + "abcd",          # 64 hex chars
    "TOTP_SECRET_ENCRYPTION_KEY": "CANARY-TOTP-KEY-do-not-print",
    "FEDERATION_SECRET": "CANARY-FEDERATION-do-not-print",
    "TURN_PASSWORD": "CANARY-TURN-PASS-do-not-print",
    "TURN_SECRET": "CANARY-TURN-SECRET-do-not-print",
    "GOOGLE_APPLICATION_CREDENTIALS": os.path.join(os.sep, "nonexistent", "sa.json"),
}


def test_output_never_contains_secret_values(tmp_path):
    """The doctor's output is pasted into emails. Plant canary secrets in the
    environment AND in a .env file, make the checks that touch them run, and
    assert no secret value (nor the user-ish content of the DB) is printed."""
    db = tmp_path / "messages.db"
    db.write_bytes(b"SQLite format 3\x00" + b"CANARY-MESSAGE-BODY-do-not-print" * 4)
    env = {k: v for k, v in os.environ.items() if k not in CANARIES}
    env.update({k: v for k, v in CANARIES.items() if k in ("DB_ENCRYPTION_KEY_HEX", "TURN_PASSWORD")})
    env["DB_PATH"] = str(db)
    (tmp_path / ".env").write_text(
        "FEDERATION_SECRET=%s\nTOTP_SECRET_ENCRYPTION_KEY=%s\nTURN_SECRET=%s\n"
        % (CANARIES["FEDERATION_SECRET"], CANARIES["TOTP_SECRET_ENCRYPTION_KEY"], CANARIES["TURN_SECRET"]))
    env["GOOGLE_APPLICATION_CREDENTIALS"] = CANARIES["GOOGLE_APPLICATION_CREDENTIALS"]
    p = subprocess.run([sys.executable, os.path.join(SERVER_DIR, "subrosa_doctor.py")],
                       cwd=tmp_path, env=env, capture_output=True, timeout=60)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    assert "subrosa doctor" in out
    for name, value in CANARIES.items():
        if name == "GOOGLE_APPLICATION_CREDENTIALS":
            continue  # a path, deliberately printed
        assert value not in out, f"{name} value leaked into doctor output"
    assert "CANARY-MESSAGE-BODY" not in out
    # the DB key IS set and well-formed here, yet the file is plain SQLite -> that FAIL must name the variable only
    assert "DB_ENCRYPTION_KEY_HEX" in out
    assert p.returncode == 1  # plain DB + key set is a FAIL
