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


# ── path-MTU blackhole (S6) ───────────────────────────────────────────────────

IPT_WITHOUT = """-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
"""
NL = chr(10)
IPT_WITH = IPT_WITHOUT + "-A POSTROUTING -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300" + NL
NFT_WITH = NL.join(["table inet mangle {", " chain post {", "  type filter hook postrouting priority -150;",
                    "  tcp flags syn tcp option maxseg size set 1300", " }", "}", ""])


def test_mtu_parsers_on_recorded_output():
    assert d.parse_mtu_probing("1" + NL) == 1 and d.parse_mtu_probing("0" + NL) == 0
    assert d.parse_mtu_probing("") is None and d.parse_mtu_probing("garbage") is None
    assert d.has_mss_clamp(IPT_WITH) and d.has_mss_clamp(NFT_WITH)
    assert not d.has_mss_clamp(IPT_WITHOUT) and not d.has_mss_clamp("")


def test_mtu_verdict_without_protection_is_warn_not_fail():
    v = d.mtu_protection_verdict(0, False)
    assert [x[0] for x in v] == ["WARN"]
    assert "tcp_mtu_probing=1" in v[0][2] and "Small pages load, large ones hang" in v[0][2]


def test_mtu_verdict_with_protection():
    assert [x[0] for x in d.mtu_protection_verdict(1, False)] == ["PASS"]
    assert [x[0] for x in d.mtu_protection_verdict(0, True)] == ["PASS"]
    assert [x[0] for x in d.mtu_protection_verdict(1, True)] == ["PASS", "PASS"]


def test_mtu_verdict_unreadable_firewall_is_info_not_warn():
    v = d.mtu_protection_verdict(0, "unknown")
    assert [x[0] for x in v] == ["INFO"] and "sudo" in v[0][2]
    assert "FAIL" not in [x[0] for x in d.mtu_protection_verdict(None, False)]


def test_size_probe_classification():
    ok_small = (404, 300, 0.01)
    assert d.classify_size_probe(ok_small, (200, 31000, 0.05))[0] == "PASS"
    assert d.classify_size_probe(ok_small, (200, 120, 0.01))[0] == "INFO"
    assert d.classify_size_probe(ok_small, TimeoutError())[0] == "FAIL"
    assert d.classify_size_probe(None, None) is None
    assert d.classify_size_probe(Exception("x"), (200, 31000, 0.1)) is None


def _serve(handler_factory):
    import socketserver
    import threading
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_factory)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_size_probe_live_against_a_loopback_server_that_serves_both_sizes():
    import http.server

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"x" * 31000 if self.path == "/" else b"nope"
            self.send_response(200 if self.path == "/" else 404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass
    srv = _serve(H)
    try:
        port = srv.server_address[1]
        small, large = d._http_get(port, "/nothing", False), d._http_get(port, "/", False)
        assert small[0] == 404 and large[1] == 31000
        assert d.classify_size_probe(small, large)[0] == "PASS"
    finally:
        srv.shutdown()


def test_size_probe_live_detects_a_server_that_hangs_on_large_responses():
    """A real socket server that answers small requests and stalls after the headers of a large one."""
    import socketserver
    import time as _t
    CRLF = chr(13) + chr(10)

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline().decode()
            while self.rfile.readline() not in (CRLF.encode(), b""):
                pass
            if " / " in line:
                self.wfile.write(("HTTP/1.1 200 OK" + CRLF + "Content-Length: 31000" + CRLF + CRLF).encode() + b"x" * 1000)
                self.wfile.flush()
                _t.sleep(8)                      # never delivers the rest
            else:
                self.wfile.write(("HTTP/1.1 404 Not Found" + CRLF + "Content-Length: 4" + CRLF + CRLF + "nope").encode())
    srv = _serve(H)
    try:
        port = srv.server_address[1]
        small = d._http_get(port, "/nothing", False, timeout=2)
        try:
            large = d._http_get(port, "/", False, timeout=2)
        except Exception as e:
            large = e
        res = d.classify_size_probe(small, large)
        assert res and res[0] == "FAIL" and "even on loopback" in res[1]
    finally:
        srv.shutdown()
