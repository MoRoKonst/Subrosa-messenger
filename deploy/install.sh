#!/usr/bin/env bash
# deploy/install.sh — one-script install of a Subrosa server with docker compose.
#
# STATUS: run end to end on a clean Ubuntu 24.04 host on 2026-11-19, twice --
# once from a bare machine (about 7 minutes from nothing to a healthy stack,
# most of it the image build) and once more on top of itself to check that it
# leaves an existing .env and certificate alone. Three defects in the
# documented path were found by doing that and fixed in the same pass: a
# pinned miniupnpc version that no longer exists in Debian 13, a missing
# executable bit on generate-certs.sh, and a UTF-8 BOM in deploy/nginx.conf
# that nginx rejects outright.
#
# Does exactly this, and stops with a plain message at the first problem:
#   1. checks docker and docker compose
#   2. TLS certificate: uses deploy/certs/{cert.pem,key.pem} if present (put your real
#      one there), otherwise generates a SELF-SIGNED one (generate-certs.sh) and says so
#   3. creates ../.env from ../.env.example ONLY if it does not exist, filling the
#      values that must be random, and lists what YOU must fill in
#   4. starts the stack and WAITS for the healthcheck
#   5. with ACCESS_CODES=N (default 5) prints N one-time access links
#   6. prints what to check from a phone
#
# Safe to re-run: an existing .env is never touched, an existing certificate is
# never overwritten, `up -d` leaves a running stack alone.
#
# Usage:  SERVER_URL=wss://chat.example.com ACCESS_CODES=5 bash deploy/install.sh

HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"
# Access-code protection (SERVER_ACCESS_PROTECTED) is OFF by default here because whether a
# server is open or invite-only is the operator's decision, not an installer's. It is safe to
# turn on: the UnboundLocalError that used to crash start_server() under it is fixed, and a
# regression test (Server/tests/test_no_shadowed_imports.py) keeps that class of bug out.
# A firm deployment wants it ON -- pass ACCESS_CODES=5 and set SERVER_ACCESS_PROTECTED=true
# in .env.
ACCESS_CODES="${ACCESS_CODES:-0}"
CONTAINER="subrosa-messenger-server"

die() { echo "ERROR: $*" >&2; exit 1; }
rand_hex() { python3 -c "import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))" "$1" 2>/dev/null || openssl rand -hex "$1"; }

command -v docker >/dev/null 2>&1 || die "docker is not installed. Install Docker Engine first: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "'docker compose' (v2) is not available. Install the compose plugin: https://docs.docker.com/compose/install/"
docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon (is it running? are you in the 'docker' group, or use sudo?)"
command -v openssl >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1 || die "need python3 or openssl to generate random secrets"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$HERE" || die "cannot enter $HERE"

# 2. certificate
if [ -f certs/cert.pem ] && [ -f certs/key.pem ]; then
  echo "TLS: using existing deploy/certs/cert.pem + key.pem"
else
  command -v openssl >/dev/null 2>&1 || die "no certificate in deploy/certs/ and openssl is not installed to make one"
  echo "TLS: no certificate found - generating a SELF-SIGNED one."
  echo "     Phones will not trust it. For real use put a real certificate in deploy/certs/ (docs/DEPLOY.md)."
  mkdir -p certs
  openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Subrosa/CN=Subrosa.local" >/dev/null 2>&1 || die "certificate generation failed"
  chmod 600 certs/key.pem
fi

# 3. .env
NEED_BY_HAND=()
if [ -f "$ROOT/.env" ]; then
  echo ".env: exists - left untouched"
else
  [ -f "$ROOT/.env.example" ] || die "$ROOT/.env.example is missing"
  cp "$ROOT/.env.example" "$ROOT/.env" && chmod 600 "$ROOT/.env" || die "cannot create $ROOT/.env"
  set_var() {  # set_var NAME VALUE  (only replaces an EMPTY assignment)
    if grep -q "^$1=\$" "$ROOT/.env"; then sed -i "s|^$1=\$|$1=$2|" "$ROOT/.env"; else echo "$1=$2" >> "$ROOT/.env"; fi
  }
  # NOTE: DB_ENCRYPTION_KEY_HEX cannot be added later to an existing database - decide NOW.
  set_var DB_ENCRYPTION_KEY_HEX "$(rand_hex 32)"
  set_var TOTP_SECRET_ENCRYPTION_KEY "$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' 2>/dev/null)"
  [ -n "${SERVER_URL:-}" ] && set_var SERVER_URL "$SERVER_URL"
  echo ".env: created from .env.example (mode 600). Generated: DB_ENCRYPTION_KEY_HEX (TOTP key if cryptography is installed)."
  echo "      !! BACK UP .env SEPARATELY from the database: without DB_ENCRYPTION_KEY_HEX the data is unreadable."
  grep -q "^TOTP_SECRET_ENCRYPTION_KEY=.\+" "$ROOT/.env" || NEED_BY_HAND+=("TOTP_SECRET_ENCRYPTION_KEY (needs python3 + 'cryptography' to generate; see .env.example)")
fi
grep -q "^SERVER_URL=.\+" "$ROOT/.env" || NEED_BY_HAND+=("SERVER_URL (your public wss:// address, needed for the access links)")
if [ "${#NEED_BY_HAND[@]}" -gt 0 ]; then
  echo "YOU must fill in by hand in $ROOT/.env:"; printf '  - %s\n' "${NEED_BY_HAND[@]}"
fi

# 4. start and wait
echo "Starting the stack (first build takes a few minutes) ..."
docker compose up -d --build || die "docker compose up failed - see the output above"
echo "Waiting up to ${HEALTH_TIMEOUT}s for the server healthcheck ..."
deadline=$(( $(date +%s) + HEALTH_TIMEOUT )); status=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null)"
  [ "$status" = "healthy" ] && break
  sleep 3
done
if [ "$status" != "healthy" ]; then
  echo "ERROR: server did not become healthy (status: ${status:-unknown}). Last log lines:" >&2
  docker compose logs --tail 30 subrosa-server >&2
  echo "Run: python3 Server/subrosa_doctor.py   and send us the output (docs/DEPLOY.md, Troubleshooting)." >&2
  exit 1
fi
echo "Server is healthy."

# 5. access codes (they are only shown once; the server stores hashes) — needs SERVER_ACCESS_PROTECTED=true
if [ "$ACCESS_CODES" -gt 0 ] 2>/dev/null && [ -f "$ROOT/Server/admin_gen_codes.py" ]; then
  echo "Generating $ACCESS_CODES one-time access codes ..."
  # The image contains only server.py, so run the generator from the host against the volume's DB via a throwaway container.
  docker compose run --rm --no-deps -T -e SERVER_URL="${SERVER_URL:-}" --entrypoint python subrosa-server - "$ACCESS_CODES" \
    < "$ROOT/Server/admin_gen_codes.py" || echo "WARN: could not generate codes automatically; see docs/DEPLOY.md" >&2
fi

# 6. what to check
cat <<EOF

DONE. Check from a PHONE (mobile data, not your Wi-Fi):
  1. install the app, add the server (the access link above), register
  2. send a message to a second phone / the desktop client and confirm it arrives
If something fails:  python3 Server/subrosa_doctor.py   and send the output.
EOF
