#!/usr/bin/env bash
# deploy/upgrade.sh — update a docker-compose Subrosa server, backup first.
#
# STATUS: run on 2026-11-19 on a clean Ubuntu 24.04 host with docker compose v5: a success run
# (encrypted DB backed up, 4 s), and a deliberately broken release (SyntaxError in server.py) whose
# failure branch printed the rollback commands; running them verbatim restored a healthy server.
# Not tested: a real `git pull` from GitHub with new upstream commits (a local bare repo was the origin).

# What it does, stopping at the first problem:
#   1. records the current commit and image (what to roll back to)
#   2. takes a CONSISTENT backup of the live database (SQLite online-backup API,
#      never `cp` — the DB is in WAL mode) and reads it back (integrity_check)
#   3. pulls the code, rebuilds, restarts
#   4. waits for the container healthcheck (a real TCP connect), with a timeout
#   5. on failure prints the exact commands to go back
#
# Run from anywhere inside the repository:   bash deploy/upgrade.sh
# Options (env): SERVICE (default subrosa-server), HEALTH_TIMEOUT seconds (default 120)

SERVICE="${SERVICE:-subrosa-server}"
CONTAINER="${CONTAINER:-subrosa-messenger-server}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"
DB_IN_CONTAINER="${DB_IN_CONTAINER:-/app/data/messages.db}"
BACKUP_DIR_IN_CONTAINER="${BACKUP_DIR_IN_CONTAINER:-/app/data/backups}"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "git is not installed"
command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "'docker compose' (v2) is not available"

REPO="$(git rev-parse --show-toplevel 2>/dev/null)" || die "run this inside the Subrosa repository"
cd "$REPO/deploy" || die "cannot enter $REPO/deploy"
[ -f ../.env ] || die "../.env is missing — this does not look like a configured install"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  die "the working tree has local changes; commit or stash them first (the update would merge into them)"
fi

# 1. what to go back to
PREV_COMMIT="$(git rev-parse HEAD)"
PREV_IMAGE="$(docker compose images -q "$SERVICE" 2>/dev/null | head -n1)"
echo "Current commit: $PREV_COMMIT"
echo "Current image:  ${PREV_IMAGE:-<none found>}"

docker compose ps --status running -q "$SERVICE" | grep -q . \
  || die "the '$SERVICE' container is not running; nothing to back up. Start it first, or take the backup by hand"

# 2. consistent backup + read-back
echo "Backing up the database (online backup + integrity_check) ..."
OUT="$(docker compose exec -T "$SERVICE" python - "$DB_IN_CONTAINER" "$BACKUP_DIR_IN_CONTAINER" < db_backup.py)" \
  || die "database backup FAILED — nothing has been changed. Fix this before updating."
echo "$OUT"
BACKUP_IN_CONTAINER="$(echo "$OUT" | tail -n1)"
mkdir -p ../backups || die "cannot create ../backups"
BACKUP_LOCAL="../backups/$(basename "$BACKUP_IN_CONTAINER")"
docker compose cp "$SERVICE:$BACKUP_IN_CONTAINER" "$BACKUP_LOCAL" \
  || die "could not copy the backup out of the container (it is still inside the volume at $BACKUP_IN_CONTAINER)"
chmod 600 "$BACKUP_LOCAL" 2>/dev/null
echo "Backup copied to deploy/$BACKUP_LOCAL"

print_rollback() {
  cat <<EOF

ROLLBACK — run from $REPO/deploy:
  docker compose stop $SERVICE
  docker compose run --rm --no-deps --entrypoint sh $SERVICE -c 'rm -f ${DB_IN_CONTAINER}-wal ${DB_IN_CONTAINER}-shm'
  docker compose cp $BACKUP_LOCAL $SERVICE:$DB_IN_CONTAINER
  git checkout $PREV_COMMIT
  docker compose up -d --build
The backup above is a snapshot from BEFORE this update; messages accepted after
it was taken are not in it.
EOF
}

# 3. update
echo "Pulling ..."
git pull --ff-only || { echo "ERROR: git pull failed; nothing was rebuilt or restarted, the old server is still running." >&2; exit 1; }
NEW_COMMIT="$(git rev-parse HEAD)"
[ "$NEW_COMMIT" = "$PREV_COMMIT" ] && echo "Already up to date (still rebuilding and restarting)."

echo "Rebuilding and restarting ..."
if ! docker compose up -d --build; then
  echo "ERROR: build or start failed." >&2
  print_rollback
  exit 1
fi

# 4. wait for health
echo "Waiting up to ${HEALTH_TIMEOUT}s for the healthcheck ..."
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
status=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null)"
  [ "$status" = "healthy" ] && break
  sleep 3
done
if [ "$status" != "healthy" ]; then
  echo "ERROR: the server did not become healthy within ${HEALTH_TIMEOUT}s (last status: ${status:-unknown})." >&2
  echo "Last log lines:" >&2
  docker compose logs --tail 30 "$SERVICE" >&2
  print_rollback
  exit 1
fi

echo
echo "OK: updated $PREV_COMMIT -> $NEW_COMMIT, server healthy."
echo "Now check from a phone: connect and send a message."
echo "Keep deploy/$BACKUP_LOCAL until you are sure the update is fine."
