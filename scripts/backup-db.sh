#!/bin/bash
set -euo pipefail

# --- Configuration -- edit PROJECT_DIR to match where this actually lives ---
PROJECT_DIR="/srv/docker/abyssal-arsenal"
ENV_FILE="$PROJECT_DIR/.env"
DB_CONTAINER="abyssal-arsenal-db"
BACKUP_DIR="/var/backups/abyssal-arsenal"
RETENTION_COUNT=14

mkdir -p "$BACKUP_DIR"

# Pull MARIADB_DATABASE and MARIADB_ROOT_PASSWORD out of .env without
# exporting every other secret in that file into this script's environment.
DB_NAME=$(grep -E '^MARIADB_DATABASE=' "$ENV_FILE" | cut -d '=' -f2-)
DB_ROOT_PASS=$(grep -E '^MARIADB_ROOT_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2-)

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_FILE="$BACKUP_DIR/abyssal-arsenal-${TIMESTAMP}.sql.xz"

# MYSQL_PWD as an env var, rather than mariadb-dump's -p flag, keeps the
# password out of the process list (`ps aux` on most systems shows every
# process's command-line arguments to any user, but not its environment
# variables) -- a small, cheap hardening step for a script that's going to
# run unattended every night.
docker exec -e MYSQL_PWD="$DB_ROOT_PASS" "$DB_CONTAINER" \
  mariadb-dump --single-transaction --quick -u root "$DB_NAME" \
  | xz > "$BACKUP_FILE"

chmod 600 "$BACKUP_FILE"

# Keep only the most recent $RETENTION_COUNT backups. The timestamp format
# above is zero-padded and year-first, so a plain alphabetical sort is also
# a chronological sort -- no need to parse dates out of filenames.
ls -1t "$BACKUP_DIR"/abyssal-arsenal-*.sql.xz | tail -n +$((RETENTION_COUNT + 1)) | xargs -r rm --

echo "Backup complete: $BACKUP_FILE"
