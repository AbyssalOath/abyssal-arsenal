#!/bin/bash
set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <path-to-backup.sql.xz>"
    exit 1
fi

PROJECT_DIR="/srv/docker/abyssal-arsenal"
ENV_FILE="$PROJECT_DIR/.env"
DB_CONTAINER="abyssal-arsenal-db"
BACKUP_FILE="$1"

DB_NAME=$(grep -E '^MARIADB_DATABASE=' "$ENV_FILE" | cut -d '=' -f2-)
DB_ROOT_PASS=$(grep -E '^MARIADB_ROOT_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2-)

echo "About to restore $BACKUP_FILE into database '$DB_NAME'."
echo "This will OVERWRITE all current data in that database."
read -rp "Type 'yes' to continue: " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

xz -dc "$BACKUP_FILE" | docker exec -i -e MYSQL_PWD="$DB_ROOT_PASS" "$DB_CONTAINER" \
    mariadb -u root "$DB_NAME"

echo "Restore complete."
