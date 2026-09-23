-- Optional least-privilege MariaDB user for Reliquary's native database
-- backups (GitHub issue #9). The app falls back to its own MARIADB_USER
-- credentials (with a startup warning) if this isn't set up -- fine for
-- local testing, not recommended for a real deployment, since that user
-- can also write to every table.
--
-- Run this once against the running mariadb service, e.g.:
--   docker compose exec mariadb mariadb -u root -p < scripts/reliquary-backup-grants.sql
-- (substitute the database name and password below first).
--
-- Then set RELIQUARY_BACKUP_DB_USER / RELIQUARY_BACKUP_DB_PASSWORD in
-- .env to these values and restart the app.

CREATE USER IF NOT EXISTS 'abyssal_backup'@'%' IDENTIFIED BY 'change-this-password';

-- SELECT: read every table's rows.
-- SHOW VIEW: mariadb-dump needs this to dump view definitions.
-- TRIGGER: needed for --triggers.
-- EVENT: needed for --events.
-- LOCK TABLES: needed for --single-transaction to establish a consistent
--   snapshot cleanly even on tables that aren't InnoDB.
-- PROCESS: optional -- only needed if you want this user to also be able
--   to run `SHOW PROCESSLIST` for diagnostics; not required for a dump.
GRANT SELECT, SHOW VIEW, TRIGGER, EVENT, LOCK TABLES
    ON abyssal_arsenal.* TO 'abyssal_backup'@'%';

FLUSH PRIVILEGES;
