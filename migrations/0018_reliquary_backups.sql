-- GitHub issue #9: native (control-plane) backups under Reliquary. One
-- row per backup job/attempt -- manual or scheduled, whatever its outcome.
-- `job_type` is 'native' for everything this migration's feature
-- produces; a future Remote/Agent mode (out of scope now) would add
-- 'remote' without needing a new table, per the two-provider design in
-- `crates/web/src/reliquary_backup/`.
--
-- Concurrency (no duplicate/conflicting scheduled runs across restarts or
-- multiple instances) uses MariaDB's session-scoped `GET_LOCK()`/
-- `RELEASE_LOCK()` named locks, not a table -- see
-- `reliquary_backup::orchestrator::with_backup_lock`. A job stuck in
-- `running` because the process crashed mid-backup is swept to `failed`
-- at the next startup (`reliquary_backup::recover_interrupted_jobs`),
-- since a held `GET_LOCK` alone doesn't rewrite the row itself.

CREATE TABLE reliquary_backups (
    id                        CHAR(36)      NOT NULL PRIMARY KEY,
    job_type                  VARCHAR(16)   NOT NULL DEFAULT 'native',
    status                    VARCHAR(16)   NOT NULL,
    trigger_source            VARCHAR(16)   NOT NULL,
    components                JSON          NOT NULL,
    encrypted                 BOOLEAN       NOT NULL DEFAULT FALSE,
    includes_encryption_keys  BOOLEAN       NOT NULL DEFAULT FALSE,
    destination_path          VARCHAR(1024) NOT NULL,
    file_name                 VARCHAR(255)  NULL,
    size_bytes                BIGINT UNSIGNED NULL,
    sha256                    CHAR(64)      NULL,
    manifest_json             JSON          NULL,
    error_message             TEXT          NULL,
    verification_status       VARCHAR(16)   NULL,
    verification_at           DATETIME(6)   NULL,
    verification_details      TEXT          NULL,
    started_at                DATETIME(6)   NULL,
    finished_at               DATETIME(6)   NULL,
    created_by                CHAR(36)      NULL,
    created_at                DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_reliquary_backups_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_reliquary_backups_status (status),
    INDEX idx_reliquary_backups_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
