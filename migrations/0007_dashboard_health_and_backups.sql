-- One row per host, refreshed on every unattended health sweep tick (see
-- crates/web/src/health_ops.rs) so the dashboard has something cheap to
-- read instead of dispatching to every agent on every page load.
CREATE TABLE host_health_snapshots (
    host_id            CHAR(36)     NOT NULL PRIMARY KEY,
    failed_unit_count  INT          NOT NULL DEFAULT 0,
    error              VARCHAR(500) NULL,
    checked_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_host_health_snapshots_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per backup Reliquary actually creates, so the dashboard can show
-- fleet-wide "last backup" status without asking every agent to list its
-- own backup directory on every page load.
CREATE TABLE backup_records (
    id           CHAR(36)      NOT NULL PRIMARY KEY,
    host_id      CHAR(36)      NOT NULL,
    name         VARCHAR(255)  NOT NULL,
    source_path  VARCHAR(1024) NOT NULL,
    created_by   CHAR(36)      NULL,
    created_at   DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_backup_records_host_id (host_id),
    KEY idx_backup_records_created_at (created_at),
    CONSTRAINT fk_backup_records_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    CONSTRAINT fk_backup_records_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
