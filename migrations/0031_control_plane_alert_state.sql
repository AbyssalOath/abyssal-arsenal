-- Firing state for control-plane self-alerts, so an alert fires once on the
-- transition into a bad state (and clears once on recovery) rather than every
-- sweep tick, and so that state survives a restart. One row per alert key
-- (e.g. "cpu", "disk", "backup_overdue", "task:health_sweep").
CREATE TABLE control_plane_alert_state (
    alert_key   VARCHAR(96)  NOT NULL PRIMARY KEY,
    firing      TINYINT(1)   NOT NULL DEFAULT 0,
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
