-- Operator-configured thresholds for Mortiscope metric alerting, managed from
-- the Mortiscope thresholds page and acted on by the metrics sweep when
-- mortiscope.monitoring_enabled is on.
CREATE TABLE monitoring_thresholds (
    id          CHAR(36)     NOT NULL PRIMARY KEY,
    metric      VARCHAR(64)  NOT NULL,
    comparator  VARCHAR(2)   NOT NULL,           -- 'ge' (>=) or 'le' (<=)
    threshold   DOUBLE       NOT NULL,
    severity    VARCHAR(16)  NOT NULL,           -- info | warning | critical
    enabled     TINYINT(1)   NOT NULL DEFAULT 1,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_monitoring_thresholds_metric (metric)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-host, per-metric firing state, so the sweep alerts on the transition
-- into a sustained breach (not every tick) and clears on recovery.
CREATE TABLE monitoring_alert_state (
    host_id  CHAR(36)     NOT NULL,
    metric   VARCHAR(64)  NOT NULL,
    firing   TINYINT(1)   NOT NULL DEFAULT 0,
    since    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (host_id, metric),
    CONSTRAINT fk_monitoring_alert_state_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
