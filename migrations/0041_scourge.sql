-- Scourge NAC/IDS phase 3: the control-plane cache and per-host sensor state.
-- This is a BOUNDED working set for live views, NOT a history store (that's
-- Obituary) and NOT a duplicate of thanatos_events (that's the SIEM, which
-- Scourge forwards into separately). It is pruned by age
-- (scourge.event_retention_days) and a hard row cap.

-- One cached alert, parsed from a host's EVE JSON by the collection sweep. The
-- sweep forwards qualifying alerts into Thanatos's ingest path too; this table
-- only backs Scourge's own filterable live views.
CREATE TABLE scourge_alerts (
    id          CHAR(36) NOT NULL PRIMARY KEY,
    host_id     CHAR(36) NOT NULL,
    -- From the EVE record's own timestamp (falls back to ingest time if absent
    -- or unparseable), so the UI's time filter reflects when the alert fired.
    occurred_at DATETIME(6) NOT NULL,
    severity    VARCHAR(16) NOT NULL,   -- low | medium | high | critical
    sid         INT UNSIGNED NULL,
    signature   VARCHAR(255) NOT NULL,
    category    VARCHAR(128) NULL,
    proto       VARCHAR(16) NULL,
    src_ip      VARCHAR(64) NULL,
    src_port    INT UNSIGNED NULL,
    dst_ip      VARCHAR(64) NULL,
    dst_port    INT UNSIGNED NULL,
    -- Content hash for idempotent inserts: a rotation-reset re-read (the sweep
    -- restarting from offset 0 of a rotated file) must not duplicate an alert
    -- already cached. Includes occurred_at so genuinely distinct occurrences of
    -- the same signature at different times stay separate rows.
    line_hash   CHAR(64) NOT NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_scourge_alert (line_hash),
    KEY idx_scourge_alert_host_time (host_id, occurred_at),
    KEY idx_scourge_alert_time (occurred_at),
    KEY idx_scourge_alert_severity (severity),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-host sensor/collection state: the EVE read cursor (inode + byte offset,
-- the rotation-safe high-water mark the sweep passes back to the agent each
-- tick) and whether the EVE log is currently readable, so the "needs
-- permissions" state can be shown on the page and tiles without a live dispatch.
CREATE TABLE scourge_sensor_state (
    host_id           CHAR(36) NOT NULL PRIMARY KEY,
    eve_inode         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    eve_offset        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    eve_readable      BOOLEAN NOT NULL DEFAULT 1,
    -- The "unreadable" reason (or last collection error), shown in the UI.
    last_error        VARCHAR(512) NULL,
    last_collected_at DATETIME(6) NULL,
    updated_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                          ON UPDATE CURRENT_TIMESTAMP(6),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
