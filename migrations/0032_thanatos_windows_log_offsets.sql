-- Per-host, per-channel Windows Event Log high-water marks for Thanatos. The
-- control plane stores the newest EventRecordID it has ingested for each
-- (host, channel) and passes them back into the next ScanSecurityEvents, so the
-- Windows agent reads only events newer than it last saw -- no lost bursts
-- between scans, no re-processing, and the high-volume channels (native 4688
-- process creation, Sysmon) become affordable. `channel` is the scan's own
-- source key (e.g. "security", "system", "sysmon"), not necessarily the raw log
-- name, since two queries can target one log with different id sets.
CREATE TABLE thanatos_windows_log_offsets (
    host_id     CHAR(36)        NOT NULL,
    channel     VARCHAR(128)    NOT NULL,
    record_id   BIGINT UNSIGNED NOT NULL,
    updated_at  DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (host_id, channel),
    CONSTRAINT fk_thanatos_win_offsets_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
