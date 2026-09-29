-- Time-series samples of key Mortiscope metrics per host, written by the
-- unattended metrics sweep (crates/web/src/mortiscope_ops.rs) so the
-- Mortiscope page can show recent trends without re-polling on every load,
-- and so later phases can alert on a sustained threshold breach. Pruned to a
-- bounded retention window by the same sweep, so the table can't grow without
-- limit.
CREATE TABLE host_metric_samples (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    host_id     CHAR(36)     NOT NULL,
    metric      VARCHAR(64)  NOT NULL,
    value       DOUBLE       NOT NULL,
    sampled_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_host_metric_samples_lookup (host_id, metric, sampled_at),
    KEY idx_host_metric_samples_sampled_at (sampled_at),
    CONSTRAINT fk_host_metric_samples_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
