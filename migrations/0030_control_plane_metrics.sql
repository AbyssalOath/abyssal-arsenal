-- Control-plane self-metrics history: the server's OWN CPU / memory / disk
-- usage over time, sampled by `crate::self_metrics`. Kept separate from
-- `host_metric_samples` (no host_id, no foreign key) so the fleet/host queries
-- stay clean -- these are the machine Abyssal Arsenal itself runs on.
CREATE TABLE control_plane_metric_samples (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    metric      VARCHAR(64)  NOT NULL,
    value       DOUBLE       NOT NULL,
    sampled_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_control_plane_metric_samples_lookup (metric, sampled_at),
    KEY idx_control_plane_metric_samples_sampled_at (sampled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
