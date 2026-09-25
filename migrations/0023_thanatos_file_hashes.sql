-- Thanatos SIEM/EDR build-out, Phase 2: lightweight file-integrity
-- monitoring (FIM). Each scan (`AgentOperation::ScanSecurityEvents`) now
-- also hashes a small fixed watch-list of security-sensitive files
-- (/etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssh/sshd_config) and
-- reports the hashes back tagged `fim\t<path>\t<hash>` in the same scan
-- output. The agent stays stateless (no offset/baseline tracking on the
-- host) -- this table holds the only copy of "what did we last see" per
-- host+path, compared in `repo::thanatos_file_hashes::upsert_if_changed`.
-- A changed hash (never the very first sighting of a path, which just
-- establishes the baseline silently) emits a synthetic `high`-severity
-- `thanatos_events` row (`source = 'fim'`).
CREATE TABLE thanatos_file_hashes (
    host_id      CHAR(36)     NOT NULL,
    path         VARCHAR(255) NOT NULL,
    hash         CHAR(64)     NOT NULL,
    observed_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (host_id, path),
    CONSTRAINT fk_thanatos_file_hashes_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
