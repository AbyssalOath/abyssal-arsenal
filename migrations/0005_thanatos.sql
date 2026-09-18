-- Thanatos: classified security events (from an agent's on-demand scan or
-- the control plane's own periodic sweep) and correlation findings, both
-- stored in the same table -- a correlation finding is just a row with
-- source = 'correlation' and severity = 'critical'.

CREATE TABLE thanatos_events (
    id           CHAR(36)     NOT NULL PRIMARY KEY,
    host_id      CHAR(36)     NOT NULL,
    -- SHA-256 of host_id + source + raw_line, so re-scanning the same log
    -- tail window on every sweep is a harmless no-op (INSERT IGNORE)
    -- rather than a duplicate row.
    line_hash    CHAR(64)     NOT NULL,
    source       VARCHAR(64)  NOT NULL,
    severity     VARCHAR(16)  NOT NULL,
    label        VARCHAR(150) NOT NULL,
    raw_line     TEXT         NOT NULL,
    occurred_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_thanatos_events_hash (line_hash),
    KEY idx_thanatos_events_host_time (host_id, occurred_at),
    CONSTRAINT fk_thanatos_events_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
