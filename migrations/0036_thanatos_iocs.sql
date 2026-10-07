-- Threat-intel indicators of compromise for Thanatos (M5). Each row is an
-- indicator (an IP, a domain, or a file hash) matched against every stored
-- finding's text at ingest; a match raises a dedicated high-signal `ioc`
-- finding at the configured severity. Operators import these from a feed or add
-- them by hand. `value` is stored already-normalized (domains/hashes lowercased)
-- so matching is a direct comparison. A `(ioc_type, value)` is unique so the
-- same indicator isn't stored twice.
CREATE TABLE thanatos_iocs (
    id          CHAR(36)      NOT NULL,
    ioc_type    VARCHAR(16)   NOT NULL,
    value       VARCHAR(255)  NOT NULL,
    severity    VARCHAR(16)   NOT NULL DEFAULT 'high',
    label       VARCHAR(150)  NULL,
    created_by  CHAR(36)      NULL,
    created_at  DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at  DATETIME(6)   NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_thanatos_ioc (ioc_type, value),
    CONSTRAINT fk_thanatos_ioc_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
