-- Thanatos suppression / allowlist rules (M4). Each rule is matched against
-- every incoming classified finding at ingest; a finding matching any active
-- rule is dropped (never persisted, never alerted), which is how an operator
-- silences a class of noisy-but-benign finding or allowlists a known-good
-- indicator (a monitoring host's IP, a service account) without it re-appearing
-- on every scan. Every non-NULL column is an AND criterion; a NULL column is a
-- wildcard. A rule with every criterion NULL would match everything and is
-- rejected control-plane-side. `host_id` NULL = fleet-wide.
CREATE TABLE thanatos_suppression_rules (
    id             CHAR(36)      NOT NULL,
    host_id        CHAR(36)      NULL,
    source         VARCHAR(64)   NULL,
    label          VARCHAR(150)  NULL,
    technique      VARCHAR(16)   NULL,
    text_contains  VARCHAR(255)  NULL,
    reason         VARCHAR(500)  NULL,
    created_by     CHAR(36)      NULL,
    created_at     DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at     DATETIME(6)   NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_thanatos_suppress_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    CONSTRAINT fk_thanatos_suppress_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
