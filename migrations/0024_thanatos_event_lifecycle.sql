-- Thanatos SIEM/EDR build-out, Phase 3: a manual, analyst-driven lifecycle
-- for security events -- the first real use of `security.manage`
-- (`Permission::SecurityManage`, defined since this app's early days but
-- never gated an actual action until now). Every event starts 'open';
-- nothing in this app ever transitions a status automatically -- a
-- re-scan matching the same content hash is a no-op via `INSERT IGNORE`,
-- never a "reopen" of something an analyst already acknowledged/resolved/
-- suppressed. `acknowledged_by`/`acknowledged_at` track whoever last
-- changed the status away from 'open', regardless of which of the three
-- transitions it was -- there's no separate resolved_by/suppressed_by,
-- since only one transition can be "the current one" at a time anyway.
ALTER TABLE thanatos_events
    ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'open' AFTER raw_line,
    ADD COLUMN acknowledged_by CHAR(36) NULL AFTER status,
    ADD COLUMN acknowledged_at DATETIME(6) NULL AFTER acknowledged_by,
    ADD COLUMN resolution_note VARCHAR(500) NULL AFTER acknowledged_at,
    ADD INDEX idx_thanatos_events_status (status),
    ADD CONSTRAINT fk_thanatos_events_acknowledged_by FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL;
