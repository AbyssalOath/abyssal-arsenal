-- 0.2.7 N2 (docs/roadmap/0.2.7.md): RADIUS Change of Authorization (RFC 5176).
--
-- Per NAS client: how Panopticon tells it to re-authorize a session when a
-- device's trust or quarantine changes -- 'off' (existing clients keep
-- today's behaviour until an admin opts in), 'disconnect' (RFC 5176
-- Disconnect-Request: the session ends and the device re-authenticates), or
-- 'cisco_reauth' (CoA-Request with Cisco's subscriber:command=reauthenticate,
-- which re-runs authorization without dropping the link) -- and the UDP port
-- it listens on for them.
ALTER TABLE panopticon_radius_clients
    ADD COLUMN coa_mode VARCHAR(16) NOT NULL DEFAULT 'off' AFTER enabled,
    ADD COLUMN coa_port SMALLINT UNSIGNED NOT NULL DEFAULT 3799 AFTER coa_mode;

-- The latest CoA sent for a session and what the NAS said, for the sessions
-- table ("ACK", "NAK: Session-Context-Not-Found", "no response").
ALTER TABLE panopticon_radius_sessions
    ADD COLUMN last_coa_at DATETIME(6) NULL AFTER terminate_cause,
    ADD COLUMN last_coa_result VARCHAR(128) NULL AFTER last_coa_at;
