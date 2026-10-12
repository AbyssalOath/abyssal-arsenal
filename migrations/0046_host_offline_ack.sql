-- "Known offline": an admin can acknowledge that a host is offline or not
-- responding on purpose (powered off, in storage, on leave). While it is,
-- the dashboard doesn't count it as degraded or list it as needing
-- attention. Cleared automatically when the host connects or answers a
-- health check again.
ALTER TABLE hosts
    ADD COLUMN offline_ack_at DATETIME(6) NULL AFTER is_control_plane,
    ADD COLUMN offline_ack_by VARCHAR(255) NULL AFTER offline_ack_at;
