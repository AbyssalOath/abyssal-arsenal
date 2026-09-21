-- Panopticon Phase 0: manual device classification (device type, trust
-- state, notes -- the first NAC-adjacent primitive, an admin-assigned trust
-- flag rather than anything enforced), plus normalizing the freeform
-- `open_ports` summary string into its own table so open ports become
-- queryable/filterable instead of just a blob of text.

ALTER TABLE panopticon_devices
    ADD COLUMN device_type VARCHAR(32) NOT NULL DEFAULT 'unknown' AFTER hostname,
    ADD COLUMN trust_state VARCHAR(16) NOT NULL DEFAULT 'unknown' AFTER device_type,
    ADD COLUMN notes TEXT NULL AFTER trust_state,
    DROP COLUMN open_ports;

CREATE TABLE panopticon_device_ports (
    device_id  CHAR(36)    NOT NULL,
    port       SMALLINT UNSIGNED NOT NULL,
    protocol   VARCHAR(10) NOT NULL,
    service    VARCHAR(64) NULL,
    PRIMARY KEY (device_id, port, protocol),
    FOREIGN KEY (device_id) REFERENCES panopticon_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
