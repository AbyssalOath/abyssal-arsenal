-- Panopticon: network discovery/device inventory, plus the connecting IP
-- address for enrolled hosts (captured at WebSocket connect time), used to
-- correlate discovered devices against known agent-managed hosts.

ALTER TABLE hosts ADD COLUMN last_seen_ip VARCHAR(45) NULL AFTER last_seen_at;

CREATE TABLE panopticon_devices (
    id             CHAR(36)     NOT NULL PRIMARY KEY,
    ip_address     VARCHAR(45)  NOT NULL,
    mac_address    VARCHAR(17)  NULL,
    hostname       VARCHAR(255) NULL,
    open_ports     TEXT         NULL,
    first_seen_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_panopticon_devices_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
