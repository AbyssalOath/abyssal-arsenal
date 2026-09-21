-- Panopticon Phase 2: managed switches (SNMP-polled for BRIDGE-MIB
-- MAC-to-port mapping -- the actual NAC-grade "which physical port is this
-- device behind" visibility) and the resulting per-device switch/port
-- location. `community_encrypted` is AES-256-GCM ciphertext (base64,
-- nonce prepended) -- see `abyssal_core::crypto` -- never plaintext at
-- rest, since a switch's SNMP community string is a real credential.

CREATE TABLE panopticon_switches (
    id                   CHAR(36)     NOT NULL PRIMARY KEY,
    name                 VARCHAR(128) NOT NULL,
    ip_address           VARCHAR(45)  NOT NULL,
    snmp_port            SMALLINT UNSIGNED NOT NULL DEFAULT 161,
    community_encrypted  TEXT         NOT NULL,
    enabled              BOOLEAN      NOT NULL DEFAULT TRUE,
    last_polled_at       DATETIME(6)  NULL,
    last_poll_error      TEXT         NULL,
    created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_panopticon_switches_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE panopticon_devices
    ADD COLUMN switch_id CHAR(36) NULL,
    ADD COLUMN switch_port VARCHAR(64) NULL,
    ADD COLUMN switch_port_seen_at DATETIME(6) NULL,
    ADD CONSTRAINT fk_panopticon_devices_switch
        FOREIGN KEY (switch_id) REFERENCES panopticon_switches(id) ON DELETE SET NULL;
