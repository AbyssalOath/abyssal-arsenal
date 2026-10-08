-- Panopticon NAC phase 5: embedded RADIUS server (MAC Auth Bypass + dynamic
-- VLAN + accounting). Two tables: the NAS clients allowed to talk to the server
-- (with their encrypted shared secrets), and the accounted sessions that give
-- the inventory its "who authenticated where" identity.

-- A network access server (switch / AP) permitted to send RADIUS requests,
-- matched by source address and keyed to a shared secret. The secret is stored
-- encrypted at rest (abyssal_core::crypto::EncryptionKey), like switch SNMP
-- credentials -- the server decrypts it only to verify/sign a packet.
CREATE TABLE panopticon_radius_clients (
    id                     CHAR(36) NOT NULL PRIMARY KEY,
    name                   VARCHAR(255) NOT NULL,
    -- Bare IP ("10.0.0.2") or CIDR ("10.0.0.0/24") the NAS source must match.
    nas_address            VARCHAR(64) NOT NULL,
    shared_secret_encrypted TEXT NOT NULL,
    enabled                BOOLEAN NOT NULL DEFAULT 1,
    created_at             DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One accounted session. Unique per (nas_ip, acct_session_id): Interim-Update
-- refreshes last_seen_at, Stop sets stopped_at. A MAB session's username is the
-- MAC; an EAP session proxied to us carries the real username.
CREATE TABLE panopticon_radius_sessions (
    id              CHAR(36) NOT NULL PRIMARY KEY,
    username        VARCHAR(255) NULL,
    mac_address     VARCHAR(64) NULL,
    nas_ip          VARCHAR(64) NULL,
    nas_port        VARCHAR(128) NULL,
    framed_ip       VARCHAR(64) NULL,
    acct_session_id VARCHAR(255) NULL,
    auth_method     VARCHAR(32) NULL,
    started_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    stopped_at      DATETIME(6) NULL,
    terminate_cause VARCHAR(64) NULL,
    -- The accounting upsert key. nas_ip + acct_session_id uniquely identify a
    -- session across its Start/Interim/Stop lifecycle.
    UNIQUE KEY uq_radius_session (nas_ip, acct_session_id),
    KEY idx_radius_session_mac (mac_address),
    KEY idx_radius_session_last_seen (last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
