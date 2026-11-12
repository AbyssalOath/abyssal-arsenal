-- 0.2.7 (docs/roadmap/0.2.7.md, "Enforcement through RADIUS"): enforcement
-- that doesn't write to a switch. A device action is held against a MAC; the
-- RADIUS decision (embedded server or FreeRADIUS) honors it -- quarantine
-- VLAN, or reject for 'disable' -- and a CoA applies and lifts it. For
-- RADIUS-controlled devices on switches Panopticon can't (or shouldn't)
-- write over SNMP. Port actions stay in panopticon_enforcement_actions.
CREATE TABLE panopticon_device_enforcements (
    id                  CHAR(36)     NOT NULL PRIMARY KEY,
    mac_address         VARCHAR(17)  NOT NULL,
    -- The device's address when enforced, so history stays readable.
    device_ip           VARCHAR(45)  NULL,
    -- 'disable' (reject) | 'quarantine' (quarantine VLAN)
    kind                VARCHAR(32)  NOT NULL,
    -- 'active' | 'reverted'
    state               VARCHAR(32)  NOT NULL,
    reason              TEXT         NULL,
    created_by          CHAR(36)     NULL,
    created_by_username VARCHAR(255) NULL,
    created_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- NULL = permanent. Otherwise the revert sweep lifts it at this time.
    expires_at          DATETIME(6)  NULL,
    reverted_at         DATETIME(6)  NULL,
    KEY idx_device_enforcement_mac (mac_address, state),
    KEY idx_device_enforcement_due (state, expires_at),
    CONSTRAINT fk_device_enforcement_user FOREIGN KEY (created_by)
        REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
