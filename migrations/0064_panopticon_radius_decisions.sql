-- Panopticon NAC 0.2.9 Q2 (docs/roadmap/0.2.9.md): decision records.
--
-- One row per RADIUS admission decision, from either front end (the
-- embedded server or FreeRADIUS), with what it was based on, so "why is
-- this device in quarantine?" is answered on a page instead of in the
-- server log. Rejected logins have no session, so there's no foreign key:
-- a session's decision is found by MAC and NAS. Kept for
-- panopticon.radius_decision_retention_days (default 30).
CREATE TABLE panopticon_radius_decisions (
    id                CHAR(36)          NOT NULL PRIMARY KEY,
    decided_at        DATETIME(6)       NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- Lowercase colon form; NULL for an 802.1X login without a MAC.
    mac_address       VARCHAR(17)       NULL,
    -- The NAS client that asked (NULL: not a known client), and the
    -- address it asked from.
    nas_client_id     CHAR(36)          NULL,
    nas_name          VARCHAR(128)      NULL,
    nas_address       VARCHAR(64)       NULL,
    -- 'embedded' | 'freeradius'
    front_end         VARCHAR(16)       NOT NULL,
    -- 'mab' | 'dot1x'
    admission         VARCHAR(16)       NOT NULL,
    -- The login (the real one, for PEAP), or the MAC for MAB.
    identity          VARCHAR(255)      NULL,
    -- 'accept' | 'reject'
    outcome           VARCHAR(8)        NOT NULL,
    vlan              SMALLINT UNSIGNED NULL,
    -- The role sent (NULL: none, including for a NAS without a role
    -- attribute).
    role              VARCHAR(64)       NULL,
    session_timeout   INT UNSIGNED      NULL,
    -- What it was based on.
    reason            VARCHAR(255)      NOT NULL,
    trust_state       VARCHAR(16)       NULL,
    enforcement       VARCHAR(16)       NULL,
    signal_action     VARCHAR(16)       NULL,
    signal_detail     VARCHAR(512)      NULL,
    group_rule        VARCHAR(256)      NULL,
    -- The login's AD groups that have a rule, ';'-separated: what a
    -- re-evaluation (Q3) decides with, since it can't ask AD itself.
    ad_groups         VARCHAR(2000)     NULL,
    KEY idx_radius_decision_mac (mac_address, decided_at),
    KEY idx_radius_decision_time (decided_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The policy engine's Simulate mode (B6): what each rule would have done,
-- one row per rule and device, updated every sweep it still matches.
CREATE TABLE panopticon_policy_simulations (
    rule_id         CHAR(36)      NOT NULL,
    device_id       CHAR(36)      NOT NULL,
    rule_name       VARCHAR(128)  NOT NULL,
    device_ip       VARCHAR(45)   NOT NULL,
    mac_address     VARCHAR(17)   NULL,
    -- 'disable' | 'quarantine'
    action          VARCHAR(16)   NOT NULL,
    -- 'port' (SNMP) | 'radius' | 'skipped'
    path            VARCHAR(16)   NOT NULL,
    -- The port, or why it wouldn't be enforced, and the signal.
    detail          VARCHAR(512)  NOT NULL,
    first_seen_at   DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at    DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    times_seen      INT UNSIGNED  NOT NULL DEFAULT 1,
    PRIMARY KEY (rule_id, device_id),
    KEY idx_policy_simulation_seen (last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
