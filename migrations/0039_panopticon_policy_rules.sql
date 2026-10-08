-- Panopticon NAC phase 4: auto-enforcement policy rules. An ordered list of
-- rules, each pairing a trigger (untrusted / new-unknown device) with an action
-- (disable / quarantine) and optional scope filters (subnet / switch / device
-- type). The background policy sweep (abyssal_web::panopticon_policy) evaluates
-- enabled rules in ascending priority and acts on the first match -- subject to
-- the engine mode (off/simulate/active, panopticon.auto_enforce_mode) and every
-- M3 enforcement gate.
CREATE TABLE panopticon_policy_rules (
    id              CHAR(36) NOT NULL PRIMARY KEY,
    -- Lower priority runs first. The CRUD layer keeps these distinct and
    -- supports reordering by swapping adjacent values.
    priority        INT NOT NULL,
    name            VARCHAR(255) NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT 1,
    -- 'untrusted' | 'new_unknown'
    trigger_kind    VARCHAR(32) NOT NULL,
    -- 'disable' | 'quarantine' (reuses EnforcementKind)
    action          VARCHAR(32) NOT NULL,
    -- Scope filters; NULL = "any". subnet matches the device's normalized
    -- network string (e.g. "10.0.9.0/24").
    subnet          VARCHAR(64) NULL,
    switch_id       CHAR(36) NULL,
    device_type     VARCHAR(64) NULL,
    -- Auto-revert timeout for actions this rule applies: NULL = use the global
    -- default, 0 = permanent, n = n minutes.
    timeout_minutes INT UNSIGNED NULL,
    created_by      CHAR(36) NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_policy_priority (priority),
    -- A deleted switch just nulls the scope (rule becomes "any switch") rather
    -- than deleting the rule.
    CONSTRAINT fk_policy_switch FOREIGN KEY (switch_id)
        REFERENCES panopticon_switches(id) ON DELETE SET NULL,
    CONSTRAINT fk_policy_user FOREIGN KEY (created_by)
        REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
