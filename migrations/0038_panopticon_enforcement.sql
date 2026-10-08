-- Panopticon NAC phase 3: SNMP-SET enforcement (port disable / VLAN
-- quarantine). This is the first Panopticon feature that *writes* to a live
-- switch, so it is gated three ways: a global kill-switch setting
-- (panopticon.enforcement_enabled), this per-switch opt-in flag, and the
-- operator's network.manage permission. All three must hold before any SNMP
-- SET is issued (see abyssal_web::panopticon_enforcement).

-- Per-switch opt-in. Defaults off for every existing and new switch -- an
-- admin has to deliberately mark a switch as safe to write to (correct
-- read-write SNMP credentials, a real quarantine VLAN provisioned) before
-- enforcement will touch it, even with the global switch on.
ALTER TABLE panopticon_switches
    ADD COLUMN enforcement_enabled BOOLEAN NOT NULL DEFAULT 0 AFTER enabled;

-- One row per enforcement action ever applied (or attempted) against a port.
-- Kept as an append-mostly audit trail: an action is never deleted, only
-- transitioned through its state column. The snapshotted original_* columns
-- are what the revert path restores to, captured by reading the switch
-- immediately before the enforcing SET so a revert returns the port to
-- exactly its prior state rather than a guessed default.
CREATE TABLE panopticon_enforcement_actions (
    id                    CHAR(36) NOT NULL PRIMARY KEY,
    switch_id             CHAR(36) NOT NULL,
    -- Switch name snapshot, so history stays readable after a rename/removal.
    switch_name           VARCHAR(255) NOT NULL,
    if_index              INT UNSIGNED NOT NULL,
    port_label            VARCHAR(255) NOT NULL,
    -- 'disable' | 'quarantine'
    kind                  VARCHAR(32) NOT NULL,
    -- 'active' | 'reverted' | 'apply_failed' | 'revert_failed'
    state                 VARCHAR(32) NOT NULL,
    -- Prior ifAdminStatus (disable) / dot1qPvid (quarantine), for revert.
    original_admin_status INT NULL,
    original_pvid         INT NULL,
    quarantine_vlan       INT NULL,
    reason                TEXT NULL,
    created_by            CHAR(36) NULL,
    created_by_username   VARCHAR(255) NULL,
    created_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- NULL = permanent (no auto-revert). Otherwise the revert sweep restores
    -- the action at/after this time.
    expires_at            DATETIME(6) NULL,
    reverted_at           DATETIME(6) NULL,
    last_error            TEXT NULL,
    -- The sweep scans for in-effect actions past their expiry.
    KEY idx_enforcement_state_expiry (state, expires_at),
    KEY idx_enforcement_switch (switch_id),
    -- At most one in-effect action per port at a time is enforced in code
    -- (panopticon_enforcement.rs), not by a DB constraint, since terminal
    -- rows for the same port accumulate as history.
    KEY idx_enforcement_switch_port (switch_id, if_index),
    -- ON DELETE CASCADE would erase the enforcement history when a switch is
    -- removed; keep it instead (switch_id/switch_name are snapshots), so no FK.
    CONSTRAINT fk_enforcement_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
