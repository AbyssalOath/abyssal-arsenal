-- Gravekeeper (docs/roadmap/ad-management.md), Phase 3 P3-M3: a snapshot taken
-- when an account is offboarded, so the offboarding can be undone. It records
-- where the account was (its original OU) and which groups it was stripped from;
-- undo moves it back and re-adds those groups. One active snapshot per account
-- (the newest, with undone_at NULL); undo stamps undone_at.
CREATE TABLE directory_offboard_snapshots (
    id             CHAR(36)     NOT NULL PRIMARY KEY,
    domain_id      CHAR(36)     NOT NULL,
    -- The account's sAMAccountName / UPN (for display) and its DN after the move
    -- (in the disabled OU), which undo acts on.
    sam            VARCHAR(64)  NULL,
    upn            VARCHAR(255) NULL,
    current_dn     VARCHAR(512) NOT NULL,
    -- Where it was before offboarding, and the groups it was removed from (JSON
    -- array of DNs), so undo can restore both.
    original_ou    VARCHAR(512) NOT NULL,
    groups_json    TEXT         NULL,
    offboarded_by  CHAR(36)     NULL,
    offboarded_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- Set when undone; a non-null value means the snapshot is spent.
    undone_at      DATETIME(6)  NULL,
    CONSTRAINT fk_directory_offboard_domain FOREIGN KEY (domain_id)
        REFERENCES directory_domains(id) ON DELETE CASCADE
);
