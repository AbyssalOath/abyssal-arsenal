-- Gravekeeper (docs/roadmap/ad-management.md), Phase 2: onboarding templates.
-- A department/role template fixes where a new user lands (OU), what groups and
-- attribute defaults they get, how their username/UPN/email are formed, and the
-- mailbox type. Onboarding then asks only for a name (and a start date), builds
-- the exact change-set from the template, shows it for review, and creates it.
--
-- `mail_settings_json` is reserved for the mail milestone (P2-M3): the licensing
-- group/SKU, Exchange database, etc. It is unused until then. Groups and
-- attribute defaults are JSON (a list of group identifiers; an object of
-- attribute -> value, validated against the writable-attribute allowlist).
CREATE TABLE directory_templates (
    id               CHAR(36)     NOT NULL PRIMARY KEY,
    -- The domain this template creates users in. Removing the domain removes
    -- its templates.
    domain_id        CHAR(36)     NOT NULL,
    name             VARCHAR(100) NOT NULL,
    -- DN of the OU new users are created in (must be an OU the service account
    -- can manage). NULL = the domain's default Users container.
    target_ou        VARCHAR(512) NULL,
    -- How the sAMAccountName is formed, e.g. `{first}.{last}`, `{f}{last}`.
    username_pattern VARCHAR(128) NOT NULL DEFAULT '{first}.{last}',
    -- The UPN suffix (the right-hand side of user@suffix). NULL = the domain's
    -- own DNS name.
    upn_suffix       VARCHAR(255) NULL,
    -- How the `mail` attribute is formed (same token syntax). NULL = none.
    email_pattern    VARCHAR(128) NULL,
    -- JSON array of group identifiers (DNs) the new user is added to.
    groups_json      TEXT         NULL,
    -- JSON object of attribute defaults (e.g. {"department":"Sales"}).
    attributes_json  TEXT         NULL,
    -- none | exchange_onprem | exchange_hybrid | m365 (defaults to none; the
    -- mail milestone wires the non-none modes).
    mail_mode        VARCHAR(16)  NOT NULL DEFAULT 'none',
    -- Reserved for P2-M3: licensing group/SKU, Exchange database, etc.
    mail_settings_json TEXT       NULL,
    -- Whether onboarding must be given a manager.
    manager_required TINYINT(1)   NOT NULL DEFAULT 0,
    created_by       CHAR(36)     NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY directory_templates_domain_name (domain_id, name),
    CONSTRAINT fk_directory_templates_domain FOREIGN KEY (domain_id)
        REFERENCES directory_domains(id) ON DELETE CASCADE
);
