-- Gravekeeper (docs/roadmap/ad-management.md), Phase 1: the configured
-- Active Directory domains a control plane manages. One row per domain
-- (a single-domain forest is just one row). Directory changes run on the
-- domain's write DC through the Haruspex DC agent, under the delegated
-- service account whose credentials are sealed here with ENCRYPTION_KEY --
-- the same way install-token secrets and SNMP communities are stored. Until
-- a domain has a validated service account, Gravekeeper stays read-only for
-- it.
--
-- The remaining data-model tables in the roadmap (mail connections,
-- templates, onboarding/offboarding jobs and their steps, offboard
-- snapshots) arrive with the phases that use them; Phase 1 needs only this.
-- Global flags (e.g. whether first-run setup has been completed) live in
-- `settings` under `gravekeeper.*`, audited the same way every other setting
-- change is.
CREATE TABLE directory_domains (
    id                       CHAR(36)     NOT NULL PRIMARY KEY,
    -- The domain's DNS name (e.g. corp.example.com); the unique identity.
    dns_name                 VARCHAR(255) NOT NULL,
    -- NetBIOS/short name (e.g. CORP), discovered from the forest.
    netbios_name             VARCHAR(64)  NULL,
    -- The forest root domain this belongs to, for multi-domain forests.
    forest_root              VARCHAR(255) NULL,
    -- The DC agent every change for this domain is sent to (the PDC emulator
    -- by default). SET NULL if that host is removed -- the domain config and
    -- its sealed credentials survive; writes just wait until a write DC is
    -- reselected.
    write_dc_host_id         CHAR(36)     NULL,
    -- The delegated service account: its UPN/username and sealed password.
    -- NULL until setup's service-account step is completed. The agent's
    -- SYSTEM identity is never used for writes.
    service_account_upn      VARCHAR(255) NULL,
    service_account_sealed   TEXT         NULL,
    -- Where offboarded accounts go. Defaults to OU=Disabled Users at the
    -- domain root (created at setup if missing); changeable per domain.
    disabled_ou              VARCHAR(512) NULL,
    -- How long an offboarded account waits in the disabled OU before Delete
    -- is offered. 0 offers it immediately (still a separate step).
    deletion_grace_days      INT          NOT NULL DEFAULT 30,
    -- none | exchange_onprem | exchange_hybrid | m365. The mail connection
    -- details themselves land in directory_mail_connections in a later phase.
    mail_mode                VARCHAR(16)  NOT NULL DEFAULT 'none',
    -- The last DirectoryTestDelegation result: when it ran, whether it
    -- passed, and a JSON detail (manageable OUs, overprivilege findings).
    last_delegation_check_at DATETIME(6)  NULL,
    last_delegation_ok       TINYINT(1)   NULL,
    last_delegation_detail   TEXT         NULL,
    created_by               CHAR(36)     NULL,
    created_at               DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at               DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY directory_domains_dns (dns_name),
    CONSTRAINT fk_directory_domains_write_dc FOREIGN KEY (write_dc_host_id)
        REFERENCES hosts(id) ON DELETE SET NULL
);
