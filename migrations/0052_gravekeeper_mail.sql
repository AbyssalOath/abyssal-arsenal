-- Gravekeeper (docs/roadmap/ad-management.md), Phase 2 mail: one mail
-- connection per domain. The mode decides which columns matter:
--   exchange_onprem / exchange_hybrid -> the Exchange remote-PowerShell fields
--     (version, connection URI, the Recipient Management account [sealed], and
--     the domain-joined agent host that runs the session). hybrid also uses
--     remote_routing_domain for Enable-RemoteMailbox's routing address.
--   m365 -> the Microsoft Graph fields (tenant, app id, sealed certificate,
--     licensing method). These are wired in P2-M3b; the columns exist now so
--     that milestone needs no migration.
-- Secrets (the Exchange account password, the Graph certificate) are sealed with
-- ENCRYPTION_KEY, stored as ciphertext, and never logged.
CREATE TABLE directory_mail_connections (
    id                     CHAR(36)     NOT NULL PRIMARY KEY,
    domain_id              CHAR(36)     NOT NULL,
    -- none | exchange_onprem | exchange_hybrid | m365.
    mode                   VARCHAR(16)  NOT NULL DEFAULT 'none',
    -- Exchange (on-prem / hybrid):
    exchange_version       VARCHAR(8)   NULL,  -- 2016 | 2019 | se
    exchange_uri           VARCHAR(512) NULL,  -- e.g. http://exch01/PowerShell/
    exchange_account_upn   VARCHAR(255) NULL,  -- Recipient Management account
    exchange_account_sealed TEXT        NULL,
    -- The domain-joined host whose agent opens the Exchange remote session.
    exchange_agent_host_id CHAR(36)     NULL,
    -- Hybrid only: the routing domain for RemoteRoutingAddress
    -- (user@<this>, typically tenant.mail.onmicrosoft.com).
    remote_routing_domain  VARCHAR(255) NULL,
    -- Microsoft 365 (Graph), reserved for P2-M3b:
    m365_tenant_id         VARCHAR(255) NULL,
    m365_app_id            VARCHAR(255) NULL,
    m365_cert_sealed       TEXT         NULL,
    m365_licensing_method  VARCHAR(8)   NULL,  -- group | direct | both
    -- Last "Test connection" result.
    last_test_at           DATETIME(6)  NULL,
    last_test_ok           TINYINT(1)   NULL,
    last_test_detail       TEXT         NULL,
    created_by             CHAR(36)     NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY directory_mail_connections_domain (domain_id),
    CONSTRAINT fk_directory_mail_conn_domain FOREIGN KEY (domain_id)
        REFERENCES directory_domains(id) ON DELETE CASCADE,
    CONSTRAINT fk_directory_mail_conn_host FOREIGN KEY (exchange_agent_host_id)
        REFERENCES hosts(id) ON DELETE SET NULL
);
