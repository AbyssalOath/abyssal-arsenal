-- Sepulchre: storage & file-sharing connectivity (SFTP/SMB/local
-- connections, host-side shares/mounts, and validation). Protocol,
-- access method, role, and capability are kept as separate concepts
-- (see crates/core/src/storage.rs) rather than one flat table with
-- protocol-specific columns -- `protocol_config` holds per-protocol
-- settings as validated JSON (the same JSON-column-plus-Rust-enum
-- convention `reliquary_backups.components`/`manifest_json` already use
-- in this codebase), and role/capability/access-method are their own
-- small join tables so a connection's "what is this for" and "what can
-- it actually do" are never conflated with "what does it speak".

CREATE TABLE storage_connections (
    id                      CHAR(36)      NOT NULL PRIMARY KEY,
    name                    VARCHAR(100)  NOT NULL,
    protocol                VARCHAR(16)   NOT NULL,
    origin                  VARCHAR(24)   NOT NULL,
    managed_host_id         CHAR(36)      NULL,
    protocol_config         JSON          NOT NULL,
    enabled                 BOOLEAN       NOT NULL DEFAULT TRUE,
    last_validation_status  VARCHAR(16)   NULL,
    last_validation_at      DATETIME(6)   NULL,
    created_by              CHAR(36)      NULL,
    created_at              DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at              DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_storage_connections_name (name),
    -- A host-side-managed connection is blocked from deletion while this
    -- FK exists; the host must be un-enrolled/reassigned first, same
    -- safety posture as `roles.parent_role_id`'s RESTRICT.
    CONSTRAINT fk_storage_connections_host FOREIGN KEY (managed_host_id) REFERENCES hosts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_storage_connections_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_storage_connections_protocol (protocol),
    INDEX idx_storage_connections_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The connection's own encrypted secret (password, or an imported/
-- generated SFTP private key), kept in its own table rather than a
-- column on `storage_connections` so a secret rotation/replacement never
-- touches the connection row's own `updated_at`/audit shape, and so a
-- `local` connection (which never has one) doesn't carry a permanently
-- NULL secret column. Ciphertext only -- see
-- `abyssal_core::crypto::EncryptionKey`, the same AES-256-GCM mechanism
-- already used for Panopticon switch credentials and Reliquary's
-- encryption-keys backup component. `secret_key_id` is always the fixed
-- constant `"env:ENCRYPTION_KEY"` today (this platform has exactly one
-- master key, no rotation support yet) -- present now so a future
-- multi-key rotation doesn't need a schema change, not because rotation
-- is implemented in this pass.
CREATE TABLE storage_connection_secrets (
    connection_id      CHAR(36)     NOT NULL PRIMARY KEY,
    secret_ciphertext  TEXT         NOT NULL,
    secret_key_id      VARCHAR(64)  NOT NULL DEFAULT 'env:ENCRYPTION_KEY',
    secret_version     INT UNSIGNED NOT NULL DEFAULT 1,
    -- For an SSH-key-authenticated SFTP connection: the *public* half and
    -- its fingerprint, shown in the UI so an admin can install it on the
    -- remote server -- never the private key material.
    public_key         TEXT         NULL,
    key_fingerprint    CHAR(64)     NULL,
    updated_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    updated_by         CHAR(36)     NULL,
    CONSTRAINT fk_storage_connection_secrets_connection FOREIGN KEY (connection_id) REFERENCES storage_connections(id) ON DELETE CASCADE,
    CONSTRAINT fk_storage_connection_secrets_updated_by FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE connection_roles (
    connection_id  CHAR(36)     NOT NULL,
    role           VARCHAR(24)  NOT NULL,
    PRIMARY KEY (connection_id, role),
    CONSTRAINT fk_connection_roles_connection FOREIGN KEY (connection_id) REFERENCES storage_connections(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- `declared` is the admin's stated intent at setup time; `verified_at`/
-- `verified_by_validation_run_id` are only ever set by a successful
-- validation run's actual read/write test and cleared by a failure or
-- regression -- a consumer must only ever rely on the verified half (see
-- `StorageConnectionResolver::resolve` in crates/web/src/sepulchre/).
CREATE TABLE connection_capabilities (
    connection_id                 CHAR(36)     NOT NULL,
    capability                    VARCHAR(16)  NOT NULL,
    declared                      BOOLEAN      NOT NULL DEFAULT FALSE,
    verified_at                   DATETIME(6)  NULL,
    verified_by_validation_run_id CHAR(36)     NULL,
    PRIMARY KEY (connection_id, capability),
    CONSTRAINT fk_connection_capabilities_connection FOREIGN KEY (connection_id) REFERENCES storage_connections(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Which access methods are enabled for a connection, and in which
-- execution context. `managed_host_id` is the host actually running the
-- method (e.g. the host mounting a remote SFTP share via SSHFS) --
-- deliberately independent of `storage_connections.managed_host_id`
-- (which is about a host-side-*managed* connection's own server), since
-- e.g. three different managed hosts could each mount the same
-- control-plane-origin SFTP connection.
CREATE TABLE connection_access_methods (
    id               CHAR(36)     NOT NULL PRIMARY KEY,
    connection_id    CHAR(36)     NOT NULL,
    method           VARCHAR(24)  NOT NULL,
    context          VARCHAR(16)  NOT NULL,
    managed_host_id  CHAR(36)     NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_connection_access_methods_connection FOREIGN KEY (connection_id) REFERENCES storage_connections(id) ON DELETE CASCADE,
    CONSTRAINT fk_connection_access_methods_host FOREIGN KEY (managed_host_id) REFERENCES hosts(id) ON DELETE RESTRICT,
    UNIQUE KEY uq_connection_access_methods (connection_id, method, managed_host_id),
    INDEX idx_connection_access_methods_host (managed_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One validation attempt's full check-by-check results (JSON array of
-- `{check, method, status, error_kind, message, duration_ms}`), method-
-- aware per GitHub issue #Sepulchre's Phase 1B: a connection with both a
-- control-plane native client and a host mount validates each
-- independently.
CREATE TABLE validation_runs (
    id              CHAR(36)     NOT NULL PRIMARY KEY,
    connection_id   CHAR(36)     NOT NULL,
    mode            VARCHAR(16)  NOT NULL,
    checks          JSON         NOT NULL,
    overall_status  VARCHAR(16)  NOT NULL,
    started_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    finished_at     DATETIME(6)  NULL,
    triggered_by    CHAR(36)     NULL,
    CONSTRAINT fk_validation_runs_connection FOREIGN KEY (connection_id) REFERENCES storage_connections(id) ON DELETE CASCADE,
    CONSTRAINT fk_validation_runs_triggered_by FOREIGN KEY (triggered_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_validation_runs_connection_started (connection_id, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Which Arsenal/job references a connection, and what it actually needs
-- from it -- lets Sepulchre show "used by Reliquary: nightly DB backup
-- (needs write, list, delete as backup_destination)" and block deleting
-- or disabling a connection still in use without an explicit override.
CREATE TABLE connection_consumers (
    id                     CHAR(36)     NOT NULL PRIMARY KEY,
    connection_id          CHAR(36)     NOT NULL,
    arsenal                VARCHAR(64)  NOT NULL,
    reference_id           VARCHAR(64)  NOT NULL,
    purpose                VARCHAR(255) NOT NULL,
    role                   VARCHAR(24)  NOT NULL,
    required_capabilities  JSON         NOT NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_connection_consumers_connection FOREIGN KEY (connection_id) REFERENCES storage_connections(id) ON DELETE CASCADE,
    UNIQUE KEY uq_connection_consumers (connection_id, arsenal, reference_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Host-side provisioned resources: an SFTP chroot/account or an SMB
-- share Sepulchre has rendered into its own managed drop-in files on a
-- managed host. `rendered_config_hash` is the hash of the last-applied
-- drop-in content, used to detect drift between desired and observed
-- state without re-fetching and re-diffing the whole file on every page
-- load.
CREATE TABLE managed_shares (
    id                    CHAR(36)     NOT NULL PRIMARY KEY,
    host_id               CHAR(36)     NOT NULL,
    protocol              VARCHAR(16)  NOT NULL,
    local_path            VARCHAR(1024) NOT NULL,
    share_name            VARCHAR(255) NULL,
    chroot_user           VARCHAR(64)  NULL,
    access_principals     JSON         NOT NULL,
    rendered_config_hash  CHAR(64)     NULL,
    desired_state         JSON         NOT NULL,
    observed_state        JSON         NULL,
    connection_id         CHAR(36)     NULL,
    created_by            CHAR(36)     NULL,
    created_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_managed_shares_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_managed_shares_connection FOREIGN KEY (connection_id) REFERENCES storage_connections(id) ON DELETE SET NULL,
    CONSTRAINT fk_managed_shares_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_managed_shares_host (host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE mount_definitions (
    id                 CHAR(36)     NOT NULL PRIMARY KEY,
    host_id            CHAR(36)     NOT NULL,
    connection_id      CHAR(36)     NOT NULL,
    mount_point        VARCHAR(1024) NOT NULL,
    options             JSON         NOT NULL,
    persistence_method  VARCHAR(24)  NOT NULL,
    state               VARCHAR(24)  NOT NULL,
    created_by          CHAR(36)     NULL,
    created_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_mount_definitions_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE RESTRICT,
    CONSTRAINT fk_mount_definitions_connection FOREIGN KEY (connection_id) REFERENCES storage_connections(id) ON DELETE RESTRICT,
    CONSTRAINT fk_mount_definitions_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE KEY uq_mount_definitions_host_point (host_id, mount_point(255)),
    INDEX idx_mount_definitions_connection (connection_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
