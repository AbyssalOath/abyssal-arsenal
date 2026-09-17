-- Registered managed Linux hosts and their one-time enrollment tokens.

CREATE TABLE hosts (
    id               CHAR(36)     NOT NULL PRIMARY KEY,
    name             VARCHAR(100) NOT NULL,
    credential_hash  CHAR(64)     NOT NULL,
    enrolled_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at     DATETIME(6)  NULL,
    revoked_at       DATETIME(6)  NULL,
    UNIQUE KEY uq_hosts_name (name),
    UNIQUE KEY uq_hosts_credential_hash (credential_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE host_enrollment_tokens (
    id           CHAR(36)    NOT NULL PRIMARY KEY,
    token_hash   CHAR(64)    NOT NULL,
    created_by   CHAR(36)    NULL,
    created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at   DATETIME(6) NOT NULL,
    used_at      DATETIME(6) NULL,
    UNIQUE KEY uq_host_enrollment_tokens_hash (token_hash),
    CONSTRAINT fk_host_enrollment_tokens_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
