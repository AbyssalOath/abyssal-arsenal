-- Abyssal Arsenal core schema.

CREATE TABLE users (
    id                    CHAR(36)      NOT NULL PRIMARY KEY,
    username              VARCHAR(64)   NOT NULL,
    email                 VARCHAR(255)  NOT NULL,
    password_hash         VARCHAR(255)  NULL,
    auth_provider         VARCHAR(32)   NOT NULL DEFAULT 'local',
    is_active             BOOLEAN       NOT NULL DEFAULT TRUE,
    must_change_password  BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at            DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at            DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    last_login_at         DATETIME(6)   NULL,
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE roles (
    id           CHAR(36)     NOT NULL PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    description  VARCHAR(500) NOT NULL DEFAULT '',
    is_system    BOOLEAN      NOT NULL DEFAULT FALSE,
    UNIQUE KEY uq_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE permissions (
    `key`        VARCHAR(64)  NOT NULL PRIMARY KEY,
    description  VARCHAR(255) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE role_permissions (
    role_id          CHAR(36)    NOT NULL,
    permission_key   VARCHAR(64) NOT NULL,
    PRIMARY KEY (role_id, permission_key),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_key) REFERENCES permissions(`key`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_roles (
    user_id  CHAR(36) NOT NULL,
    role_id  CHAR(36) NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sessions (
    id           CHAR(36)    NOT NULL PRIMARY KEY,
    token_hash   CHAR(64)    NOT NULL,
    user_id      CHAR(36)    NOT NULL,
    created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at   DATETIME(6) NOT NULL,
    revoked_at   DATETIME(6) NULL,
    ip_address   VARCHAR(45) NULL,
    user_agent   VARCHAR(255) NULL,
    UNIQUE KEY uq_sessions_token_hash (token_hash),
    KEY idx_sessions_user_id (user_id),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Append-only. No application code ever issues UPDATE/DELETE against this table.
CREATE TABLE audit_log (
    id                 CHAR(36)     NOT NULL PRIMARY KEY,
    occurred_at        DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    user_id            CHAR(36)     NULL,
    username_snapshot  VARCHAR(64)  NOT NULL,
    action             VARCHAR(64)  NOT NULL,
    resource           VARCHAR(255) NULL,
    result             VARCHAR(16)  NOT NULL,
    source_ip          VARCHAR(45)  NULL,
    auth_method        VARCHAR(32)  NULL,
    metadata           JSON         NULL,
    KEY idx_audit_log_occurred_at (occurred_at),
    KEY idx_audit_log_action (action),
    KEY idx_audit_log_user_id (user_id),
    CONSTRAINT fk_audit_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE settings (
    `key`        VARCHAR(128) NOT NULL PRIMARY KEY,
    value        JSON         NOT NULL,
    updated_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    updated_by   CHAR(36)     NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE modules (
    `key`     VARCHAR(64) NOT NULL PRIMARY KEY,
    enabled   BOOLEAN     NOT NULL DEFAULT TRUE,
    config    JSON        NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
