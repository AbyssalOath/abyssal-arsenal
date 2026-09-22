-- GitHub issue #7: saved, reusable "macros" -- v1 supports exactly one
-- payload shape, a Grimoire scheduled-task (cron job) template
-- (job_name/schedule/run_as_user/command), reused across hosts instead of
-- retyped every time. `scope` is 'personal' (visible only to
-- `owner_user_id`) or 'role' (visible to every member of `role_id`,
-- required exactly when `scope = 'role'`). See
-- `crates/core/src/macros.rs::Macro`.

CREATE TABLE macros (
    id              CHAR(36)     NOT NULL PRIMARY KEY,
    name            VARCHAR(128) NOT NULL,
    owner_user_id   CHAR(36)     NOT NULL,
    scope           VARCHAR(16)  NOT NULL,
    role_id         CHAR(36)     NULL,
    job_name        VARCHAR(128) NOT NULL,
    schedule        VARCHAR(128) NOT NULL,
    run_as_user     VARCHAR(64)  NOT NULL,
    command         TEXT         NOT NULL,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_macros_owner FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_macros_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    INDEX idx_macros_owner (owner_user_id),
    INDEX idx_macros_role (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
