-- Single-use, short-lived tokens for local-account self-service "forgot
-- password" reset, emailed to the account's address. Only a SHA-256 hash
-- of the raw token is stored (crate abyssal_core::secret::hash_token),
-- mirroring sessions.token_hash and host_enrollment_tokens.token_hash --
-- the raw value only ever exists in the emailed link, never in the
-- database or logs.
CREATE TABLE password_resets (
    id          CHAR(36)    NOT NULL PRIMARY KEY,
    user_id     CHAR(36)    NOT NULL,
    token_hash  CHAR(64)    NOT NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at  DATETIME(6) NOT NULL,
    used_at     DATETIME(6) NULL,
    UNIQUE KEY uq_password_resets_token_hash (token_hash),
    KEY idx_password_resets_user_id (user_id),
    CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
