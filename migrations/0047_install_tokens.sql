-- Additional install tokens (docs/roadmap/0.2.4.md, section 2): AAT-format
-- tokens with a label, an optional expiry, a use count, their own approval
-- setting and their own revoke. The default token (the AAT) stays in
-- `settings`. The secret is stored encrypted with ENCRYPTION_KEY (it keys the
-- CA proof, so a hash alone isn't enough); `token_hash` finds it at
-- enrollment, and `key_id` (a non-secret digest the agent sends with its CA
-- request) finds it for the CA proof.
CREATE TABLE install_tokens (
    id               CHAR(36)     NOT NULL PRIMARY KEY,
    label            VARCHAR(100) NOT NULL,
    token_sealed     TEXT         NOT NULL,
    token_hash       CHAR(64)     NOT NULL,
    key_id           CHAR(16)     NOT NULL,
    require_approval TINYINT(1)   NOT NULL DEFAULT 0,
    created_by       CHAR(36)     NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at       DATETIME(6)  NULL,
    revoked_at       DATETIME(6)  NULL,
    use_count        INT          NOT NULL DEFAULT 0,
    last_used_at     DATETIME(6)  NULL,
    UNIQUE KEY install_tokens_hash (token_hash),
    UNIQUE KEY install_tokens_key_id (key_id)
);

-- Which token enrolled each host: 'default_token', 'install_token',
-- 'deployment_token' (legacy), 'enrollment_token' (single-use) or
-- 'control_plane' (install.sh). NULL for hosts enrolled before this.
ALTER TABLE hosts
    ADD COLUMN enrolled_via          VARCHAR(32) NULL AFTER enrolled_at,
    ADD COLUMN enrolled_via_token_id CHAR(36)    NULL AFTER enrolled_via;
