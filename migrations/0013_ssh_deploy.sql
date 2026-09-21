-- "Quick Add Host From Network Scan" (GitHub issue #5): SSH into scan
-- results directly to deploy the agent, instead of the operator having to
-- SSH in by hand. This is the one piece of that feature with anything to
-- persist -- the trust-on-first-use store for SSH host keys. Deliberately
-- the *only* new table: deploy job status is in-memory only (mirrors
-- `AppState.update_status`, see `crates/web/src/state.rs`) and SSH
-- credentials (passwords, private keys, passphrases, sudo passwords) are
-- never persisted anywhere, ever -- held in memory for the duration of a
-- deploy job only, then dropped. See ARCHITECTURE.md's "Deploying agents
-- over SSH" section for the full design.

CREATE TABLE ssh_trusted_host_keys (
    ip_address     VARCHAR(45)  NOT NULL PRIMARY KEY,
    -- `SHA256:<base64>` -- the same format `ssh-keygen -lf`/OpenSSH's own
    -- client shows, so a fingerprint here is directly comparable to
    -- whatever the admin already sees from another tool.
    fingerprint    VARCHAR(255) NOT NULL,
    first_seen_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
