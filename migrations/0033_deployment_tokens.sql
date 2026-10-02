-- Reusable "deployment tokens" for mass agent rollout (PDQ Deploy, GPO, Intune,
-- …), the Wazuh "registration key" equivalent. The existing single-use,
-- short-lived enrollment tokens stay exactly as they are (reusable = 0); a
-- deployment token (reusable = 1) can enroll many hosts, each auto-registering
-- under its own hostname, until it expires or is revoked.
ALTER TABLE host_enrollment_tokens
    ADD COLUMN reusable   TINYINT(1)   NOT NULL DEFAULT 0,
    ADD COLUMN use_count  INT          NOT NULL DEFAULT 0,
    ADD COLUMN revoked_at DATETIME(6)  NULL,
    ADD COLUMN label      VARCHAR(100) NULL;
