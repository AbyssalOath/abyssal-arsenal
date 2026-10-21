-- Gravekeeper (docs/roadmap/ad-management.md), Phase 2: onboarding/offboarding
-- jobs, step by step, so a run can be reviewed and (from P2-M4) its failed
-- steps retried. An onboarding job is created with its AD step; the mail steps
-- (P2-M3) append to the same job, which is why steps are their own rows.
CREATE TABLE directory_jobs (
    id          CHAR(36)     NOT NULL PRIMARY KEY,
    domain_id   CHAR(36)     NOT NULL,
    -- onboard | offboard | bulk (onboard in Phase 2).
    kind        VARCHAR(16)  NOT NULL,
    title       VARCHAR(255) NOT NULL,
    -- The created/affected account's sAMAccountName, once known.
    target_sam  VARCHAR(64)  NULL,
    -- running | completed | failed | partial.
    status      VARCHAR(16)  NOT NULL DEFAULT 'running',
    created_by  CHAR(36)     NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_directory_jobs_domain FOREIGN KEY (domain_id)
        REFERENCES directory_domains(id) ON DELETE CASCADE
);

CREATE TABLE directory_job_steps (
    id         CHAR(36)     NOT NULL PRIMARY KEY,
    job_id     CHAR(36)     NOT NULL,
    seq        INT          NOT NULL,
    name       VARCHAR(100) NOT NULL,
    -- pending | ok | failed | skipped.
    status     VARCHAR(16)  NOT NULL DEFAULT 'pending',
    detail     TEXT         NULL,
    updated_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_directory_job_steps_job FOREIGN KEY (job_id)
        REFERENCES directory_jobs(id) ON DELETE CASCADE,
    INDEX directory_job_steps_job (job_id, seq)
);
