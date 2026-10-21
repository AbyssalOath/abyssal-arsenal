-- Gravekeeper (docs/roadmap/ad-management.md), Phase 2 P2-M4: enough context on
-- an onboarding job to retry a failed step (the mail step) without re-creating
-- the AD account. `target_upn` is the created user's UPN (the mailbox identity);
-- `template_id` is the template whose mail settings the retry re-reads. The
-- template may be deleted later, so the reference is nulled rather than blocking.
ALTER TABLE directory_jobs
    ADD COLUMN target_upn  VARCHAR(255) NULL AFTER target_sam,
    ADD COLUMN template_id CHAR(36)     NULL AFTER target_upn,
    ADD CONSTRAINT fk_directory_jobs_template FOREIGN KEY (template_id)
        REFERENCES directory_templates(id) ON DELETE SET NULL;
