-- Gravekeeper (docs/roadmap/ad-management.md), Phase 4 P4-M1: a bulk (CSV)
-- onboarding job stores its rows so failed rows can be retried later
-- ("resumable"). `payload_json` holds the parsed rows ([{first,last}, ...]); the
-- job's existing `template_id` says which template to apply. Each row is a step
-- (seq = row index + 1); retry re-runs the rows whose step failed.
ALTER TABLE directory_jobs
    ADD COLUMN payload_json MEDIUMTEXT NULL AFTER template_id;
