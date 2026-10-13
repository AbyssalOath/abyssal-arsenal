-- Cadavault posture runs (docs/roadmap/0.2.4.md, section 1): one row per
-- run of the check catalog on a host, and one row per check's result. Kept
-- for history, the "changed since the last run" line and the fleet view.
-- The checks' text lives in the abyssal-posture crate, by check ID.
CREATE TABLE posture_runs (
    id          CHAR(36)     NOT NULL PRIMARY KEY,
    host_id     CHAR(36)     NOT NULL,
    platform    VARCHAR(16)  NOT NULL,
    -- Who ran it, or "schedule".
    started_by  VARCHAR(255) NOT NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    passed      INT          NOT NULL,
    failed      INT          NOT NULL,
    not_applicable INT       NOT NULL,
    score       TINYINT UNSIGNED NULL,
    KEY posture_runs_host_time (host_id, created_at)
);

CREATE TABLE posture_results (
    run_id    CHAR(36)    NOT NULL,
    check_id  VARCHAR(32) NOT NULL,
    -- passed, failed or na
    status    VARCHAR(8)  NOT NULL,
    evidence  TEXT        NOT NULL,
    PRIMARY KEY (run_id, check_id),
    KEY posture_results_check (check_id, status)
);
