-- MITRE ATT&CK technique annotation for Thanatos findings (M1). Each
-- classified event, where the control plane can map its label to a technique,
-- records the technique ID (e.g. "T1003.001" for LSASS memory access) so
-- findings can be grouped, filtered and reported by ATT&CK technique/tactic.
-- Empty string = no technique mapped (the default for generic/reliability
-- findings and for any label the control-plane map doesn't cover). Stored as a
-- short string rather than a lookup table: a technique ID is a stable, opaque
-- identifier, and keeping it inline keeps the single-table query shape every
-- existing Thanatos view already uses.
ALTER TABLE thanatos_events
    ADD COLUMN technique VARCHAR(16) NOT NULL DEFAULT '' AFTER label;

-- Lets the investigation/reporting views filter by technique without a scan.
CREATE INDEX idx_thanatos_events_technique ON thanatos_events (technique);
