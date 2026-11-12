-- 0.2.7 N1 (docs/roadmap/0.2.7.md): security signals drive NAC enforcement.
--
-- panopticon_devices.host_id links an inventory device to the managed host
-- whose agent reported the device's address as one of its own interfaces,
-- so a Thanatos event or Cadavault posture run (keyed by host) can find the
-- device's switch port, and the control plane's own server can be kept out
-- of auto-enforcement. Cleared when the device's MAC changes.
ALTER TABLE panopticon_devices
    ADD COLUMN host_id CHAR(36) NULL AFTER trust_state,
    ADD CONSTRAINT fk_panopticon_devices_host FOREIGN KEY (host_id)
        REFERENCES hosts(id) ON DELETE SET NULL;

-- Per-rule thresholds for the signal triggers: min_severity for ids_alert /
-- security_event (low | medium | high | critical), posture_below for
-- posture_failing (fires when the host's latest score is below it). NULL
-- means the trigger's default.
ALTER TABLE panopticon_policy_rules
    ADD COLUMN min_severity VARCHAR(16) NULL AFTER action,
    ADD COLUMN posture_below TINYINT UNSIGNED NULL AFTER min_severity;
