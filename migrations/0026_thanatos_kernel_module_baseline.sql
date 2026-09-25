-- Thanatos SIEM/EDR build-out, Phase 9: kernel module (Linux) / driver
-- (Windows) baseline tracking -- a rootkit/kernel-level-malware
-- persistence indicator neither platform's detection covered until now.
-- Each scan reports the host's currently loaded modules/running
-- drivers, tagged `module\t<name>` in the same scan output. Same shape
-- and reasoning as `thanatos_network_baseline` (migration 0025): set
-- membership per host, not a value-per-key comparison the way file-
-- integrity hashes are, so a genuinely new module can be told apart
-- from a host's very first scan. Deliberately a second, separately-
-- shaped table rather than generalizing the two into one shared "set
-- baseline" table with a category column -- that generalization would
-- mean an ALTER-and-rename migration touching Phase 7a's already-
-- shipped, live-tested schema for a hypothetical third consumer that
-- doesn't exist yet; worth revisiting if one actually shows up later,
-- not done speculatively now. `repo::thanatos_kernel_module_baseline::
-- record_seen_modules` holds the only copy of "what was already
-- loaded" per host, establishing the baseline silently on a host's
-- first-ever scan and reporting only genuinely new modules after that.
-- A module that's since been unloaded is quietly dropped from
-- tracking, not alerted on -- unloading isn't itself a security
-- concern the way a new module loading is.
CREATE TABLE thanatos_kernel_module_baseline (
    host_id      CHAR(36)     NOT NULL,
    module_key   VARCHAR(64)  NOT NULL,
    observed_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (host_id, module_key),
    CONSTRAINT fk_thanatos_kernel_module_baseline_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
