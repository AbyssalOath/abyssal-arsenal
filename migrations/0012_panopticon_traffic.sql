-- Panopticon Phase 3: per-switch-port bandwidth history. Raw counter
-- samples come from the same SNMP poll that already walks each switch for
-- BRIDGE-MIB MAC-to-port data (panopticon_snmp.rs) -- one SNMP session
-- per switch per poll handles both, no separate polling cadence.
--
-- Two optional rollup tiers (hourly, daily) let an admin trade storage for
-- how far back a bandwidth graph can look. Either tier is completely
-- inert -- never written, never queried, actively pruned to empty -- while
-- its retention setting is 0. See
-- abyssal_core::settings::PANOPTICON_TRAFFIC_*_RETENTION_DAYS.

-- Every port a poll has ever seen on a switch, independent of whether it
-- currently has a device mapped to it (panopticon_devices.switch_port only
-- knows about ports with a live FDB entry) -- this is what the traffic
-- page lists, so a port stays visible (with its last-known label) even
-- between polls or if the switch is briefly unreachable.
CREATE TABLE panopticon_switch_ports (
    switch_id    CHAR(36) NOT NULL,
    if_index     INT UNSIGNED NOT NULL,
    if_descr     VARCHAR(255) NULL,
    last_seen_at DATETIME(6) NOT NULL,
    PRIMARY KEY (switch_id, if_index),
    FOREIGN KEY (switch_id) REFERENCES panopticon_switches(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Raw cumulative octet counters, one row per port per poll -- not yet a
-- rate. `counter_bits` records whether this sample came from IF-MIB's
-- 64-bit ifHCIn/OutOctets (preferred) or the legacy 32-bit ifIn/OutOctets
-- fallback, since a 32-bit counter needs wrap-handling a 64-bit one
-- never realistically will (see panopticon_traffic.rs::rates_from_raw).
CREATE TABLE panopticon_port_traffic_raw (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    switch_id    CHAR(36) NOT NULL,
    if_index     INT UNSIGNED NOT NULL,
    in_octets    BIGINT UNSIGNED NOT NULL,
    out_octets   BIGINT UNSIGNED NOT NULL,
    counter_bits TINYINT UNSIGNED NOT NULL,
    polled_at    DATETIME(6) NOT NULL,
    KEY idx_traffic_raw_switch_port_time (switch_id, if_index, polled_at),
    FOREIGN KEY (switch_id) REFERENCES panopticon_switches(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Hourly rollup: one row per port per completed hour, computed directly
-- from that hour's raw samples (not from raw via daily, and not from
-- hourly via daily either -- see panopticon_traffic.rs for why both
-- rollup tiers are independent of each other, not chained).
CREATE TABLE panopticon_port_traffic_hourly (
    switch_id    CHAR(36) NOT NULL,
    if_index     INT UNSIGNED NOT NULL,
    bucket_start DATETIME NOT NULL,
    avg_in_bps   DOUBLE NOT NULL,
    avg_out_bps  DOUBLE NOT NULL,
    max_in_bps   DOUBLE NOT NULL,
    max_out_bps  DOUBLE NOT NULL,
    sample_count INT UNSIGNED NOT NULL,
    PRIMARY KEY (switch_id, if_index, bucket_start),
    FOREIGN KEY (switch_id) REFERENCES panopticon_switches(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Daily rollup: one row per port per completed day, computed directly
-- from that day's raw samples.
CREATE TABLE panopticon_port_traffic_daily (
    switch_id    CHAR(36) NOT NULL,
    if_index     INT UNSIGNED NOT NULL,
    day          DATE NOT NULL,
    avg_in_bps   DOUBLE NOT NULL,
    avg_out_bps  DOUBLE NOT NULL,
    max_in_bps   DOUBLE NOT NULL,
    max_out_bps  DOUBLE NOT NULL,
    sample_count INT UNSIGNED NOT NULL,
    PRIMARY KEY (switch_id, if_index, day),
    FOREIGN KEY (switch_id) REFERENCES panopticon_switches(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
