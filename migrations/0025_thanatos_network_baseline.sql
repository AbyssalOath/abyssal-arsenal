-- Thanatos SIEM/EDR build-out, Phase 7a: lightweight network-baseline
-- tracking. Each scan (`AgentOperation::ScanSecurityEvents`) now also
-- reports the host's current TCP/UDP listening ports, tagged
-- `port\t<proto>:<port>` in the same scan output. Unlike file-integrity
-- hashes (one value per fixed path, compared value-to-value), this
-- tracks *set membership* -- which ports are listening right now -- so
-- a newly-appearing port can be told apart from a host's very first
-- scan (which would otherwise report every one of its existing ports as
-- "new"). `repo::thanatos_network_baseline::record_seen_ports` holds the
-- only copy of "what were we already tracking" per host, establishing
-- the baseline silently on a host's first-ever scan and reporting only
-- genuinely new ports on every scan after that. A port_key that stops
-- being listened on is quietly dropped from tracking, not alerted on --
-- a port closing isn't itself a security concern the way a new one
-- opening is.
CREATE TABLE thanatos_network_baseline (
    host_id      CHAR(36)     NOT NULL,
    port_key     VARCHAR(32)  NOT NULL,
    observed_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (host_id, port_key),
    CONSTRAINT fk_thanatos_network_baseline_host FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
