-- Switch neighbors from LLDP / CDP (read in the same SNMP poll as the
-- forwarding table), replaced on every poll -- what the Topology page
-- shows.
CREATE TABLE panopticon_switch_neighbors (
    id              CHAR(36) NOT NULL PRIMARY KEY,
    switch_id       CHAR(36) NOT NULL,
    protocol        VARCHAR(8) NOT NULL,
    local_port      VARCHAR(255) NOT NULL,
    local_if_index  INT UNSIGNED NULL,
    remote_name     VARCHAR(255) NOT NULL,
    remote_port     VARCHAR(255) NOT NULL,
    remote_address  VARCHAR(45) NULL,
    remote_platform VARCHAR(512) NOT NULL,
    chassis_id      VARCHAR(255) NOT NULL,
    seen_at         DATETIME(6) NOT NULL,
    KEY idx_neighbors_switch (switch_id),
    FOREIGN KEY (switch_id) REFERENCES panopticon_switches(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DHCP leases imported from a lease file or a managed DHCP server: a
-- hostname (and MAC) source for networks without reverse DNS. One row per
-- address, the newest import winning.
CREATE TABLE panopticon_dhcp_leases (
    ip_address   VARCHAR(45) NOT NULL PRIMARY KEY,
    mac_address  VARCHAR(17) NULL,
    hostname     VARCHAR(255) NULL,
    expires_at   DATETIME(6) NULL,
    source       VARCHAR(255) NOT NULL,
    imported_at  DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
