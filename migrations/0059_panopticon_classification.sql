-- 0.2.7 N3 (docs/roadmap/0.2.7.md): automatic device classification.
--
-- DHCP fingerprints the control plane's passive capture saw, one row per
-- client MAC (latest wins): option 55 (parameter request list, as
-- comma-separated codes), option 60 (vendor class) and option 12 (hostname).
CREATE TABLE panopticon_dhcp_fingerprints (
    mac_address   VARCHAR(17)  NOT NULL PRIMARY KEY,
    prl           VARCHAR(255) NULL,
    vendor_class  VARCHAR(255) NULL,
    hostname      VARCHAR(255) NULL,
    first_seen_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Whether device_type was set by the classifier rather than a person. The
-- auto-classify sweep only ever touches devices still 'unknown' or set by
-- itself, so a person's classification is never overwritten.
ALTER TABLE panopticon_devices
    ADD COLUMN device_type_auto BOOLEAN NOT NULL DEFAULT 0 AFTER device_type;
