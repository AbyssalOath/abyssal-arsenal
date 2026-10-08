-- Panopticon NAC M2: per-port operational/admin state visibility.
--
-- The SNMP poll already walks IF-MIB's ifDescr and octet counters for every
-- port (panopticon_snmp.rs). This adds the port's administrative state
-- (ifAdminStatus -- what a human configured the port to) and its live
-- operational state (ifOperStatus -- whether a link is actually up right
-- now), plus negotiated link speed, onto the existing per-port row so the
-- switches UI can show which ports are up, down, or administratively shut.
--
-- All read-only: nothing here writes SNMP SET. Knowing a port's current
-- admin state is also the baseline a later enforcement phase needs before
-- it could safely toggle a port, which is why this lands as its own phase
-- first.
--
-- Codes are IF-MIB's own integers, stored raw (nullable) rather than as an
-- app-side ENUM, so a switch returning an unexpected value is preserved
-- instead of rejected -- abyssal_core::IfAdminStatus / IfOperStatus map the
-- standard ones to labels and leave anything else as "unknown".
ALTER TABLE panopticon_switch_ports
    ADD COLUMN admin_status   TINYINT UNSIGNED NULL AFTER if_descr,
    ADD COLUMN oper_status    TINYINT UNSIGNED NULL AFTER admin_status,
    ADD COLUMN speed_mbps     INT UNSIGNED NULL AFTER oper_status,
    ADD COLUMN status_seen_at DATETIME(6) NULL AFTER speed_mbps;
