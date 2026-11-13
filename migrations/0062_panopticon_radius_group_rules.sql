-- 0.2.8 P1 (docs/roadmap/0.2.8.md): VLAN by Active Directory group.
--
-- An ordered list of AD group -> VLAN rules for 802.1X logins that passed
-- PEAP against AD (deploy/freeradius). The first rule (lowest position)
-- whose group the login is in chooses the VLAN, but only where the device
-- would be admitted anyway: port/device enforcement and an Untrusted device
-- still win (crates/web/src/panopticon_radius.rs, decide()).
--
-- group_name is "DOMAIN\Group" or a plain "Group" (any domain), matched
-- case-insensitively. It never contains ';', which separates group names
-- on their way through FreeRADIUS (Abyssal-AD-Groups).
CREATE TABLE panopticon_radius_group_rules (
    id          CHAR(36) NOT NULL PRIMARY KEY,
    group_name  VARCHAR(256) NOT NULL,
    vlan        SMALLINT UNSIGNED NOT NULL,
    position    INT NOT NULL DEFAULT 100,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_panopticon_radius_group_rules_position (position, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
