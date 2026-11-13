-- 0.2.8 P2 (docs/roadmap/0.2.8.md): roles and ACLs, not just VLANs.
--
-- Per NAS client: which attribute carries a role name in an Access-Accept,
-- if any -- 'none' (existing clients keep today's replies), 'filter_id'
-- (RFC 2865 Filter-Id: Cisco named ACLs as "NAME.in", Juniper, HPE and most
-- others), or 'aruba_role' (Aruba-User-Role, vendor 14823 type 1). Defining
-- the ACL or role itself stays on the switch or controller.
ALTER TABLE panopticon_radius_clients
    ADD COLUMN role_attribute VARCHAR(16) NOT NULL DEFAULT 'none' AFTER coa_port;

-- An AD group rule (0.2.8 P1) can choose a role too. Its VLAN may now be 0
-- ("keep the device's VLAN") when it sets a role.
ALTER TABLE panopticon_radius_group_rules
    ADD COLUMN role VARCHAR(64) NULL AFTER vlan;
