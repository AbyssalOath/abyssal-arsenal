-- GitHub issue #6: let a managed switch be polled over SNMP v1, v2c, or
-- v3 instead of v2c only. `snmp_version` defaults to 'v2c' so every
-- existing row (added before this column existed) keeps polling exactly
-- as it did before, unmodified. `community_encrypted` becomes nullable
-- since a v3 switch has no community string at all; the v3 credential
-- columns are nullable for the opposite reason (a v1/v2c switch has none
-- of them). See `crates/core/src/network_device.rs::PanopticonSwitch` and
-- `crates/web/src/panopticon_snmp.rs`.

ALTER TABLE panopticon_switches
    MODIFY COLUMN community_encrypted TEXT NULL,
    ADD COLUMN snmp_version VARCHAR(8) NOT NULL DEFAULT 'v2c' AFTER snmp_port,
    ADD COLUMN snmp_v3_username VARCHAR(255) NULL AFTER community_encrypted,
    ADD COLUMN snmp_v3_security_level VARCHAR(16) NULL AFTER snmp_v3_username,
    ADD COLUMN snmp_v3_auth_protocol VARCHAR(16) NULL AFTER snmp_v3_security_level,
    ADD COLUMN snmp_v3_auth_password_encrypted TEXT NULL AFTER snmp_v3_auth_protocol,
    ADD COLUMN snmp_v3_priv_protocol VARCHAR(16) NULL AFTER snmp_v3_auth_password_encrypted,
    ADD COLUMN snmp_v3_priv_password_encrypted TEXT NULL AFTER snmp_v3_priv_protocol;
