-- Panopticon 0.2.9 Q5 (docs/roadmap/0.2.9.md): SNMP traps. The last trap
-- each switch sent that Panopticon accepted (its source and community
-- checked), for the switches page.
ALTER TABLE panopticon_switches
    ADD COLUMN last_trap_at DATETIME(6)  NULL,
    ADD COLUMN last_trap    VARCHAR(255) NULL;
