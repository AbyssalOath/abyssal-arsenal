-- Switch port names. The SNMP poll now reads IF-MIB ifAlias (the name an
-- admin gave the port on the switch) and stores it as the port's label in
-- `if_descr`, which every consumer already keys on (device-to-port matching,
-- NAC enforcement, the Ports page). An unnamed port keeps ifDescr ("Slot: 0
-- Port: 3 Gigabit - Level") as its label. The raw ifDescr is kept here so the
-- hardware port stays visible next to a name.
ALTER TABLE panopticon_switch_ports
    ADD COLUMN hw_descr VARCHAR(255) NULL AFTER if_descr;
