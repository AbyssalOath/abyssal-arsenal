-- GitHub issue #10: Device Inventory subnet grouping. `network` is the
-- CIDR string (e.g. "10.0.1.0/24", "2001:db8::/64") a device's
-- `ip_address` masks down to at the configured prefix
-- (`panopticon.subnet_prefix_v4`/`_v6`, `crates/core/src/settings.rs`),
-- computed in Rust (`abyssal_core::network_of`) and stored at write time
-- rather than derived on every read -- a single `GROUP BY network` then
-- answers "how many devices per subnet" without fetching every device
-- row, which is the whole point (see docs/device-inventory.md). NULL
-- means the IP didn't parse at all (extremely unlikely given how rows
-- are written, but never assumed impossible) -- the "Unassigned /
-- Unknown" group. Existing rows are backfilled by
-- `repo::network_devices::backfill_network`, called once at every
-- startup (idempotent -- only touches rows where `network IS NULL`), not
-- inline in this migration, since it needs the same Rust CIDR-masking
-- logic the write path uses rather than duplicating it in SQL.

ALTER TABLE panopticon_devices
    ADD COLUMN network VARCHAR(43) NULL AFTER ip_address,
    ADD INDEX idx_panopticon_devices_network (network);
