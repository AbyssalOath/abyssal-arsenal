-- Wires Sepulchre connections up as an actual, selectable Reliquary
-- backup destination (previously only adapter code existed with no
-- caller anywhere -- see docs/sepulchre.md). NULL means "the local
-- destination" (`RELIQUARY_BACKUP_DESTINATION_PATH`), same as today.
-- `ON DELETE SET NULL` rather than `RESTRICT`: deleting a Sepulchre
-- connection should never be blocked by old backup job history, and a
-- job row that outlives its connection still keeps its own
-- `destination_path` label and file metadata either way.

ALTER TABLE reliquary_backups
    ADD COLUMN destination_connection_id CHAR(36) NULL AFTER destination_path,
    ADD CONSTRAINT fk_reliquary_backups_destination_connection
        FOREIGN KEY (destination_connection_id) REFERENCES storage_connections(id) ON DELETE SET NULL,
    ADD INDEX idx_reliquary_backups_destination_connection (destination_connection_id);
