-- GitHub issue #7 follow-up: macros gain a second payload type, a saved
-- SNMP community string (Panopticon's "add managed switch" form) alongside
-- the existing Grimoire scheduled-task template. `macro_type` picks which
-- of the two field groups below is populated; the cron-job columns become
-- nullable (a community-string macro has none of them) and the new
-- `secret_value_encrypted` is nullable for the opposite reason. Every
-- existing row predates this column and is a cron-job macro, so
-- `macro_type` defaults to 'cron_job' -- no existing macro changes
-- meaning. `secret_value_encrypted` is AES-256-GCM ciphertext
-- (`abyssal_core::crypto::EncryptionKey`), the same key already used for
-- Panopticon switches' own SNMP credentials -- never plaintext at rest.

ALTER TABLE macros
    ADD COLUMN macro_type VARCHAR(20) NOT NULL DEFAULT 'cron_job' AFTER scope,
    MODIFY COLUMN job_name VARCHAR(128) NULL,
    MODIFY COLUMN schedule VARCHAR(128) NULL,
    MODIFY COLUMN run_as_user VARCHAR(64) NULL,
    MODIFY COLUMN command TEXT NULL,
    ADD COLUMN secret_value_encrypted TEXT NULL AFTER command;
