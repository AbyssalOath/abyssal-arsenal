# Reliquary native backups

GitHub issue #9. This is the control plane's own backup/restore/disaster-recovery
system for its **local (Docker Compose) install**: MariaDB dump, this process's
own redacted config, and (opt-in) the `ENCRYPTION_KEY` used for Panopticon/macro
secrets, sealed into one compressed, checksummed, optionally-encrypted archive.

It is unrelated to Reliquary's other, older feature: agent-driven backups of
*managed hosts* (`/arsenals/reliquary/<host_id>`). This document only covers
the native, control-plane-local feature at `/arsenals/reliquary/backups`.

## What is backed up

Selectable per backup (all default on except encryption keys):

- **Database** -- a full logical dump of the app's own MariaDB database via
  `mariadb-dump --single-transaction --routines --triggers --events --hex-blob
  --default-character-set=utf8mb4 --quick --databases <db>`. Because the dump
  uses `--databases`, it embeds its own `CREATE DATABASE`/`USE` statements --
  restoring it recreates the database by name with no extra logic.
- **Configuration** -- a redacted snapshot of *this process's own environment
  variables* (anything with `PASSWORD`, `SECRET`, `KEY`, or `TOKEN` in the name
  is redacted). This is **not** `docker-compose.yml`, `.env`, or `Caddyfile` --
  see "What is NOT backed up" below for why.
- **Encryption keys** -- the `ENCRYPTION_KEY` environment variable, if set.
  Selecting this always forces the whole archive to be encrypted (a backup
  containing the key used to encrypt itself, sitting next to itself in
  plaintext, would defeat the point).
- **Audit logs** -- whether the `audit_log` table's rows are included in the
  database dump. This is *not* a separate file; unchecking it makes the
  database dump itself exclude that one table (`mariadb-dump
  --ignore-table=<db>.audit_log`) for a deployment that wants its backups to
  exclude potentially sensitive audit detail by default. A dedicated setting
  (`reliquary.backup_include_audit_logs`, default on) controls what scheduled/
  unattended backups do, and what the create-backup form defaults to.

Every archive also carries a `manifest.json`: backup ID, timestamps, the
Arsenal and database-schema-migration versions at backup time, MariaDB
version/charset/collation/sql_mode, which components were included, a SHA-256
per top-level file plus one for the whole archive, encryption metadata (KDF
and salt -- **never the key or passphrase**), and this container's own image
reference (`abyssal-arsenal:<version>` -- there's no Docker socket access, so
that's the most this process can honestly report about its own image).

## What is NOT backed up

- **`docker-compose.yml`, `.env`, `Caddyfile`.** These live only on the Docker
  host's filesystem -- the app container has no mount giving it visibility
  into them. "Configuration" above is the closest available substitute (this
  process's own resolved environment); keep the actual compose/env files in
  version control or back them up separately (e.g. as part of a host-level
  backup of `/srv/docker/abyssal-arsenal` or wherever this repo lives).
- **Container images and build artifacts.** Only image *references* are
  recorded in the manifest, never image data -- rebuild from source (this
  repo, pinned to the tag in the manifest) instead.
- **Managed hosts.** Reliquary's separate agent-backed feature
  (`/arsenals/reliquary/<host_id>`) is untouched by this feature. "Managed
  Systems" appears as a placeholder card on the backups page for future work,
  not something this pass implements.
- **Physical/hot backups, binlog point-in-time recovery.** This is a logical
  (`mariadb-dump`) backup taken at a point in time, not continuous replication
  or WAL/binlog shipping. Data written after the last successful backup is
  lost in a disaster, same as any dump-based scheme.

## Off-host storage (important)

Backups are written into a dedicated Docker volume (`abyssal_backups`, mounted
at `/backups`), deliberately **separate from the database's own volume**
(`abyssal_db_data`) -- a restore gone wrong, or a lost/corrupted DB volume,
can't also take out the backups that would fix it. Files are written `0600`
and the destination is never served over HTTP.

That volume is still local to this Docker host. **A host-level failure (disk
failure, host lost, ransomware) takes the backups with it unless you copy them
somewhere else.** For a genuinely off-host destination without copying files
around by hand, see "Sepulchre-backed destinations" just below; otherwise,
periodically copy `/backups` (or the Docker volume it maps to) off-host
yourself, the same way `scripts/backup-db.sh`'s output already should be.

## Sepulchre-backed destinations

A backup can be written directly to an SFTP server, an SMB share, or an
allowlisted local path managed by the [Sepulchre arsenal](sepulchre.md),
instead of (or alongside, across different jobs) the local destination
above -- genuinely off-host, with no manual copy step, once a connection is
set up.

**Setup**: create a Sepulchre connection (`/arsenals/sepulchre`) with the
`Backup destination` role, then validate it (read/write) so every
capability shows verified -- only a connection that's enabled, holds that
role, and has all four capabilities (read/list/write/delete) verified
recently is actually usable here.

**Manual backups**: the "Backup now" form on this page gets a Destination
picker listing every eligible connection alongside "Local." Pick one per
run.

**Scheduled backups**: the Control-Plane Configuration section's own
"Scheduled backup destination" picker sets the schedule's fixed answer
(there's nobody present on an unattended run to choose each time).

**What works today**: writing a backup -- the archive streams straight to
the connection, never touching this container's local disk first.

**What doesn't work today, on purpose**: downloading, verifying, or
restoring a backup that was written to a Sepulchre connection. Those three
operations need a real local file to hash/extract/stream from
(`storage.resolve(file_name)`), which only the local destination can give
them -- a Sepulchre connection's `resolve()` returns a synthetic,
display-only string, not a real path. Attempting any of the three against
a Sepulchre-backed job is refused with a clear message rather than failing
confusingly partway through. Retention pruning, by contrast, *does* work
for Sepulchre-backed jobs (it only ever calls `delete`, which every
destination implements for real).

If you need to actually restore from a Sepulchre-backed backup today,
retrieve the archive file yourself through whatever tool the connection's
protocol supports (an SFTP client, `smbclient`, etc.), then hand it to the
disaster-recovery CLI (`docker compose run --rm app reliquary backup
restore <path-to-the-file>`) the same way you would for any other archive
file -- the CLI operates on a raw file path, not a database-tracked job,
so it works regardless of where that file came from.

## Database grants

By default, database dumps use the app's own `MARIADB_USER`/`MARIADB_PASSWORD`
credentials, with a startup warning logged. For a real deployment, create a
dedicated, least-privilege user instead:
[`scripts/reliquary-backup-grants.sql`](../scripts/reliquary-backup-grants.sql)
(`SELECT, SHOW VIEW, TRIGGER, EVENT, LOCK TABLES` -- exactly what
`mariadb-dump`'s flags above need, nothing else). Set
`RELIQUARY_BACKUP_DB_USER`/`RELIQUARY_BACKUP_DB_PASSWORD` in `.env` and
restart the app to use it. Credentials are passed to `mariadb-dump`/`mariadb`
via a `0600` `--defaults-extra-file`, never as a `-p` flag or in an
environment variable a co-tenant process could read from `/proc`.

## Scheduling and retention

Configured from the "Control-Plane Configuration" section of
`/arsenals/reliquary/backups` (`backups.create` permission required):

- **Schedule**: off by default. When on, runs at most one backup per
  configured interval (default 24h), tracked by the most recent successful
  backup's own timestamp (not an in-process timer), so a restart doesn't
  cause an extra backup or lose track of timing. Scheduled backups are
  **always unencrypted** -- there's nobody present on an unattended run to
  supply a passphrase, and storing one for unattended use is a real feature
  this pass doesn't build (see "Deferred" below). They back up Database +
  Configuration (+ Audit logs, per the setting above).
- **Retention**: keep at least the N most recent backups (default 7)
  regardless of age, and additionally prune anything older than a
  configurable number of days (default 30, `0` disables age-based pruning).
  **The only remaining backup whose quick-verify status is passing is never
  pruned**, even if every retention rule above says it should be -- every
  prune, and every time this protection kicks in, is logged.

## Encryption and passphrases

Encryption is AES-256-GCM in streaming mode (the `aes-gcm` crate's STREAM
construction, `EncryptorBE32`/`DecryptorBE32`), processed in 512KB chunks so
memory use stays bounded regardless of archive size. The key is derived from
an operator-supplied passphrase via Argon2id (`m=19456,t=2,p=1` -- the same
parameters this app's own user-password hashing uses). The passphrase itself
is **never stored anywhere** -- not in the database, not in the manifest, not
on disk. Losing it means losing the ability to restore that specific archive;
there is no recovery path. Store it somewhere safe and separate from the
backup itself (a password manager, not the same disk).

In memory, the passphrase is held in `zeroize::Zeroizing`, this codebase's
standing convention for secrets, for as short a scope as possible.

## Restore

From the "Verification & Recovery" section, Restore leads to a **dry-run
preview** (nothing changes yet) showing: whether the backup is verified,
whether it was taken from a different major MariaDB version, and whether its
manifest schema version matches what this deployment understands (a mismatch
hard-blocks the restore). Confirming requires typing `RESTORE` into a text
field -- no single click can trigger it.

On confirm:

1. **Refuses unless the backup is verified**, unless you explicitly check an
   "I understand this hasn't been verified" override.
2. **Takes an automatic, unencrypted safety backup of the current database
   first** (best-effort -- a failure here doesn't block the restore, since the
   whole point of restoring is that the current state is what you're trying
   to replace). **Important**: because a successful restore overwrites the
   *entire* database -- including the `reliquary_backups` tracking table
   itself -- with the restored archive's own older data, this safety
   backup's database row does not survive a successful restore; only its
   file (in the `/backups` volume) does. If you need to undo a restore
   after the fact, find that file by timestamp (it's the newest one) and
   feed it to the disaster-recovery CLI's `verify`/`restore` subcommands
   directly -- they operate on the file, not a database row, and work
   regardless of what the currently-live database's tracking table says.
3. **Enters maintenance mode**: a middleware
   (`crates/web/src/middleware/maintenance_mode.rs`) blocks every request
   except static assets and the backups page itself with a 503 page, for the
   restore's duration. Cleared automatically (even on panic/early-return) via
   an RAII guard, and pauses nothing else explicitly -- the scheduler simply
   can't acquire the backup/restore lock while a restore holds it (see
   "Concurrency" below).
4. Decrypts (if encrypted), extracts, and -- if Database was selected --
   streams the dump back into MariaDB via the `mariadb` client, mirroring
   `mariadb-dump`'s own credential handling.
5. Configuration and Encryption-keys components, if present in the archive
   and selected, are only **extracted to disk** during restore, never
   automatically re-applied -- re-injecting arbitrary "configuration" into a
   live, already-configured process is out of scope and would be its own can
   of worms; an operator reviews and re-applies what's relevant by hand.

## Verification

- **Quick verify** (implemented): confirms the archive file exists, recomputes
  and compares its SHA-256 (constant-time comparison), checks the manifest is
  present/well-formed/non-empty, and for unencrypted archives also confirms
  `manifest.json` is readable straight out of the tar/zstd stream. Fast,
  requires no passphrase, safe to run anytime.
- **Deep verify (NOT implemented in this pass)**: the issue asks for restoring
  into an isolated scratch database, running `CHECK TABLE`, and comparing row
  counts against the source, always dropping the scratch database and never
  touching the live one. The blocker: `mariadb-dump --databases <db>` embeds
  its own `CREATE DATABASE <db>`/`USE <db>` statements (see "What is backed
  up" above) -- exactly what makes a *real* restore simple also makes
  restoring into a *differently-named* scratch database (`arsenal_verify_*`)
  unsafe to do naively, since the dump would try to create/use the original
  database name regardless of where you point the client. Correctly
  redirecting it needs either rewriting the dump's embedded statements before
  replay or a different dump strategy (e.g. `--no-create-db` plus manually
  creating the scratch database first and connecting the restore client to it
  instead of letting the dump's own `USE` statement win) -- both solvable, but
  not attempted here rather than risk a subtly wrong implementation touching
  a real database. `deep_verify` (`crates/web/src/reliquary_backup/verify.rs`)
  returns a clear "not implemented" error rather than silently no-op'ing or
  reporting a false pass.

## Disaster-recovery CLI

Works against a **completely fresh install** -- empty database, brand-new
containers, no web UI, no session, and doesn't require the `reliquary_backups`
table to exist yet (it operates on an archive *file* you point it at directly,
not a database-tracked job):

```sh
# List every backup this control plane's database currently knows about
# (only meaningful against an install that already has the table/rows).
docker compose run --rm app reliquary backup list

# Confirm an archive is readable and its manifest is well-formed. Add
# --passphrase-file for an encrypted archive.
docker compose run --rm app reliquary backup verify /backups/backup-<id>.tar.zst

# Restore an archive into whatever DATABASE_URL currently points at.
docker compose run --rm app reliquary backup restore /backups/backup-<id>.tar.zst \
  --passphrase-file /path/to/passphrase.txt
```

`--passphrase-file` (never a bare `--passphrase` flag) so the passphrase never
appears in `ps` output or shell history.

### Full walkthrough onto a fresh install

1. Copy the backup archive you want to restore onto the new host, e.g. into
   the project directory as `./restore-me.tar.zst`.
2. `docker compose up -d mariadb` and wait for it to report healthy
   (`docker compose ps`) -- this creates a fresh, empty database.
3. `docker compose run --rm -v "$(pwd)/restore-me.tar.zst:/restore.tar.zst:ro" app reliquary backup restore /restore.tar.zst`
   (add `--passphrase-file` if the archive is encrypted; mount the passphrase
   file in too, e.g. `-v "$(pwd)/passphrase.txt:/passphrase.txt:ro"` and pass
   `--passphrase-file /passphrase.txt`).
4. On success, `docker compose up -d` to bring up the full stack against the
   now-restored database.

No web UI, authentication, or existing `reliquary_backups` row is required for
any of this -- it's the intended path when the entire control plane, not just
its database, needs to be rebuilt from scratch.

## Concurrency and crash recovery

A MariaDB session-scoped named lock (`GET_LOCK('reliquary_backup', 0)`,
non-blocking) held on one dedicated connection prevents two backups, or a
backup and a restore, from running at once -- a second attempt while one is in
progress fails cleanly rather than corrupting either. The lock is
automatically released if the process holding it crashes (session-scoped), so
a crash never leaves the *lock* stuck -- but the job row would otherwise still
say `Running` forever. At startup, every `Queued`/`Running`/`Verifying` job is
swept to `Failed` with a clear "interrupted by a crash or restart" message,
since there's no well-defined way to resume a partially-written dump/archive.

## Permissions and audit logging

Reuses the pre-existing `Permission::BackupsView` / `BackupsCreate` /
`BackupsRestore`. Every create, verify, delete, download, settings change, and
restore is recorded via the existing audit log
(`BackupCreated`/`BackupVerified`/`BackupDeleted`/`BackupDownloaded`/
`BackupSettingsChanged`/`BackupRestored`).

## Deferred / not implemented in this pass

Flagged deliberately, not silent scope cuts:

- **Deep verify** -- see above.
- **Reading a backup back from a Sepulchre-backed destination** --
  download, verify, and restore all still require the local destination;
  see "Sepulchre-backed destinations" above for exactly what's missing
  and the manual workaround.
- **S3/cloud-object-storage destinations specifically** -- `StorageDestination`
  and `BackupProvider` remain traits precisely so this (or any other
  destination kind) can be added later without refactoring the engine;
  `LocalFs` and a Sepulchre-backed destination are the two implementations
  that exist today.
- **Encrypted, unattended scheduled backups** -- would need a way to store a
  passphrase (or a KMS-style key) for the scheduler to use without an
  operator present; scheduled backups are unencrypted today by design (see
  "Scheduling and retention" above).
- **Automatic re-application of the Configuration/Encryption-keys components
  on restore** -- extracted to disk only; see "Restore" above.
- **A `testcontainers`-based integration test suite.** This codebase has no
  precedent for spinning up a real database inside `cargo test` anywhere
  (confirmed by inspection of the whole workspace) -- every other DB-touching
  feature this session relied on unit tests over pure-function extractions
  plus manual verification against a real, running MariaDB instead, and this
  feature follows the same pattern rather than introducing a new one. See
  "Manual test steps" below for what that manual verification looked like.

## Manual test steps

1. `docker compose build` (picks up the Dockerfile's new `mariadb-client`
   package and the `ENTRYPOINT` change).
2. `docker compose up -d` -- fresh containers, empty database.
3. Log in, create a user with `backups.view`/`backups.create`/`backups.restore`
   if the admin account doesn't already have them (Super Admin does by
   default).
4. Add some data worth backing up (a user, a role, a macro, whatever's
   convenient to recognize later).
5. `/arsenals/reliquary/backups` -> select Database + Configuration, leave
   encryption off -> "Backup now". Confirm the job appears with status
   Succeeded and a non-zero size.
6. Click Verify on it -- confirm it reports passed.
7. Repeat with encryption on and a passphrase -- confirm it also succeeds and
   verifies.
8. Click Download on one -- confirm a `.tar.zst` (or `.tar.zst.enc`) file
   downloads and `tar --zstd -tf` (after decrypting the encrypted one, if
   needed) lists `manifest.json` and `db.sql`/`config.json` as expected.
9. Change the recognizable data from step 4 (edit or delete it).
10. Restore -> preview page -> confirm the warnings/table look right -> type
    `RESTORE` -> submit. Confirm: the app is unreachable (except the backups
    page) for the few seconds the restore takes, then the recognizable data
    from step 4 is back exactly as it was, and a new automatic pre-restore
    safety backup shows up in the list.
11. **Full disaster-recovery test onto a fresh environment**: on a *separate*
    fresh checkout (or after `docker compose down -v` to wipe every volume,
    including backups -- so copy the archive out first with `docker cp` or
    the Download button), follow the "Full walkthrough onto a fresh install"
    steps above using an archive downloaded/copied from a previous run.
    Confirm the restored install has the same recognizable data and that
    `docker compose up -d` afterward serves it normally through the web UI.
12. Toggle the schedule on with a short interval (temporarily edit
    `RELIQUARY_BACKUP_SCHEDULE_DEFAULT_INTERVAL_HOURS` or wait out a real
    interval) and confirm a Scheduled-triggered backup appears unattended.
13. Set retention to keep-last=1 and create several backups; confirm older
    ones get pruned on the next scheduled tick, and that if only one verified
    backup exists, it survives pruning even past its age limit.
