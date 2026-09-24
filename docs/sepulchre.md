# Sepulchre: storage and file-sharing connectivity

Sepulchre is the control plane's shared layer for storage connections --
SFTP servers, SMB/CIFS shares, and allowlisted local paths -- so other
Arsenals (Reliquary first) consume a named connection instead of each
building and configuring its own SFTP/SMB client and credential handling.
This document covers the connection model, what's implemented today versus
stubbed or deliberately out of scope, host-side provisioning's safety
guarantees, the `local` protocol's containment design, and how to test the
whole thing manually end to end.

There is no JavaScript anywhere in Sepulchre's UI -- every page is a plain
server-rendered HTML form, using the POST/redirect/GET pattern the rest of
this app already uses.

## Responsibilities

| Concern | Owner |
| --- | --- |
| Connection definitions, protocol config, roles, capabilities, access methods | **Sepulchre** |
| The secrets a connection needs (passwords, SSH keys) | **Sepulchre** (encrypted at rest, write-only in the UI) |
| Host-side security inspection: SSH host keys, `authorized_keys` listing/removal, TLS certs, file-permission scans, SSH keypair generation | **Cryptkeeper** |
| Backup-specific behavior consuming a connection (what to back up, retention, scheduling) | **Reliquary** (write path wired up and working; reading a backup back from a Sepulchre connection is a known, deliberate gap -- see "How Reliquary consumes a Sepulchre connection today" below) |

Cryptkeeper has no credential store of its own -- it never held connection
secrets, and this design never asked it to. Sepulchre owns both the
connection definition and the secret material a connection needs, reusing
the same `abyssal_core::crypto::EncryptionKey` (AES-256-GCM, single static
key from the `ENCRYPTION_KEY` env var) that Panopticon's switch SNMP
community strings and Grimoire's community-string macros already use --
no new encryption mechanism, no new env var. Sepulchre only ever calls
into Cryptkeeper's existing host-inspection operations (over the same
`execute_on_host`/agent-protocol channel every other Arsenal uses) for
things Cryptkeeper already does: generating an SSH keypair on a managed
host, or listing/removing an `authorized_keys` entry. Cryptkeeper cannot
*add* an authorized key -- Sepulchre writes its own, into a
Sepulchre-owned path (see "Host-side SFTP provisioning" below), so the two
Arsenals never fight over the same file.

## Protocol, access method, and role: three separate concepts

Earlier drafts of this feature conflated "SFTP" with "backup destination"
with "mount it on the host." They're independent:

- **Protocol** -- `sftp` | `smb` | `local`, `#[non_exhaustive]`
  (`crates/core/src/storage.rs`) so a future `nfs`/`webdav`/`s3` variant
  doesn't silently fall through an existing `match` uncaught; every
  cross-crate match already carries a wildcard arm for this. No variants
  exist yet for those three -- they're reserved, not implemented, and
  never shown in the UI.
- **Access method** -- *how* a connection is actually used:
  `native_client` (control-plane-only), `diagnostic_client`
  (control-plane-only), `mount` (managed-host-only), `rsync_ssh`
  (managed-host-only). The control plane container never performs a
  kernel mount -- no `CAP_SYS_ADMIN`, no privileged mode, no Docker
  socket -- so `mount` is only ever something a *managed host* does via
  the existing agent executor, never this process.
- **Role** -- *what a connection is for*, many-to-many via
  `connection_roles`: `backup_destination`, `file_transfer`,
  `remote_storage`, `other`. A connection is never inherently "a backup
  connection" -- a consumer (Reliquary) asks the resolver for a
  connection by role and required capabilities, never by protocol, so a
  Sepulchre connection with the `file_transfer` role only can't
  accidentally get treated as a backup target.

## Access method matrix (as implemented)

| Protocol | Method | Context | Status |
| --- | --- | --- | --- |
| SFTP | native client | control plane | **Implemented** -- primary path, `russh`+`russh-sftp` |
| SFTP | SSHFS mount | managed host | **Implemented** -- provisioning primitives only (render/apply/rollback); no UI wizard for it yet, see "Known limitations" |
| SFTP | rsync over SSH | managed host | **Model only** -- `AccessMethod::RsyncSsh` exists as a declarable capability flag; no control-plane rsync execution was added this pass (the existing executor's command surface wasn't extended for it) |
| SFTP | SCP | -- | **Non-goal** -- modern `scp` implementations use the SFTP protocol internally; never a separate method |
| SFTP | raw SSH command execution | -- | **Non-goal** -- provisioning plumbing (via the existing agent executor) is not a general "run a command" storage feature |
| SMB | CIFS mount | managed host | **Implemented** -- provisioning primitives only, same caveat as SFTP mount |
| SMB | native/diagnostic client | control plane | **Implemented** -- shells out to `smbclient`, one implementation covers both |
| SMB | Samba server provisioning | managed host | **Implemented** -- drop-in `smb.conf` include, `smbpasswd`-managed service user |
| SMB | Windows-admin / Kerberos / AD / DFS / multichannel / QUIC | -- | **Non-goal**, docs-only; legacy NTLMv1/SMB1 is never enabled |
| Local | direct path / existing host mount | control plane | **Implemented** -- allowlisted, `cap-std`-rooted |
| NFS / WebDAV / S3 | -- | -- | **Reserved** -- no `Protocol` variants exist yet |

## The `local` protocol

`local` treats an already-mounted or directly-attached filesystem path
(inside the control-plane container) as a storage connection -- e.g. the
same volume Reliquary's own native backups already use.

- **Allowlist**: `SEPULCHRE_LOCAL_ROOTS`, a comma-separated list of
  absolute host paths. If unset, it falls back to whatever
  `RELIQUARY_BACKUP_DESTINATION_PATH` is set to (the `abyssal_backups`
  volume by default), so pointing Reliquary at a Sepulchre `local`
  connection needs no extra configuration out of the box. Set it
  explicitly to allow more paths, or to an empty string to disable the
  `local` protocol entirely.
- Forbidden even if configured: `/`, `/etc`, `/proc`, `/sys`, `/dev`,
  `/var/run`, `/run`, and the Docker socket path -- these are rejected at
  parse time, independent of what an admin types.
- **Containment**: every connection and every I/O call resolves its path
  through a `cap_std::fs::Dir` opened once via `Dir::open_ambient_dir` on
  the allowed root, using `cap-std`'s rooted (`openat`-style) operations
  rather than a plain `std::fs::canonicalize`-then-check -- the latter has
  a TOCTOU window between the check and the actual open; `cap-std`'s API
  makes that window structurally impossible, since every subsequent
  operation is scoped to the already-open directory handle. `..`
  components are rejected outright at both connection-create time and on
  every I/O call.
- Created directories/files default to `0700`/`0600`.
- Validation includes a same-filesystem-as-the-database-volume check and a
  `/proc/self/mountinfo`-based network-filesystem detector (flags `nfs`,
  `nfs4`, `cifs`, `smb3`, `fuse.sshfs`, `9p` mount types with a warning,
  since a "local" path that's actually a network mount has different
  failure characteristics than local disk).
- Reliquary's existing `LocalFs`/`StorageDestination` (GitHub issue #9)
  is untouched -- this is a separate, new adapter path
  (`SepulchreDestination`), and no existing Reliquary configuration is
  ever force-migrated to it.

## Data model

Nine tables (`migrations/0019_sepulchre_storage.sql`):

- `storage_connections` -- the connection itself: protocol, origin
  (control-plane vs. host-side-managed), protocol-specific JSON config,
  enabled flag, last validation summary.
- `storage_connection_secrets` -- `auth_method`, `secret_ciphertext`
  (AES-256-GCM), `secret_key_id` (a fixed constant today --
  `env:ENCRYPTION_KEY`, no rotation support yet), `secret_version`,
  `username`, `key_fingerprint`, `secret_updated_at`/`secret_updated_by`.
  Never a plaintext value at rest, and the secret fields are write-only in
  every form -- a blank field on submit means "keep the existing value,"
  never "clear it."
- `connection_roles` -- many-to-many, a connection's declared purpose(s).
- `connection_capabilities` -- `Read`/`List`/`Write`/`Delete`, each with a
  `declared` flag (admin intent) and a separate `verified_at`/
  `verified_by_validation_run_id` (only ever set by an actual successful
  validation check, cleared on the next run if that check doesn't pass
  again -- capabilities are never "sticky true").
- `connection_access_methods` -- which methods are enabled, in which
  execution context, on which managed host (if any).
- `validation_runs` -- one row per validation attempt, an ordered JSON
  array of per-check results (`check`, `method`, `status`, `error_kind`,
  `message`, `duration_ms`), overall status, triggered-by.
- `connection_consumers` -- which Arsenal is using a connection, for what
  purpose, under which role, requiring which capabilities (Reliquary
  registers itself here the first time it resolves a Sepulchre
  destination).
- `managed_shares` / `mount_definitions` -- host-side provisioning state
  (share/mount name, path, persistence method, applied/failed/removed
  status) for the share- and mount-creation primitives described below.

`storage_connections.managed_host_id`, `managed_shares.host_id`, and
`mount_definitions.host_id` are all `ON DELETE RESTRICT` against `hosts`
-- deleting a host that still has Sepulchre state on it is blocked rather
than silently orphaning rows.

## The shared consumer interface

```rust
trait StorageBackend: Send + Sync {
    async fn stat(&self, path: &str) -> Result<FileStat, SepulchreError>;
    async fn list(&self, path: &str) -> Result<Vec<FileEntry>, SepulchreError>;
    async fn open_read(&self, path: &str) -> Result<Box<dyn AsyncRead + Send + Unpin>, SepulchreError>;
    async fn open_write(&self, path: &str) -> Result<Box<dyn AsyncWrite + Send + Unpin>, SepulchreError>;
    async fn delete(&self, path: &str) -> Result<(), SepulchreError>;
    async fn ensure_dir(&self, path: &str) -> Result<(), SepulchreError>;
    async fn free_space(&self) -> Result<Option<u64>, SepulchreError>;
    fn possible_capabilities(&self) -> HashSet<Capability>;
}
```

Every I/O method is async, streaming (`AsyncRead`/`AsyncWrite`, never a
buffered `Vec<u8>` of a whole file in the SFTP/Local backends), and
timeout-bounded (`with_timeout`, a 60-second default).

A consumer never talks to a backend directly. It asks the resolver:

```rust
StorageConnectionResolver { pool }.resolve(
    connection_id,
    RequiredUse { role: ConnectionRole::BackupDestination, capabilities: &[Read, List, Write, Delete] },
).await
```

which returns a usable `ResolvedConnection` only if, in order: the
connection is enabled, it holds the required role, every required
capability is *verified* (not just declared), the last validation run
passed, and that validation is recent (within a 24-hour staleness
window) -- otherwise a typed `NotUsableReason` (`Disabled`,
`MissingRole`, `CapabilityUnverified`, `ValidationStale`,
`ValidationFailed`), never a generic error string a caller has to
string-match.

## Crate choices

- **SFTP -- `russh` + `russh-sftp`**: `russh` was already a workspace
  dependency (added for the SSH-deploy-agents feature); layering
  `russh-sftp` on its channel transport avoids a second, unrelated SSH
  stack (`ssh2`/libssh2) existing alongside it. Host-key verification is
  mandatory -- connecting with no pinned fingerprint yet is refused
  outright; a later fingerprint mismatch is a hard `host_key_mismatch`
  error, never a silent auto-accept.
- **`ssh-key` 0.7.0-rc.11**, pinned to the *exact* transitive version
  `russh` already resolves (`cargo tree -i ssh-key`), so the dependency
  tree never carries two conflicting major versions of the same crate.
  Keypair generation deliberately uses `Ed25519Keypair::from_seed` fed by
  `rand::rngs::OsRng` rather than `PrivateKey::random()`, because the
  latter needs `rand_core 0.10`'s `CryptoRng` trait -- incompatible with
  the workspace's existing `rand 0.8`/`rand_core 0.6` stack, and not worth
  a second major version of `rand_core` just for this.
- **SMB -- shelling out to `smbclient`** (already present via the
  Dockerfile's runtime `apt-get install`) rather than binding
  `libsmbclient` via FFI (`pavao`/similar). Documented trade-off:
  `smbclient`'s CLI has no byte-stream `get`/`put`, only whole-file
  transfers, so `open_read`/`open_write` stage through a private `0600`
  temp file rather than a true zero-copy stream the way SFTP/Local are --
  disk-buffered, not memory-buffered, so the "don't blow up on a large
  file" concern is still satisfied, just not the strictest possible
  reading of "streaming only." A future move to `pavao` would close this
  gap if it ever becomes a real problem.
- **`cap-std`** -- the one new crate this pass required beyond what SFTP/
  SMB needed, specifically for `local`'s TOCTOU-safe rooted filesystem
  operations (see "The `local` protocol" above). No other new
  dependencies were added.

## Host-side provisioning

Every host-side change goes through the same agent-executor channel every
other Arsenal already uses (`execute_on_host`/`AgentOperation`, WebSocket,
never raw SSH) -- no new remote-execution mechanism was introduced.
`PROTOCOL_VERSION` was bumped (20 -> 21) for the 12 new operation variants.

Safety guarantees, all enforced the same way regardless of SFTP or SMB:

- **Never edits the distro's main config file.** Only a Sepulchre-owned
  drop-in (`/etc/ssh/sshd_config.d/50-sepulchre.conf`) or include file
  (`/etc/samba/sepulchre.conf`, referenced from `smb.conf` via an
  `include =` line Sepulchre checks for but never edits into place
  automatically -- adding that line is a separate, explicitly confirmed
  step).
- **Validate before reload, always.** `sshd -t` / `testparm -s` must pass
  before a reload is even attempted. On either a validation failure or a
  reload failure, the previous config is restored and reloaded again --
  a bad config is never left applied.
- **Lockout protection**: every SFTP directive is scoped inside a
  `Match User`/`Match Group` block, never touching the server's global
  auth behavior.
- **Config rendering is template-based and escaped**, not string
  concatenation of raw admin input -- usernames, paths, and share names
  are validated against a config-safe character allowlist before ever
  reaching a rendered line, guarding against directive injection into the
  generated `sshd`/`smb.conf` snippets.
- **Firewall changes are detect-and-report only** -- Sepulchre never
  modifies firewall rules on a managed host.
- **Mounts** prefer a systemd mount unit (`_netdev`, `nofail`) over
  `/etc/fstab`, with credentials in a root-owned `0600` file.
- **SFTP host-side authorized keys**: Cryptkeeper generates the keypair
  (its existing host-side SSH key generation), but Cryptkeeper can only
  *list or remove* an `authorized_keys` entry, never add one. Sepulchre
  writes its own, into a Sepulchre-reserved,
  root-owned `AuthorizedKeysFile /etc/ssh/sepulchre/authorized_keys/%u`
  path, specifically to avoid ownership conflicts with a chrooted SFTP
  account's own home directory.
- **Destructive host-side actions** (removing a share, a mount, an
  authorized key, a chroot account) go through the same typed-confirmation
  pattern as every other destructive action in this app, and are audited
  (`StorageShareRemoved`, `StorageMountRemoved`, etc.) -- never delete
  data on disk unless separately, explicitly requested.

## Validation

An ordered check list runs on demand or can be re-run any time from a
connection's detail page: connect, list the base path, stat-based
read-permission check, an optional read/write round-trip (writes into a
reserved `.sepulchre-validation/` scratch subdirectory -- created first
via `ensure_dir` -- writes a random payload, SHA-256 hashes it, reads it
back, re-hashes, compares, and always attempts cleanup even if the write
itself failed), and a free-space check. Every check maps to a stable
`error_kind`: `unreachable`, `timeout`, `dns_failure`, `auth_failed`,
`host_key_mismatch`, `permission_denied`, `not_found`, `read_only`,
`protocol_unsupported`, `method_unavailable`, `path_not_allowed`,
`unknown`. A connection's capabilities are only ever marked verified by
an actual passing check in the current run -- a capability not
re-proven this run is cleared, not left stale.

## Workflow registry entries

Following the existing compiled-in registry (`crates/workflows/registry.json`)
and its host-scoped-only URL convention (every target URL is
`/arsenals/<target>/<host_id>`, so an entry only makes sense when a real
managed host actually exists for the connection):

**Added:**

- `sepulchre.connection_validation` `error_kind == auth_failed` AND
  `origin == host_side_managed` -> Cryptkeeper's host page ("Review Keys
  and Authorized Keys").
- `sepulchre.connection_validation` `error_kind == host_key_mismatch` AND
  `origin == host_side_managed` -> Cryptkeeper's host page ("Review Host
  Keys").
- `sepulchre.connection_validation` `error_kind == method_unavailable` AND
  `origin == host_side_managed` -> Sepulchre's own host page ("Install
  Prerequisites on Host").
- `sepulchre.connection_validation` `error_kind == read_only` AND
  `origin == host_side_managed` -> Resurrection's read-only-filesystems
  view.
- `sepulchre.mount_status` `read_only == true` -> Resurrection's
  read-only-filesystems view.
- `resurrection.read_only_filesystems`, when `fstype` matches
  `nfs`/`nfs4`/`cifs`/`smb3`/`fuse.sshfs` -> Sepulchre's host page
  ("Check Network Storage with Sepulchre").

**Explicitly skipped** (documented rather than silently dropped): "Use as
Backup Target with Reliquary" and "Assign Backup Role" -- neither has a
real managed host to target (a connection isn't necessarily host-scoped,
and the destination-picker UI these would need is out of scope this pass);
an `unreachable` entry pointing at Cystoolbox (no such target view
exists); `reliquary.backup_write_failed` -> Sepulchre/Catacomb (no
`destination_connection_id` concept exists in Reliquary's current write
path); Cystoolbox -> Sepulchre (Cystoolbox doesn't expose an `fstype`
field); Cryptkeeper's certificate-detail view -> Sepulchre (Sepulchre
doesn't use TLS certificates at all, so there's no real condition to key
off).

## How Reliquary consumes a Sepulchre connection today

**It's wired up and working, for the write path.** An earlier draft of
this document (and an earlier summary given to the user) claimed
otherwise -- the `SepulchreDestination` adapter existed but nothing
called it, so it was dead code. That gap has been closed.

`Reliquary`'s `StorageDestination` trait (`crates/web/src/reliquary_backup/storage.rs`)
has streaming `open_write`/`open_read` methods, and `NativeProvider::create()`'s
final archive-landing step goes through `storage.open_write()` +
`tokio::io::copy` + `.shutdown()`, so it's destination-agnostic.
`SepulchreDestination` (`crates/web/src/sepulchre/reliquary_adapter.rs`)
implements that trait by resolving a Sepulchre connection requiring the
`backup_destination` role and all four capabilities, and registers itself
as a consumer in `connection_consumers`.

**What actually picks a destination**: `reliquary_backup::orchestrator::resolve_destination(state, connection_id)`
-- `None` resolves the local destination (`AppState.reliquary_backup_storage`,
unchanged from before); `Some(id)` resolves that Sepulchre connection via
the same usable-check every other consumer goes through. `NativeProvider`
no longer holds a fixed `storage` field; `BackupProvider::create()` takes
`storage: &dyn StorageDestination` per call, so the same provider instance
serves every job regardless of which destination that job actually uses.
Three places call `resolve_destination`:

- **Manual "Backup now"** (`/arsenals/reliquary/backups`) -- a Destination
  dropdown lists every enabled, `backup_destination`-role connection
  alongside "Local"; picked per run.
- **Scheduled backups** -- a `RELIQUARY_BACKUP_DESTINATION_CONNECTION_ID`
  setting (empty = local), configured from the same page's Control-Plane
  Configuration card, since nobody's present on an unattended run to
  choose each time.
- **Retention pruning** -- resolves each prunable job's own destination
  individually (jobs can be spread across local and any number of
  Sepulchre connections); a connection that's since become unusable fails
  that one job's prune with a logged warning and moves on, rather than
  aborting the whole sweep.

Every job row now records `destination_connection_id` (nullable, `ON
DELETE SET NULL` against `storage_connections` -- deleting a connection is
never blocked by backup history) alongside a human-readable
`destination_path` label (`"sepulchre://<connection name>"` for a
Sepulchre-backed job).

**What still doesn't work, on purpose**: reading a backup back from a
Sepulchre-backed destination. Download, quick-verify, and restore all
still assume a real local file at `storage.resolve(...)` -- only `LocalFs`
can give them that; a Sepulchre connection's `resolve()` returns a
synthetic, display-only string. All three routes now check
`job.destination_connection_id` first and refuse cleanly
("downloading, verifying, and restoring from a Sepulchre-backed
destination isn't supported yet") rather than failing confusingly partway
through -- this is a real, live-tested guard, not just a design
intention. The restore flow's own pre-restore safety backup is always
forced to the local destination regardless of what the backup being
restored used, deliberately: restoring is exactly the moment a remote
connection's own reachability is least trustworthy to depend on for a
safety net. See docs/reliquary-backups.md's "Sepulchre-backed
destinations" section for the operator-facing version of all of this,
including the manual workaround for restoring a Sepulchre-backed backup
today.

**Verified live**, not just unit-tested: a real `local`-protocol Sepulchre
connection was created, validated, and set as a manual backup's
destination; the archive genuinely landed in that connection's own
directory (confirmed on disk, not just via the success message); the
download/verify guards were confirmed to refuse with the expected message
against that job; and deleting the job was confirmed to remove the
archive from the connection's own directory, not just the database row.
This is also how a real bug was caught and fixed:
`SepulchreDestination::open_write` always calls the backend's
`ensure_dir("")` first (a protocol-agnostic "make sure the target
directory exists" step), and `LocalBackend::ensure_dir` didn't have the
same "empty path means the base directory itself" special case
`stat`/`list` already had, so it rejected the call with `path_not_allowed`
on every single write attempt until fixed.

## Known limitations

- **`rsync_ssh` is model-only.** The access method exists as a
  declarable/verifiable flag; no control-plane rsync execution was
  implemented.
- **The host-side share/mount creation wizard has no separate
  plan-preview step.** `/arsenals/sepulchre/hosts/:id/shares/new` and
  `.../mounts/new` apply directly on submit -- the warning banner on the
  form itself is the "preview" (an explicitly permitted simplification
  of the plan/preview/apply flow, since every step is still reported
  back clearly and a failure partway through rolls back or is recorded
  as `failed` rather than left silently half-applied).
- **SSHFS mounts of an SFTP connection are not exposed in the mount
  wizard** -- only SMB/CIFS. Doing this properly needs the server's raw
  host-key *text* to build a `UserKnownHostsFile` sshfs can verify
  against, not just the SHA256 fingerprint Sepulchre already stores; the
  provisioning primitives (`render_mount_unit_content` with
  `fs_type="fuse.sshfs"`) already support it, so this is a UI/host-key-
  storage gap, not a missing backend capability.
- **A CIFS mount requires the host's kernel to have the `cifs` filesystem
  driver available** (usually via the distro's `cifs-utils` package plus
  a running kernel that was built with `CONFIG_CIFS`) -- Sepulchre
  detects and reports a resulting `mount: unknown filesystem type 'cifs'`
  or `No such device` failure (recorded as a `failed`-state mount,
  visible and removable from the host page) but never installs kernel
  modules or packages for it. Confirmed live: this is exactly the
  failure mode hit in this project's own sandbox, whose on-disk kernel
  had been upgraded past the currently *booted* one.
- **Reliquary can write a backup to a Sepulchre connection, but can't read
  one back from it yet** -- download, quick-verify, and restore are all
  refused with a clear message for a Sepulchre-backed job. See "How
  Reliquary consumes a Sepulchre connection today" above for the full
  detail and the manual workaround.
- **New Super Admin permissions need a manual re-grant on an existing
  deployment.** `seed_role()` only sets a role's permission set the first
  time that role is created -- it never tops up an already-existing role
  with newly-added `Permission` variants on a later restart (a
  pre-existing, intentional tradeoff: startup shouldn't silently clobber
  an admin's customized permission set). A fresh install seeds
  `storage_connections.view`/`storage_connections.manage` automatically;
  an existing deployment needs a Super Admin to grant them once from the
  Roles page after upgrading.
- **SMB's streaming is disk-buffered, not memory-buffered** -- see "Crate
  choices" above.

## Manual test steps

Steps 1-5 were actually carried out against real infrastructure (disposable
Docker containers -- a standalone `atmoz/sftp` server, a standalone
`dperson/samba` server, and a systemd-enabled Debian container running a
real `abyssal-agent` as a genuine connected managed host), not just
described. Four real bugs surfaced this way and were fixed: an SFTP
chroot's `base_path` of `/` being collapsed to an empty string by
`trim_end_matches('/')`; `smbclient`'s `NT_STATUS_*` codes not being
recognized by `error_kind_for`; a Samba share directory created root-owned
(blocking the very service account meant to write to it); and a systemd
mount-unit name that didn't escape a literal hyphen, which systemd's own
unit-name validation rejects outright. See the CHANGELOG for the full list.

1. `docker compose up -d --build` (or `cargo run -p abyssal-arsenal`
   against a local MariaDB) and confirm migration `0019` applies.
2. As a Super Admin (or a role holding `storage_connections.manage`),
   visit `/arsenals/sepulchre` -> create a `local` connection pointed at
   a path under the allowlist; validate it (read-only, then read/write);
   confirm all four capabilities show verified.
3. Stand up a real SFTP server (e.g. `openssh-server`) and a real SMB
   share (e.g. Samba) reachable from the control plane container. For
   each: create the connection, use "Review and pin the host key" (SFTP
   only) or enter credentials (SMB), then validate. Confirm a wrong
   password produces `auth_failed`, a wrong port/host produces
   `unreachable`, and (SFTP) presenting a different host key on a later
   validation produces a hard `host_key_mismatch`, never a silent
   re-pin.
4. Assign the `backup_destination` role to one verified connection, pick
   it from the Destination dropdown on `/arsenals/reliquary/backups` and
   run a manual backup; confirm the archive lands on the remote share/
   server (not just that the UI says "Backup completed"), the job's
   Destination column names the connection, and the connection's
   `connection_consumers` row shows Reliquary. Confirm Download/Verify/
   Restore on that job are all refused with a clear message. Actually
   carried out (not just described) against a real `local`-protocol
   Sepulchre connection -- see the CHANGELOG for what that caught.
5. Enroll a real managed host (a disposable, systemd-enabled container
   is enough -- never the control plane's own host), elevate it (any
   arsenal's existing "Elevate" action; elevation is host-scoped, not
   arsenal-scoped), then from `/arsenals/sepulchre/hosts/:id`: provision
   an SFTP share ("New SFTP share") and confirm the chroot account,
   drop-in config, generated keypair, and installed authorized key all
   exist on the host and the resulting connection validates clean;
   provision an SMB share ("New SMB share") the same way; create a CIFS
   mount of that SMB connection ("New mount") and confirm the
   credentials file, mount unit, and (kernel `cifs` support permitting)
   the actual mount all exist; remove the share and the mount and
   confirm the host-side account/config/unit are cleaned up (data on
   disk is deliberately left behind).
6. Confirm no `<script>` tag appears anywhere under `/arsenals/sepulchre`
   and that every form carries a CSRF token.
