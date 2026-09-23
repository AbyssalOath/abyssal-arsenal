//! Restore -- GitHub issue #9. Database restore is the fully-automated
//! path (decrypt/extract the archive, stream the dump back into
//! MariaDB -- `mariadb-dump --databases`'s own embedded `CREATE DATABASE`/
//! `USE` statements mean this correctly recreates the original database
//! by name, no extra drop/create logic needed). "Configuration" and
//! "encryption keys" components are extracted to disk for an operator to
//! read and reapply by hand, not automatically reinstated -- this process
//! can't safely rewrite its own environment or the `.env`/`docker-
//! compose.yml` files it was started from (which it can't even see; see
//! `provider::NativeProvider`'s own doc comment), so pretending to
//! "restore" them automatically would be misleading.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use abyssal_core::{BackupComponent, BackupManifest};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::archive;
use super::crypto;
use super::dump;
use super::storage::StorageDestination;
use super::{BackupError, DbConnectionInfo};

/// Set while a restore is in progress -- checked by
/// `crate::middleware::maintenance_mode` to block ordinary traffic and
/// show a clear "under maintenance" page instead. A plain shared
/// `AtomicBool` rather than a richer lock: nothing here needs to *wait*
/// for maintenance mode, only read whether it's currently on, on every
/// request, cheaply.
#[derive(Clone, Default)]
pub struct MaintenanceMode(Arc<AtomicBool>);

impl MaintenanceMode {
    pub fn is_active(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn enter(&self) -> MaintenanceGuard {
        self.0.store(true, Ordering::SeqCst);
        MaintenanceGuard(self.0.clone())
    }
}

/// Clears maintenance mode when dropped -- guarantees it comes back off
/// even if the restore returns early via `?`, panics, or is cancelled.
struct MaintenanceGuard(Arc<AtomicBool>);
impl Drop for MaintenanceGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

pub struct RestorePreview {
    pub manifest: BackupManifest,
    pub schema_version_matches: bool,
    pub current_schema_version: i64,
    pub mariadb_major_version_differs: bool,
    pub current_mariadb_version: String,
}

/// Dry-run: decrypts/reads the manifest and compares it against the
/// current deployment, changing nothing. What the restore page's preview
/// step shows before anyone can confirm an actual restore.
pub async fn preview(
    storage: &dyn StorageDestination,
    file_name: &str,
    manifest: &BackupManifest,
    database_url: &str,
) -> Result<RestorePreview, BackupError> {
    let _ = storage.resolve(file_name); // existence is checked by the caller via quick_verify
    let conn = DbConnectionInfo::parse(database_url)?;
    let creds = dump::resolve_backup_credentials(&conn);
    let (current_version, ..) = dump::server_metadata(&conn, &creds).await?;
    let current_major = current_version.split('.').next().unwrap_or("");
    let backup_major = manifest.mariadb_version.split('.').next().unwrap_or("");

    Ok(RestorePreview {
        schema_version_matches: manifest.manifest_version == 1,
        current_schema_version: manifest.schema_migration_version,
        mariadb_major_version_differs: !current_major.is_empty() && current_major != backup_major,
        current_mariadb_version: current_version,
        manifest: manifest.clone(),
    })
}

pub struct RestoreRequest<'a> {
    pub file_name: &'a str,
    pub manifest: &'a BackupManifest,
    pub components: &'a [BackupComponent],
    pub passphrase: Option<Zeroizing<String>>,
    pub database_url: &'a str,
    pub work_dir: &'a Path,
}

/// Runs an actual restore: enters maintenance mode for its duration,
/// decrypts/extracts the archive, and (if `Database` is among
/// `components`) streams the dump back into MariaDB. Extracted
/// configuration/encryption-key files are left in `work_dir` for the
/// caller to surface for manual download -- see this module's own doc
/// comment for why those aren't reapplied automatically. Always exits
/// maintenance mode on return, success or failure.
pub async fn restore(
    storage: &dyn StorageDestination,
    maintenance: &MaintenanceMode,
    request: RestoreRequest<'_>,
    cancel: &CancellationToken,
) -> Result<(), BackupError> {
    let _guard = maintenance.enter();

    let archive_path = storage.resolve(request.file_name);
    if !archive_path.is_file() {
        return Err(BackupError::Restore(format!(
            "archive file is missing: {}",
            archive_path.display()
        )));
    }

    tokio::fs::create_dir_all(request.work_dir).await?;

    let plaintext_archive_path = if let Some(encryption) = &request.manifest.encryption {
        let Some(passphrase) = request.passphrase.as_deref() else {
            return Err(BackupError::Restore(
                "this backup is encrypted -- a passphrase is required to restore it".to_string(),
            ));
        };
        let out_path = request.work_dir.join("archive.tar.zst");
        let in_path = archive_path.clone();
        let out_path_for_task = out_path.clone();
        let passphrase_owned = passphrase.to_string();
        let encryption = encryption.clone();
        tokio::task::spawn_blocking(move || {
            crypto::decrypt_file_blocking(
                &in_path,
                &out_path_for_task,
                &passphrase_owned,
                &encryption,
            )
        })
        .await
        .map_err(|e| BackupError::Crypto(format!("decryption task panicked: {e}")))??;
        out_path
    } else {
        archive_path.clone()
    };

    if cancel.is_cancelled() {
        return Err(BackupError::Cancelled);
    }

    let extract_dir = request.work_dir.join("extracted");
    let extract_path = extract_dir.clone();
    let archive_for_extract = plaintext_archive_path.clone();
    tokio::task::spawn_blocking(move || {
        archive::extract_archive_blocking(&archive_for_extract, &extract_path)
    })
    .await
    .map_err(|e| BackupError::Archive(format!("extraction task panicked: {e}")))??;

    if request.components.contains(&BackupComponent::Database) {
        let dump_path = extract_dir.join("db.sql");
        if !dump_path.is_file() {
            return Err(BackupError::Restore(
                "archive has no db.sql -- was it created without the Database component?"
                    .to_string(),
            ));
        }
        let conn = DbConnectionInfo::parse(request.database_url)?;
        let creds = dump::resolve_backup_credentials(&conn);
        // The dump is self-naming (`--databases <db>` embeds its own
        // CREATE DATABASE/USE), so the positional database argument here
        // only needs to be a database the connecting user can reach at
        // all -- it's immediately superseded by the dump's own `USE`.
        dump::restore_database(&conn, &creds, &conn.database, &dump_path, cancel).await?;
    }

    Ok(())
}
