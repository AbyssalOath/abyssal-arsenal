//! `BackupProvider` -- GitHub issue #9's abstraction over *how* a backup
//! is actually produced/restored, so a future Remote/Agent provider
//! (backing up a managed host's own data, dispatched over the agent
//! protocol like every other Reliquary-today operation) can be added
//! later as a second implementation of this same trait, not a redesign.
//! `NativeProvider` -- the control plane backing up itself -- is the only
//! implementation this pass builds.

use std::path::PathBuf;
use std::sync::Arc;

use abyssal_core::{BackupComponent, BackupManifest, ManifestEntry};
use abyssal_database::DbPool;
use chrono::Utc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::archive::{self, ArchiveEntry};
use super::crypto;
use super::dump;
use super::storage::StorageDestination;
use super::{BackupError, DbConnectionInfo};

pub struct BackupRequest {
    pub components: Vec<BackupComponent>,
    pub encrypt: bool,
    pub passphrase: Option<Zeroizing<String>>,
}

pub struct BackupOutcome {
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub manifest: BackupManifest,
}

#[async_trait::async_trait]
pub trait BackupProvider: Send + Sync {
    async fn create(
        &self,
        request: BackupRequest,
        cancel: &CancellationToken,
    ) -> Result<BackupOutcome, BackupError>;

    fn describe(&self) -> &'static str;
}

/// Backs up the control plane's own persistent data: the application
/// database (always, if selected), a redacted snapshot of this process's
/// own configuration, and -- opt-in, always encrypted -- `ENCRYPTION_KEY`.
///
/// One real constraint discovered while building this, worth stating
/// plainly: `docker-compose.yml`/`.env`/`Caddyfile` live on the Docker
/// *host*, not inside the app container this process runs in, and
/// nothing mounts them in. "Application configuration" here is therefore
/// this running process's own environment (redacted), which is actually
/// the more relevant artifact anyway -- it's exactly what this instance
/// is configured with right now, not a possibly-stale copy of a file --
/// but it does mean `docker-compose.yml` itself needs to be kept in
/// version control or backed up separately; see
/// `docs/reliquary-backups.md`.
pub struct NativeProvider {
    pub pool: DbPool,
    pub database_url: String,
    pub work_dir: PathBuf,
    pub storage: Arc<dyn StorageDestination>,
    pub arsenal_version: String,
}

impl NativeProvider {
    /// Snapshots this process's own environment, dropping anything whose
    /// name looks secret-shaped (`PASSWORD`, `SECRET`, `KEY`, `TOKEN`) --
    /// GitHub issue #9: "Redact raw secret values from `.env`; store
    /// variable names and non-secret values only." A name being kept
    /// doesn't mean its value definitely isn't sensitive (this is a
    /// heuristic, not a guarantee), so this component is still only ever
    /// included in an *encrypted* archive by default
    /// (`RELIQUARY_BACKUP_ENCRYPT_BY_DEFAULT`).
    fn redacted_config_snapshot(&self) -> serde_json::Value {
        const SECRET_MARKERS: &[&str] = &["PASSWORD", "SECRET", "KEY", "TOKEN"];
        let mut vars = serde_json::Map::new();
        for (key, value) in std::env::vars() {
            let is_secret = SECRET_MARKERS
                .iter()
                .any(|m| key.to_uppercase().contains(m));
            vars.insert(
                key,
                if is_secret {
                    serde_json::Value::String("<redacted>".to_string())
                } else {
                    serde_json::Value::String(value)
                },
            );
        }
        serde_json::json!({
            "note": "Snapshot of this control-plane process's own environment at backup time. \
                     Values that look like secrets (name contains PASSWORD/SECRET/KEY/TOKEN) are \
                     redacted. docker-compose.yml/Caddyfile are NOT included here -- they live on \
                     the Docker host, not inside this container. Keep them in version control or \
                     back them up separately.",
            "environment": vars,
        })
    }

    async fn image_references(&self) -> Vec<String> {
        // No Docker socket access (deliberately -- GitHub issue #9: "Do
        // not mount the Docker socket or docker exec into the DB
        // container," extended here to the app's own image too). All
        // this process can honestly report about its own image is its
        // own build version.
        vec![format!("abyssal-arsenal:{}", self.arsenal_version)]
    }
}

#[async_trait::async_trait]
impl BackupProvider for NativeProvider {
    async fn create(
        &self,
        request: BackupRequest,
        cancel: &CancellationToken,
    ) -> Result<BackupOutcome, BackupError> {
        let backup_id = Uuid::new_v4();
        let work_dir = self.work_dir.join(format!("build-{backup_id}"));
        tokio::fs::create_dir_all(&work_dir).await?;
        // Always cleaned up, success or failure -- this is scratch space
        // for the plaintext dump/config before they're sealed into the
        // final archive, never the archive's own permanent home.
        let _cleanup = CleanupDir(work_dir.clone());

        let mut entries = Vec::new();
        let mut manifest_entries = Vec::new();
        let (mut dump_started_at, mut dump_finished_at) = (Utc::now(), Utc::now());
        let (mut mariadb_version, mut charset, mut collation, mut sql_mode) =
            (String::new(), String::new(), String::new(), String::new());

        if request.components.contains(&BackupComponent::Database) {
            let conn = DbConnectionInfo::parse(&self.database_url)?;
            let creds = dump::resolve_backup_credentials(&conn);
            let dump_path = work_dir.join("db.sql");
            let exclude_audit_log = !request.components.contains(&BackupComponent::AuditLogs);
            let outcome =
                dump::dump_database(&conn, &creds, &dump_path, exclude_audit_log, cancel).await?;
            dump_started_at = outcome.started_at;
            dump_finished_at = outcome.finished_at;
            manifest_entries.push(ManifestEntry {
                path: "db.sql".to_string(),
                sha256: outcome.sha256,
                size_bytes: outcome.size_bytes,
            });
            entries.push(ArchiveEntry {
                archive_path: "db.sql".to_string(),
                source_path: dump_path,
            });

            let (v, c, col, mode) = dump::server_metadata(&conn, &creds).await?;
            mariadb_version = v;
            charset = c;
            collation = col;
            sql_mode = mode;
        }

        if cancel.is_cancelled() {
            return Err(BackupError::Cancelled);
        }

        if request.components.contains(&BackupComponent::Configuration) {
            let config_path = work_dir.join("config.json");
            let snapshot = self.redacted_config_snapshot();
            let bytes = serde_json::to_vec_pretty(&snapshot)?;
            tokio::fs::write(&config_path, &bytes).await?;
            manifest_entries.push(sha256_entry("config.json", &bytes));
            entries.push(ArchiveEntry {
                archive_path: "config.json".to_string(),
                source_path: config_path,
            });
        }

        if request
            .components
            .contains(&BackupComponent::EncryptionKeys)
        {
            let Some(raw_key) = std::env::var("ENCRYPTION_KEY")
                .ok()
                .filter(|v| !v.is_empty())
            else {
                return Err(BackupError::Config(
                    "ENCRYPTION_KEY component was requested but ENCRYPTION_KEY isn't set in \
                     this environment"
                        .to_string(),
                ));
            };
            let keys_path = work_dir.join("encryption_keys.json");
            let bytes =
                serde_json::to_vec_pretty(&serde_json::json!({ "ENCRYPTION_KEY": raw_key }))?;
            tokio::fs::write(&keys_path, &bytes).await?;
            manifest_entries.push(sha256_entry("encryption_keys.json", &bytes));
            entries.push(ArchiveEntry {
                archive_path: "encryption_keys.json".to_string(),
                source_path: keys_path,
            });
        }

        // AuditLogs has no archive entry of its own -- when selected, its
        // rows are already inside db.sql (see `exclude_audit_log` above);
        // when not selected, `--ignore-table` left them out of db.sql
        // entirely. Recorded in the manifest's `components` list either
        // way purely so a restore/consumer can see whether it was
        // deliberately included, not silently along for the ride.

        if cancel.is_cancelled() {
            return Err(BackupError::Cancelled);
        }

        let schema_migration_version = current_migration_version(&self.pool).await?;
        let manifest = BackupManifest {
            manifest_version: 1,
            backup_id,
            created_at: Utc::now(),
            arsenal_version: self.arsenal_version.clone(),
            schema_migration_version,
            mariadb_version,
            mariadb_charset: charset,
            mariadb_collation: collation,
            mariadb_sql_mode: sql_mode,
            components: request.components.clone(),
            database_dump_started_at: dump_started_at,
            database_dump_finished_at: dump_finished_at,
            entries: manifest_entries,
            archive_sha256: String::new(), // filled in after the archive is built
            encryption: None,              // filled in below if encrypting
            image_references: self.image_references().await,
        };

        let manifest_path = work_dir.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?).await?;
        entries.push(ArchiveEntry {
            archive_path: "manifest.json".to_string(),
            source_path: manifest_path.clone(),
        });

        let unencrypted_name = format!("backup-{backup_id}.tar.zst");
        let unencrypted_path = work_dir.join(&unencrypted_name);
        let entries_for_build = entries;
        let build_path = unencrypted_path.clone();
        let (archive_sha256, archive_size) = tokio::task::spawn_blocking(move || {
            archive::build_archive_blocking(&entries_for_build, &build_path)
        })
        .await
        .map_err(|e| BackupError::Archive(format!("archive build task panicked: {e}")))??;

        let mut manifest = manifest;
        manifest.archive_sha256 = archive_sha256;

        // The manifest.json entry inside the archive above was written
        // *before* archive_sha256 was known (necessarily -- it's a hash
        // of the archive that contains it). The row/job-level manifest
        // (what the UI shows, and what a restore reads from the DB
        // first) is the authoritative copy; the in-archive one is best-
        // effort/informational, documented as such rather than an
        // inconsistency to silently paper over.

        let (final_name, final_path, final_size, encryption_meta) = if request.encrypt {
            let passphrase = request.passphrase.as_deref().ok_or_else(|| {
                BackupError::Config(
                    "encryption was requested but no passphrase was given".to_string(),
                )
            })?;
            let encrypted_name = format!("{unencrypted_name}.enc");
            let encrypted_path = work_dir.join(&encrypted_name);
            let enc_in = unencrypted_path.clone();
            let enc_out = encrypted_path.clone();
            let passphrase_owned = passphrase.to_string();
            let meta = tokio::task::spawn_blocking(move || {
                crypto::encrypt_file_blocking(&enc_in, &enc_out, &passphrase_owned)
            })
            .await
            .map_err(|e| BackupError::Crypto(format!("encryption task panicked: {e}")))??;
            let size = tokio::fs::metadata(&encrypted_path).await?.len();
            (encrypted_name, encrypted_path, size, Some(meta))
        } else {
            (unencrypted_name, unencrypted_path, archive_size, None)
        };
        manifest.encryption = encryption_meta;

        // The hash of the file actually landing in storage -- the
        // encrypted file's bytes when encrypting, which differ entirely
        // from `manifest.archive_sha256` (the pre-encryption archive's
        // hash, kept in the manifest for its own documentation purposes).
        // This is the value quick-verify recomputes and compares against,
        // so it has to match what's really on disk in every case, not
        // just the unencrypted one.
        let final_sha256 = super::verify::hash_file(&final_path).await?;

        let dest_path = self.storage.resolve(&final_name);
        tokio::fs::copy(&final_path, &dest_path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(0o600)).await?;
        }

        Ok(BackupOutcome {
            file_name: final_name,
            size_bytes: final_size,
            sha256: final_sha256,
            manifest,
        })
    }

    fn describe(&self) -> &'static str {
        "native"
    }
}

fn sha256_entry(path: &str, bytes: &[u8]) -> ManifestEntry {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    ManifestEntry {
        path: path.to_string(),
        sha256: super::hex_encode(&hasher.finalize()),
        size_bytes: bytes.len() as u64,
    }
}

async fn current_migration_version(pool: &DbPool) -> Result<i64, BackupError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT MAX(version) FROM _sqlx_migrations WHERE success = TRUE")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(v,)| v).unwrap_or(0))
}

/// Removes a scratch build directory on drop, success or failure alike --
/// `spawn_blocking`'s own panics aside, every early `?` return in
/// `create` above goes through this the same way a clean finish does.
struct CleanupDir(PathBuf);
impl Drop for CleanupDir {
    fn drop(&mut self) {
        let path = self.0.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_dir_all(&path).await;
        });
    }
}
