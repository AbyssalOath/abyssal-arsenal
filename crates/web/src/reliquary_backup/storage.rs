//! Where a finished backup archive lives -- GitHub issue #9's
//! `StorageDestination` trait. `LocalFs` (this file) and
//! `sepulchre::reliquary_adapter::SepulchreDestination` are the two
//! implementations today, chosen per-job (see
//! `reliquary_backup::orchestrator::resolve_destination`) rather than
//! fixed at startup. An S3-compatible destination is a natural third
//! implementation later (same trait, no redesign), out of scope for this
//! pass.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncWrite};

use super::BackupError;

#[async_trait::async_trait]
pub trait StorageDestination: Send + Sync {
    /// The path a new backup with this file name should be written to.
    /// Doesn't create anything -- just resolves where. Meaningful only
    /// for a destination backed by a real local filesystem path
    /// (`LocalFs`); a genuinely remote destination (e.g. Sepulchre's
    /// SFTP/SMB adapter) returns a synthetic, display-only path here --
    /// see that impl's own doc comment for exactly which callers this
    /// still safely serves (labeling) versus which ones need the
    /// streaming methods below instead (actual I/O).
    fn resolve(&self, file_name: &str) -> PathBuf;

    /// Every backup archive file name currently present -- used to cross-
    /// check the database's job records against what's actually on disk
    /// (a file deleted out-of-band, or a DB row left behind by a crash
    /// before the file was written, are both real possibilities this
    /// deliberately doesn't paper over).
    async fn list(&self) -> Result<Vec<String>, BackupError>;

    async fn delete(&self, file_name: &str) -> Result<(), BackupError>;

    fn exists(&self, file_name: &str) -> bool {
        self.resolve(file_name).is_file()
    }

    /// Streaming write -- the destination-agnostic way to land the
    /// finished archive, added so a non-local destination (Sepulchre)
    /// can implement this trait at all. `NativeProvider::create` uses
    /// this (never `resolve` + a direct filesystem copy) for exactly
    /// that reason.
    async fn open_write(
        &self,
        file_name: &str,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin>, BackupError>;

    /// Streaming read -- the destination-agnostic counterpart to
    /// `open_write`. Not yet used by `verify`/`download`/the CLI's
    /// restore path, which still read a local path directly via
    /// `resolve` -- see `docs/reliquary-backups.md`'s "Sepulchre-backed
    /// destinations" section for the follow-up this implies.
    async fn open_read(
        &self,
        file_name: &str,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>, BackupError>;
}

/// Writes backups to a plain directory on the control plane's own disk
/// (`RELIQUARY_BACKUP_DESTINATION_PATH`, default `/backups` -- a
/// dedicated Compose volume, separate from the database's own, per
/// GitHub issue #9). Not web-served by anything; every file this creates
/// is 0600.
pub struct LocalFs {
    root: PathBuf,
}

impl LocalFs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub async fn ensure_root_exists(&self) -> Result<(), BackupError> {
        tokio::fs::create_dir_all(&self.root).await?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[async_trait::async_trait]
impl StorageDestination for LocalFs {
    fn resolve(&self, file_name: &str) -> PathBuf {
        self.root.join(file_name)
    }

    async fn list(&self) -> Result<Vec<String>, BackupError> {
        let mut names = Vec::new();
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file()
                && let Some(name) = entry.file_name().to_str()
            {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    async fn delete(&self, file_name: &str) -> Result<(), BackupError> {
        let path = self.resolve(file_name);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn open_write(
        &self,
        file_name: &str,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin>, BackupError> {
        let file = tokio::fs::File::create(self.resolve(file_name)).await?;
        // Set here, not as a separate post-write step in the caller --
        // a remote `StorageDestination` has no local path for a caller
        // to `set_permissions` on afterward, so this has to be each
        // destination's own responsibility.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .await?;
        }
        Ok(Box::new(file))
    }

    async fn open_read(
        &self,
        file_name: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, BackupError> {
        let file = tokio::fs::File::open(self.resolve(file_name)).await?;
        Ok(Box::new(file))
    }
}
