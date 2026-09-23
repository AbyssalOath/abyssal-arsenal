//! Where a finished backup archive lives -- GitHub issue #9's
//! `StorageDestination` trait. `LocalFs` is the only implementation now;
//! an S3-compatible destination is a natural second implementation later
//! (same trait, no redesign), out of scope for this pass.

use std::path::{Path, PathBuf};

use super::BackupError;

#[async_trait::async_trait]
pub trait StorageDestination: Send + Sync {
    /// The path a new backup with this file name should be written to.
    /// Doesn't create anything -- just resolves where.
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
}
