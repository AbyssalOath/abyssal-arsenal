//! Bridges Sepulchre to Reliquary: a [`StorageDestination`] backed by a
//! resolved Sepulchre connection (`backup_destination` role, all four
//! capabilities verified) instead of a local path. Registers itself as a
//! `connection_consumers` row so Sepulchre's own UI shows "used by
//! Reliquary."
//!
//! **Known limitation, documented rather than silently incomplete**: the
//! write path (`open_write`, used by `NativeProvider::create`) is fully
//! streaming and works end to end. `resolve()` returns a synthetic,
//! display-only path (there is no real local path for a remote
//! connection) -- this means Reliquary's `verify::quick_verify` (which
//! hashes `storage.resolve(file_name)` as a real file) and the
//! `download` route (which streams that same local path) do not yet work
//! against a Sepulchre-backed destination, nor does the disaster-
//! recovery CLI's restore path. A Sepulchre-backed connection can be
//! used as a **write-only scheduled backup destination** today; reading
//! a backup back from one (verify/download/restore) needs those three
//! call sites migrated to `open_read` first -- see `docs/sepulchre.md`
//! and `docs/reliquary-backups.md` for the follow-up this leaves for
//! whoever picks it up next.

use std::collections::HashSet;
use std::path::PathBuf;

use abyssal_core::{Capability, ConnectionRole};
use uuid::Uuid;

use crate::reliquary_backup::BackupError;
use crate::reliquary_backup::storage::StorageDestination;
use crate::sepulchre::SepulchreError;
use crate::sepulchre::backend::{RequiredUse, StorageBackend, StorageConnectionResolver};
use crate::state::AppState;

fn to_backup_error(e: SepulchreError) -> BackupError {
    BackupError::Other(anyhow::anyhow!(e.to_string()))
}

pub struct SepulchreDestination {
    backend: Box<dyn StorageBackend>,
    connection_id: Uuid,
    connection_name: String,
}

impl SepulchreDestination {
    /// The exact capability set a backup destination needs -- matches
    /// what `register_as_consumer` below records, so what's checked and
    /// what's declared to Sepulchre's own "used by" UI never drift apart.
    fn required_capabilities() -> HashSet<Capability> {
        [
            Capability::Read,
            Capability::List,
            Capability::Write,
            Capability::Delete,
        ]
        .into_iter()
        .collect()
    }

    /// Resolves `connection_id` as a usable `backup_destination` --
    /// enabled, holding that role, every capability above verified, and
    /// validated recently (see `StorageConnectionResolver::resolve`).
    /// Registers Reliquary as a consumer on success, so Sepulchre's own
    /// connection page reflects the dependency immediately, not only
    /// after a backup actually runs.
    pub async fn resolve(state: &AppState, connection_id: Uuid) -> Result<Self, SepulchreError> {
        let resolver = StorageConnectionResolver::new(state);
        let resolved = resolver
            .resolve(
                connection_id,
                RequiredUse {
                    role: ConnectionRole::BackupDestination,
                    capabilities: Self::required_capabilities(),
                },
            )
            .await
            .map_err(SepulchreError::NotUsable)?;

        abyssal_database::repo::connection_consumers::register(
            &state.pool,
            connection_id,
            "reliquary",
            "native_backup",
            "Native (control-plane) backup destination",
            ConnectionRole::BackupDestination,
            &Self::required_capabilities(),
        )
        .await
        .map_err(SepulchreError::Other)?;

        Ok(Self {
            backend: resolved.backend,
            connection_id,
            connection_name: resolved.connection.name,
        })
    }

    pub fn connection_name(&self) -> &str {
        &self.connection_name
    }
}

#[async_trait::async_trait]
impl StorageDestination for SepulchreDestination {
    fn resolve(&self, file_name: &str) -> PathBuf {
        // Synthetic and display-only -- see this module's doc comment.
        // Deliberately still namespaced by connection name/id so two
        // different Sepulchre-backed jobs never collide even in a
        // display string.
        PathBuf::from(format!(
            "sepulchre://{}/{}/{file_name}",
            self.connection_name, self.connection_id
        ))
    }

    async fn list(&self) -> Result<Vec<String>, BackupError> {
        let entries = self.backend.list("").await.map_err(to_backup_error)?;
        Ok(entries
            .into_iter()
            .filter(|e| !e.is_dir)
            .map(|e| e.name)
            .collect())
    }

    async fn delete(&self, file_name: &str) -> Result<(), BackupError> {
        self.backend
            .delete(file_name)
            .await
            .map_err(to_backup_error)
    }

    fn exists(&self, _file_name: &str) -> bool {
        // The trait's default (`resolve(..).is_file()`) would always be
        // false here, since `resolve` never returns a real path -- but
        // nothing in Reliquary's own code currently calls `exists` on
        // the write-only path this adapter actually supports, so a
        // conservative `false` (never silently claim readiness) is safer
        // than a blocking async `stat` call from a sync trait method.
        false
    }

    async fn open_write(
        &self,
        file_name: &str,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin>, BackupError> {
        self.backend.ensure_dir("").await.map_err(to_backup_error)?;
        self.backend
            .open_write(file_name)
            .await
            .map_err(to_backup_error)
    }

    async fn open_read(
        &self,
        file_name: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, BackupError> {
        self.backend
            .open_read(file_name)
            .await
            .map_err(to_backup_error)
    }
}
