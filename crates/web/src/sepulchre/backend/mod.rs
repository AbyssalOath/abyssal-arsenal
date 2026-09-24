//! The [`StorageBackend`] trait (one implementation per protocol) and
//! [`StorageConnectionResolver`] (the interface a consumer like Reliquary
//! actually calls) -- see `crates/web/src/sepulchre/mod.rs`.

pub mod local;
pub mod sftp;
pub mod smb;

use std::collections::HashSet;
use std::time::Duration;

use abyssal_core::{Capability, ConnectionRole, NotUsableReason, StorageConnection};
use tokio::io::{AsyncRead, AsyncWrite};

use super::SepulchreError;

#[derive(Debug, Clone)]
pub struct FileStat {
    pub size_bytes: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

/// A default, generous-but-bounded timeout applied by the resolver/
/// validation engine around every backend call -- see
/// `with_timeout` below. Individual backends may apply their own
/// tighter connect timeouts from `ProtocolConfig` on top of this.
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

/// One protocol's actual I/O implementation -- SFTP, SMB, or local.
/// Every method is streaming (never buffers a whole file in memory),
/// async, and expected to be cancel-safe in the ordinary Tokio sense
/// (dropping the future stops the operation; callers apply their own
/// timeout via [`with_timeout`] rather than each method managing its
/// own).
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    async fn stat(&self, path: &str) -> Result<FileStat, SepulchreError>;
    async fn list(&self, path: &str) -> Result<Vec<FileEntry>, SepulchreError>;
    async fn open_read(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>, SepulchreError>;
    async fn open_write(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin>, SepulchreError>;
    async fn delete(&self, path: &str) -> Result<(), SepulchreError>;
    /// Idempotent: creates `path` (and any missing parent components) if
    /// it doesn't already exist, and is not an error if it does.
    /// `open_write` never creates parent directories on its own -- this
    /// is the explicit way to ensure one exists first, used by
    /// validation's scratch subdirectory and by any future share/
    /// directory-management action.
    async fn ensure_dir(&self, path: &str) -> Result<(), SepulchreError>;
    /// Best-effort; `None` when the protocol/server doesn't expose it.
    async fn free_space(&self) -> Result<Option<u64>, SepulchreError>;

    /// What this backend/config combination can *possibly* do -- e.g. a
    /// read-only SMB share reports no `Write`/`Delete`. Bounds what an
    /// admin may *declare* on the connection; never itself a substitute
    /// for verified capabilities.
    fn possible_capabilities(&self) -> HashSet<Capability>;
}

/// Runs `fut` under [`DEFAULT_OPERATION_TIMEOUT`] (or `timeout` if given),
/// mapping an elapsed deadline to [`SepulchreError::Timeout`] -- the one
/// place every backend call funnels through so no caller can accidentally
/// hang forever on an unreachable server.
pub async fn with_timeout<T>(
    timeout: Option<Duration>,
    fut: impl std::future::Future<Output = Result<T, SepulchreError>>,
) -> Result<T, SepulchreError> {
    match tokio::time::timeout(timeout.unwrap_or(DEFAULT_OPERATION_TIMEOUT), fut).await {
        Ok(result) => result,
        Err(_) => Err(SepulchreError::Timeout),
    }
}

/// What a consumer (e.g. Reliquary) needs from a connection -- the
/// resolver's only real input beyond the connection ID itself.
pub struct RequiredUse {
    pub role: ConnectionRole,
    pub capabilities: HashSet<Capability>,
}

/// A connection that passed [`StorageConnectionResolver::resolve`] --
/// its ready-to-use backend plus enough of the underlying row for a
/// consumer to label what it's using.
pub struct ResolvedConnection {
    pub connection: StorageConnection,
    pub backend: Box<dyn StorageBackend>,
}

/// The one entry point a consumer Arsenal should ever call -- never a
/// direct `repo::storage_connections` query, and never constructing a
/// backend by hand. Enforces "enabled, has the role, every required
/// capability is *verified*, and the last validation is recent enough"
/// before handing back anything usable.
pub struct StorageConnectionResolver<'a> {
    pool: &'a crate::state::AppState,
}

impl<'a> StorageConnectionResolver<'a> {
    pub fn new(state: &'a crate::state::AppState) -> Self {
        Self { pool: state }
    }

    /// How stale a connection's last validation may be and still count
    /// as usable -- 24 hours. A connection validated less recently than
    /// this resolves to `ValidationStale` even if that last run passed,
    /// since an unvalidated-in-a-while remote server is exactly the kind
    /// of drift this exists to catch before a consumer (e.g. a scheduled
    /// backup) finds out the hard way.
    pub const STALENESS_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

    pub async fn resolve(
        &self,
        connection_id: uuid::Uuid,
        required: RequiredUse,
    ) -> Result<ResolvedConnection, NotUsableReason> {
        let pool = &self.pool.pool;
        let connection =
            abyssal_database::repo::storage_connections::find_by_id(pool, connection_id)
                .await
                .ok()
                .flatten()
                .ok_or(NotUsableReason::ValidationFailed)?;

        if !connection.enabled {
            return Err(NotUsableReason::Disabled);
        }

        let roles =
            abyssal_database::repo::storage_connections::roles_for_connection(pool, connection_id)
                .await
                .unwrap_or_default();
        if !roles.contains(&required.role) {
            return Err(NotUsableReason::MissingRole(required.role));
        }

        let capabilities =
            abyssal_database::repo::storage_connections::capabilities_for_connection(
                pool,
                connection_id,
            )
            .await
            .unwrap_or_default();
        for needed in &required.capabilities {
            let verified = capabilities
                .iter()
                .any(|c| c.capability == *needed && c.is_verified());
            if !verified {
                return Err(NotUsableReason::CapabilityUnverified(*needed));
            }
        }

        match connection.last_validation_status {
            Some(abyssal_core::ValidationStatus::Ok) => {}
            Some(_) => return Err(NotUsableReason::ValidationFailed),
            None => return Err(NotUsableReason::ValidationStale),
        }
        let Some(last_at) = connection.last_validation_at else {
            return Err(NotUsableReason::ValidationStale);
        };
        let age = chrono::Utc::now().signed_duration_since(last_at);
        if age > chrono::Duration::from_std(Self::STALENESS_WINDOW).unwrap_or_default() {
            return Err(NotUsableReason::ValidationStale);
        }

        let backend = build_backend(self.pool, &connection)
            .await
            .map_err(|_| NotUsableReason::ValidationFailed)?;

        Ok(ResolvedConnection {
            connection,
            backend,
        })
    }
}

/// Constructs the right [`StorageBackend`] for a connection's protocol,
/// decrypting its secret (if any) along the way. The one place backend
/// construction happens, so a consumer never needs to know which
/// protocol it's actually talking to.
pub async fn build_backend(
    state: &crate::state::AppState,
    connection: &StorageConnection,
) -> Result<Box<dyn StorageBackend>, SepulchreError> {
    match &connection.protocol_config {
        abyssal_core::ProtocolConfig::Local(config) => {
            let roots = local::local_roots_from_env();
            Ok(Box::new(local::LocalBackend::new(config.clone(), roots)?))
        }
        abyssal_core::ProtocolConfig::Sftp(config) => {
            let secret = super::secrets::decrypt_secret(state, connection.id).await?;
            Ok(Box::new(
                sftp::SftpBackend::new(config.clone(), secret).await?,
            ))
        }
        abyssal_core::ProtocolConfig::Smb(config) => {
            let secret = super::secrets::decrypt_secret(state, connection.id).await?;
            Ok(Box::new(
                smb::SmbBackend::new(config.clone(), secret).await?,
            ))
        }
    }
}
