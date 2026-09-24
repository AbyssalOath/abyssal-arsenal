//! Sepulchre: storage & file-sharing connectivity. A connection-and-share
//! *provisioning layer* other Arsenals consume (Reliquary first) rather
//! than each implementing their own SFTP/SMB configuration -- see
//! `docs/sepulchre.md`.
//!
//! - [`backend`] -- the [`backend::StorageBackend`] trait (one
//!   implementation per [`abyssal_core::Protocol`]: SFTP, SMB, local) and
//!   [`backend::StorageConnectionResolver`], the interface other Arsenals'
//!   own code (also living in this crate, per this codebase's "all logic
//!   lives in `crates/web`" convention) depends on instead of reaching
//!   into Sepulchre's internals directly.
//! - [`secrets`] -- encrypted-at-rest connection credentials, reusing
//!   `abyssal_core::crypto::EncryptionKey` (the same mechanism Panopticon
//!   and Reliquary already use), and control-plane SFTP keypair
//!   generation/import (never routed through Cryptkeeper's host-side
//!   keypair generation, which writes to a managed host's filesystem).
//! - [`validation`] -- the method-aware validation engine and its stable
//!   `error_kind` mapping.
//! - [`provisioning`] -- host-side SFTP/SMB drop-in rendering and mount
//!   unit generation, applied through the existing executor
//!   (`AgentOperation`), never a new remote-execution channel.

pub mod backend;
pub mod provisioning;
pub mod reliquary_adapter;
pub mod secrets;
pub mod validation;

#[derive(Debug, thiserror::Error)]
pub enum SepulchreError {
    #[error("{0}")]
    Config(String),
    #[error("connection unusable: {0:?}")]
    NotUsable(abyssal_core::NotUsableReason),
    #[error("{0}")]
    Backend(String),
    #[error("path not allowed: {0}")]
    PathNotAllowed(String),
    #[error("operation timed out")]
    Timeout,
    #[error("operation was cancelled")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("failed to serialize/deserialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<SepulchreError> for abyssal_core::ErrorKind {
    fn from(e: SepulchreError) -> Self {
        match e {
            SepulchreError::NotUsable(_) => abyssal_core::ErrorKind::Unknown,
            SepulchreError::PathNotAllowed(_) => abyssal_core::ErrorKind::PathNotAllowed,
            SepulchreError::Timeout => abyssal_core::ErrorKind::Timeout,
            _ => abyssal_core::ErrorKind::Unknown,
        }
    }
}
