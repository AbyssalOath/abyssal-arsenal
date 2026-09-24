//! The `sftp` storage protocol's native client -- `russh` (already a
//! workspace dependency, added this session for the SSH-deploy-agents
//! feature) plus `russh-sftp` layered on its channel transport, rather
//! than a second, unrelated SSH stack (`ssh2`/libssh2).
//!
//! Host key verification is mandatory and never optional: connecting
//! with no pinned fingerprint yet is refused outright (see
//! [`probe_host_key`] for the separate, explicit step that establishes
//! one), and a fingerprint mismatch on a later connect is a hard
//! [`SepulchreError::Backend`] carrying `host_key_mismatch`, never a
//! silent auto-accept.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use abyssal_core::{Capability, SftpAuthMethod, SftpConfig};
use russh::client;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use super::{FileEntry, FileStat, StorageBackend};
use crate::sepulchre::SepulchreError;

/// A host-key fingerprint mismatch, surfaced distinctly from every other
/// connection failure so the UI/workflow-registry `error_kind` mapping
/// can tell "wrong credentials" apart from "this might be an
/// impersonation attempt."
pub const HOST_KEY_MISMATCH_MARKER: &str = "host_key_mismatch";

struct HostKeyHandler {
    /// `None` means probing mode (see [`probe_host_key`]) -- accept
    /// whatever key is offered purely to observe and report its
    /// fingerprint, never used for a connection that will actually
    /// authenticate or move data.
    expected_fingerprint: Option<String>,
    observed_fingerprint: Arc<Mutex<Option<String>>>,
}

impl client::Handler for HostKeyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            // No CA-certificate support -- out of scope, refuse cleanly.
            return Ok(false);
        };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        if let Ok(mut observed) = self.observed_fingerprint.lock() {
            *observed = Some(fingerprint.clone());
        }
        match &self.expected_fingerprint {
            None => Ok(true),
            Some(expected) => Ok(constant_time_eq(
                expected.as_bytes(),
                fingerprint.as_bytes(),
            )),
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Connects far enough to read the server's host key fingerprint and
/// report it back, without authenticating or pinning anything -- the
/// explicit "show the admin the fingerprint before trusting it" step
/// the connection-creation wizard uses ahead of storing it into
/// `SftpConfig::pinned_host_key_fingerprint`.
pub async fn probe_host_key(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<String, SepulchreError> {
    let observed = Arc::new(Mutex::new(None));
    let handler = HostKeyHandler {
        expected_fingerprint: None,
        observed_fingerprint: observed.clone(),
    };
    let config = Arc::new(client::Config::default());
    let connect = client::connect(config, (host, port), handler);
    match tokio::time::timeout(timeout, connect).await {
        Err(_) => Err(SepulchreError::Timeout),
        Ok(Err(e)) => Err(SepulchreError::Backend(format!("connection failed: {e}"))),
        Ok(Ok(_handle)) => {
            observed.lock().ok().and_then(|g| g.clone()).ok_or_else(|| {
                SepulchreError::Backend("server never offered a host key".to_string())
            })
        }
    }
}

/// `trim_end_matches('/')` on a bare `"/"` (the common case for a chroot
/// account, where the whole chroot *is* the base path) collapses it to
/// `""` -- an empty remote path an SFTP server resolves as "no path
/// given" rather than "the root," breaking every operation against the
/// connection's own base directory. Caught live against a real SFTP
/// chroot account: `list("")` failed with a bare "No such file" despite
/// the directory plainly existing. Kept as `"/"` instead of trimmed to
/// empty.
fn normalize_base_path(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

pub struct SftpBackend {
    session: SftpSession,
    base_path: String,
}

impl SftpBackend {
    pub async fn new(
        config: SftpConfig,
        secret: Zeroizing<String>,
    ) -> Result<Self, SepulchreError> {
        let expected_fingerprint = config.pinned_host_key_fingerprint.clone().ok_or_else(|| {
            SepulchreError::Config(
                "no pinned host key fingerprint -- validate this connection first".to_string(),
            )
        })?;
        let observed = Arc::new(Mutex::new(None));
        let handler = HostKeyHandler {
            expected_fingerprint: Some(expected_fingerprint.clone()),
            observed_fingerprint: observed.clone(),
        };
        let russh_config = Arc::new(client::Config::default());
        let connect_timeout = Duration::from_secs(u64::from(config.connect_timeout_secs.max(1)));
        let connect = client::connect(russh_config, (config.host.as_str(), config.port), handler);
        let mut handle = match tokio::time::timeout(connect_timeout, connect).await {
            Err(_) => return Err(SepulchreError::Timeout),
            Ok(Err(e)) => {
                let observed_fp = observed.lock().ok().and_then(|g| g.clone());
                if observed_fp
                    .as_deref()
                    .is_some_and(|fp| fp != expected_fingerprint)
                {
                    return Err(SepulchreError::Backend(format!(
                        "{HOST_KEY_MISMATCH_MARKER}: server presented a different host key than pinned"
                    )));
                }
                return Err(SepulchreError::Backend(format!("connection failed: {e}")));
            }
            Ok(Ok(handle)) => handle,
        };

        let auth_result = match config.auth_method {
            SftpAuthMethod::Password => handle
                .authenticate_password(&config.username, secret.as_str())
                .await
                .map_err(|e| SepulchreError::Backend(format!("authentication error: {e}")))?,
            SftpAuthMethod::SshKey => {
                let private_key = PrivateKey::from_openssh(secret.as_str()).map_err(|e| {
                    SepulchreError::Config(format!("stored SFTP key is invalid: {e}"))
                })?;
                let keypair = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
                handle
                    .authenticate_publickey(&config.username, keypair)
                    .await
                    .map_err(|e| SepulchreError::Backend(format!("authentication error: {e}")))?
            }
        };
        if !auth_result.success() {
            return Err(SepulchreError::Backend("auth_failed".to_string()));
        }

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| SepulchreError::Backend(format!("channel open failed: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| SepulchreError::Backend(format!("sftp subsystem request failed: {e}")))?;
        let stream = channel.into_stream();
        let session = SftpSession::new(stream)
            .await
            .map_err(|e| SepulchreError::Backend(format!("sftp session init failed: {e}")))?;

        Ok(Self {
            session,
            base_path: normalize_base_path(&config.base_path),
        })
    }

    fn resolve(&self, path: &str) -> String {
        if path.is_empty() {
            self.base_path.clone()
        } else if self.base_path == "/" {
            format!("/{}", path.trim_start_matches('/'))
        } else {
            format!("{}/{}", self.base_path, path.trim_start_matches('/'))
        }
    }
}

#[async_trait::async_trait]
impl StorageBackend for SftpBackend {
    async fn stat(&self, path: &str) -> Result<FileStat, SepulchreError> {
        let meta = self
            .session
            .metadata(self.resolve(path))
            .await
            .map_err(|e| SepulchreError::Backend(e.to_string()))?;
        Ok(FileStat {
            size_bytes: meta.size.unwrap_or(0),
            is_dir: meta.is_dir(),
        })
    }

    async fn list(&self, path: &str) -> Result<Vec<FileEntry>, SepulchreError> {
        let entries = self
            .session
            .read_dir(self.resolve(path))
            .await
            .map_err(|e| SepulchreError::Backend(e.to_string()))?;
        Ok(entries
            .map(|entry| FileEntry {
                name: entry.file_name(),
                is_dir: entry.file_type().is_dir(),
                size_bytes: entry.metadata().size.unwrap_or(0),
            })
            .collect())
    }

    async fn open_read(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>, SepulchreError> {
        let file = self
            .session
            .open(self.resolve(path))
            .await
            .map_err(|e| SepulchreError::Backend(e.to_string()))?;
        Ok(Box::new(file))
    }

    async fn open_write(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin>, SepulchreError> {
        let file = self
            .session
            .open_with_flags(
                self.resolve(path),
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(|e| SepulchreError::Backend(e.to_string()))?;
        Ok(Box::new(file))
    }

    async fn delete(&self, path: &str) -> Result<(), SepulchreError> {
        self.session
            .remove_file(self.resolve(path))
            .await
            .map_err(|e| SepulchreError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn ensure_dir(&self, path: &str) -> Result<(), SepulchreError> {
        // SFTP's `create_dir` has no `create_dir_all`/idempotent
        // counterpart -- create each path component in turn, tolerating
        // "already exists" at every level (checked via `try_exists`
        // rather than trusting the error message, since SFTP servers
        // don't agree on one for this).
        let mut current = self.base_path.clone();
        for component in path.split('/').filter(|c| !c.is_empty()) {
            current = format!("{current}/{component}");
            if self.session.try_exists(&current).await.unwrap_or(false) {
                continue;
            }
            if let Err(e) = self.session.create_dir(&current).await {
                // A concurrent creator or a race with `try_exists` above
                // is the only expected failure mode here; anything else
                // (permission denied, etc.) should surface once the
                // actual write is attempted right after this.
                if !self.session.try_exists(&current).await.unwrap_or(false) {
                    return Err(SepulchreError::Backend(format!(
                        "could not create directory {current}: {e}"
                    )));
                }
            }
        }
        Ok(())
    }

    async fn free_space(&self) -> Result<Option<u64>, SepulchreError> {
        match self.session.fs_info(self.resolve("")).await {
            Ok(Some(stat)) => Ok(Some(stat.blocks_avail.saturating_mul(stat.fragment_size))),
            Ok(None) | Err(_) => Ok(None),
        }
    }

    fn possible_capabilities(&self) -> HashSet<Capability> {
        Capability::ALL.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_bytes() {
        assert!(constant_time_eq(b"SHA256:abc", b"SHA256:abc"));
    }

    #[test]
    fn constant_time_eq_rejects_different_bytes() {
        assert!(!constant_time_eq(b"SHA256:abc", b"SHA256:xyz"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer-value"));
    }

    #[test]
    fn normalize_base_path_keeps_a_bare_root_as_root() {
        assert_eq!(normalize_base_path("/"), "/");
    }

    #[test]
    fn normalize_base_path_trims_a_trailing_slash() {
        assert_eq!(normalize_base_path("/upload/"), "/upload");
    }

    #[test]
    fn normalize_base_path_leaves_a_path_without_a_trailing_slash_alone() {
        assert_eq!(normalize_base_path("/upload"), "/upload");
    }
}
