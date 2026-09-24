//! The `local` storage protocol -- a control-plane-local directory,
//! restricted to an admin-configured allowlist of roots
//! (`SEPULCHRE_LOCAL_ROOTS`). Path containment is enforced with
//! [`cap_std`] (Bytecode Alliance) rather than hand-rolled canonicalize-
//! then-string-prefix logic: every operation is resolved *relative to an
//! already-open, capability-scoped directory handle* via `openat`-style
//! syscalls, so a symlink swapped in between validation and use (TOCTOU)
//! can never redirect an operation outside the root -- the containment
//! check isn't a one-time string comparison, it's structurally
//! impossible to escape.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use abyssal_core::{Capability, LocalConfig};
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{FileEntry, FileStat, StorageBackend};
use crate::sepulchre::SepulchreError;

/// Reads `SEPULCHRE_LOCAL_ROOTS` (comma-separated absolute paths).
/// Anything resolving to (or containing as a parent of) a
/// catastrophically dangerous path is dropped with a loud warning rather
/// than trusted -- misconfiguring this env var must never be able to
/// turn a `local` connection into `/`, `/etc`, or the Docker socket
/// path.
pub fn local_roots_from_env() -> Vec<PathBuf> {
    const FORBIDDEN: &[&str] = &[
        "/",
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "/var/run",
        "/run",
        "/var/run/docker.sock",
    ];
    // Unset means "just the Reliquary backups volume, if any" -- never a
    // hard-coded `/backups` guess independent of what Reliquary itself
    // is actually configured with (`RELIQUARY_BACKUP_DESTINATION_PATH`,
    // GitHub issue #9). An admin who wants more (or none at all) sets
    // `SEPULCHRE_LOCAL_ROOTS` explicitly, which fully replaces this
    // default rather than adding to it.
    let raw = std::env::var("SEPULCHRE_LOCAL_ROOTS").unwrap_or_else(|_| {
        std::env::var("RELIQUARY_BACKUP_DESTINATION_PATH")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_default()
    });
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let path = PathBuf::from(s);
            if !path.is_absolute() {
                tracing::warn!(root = %s, "SEPULCHRE_LOCAL_ROOTS: ignoring non-absolute entry");
                return None;
            }
            if FORBIDDEN.iter().any(|f| path == Path::new(f)) {
                tracing::warn!(root = %s, "SEPULCHRE_LOCAL_ROOTS: refusing a forbidden root");
                return None;
            }
            Some(path)
        })
        .collect()
}

/// Finds which allowed root (if any) contains `path`, and the path
/// relative to it -- a cheap string-prefix pre-check only, *not* the
/// security boundary itself (that's `Dir::open_dir` below, which
/// re-resolves the relative path safely through the opened root).
fn containing_root<'a>(path: &Path, roots: &'a [PathBuf]) -> Option<(&'a PathBuf, PathBuf)> {
    for root in roots {
        if let Ok(relative) = path.strip_prefix(root) {
            return Some((root, relative.to_path_buf()));
        }
    }
    None
}

pub struct LocalBackend {
    dir: Dir,
    /// Kept for `free_space`/same-filesystem diagnostics, which need a
    /// real path (`df`, `stat`), not just a capability handle.
    resolved_path: PathBuf,
}

impl LocalBackend {
    pub fn new(config: LocalConfig, roots: Vec<PathBuf>) -> Result<Self, SepulchreError> {
        let path = PathBuf::from(&config.path);
        if !path.is_absolute() {
            return Err(SepulchreError::PathNotAllowed(config.path.clone()));
        }
        let Some((root, relative)) = containing_root(&path, &roots) else {
            return Err(SepulchreError::PathNotAllowed(format!(
                "{} is not inside any SEPULCHRE_LOCAL_ROOTS entry",
                config.path
            )));
        };
        // Reject `..`/empty components defensively even though
        // `strip_prefix` above already guarantees `relative` has no
        // leading `..` -- a component-level check is cheap and this is
        // exactly the kind of boundary worth double-guarding.
        if relative
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(SepulchreError::PathNotAllowed(config.path.clone()));
        }

        let root_dir = Dir::open_ambient_dir(root, ambient_authority()).map_err(|e| {
            SepulchreError::Config(format!(
                "cannot open configured root {}: {e}",
                root.display()
            ))
        })?;

        if !relative.as_os_str().is_empty() {
            if config.create_if_missing {
                root_dir.create_dir_all(&relative)?;
            }
            #[cfg(unix)]
            {
                use cap_std::fs::PermissionsExt;
                let mode = config.expected_mode.unwrap_or(0o700);
                if let Ok(meta) = root_dir.metadata(&relative) {
                    let mut perms = meta.permissions();
                    perms.set_mode(mode);
                    let _ = root_dir.set_permissions(&relative, perms);
                }
            }
        }

        let dir = if relative.as_os_str().is_empty() {
            root_dir
        } else {
            root_dir
                .open_dir(&relative)
                .map_err(|e| SepulchreError::PathNotAllowed(format!("{}: {e}", config.path)))?
        };

        Ok(Self {
            dir,
            resolved_path: path,
        })
    }
}

fn reject_traversal(path: &str) -> Result<&str, SepulchreError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.split('/').any(|c| c == ".." || c.is_empty())
        || path.chars().any(|c| c.is_control())
    {
        return Err(SepulchreError::PathNotAllowed(path.to_string()));
    }
    Ok(path)
}

#[async_trait::async_trait]
impl StorageBackend for LocalBackend {
    async fn stat(&self, path: &str) -> Result<FileStat, SepulchreError> {
        // An empty path means "the connection's own base directory" --
        // the same special case `list` below already handles, needed
        // here too since the validation engine's read-permission check
        // stats the base path itself before doing anything else.
        if path.is_empty() {
            let dir = self.dir.try_clone()?;
            return tokio::task::spawn_blocking(move || {
                let meta = dir.dir_metadata()?;
                Ok(FileStat {
                    size_bytes: meta.len(),
                    is_dir: meta.is_dir(),
                })
            })
            .await
            .map_err(|e| SepulchreError::Backend(format!("blocking task panicked: {e}")))?;
        }
        let path = reject_traversal(path)?.to_string();
        let dir = self.dir.try_clone()?;
        tokio::task::spawn_blocking(move || {
            let meta = dir.metadata(&path)?;
            Ok(FileStat {
                size_bytes: meta.len(),
                is_dir: meta.is_dir(),
            })
        })
        .await
        .map_err(|e| SepulchreError::Backend(format!("blocking task panicked: {e}")))?
    }

    async fn list(&self, path: &str) -> Result<Vec<FileEntry>, SepulchreError> {
        let path = if path.is_empty() {
            String::new()
        } else {
            reject_traversal(path)?.to_string()
        };
        let dir = self.dir.try_clone()?;
        tokio::task::spawn_blocking(move || {
            let read_dir = if path.is_empty() {
                dir.entries()?
            } else {
                dir.read_dir(&path)?
            };
            let mut entries = Vec::new();
            for entry in read_dir {
                let entry = entry?;
                let meta = entry.metadata()?;
                entries.push(FileEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    is_dir: meta.is_dir(),
                    size_bytes: meta.len(),
                });
            }
            Ok(entries)
        })
        .await
        .map_err(|e| SepulchreError::Backend(format!("blocking task panicked: {e}")))?
    }

    async fn open_read(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>, SepulchreError> {
        let path = reject_traversal(path)?.to_string();
        let dir = self.dir.try_clone()?;
        let file = tokio::task::spawn_blocking(move || dir.open(&path))
            .await
            .map_err(|e| SepulchreError::Backend(format!("blocking task panicked: {e}")))??;
        let std_file = file.into_std();
        Ok(Box::new(tokio::fs::File::from_std(std_file)))
    }

    async fn open_write(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin>, SepulchreError> {
        let path = reject_traversal(path)?.to_string();
        let dir = self.dir.try_clone()?;
        let file = tokio::task::spawn_blocking(move || {
            let file = dir.create(&path)?;
            #[cfg(unix)]
            {
                use cap_std::fs::PermissionsExt;
                let mut perms = file.metadata()?.permissions();
                perms.set_mode(0o600);
                file.set_permissions(perms)?;
            }
            Ok::<_, std::io::Error>(file)
        })
        .await
        .map_err(|e| SepulchreError::Backend(format!("blocking task panicked: {e}")))??;
        let std_file = file.into_std();
        Ok(Box::new(tokio::fs::File::from_std(std_file)))
    }

    async fn delete(&self, path: &str) -> Result<(), SepulchreError> {
        let path = reject_traversal(path)?.to_string();
        let dir = self.dir.try_clone()?;
        tokio::task::spawn_blocking(move || dir.remove_file(&path))
            .await
            .map_err(|e| SepulchreError::Backend(format!("blocking task panicked: {e}")))??;
        Ok(())
    }

    async fn ensure_dir(&self, path: &str) -> Result<(), SepulchreError> {
        // An empty path means "the connection's own base directory" --
        // the same special case `stat`/`list` already handle. It always
        // already exists by construction (`LocalBackend::new` creates it
        // if missing), so this is a no-op rather than routing through
        // `reject_traversal`, which rejects an empty string outright.
        // Caught live: every write through the `SepulchreDestination`
        // Reliquary adapter calls `ensure_dir("")` first, which failed
        // with `path_not_allowed` on every single attempt before this.
        if path.is_empty() {
            return Ok(());
        }
        let path = reject_traversal(path)?.to_string();
        let dir = self.dir.try_clone()?;
        tokio::task::spawn_blocking(move || dir.create_dir_all(&path))
            .await
            .map_err(|e| SepulchreError::Backend(format!("blocking task panicked: {e}")))??;
        Ok(())
    }

    async fn free_space(&self) -> Result<Option<u64>, SepulchreError> {
        // `df` (arg list, never a shell string) -- the same subprocess-
        // for-an-OS-query pattern this codebase already uses for
        // `mariadb-dump`/`nmap` rather than a new statvfs-binding crate
        // for one best-effort field.
        let path = self.resolved_path.clone();
        let output = tokio::process::Command::new("df")
            .arg("-B1")
            .arg("--output=avail")
            .arg(&path)
            .output()
            .await;
        let Ok(output) = output else {
            return Ok(None);
        };
        if !output.status.success() {
            return Ok(None);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let avail = stdout
            .lines()
            .nth(1)
            .and_then(|l| l.trim().parse::<u64>().ok());
        Ok(avail)
    }

    fn possible_capabilities(&self) -> HashSet<Capability> {
        Capability::ALL.iter().copied().collect()
    }
}

/// Whether `path` sits on a network filesystem -- parsed from
/// `/proc/self/mountinfo`, matched against the longest mount-point
/// prefix (the standard way to find "which mount actually owns this
/// path" without a `statfs`-family binding). Returns the filesystem
/// type name when it's a recognized network filesystem, `None`
/// otherwise (including "couldn't determine" -- best-effort, never a
/// hard error).
pub fn network_filesystem_type(path: &Path) -> Option<String> {
    const NETWORK_FS_TYPES: &[&str] = &["nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "9p"];
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let path = path.to_string_lossy();
    let mut best: Option<(usize, String)> = None;
    for line in mountinfo.lines() {
        // Format: ... <mount point> ... - <fs type> <source> <options>
        let Some((_, after_dash)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<&str> = line.split_whitespace().collect();
        let mount_point = fields.get(4)?;
        if !path.starts_with(mount_point) {
            continue;
        }
        let fs_type = after_dash.split_whitespace().next()?.to_string();
        let len = mount_point.len();
        if best.as_ref().is_none_or(|(best_len, _)| len > *best_len) {
            best = Some((len, fs_type));
        }
    }
    let (_, fs_type) = best?;
    NETWORK_FS_TYPES
        .iter()
        .any(|t| fs_type.eq_ignore_ascii_case(t))
        .then_some(fs_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sepulchre-local-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config(path: &Path, create_if_missing: bool) -> LocalConfig {
        LocalConfig {
            path: path.to_string_lossy().into_owned(),
            create_if_missing,
            expected_mode: None,
        }
    }

    #[test]
    fn refuses_a_path_outside_every_allowed_root() {
        let root = tmp_root();
        let outside = std::env::temp_dir().join("definitely-not-under-root");
        let result = LocalBackend::new(config(&outside, false), vec![root.clone()]);
        assert!(result.is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn accepts_a_path_inside_an_allowed_root() {
        let root = tmp_root();
        let sub = root.join("conn-a");
        let result = LocalBackend::new(config(&sub, true), vec![root.clone()]);
        assert!(result.is_ok());
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn write_read_delete_round_trip() {
        let root = tmp_root();
        let sub = root.join("conn-b");
        let backend = LocalBackend::new(config(&sub, true), vec![root.clone()]).unwrap();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut writer = backend.open_write("hello.txt").await.unwrap();
        writer.write_all(b"hello sepulchre").await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let stat = backend.stat("hello.txt").await.unwrap();
        assert_eq!(stat.size_bytes, 15);

        let mut reader = backend.open_read("hello.txt").await.unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello sepulchre");

        let entries = backend.list("").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");

        backend.delete("hello.txt").await.unwrap();
        assert!(backend.stat("hello.txt").await.is_err());

        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn rejects_traversal_in_a_requested_file_name() {
        let root = tmp_root();
        let sub = root.join("conn-c");
        let backend = LocalBackend::new(config(&sub, true), vec![root.clone()]).unwrap();
        assert!(backend.open_write("../escape.txt").await.is_err());
        assert!(backend.open_write("/etc/passwd").await.is_err());
        assert!(backend.stat("a/../../b").await.is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    /// Regression test: `stat("")` means "the connection's own base
    /// directory" (same as `list("")`), used by the validation engine's
    /// read-permission check -- caught live against a real Sepulchre
    /// connection before this test existed, since every other `stat`
    /// call in the original test suite used a real filename.
    #[tokio::test]
    async fn stat_of_empty_path_returns_the_base_directory_itself() {
        let root = tmp_root();
        let sub = root.join("conn-d");
        let backend = LocalBackend::new(config(&sub, true), vec![root.clone()]).unwrap();
        let stat = backend.stat("").await.unwrap();
        assert!(stat.is_dir);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Regression test: caught live via a real Reliquary backup written
    /// to a `local`-protocol Sepulchre connection -- `SepulchreDestination::open_write`
    /// always calls `ensure_dir("")` first (the shared, protocol-agnostic
    /// "make sure the target directory exists" step), which failed with
    /// `path_not_allowed` on every single attempt before this, since
    /// `ensure_dir` routed an empty path through `reject_traversal`
    /// instead of treating it as "the base directory, which already
    /// exists by construction" the way `stat`/`list` already do.
    #[tokio::test]
    async fn ensure_dir_of_empty_path_is_a_no_op() {
        let root = tmp_root();
        let sub = root.join("conn-e");
        let backend = LocalBackend::new(config(&sub, true), vec![root.clone()]).unwrap();
        backend.ensure_dir("").await.unwrap();
        std::fs::remove_dir_all(&root).ok();
    }

    /// `cargo test` runs tests in the same process concurrently by
    /// default, but `SEPULCHRE_LOCAL_ROOTS`/`RELIQUARY_BACKUP_DESTINATION_PATH`
    /// are process-wide state -- every test below that reads or writes
    /// either one takes this lock first so they can't interleave and
    /// observe each other's env var changes mid-test.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn local_roots_from_env_drops_forbidden_and_relative_entries() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: test-only, serialized by ENV_TEST_LOCK above.
        unsafe {
            std::env::set_var("SEPULCHRE_LOCAL_ROOTS", "/,/etc,relative/path,/backups");
        }
        let roots = local_roots_from_env();
        assert_eq!(roots, vec![PathBuf::from("/backups")]);
        unsafe {
            std::env::remove_var("SEPULCHRE_LOCAL_ROOTS");
        }
    }

    #[test]
    fn falls_back_to_the_reliquary_backup_path_when_unset() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: test-only, serialized by ENV_TEST_LOCK above.
        unsafe {
            std::env::remove_var("SEPULCHRE_LOCAL_ROOTS");
            std::env::set_var("RELIQUARY_BACKUP_DESTINATION_PATH", "/backups");
        }
        let roots = local_roots_from_env();
        assert_eq!(roots, vec![PathBuf::from("/backups")]);
        unsafe {
            std::env::remove_var("RELIQUARY_BACKUP_DESTINATION_PATH");
        }
    }

    #[test]
    fn empty_allowlist_when_neither_variable_is_set() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: test-only, serialized by ENV_TEST_LOCK above.
        unsafe {
            std::env::remove_var("SEPULCHRE_LOCAL_ROOTS");
            std::env::remove_var("RELIQUARY_BACKUP_DESTINATION_PATH");
        }
        assert!(local_roots_from_env().is_empty());
    }
}
