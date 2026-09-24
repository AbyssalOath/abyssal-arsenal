//! The `smb` storage protocol -- shells out to `smbclient` (arg list,
//! never a shell string; credentials via a `0600` authentication file,
//! never argv/env) rather than binding `libsmbclient` via FFI
//! (`pavao`/similar). Trade-off, documented rather than silently
//! accepted: `smbclient`'s CLI has no byte-stream `get`/`put` (it only
//! moves whole files to/from a local path), so `open_read`/`open_write`
//! here stage through a private, `0600` temp file rather than truly
//! never touching disk -- the memory-blowup risk the "streaming only"
//! requirement cares most about is still avoided (nothing is ever held
//! in the process's own heap), but this is disk-buffered, not a true
//! zero-copy stream the way the SFTP/local backends are. A future
//! iteration could adopt `pavao` (vendored libsmbclient, no system
//! package needed) for genuine streaming if this becomes a real problem
//! -- see `docs/sepulchre.md`.

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};

use abyssal_core::{Capability, SmbConfig, SmbEncryption};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::{FileEntry, FileStat, StorageBackend};
use crate::sepulchre::SepulchreError;

/// Opens `path` for writing with mode `0600` set atomically at creation
/// (never a separate `set_permissions` call after the fact, which would
/// leave a window where the file exists with the process's default,
/// often world-readable, umask) and `create_new` so a pre-planted file
/// or symlink at a guessed path in the shared temp directory is refused
/// rather than silently written through.
async fn create_private_file(path: &std::path::Path) -> Result<tokio::fs::File, SepulchreError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    Ok(options.open(path).await?)
}

/// A `0600` temp file holding `smbclient -A`'s credentials, removed on
/// drop -- the same "write a scoped credentials file, never pass a
/// secret as an argument" pattern `reliquary_backup::dump`'s
/// `DefaultsExtraFile` already established for `mariadb-dump`.
struct CredentialsFile {
    path: PathBuf,
}

impl CredentialsFile {
    async fn write(
        username: &str,
        secret: &str,
        domain: Option<&str>,
    ) -> Result<Self, SepulchreError> {
        let path = std::env::temp_dir().join(format!("sepulchre-smb-{}.cnf", uuid::Uuid::new_v4()));
        let mut contents = format!("username={username}\npassword={secret}\n");
        if let Some(domain) = domain {
            contents.push_str(&format!("domain={domain}\n"));
        }
        let mut file = create_private_file(&path).await?;
        file.write_all(contents.as_bytes()).await?;
        file.flush().await?;
        Ok(Self { path })
    }
}

impl Drop for CredentialsFile {
    fn drop(&mut self) {
        let path = self.path.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(&path).await;
        });
    }
}

pub struct SmbBackend {
    host: String,
    port: u16,
    share: String,
    subpath: String,
    min_protocol_option: &'static str,
    protection_flag: Option<&'static str>,
    credentials: std::sync::Arc<CredentialsFile>,
}

impl SmbBackend {
    /// Constructing this doesn't itself connect -- `smbclient` is a
    /// fresh subprocess per call, same as `reliquary_backup::dump`'s
    /// `mariadb-dump` invocations. Async because writing the
    /// credentials file is.
    pub async fn new(config: SmbConfig, secret: Zeroizing<String>) -> Result<Self, SepulchreError> {
        // Defense in depth: `subpath` and `share_name` end up interpolated
        // into `smbclient`'s own `-c "..."` command-language string
        // (see `resolve`'s doc comment), so they're validated here too,
        // not just at connection-creation time in the web route.
        reject_unsafe_smb_component(&config.subpath)?;
        reject_unsafe_smb_component(&config.share_name)?;
        let credentials =
            CredentialsFile::write(&config.username, secret.as_str(), config.domain.as_deref())
                .await?;
        let protection_flag = match config.encryption {
            SmbEncryption::Off => None,
            SmbEncryption::IfSupported => Some("sign"),
            SmbEncryption::Required => Some("encrypt"),
        };
        Ok(Self {
            host: config.host.clone(),
            port: config.port,
            share: config.share_name.clone(),
            subpath: config.subpath.trim_matches('/').to_string(),
            min_protocol_option: "client min protocol=SMB3",
            protection_flag,
            credentials: std::sync::Arc::new(credentials),
        })
    }

    fn base_command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new("smbclient");
        cmd.arg(format!("//{}/{}", self.host, self.share))
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-A")
            .arg(&self.credentials.path)
            .arg("-m")
            .arg("SMB3")
            .arg("--option")
            .arg(self.min_protocol_option)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(protection) = self.protection_flag {
            cmd.arg("--client-protection").arg(protection);
        }
        cmd
    }

    /// Builds the remote path used inside an `smbclient -c "..."`
    /// command string. `path` is validated first: `smbclient`'s scripting
    /// language treats `;` as a command separator and a leading `!` as
    /// "run this as a local shell command" *within that one argument*,
    /// independent of the OS shell (this process never invokes one --
    /// `tokio::process::Command` passes `-c`'s value as a single argv
    /// entry) -- so an attacker-influenced path containing either could
    /// still inject additional `smbclient` commands. Rejected outright
    /// rather than escaped, since `smbclient`'s own quoting rules for its
    /// command language aren't documented precisely enough to trust an
    /// escaping scheme.
    fn resolve(&self, path: &str) -> Result<String, SepulchreError> {
        reject_unsafe_smb_component(path)?;
        let joined = if self.subpath.is_empty() {
            path.trim_matches('/').to_string()
        } else {
            format!("{}/{}", self.subpath, path.trim_matches('/'))
        };
        Ok(joined.replace('/', "\\"))
    }

    async fn run_command(&self, smb_command: &str) -> Result<String, SepulchreError> {
        let mut cmd = self.base_command();
        cmd.arg("-c").arg(smb_command);
        let output = cmd
            .output()
            .await
            .map_err(|e| SepulchreError::Backend(format!("failed to run smbclient: {e}")))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SepulchreError::Backend(format!(
                "smbclient exited with {}: {}{}",
                output.status, stdout, stderr
            )));
        }
        Ok(stdout)
    }
}

/// Rejects a path component that could break out of `smbclient`'s own
/// `-c "..."` command-language string -- see [`SmbBackend::resolve`].
/// `pub(crate)` so the connection-creation route can reject an unsafe
/// `share_name`/`subpath` up front, rather than only discovering it the
/// first time the backend is actually used.
pub(crate) fn reject_unsafe_smb_component(value: &str) -> Result<(), SepulchreError> {
    if value.starts_with('!') {
        return Err(SepulchreError::PathNotAllowed(
            "path may not start with '!'".to_string(),
        ));
    }
    if value.contains(['"', ';', '\n', '\r', '\\']) {
        return Err(SepulchreError::PathNotAllowed(
            "path contains a character that isn't allowed in an SMB path".to_string(),
        ));
    }
    Ok(())
}

/// Parses one `smbclient` `ls` line, e.g.
/// `  report.txt                          N     1234  Mon Jan  1 00:00:00 2024`
/// The attribute column (`N`/`D`/`A`/`H`/...) is whichever combination
/// of letters `smbclient` prints; `D` marks a directory, anything else a
/// regular-enough file for this purpose.
fn parse_ls_line(line: &str) -> Option<FileEntry> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('.') {
        return None; // skips blank lines and the "." / ".." entries
    }
    // The attributes column is the last run of A-Z letters before the
    // size column; split from the right, since filenames may contain
    // spaces.
    let mut fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 3 {
        return None;
    }
    // Reconstruct: [name...] attrs size day month date time year
    // -- take the last 6 tokens as the fixed-shape suffix.
    if fields.len() < 6 {
        return None;
    }
    let year_etc = fields.split_off(fields.len() - 6);
    if fields.is_empty() {
        return None;
    }
    let attrs = fields.pop()?;
    let name = fields.join(" ");
    let size: u64 = year_etc.first()?.parse().unwrap_or(0);
    if name.is_empty() {
        return None;
    }
    Some(FileEntry {
        name,
        is_dir: attrs.contains('D'),
        size_bytes: size,
    })
}

#[async_trait::async_trait]
impl StorageBackend for SmbBackend {
    async fn stat(&self, path: &str) -> Result<FileStat, SepulchreError> {
        let remote = self.resolve(path)?;
        // `stat("")` means "the connection's own base directory" (same
        // convention as the Local/SFTP backends), which has no listing
        // entry of its own to match against below -- `smbclient` has no
        // "stat a bare directory" scripting command, so a successful
        // listing of it stands in as proof it exists and is readable,
        // the same operational definition `list()` already uses.
        // Regression test: caught live against a real Samba server,
        // where every SMB connection's read-permission validation check
        // failed with `not_found` before this special case existed.
        if remote.is_empty() {
            self.list(path).await?;
            return Ok(FileStat {
                size_bytes: 0,
                is_dir: true,
            });
        }
        let (parent, name) = match remote.rsplit_once('\\') {
            Some((p, n)) => (p.to_string(), n.to_string()),
            None => (String::new(), remote.clone()),
        };
        let list_target = if parent.is_empty() {
            "*".to_string()
        } else {
            format!("{parent}\\*")
        };
        let output = self.run_command(&format!("ls {list_target}")).await?;
        for line in output.lines() {
            if let Some(entry) = parse_ls_line(line)
                && entry.name == name
            {
                return Ok(FileStat {
                    size_bytes: entry.size_bytes,
                    is_dir: entry.is_dir,
                });
            }
        }
        Err(SepulchreError::Backend(format!("not_found: {path}")))
    }

    async fn list(&self, path: &str) -> Result<Vec<FileEntry>, SepulchreError> {
        let remote = self.resolve(path)?;
        let target = if remote.is_empty() {
            "*".to_string()
        } else {
            format!("{remote}\\*")
        };
        let output = self.run_command(&format!("ls {target}")).await?;
        Ok(output.lines().filter_map(parse_ls_line).collect())
    }

    async fn open_read(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>, SepulchreError> {
        let remote = self.resolve(path)?;
        let temp_path =
            std::env::temp_dir().join(format!("sepulchre-smb-get-{}", uuid::Uuid::new_v4()));
        // Pre-create the destination with `0600` and `create_new` before
        // handing it to `smbclient get`: since the file already exists,
        // `get`'s own `open(..., O_CREAT | O_TRUNC)` truncates it in
        // place rather than creating a fresh, umask-permissioned one, so
        // the permissions set here are what the downloaded payload
        // actually ends up with.
        drop(create_private_file(&temp_path).await?);
        self.run_command(&format!("get \"{remote}\" \"{}\"", temp_path.display()))
            .await?;
        let file = tokio::fs::File::open(&temp_path).await?;
        Ok(Box::new(CleanupOnDropReader {
            file,
            temp_path: Some(temp_path),
        }))
    }

    async fn open_write(
        &self,
        path: &str,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin>, SepulchreError> {
        let remote = self.resolve(path)?;
        let temp_path =
            std::env::temp_dir().join(format!("sepulchre-smb-put-{}", uuid::Uuid::new_v4()));
        let file = create_private_file(&temp_path).await?;
        Ok(Box::new(UploadOnShutdownWriter {
            file,
            temp_path,
            remote,
            backend: SmbCommandRunner {
                credentials: self.credentials.clone(),
                host: self.host.clone(),
                port: self.port,
                share: self.share.clone(),
                min_protocol_option: self.min_protocol_option,
                protection_flag: self.protection_flag,
            },
            upload: None,
        }))
    }

    async fn delete(&self, path: &str) -> Result<(), SepulchreError> {
        let remote = self.resolve(path)?;
        self.run_command(&format!("del \"{remote}\"")).await?;
        Ok(())
    }

    async fn ensure_dir(&self, path: &str) -> Result<(), SepulchreError> {
        // `smbclient`'s `mkdir` has no `-p`-equivalent and errors if the
        // directory already exists -- create each path component in
        // turn, ignoring a failure on a component that's already there
        // (checked structurally via a listing, not by string-matching
        // smbclient's own error text, which varies by server). Splits the
        // fully `resolve`d path (subpath included) rather than the raw
        // `path` argument directly, so this honors the connection's
        // `subpath` the same way `stat`/`list`/`open_read`/`open_write`/
        // `delete` already do.
        let mut current = String::new();
        for component in self.resolve(path)?.split('\\').filter(|c| !c.is_empty()) {
            current = if current.is_empty() {
                component.to_string()
            } else {
                format!("{current}\\{component}")
            };
            let already_exists = self.run_command(&format!("ls \"{current}\"")).await.is_ok();
            if already_exists {
                continue;
            }
            let _ = self.run_command(&format!("mkdir \"{current}\"")).await;
        }
        Ok(())
    }

    async fn free_space(&self) -> Result<Option<u64>, SepulchreError> {
        // `smbclient` has no portable, parse-stable free-space command
        // across server implementations -- best-effort `None` rather
        // than a fragile text scrape.
        Ok(None)
    }

    fn possible_capabilities(&self) -> HashSet<Capability> {
        Capability::ALL.iter().copied().collect()
    }
}

/// A minimal clone of just what [`SmbBackend`] needs to issue one more
/// `smbclient` command later, held by [`UploadOnShutdownWriter`] so it
/// can trigger the actual upload from `poll_shutdown` without borrowing
/// the original backend.
struct SmbCommandRunner {
    credentials: std::sync::Arc<CredentialsFile>,
    host: String,
    port: u16,
    share: String,
    min_protocol_option: &'static str,
    protection_flag: Option<&'static str>,
}

impl SmbCommandRunner {
    async fn run(&self, smb_command: String) -> Result<(), SepulchreError> {
        let mut cmd = tokio::process::Command::new("smbclient");
        cmd.arg(format!("//{}/{}", self.host, self.share))
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-A")
            .arg(&self.credentials.path)
            .arg("-m")
            .arg("SMB3")
            .arg("--option")
            .arg(self.min_protocol_option)
            .arg("-c")
            .arg(&smb_command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(protection) = self.protection_flag {
            cmd.arg("--client-protection").arg(protection);
        }
        let output = cmd
            .output()
            .await
            .map_err(|e| SepulchreError::Backend(format!("failed to run smbclient: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SepulchreError::Backend(format!(
                "smbclient upload failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                stderr
            )));
        }
        Ok(())
    }
}

/// Wraps a temp-file [`AsyncRead`], deleting the file once fully
/// dropped (best-effort, via a detached `tokio::spawn` since `Drop`
/// can't `.await` -- same pattern `reliquary_backup::provider`'s
/// `CleanupDir` already uses).
struct CleanupOnDropReader {
    file: tokio::fs::File,
    temp_path: Option<PathBuf>,
}

impl AsyncRead for CleanupOnDropReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

impl Drop for CleanupOnDropReader {
    fn drop(&mut self) {
        if let Some(path) = self.temp_path.take() {
            tokio::spawn(async move {
                let _ = tokio::fs::remove_file(&path).await;
            });
        }
    }
}

/// Buffers writes to a local temp file, then -- on `poll_shutdown`,
/// exactly the "I'm done, finalize" signal `AsyncWrite` already defines
/// -- uploads it via `smbclient put` and removes the temp file. State
/// machine: the upload only starts on the *first* `poll_shutdown` call
/// (lazily spawned), and every call after that just polls the same
/// in-flight task until it resolves.
struct UploadOnShutdownWriter {
    file: tokio::fs::File,
    temp_path: PathBuf,
    remote: String,
    backend: SmbCommandRunner,
    upload: Option<Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>>,
}

impl AsyncWrite for UploadOnShutdownWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.file).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // First: make sure every buffered byte actually reached the temp
        // file before we start uploading it.
        match Pin::new(&mut self.file).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }

        if self.upload.is_none() {
            let temp_path = self.temp_path.clone();
            let remote = self.remote.clone();
            let command = format!("put \"{}\" \"{remote}\"", temp_path.display());
            // `backend` is only ever used to spawn this one future, so
            // taking a fresh clone of what it needs and moving it in is
            // simpler than fighting the borrow checker over `self` --
            // `SmbCommandRunner` is cheap to reconstruct field-by-field.
            let runner = SmbCommandRunner {
                credentials: self.backend.credentials.clone(),
                host: self.backend.host.clone(),
                port: self.backend.port,
                share: self.backend.share.clone(),
                min_protocol_option: self.backend.min_protocol_option,
                protection_flag: self.backend.protection_flag,
            };
            let fut = async move {
                let result = runner.run(command).await;
                let _ = tokio::fs::remove_file(&temp_path).await;
                result.map_err(|e| io::Error::other(e.to_string()))
            };
            self.upload = Some(Box::pin(fut));
        }

        let upload = self.upload.as_mut().expect("just set if it was None");
        upload.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_regular_file_ls_line() {
        let entry = parse_ls_line(
            "  report.txt                          A     1234  Mon Jan  1 00:00:00 2024",
        )
        .unwrap();
        assert_eq!(entry.name, "report.txt");
        assert!(!entry.is_dir);
        assert_eq!(entry.size_bytes, 1234);
    }

    #[test]
    fn parses_a_directory_ls_line() {
        let entry = parse_ls_line(
            "  backups                             D        0  Mon Jan  1 00:00:00 2024",
        )
        .unwrap();
        assert_eq!(entry.name, "backups");
        assert!(entry.is_dir);
    }

    #[test]
    fn skips_dot_and_dotdot_entries() {
        assert!(
            parse_ls_line(
                "  .                                    D        0  Mon Jan  1 00:00:00 2024"
            )
            .is_none()
        );
        assert!(
            parse_ls_line(
                "  ..                                   D        0  Mon Jan  1 00:00:00 2024"
            )
            .is_none()
        );
    }

    #[test]
    fn skips_blank_lines() {
        assert!(parse_ls_line("").is_none());
        assert!(parse_ls_line("   ").is_none());
    }

    #[test]
    fn handles_a_filename_containing_spaces() {
        let entry = parse_ls_line(
            "  my report v2.txt                   A     500  Mon Jan  1 00:00:00 2024",
        )
        .unwrap();
        assert_eq!(entry.name, "my report v2.txt");
    }

    #[test]
    fn accepts_an_ordinary_path_component() {
        assert!(reject_unsafe_smb_component("reports/2024/january.txt").is_ok());
    }

    #[test]
    fn rejects_a_semicolon_that_could_inject_a_second_smbclient_command() {
        assert!(reject_unsafe_smb_component("evil\"; del important.txt; \"").is_err());
        assert!(reject_unsafe_smb_component("plain; del important.txt").is_err());
    }

    #[test]
    fn rejects_a_leading_bang_that_smbclient_treats_as_a_local_shell_command() {
        assert!(reject_unsafe_smb_component("!rm -rf /").is_err());
    }

    #[test]
    fn rejects_an_embedded_double_quote() {
        assert!(reject_unsafe_smb_component("a\"b").is_err());
    }

    #[test]
    fn a_connection_with_an_unsafe_subpath_is_refused_at_construction() {
        let config = abyssal_core::SmbConfig {
            host: "example.test".to_string(),
            port: 445,
            share_name: "share".to_string(),
            subpath: "a; del *".to_string(),
            username: "user".to_string(),
            domain: None,
            min_protocol: abyssal_core::SmbMinProtocol::Smb3,
            signing_required: true,
            encryption: SmbEncryption::Off,
        };
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(SmbBackend::new(
                config,
                Zeroizing::new("password".to_string()),
            ));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_private_file_refuses_to_overwrite_an_existing_path() {
        let path =
            std::env::temp_dir().join(format!("sepulchre-smb-test-{}", uuid::Uuid::new_v4()));
        let _first = create_private_file(&path).await.unwrap();
        let second = create_private_file(&path).await;
        assert!(second.is_err());
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn create_private_file_is_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("sepulchre-smb-test-{}", uuid::Uuid::new_v4()));
        let file = create_private_file(&path).await.unwrap();
        let mode = file.metadata().await.unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(file);
        let _ = tokio::fs::remove_file(&path).await;
    }
}
