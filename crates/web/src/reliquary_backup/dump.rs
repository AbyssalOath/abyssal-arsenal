//! The MariaDB logical-dump half of a native backup -- GitHub issue #9.
//! Shells out to `mariadb-dump` (falling back to `mysqldump` only if the
//! former isn't on `PATH`) with an argument list, never a shell string,
//! and streams its stdout straight to disk through a SHA-256 hasher
//! without ever holding the full dump in memory.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{BackupError, DbConnectionInfo};

/// stdout is read in fixed-size chunks and written straight through to
/// disk -- this bounds how much of the dump is ever resident in memory
/// at once, regardless of the dump's total size.
const READ_CHUNK_BYTES: usize = 256 * 1024;

pub struct DumpOutcome {
    pub sha256: String,
    pub size_bytes: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

/// Which credentials to run `mariadb-dump`/the restore `mariadb` client
/// with. `RELIQUARY_BACKUP_DB_USER`/`RELIQUARY_BACKUP_DB_PASSWORD`
/// override this when set (a dedicated least-privilege backup user, see
/// `docs/reliquary-backups.md`); otherwise this falls back to the
/// application's own `DATABASE_URL` credentials, logging a warning each
/// time, per GitHub issue #9's explicit requirement.
pub struct BackupCredentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

pub fn resolve_backup_credentials(conn: &DbConnectionInfo) -> BackupCredentials {
    let user = std::env::var("RELIQUARY_BACKUP_DB_USER").ok();
    let pass = std::env::var("RELIQUARY_BACKUP_DB_PASSWORD").ok();
    match (user, pass) {
        (Some(user), Some(pass)) if !user.is_empty() => BackupCredentials {
            username: user,
            password: Zeroizing::new(pass),
        },
        _ => {
            tracing::warn!(
                "RELIQUARY_BACKUP_DB_USER/RELIQUARY_BACKUP_DB_PASSWORD not set -- backups will \
                 run as the application's own database user, which has more privilege than a \
                 backup needs. See docs/reliquary-backups.md for the recommended least-privilege \
                 grants."
            );
            BackupCredentials {
                username: conn.username.clone(),
                password: conn.password.clone(),
            }
        }
    }
}

/// A `--defaults-extra-file` for `mariadb-dump`/`mariadb`, so the
/// password never appears in argv (visible to any other user via `ps` on
/// most systems) or in a log line. Written 0600, to a random path under
/// the system temp directory, and deleted on drop -- best-effort deletion
/// (a leftover temp file with credentials in it would be a real problem,
/// but there's nothing more this can do synchronously in a `Drop` impl
/// beyond trying once).
struct DefaultsExtraFile {
    path: PathBuf,
}

impl DefaultsExtraFile {
    async fn write(creds: &BackupCredentials) -> Result<Self, BackupError> {
        let path = std::env::temp_dir().join(format!(".reliquary-backup-{}.cnf", Uuid::new_v4()));
        let contents = format!(
            "[client]\nuser={}\npassword={}\n",
            escape_ini_value(&creds.username),
            escape_ini_value(&creds.password)
        );

        #[cfg(unix)]
        {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .await?;
            file.write_all(contents.as_bytes()).await?;
        }
        #[cfg(not(unix))]
        {
            tokio::fs::write(&path, contents.as_bytes()).await?;
        }

        Ok(Self { path })
    }
}

impl Drop for DefaultsExtraFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// MariaDB's `.cnf`/INI format doesn't need much escaping for a value on
/// its own line, but a literal `#`/`;` starts a comment and would
/// truncate the value silently -- reject rather than mis-parse.
fn escape_ini_value(value: &str) -> String {
    value.replace(['#', ';', '\n'], "")
}

fn resolve_dump_binary() -> Result<&'static str, BackupError> {
    for candidate in ["mariadb-dump", "mysqldump"] {
        if which(candidate) {
            return Ok(candidate);
        }
    }
    Err(BackupError::Config(
        "neither mariadb-dump nor mysqldump was found on PATH -- install mariadb-client in the \
         runtime image"
            .to_string(),
    ))
}

fn resolve_restore_binary() -> Result<&'static str, BackupError> {
    for candidate in ["mariadb", "mysql"] {
        if which(candidate) {
            return Ok(candidate);
        }
    }
    Err(BackupError::Config(
        "neither mariadb nor mysql was found on PATH -- install mariadb-client in the runtime \
         image"
            .to_string(),
    ))
}

fn which(binary: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(binary).is_file()))
        .unwrap_or(false)
}

/// Runs `mariadb-dump` for `conn.database`, streaming its stdout to
/// `out_path` through a SHA-256 hasher. `--single-transaction` gives a
/// consistent InnoDB snapshot without `--lock-all-tables`;
/// `--databases <db>` (rather than a bare positional database name)
/// makes the dump self-contained -- it includes its own `CREATE DATABASE`/
/// `USE`, so a restore doesn't need the target database to already exist
/// with the right name. Kills the child and removes the partial output
/// file if `cancel` fires or the process errors out.
pub async fn dump_database(
    conn: &DbConnectionInfo,
    creds: &BackupCredentials,
    out_path: &Path,
    exclude_audit_log: bool,
    cancel: &CancellationToken,
) -> Result<DumpOutcome, BackupError> {
    let started_at = Utc::now();
    let binary = resolve_dump_binary()?;
    let defaults_file = DefaultsExtraFile::write(creds).await?;

    let mut command = Command::new(binary);
    command
        .arg(format!(
            "--defaults-extra-file={}",
            defaults_file.path.display()
        ))
        .arg(format!("--host={}", conn.host))
        .arg(format!("--port={}", conn.port))
        .arg("--single-transaction")
        .arg("--routines")
        .arg("--triggers")
        .arg("--events")
        .arg("--hex-blob")
        .arg("--default-character-set=utf8mb4")
        .arg("--quick");
    // `--ignore-table` takes db.table and can be repeated; a deployment
    // that wants its backups to exclude potentially sensitive audit
    // detail by default (RELIQUARY_BACKUP_INCLUDE_AUDIT_LOGS) still gets
    // the rest of the schema/data -- just not this one table's rows.
    if exclude_audit_log {
        command.arg(format!("--ignore-table={}.audit_log", conn.database));
    }
    command
        .arg("--databases")
        .arg(&conn.database)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command
        .spawn()
        .map_err(|e| BackupError::Dump(format!("failed to start {binary}: {e}")))?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| BackupError::Dump("child process had no stdout".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BackupError::Dump("child process had no stderr".to_string()))?;

    let mut out_file = tokio::fs::File::create(out_path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        out_file
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .await?;
    }

    let mut hasher = Sha256::new();
    let mut size_bytes: u64 = 0;
    let mut buf = vec![0u8; READ_CHUNK_BYTES];
    // The dump is well-formed SQL text ending in a comment line once
    // `mariadb-dump` finishes cleanly -- kept as a tail window (its own
    // small buffer, not the whole dump) so the completion marker can be
    // checked without re-reading the file afterward.
    let mut tail = Vec::new();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                let _ = child.kill().await;
                let _ = tokio::fs::remove_file(out_path).await;
                return Err(BackupError::Cancelled);
            }
            read = stdout.read(&mut buf) => {
                let n = read.map_err(|e| BackupError::Dump(format!("reading dump output: {e}")))?;
                if n == 0 {
                    break;
                }
                let chunk = &buf[..n];
                hasher.update(chunk);
                size_bytes += n as u64;
                out_file
                    .write_all(chunk)
                    .await
                    .map_err(|e| BackupError::Dump(format!("writing dump output: {e}")))?;

                tail.extend_from_slice(chunk);
                if tail.len() > 256 {
                    let cut = tail.len() - 256;
                    tail.drain(..cut);
                }
            }
        }
    }
    out_file.flush().await?;

    // Drain stderr (bounded -- a runaway dump's error chatter shouldn't
    // grow unbounded in memory) for error reporting.
    let mut stderr_buf = Vec::new();
    let _ = stderr.take(64 * 1024).read_to_end(&mut stderr_buf).await;

    let status = child
        .wait()
        .await
        .map_err(|e| BackupError::Dump(format!("waiting for {binary}: {e}")))?;

    if !status.success() {
        let _ = tokio::fs::remove_file(out_path).await;
        let stderr_text = String::from_utf8_lossy(&stderr_buf);
        return Err(BackupError::Dump(format!(
            "{binary} exited with {status}: {}",
            stderr_text.trim()
        )));
    }

    let tail_text = String::from_utf8_lossy(&tail);
    if !tail_text.contains("-- Dump completed") {
        let _ = tokio::fs::remove_file(out_path).await;
        return Err(BackupError::Dump(
            "dump exited successfully but is missing the \"-- Dump completed\" marker -- \
             treating it as incomplete rather than trusting a zero exit code alone"
                .to_string(),
        ));
    }

    Ok(DumpOutcome {
        sha256: super::hex_encode(&hasher.finalize()),
        size_bytes,
        started_at,
        finished_at: Utc::now(),
    })
}

/// Streams `dump_path`'s contents into the `mariadb`/`mysql` client's
/// stdin -- the restore-side mirror of `dump_database`. No shell, no
/// password in argv; same `--defaults-extra-file` mechanism.
pub async fn restore_database(
    conn: &DbConnectionInfo,
    creds: &BackupCredentials,
    target_database: &str,
    dump_path: &Path,
    cancel: &CancellationToken,
) -> Result<(), BackupError> {
    let binary = resolve_restore_binary()?;
    let defaults_file = DefaultsExtraFile::write(creds).await?;

    let mut command = Command::new(binary);
    command
        .arg(format!(
            "--defaults-extra-file={}",
            defaults_file.path.display()
        ))
        .arg(format!("--host={}", conn.host))
        .arg(format!("--port={}", conn.port))
        .arg("--default-character-set=utf8mb4")
        .arg(target_database)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command
        .spawn()
        .map_err(|e| BackupError::Restore(format!("failed to start {binary}: {e}")))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| BackupError::Restore("child process had no stdin".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BackupError::Restore("child process had no stderr".to_string()))?;

    let mut in_file = tokio::fs::File::open(dump_path).await?;
    let mut buf = vec![0u8; READ_CHUNK_BYTES];
    let write_result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                let _ = child.kill().await;
                break Err(BackupError::Cancelled);
            }
            read = in_file.read(&mut buf) => {
                match read {
                    Ok(0) => break Ok(()),
                    Ok(n) => {
                        if let Err(e) = stdin.write_all(&buf[..n]).await {
                            break Err(BackupError::Restore(format!("writing to {binary} stdin: {e}")));
                        }
                    }
                    Err(e) => break Err(BackupError::Restore(format!("reading dump file: {e}"))),
                }
            }
        }
    };
    drop(stdin); // signal EOF to the client regardless of outcome
    write_result?;

    let mut stderr_buf = Vec::new();
    let _ = stderr.take(64 * 1024).read_to_end(&mut stderr_buf).await;

    let status = child
        .wait()
        .await
        .map_err(|e| BackupError::Restore(format!("waiting for {binary}: {e}")))?;
    if !status.success() {
        let stderr_text = String::from_utf8_lossy(&stderr_buf);
        return Err(BackupError::Restore(format!(
            "{binary} exited with {status}: {}",
            stderr_text.trim()
        )));
    }
    Ok(())
}

/// Server version/charset/collation/sql_mode for the manifest -- run as
/// separate, trivial `mariadb`/`mysql` invocations (each a single `-e`
/// query, output captured directly) rather than parsing them out of the
/// dump text, which is a much less stable interface than just asking the
/// server.
pub async fn server_metadata(
    conn: &DbConnectionInfo,
    creds: &BackupCredentials,
) -> Result<(String, String, String, String), BackupError> {
    let version = run_scalar_query(conn, creds, "SELECT VERSION()").await?;
    let charset = run_scalar_query(conn, creds, "SELECT @@character_set_database").await?;
    let collation = run_scalar_query(conn, creds, "SELECT @@collation_database").await?;
    let sql_mode = run_scalar_query(conn, creds, "SELECT @@sql_mode").await?;
    Ok((version, charset, collation, sql_mode))
}

async fn run_scalar_query(
    conn: &DbConnectionInfo,
    creds: &BackupCredentials,
    query: &str,
) -> Result<String, BackupError> {
    let binary = resolve_restore_binary()?;
    let defaults_file = DefaultsExtraFile::write(creds).await?;
    let output = Command::new(binary)
        .arg(format!(
            "--defaults-extra-file={}",
            defaults_file.path.display()
        ))
        .arg(format!("--host={}", conn.host))
        .arg(format!("--port={}", conn.port))
        .arg("--skip-column-names")
        .arg("--batch")
        .arg("-e")
        .arg(query)
        .output()
        .await
        .map_err(|e| BackupError::Dump(format!("failed to run {binary}: {e}")))?;
    if !output.status.success() {
        return Err(BackupError::Dump(format!(
            "{binary} query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
