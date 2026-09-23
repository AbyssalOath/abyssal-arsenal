//! Native (control-plane) backups -- GitHub issue #9. Backs up the
//! Arsenal application's own persistent data (MariaDB dump, redacted
//! config, optionally the encryption key) into one `.tar.zst[.enc]`
//! archive per backup, restorable onto a fresh install via either the web
//! UI or the `abyssal-arsenal reliquary` CLI subcommand
//! (`crates/app/src/cli.rs`) for total-loss recovery.
//!
//! Layered per the `BackupProvider`/`StorageDestination` design GitHub
//! issue #9 asked for, so a future Remote/Agent provider (backing up
//! *managed hosts'* data, not the control plane's own) can be added
//! without refactoring this one:
//! - [`provider::BackupProvider`] -- `create`/`verify`/`restore`/`describe`.
//!   [`provider::NativeProvider`] is the only implementation today.
//! - [`storage::StorageDestination`] -- where the finished archive lands.
//!   [`storage::LocalFs`] is the only implementation today; an
//!   S3-compatible one is a natural second implementation later, not a
//!   redesign.
//! - [`dump`] -- the MariaDB logical-dump half of a backup.
//! - [`archive`] -- tar+zstd archive building and safe extraction.
//! - [`crypto`] -- streaming AEAD encryption/decryption of a whole archive.
//! - [`orchestrator`] -- job lifecycle, the scheduled-backup loop, and
//!   retention pruning.
//! - [`verify`] -- quick (checksum/manifest) and deep (scratch-database
//!   restore test) verification.
//! - [`restore`] -- the restore pipeline and maintenance-mode gate.

pub mod archive;
pub mod crypto;
pub mod dump;
pub mod orchestrator;
pub mod provider;
pub mod restore;
pub mod storage;
pub mod verify;

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("{0}")]
    Config(String),
    #[error("database dump failed: {0}")]
    Dump(String),
    #[error("archive error: {0}")]
    Archive(String),
    #[error("encryption error: {0}")]
    Crypto(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("restore failed: {0}")]
    Restore(String),
    #[error("backup was cancelled")]
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

/// The pieces of `DATABASE_URL` needed to invoke `mariadb-dump`/`mariadb`
/// directly (as a child process, not through the connection pool) --
/// parsed by hand rather than pulling in the `url` crate for one narrow,
/// well-defined format this app already only ever produces itself
/// (`mysql://user:pass@host:port/database`, `docker-compose.yml`'s own
/// `DATABASE_URL` line). `password` is `Zeroizing` since it's a real
/// credential, same as every other secret this codebase holds in memory.
pub struct DbConnectionInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Zeroizing<String>,
    pub database: String,
}

impl DbConnectionInfo {
    pub fn parse(database_url: &str) -> Result<Self, BackupError> {
        let rest = database_url.strip_prefix("mysql://").ok_or_else(|| {
            BackupError::Config("DATABASE_URL must start with mysql://".to_string())
        })?;
        let (creds, host_and_path) = rest
            .split_once('@')
            .ok_or_else(|| BackupError::Config("DATABASE_URL is missing '@'".to_string()))?;
        let (user, pass) = creds.split_once(':').unwrap_or((creds, ""));
        let (host_port, database) = host_and_path.split_once('/').ok_or_else(|| {
            BackupError::Config("DATABASE_URL is missing a database path".to_string())
        })?;
        let (host, port) = host_port.split_once(':').unwrap_or((host_port, "3306"));
        let port: u16 = port
            .parse()
            .map_err(|_| BackupError::Config("DATABASE_URL has an invalid port".to_string()))?;
        let database = database.split(['?', '#']).next().unwrap_or(database);

        Ok(Self {
            host: percent_decode(host),
            port,
            username: percent_decode(user),
            password: Zeroizing::new(percent_decode(pass)),
            database: percent_decode(database),
        })
    }
}

/// Lower-case hex encoding for a SHA-256 digest -- the one place this
/// module needs hex at all, so a two-line helper here beats a new
/// dependency for it.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Minimal RFC 3986 percent-decoding -- just enough for URL userinfo/path
/// components, which is the only place this module ever needs it. Not a
/// general-purpose decoder (doesn't validate UTF-8 boundaries beyond
/// falling back to the replacement character, which is fine here: a
/// malformed percent-escape in `DATABASE_URL` should surface as "wrong
/// credentials" downstream, not a panic).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_database_url() {
        let info = DbConnectionInfo::parse("mysql://abyssal:changeme@mariadb:3306/abyssal_arsenal")
            .unwrap();
        assert_eq!(info.host, "mariadb");
        assert_eq!(info.port, 3306);
        assert_eq!(info.username, "abyssal");
        assert_eq!(&*info.password, "changeme");
        assert_eq!(info.database, "abyssal_arsenal");
    }

    #[test]
    fn defaults_to_port_3306_when_omitted() {
        let info = DbConnectionInfo::parse("mysql://u:p@dbhost/db").unwrap();
        assert_eq!(info.port, 3306);
    }

    #[test]
    fn decodes_percent_escaped_credentials() {
        let info = DbConnectionInfo::parse("mysql://u%40ser:p%40ss@host:3306/db").unwrap();
        assert_eq!(info.username, "u@ser");
        assert_eq!(&*info.password, "p@ss");
    }

    #[test]
    fn strips_a_trailing_query_string_from_the_database_name() {
        let info = DbConnectionInfo::parse("mysql://u:p@host:3306/db?ssl-mode=disabled").unwrap();
        assert_eq!(info.database, "db");
    }

    #[test]
    fn rejects_a_non_mysql_scheme() {
        assert!(DbConnectionInfo::parse("postgres://u:p@host/db").is_err());
    }
}
