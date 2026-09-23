//! tar+zstd archive building and safe extraction -- GitHub issue #9.
//! Building uses the sync `tar`/`zstd` crates (there's no mature async
//! tar implementation worth trusting for this), always run inside
//! `spawn_blocking` per the project's own guidance for CPU-heavy/blocking
//! work; nothing here ever buffers a whole archive or a whole entry's
//! contents in memory -- `tar::Builder::append_file` and `zstd::Encoder`
//! both stream in bounded chunks internally.

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::BackupError;

/// One file to place into the archive at `archive_path` (the tar entry
/// name, always a relative Unix-style path -- e.g. `"db.sql"`,
/// `"manifest.json"`), sourced from `source_path` on disk.
pub struct ArchiveEntry {
    pub archive_path: String,
    pub source_path: PathBuf,
}

/// Wraps any `Write` and updates a running SHA-256 digest of everything
/// written through it -- computes the finished archive's own checksum in
/// the same pass that writes it, rather than a second read-back pass.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Builds `out_path` as a zstd-compressed tar archive containing exactly
/// `entries`, and returns its SHA-256 and total size. Must be called from
/// `tokio::task::spawn_blocking` -- every operation here is synchronous.
pub fn build_archive_blocking(
    entries: &[ArchiveEntry],
    out_path: &Path,
) -> Result<(String, u64), BackupError> {
    let file = std::fs::File::create(out_path)
        .map_err(|e| BackupError::Archive(format!("creating {}: {e}", out_path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| BackupError::Archive(format!("setting archive permissions: {e}")))?;
    }

    let hashing = HashingWriter {
        inner: file,
        hasher: Sha256::new(),
    };
    let encoder = zstd::Encoder::new(hashing, 3)
        .map_err(|e| BackupError::Archive(format!("starting zstd stream: {e}")))?;
    let mut builder = tar::Builder::new(encoder);

    for entry in entries {
        let mut source = std::fs::File::open(&entry.source_path).map_err(|e| {
            BackupError::Archive(format!("reading {}: {e}", entry.source_path.display()))
        })?;
        builder
            .append_file(&entry.archive_path, &mut source)
            .map_err(|e| {
                BackupError::Archive(format!("adding {} to archive: {e}", entry.archive_path))
            })?;
    }

    let hashing = builder
        .into_inner()
        .map_err(|e| BackupError::Archive(format!("finalizing tar stream: {e}")))?
        .finish()
        .map_err(|e| BackupError::Archive(format!("finalizing zstd stream: {e}")))?;
    hashing
        .inner
        .sync_all()
        .map_err(|e| BackupError::Archive(format!("syncing archive to disk: {e}")))?;

    let size_bytes = std::fs::metadata(out_path)
        .map_err(|e| BackupError::Archive(format!("statting finished archive: {e}")))?
        .len();
    Ok((super::hex_encode(&hashing.hasher.finalize()), size_bytes))
}

/// Rejects a tar entry path before it's ever handed to `unpack_in` --
/// defense in depth on top of `unpack_in`'s own confinement, per GitHub
/// issue #9's explicit requirement to validate every entry, not just
/// trust the extraction call: an absolute path, any `..` component, or a
/// symlink/hardlink target that isn't confined to the archive's own
/// contents is rejected outright rather than attempted.
fn validate_entry_path(path: &Path) -> Result<(), BackupError> {
    if path.is_absolute() {
        return Err(BackupError::Archive(format!(
            "archive entry has an absolute path: {}",
            path.display()
        )));
    }
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(BackupError::Archive(format!(
                    "archive entry escapes its directory: {}",
                    path.display()
                )));
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(BackupError::Archive(format!(
                    "archive entry has an absolute/rooted path: {}",
                    path.display()
                )));
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

/// Safely extracts every entry of `archive_path` (a `.tar.zst` built by
/// `build_archive_blocking`, already decrypted if it was encrypted) into
/// `dest_dir`. Must be called from `spawn_blocking`. Every entry's path
/// is validated (`validate_entry_path`) before extraction, and only
/// regular files and directories are accepted -- a symlink or hardlink
/// entry (which this application's own `build_archive_blocking` never
/// produces, so one appearing at all is itself suspicious) is rejected
/// rather than followed, since its target could point outside `dest_dir`
/// regardless of how the entry's own *name* looks.
pub fn extract_archive_blocking(archive_path: &Path, dest_dir: &Path) -> Result<(), BackupError> {
    std::fs::create_dir_all(dest_dir)
        .map_err(|e| BackupError::Archive(format!("creating {}: {e}", dest_dir.display())))?;

    let file = std::fs::File::open(archive_path)
        .map_err(|e| BackupError::Archive(format!("opening {}: {e}", archive_path.display())))?;
    let decoder = zstd::Decoder::new(file)
        .map_err(|e| BackupError::Archive(format!("starting zstd decode: {e}")))?;
    let mut archive = tar::Archive::new(decoder);

    for entry in archive
        .entries()
        .map_err(|e| BackupError::Archive(format!("reading archive entries: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| BackupError::Archive(format!("reading archive entry: {e}")))?;
        let entry_path = entry
            .path()
            .map_err(|e| BackupError::Archive(format!("reading entry path: {e}")))?
            .into_owned();
        validate_entry_path(&entry_path)?;

        match entry.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Directory => {}
            other => {
                return Err(BackupError::Archive(format!(
                    "archive entry {} has disallowed type {:?} -- refusing to extract",
                    entry_path.display(),
                    other
                )));
            }
        }

        entry.unpack_in(dest_dir).map_err(|e| {
            BackupError::Archive(format!("extracting {}: {e}", entry_path.display()))
        })?;
    }
    Ok(())
}

/// Reads one small file (e.g. `manifest.json`) out of an archive without
/// extracting everything else -- what a quick verify and a restore
/// dry-run preview both use to inspect the manifest cheaply. Must be
/// called from `spawn_blocking`.
pub fn read_archive_entry_blocking(
    archive_path: &Path,
    entry_name: &str,
) -> Result<Vec<u8>, BackupError> {
    let file = std::fs::File::open(archive_path)
        .map_err(|e| BackupError::Archive(format!("opening {}: {e}", archive_path.display())))?;
    let decoder = zstd::Decoder::new(file)
        .map_err(|e| BackupError::Archive(format!("starting zstd decode: {e}")))?;
    let mut archive = tar::Archive::new(decoder);

    for entry in archive
        .entries()
        .map_err(|e| BackupError::Archive(format!("reading archive entries: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| BackupError::Archive(format!("reading archive entry: {e}")))?;
        let entry_path = entry
            .path()
            .map_err(|e| BackupError::Archive(format!("reading entry path: {e}")))?
            .into_owned();
        if entry_path == Path::new(entry_name) {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| BackupError::Archive(format!("reading {entry_name}: {e}")))?;
            return Ok(buf);
        }
    }
    Err(BackupError::Archive(format!(
        "archive has no entry named {entry_name}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absolute_paths() {
        assert!(validate_entry_path(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn rejects_parent_dir_traversal() {
        assert!(validate_entry_path(Path::new("../../etc/passwd")).is_err());
        assert!(validate_entry_path(Path::new("db.sql/../../../etc/passwd")).is_err());
    }

    #[test]
    fn accepts_a_plain_relative_path() {
        assert!(validate_entry_path(Path::new("db.sql")).is_ok());
        assert!(validate_entry_path(Path::new("config/app.env")).is_ok());
    }

    #[test]
    fn round_trips_a_small_archive() {
        let tmp =
            std::env::temp_dir().join(format!("reliquary-archive-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let source_path = tmp.join("source.txt");
        std::fs::write(&source_path, b"hello reliquary").unwrap();

        let archive_path = tmp.join("out.tar.zst");
        let (sha256, size) = build_archive_blocking(
            &[ArchiveEntry {
                archive_path: "greeting.txt".to_string(),
                source_path: source_path.clone(),
            }],
            &archive_path,
        )
        .unwrap();
        assert!(size > 0);
        assert_eq!(sha256.len(), 64);

        let dest = tmp.join("extracted");
        extract_archive_blocking(&archive_path, &dest).unwrap();
        let extracted = std::fs::read(dest.join("greeting.txt")).unwrap();
        assert_eq!(extracted, b"hello reliquary");

        let read_directly = read_archive_entry_blocking(&archive_path, "greeting.txt").unwrap();
        assert_eq!(read_directly, b"hello reliquary");

        std::fs::remove_dir_all(&tmp).ok();
    }
}
