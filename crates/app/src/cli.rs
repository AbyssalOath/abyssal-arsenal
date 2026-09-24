//! Disaster-recovery CLI -- GitHub issue #9. Works against a completely
//! fresh install (empty database, brand-new containers) without the web
//! UI, a session, or even the `reliquary_backups` table existing yet --
//! it operates directly on an archive *file* the operator points it at,
//! not a database-tracked job. Run via
//! `docker compose run --rm app reliquary backup restore <path> [...]`.
//! See `docs/reliquary-backups.md` for the full walkthrough.

use std::path::PathBuf;

use abyssal_web::reliquary_backup::{archive, crypto, restore as restore_engine};
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ReliquaryCommand {
    /// Lists every backup tracked in the database.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
}

#[derive(Subcommand)]
pub enum BackupAction {
    List,
    /// Confirms `archive` is readable and its manifest is well-formed.
    /// Decrypts first (`--passphrase-file`) if the archive is encrypted.
    Verify(ArchiveArgs),
    /// Restores `archive` into the database `DATABASE_URL` points at.
    /// Refuses to guess: the target must already exist and be reachable
    /// (`docker compose up mariadb` on a fresh install creates an empty
    /// one automatically) -- this streams the dump into it, which
    /// recreates the schema from scratch.
    Restore(ArchiveArgs),
}

#[derive(Args)]
pub struct ArchiveArgs {
    /// Path to the backup archive file (e.g. `/backups/backup-<id>.tar.zst`
    /// or the `.enc` variant).
    archive: PathBuf,
    /// Path to a file containing the passphrase, if the archive is
    /// encrypted -- never passed as a bare `--passphrase` flag, which
    /// would put it in `ps` output and shell history.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
}

pub async fn run(command: ReliquaryCommand) -> anyhow::Result<()> {
    match command {
        ReliquaryCommand::Backup { action } => match action {
            BackupAction::List => list().await,
            BackupAction::Verify(args) => verify(args).await,
            BackupAction::Restore(args) => restore(args).await,
        },
    }
}

async fn read_passphrase(args: &ArchiveArgs) -> anyhow::Result<Option<String>> {
    match &args.passphrase_file {
        Some(path) => {
            let contents = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
            Ok(Some(contents.trim_end_matches(['\n', '\r']).to_string()))
        }
        None => Ok(None),
    }
}

/// Reads the manifest out of `archive`, decrypting to a temp file first
/// if `--passphrase-file` was given (an unencrypted archive's manifest is
/// read directly, no temp file needed).
async fn read_manifest(args: &ArchiveArgs) -> anyhow::Result<abyssal_core::BackupManifest> {
    let passphrase = read_passphrase(args).await?;
    let archive_path = args.archive.clone();

    let (manifest_bytes, encryption_metadata) = if let Some(passphrase) = &passphrase {
        // An encrypted archive's manifest is only readable after
        // decrypting the whole thing (the manifest is a tar entry
        // *inside* the plaintext archive) -- there's no way to peek just
        // the manifest without a passphrase, by design.
        let tmp_dir = std::env::temp_dir().join(format!("reliquary-cli-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&tmp_dir).await?;
        let decrypted_path = tmp_dir.join("archive.tar.zst");
        // The CLI doesn't have the job's stored EncryptionMetadata (no DB
        // row to read it from for an arbitrary file) -- it's read back
        // out of the encrypted file's own header instead, which only
        // contains the salt/nonce, never the algorithm name (that part
        // of the metadata lives solely in manifest.json, which is
        // exactly what we're trying to read). This CLI therefore only
        // supports the one algorithm this codebase ever produces
        // (`aes-256-gcm-stream-be32`) -- reasonable, since nothing else
        // could have created the file in the first place.
        let metadata = abyssal_core::EncryptionMetadata {
            algorithm: "aes-256-gcm-stream-be32".to_string(),
            kdf: "argon2id".to_string(),
            kdf_salt_base64: String::new(), // overwritten below, read from the file itself
            kdf_params: "m=19456,t=2,p=1".to_string(),
        };
        let metadata = read_salt_into_metadata(&archive_path, metadata).await?;
        let metadata_for_decrypt = metadata.clone();
        let passphrase_owned = passphrase.clone();
        let in_path = archive_path.clone();
        let out_path = decrypted_path.clone();
        tokio::task::spawn_blocking(move || {
            crypto::decrypt_file_blocking(
                &in_path,
                &out_path,
                &passphrase_owned,
                &metadata_for_decrypt,
            )
        })
        .await??;
        let bytes = tokio::task::spawn_blocking(move || {
            archive::read_archive_entry_blocking(&decrypted_path, "manifest.json")
        })
        .await??;
        tokio::fs::remove_dir_all(&tmp_dir).await.ok();
        (bytes, Some(metadata))
    } else {
        let bytes = tokio::task::spawn_blocking(move || {
            archive::read_archive_entry_blocking(&archive_path, "manifest.json")
        })
        .await??;
        (bytes, None)
    };

    let mut manifest: abyssal_core::BackupManifest = serde_json::from_slice(&manifest_bytes)?;
    // The manifest embedded *inside* the archive is necessarily written
    // before encryption happens (see provider::NativeProvider::create),
    // so its own `encryption` field is always `None`, encrypted archive
    // or not. Restore (`reliquary_backup::restore::restore`) decides
    // whether to decrypt based on this field, so it's overwritten here
    // with the real metadata this function just used to decrypt the
    // archive -- otherwise `reliquary backup restore` would silently
    // skip decryption and try to extract raw ciphertext as a tar stream.
    if let Some(metadata) = encryption_metadata {
        manifest.encryption = Some(metadata);
    }
    Ok(manifest)
}

/// The encryption header (nonce prefix + salt) is a fixed-size prefix of
/// the encrypted file itself -- read directly, no manifest needed yet.
async fn read_salt_into_metadata(
    path: &std::path::Path,
    mut metadata: abyssal_core::EncryptionMetadata,
) -> anyhow::Result<abyssal_core::EncryptionMetadata> {
    use base64::Engine as _;
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut header = [0u8; 7 + 16]; // nonce prefix + salt, see crypto.rs
    file.read_exact(&mut header).await?;
    let salt = &header[7..];
    metadata.kdf_salt_base64 = base64::engine::general_purpose::STANDARD.encode(salt);
    Ok(metadata)
}

async fn list() -> anyhow::Result<()> {
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;
    let pool = abyssal_database::connect(&database_url).await?;
    let jobs = abyssal_database::repo::reliquary_backups::list(&pool).await?;
    if jobs.is_empty() {
        println!("No backups recorded.");
        return Ok(());
    }
    println!(
        "{:<38} {:<10} {:<20} {:>12}  {:<10}  FILE",
        "ID", "STATUS", "CREATED", "SIZE", "DESTINATION"
    );
    for job in jobs {
        // Only a `local` destination has a real file this CLI's own
        // `verify`/`restore` subcommands can actually point at -- a
        // Sepulchre-backed job is listed for visibility, but downloading
        // its archive back off the connection isn't supported yet (see
        // docs/sepulchre.md).
        let destination = if job.destination_connection_id.is_some() {
            "sepulchre"
        } else {
            "local"
        };
        println!(
            "{:<38} {:<10} {:<20} {:>12}  {:<10}  {}",
            job.id,
            job.status.as_str(),
            job.created_at.format("%Y-%m-%d %H:%M:%S"),
            job.size_bytes.map(|b| b.to_string()).unwrap_or_default(),
            destination,
            job.file_name.unwrap_or_default(),
        );
    }
    Ok(())
}

async fn verify(args: ArchiveArgs) -> anyhow::Result<()> {
    if !args.archive.is_file() {
        anyhow::bail!("no such file: {}", args.archive.display());
    }
    let manifest = read_manifest(&args).await?;
    println!("Archive:            {}", args.archive.display());
    println!("Manifest version:   {}", manifest.manifest_version);
    println!("Backup ID:          {}", manifest.backup_id);
    println!("Created at:         {}", manifest.created_at);
    println!("Arsenal version:    {}", manifest.arsenal_version);
    println!("Schema version:     {}", manifest.schema_migration_version);
    println!("MariaDB version:    {}", manifest.mariadb_version);
    println!(
        "Components:         {}",
        manifest
            .components
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Encrypted:          {}", manifest.encryption.is_some());
    println!(
        "Entries:             {} ({} bytes total)",
        manifest.entries.len(),
        manifest.entries.iter().map(|e| e.size_bytes).sum::<u64>()
    );
    println!("\nArchive is readable and its manifest is well-formed.");
    Ok(())
}

async fn restore(args: ArchiveArgs) -> anyhow::Result<()> {
    if !args.archive.is_file() {
        anyhow::bail!("no such file: {}", args.archive.display());
    }
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;
    let passphrase = read_passphrase(&args).await?;
    let manifest = read_manifest(&args).await?;

    if manifest.encryption.is_some() && passphrase.is_none() {
        anyhow::bail!(
            "this archive is encrypted -- pass --passphrase-file <path to a file containing the \
             passphrase>"
        );
    }

    println!(
        "Restoring backup {} (created {}) into the database at DATABASE_URL...",
        manifest.backup_id, manifest.created_at
    );

    let work_dir = std::env::temp_dir().join(format!("reliquary-restore-{}", uuid::Uuid::new_v4()));
    let cancel = tokio_util::sync::CancellationToken::new();
    let storage = abyssal_web::reliquary_backup::storage::LocalFs::new(
        args.archive
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")),
    );
    let file_name = args
        .archive
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("archive path has no file name"))?
        .to_string();

    let maintenance = restore_engine::MaintenanceMode::default();
    let result = restore_engine::restore(
        &storage,
        &maintenance,
        restore_engine::RestoreRequest {
            file_name: &file_name,
            manifest: &manifest,
            components: &manifest.components,
            passphrase: passphrase.map(zeroize::Zeroizing::new),
            database_url: &database_url,
            work_dir: &work_dir,
        },
        &cancel,
    )
    .await;
    tokio::fs::remove_dir_all(&work_dir).await.ok();

    match result {
        Ok(()) => {
            println!("Restore completed successfully.");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("restore failed: {e}")),
    }
}
