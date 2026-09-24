//! Native (control-plane) backups -- GitHub issue #9. Pure data types
//! only; the actual dump/archive/encrypt/restore engine
//! (`crates/web/src/reliquary_backup/`) is IO-heavy and doesn't belong in
//! this crate, same split every other feature this session used (e.g.
//! `Macro`/`MacroType` here, the macro engine itself in `crates/web`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `native` (this feature) vs. a future `remote` (agent-backed, out of
/// scope for GitHub issue #9 -- see `BackupProvider`). Stored as its
/// `as_str()` key, same reasoning as every other stored-enum in this
/// codebase: adding `Remote` later never needs a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupJobType {
    Native,
    Remote,
}

impl BackupJobType {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupJobType::Native => "native",
            BackupJobType::Remote => "remote",
        }
    }
}

impl std::str::FromStr for BackupJobType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "native" => Ok(BackupJobType::Native),
            "remote" => Ok(BackupJobType::Remote),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Verifying,
    Verified,
    Cancelled,
}

impl BackupStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupStatus::Queued => "queued",
            BackupStatus::Running => "running",
            BackupStatus::Succeeded => "succeeded",
            BackupStatus::Failed => "failed",
            BackupStatus::Verifying => "verifying",
            BackupStatus::Verified => "verified",
            BackupStatus::Cancelled => "cancelled",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            BackupStatus::Queued => "Queued",
            BackupStatus::Running => "Running",
            BackupStatus::Succeeded => "Succeeded",
            BackupStatus::Failed => "Failed",
            BackupStatus::Verifying => "Verifying",
            BackupStatus::Verified => "Verified",
            BackupStatus::Cancelled => "Cancelled",
        }
    }

    /// Whether this status represents a finished attempt -- a job in one
    /// of these will never transition again. Used by the interrupted-job
    /// sweep at startup (anything NOT terminal after a crash is stuck,
    /// not actually still running) and by retention pruning (only
    /// terminal jobs are eligible to prune).
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            BackupStatus::Succeeded
                | BackupStatus::Failed
                | BackupStatus::Verified
                | BackupStatus::Cancelled
        )
    }
}

impl std::str::FromStr for BackupStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(BackupStatus::Queued),
            "running" => Ok(BackupStatus::Running),
            "succeeded" => Ok(BackupStatus::Succeeded),
            "failed" => Ok(BackupStatus::Failed),
            "verifying" => Ok(BackupStatus::Verifying),
            "verified" => Ok(BackupStatus::Verified),
            "cancelled" => Ok(BackupStatus::Cancelled),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupTrigger {
    Manual,
    Scheduled,
}

impl BackupTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupTrigger::Manual => "manual",
            BackupTrigger::Scheduled => "scheduled",
        }
    }
}

impl std::str::FromStr for BackupTrigger {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "manual" => Ok(BackupTrigger::Manual),
            "scheduled" => Ok(BackupTrigger::Scheduled),
            _ => Err(()),
        }
    }
}

/// One selectable piece of a backup -- what the create-backup form's
/// checkboxes and a restore's component picker both operate on.
/// `EncryptionKeys` is opt-in and, per GitHub issue #9's explicit
/// requirement, forces `encrypted = true` on the whole archive regardless
/// of the backup's own encryption setting -- enforced in
/// `reliquary_backup::orchestrator`, not just the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupComponent {
    Database,
    Configuration,
    EncryptionKeys,
    AuditLogs,
}

impl BackupComponent {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupComponent::Database => "database",
            BackupComponent::Configuration => "configuration",
            BackupComponent::EncryptionKeys => "encryption_keys",
            BackupComponent::AuditLogs => "audit_logs",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            BackupComponent::Database => "Application database",
            BackupComponent::Configuration => "Control-plane configuration",
            BackupComponent::EncryptionKeys => "Encryption keys (always encrypted)",
            BackupComponent::AuditLogs => "Audit logs",
        }
    }

    pub const ALL: &'static [BackupComponent] = &[
        BackupComponent::Database,
        BackupComponent::Configuration,
        BackupComponent::EncryptionKeys,
        BackupComponent::AuditLogs,
    ];
}

impl std::str::FromStr for BackupComponent {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "database" => Ok(BackupComponent::Database),
            "configuration" => Ok(BackupComponent::Configuration),
            "encryption_keys" => Ok(BackupComponent::EncryptionKeys),
            "audit_logs" => Ok(BackupComponent::AuditLogs),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    QuickPassed,
    QuickFailed,
    DeepPassed,
    DeepFailed,
}

impl VerificationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            VerificationStatus::QuickPassed => "quick_passed",
            VerificationStatus::QuickFailed => "quick_failed",
            VerificationStatus::DeepPassed => "deep_passed",
            VerificationStatus::DeepFailed => "deep_failed",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            VerificationStatus::QuickPassed => "Verified (quick)",
            VerificationStatus::QuickFailed => "Quick verify failed",
            VerificationStatus::DeepPassed => "Verified (deep)",
            VerificationStatus::DeepFailed => "Deep verify failed",
        }
    }

    /// Whether this counts as "a verified backup" for the retention
    /// pruner's "never delete the only remaining verified backup" rule.
    pub const fn is_passing(self) -> bool {
        matches!(
            self,
            VerificationStatus::QuickPassed | VerificationStatus::DeepPassed
        )
    }
}

impl std::str::FromStr for VerificationStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "quick_passed" => Ok(VerificationStatus::QuickPassed),
            "quick_failed" => Ok(VerificationStatus::QuickFailed),
            "deep_passed" => Ok(VerificationStatus::DeepPassed),
            "deep_failed" => Ok(VerificationStatus::DeepFailed),
            _ => Err(()),
        }
    }
}

/// One backup attempt, successful or not -- the durable row behind
/// everything the Reliquary "Application Data"/"Verification & Recovery"
/// pages show. `manifest` is only `Some` once the archive itself exists
/// (a `Queued`/`Running`/early-`Failed` job has none yet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJob {
    pub id: Uuid,
    pub job_type: BackupJobType,
    pub status: BackupStatus,
    pub trigger_source: BackupTrigger,
    pub components: Vec<BackupComponent>,
    pub encrypted: bool,
    pub includes_encryption_keys: bool,
    pub destination_path: String,
    /// `None` means the local destination
    /// (`RELIQUARY_BACKUP_DESTINATION_PATH`); `Some` is the Sepulchre
    /// connection this backup was actually written through.
    pub destination_connection_id: Option<Uuid>,
    pub file_name: Option<String>,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub manifest: Option<BackupManifest>,
    pub error_message: Option<String>,
    pub verification_status: Option<VerificationStatus>,
    pub verification_at: Option<DateTime<Utc>>,
    pub verification_details: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// A component's checksum, recorded per top-level entry the archive
/// contains (the database dump file, the config snapshot file, ...) --
/// coarser than a full per-file manifest of every tar entry (which would
/// duplicate what the tar/gzip layer already guarantees the integrity
/// of), but enough to answer "did the *database dump specifically*
/// survive transport intact" independent of the archive's own overall
/// checksum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// The versioned metadata written into every backup archive as
/// `manifest.json`, and mirrored onto the `BackupJob` row for display
/// without needing to reopen the archive. `manifest_version` is checked
/// on restore (`reliquary_backup::restore`) before anything else --
/// GitHub issue #9's "compare manifest schema version with current."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub manifest_version: u32,
    pub backup_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub arsenal_version: String,
    /// The highest applied `sqlx` migration version at backup time (see
    /// `crates/database/src/pool.rs`) -- what a restore compares against
    /// the *target* database's own applied migrations before deciding
    /// whether to run migrations forward or refuse.
    pub schema_migration_version: i64,
    pub mariadb_version: String,
    pub mariadb_charset: String,
    pub mariadb_collation: String,
    pub mariadb_sql_mode: String,
    pub components: Vec<BackupComponent>,
    /// When the database dump itself started/finished, separate from the
    /// archive's own overall `created_at` -- GitHub issue #9's
    /// "record both timestamps... note any drift risk between DB rows
    /// and uploaded files." Files are archived immediately after the dump
    /// completes; the gap between `database_dump_finished_at` and
    /// `created_at` is that drift window.
    pub database_dump_started_at: DateTime<Utc>,
    pub database_dump_finished_at: DateTime<Utc>,
    pub entries: Vec<ManifestEntry>,
    pub archive_sha256: String,
    /// `None` for an unencrypted archive. Never contains the key/passphrase
    /// itself -- only enough to derive it again from a passphrase the
    /// operator supplies at restore time.
    pub encryption: Option<EncryptionMetadata>,
    /// Container image references this deployment was running at backup
    /// time (image name:tag, digest if resolvable) -- recorded, never
    /// backed up as actual image data (GitHub issue #9: "Container
    /// images: No. Record image references/tags/digests in the
    /// manifest.").
    pub image_references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub kdf: String,
    pub kdf_salt_base64: String,
    pub kdf_params: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> BackupManifest {
        BackupManifest {
            manifest_version: 1,
            backup_id: Uuid::new_v4(),
            created_at: Utc::now(),
            arsenal_version: "0.1.2".to_string(),
            schema_migration_version: 18,
            mariadb_version: "11.4.2-MariaDB".to_string(),
            mariadb_charset: "utf8mb4".to_string(),
            mariadb_collation: "utf8mb4_general_ci".to_string(),
            mariadb_sql_mode: "STRICT_TRANS_TABLES".to_string(),
            components: vec![
                BackupComponent::Database,
                BackupComponent::Configuration,
                BackupComponent::AuditLogs,
            ],
            database_dump_started_at: Utc::now(),
            database_dump_finished_at: Utc::now(),
            entries: vec![ManifestEntry {
                path: "db.sql".to_string(),
                sha256: "a".repeat(64),
                size_bytes: 12345,
            }],
            archive_sha256: "b".repeat(64),
            encryption: Some(EncryptionMetadata {
                algorithm: "aes-256-gcm-stream-be32".to_string(),
                kdf: "argon2id".to_string(),
                kdf_salt_base64: "c29tZXNhbHQ=".to_string(),
                kdf_params: "m=19456,t=2,p=1".to_string(),
            }),
            image_references: vec!["abyssal-arsenal:0.1.2".to_string()],
        }
    }

    #[test]
    fn manifest_json_round_trip_preserves_every_field() {
        let original = sample_manifest();
        let json = serde_json::to_vec_pretty(&original).expect("serialize");
        let restored: BackupManifest = serde_json::from_slice(&json).expect("deserialize");

        assert_eq!(restored.manifest_version, original.manifest_version);
        assert_eq!(restored.backup_id, original.backup_id);
        assert_eq!(restored.arsenal_version, original.arsenal_version);
        assert_eq!(
            restored.schema_migration_version,
            original.schema_migration_version
        );
        assert_eq!(restored.mariadb_version, original.mariadb_version);
        assert_eq!(restored.components.len(), original.components.len());
        assert_eq!(restored.entries.len(), original.entries.len());
        assert_eq!(restored.entries[0].sha256, original.entries[0].sha256);
        assert_eq!(restored.archive_sha256, original.archive_sha256);
        assert_eq!(
            restored.encryption.as_ref().map(|e| e.algorithm.clone()),
            original.encryption.as_ref().map(|e| e.algorithm.clone())
        );
        assert_eq!(restored.image_references, original.image_references);
    }

    #[test]
    fn manifest_without_encryption_round_trips_none() {
        let mut original = sample_manifest();
        original.encryption = None;
        let json = serde_json::to_vec(&original).expect("serialize");
        let restored: BackupManifest = serde_json::from_slice(&json).expect("deserialize");
        assert!(restored.encryption.is_none());
    }

    #[test]
    fn component_as_str_round_trips_through_from_str() {
        for component in BackupComponent::ALL {
            let s = component.as_str();
            let parsed: BackupComponent = s.parse().expect("known component key must parse");
            assert_eq!(parsed, *component);
        }
    }
}
