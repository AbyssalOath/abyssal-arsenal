//! Sepulchre: storage & file-sharing connectivity (SFTP/SMB/local
//! connections, shares, mounts, and validation). Pure domain types only --
//! same split every other feature this session used (e.g. `BackupJob`/
//! `BackupManifest` here, the actual dump/archive/protocol engine in
//! `crates/web/src/sepulchre/`).
//!
//! Three concepts are kept deliberately separate and never conflated:
//! **protocol** (what the endpoint speaks -- [`Protocol`]), **access
//! method** (how a given execution context reaches it -- [`AccessMethod`]),
//! and **role** (what the connection is *for* -- [`ConnectionRole`]). A
//! connection is never inherently a backup connection: Reliquary (or any
//! other consumer) asks the resolver for a connection by role plus the
//! [`Capability`] set it needs, never by protocol or method.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What the remote endpoint speaks. `#[non_exhaustive]` and deliberately
/// without a `Default` impl -- adding `Nfs`/`WebDav`/`S3` later must force
/// every `match` on this type to be revisited by the compiler, not
/// silently fall through to a wrong branch. Only `Sftp`/`Smb`/`Local` are
/// implemented; the others are reserved (see `docs/sepulchre.md`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Sftp,
    Smb,
    Local,
}

impl Protocol {
    pub const ALL: &'static [Protocol] = &[Protocol::Sftp, Protocol::Smb, Protocol::Local];

    pub const fn as_str(self) -> &'static str {
        match self {
            Protocol::Sftp => "sftp",
            Protocol::Smb => "smb",
            Protocol::Local => "local",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Protocol::Sftp => "SFTP",
            Protocol::Smb => "SMB",
            Protocol::Local => "Local filesystem",
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sftp" => Ok(Protocol::Sftp),
            "smb" => Ok(Protocol::Smb),
            "local" => Ok(Protocol::Local),
            _ => Err(()),
        }
    }
}

/// Where a connection's host side lives. `ControlPlane` connections reach
/// out from this process itself (a remote SFTP/SMB server, or a `Local`
/// path inside an allowed root); `HostSideManaged` connections are
/// provisioned by Sepulchre onto a managed host (that host runs the SFTP/
/// SMB *server*, or is the client side of an SSHFS/CIFS mount) and carry a
/// real `managed_host_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionOrigin {
    ControlPlane,
    HostSideManaged,
}

impl ConnectionOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            ConnectionOrigin::ControlPlane => "control_plane",
            ConnectionOrigin::HostSideManaged => "host_side_managed",
        }
    }
}

impl std::str::FromStr for ConnectionOrigin {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "control_plane" => Ok(ConnectionOrigin::ControlPlane),
            "host_side_managed" => Ok(ConnectionOrigin::HostSideManaged),
            _ => Err(()),
        }
    }
}

/// What a connection is *for*. Many-to-many with a connection
/// (`connection_roles`) -- e.g. a connection can be both `RemoteStorage`
/// and `BackupDestination` at once. Extensible: adding a role is additive,
/// not a breaking enum change for consumers that only check for the one
/// role they care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionRole {
    BackupDestination,
    FileTransfer,
    RemoteStorage,
    Other,
}

impl ConnectionRole {
    pub const ALL: &'static [ConnectionRole] = &[
        ConnectionRole::BackupDestination,
        ConnectionRole::FileTransfer,
        ConnectionRole::RemoteStorage,
        ConnectionRole::Other,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ConnectionRole::BackupDestination => "backup_destination",
            ConnectionRole::FileTransfer => "file_transfer",
            ConnectionRole::RemoteStorage => "remote_storage",
            ConnectionRole::Other => "other",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            ConnectionRole::BackupDestination => "Backup destination",
            ConnectionRole::FileTransfer => "File transfer",
            ConnectionRole::RemoteStorage => "Remote storage",
            ConnectionRole::Other => "Other",
        }
    }
}

impl std::str::FromStr for ConnectionRole {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "backup_destination" => Ok(ConnectionRole::BackupDestination),
            "file_transfer" => Ok(ConnectionRole::FileTransfer),
            "remote_storage" => Ok(ConnectionRole::RemoteStorage),
            "other" => Ok(ConnectionRole::Other),
            _ => Err(()),
        }
    }
}

/// What a connection can actually *do*. `declared` (the admin's stated
/// intent) is tracked separately from *verified* (only ever set by a
/// successful validation run) -- see [`ConnectionCapability`]. A consumer
/// must only ever rely on verified capabilities, never declared-only
/// ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    Read,
    List,
    Write,
    Delete,
}

impl Capability {
    pub const ALL: &'static [Capability] = &[
        Capability::Read,
        Capability::List,
        Capability::Write,
        Capability::Delete,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Read => "read",
            Capability::List => "list",
            Capability::Write => "write",
            Capability::Delete => "delete",
        }
    }
}

impl std::str::FromStr for Capability {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Capability::Read),
            "list" => Ok(Capability::List),
            "write" => Ok(Capability::Write),
            "delete" => Ok(Capability::Delete),
            _ => Err(()),
        }
    }
}

/// A capability's declared-vs-verified state for one connection. Declared
/// is the admin's intent (checked at connection setup); verified is only
/// ever set by a successful validation run's read/write test and cleared
/// by a failure or regression -- see `docs/sepulchre.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionCapability {
    pub capability: Capability,
    pub declared: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_by_validation_run_id: Option<Uuid>,
}

impl ConnectionCapability {
    pub const fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }
}

/// *How* a given execution context reaches a connection. Never conflated
/// with [`Protocol`]: SFTP alone has three real methods (native client,
/// SSHFS mount, rsync-over-ssh).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessMethod {
    /// Direct application-level client (the control plane's own SFTP/SMB/
    /// local I/O) -- streaming, no subprocess mount, no filesystem path
    /// exposed to the OS.
    NativeClient,
    /// A real filesystem mount (SSHFS or CIFS) -- always host-side, never
    /// in the control-plane container (which must never perform kernel
    /// mounts).
    Mount,
    /// Incremental replication via `rsync` over SSH, run on a managed
    /// host through the executor. Modeled (capability flag only) in this
    /// pass -- see `docs/sepulchre.md` for why it's not implemented.
    RsyncSsh,
    /// A diagnostic-only client used for validation/troubleshooting
    /// (today, SMB's `smbclient` invocation doubles as both the native
    /// client and the diagnostic path -- see `backend::smb`).
    DiagnosticClient,
}

impl AccessMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            AccessMethod::NativeClient => "native_client",
            AccessMethod::Mount => "mount",
            AccessMethod::RsyncSsh => "rsync_ssh",
            AccessMethod::DiagnosticClient => "diagnostic_client",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            AccessMethod::NativeClient => "Native client",
            AccessMethod::Mount => "Filesystem mount",
            AccessMethod::RsyncSsh => "rsync over SSH",
            AccessMethod::DiagnosticClient => "Diagnostic client",
        }
    }

    /// Which execution context(s) this method may run in. The API and UI
    /// both enforce this -- a `Mount` can never be configured for
    /// `ControlPlane` context, since this process must never perform a
    /// kernel mount itself.
    pub const fn valid_contexts(self) -> &'static [ExecutionContext] {
        match self {
            AccessMethod::NativeClient | AccessMethod::DiagnosticClient => {
                &[ExecutionContext::ControlPlane]
            }
            AccessMethod::Mount | AccessMethod::RsyncSsh => &[ExecutionContext::ManagedHost],
        }
    }
}

impl std::str::FromStr for AccessMethod {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "native_client" => Ok(AccessMethod::NativeClient),
            "mount" => Ok(AccessMethod::Mount),
            "rsync_ssh" => Ok(AccessMethod::RsyncSsh),
            "diagnostic_client" => Ok(AccessMethod::DiagnosticClient),
            _ => Err(()),
        }
    }
}

/// Where an access method executes -- see [`AccessMethod::valid_contexts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionContext {
    ControlPlane,
    ManagedHost,
}

impl ExecutionContext {
    pub const fn as_str(self) -> &'static str {
        match self {
            ExecutionContext::ControlPlane => "control_plane",
            ExecutionContext::ManagedHost => "managed_host",
        }
    }
}

impl std::str::FromStr for ExecutionContext {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "control_plane" => Ok(ExecutionContext::ControlPlane),
            "managed_host" => Ok(ExecutionContext::ManagedHost),
            _ => Err(()),
        }
    }
}

/// One access method enabled for a connection, and the context it runs
/// in (`ManagedHost` methods additionally carry which host).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionAccessMethod {
    pub method: AccessMethod,
    pub context: ExecutionContext,
    pub managed_host_id: Option<Uuid>,
}

/// SFTP authentication method -- password or an SSH key (see the
/// amendment: control-plane SFTP keys are imported or generated *by*
/// Sepulchre, never routed through Cryptkeeper's host-side keypair
/// generation, since that would write the key onto a managed host's
/// filesystem instead of holding it here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SftpAuthMethod {
    Password,
    SshKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SftpConfig {
    pub host: String,
    pub port: u16,
    pub base_path: String,
    pub auth_method: SftpAuthMethod,
    pub username: String,
    /// SHA256 SSH host key fingerprint, pinned at first connect (or
    /// automatically, for a `HostSideManaged` connection -- see
    /// `docs/sepulchre.md`'s "host key pinning" section). `None` only
    /// before the first successful connect.
    pub pinned_host_key_fingerprint: Option<String>,
    pub connect_timeout_secs: u32,
    pub read_timeout_secs: u32,
}

/// SMB protocol minimum -- fixed at SMB3 for now (no SMB1, ever). An enum
/// (not a bool) so a future SMB3.1.1-specific requirement doesn't need a
/// schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmbMinProtocol {
    Smb3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmbEncryption {
    Off,
    IfSupported,
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbConfig {
    pub host: String,
    pub port: u16,
    pub share_name: String,
    pub subpath: String,
    pub username: String,
    /// Plain NTLMv2/local-account auth only -- no Kerberos/AD (non-goal).
    pub domain: Option<String>,
    pub min_protocol: SmbMinProtocol,
    pub signing_required: bool,
    pub encryption: SmbEncryption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    /// Must resolve inside a `SEPULCHRE_LOCAL_ROOTS`-allowed root --
    /// enforced at connection-create time and again on every I/O
    /// operation, never trusted from the stored value alone. See
    /// `sepulchre::backend::local` for the containment/TOCTOU defense.
    pub path: String,
    pub create_if_missing: bool,
    pub expected_mode: Option<u32>,
}

/// One connection's protocol-specific configuration, tagged by protocol
/// so `serde` round-trips it as a single JSON column
/// (`storage_connections.protocol_config`) without three near-empty
/// per-protocol tables -- the same JSON-column-plus-Rust-enum convention
/// `BackupManifest`'s `components`/`encryption` fields already use in
/// this codebase. Always validated against `protocol` before being
/// persisted -- never trusted as pre-validated just because it
/// deserialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum ProtocolConfig {
    Sftp(SftpConfig),
    Smb(SmbConfig),
    Local(LocalConfig),
}

impl ProtocolConfig {
    pub const fn protocol(&self) -> Protocol {
        match self {
            ProtocolConfig::Sftp(_) => Protocol::Sftp,
            ProtocolConfig::Smb(_) => Protocol::Smb,
            ProtocolConfig::Local(_) => Protocol::Local,
        }
    }
}

/// Stable error-kind enum surfaced by validation -- used by the UI, and
/// by workflow-registry conditions (`error_kind == "..."`), so these
/// strings are a real, load-bearing interface, not just a display label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Unreachable,
    Timeout,
    DnsFailure,
    AuthFailed,
    HostKeyMismatch,
    PermissionDenied,
    NotFound,
    ReadOnly,
    ProtocolUnsupported,
    /// A required client/tool isn't available (e.g. `smbclient` missing
    /// from the image, or `cifs-utils` missing on a managed host).
    MethodUnavailable,
    /// A `Local` connection's path doesn't resolve inside any
    /// `SEPULCHRE_LOCAL_ROOTS` entry.
    PathNotAllowed,
    Unknown,
}

impl ErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Unreachable => "unreachable",
            ErrorKind::Timeout => "timeout",
            ErrorKind::DnsFailure => "dns_failure",
            ErrorKind::AuthFailed => "auth_failed",
            ErrorKind::HostKeyMismatch => "host_key_mismatch",
            ErrorKind::PermissionDenied => "permission_denied",
            ErrorKind::NotFound => "not_found",
            ErrorKind::ReadOnly => "read_only",
            ErrorKind::ProtocolUnsupported => "protocol_unsupported",
            ErrorKind::MethodUnavailable => "method_unavailable",
            ErrorKind::PathNotAllowed => "path_not_allowed",
            ErrorKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMode {
    ReadOnly,
    ReadWrite,
}

impl ValidationMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ValidationMode::ReadOnly => "read_only",
            ValidationMode::ReadWrite => "read_write",
        }
    }
}

impl std::str::FromStr for ValidationMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read_only" => Ok(ValidationMode::ReadOnly),
            "read_write" => Ok(ValidationMode::ReadWrite),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Ok,
    Failed,
    Skipped,
}

impl ValidationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            ValidationStatus::Ok => "ok",
            ValidationStatus::Failed => "failed",
            ValidationStatus::Skipped => "skipped",
        }
    }
}

impl std::str::FromStr for ValidationStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ok" => Ok(ValidationStatus::Ok),
            "failed" => Ok(ValidationStatus::Failed),
            "skipped" => Ok(ValidationStatus::Skipped),
            _ => Err(()),
        }
    }
}

/// One check's result within a validation run -- method-aware (Phase 1B):
/// a connection with both `native_client` and a host `mount` enabled
/// validates each independently, since either can fail without the
/// other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCheckResult {
    pub check: String,
    pub method: Option<AccessMethod>,
    pub status: ValidationStatus,
    pub error_kind: Option<ErrorKind>,
    pub message: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRun {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub mode: ValidationMode,
    pub checks: Vec<ValidationCheckResult>,
    pub overall_status: ValidationStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub triggered_by: Option<Uuid>,
}

/// A reason a connection isn't usable by a consumer right now -- returned
/// by the resolver instead of a bare bool, so a consumer (e.g. Reliquary)
/// can show the operator exactly what's wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotUsableReason {
    Disabled,
    MissingRole(ConnectionRole),
    CapabilityUnverified(Capability),
    ValidationStale,
    ValidationFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConnection {
    pub id: Uuid,
    pub name: String,
    pub protocol: Protocol,
    pub origin: ConnectionOrigin,
    pub managed_host_id: Option<Uuid>,
    pub protocol_config: ProtocolConfig,
    pub enabled: bool,
    pub last_validation_status: Option<ValidationStatus>,
    pub last_validation_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_as_str_round_trips_through_from_str() {
        for protocol in Protocol::ALL {
            let parsed: Protocol = protocol.as_str().parse().expect("known key must parse");
            assert_eq!(parsed, *protocol);
        }
    }

    #[test]
    fn connection_role_as_str_round_trips_through_from_str() {
        for role in ConnectionRole::ALL {
            let parsed: ConnectionRole = role.as_str().parse().expect("known key must parse");
            assert_eq!(parsed, *role);
        }
    }

    #[test]
    fn capability_as_str_round_trips_through_from_str() {
        for cap in Capability::ALL {
            let parsed: Capability = cap.as_str().parse().expect("known key must parse");
            assert_eq!(parsed, *cap);
        }
    }

    #[test]
    fn access_method_as_str_round_trips_through_from_str() {
        for method in [
            AccessMethod::NativeClient,
            AccessMethod::Mount,
            AccessMethod::RsyncSsh,
            AccessMethod::DiagnosticClient,
        ] {
            let parsed: AccessMethod = method.as_str().parse().expect("known key must parse");
            assert_eq!(parsed, method);
        }
    }

    #[test]
    fn mount_and_rsync_are_managed_host_only() {
        assert_eq!(
            AccessMethod::Mount.valid_contexts(),
            &[ExecutionContext::ManagedHost]
        );
        assert_eq!(
            AccessMethod::RsyncSsh.valid_contexts(),
            &[ExecutionContext::ManagedHost]
        );
    }

    #[test]
    fn native_client_and_diagnostic_are_control_plane_only() {
        assert_eq!(
            AccessMethod::NativeClient.valid_contexts(),
            &[ExecutionContext::ControlPlane]
        );
        assert_eq!(
            AccessMethod::DiagnosticClient.valid_contexts(),
            &[ExecutionContext::ControlPlane]
        );
    }

    #[test]
    fn protocol_config_reports_its_own_protocol() {
        let sftp = ProtocolConfig::Sftp(SftpConfig {
            host: "example.com".to_string(),
            port: 22,
            base_path: "/uploads".to_string(),
            auth_method: SftpAuthMethod::SshKey,
            username: "backup".to_string(),
            pinned_host_key_fingerprint: None,
            connect_timeout_secs: 10,
            read_timeout_secs: 30,
        });
        assert_eq!(sftp.protocol(), Protocol::Sftp);
    }

    #[test]
    fn protocol_config_json_round_trip_preserves_the_tag() {
        let local = ProtocolConfig::Local(LocalConfig {
            path: "/backups/sepulchre".to_string(),
            create_if_missing: true,
            expected_mode: Some(0o700),
        });
        let json = serde_json::to_value(&local).unwrap();
        assert_eq!(json["protocol"], "local");
        let restored: ProtocolConfig = serde_json::from_value(json).unwrap();
        assert_eq!(restored.protocol(), Protocol::Local);
    }

    #[test]
    fn connection_capability_is_verified_matches_timestamp_presence() {
        let unverified = ConnectionCapability {
            capability: Capability::Write,
            declared: true,
            verified_at: None,
            verified_by_validation_run_id: None,
        };
        assert!(!unverified.is_verified());

        let verified = ConnectionCapability {
            verified_at: Some(Utc::now()),
            verified_by_validation_run_id: Some(Uuid::new_v4()),
            ..unverified
        };
        assert!(verified.is_verified());
    }
}
