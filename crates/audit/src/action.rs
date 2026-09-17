/// Every security-sensitive action the platform records. New actions should be
/// added here rather than as free-form strings scattered across handlers, so
/// the audit viewer's action filter always has a complete, typo-proof list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    UserCreated,
    UserEnabled,
    UserDisabled,
    UserDeleted,
    SessionsRevoked,
    RoleChanged,
    LoginSuccess,
    LoginFailure,
    Logout,
    PasswordChanged,
    SsoLogin,
    ModuleEnabled,
    ModuleDisabled,
    SystemCommandExecuted,
    ConfigurationChanged,
    AuditExported,
    SecretAccessed,
    BackupCreated,
    BackupRestored,
    HostEnrolled,
    HostRevoked,
    HostRemoved,
    HostElevated,
    HostElevationFailed,
    HostDeescalated,
    HostElevationExpired,
}

impl AuditAction {
    pub const fn as_key(self) -> &'static str {
        match self {
            AuditAction::UserCreated => "USER_CREATED",
            AuditAction::UserEnabled => "USER_ENABLED",
            AuditAction::UserDisabled => "USER_DISABLED",
            AuditAction::UserDeleted => "USER_DELETED",
            AuditAction::SessionsRevoked => "SESSIONS_REVOKED",
            AuditAction::RoleChanged => "ROLE_CHANGED",
            AuditAction::LoginSuccess => "LOGIN_SUCCESS",
            AuditAction::LoginFailure => "LOGIN_FAILURE",
            AuditAction::Logout => "LOGOUT",
            AuditAction::PasswordChanged => "PASSWORD_CHANGED",
            AuditAction::SsoLogin => "SSO_LOGIN",
            AuditAction::ModuleEnabled => "MODULE_ENABLED",
            AuditAction::ModuleDisabled => "MODULE_DISABLED",
            AuditAction::SystemCommandExecuted => "SYSTEM_COMMAND_EXECUTED",
            AuditAction::ConfigurationChanged => "CONFIGURATION_CHANGED",
            AuditAction::AuditExported => "AUDIT_EXPORTED",
            AuditAction::SecretAccessed => "SECRET_ACCESSED",
            AuditAction::BackupCreated => "BACKUP_CREATED",
            AuditAction::BackupRestored => "BACKUP_RESTORED",
            AuditAction::HostEnrolled => "HOST_ENROLLED",
            AuditAction::HostRevoked => "HOST_REVOKED",
            AuditAction::HostRemoved => "HOST_REMOVED",
            AuditAction::HostElevated => "HOST_ELEVATED",
            AuditAction::HostElevationFailed => "HOST_ELEVATION_FAILED",
            AuditAction::HostDeescalated => "HOST_DEESCALATED",
            AuditAction::HostElevationExpired => "HOST_ELEVATION_EXPIRED",
        }
    }

    pub const ALL: &'static [AuditAction] = &[
        AuditAction::UserCreated,
        AuditAction::UserEnabled,
        AuditAction::UserDisabled,
        AuditAction::UserDeleted,
        AuditAction::SessionsRevoked,
        AuditAction::RoleChanged,
        AuditAction::LoginSuccess,
        AuditAction::LoginFailure,
        AuditAction::Logout,
        AuditAction::PasswordChanged,
        AuditAction::SsoLogin,
        AuditAction::ModuleEnabled,
        AuditAction::ModuleDisabled,
        AuditAction::SystemCommandExecuted,
        AuditAction::ConfigurationChanged,
        AuditAction::AuditExported,
        AuditAction::SecretAccessed,
        AuditAction::BackupCreated,
        AuditAction::BackupRestored,
        AuditAction::HostEnrolled,
        AuditAction::HostRevoked,
        AuditAction::HostRemoved,
        AuditAction::HostElevated,
        AuditAction::HostElevationFailed,
        AuditAction::HostDeescalated,
        AuditAction::HostElevationExpired,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure,
}

impl AuditOutcome {
    pub const fn as_key(self) -> &'static str {
        match self {
            AuditOutcome::Success => "SUCCESS",
            AuditOutcome::Failure => "FAILURE",
        }
    }
}
