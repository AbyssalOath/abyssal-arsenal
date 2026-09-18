use thiserror::Error;

/// Unified application error. Every layer maps its own errors into this type so
/// handlers have one place to decide status codes / user-facing messages.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,

    #[error("authentication required")]
    Unauthenticated,

    /// Authorization denied. Always fail closed: this is also returned when the
    /// permission set could not be resolved at all (e.g. a database error), never
    /// silently allowed.
    #[error("permission denied")]
    Forbidden,

    /// The authenticated user has `must_change_password` set (an admin
    /// created their account with a temporary password) and hasn't changed
    /// it yet. Distinct from `Forbidden`: the caller is who they say they
    /// are, they just can't do anything else until this is resolved.
    #[error("password change required")]
    MustChangePassword,

    #[error("invalid request: {0}")]
    Validation(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type AppResult<T> = Result<T, AppError>;
