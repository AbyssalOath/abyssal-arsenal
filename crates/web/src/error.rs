use abyssal_core::AppError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

/// Newtype so we can implement `IntoResponse` for `AppError` despite both
/// being defined outside this crate (Rust's orphan rule requires it).
pub struct WebError(pub AppError);

impl From<AppError> for WebError {
    fn from(e: AppError) -> Self {
        WebError(e)
    }
}

impl From<anyhow::Error> for WebError {
    fn from(e: anyhow::Error) -> Self {
        WebError(AppError::Internal(e))
    }
}

/// A `BackupError` reaching a route handler unconverted is always a
/// genuine failure of the backup engine itself (a bad dump, a corrupted
/// archive, a subprocess that wouldn't start) -- surfaced as a plain
/// validation-shaped error rather than a raw 500, since the message is
/// almost always meaningful to the admin looking at it (unlike a stack
/// trace), not an internal implementation detail to hide.
impl From<crate::reliquary_backup::BackupError> for WebError {
    fn from(e: crate::reliquary_backup::BackupError) -> Self {
        WebError(AppError::Validation(e.to_string()))
    }
}

impl From<crate::sepulchre::SepulchreError> for WebError {
    fn from(e: crate::sepulchre::SepulchreError) -> Self {
        WebError(AppError::Validation(e.to_string()))
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        // Unauthenticated is special-cased to a redirect rather than a bare
        // 401 body: nearly every route behind `CurrentUser` is a browser page,
        // so bouncing to /login is the right default here. `/api/me` is the
        // one caller that would prefer a plain 401 — a documented rough edge
        // for this pass rather than splitting this type in two.
        if matches!(self.0, AppError::Unauthenticated) {
            return Redirect::to("/login").into_response();
        }
        // Same idea as Unauthenticated above: nearly every route behind
        // `CurrentUser` is a browser page, so send them straight to where
        // they can actually resolve this instead of a bare 403.
        if matches!(self.0, AppError::MustChangePassword) {
            return Redirect::to("/account").into_response();
        }

        let (status, message) = match &self.0 {
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found.".to_string()),
            AppError::Unauthenticated => unreachable!("handled above"),
            AppError::MustChangePassword => unreachable!("handled above"),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Permission denied.".to_string()),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error.".to_string(),
                )
            }
        };
        (status, message).into_response()
    }
}

pub type WebResult<T> = Result<T, WebError>;
