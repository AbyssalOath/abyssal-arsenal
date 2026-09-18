use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_core::AppError;
use abyssal_database::repo;
use abyssal_notifications::{NotificationMessage, Severity};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use chrono::Duration;
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::state::AppState;
use crate::templates::{ForgotPasswordTemplate, ResetPasswordTemplate};
use crate::theme;

/// How long an emailed reset code stays valid.
const RESET_TOKEN_TTL: Duration = Duration::hours(1);
/// Minimum gap between two reset emails sent to the same account, so
/// repeatedly submitting "forgot password" can't be used to spam someone's
/// inbox.
const RESET_COOLDOWN_MINUTES: i64 = 15;

pub async fn show_forgot_password(jar: CookieJar) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let tpl = ForgotPasswordTemplate {
        theme: theme::current(&jar),
        csrf_token,
        submitted: false,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    csrf_token: String,
    email: String,
}

fn build_reset_email(
    recipient: &str,
    raw_token: &str,
    public_url: Option<&str>,
) -> NotificationMessage {
    let body = match public_url {
        Some(base) => format!(
            "A password reset was requested for your Abyssal Arsenal account.\n\n\
             Reset link: {base}/reset-password?token={raw_token}\n\n\
             If that link doesn't work, go to {base}/reset-password and enter this \
             code directly: {raw_token}\n\n\
             This link/code expires in 1 hour. If you didn't request this, you can \
             safely ignore this email -- your password hasn't been changed."
        ),
        None => format!(
            "A password reset was requested for your Abyssal Arsenal account.\n\n\
             Reset code: {raw_token}\n\n\
             Go to your control plane's \"Reset password\" page and enter this code.\n\n\
             This code expires in 1 hour. If you didn't request this, you can safely \
             ignore this email -- your password hasn't been changed."
        ),
    };

    NotificationMessage {
        subject: "Reset your Abyssal Arsenal password".to_string(),
        body,
        severity: Severity::Info,
        recipients: vec![recipient.to_string()],
    }
}

/// Always renders the same "if an account exists..." result regardless of
/// whether the email actually matched anything, is inactive, or has no
/// local password to reset (SSO-only) -- never lets this form be used to
/// probe which email addresses have an account.
pub async fn submit_forgot_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ForgotPasswordForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    let email = form.email.trim().to_string();
    if let Ok(Some(user)) = repo::users::find_by_email(&state.pool, &email).await {
        if user.is_active && user.password_hash.is_some() {
            let already_recent = repo::password_resets::has_recent_request(
                &state.pool,
                user.id,
                RESET_COOLDOWN_MINUTES,
            )
            .await
            .unwrap_or(false);

            if !already_recent {
                let raw_token = generate_token();
                let token_hash = hash_token(&raw_token);

                if repo::password_resets::create(&state.pool, user.id, &token_hash, RESET_TOKEN_TTL)
                    .await
                    .is_ok()
                {
                    let message = build_reset_email(
                        &user.email,
                        &raw_token,
                        state.config.public_url.as_deref(),
                    );
                    state.notifications.dispatch(&message).await;

                    abyssal_audit::record(
                        &state.pool,
                        AuditEvent::new(AuditAction::PasswordResetRequested, AuditOutcome::Success)
                            .resource(&user.username),
                    )
                    .await
                    .ok();
                }
            }
        }
    }

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let tpl = ForgotPasswordTemplate {
        theme: theme::current(&jar),
        csrf_token,
        submitted: true,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ResetPasswordQuery {
    #[serde(default)]
    token: String,
}

pub async fn show_reset_password(
    jar: CookieJar,
    Query(q): Query<ResetPasswordQuery>,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let tpl = ResetPasswordTemplate {
        theme: theme::current(&jar),
        csrf_token,
        token: q.token,
        error: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    csrf_token: String,
    token: String,
    new_password: String,
    new_password_confirm: String,
}

async fn reset_password_error(jar: &CookieJar, token: String, error: String) -> Response {
    let (csrf_token, _) = csrf::ensure_token(jar);
    let tpl = ResetPasswordTemplate {
        theme: theme::current(jar),
        csrf_token,
        token,
        error: Some(error),
    };
    tpl.into_response()
}

pub async fn submit_reset_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ResetPasswordForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    if form.new_password != form.new_password_confirm {
        return Ok(reset_password_error(
            &jar,
            form.token,
            "New password and confirmation don't match.".to_string(),
        )
        .await);
    }

    if let Err(message) = abyssal_auth::password::validate_strength(&form.new_password) {
        return Ok(reset_password_error(&jar, form.token, message).await);
    }

    let token_hash = hash_token(form.token.trim());
    let Some(user_id) = repo::password_resets::consume(&state.pool, &token_hash).await? else {
        return Ok(reset_password_error(
            &jar,
            form.token,
            "That reset code is invalid or has expired. Request a new one.".to_string(),
        )
        .await);
    };

    let user = repo::users::find_by_id(&state.pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let new_hash = abyssal_auth::password::hash_password(&form.new_password)?;
    repo::users::update_password(&state.pool, user_id, &new_hash, false).await?;
    repo::sessions::revoke_all_for_user(&state.pool, user_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::PasswordReset, AuditOutcome::Success).resource(&user.username),
    )
    .await?;

    Ok(Redirect::to("/login").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_email_includes_clickable_link_when_public_url_configured() {
        let message = build_reset_email(
            "user@example.com",
            "raw-token-value",
            Some("https://arsenal.example.com"),
        );
        assert_eq!(message.recipients, vec!["user@example.com".to_string()]);
        assert!(message
            .body
            .contains("https://arsenal.example.com/reset-password?token=raw-token-value"));
        assert!(message.body.contains("raw-token-value"));
    }

    #[test]
    fn reset_email_falls_back_to_a_plain_code_without_public_url() {
        let message = build_reset_email("user@example.com", "raw-token-value", None);
        assert!(message.body.contains("raw-token-value"));
        assert!(!message.body.contains("http"));
    }
}
