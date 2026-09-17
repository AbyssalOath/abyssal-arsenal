use std::net::SocketAddr;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_auth::{AuthError, AuthProvider, LocalAuthProvider};
use abyssal_core::settings::PUBLIC_REGISTRATION_ENABLED;
use abyssal_database::repo;
use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::{build_session_cookie, clear_session_cookie, require_csrf};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::LoginTemplate;
use crate::theme;

pub async fn show(State(state): State<AppState>, jar: CookieJar) -> Result<Response, WebError> {
    if repo::users::count(&state.pool).await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }

    let registration_enabled =
        repo::settings::get_bool(&state.pool, PUBLIC_REGISTRATION_ENABLED, false).await?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let tpl = LoginTemplate {
        theme: theme::current(&jar),
        csrf_token,
        error: None,
        registration_enabled,
    };

    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct LoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

pub async fn submit(
    State(state): State<AppState>,
    jar: CookieJar,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    let ip = addr.ip().to_string();
    let limiter_key = format!("{}:{}", form.username, ip);

    if state.login_limiter.is_locked(&limiter_key) {
        return Ok(login_error(&state, &jar, "Too many failed attempts. Try again later.").await);
    }

    let provider = LocalAuthProvider;
    match provider
        .authenticate(&state.pool, &form.username, &form.password)
        .await
    {
        Ok(user) => {
            state.login_limiter.clear(&limiter_key);
            repo::users::touch_last_login(&state.pool, user.id).await?;

            abyssal_audit::record(
                &state.pool,
                AuditEvent::new(AuditAction::LoginSuccess, AuditOutcome::Success)
                    .actor(Actor {
                        user_id: user.id,
                        username: &user.username,
                    })
                    .source_ip(&ip)
                    .auth_method("local"),
            )
            .await?;

            let (token, _session) = abyssal_auth::session::issue(
                &state.pool,
                user.id,
                state.config.session_ttl,
                Some(&ip),
                None,
            )
            .await?;

            let jar = jar.add(build_session_cookie(&state, token));
            Ok((jar, Redirect::to("/")).into_response())
        }
        Err(e) => {
            state.login_limiter.record_failure(&limiter_key);

            abyssal_audit::record(
                &state.pool,
                AuditEvent::new(AuditAction::LoginFailure, AuditOutcome::Failure)
                    .resource(&form.username)
                    .source_ip(&ip)
                    .auth_method("local"),
            )
            .await?;

            let message = match e {
                AuthError::AccountDisabled => "This account has been disabled.",
                _ => "Invalid username or password.",
            };
            Ok(login_error(&state, &jar, message).await)
        }
    }
}

async fn login_error(state: &AppState, jar: &CookieJar, message: &str) -> Response {
    let registration_enabled =
        repo::settings::get_bool(&state.pool, PUBLIC_REGISTRATION_ENABLED, false)
            .await
            .unwrap_or(false);
    let (csrf_token, _) = csrf::ensure_token(jar);
    let tpl = LoginTemplate {
        theme: theme::current(jar),
        csrf_token,
        error: Some(message.to_string()),
        registration_enabled,
    };
    tpl.into_response()
}

#[derive(Deserialize)]
pub struct LogoutForm {
    csrf_token: String,
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    current: Option<CurrentUser>,
    Form(form): Form<LogoutForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    if let Some(token) = jar
        .get(&state.config.session_cookie_name)
        .map(|c| c.value().to_string())
    {
        if let Ok(Some(session)) = abyssal_auth::session::validate(&state.pool, &token).await {
            abyssal_auth::session::revoke(&state.pool, session.id).await?;
        }
    }

    if let Some(CurrentUser(ctx)) = current {
        abyssal_audit::record(
            &state.pool,
            AuditEvent::new(AuditAction::Logout, AuditOutcome::Success).actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            }),
        )
        .await
        .ok();
    }

    let jar = jar.add(clear_session_cookie(&state));
    Ok((jar, Redirect::to("/login")).into_response())
}
