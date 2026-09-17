use std::net::SocketAddr;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::role;
use abyssal_core::settings::PUBLIC_REGISTRATION_ENABLED;
use abyssal_database::repo;
use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::{build_session_cookie, require_csrf};
use crate::csrf;
use crate::error::WebError;
use crate::state::AppState;
use crate::templates::SetupTemplate;
use crate::theme;

pub async fn show(State(state): State<AppState>, jar: CookieJar) -> Result<Response, WebError> {
    if repo::users::count(&state.pool).await? > 0 {
        return Ok(Redirect::to("/login").into_response());
    }

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let tpl = SetupTemplate {
        theme: theme::current(&jar),
        csrf_token,
        error: None,
    };

    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct SetupForm {
    csrf_token: String,
    username: String,
    email: String,
    password: String,
    password_confirm: String,
}

pub async fn submit(
    State(state): State<AppState>,
    jar: CookieJar,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<SetupForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    if repo::users::count(&state.pool).await? > 0 {
        return Ok(Redirect::to("/login").into_response());
    }

    if form.password != form.password_confirm {
        return Ok(setup_error(&jar, "Passwords do not match."));
    }
    if form.password.len() < 12 {
        return Ok(setup_error(
            &jar,
            "Password must be at least 12 characters.",
        ));
    }

    let hash = abyssal_auth::password::hash_password(&form.password)?;
    let user = repo::users::create(
        &state.pool,
        &form.username,
        &form.email,
        Some(&hash),
        "local",
        false,
    )
    .await?;

    let super_admin = repo::roles::find_by_name(&state.pool, role::SUPER_ADMIN)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Super Admin role missing — did startup seeding run?"))?;
    repo::roles::assign_role_to_user(&state.pool, user.id, super_admin.id).await?;

    repo::settings::set(
        &state.pool,
        PUBLIC_REGISTRATION_ENABLED,
        serde_json::json!(false),
        Some(user.id),
    )
    .await?;

    let ip = addr.ip().to_string();
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserCreated, AuditOutcome::Success)
            .actor(Actor {
                user_id: user.id,
                username: &user.username,
            })
            .resource(&user.username)
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

fn setup_error(jar: &CookieJar, message: &str) -> Response {
    let (csrf_token, _) = csrf::ensure_token(jar);
    let tpl = SetupTemplate {
        theme: theme::current(jar),
        csrf_token,
        error: Some(message.to_string()),
    };
    tpl.into_response()
}
