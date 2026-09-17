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

fn render(
    jar: &CookieJar,
    username: &str,
    email: &str,
    error: Option<String>,
    generated_password: Option<String>,
) -> Response {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let password_prefill = generated_password.clone().unwrap_or_default();
    let tpl = SetupTemplate {
        theme: theme::current(jar),
        csrf_token,
        error,
        username: username.to_string(),
        email: email.to_string(),
        generated_password,
        password_prefill,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    (jar, tpl).into_response()
}

pub async fn show(State(state): State<AppState>, jar: CookieJar) -> Result<Response, WebError> {
    if repo::users::count(&state.pool).await? > 0 {
        return Ok(Redirect::to("/login").into_response());
    }
    Ok(render(&jar, "", "", None, None))
}

#[derive(Deserialize)]
pub struct SetupForm {
    csrf_token: String,
    intent: String,
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

    if form.intent == "generate" {
        let generated = abyssal_auth::password::generate_strong_password();
        return Ok(render(
            &jar,
            &form.username,
            &form.email,
            None,
            Some(generated),
        ));
    }

    if form.password != form.password_confirm {
        return Ok(render(
            &jar,
            &form.username,
            &form.email,
            Some("Passwords do not match.".to_string()),
            None,
        ));
    }
    if let Err(message) = abyssal_auth::password::validate_strength(&form.password) {
        return Ok(render(
            &jar,
            &form.username,
            &form.email,
            Some(message),
            None,
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
        .ok_or_else(|| anyhow::anyhow!("Super Admin role missing -- did startup seeding run?"))?;
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
