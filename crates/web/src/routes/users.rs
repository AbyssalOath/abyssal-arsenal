use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, ConfirmTemplate, RoleOption, UserRow, UsersTemplate};
use crate::theme;

#[allow(clippy::too_many_arguments)]
async fn render_list(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    message: Option<String>,
    error: Option<String>,
    new_username: String,
    new_email: String,
    generated_password: Option<String>,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(ctx, &theme::current(jar), &csrf_token, &state.elevation);

    let mut users = Vec::new();
    for u in repo::users::list(&state.pool).await? {
        let roles = repo::roles::roles_for_user(&state.pool, u.id)
            .await?
            .into_iter()
            .map(|r| r.name)
            .collect::<Vec<_>>()
            .join(", ");
        users.push(UserRow {
            id: u.id.to_string(),
            username: u.username,
            email: u.email,
            is_active: u.is_active,
            roles,
        });
    }

    let roles = repo::roles::list(&state.pool)
        .await?
        .into_iter()
        .map(|r| RoleOption {
            id: r.id.to_string(),
            name: r.name,
        })
        .collect();

    let password_prefill = generated_password.clone().unwrap_or_default();

    let tpl = UsersTemplate {
        base,
        users,
        roles,
        message,
        error,
        new_username,
        new_email,
        generated_password,
        password_prefill,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ListQuery {
    message: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersView)?;
    render_list(
        &state,
        &jar,
        &ctx,
        q.message,
        None,
        String::new(),
        String::new(),
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    csrf_token: String,
    intent: String,
    username: String,
    email: String,
    password: String,
    role_id: Uuid,
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<CreateUserForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersCreate)?;
    require_csrf(&jar, &form.csrf_token)?;

    if form.intent == "generate" {
        let generated = abyssal_auth::password::generate_strong_password();
        return render_list(
            &state,
            &jar,
            &ctx,
            None,
            None,
            form.username,
            form.email,
            Some(generated),
        )
        .await;
    }

    if let Err(message) = abyssal_auth::password::validate_strength(&form.password) {
        return render_list(
            &state,
            &jar,
            &ctx,
            None,
            Some(message),
            form.username,
            form.email,
            None,
        )
        .await;
    }

    let hash = abyssal_auth::password::hash_password(&form.password)?;
    let user = repo::users::create(
        &state.pool,
        &form.username,
        &form.email,
        Some(&hash),
        "local",
        true,
    )
    .await?;
    repo::roles::assign_role_to_user(&state.pool, user.id, form.role_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserCreated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&user.username),
    )
    .await?;

    Ok(Redirect::to("/admin/users").into_response())
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

/// Enabling a disabled user is low-risk and reversible (you can always
/// disable them again), so it stays a one-click action -- only *disabling*
/// (which also silently revokes every active session) goes through a
/// confirm step below.
pub async fn enable(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;
    require_csrf(&jar, &form.csrf_token)?;

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    repo::users::set_active(&state.pool, id, true).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserEnabled, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&target.username),
    )
    .await?;

    Ok(Redirect::to("/admin/users").into_response())
}

pub async fn disable_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let tpl = ConfirmTemplate {
        base,
        title: "Disable user".to_string(),
        message: format!(
            "This will disable \"{}\" and immediately sign them out everywhere -- every active session of theirs is revoked. They can be re-enabled later.",
            target.username
        ),
        action_url: format!("/admin/users/{id}/disable"),
        cancel_url: "/admin/users".to_string(),
        escalate_host_id: None,
        type_to_confirm: None,
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ConfirmOnlyForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
}

pub async fn disable(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ConfirmOnlyForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Disabling this user was not confirmed.".into(),
        )));
    }

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    repo::users::set_active(&state.pool, id, false).await?;
    abyssal_auth::session::revoke_all_for_user(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserDisabled, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&target.username),
    )
    .await?;

    Ok(Redirect::to("/admin/users").into_response())
}

pub async fn revoke_sessions_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let tpl = ConfirmTemplate {
        base,
        title: "Force logout".to_string(),
        message: format!(
            "This will immediately sign \"{}\" out of every active session.",
            target.username
        ),
        action_url: format!("/admin/users/{id}/revoke-sessions"),
        cancel_url: "/admin/users".to_string(),
        escalate_host_id: None,
        type_to_confirm: None,
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn revoke_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ConfirmOnlyForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Force logout was not confirmed.".into(),
        )));
    }

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    abyssal_auth::session::revoke_all_for_user(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::SessionsRevoked, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&target.username),
    )
    .await?;

    Ok(Redirect::to("/admin/users").into_response())
}

pub async fn delete_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersDelete)?;

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let tpl = ConfirmTemplate {
        base,
        title: "Delete user".to_string(),
        message: format!(
            "This will permanently delete the user \"{}\". This cannot be undone.",
            target.username
        ),
        action_url: format!("/admin/users/{id}/delete"),
        cancel_url: "/admin/users".to_string(),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "username".to_string(),
            expected: target.username.clone(),
        }),
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct DeleteForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn delete(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersDelete)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Deletion was not confirmed.".into(),
        )));
    }

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &target.username)?;
    repo::users::delete(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserDeleted, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&target.username),
    )
    .await?;

    Ok(Redirect::to("/admin/users").into_response())
}
