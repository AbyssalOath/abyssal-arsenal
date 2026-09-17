use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
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

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token);

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

    let tpl = UsersTemplate {
        base,
        users,
        roles,
        message: q.message,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    csrf_token: String,
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

    if form.password.len() < 12 {
        return Err(WebError(AppError::Validation(
            "Password must be at least 12 characters.".into(),
        )));
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

pub async fn toggle_active(
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
    let new_active = !target.is_active;
    repo::users::set_active(&state.pool, id, new_active).await?;

    if !new_active {
        abyssal_auth::session::revoke_all_for_user(&state.pool, id).await?;
    }

    let action = if new_active {
        AuditAction::UserEnabled
    } else {
        AuditAction::UserDisabled
    };
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(action, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&target.username),
    )
    .await?;

    Ok(Redirect::to("/admin/users").into_response())
}

pub async fn revoke_sessions(
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
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token);

    let tpl = ConfirmTemplate {
        base,
        title: "Delete user".to_string(),
        message: format!(
            "This will permanently delete the user \"{}\". This cannot be undone.",
            target.username
        ),
        action_url: format!("/admin/users/{id}/delete"),
        cancel_url: "/admin/users".to_string(),
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
