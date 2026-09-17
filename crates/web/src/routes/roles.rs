use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::collections::HashSet;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, PermissionRow, RoleDetail, RolesTemplate};
use crate::theme;

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token);

    let mut roles = Vec::new();
    for role in repo::roles::list(&state.pool).await? {
        let granted: HashSet<Permission> = repo::roles::permissions_for_role(&state.pool, role.id)
            .await?
            .into_iter()
            .collect();
        let permissions = Permission::ALL
            .iter()
            .map(|p| PermissionRow {
                key: p.as_key().to_string(),
                granted: granted.contains(p),
            })
            .collect();
        roles.push(RoleDetail {
            id: role.id.to_string(),
            name: role.name,
            description: role.description,
            is_system: role.is_system,
            permissions,
        });
    }

    let tpl = RolesTemplate { base, roles };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct UpdatePermissionsForm {
    csrf_token: String,
    #[serde(default)]
    permissions: Vec<String>,
}

pub async fn update_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<UpdatePermissionsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let role = repo::roles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let permissions: Vec<Permission> = form
        .permissions
        .iter()
        .filter_map(|k| Permission::from_key(k))
        .collect();
    repo::roles::set_permissions(&state.pool, id, &permissions).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::RoleChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&role.name),
    )
    .await?;

    Ok(Redirect::to("/admin/roles").into_response())
}
