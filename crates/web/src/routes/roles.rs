use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use axum::body::Bytes;
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
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, ConfirmTemplate, PermissionRow, RoleDetail, RolesTemplate};
use crate::theme;

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(
        &ctx,
        &theme::current(&jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(&jar),
    )
    .await?;

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

/// Renders the "review before saving" confirm step. Deliberately parses the
/// submitted body by hand with `form_urlencoded` instead of
/// `axum::Form<T>` -- axum's `Form` extractor is backed by `serde_urlencoded`
/// (axum 0.7), which has a real, documented limitation: it cannot
/// deserialize a `Vec<String>` field from repeated `permissions=x&
/// permissions=y` keys the way a standard HTML checkbox group submits (it
/// expects the *value itself* to look like a sequence, not the key to
/// repeat). A plain `Form<UpdatePermissionsForm { permissions: Vec<String>
/// }>` here fails on every submission with "invalid type: string ...,
/// expected a sequence" -- confirmed live. Parsing the raw body directly
/// sidesteps that entirely: `form_urlencoded::parse` yields every
/// occurrence of a repeated key as its own pair, no serde sequence
/// coercion involved.
pub async fn update_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;

    let mut csrf_token = String::new();
    let mut permission_keys = Vec::new();
    for (key, value) in form_urlencoded::parse(&body) {
        match key.as_ref() {
            "csrf_token" => csrf_token = value.into_owned(),
            "permissions" => permission_keys.push(value.into_owned()),
            _ => {}
        }
    }
    require_csrf(&jar, &csrf_token)?;

    let role = repo::roles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let permissions: Vec<Permission> = permission_keys
        .iter()
        .filter_map(|k| Permission::from_key(k))
        .collect();
    let current: HashSet<Permission> = repo::roles::permissions_for_role(&state.pool, id)
        .await?
        .into_iter()
        .collect();
    let requested: HashSet<Permission> = permissions.iter().copied().collect();
    let added = requested.difference(&current).count();
    let removed = current.difference(&requested).count();

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(
        &ctx,
        &theme::current(&jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(&jar),
    )
    .await?;
    // The confirm page carries the entire selection forward as one opaque
    // JSON-encoded hidden field rather than repeated hidden inputs, for the
    // exact same reason the initial submission needed manual parsing above
    // -- see this function's doc comment.
    let permissions_json = serde_json::to_string(&permission_keys)
        .map_err(|e| WebError(AppError::Internal(e.into())))?;

    let tpl = ConfirmTemplate {
        base,
        title: "Save role permissions".to_string(),
        message: format!(
            "This will set \"{}\"'s permissions to exactly {} selected ({added} added, {removed} removed). \
             A role currently in use takes effect for its members immediately.",
            role.name,
            permissions.len()
        ),
        action_url: format!("/admin/roles/{id}/permissions/apply"),
        cancel_url: "/admin/roles".to_string(),
        escalate_host_id: None,
        type_to_confirm: None,
        extra_hidden_fields: vec![("permissions_json".to_string(), permissions_json)],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ApplyPermissionsForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    permissions_json: String,
}

pub async fn apply_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ApplyPermissionsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Saving permissions was not confirmed.".into(),
        )));
    }

    let role = repo::roles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let permission_keys: Vec<String> = serde_json::from_str(&form.permissions_json)
        .map_err(|_| WebError(AppError::Validation("Malformed permission set.".into())))?;
    let permissions: Vec<Permission> = permission_keys
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
