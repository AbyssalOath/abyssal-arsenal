use std::collections::HashSet;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{
    assignable_roles, ensure_can_manage_role, grantable_permissions, has_no_ceiling, require_csrf,
};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, ConfirmTemplate, ModuleVisibilityRow, PermissionRow, RoleDetail,
    RoleDetailPageTemplate, RoleSummary, RolesTemplate,
};
use crate::theme;

/// Everything the checkbox list for `role` should render for this
/// *viewer*: `cap` is every permission they're allowed to grant on this
/// role (their own ceiling, further capped by the role's parent, exactly
/// `update_permissions`'s own rule), and `hidden_count` is how many of
/// the role's actual permissions fall outside that cap and so are left
/// off the list entirely -- summarized as a one-line note instead.
async fn viewer_capped_permissions(
    state: &AppState,
    ctx: &AuthContext,
    role: &abyssal_core::Role,
) -> anyhow::Result<(HashSet<Permission>, HashSet<Permission>, usize)> {
    let own: HashSet<Permission> = repo::roles::permissions_for_role(&state.pool, role.id)
        .await?
        .into_iter()
        .collect();
    let mut cap = grantable_permissions(ctx);
    if let Some(parent_id) = role.parent_role_id {
        let parent_effective =
            repo::roles::effective_permissions_for_role(&state.pool, parent_id).await?;
        cap = cap.intersection(&parent_effective).copied().collect();
    }
    let hidden_count = own.difference(&cap).count();
    Ok((cap, own, hidden_count))
}

/// Cheap per-role summary for the list page's cards and a detail page's
/// list of its own children -- neither needs the permission-capping or
/// module-visibility computation `build_role_detail` below does, just
/// counts and a name to link from.
async fn role_summary(
    state: &AppState,
    role: &abyssal_core::Role,
    depth: u8,
    parent_name: Option<String>,
) -> anyhow::Result<RoleSummary> {
    let user_count = repo::roles::user_count(&state.pool, role.id).await?;
    let child_count = repo::roles::children_of(&state.pool, role.id).await?.len() as i64;
    Ok(RoleSummary {
        id: role.id.to_string(),
        name: role.name.clone(),
        description: role.description.clone(),
        is_system: role.is_system,
        depth,
        parent_name,
        user_count,
        child_count,
    })
}

/// The full detail view of a single role from this *viewer*'s
/// perspective: its permission grid (capped to what the viewer may
/// grant -- see `viewer_capped_permissions`), dashboard-visibility grid,
/// and whether the viewer may manage it at all. Shared by the role
/// detail page and (historically) the list page before it was split into
/// per-role pages.
async fn build_role_detail(
    state: &AppState,
    ctx: &AuthContext,
    role: &abyssal_core::Role,
) -> Result<RoleDetail, WebError> {
    let depth = repo::roles::depth_of(&state.pool, role.id).await?;
    let parent = match role.parent_role_id {
        Some(parent_id) => repo::roles::find_by_id(&state.pool, parent_id).await?,
        None => None,
    };
    let parent_name = parent.as_ref().map(|r| r.name.clone());
    let parent_id = parent.as_ref().map(|r| r.id.to_string());

    let (cap, own, hidden_permission_count) = viewer_capped_permissions(state, ctx, role).await?;
    // Only permissions within the viewer's own cap are shown at all
    // (checked if the role already has them, unchecked if they're
    // grantable but not yet given) -- anything the role has outside
    // that cap is summarized by `hidden_permission_count` instead of
    // rendered as an uneditable/confusing row.
    let permissions: Vec<PermissionRow> = Permission::ALL
        .iter()
        .filter(|p| cap.contains(p))
        .map(|p| PermissionRow {
            key: p.as_key().to_string(),
            granted: own.contains(p),
        })
        .collect();

    // Dashboard visibility is capped by the role's own *effective*
    // (ancestor-capped) permissions -- never the viewer's personal
    // ceiling, since anyone allowed to manage this role can already
    // see its full effective grant set on this same page.
    let all_modules = state.modules.list(&state.pool).await?;
    let role_effective = repo::roles::effective_permissions_for_role(&state.pool, role.id).await?;
    let customization =
        repo::role_module_visibility::visibility_for_role(&state.pool, role.id).await?;
    let module_visibility = all_modules
        .iter()
        .filter(|m| m.enabled)
        .map(|m| {
            let has_permission = m.view_permissions.is_empty()
                || m.view_permissions
                    .iter()
                    .any(|p| role_effective.contains(p));
            let visible = match &customization {
                Some(set) => set.contains(m.key),
                None => has_permission,
            };
            ModuleVisibilityRow {
                key: m.key,
                display_name: m.display_name,
                visible,
            }
        })
        .collect();

    let can_manage = ensure_can_manage_role(&state.pool, ctx, role).await.is_ok();
    let user_count = repo::roles::user_count(&state.pool, role.id).await?;
    let child_count = repo::roles::children_of(&state.pool, role.id).await?.len() as i64;

    Ok(RoleDetail {
        id: role.id.to_string(),
        name: role.name.clone(),
        description: role.description.clone(),
        is_system: role.is_system,
        depth,
        parent_name,
        parent_id,
        permissions,
        hidden_permission_count,
        module_visibility,
        visibility_customized: customization.is_some(),
        can_manage,
        user_count,
        child_count,
    })
}

async fn render_roles_list(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    create_error: Option<String>,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(
        ctx,
        &theme::current(jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(jar),
    )
    .await?;

    let all_roles = repo::roles::list(&state.pool).await?;
    let mut roles = Vec::new();
    for role in &all_roles {
        let depth = repo::roles::depth_of(&state.pool, role.id).await?;
        let parent_name = match role.parent_role_id {
            Some(parent_id) => repo::roles::find_by_id(&state.pool, parent_id)
                .await?
                .map(|r| r.name),
            None => None,
        };
        roles.push(role_summary(state, role, depth, parent_name).await?);
    }
    roles.sort_by(|a, b| a.depth.cmp(&b.depth).then_with(|| a.name.cmp(&b.name)));

    let tpl = RolesTemplate {
        base,
        roles,
        can_create_root: has_no_ceiling(ctx),
        create_error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// One role's own page: its permission/visibility grids (from
/// `build_role_detail`), its child roles (each linking to their own page
/// in turn), and -- if `role` is within the viewer's delegation scope and
/// under `MAX_ROLE_DEPTH` -- a form to create a new sub-role directly
/// under it. This is where "Create role" now lives for every role except
/// a brand new top-level one (which has no parent page to live on, so it
/// stays on the list page -- see `RolesTemplate`).
async fn render_role_detail(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    role: &abyssal_core::Role,
    create_error: Option<String>,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(
        ctx,
        &theme::current(jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(jar),
    )
    .await?;

    let detail = build_role_detail(state, ctx, role).await?;

    let depth = repo::roles::depth_of(&state.pool, role.id).await?;
    let mut children = Vec::new();
    for child in repo::roles::children_of(&state.pool, role.id).await? {
        children.push(role_summary(state, &child, depth + 1, Some(role.name.clone())).await?);
    }
    children.sort_by(|a, b| a.name.cmp(&b.name));

    let assignable = assignable_roles(&state.pool, ctx).await?;
    let can_create_sub_role =
        assignable.iter().any(|r| r.id == role.id) && depth < abyssal_core::MAX_ROLE_DEPTH;

    // Exactly the cap `create_role` itself enforces for a sub-role
    // created under `role`: the viewer's own ceiling, further narrowed to
    // what `role` itself effectively has (a sub-role's grants must fit
    // under its parent, not just under its creator).
    let sub_role_permission_options: Vec<PermissionRow> = if can_create_sub_role {
        let role_effective =
            repo::roles::effective_permissions_for_role(&state.pool, role.id).await?;
        let cap: HashSet<Permission> = grantable_permissions(ctx)
            .intersection(&role_effective)
            .copied()
            .collect();
        Permission::ALL
            .iter()
            .filter(|p| cap.contains(p))
            .map(|p| PermissionRow {
                key: p.as_key().to_string(),
                granted: false,
            })
            .collect()
    } else {
        Vec::new()
    };

    let tpl = RoleDetailPageTemplate {
        base,
        role: detail,
        children,
        can_create_sub_role,
        sub_role_permission_options,
        create_error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Renders whichever page a `create_role` validation failure should
/// reappear on: the role named by `parent_role_id_raw`'s own detail page
/// if it's a real, existing role (a sub-role creation attempt), or the
/// list page otherwise (a top-level-role creation attempt, or a
/// malformed/empty parent). Mirrors, but doesn't replace, `create_role`'s
/// own server-side validation of that same value -- this only decides
/// where to show the error, never whether the request is allowed.
async fn render_source_page(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    parent_role_id_raw: &str,
    error: String,
) -> Result<Response, WebError> {
    let parent_role_id_raw = parent_role_id_raw.trim();
    if !parent_role_id_raw.is_empty()
        && let Ok(parent_id) = parent_role_id_raw.parse::<Uuid>()
        && let Some(parent_role) = repo::roles::find_by_id(&state.pool, parent_id).await?
    {
        return render_role_detail(state, jar, ctx, &parent_role, Some(error)).await;
    }
    render_roles_list(state, jar, ctx, Some(error)).await
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;
    // A no-ceiling (Super Admin) viewer always sees the full list --
    // they manage every role in the system, so there's no single "their
    // own role" to jump to. Everyone else lands on their own role's page
    // directly (GitHub issue #8 follow-up: "when a Network Admin clicks
    // Roles, it takes them to the Network Admin page"), unless they hold
    // more than one role, in which case there's no single unambiguous
    // target and the full (delegation-scoped by the template's own
    // `can_manage` checks) list is the safer fallback.
    if !has_no_ceiling(&ctx) {
        let own_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
        if let [only_role] = own_roles.as_slice() {
            return Ok(Redirect::to(&format!("/admin/roles/{}", only_role.id)).into_response());
        }
    }
    render_roles_list(&state, &jar, &ctx, None).await
}

pub async fn detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;
    let role = repo::roles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    render_role_detail(&state, &jar, &ctx, &role, None).await
}

/// Creates a custom role (GitHub issue #8). Parses the raw body by hand
/// for the same documented reason `update_permissions` below does --
/// `permissions` is a repeated-key checkbox group, which `axum::Form`
/// can't deserialize into a `Vec<String>`.
pub async fn create_role(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    body: Bytes,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;

    let mut csrf_token = String::new();
    let mut name = String::new();
    let mut description = String::new();
    let mut parent_role_id_raw = String::new();
    let mut permission_keys = Vec::new();
    for (key, value) in form_urlencoded::parse(&body) {
        match key.as_ref() {
            "csrf_token" => csrf_token = value.into_owned(),
            "name" => name = value.into_owned(),
            "description" => description = value.into_owned(),
            "parent_role_id" => parent_role_id_raw = value.into_owned(),
            "permissions" => permission_keys.push(value.into_owned()),
            _ => {}
        }
    }
    require_csrf(&jar, &csrf_token)?;

    let name = name.trim().to_string();
    let description = description.trim().to_string();

    macro_rules! fail {
        ($msg:expr) => {
            return render_source_page(&state, &jar, &ctx, &parent_role_id_raw, $msg.to_string())
                .await
        };
    }

    if name.is_empty() || name.len() > 100 {
        fail!("Role name must be 1-100 characters.");
    }
    if description.len() > 500 {
        fail!("Description must be 500 characters or fewer.");
    }
    if repo::roles::find_by_name(&state.pool, &name)
        .await?
        .is_some()
    {
        fail!("A role named that already exists.");
    }

    let parent_role_id_raw = parent_role_id_raw.trim();
    let parent = if parent_role_id_raw.is_empty() {
        None
    } else {
        let parent_id: Uuid = match parent_role_id_raw.parse() {
            Ok(id) => id,
            Err(_) => fail!("Not a recognized parent role."),
        };
        match repo::roles::find_by_id(&state.pool, parent_id).await? {
            Some(role) => Some(role),
            None => fail!("Not a recognized parent role."),
        }
    };

    match &parent {
        None => {
            if !has_no_ceiling(&ctx) {
                return Err(WebError(AppError::Forbidden));
            }
        }
        Some(parent_role) => {
            let creatable = assignable_roles(&state.pool, &ctx).await?;
            if !creatable.iter().any(|r| r.id == parent_role.id) {
                return Err(WebError(AppError::Forbidden));
            }
            let parent_depth = repo::roles::depth_of(&state.pool, parent_role.id).await?;
            if parent_depth + 1 > abyssal_core::MAX_ROLE_DEPTH {
                fail!(format!(
                    "That parent is already at the maximum nesting depth ({}).",
                    abyssal_core::MAX_ROLE_DEPTH
                ));
            }
        }
    }

    let mut cap = grantable_permissions(&ctx);
    if let Some(parent_role) = &parent {
        let parent_effective =
            repo::roles::effective_permissions_for_role(&state.pool, parent_role.id).await?;
        cap = cap.intersection(&parent_effective).copied().collect();
    }

    let requested: HashSet<Permission> = permission_keys
        .iter()
        .filter_map(|k| Permission::from_key(k))
        .collect();
    if !requested.is_subset(&cap) {
        return Err(WebError(AppError::Forbidden));
    }

    let role = repo::roles::create(
        &state.pool,
        &name,
        &description,
        false,
        parent.as_ref().map(|r| r.id),
        Some(ctx.user.id),
    )
    .await?;
    repo::roles::set_permissions(
        &state.pool,
        role.id,
        &requested.iter().copied().collect::<Vec<_>>(),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::RoleCreated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&name)
            .metadata(serde_json::json!({
                "parent": parent.as_ref().map(|r| r.name.clone()),
                "permissions": requested.iter().map(|p| p.as_key()).collect::<Vec<_>>(),
            })),
    )
    .await?;

    Ok(Redirect::to(&format!("/admin/roles/{}", role.id)).into_response())
}

#[derive(Deserialize)]
pub struct EditRoleForm {
    csrf_token: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    parent_role_id: String,
}

/// Renames/re-describes/re-parents a custom role. System roles are never
/// touched here -- "can't be deleted or renamed" (GitHub issue #8) --
/// even for a no-ceiling user; their permissions stay editable through
/// `apply_permissions` below exactly as before.
pub async fn edit_role(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<EditRoleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let role = repo::roles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if role.is_system {
        return Err(WebError(AppError::Forbidden));
    }
    ensure_can_manage_role(&state.pool, &ctx, &role).await?;

    let name = form.name.trim().to_string();
    let description = form.description.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return render_role_detail(
            &state,
            &jar,
            &ctx,
            &role,
            Some("Role name must be 1-100 characters.".to_string()),
        )
        .await;
    }
    if description.len() > 500 {
        return render_role_detail(
            &state,
            &jar,
            &ctx,
            &role,
            Some("Description must be 500 characters or fewer.".to_string()),
        )
        .await;
    }
    if let Some(existing) = repo::roles::find_by_name(&state.pool, &name).await?
        && existing.id != id
    {
        return render_role_detail(
            &state,
            &jar,
            &ctx,
            &role,
            Some("A role named that already exists.".to_string()),
        )
        .await;
    }

    let parent_role_id_raw = form.parent_role_id.trim();
    let new_parent_id = if parent_role_id_raw.is_empty() {
        None
    } else {
        match parent_role_id_raw.parse::<Uuid>() {
            Ok(parent_id) => Some(parent_id),
            Err(_) => {
                return render_role_detail(
                    &state,
                    &jar,
                    &ctx,
                    &role,
                    Some("Not a recognized parent role.".to_string()),
                )
                .await;
            }
        }
    };

    if new_parent_id != role.parent_role_id {
        match new_parent_id {
            None => {
                if !has_no_ceiling(&ctx) {
                    return Err(WebError(AppError::Forbidden));
                }
            }
            Some(new_parent_id) => {
                if repo::roles::would_create_cycle(&state.pool, role.id, new_parent_id).await? {
                    return render_role_detail(
                        &state,
                        &jar,
                        &ctx,
                        &role,
                        Some("That would create a cycle in the role hierarchy.".to_string()),
                    )
                    .await;
                }
                let creatable = assignable_roles(&state.pool, &ctx).await?;
                if !has_no_ceiling(&ctx) && !creatable.iter().any(|r| r.id == new_parent_id) {
                    return Err(WebError(AppError::Forbidden));
                }
                let parent_depth = repo::roles::depth_of(&state.pool, new_parent_id).await?;
                if parent_depth + 1 > abyssal_core::MAX_ROLE_DEPTH {
                    return render_role_detail(
                        &state,
                        &jar,
                        &ctx,
                        &role,
                        Some(format!(
                            "That parent is already at the maximum nesting depth ({}).",
                            abyssal_core::MAX_ROLE_DEPTH
                        )),
                    )
                    .await;
                }
            }
        }
    }

    repo::roles::update(&state.pool, id, &name, &description, new_parent_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::RoleChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&name)
            .metadata(serde_json::json!({
                "previous_name": role.name,
                "previous_description": role.description,
                "previous_parent_role_id": role.parent_role_id,
                "new_parent_role_id": new_parent_id,
            })),
    )
    .await?;

    Ok(Redirect::to(&format!("/admin/roles/{id}")).into_response())
}

pub async fn delete_role_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;
    let role = repo::roles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if role.is_system {
        return Err(WebError(AppError::Forbidden));
    }
    ensure_can_manage_role(&state.pool, &ctx, &role).await?;

    let user_count = repo::roles::user_count(&state.pool, id).await?;
    let child_count = repo::roles::children_of(&state.pool, id).await?.len();
    if user_count > 0 || child_count > 0 {
        return Err(WebError(AppError::Validation(format!(
            "Can't delete \"{}\": {user_count} user(s) and {child_count} child role(s) are \
             still assigned to it. Reassign them first.",
            role.name
        ))));
    }

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

    let tpl = ConfirmTemplate {
        base,
        title: "Remove role".to_string(),
        message: format!(
            "This will permanently remove the role \"{}\". It has no users or child roles \
             assigned, so this is safe.",
            role.name
        ),
        action_url: format!("/admin/roles/{id}/remove"),
        cancel_url: format!("/admin/roles/{id}"),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "role name".to_string(),
            expected: role.name,
        }),
        extra_hidden_fields: vec![],
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct DeleteRoleForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn delete_role(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<DeleteRoleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }

    let role = repo::roles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if role.is_system {
        return Err(WebError(AppError::Forbidden));
    }
    ensure_can_manage_role(&state.pool, &ctx, &role).await?;
    crate::common::require_typed_confirmation(&form.confirm_text, &role.name)?;

    let user_count = repo::roles::user_count(&state.pool, id).await?;
    let child_count = repo::roles::children_of(&state.pool, id).await?.len();
    if user_count > 0 || child_count > 0 {
        return Err(WebError(AppError::Validation(format!(
            "Can't delete \"{}\": {user_count} user(s) and {child_count} child role(s) are \
             still assigned to it. Reassign them first.",
            role.name
        ))));
    }

    repo::roles::delete(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::RoleDeleted, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&role.name),
    )
    .await?;

    Ok(Redirect::to("/admin/roles").into_response())
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
    ensure_can_manage_role(&state.pool, &ctx, &role).await?;

    // GitHub issue #8: "a creator can only grant permissions they
    // currently hold themselves," further capped by the role's own
    // parent (a role's grants must fit under its parent, not just under
    // the editor's ceiling). Anything the editor submits outside this
    // cap is rejected outright rather than silently dropped -- the UI
    // never renders a checkbox for it in the first place, so seeing one
    // in the submitted body at all means the request didn't come from
    // this page's own form.
    let mut cap = grantable_permissions(&ctx);
    if let Some(parent_id) = role.parent_role_id {
        let parent_effective =
            repo::roles::effective_permissions_for_role(&state.pool, parent_id).await?;
        cap = cap.intersection(&parent_effective).copied().collect();
    }
    let requested: HashSet<Permission> = permission_keys
        .iter()
        .filter_map(|k| Permission::from_key(k))
        .collect();
    if !requested.is_subset(&cap) {
        return Err(WebError(AppError::Forbidden));
    }

    // Anything this role already has that falls *outside* the editor's
    // own cap is preserved untouched -- it was never shown as an
    // editable checkbox, so it must never be silently wiped out just
    // because it's absent from this submission. Only a no-ceiling editor
    // ever has an empty "outside cap" remainder here.
    let current: HashSet<Permission> = repo::roles::permissions_for_role(&state.pool, id)
        .await?
        .into_iter()
        .collect();
    let outside_cap: HashSet<Permission> = current.difference(&cap).copied().collect();
    let final_set: HashSet<Permission> = requested.union(&outside_cap).copied().collect();

    let editable_current: HashSet<Permission> = current.intersection(&cap).copied().collect();
    let added = requested.difference(&current).count();
    let removed = editable_current.difference(&requested).count();

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
    // The confirm page carries the entire (already-capped) final
    // selection forward as one opaque JSON-encoded hidden field rather
    // than repeated hidden inputs, for the exact same reason the initial
    // submission needed manual parsing above -- see this function's doc
    // comment.
    let permission_keys_final: Vec<String> =
        final_set.iter().map(|p| p.as_key().to_string()).collect();
    let permissions_json = serde_json::to_string(&permission_keys_final)
        .map_err(|e| WebError(AppError::Internal(e.into())))?;

    let tpl = ConfirmTemplate {
        base,
        title: "Save role permissions".to_string(),
        message: format!(
            "This will set \"{}\"'s permissions to exactly {} selected ({added} added, {removed} removed). \
             A role currently in use takes effect for its members immediately.",
            role.name,
            final_set.len()
        ),
        action_url: format!("/admin/roles/{id}/permissions/apply"),
        cancel_url: format!("/admin/roles/{id}"),
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
    ensure_can_manage_role(&state.pool, &ctx, &role).await?;

    let permission_keys: Vec<String> = serde_json::from_str(&form.permissions_json)
        .map_err(|_| WebError(AppError::Validation("Malformed permission set.".into())))?;
    let permissions: Vec<Permission> = permission_keys
        .iter()
        .filter_map(|k| Permission::from_key(k))
        .collect();

    // Re-validated fresh here too (not just at the confirm step above):
    // this is the actual write, and the confirm page's hidden field is
    // untrusted input like any other -- the same cap-and-preserve rule
    // applies again rather than trusting the confirm step got it right.
    let mut cap = grantable_permissions(&ctx);
    if let Some(parent_id) = role.parent_role_id {
        let parent_effective =
            repo::roles::effective_permissions_for_role(&state.pool, parent_id).await?;
        cap = cap.intersection(&parent_effective).copied().collect();
    }
    let requested: HashSet<Permission> = permissions.iter().copied().collect();
    let current: HashSet<Permission> = repo::roles::permissions_for_role(&state.pool, id)
        .await?
        .into_iter()
        .collect();
    let outside_cap: HashSet<Permission> = current.difference(&cap).copied().collect();
    // A permission requested outside the cap is simply dropped here
    // rather than rejected outright (unlike `update_permissions`'s
    // stricter check): the confirm step already validated this exact
    // set, so reaching this handler with something out-of-cap means the
    // role or the editor's own grants changed in the few seconds between
    // confirm and apply -- silently re-clamping to the current cap is
    // the safer response to that race, not a 403 for a legitimate user
    // just re-submitting a now-stale confirm page.
    let final_set: HashSet<Permission> = requested
        .intersection(&cap)
        .copied()
        .collect::<HashSet<_>>()
        .union(&outside_cap)
        .copied()
        .collect();

    repo::roles::set_permissions(
        &state.pool,
        id,
        &final_set.iter().copied().collect::<Vec<_>>(),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::RoleChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&role.name)
            .metadata(serde_json::json!({
                "previous_permissions": current.iter().map(|p| p.as_key()).collect::<Vec<_>>(),
                "new_permissions": final_set.iter().map(|p| p.as_key()).collect::<Vec<_>>(),
            })),
    )
    .await?;

    Ok(Redirect::to(&format!("/admin/roles/{id}")).into_response())
}

/// Saves a role's dashboard-visibility customization -- a single step, no
/// confirm page, unlike permissions above: unlike a permission change,
/// getting this "wrong" never grants or revokes actual access, only which
/// arsenals a role's members see on the dashboard (still bounded by
/// permissions either way), so it doesn't carry the same risk. Manually
/// parses the raw body for the same reason `update_permissions` does --
/// see its doc comment.
pub async fn update_visibility(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::RolesManage)?;

    let mut csrf_token = String::new();
    let mut module_keys = Vec::new();
    for (key, value) in form_urlencoded::parse(&body) {
        match key.as_ref() {
            "csrf_token" => csrf_token = value.into_owned(),
            "modules" => module_keys.push(value.into_owned()),
            _ => {}
        }
    }
    require_csrf(&jar, &csrf_token)?;

    let role = repo::roles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_manage_role(&state.pool, &ctx, &role).await?;

    // Every submitted arsenal key must require a permission within this
    // role's own *effective* (ancestor-capped) set -- an arsenal never
    // grants access on its own, and this is what keeps that true even
    // for a role a delegated admin manages.
    let role_effective = repo::roles::effective_permissions_for_role(&state.pool, id).await?;
    let all_modules = state.modules.list(&state.pool).await?;
    for key in &module_keys {
        let Some(module) = all_modules.iter().find(|m| m.key == key) else {
            return Err(WebError(AppError::Forbidden));
        };
        let allowed = module.view_permissions.is_empty()
            || module
                .view_permissions
                .iter()
                .any(|p| role_effective.contains(p));
        if !allowed {
            return Err(WebError(AppError::Forbidden));
        }
    }

    repo::role_module_visibility::set_visible_modules(&state.pool, id, &module_keys).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::RoleChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&role.name)
            .metadata(serde_json::json!({ "dashboard_visibility_modules": module_keys })),
    )
    .await?;

    Ok(Redirect::to(&format!("/admin/roles/{id}")).into_response())
}
