use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, MacroScope, MacroType};
use abyssal_database::repo;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{ensure_can_edit_macro, require_csrf, safe_return_to};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{AccountMacroEditTemplate, AccountTemplate, BaseCtx, CommunityMacroRow};
use crate::theme;

/// Every SNMP community-string macro this user owns -- the Account page's
/// "macros I manage" list. `can_edit` is always true here (these are all
/// their own), included on the shared row type so the same template
/// partial-shaped data works for Panopticon's "macros I can use" list too.
async fn owned_community_macro_rows(
    state: &AppState,
    ctx: &AuthContext,
) -> anyhow::Result<Vec<CommunityMacroRow>> {
    let macros =
        repo::macros::list_owned_by(&state.pool, ctx.user.id, MacroType::CommunityString).await?;
    let all_roles = repo::roles::list(&state.pool).await?;
    let role_name = |id: Uuid| -> String {
        all_roles
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "unknown role".to_string())
    };
    Ok(macros
        .into_iter()
        .map(|m| {
            let scope_label = match m.scope {
                MacroScope::Personal => "Personal".to_string(),
                MacroScope::Role => format!("Role: {}", role_name(m.role_id.unwrap_or_default())),
            };
            CommunityMacroRow {
                id: m.id.to_string(),
                name: m.name,
                scope_label,
                can_edit: true,
            }
        })
        .collect())
}

async fn render_account(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    password_error: Option<String>,
    macro_error: Option<String>,
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

    let community_macros = owned_community_macro_rows(state, ctx).await?;
    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let macro_roles = user_roles
        .into_iter()
        .map(|r| (r.id.to_string(), r.name))
        .collect();

    let tpl = AccountTemplate {
        must_change_password: ctx.user.must_change_password,
        base,
        password_error,
        community_macros,
        macro_roles,
        macro_error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Per-user preferences (theme, timezone) -- deliberately not
/// `/admin/settings`, which is gated by `settings.manage`. Any
/// authenticated user needs to be able to set their own timezone, same
/// as the theme toggle already works for everyone.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    render_account(&state, &jar, &ctx, None, None).await
}

#[derive(Deserialize)]
pub struct TimezoneForm {
    csrf_token: String,
    timezone: String,
}

/// A personal preference, not an admin action -- any logged-in user can set
/// their own timezone, gated only by being authenticated (`CurrentUser`),
/// same as the theme toggle.
pub async fn set_timezone(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<TimezoneForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    if form.timezone.parse::<chrono_tz::Tz>().is_err() {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a recognized timezone.".into(),
        )));
    }

    repo::users::set_timezone(&state.pool, ctx.user.id, &form.timezone).await?;

    Ok(Redirect::to("/account").into_response())
}

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    csrf_token: String,
    current_password: String,
    new_password: String,
    new_password_confirm: String,
}

/// Self-service password change -- covers both a voluntary change and the
/// mandatory one for an account `CurrentUser` is otherwise redirecting
/// straight back to `/account` until this succeeds (see
/// `crates/web/src/extract.rs`).
pub async fn change_password(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ChangePasswordForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    let Some(current_hash) = ctx.user.password_hash.as_deref() else {
        return render_account(
            &state,
            &jar,
            &ctx,
            Some("This account has no local password to change.".to_string()),
            None,
        )
        .await;
    };

    if !abyssal_auth::password::verify_password(&form.current_password, current_hash) {
        return render_account(
            &state,
            &jar,
            &ctx,
            Some("Current password is incorrect.".to_string()),
            None,
        )
        .await;
    }

    if form.new_password != form.new_password_confirm {
        return render_account(
            &state,
            &jar,
            &ctx,
            Some("New password and confirmation don't match.".to_string()),
            None,
        )
        .await;
    }

    if let Err(message) = abyssal_auth::password::validate_strength(&form.new_password) {
        return render_account(&state, &jar, &ctx, Some(message), None).await;
    }

    let new_hash = abyssal_auth::password::hash_password(&form.new_password)?;
    repo::users::update_password(&state.pool, ctx.user.id, &new_hash, false).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::PasswordChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&ctx.user.username),
    )
    .await?;

    Ok(Redirect::to("/account").into_response())
}

// ---------------------------------------------------------------------
// SNMP community-string macros -- GitHub issue #7 follow-up. Reusable
// across every surface that needs a saved community string (today, just
// Panopticon's add-switch form); this page is where one gets created or
// managed directly, independent of adding a switch.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AddCommunityMacroForm {
    csrf_token: String,
    name: String,
    value: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    role_id: String,
}

pub async fn add_community_macro(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<AddCommunityMacroForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    let Some(encryption_key) = &state.encryption_key else {
        return render_account(
            &state,
            &jar,
            &ctx,
            None,
            Some(
                "Set ENCRYPTION_KEY in the environment before adding a macro -- its value \
                 can't be stored safely without it."
                    .to_string(),
            ),
        )
        .await;
    };

    let name = form.name.trim();
    if name.is_empty() || name.len() > 128 {
        return render_account(
            &state,
            &jar,
            &ctx,
            None,
            Some("Macro name must be 1-128 characters.".to_string()),
        )
        .await;
    }
    let value = form.value.trim();
    if value.is_empty() {
        return render_account(
            &state,
            &jar,
            &ctx,
            None,
            Some("Value is required.".to_string()),
        )
        .await;
    }

    let scope: MacroScope = form.scope.trim().parse().unwrap_or(MacroScope::Personal);
    let role_id = match scope {
        MacroScope::Personal => None,
        MacroScope::Role => {
            let Ok(role_id) = form.role_id.trim().parse::<Uuid>() else {
                return render_account(
                    &state,
                    &jar,
                    &ctx,
                    None,
                    Some("Pick a role for a role-scoped macro.".to_string()),
                )
                .await;
            };
            let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
            if !user_roles.iter().any(|r| r.id == role_id) {
                return render_account(
                    &state,
                    &jar,
                    &ctx,
                    None,
                    Some("You can only save a role macro for a role you belong to.".to_string()),
                )
                .await;
            }
            Some(role_id)
        }
    };

    let secret_value_encrypted = encryption_key
        .encrypt(value)
        .map_err(|e| WebError(AppError::Validation(format!("Encryption failed: {e}"))))?;

    repo::macros::create(
        &state.pool,
        repo::macros::MacroFields {
            name,
            owner_user_id: ctx.user.id,
            scope,
            role_id,
            macro_type: MacroType::CommunityString,
            job_name: None,
            schedule: None,
            run_as_user: None,
            command: None,
            secret_value_encrypted: Some(&secret_value_encrypted),
        },
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::MacroCreated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(name),
    )
    .await?;

    Ok(Redirect::to("/account").into_response())
}

#[allow(clippy::too_many_arguments)]
async fn render_community_macro_edit(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    macro_id: Uuid,
    return_to: String,
    name: String,
    scope: MacroScope,
    role_id: Option<Uuid>,
    error: Option<String>,
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

    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let macro_roles = user_roles
        .into_iter()
        .map(|r| {
            let selected = scope == MacroScope::Role && role_id == Some(r.id);
            (r.id.to_string(), r.name, selected)
        })
        .collect();

    let tpl = AccountMacroEditTemplate {
        base,
        macro_id: macro_id.to_string(),
        return_to,
        name,
        is_personal: scope == MacroScope::Personal,
        macro_roles,
        error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct MacroReturnQuery {
    #[serde(default)]
    return_to: String,
}

pub async fn community_macro_edit_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    axum::extract::Path(macro_id): axum::extract::Path<Uuid>,
    Query(q): Query<MacroReturnQuery>,
) -> Result<Response, WebError> {
    let m = repo::macros::find_by_id(&state.pool, macro_id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_macro(&ctx, &m)?;
    render_community_macro_edit(
        &state,
        &jar,
        &ctx,
        m.id,
        safe_return_to(&q.return_to, "/account").to_string(),
        m.name,
        m.scope,
        m.role_id,
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct CommunityMacroEditForm {
    csrf_token: String,
    return_to: String,
    name: String,
    /// Blank means "keep the existing value" -- but only when `scope`
    /// isn't also changing away from what it already was; see
    /// `AccountMacroEditTemplate`'s doc comment.
    #[serde(default)]
    value: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    role_id: String,
}

pub async fn community_macro_edit(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    axum::extract::Path(macro_id): axum::extract::Path<Uuid>,
    Form(form): Form<CommunityMacroEditForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    let existing = repo::macros::find_by_id(&state.pool, macro_id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_macro(&ctx, &existing)?;

    let return_to = safe_return_to(&form.return_to, "/account").to_string();
    let scope: MacroScope = form.scope.trim().parse().unwrap_or(MacroScope::Personal);
    let role_id = form.role_id.trim().parse::<Uuid>().ok();

    let render_error = |message: String| {
        render_community_macro_edit(
            &state,
            &jar,
            &ctx,
            macro_id,
            return_to.clone(),
            form.name.clone(),
            scope,
            role_id,
            Some(message),
        )
    };

    let name = form.name.trim().to_string();
    if name.is_empty() || name.len() > 128 {
        return render_error("Macro name must be 1-128 characters.".to_string()).await;
    }

    let role_id = match scope {
        MacroScope::Personal => None,
        MacroScope::Role => {
            let Some(role_id) = role_id else {
                return render_error("Pick a role for a role-scoped macro.".to_string()).await;
            };
            let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
            if !user_roles.iter().any(|r| r.id == role_id) {
                return render_error(
                    "You can only save a role macro for a role you belong to.".to_string(),
                )
                .await;
            }
            Some(role_id)
        }
    };

    let value = form.value.trim();
    let secret_value_encrypted = if value.is_empty() {
        if scope != existing.scope || role_id != existing.role_id {
            return render_error(
                "Changing who this macro is visible to requires re-entering its value.".to_string(),
            )
            .await;
        }
        match existing.secret_value_encrypted.clone() {
            Some(existing_encrypted) => existing_encrypted,
            None => {
                return render_error("This macro has no stored value -- enter one.".to_string())
                    .await;
            }
        }
    } else {
        let Some(encryption_key) = &state.encryption_key else {
            return render_error(
                "ENCRYPTION_KEY isn't configured -- can't store a new value.".to_string(),
            )
            .await;
        };
        match encryption_key.encrypt(value) {
            Ok(v) => v,
            Err(e) => return render_error(format!("Encryption failed: {e}")).await,
        }
    };

    repo::macros::update(
        &state.pool,
        macro_id,
        repo::macros::MacroFields {
            name: &name,
            owner_user_id: existing.owner_user_id,
            scope,
            role_id,
            macro_type: MacroType::CommunityString,
            job_name: None,
            schedule: None,
            run_as_user: None,
            command: None,
            secret_value_encrypted: Some(&secret_value_encrypted),
        },
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::MacroUpdated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&name),
    )
    .await?;

    Ok(Redirect::to(&return_to).into_response())
}

pub async fn community_macro_remove_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    axum::extract::Path(macro_id): axum::extract::Path<Uuid>,
    Query(q): Query<MacroReturnQuery>,
) -> Result<Response, WebError> {
    let m = repo::macros::find_by_id(&state.pool, macro_id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_macro(&ctx, &m)?;
    let return_to = safe_return_to(&q.return_to, "/account").to_string();

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

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Remove macro".to_string(),
        message: format!("This will remove the macro \"{}\".", m.name),
        action_url: format!("/account/macros/{macro_id}/remove"),
        cancel_url: return_to.clone(),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "macro name".to_string(),
            expected: m.name,
        }),
        extra_hidden_fields: vec![("return_to".to_string(), return_to)],
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct CommunityMacroRemoveForm {
    csrf_token: String,
    return_to: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn community_macro_remove(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    axum::extract::Path(macro_id): axum::extract::Path<Uuid>,
    Form(form): Form<CommunityMacroRemoveForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }

    let m = repo::macros::find_by_id(&state.pool, macro_id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_macro(&ctx, &m)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &m.name)?;

    repo::macros::delete(&state.pool, macro_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::MacroDeleted, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&m.name),
    )
    .await?;

    Ok(Redirect::to(safe_return_to(&form.return_to, "/account")).into_response())
}
