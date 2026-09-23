use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
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

    let assignable = crate::common::assignable_roles(&state.pool, ctx).await?;
    let roles = crate::common::sorted_role_options(&state.pool, assignable)
        .await?
        .into_iter()
        .map(|(id, name, depth)| RoleOption {
            id: id.to_string(),
            name,
            depth,
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

    // Server-side re-check, not just an offer-only dropdown: the role
    // picker only ever *lists* roles within the admin's own delegated
    // subtree, but a raw POST could still name anything. GitHub issue
    // #8's "users can't assign roles above their own scope" is enforced
    // here, not just by what the form happens to render.
    let assignable = crate::common::assignable_roles(&state.pool, &ctx).await?;
    if !assignable.iter().any(|r| r.id == form.role_id) {
        return Err(WebError(AppError::Forbidden));
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
    repo::roles::set_user_role(&state.pool, user.id, form.role_id).await?;
    let role = repo::roles::find_by_id(&state.pool, form.role_id).await?;

    let welcome_email_sent = send_welcome_email(&state, &user, &form.password).await;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserCreated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&user.username)
            .metadata(serde_json::json!({ "welcome_email_sent": welcome_email_sent })),
    )
    .await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserRoleAssigned, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&user.username)
            .metadata(serde_json::json!({
                "role": role.map(|r| r.name).unwrap_or_default(),
                "previous_role": serde_json::Value::Null,
            })),
    )
    .await?;

    Ok(Redirect::to("/admin/users").into_response())
}

fn build_welcome_email(
    user: &abyssal_core::User,
    temporary_password: &str,
) -> abyssal_notifications::NotificationMessage {
    abyssal_notifications::NotificationMessage {
        subject: "Your Abyssal Arsenal account has been created".to_string(),
        body: format!(
            "Hello {username},\n\n\
             An administrator has created an Abyssal Arsenal account for you.\n\n\
             Username: {username}\n\
             Temporary password: {temporary_password}\n\n\
             You will be required to set a new password the first time you log in.\n\n\
             This is an automated message -- please do not reply.",
            username = user.username,
        ),
        severity: abyssal_notifications::Severity::Info,
        recipients: vec![user.email.clone()],
    }
}

/// Emails a newly-created local account its username and temporary
/// password, if it has an email address and at least one notification
/// provider is configured -- a no-op either way, never a reason to fail
/// user creation itself. Returns whether it actually went out, purely for
/// the audit record; a missing provider and a real send failure both just
/// result in `false` (the failure case is also logged via `tracing::warn`
/// by the dispatcher itself), since the admin still has the password to
/// hand over directly regardless of which one happened.
async fn send_welcome_email(
    state: &AppState,
    user: &abyssal_core::User,
    temporary_password: &str,
) -> bool {
    if user.email.trim().is_empty() {
        return false;
    }

    let message = build_welcome_email(user, temporary_password);
    let results = state.notifications.dispatch(&message).await;
    !results.is_empty() && results.iter().all(|(_, r)| r.is_ok())
}

#[allow(clippy::too_many_arguments)]
async fn render_edit(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    user_id: Uuid,
    username: String,
    email: String,
    error: Option<String>,
    generated_password: Option<String>,
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

    let password_prefill = generated_password.clone().unwrap_or_default();

    let assignable = crate::common::assignable_roles(&state.pool, ctx).await?;
    let current_role = repo::roles::roles_for_user(&state.pool, user_id)
        .await?
        .into_iter()
        .next();
    // Changing this user's role at all requires: the viewer can assign
    // roles in the first place, this isn't the viewer editing their own
    // role (GitHub issue #8's "users can't edit their own role"), and
    // either the viewer has no delegation ceiling (Super Admin can always
    // fix a user's role, including one with no role assigned at all) or
    // the user's *current* role is itself within the viewer's delegated
    // subtree -- otherwise a scoped admin could reach into an account
    // outside their scope just because they happen to know its URL.
    let can_change_role = user_id != ctx.user.id
        && (crate::common::has_no_ceiling(ctx)
            || current_role
                .as_ref()
                .is_some_and(|r| assignable.iter().any(|a| a.id == r.id)));
    let roles = crate::common::sorted_role_options(&state.pool, assignable)
        .await?
        .into_iter()
        .map(|(id, name, depth)| crate::templates::RoleOption {
            id: id.to_string(),
            name,
            depth,
        })
        .collect();

    let tpl = crate::templates::UserEditTemplate {
        base,
        user_id: user_id.to_string(),
        username,
        email,
        error,
        generated_password,
        password_prefill,
        roles,
        current_role_id: current_role.map(|r| r.id.to_string()).unwrap_or_default(),
        can_change_role,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn edit_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;
    let user = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    render_edit(
        &state,
        &jar,
        &ctx,
        user.id,
        user.username,
        user.email,
        None,
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct EditUserForm {
    csrf_token: String,
    username: String,
    email: String,
}

/// Fixes a typo'd username/email from account creation -- distinct from
/// `reset_password` below, which is a separate form/action on the same
/// edit page.
pub async fn edit(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<EditUserForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;
    require_csrf(&jar, &form.csrf_token)?;

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let username = form.username.trim().to_string();
    let email = form.email.trim().to_string();

    if username.is_empty() || username.len() > 64 {
        return render_edit(
            &state,
            &jar,
            &ctx,
            id,
            username,
            email,
            Some("Username must be 1-64 characters.".to_string()),
            None,
        )
        .await;
    }
    if email.is_empty() || !email.contains('@') {
        return render_edit(
            &state,
            &jar,
            &ctx,
            id,
            username,
            email,
            Some("That doesn't look like a valid email address.".to_string()),
            None,
        )
        .await;
    }

    repo::users::update_profile(&state.pool, id, &username, &email).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserProfileUpdated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&username)
            .metadata(serde_json::json!({
                "previous_username": target.username,
                "previous_email": target.email,
            })),
    )
    .await?;

    Ok(Redirect::to(&format!(
        "/admin/users?message={}",
        crate::common::urlencoding_encode(&format!("Updated {username}."))
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct ChangeRoleForm {
    csrf_token: String,
    role_id: Uuid,
}

/// A separate action from `edit` above (same split `reset_password`
/// already uses) -- GitHub issue #8. Every escalation guard applies here,
/// not just at user-creation time: a scoped admin can't reach outside
/// their own delegated subtree, and nobody can change their own role
/// this way (self-escalation via re-assigning yourself a broader role).
pub async fn change_role(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ChangeRoleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;
    require_csrf(&jar, &form.csrf_token)?;

    if id == ctx.user.id {
        return Err(WebError(AppError::Forbidden));
    }

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let previous_role = repo::roles::roles_for_user(&state.pool, id)
        .await?
        .into_iter()
        .next();

    let assignable = crate::common::assignable_roles(&state.pool, &ctx).await?;
    // A no-ceiling (Super Admin) viewer can always fix a user's role,
    // including one who currently has none assigned at all (e.g. stale
    // data); a scoped admin is still confined to targets whose *current*
    // role is within their own delegated subtree.
    let target_in_scope = crate::common::has_no_ceiling(&ctx)
        || previous_role
            .as_ref()
            .is_some_and(|r| assignable.iter().any(|a| a.id == r.id));
    let new_role_assignable = assignable.iter().any(|r| r.id == form.role_id);
    if !target_in_scope || !new_role_assignable {
        return Err(WebError(AppError::Forbidden));
    }

    repo::roles::set_user_role(&state.pool, id, form.role_id).await?;
    let new_role = repo::roles::find_by_id(&state.pool, form.role_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::UserRoleAssigned, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&target.username)
            .metadata(serde_json::json!({
                "role": new_role.map(|r| r.name).unwrap_or_default(),
                "previous_role": previous_role.map(|r| r.name),
            })),
    )
    .await?;

    Ok(Redirect::to(&format!(
        "/admin/users?message={}",
        crate::common::urlencoding_encode(&format!("Updated {}'s role.", target.username))
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    csrf_token: String,
    intent: String,
    #[serde(default)]
    password: String,
}

fn build_password_reset_email(
    user: &abyssal_core::User,
    temporary_password: &str,
) -> abyssal_notifications::NotificationMessage {
    abyssal_notifications::NotificationMessage {
        subject: "Your Abyssal Arsenal password has been reset".to_string(),
        body: format!(
            "Hello {username},\n\n\
             An administrator has reset the password on your Abyssal Arsenal account.\n\n\
             Username: {username}\n\
             Temporary password: {temporary_password}\n\n\
             You will be required to set a new password the next time you log in. Every \
             other active session of yours has been signed out.\n\n\
             This is an automated message -- please do not reply.",
            username = user.username,
        ),
        severity: abyssal_notifications::Severity::Info,
        recipients: vec![user.email.clone()],
    }
}

async fn send_password_reset_email(
    state: &AppState,
    user: &abyssal_core::User,
    temporary_password: &str,
) -> bool {
    if user.email.trim().is_empty() {
        return false;
    }
    let message = build_password_reset_email(user, temporary_password);
    let results = state.notifications.dispatch(&message).await;
    !results.is_empty() && results.iter().all(|(_, r)| r.is_ok())
}

/// Admin-triggered password reset -- e.g. the user forgot theirs, or the
/// admin wants to lock out a session they suspect is compromised. Mirrors
/// `create`'s own two-step "generate, review, then confirm" flow exactly:
/// `intent=generate` only previews a strong random password (re-renders
/// the edit page, nothing persisted yet); `intent=reset` persists whatever
/// the submitted password field actually contains, forces a change at
/// next login, and revokes every other active session of theirs, the same
/// way a self-service reset (`routes/password_reset.rs`) already does.
pub async fn reset_password(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ResetPasswordForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::UsersModify)?;
    require_csrf(&jar, &form.csrf_token)?;

    let target = repo::users::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    if form.intent == "generate" {
        let generated = abyssal_auth::password::generate_strong_password();
        return render_edit(
            &state,
            &jar,
            &ctx,
            id,
            target.username,
            target.email,
            None,
            Some(generated),
        )
        .await;
    }

    if let Err(message) = abyssal_auth::password::validate_strength(&form.password) {
        return render_edit(
            &state,
            &jar,
            &ctx,
            id,
            target.username,
            target.email,
            Some(message),
            None,
        )
        .await;
    }

    let hash = abyssal_auth::password::hash_password(&form.password)?;
    repo::users::update_password(&state.pool, id, &hash, true).await?;
    abyssal_auth::session::revoke_all_for_user(&state.pool, id).await?;

    let email_sent = send_password_reset_email(&state, &target, &form.password).await;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::PasswordReset, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&target.username)
            .metadata(serde_json::json!({ "email_sent": email_sent })),
    )
    .await?;

    Ok(Redirect::to(&format!(
        "/admin/users?message={}",
        crate::common::urlencoding_encode(&format!("Password reset for {}.", target.username))
    ))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_core::{AuthProviderKind, User};
    use chrono::Utc;

    fn test_user(email: &str) -> User {
        User {
            id: Uuid::new_v4(),
            username: "newuser".to_string(),
            email: email.to_string(),
            password_hash: None,
            auth_provider: AuthProviderKind::local(),
            is_active: true,
            must_change_password: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: None,
            timezone: "UTC".to_string(),
        }
    }

    #[test]
    fn welcome_email_contains_username_and_temp_password() {
        let user = test_user("newuser@example.com");
        let message = build_welcome_email(&user, "Temp1234!@#$Pass");

        assert_eq!(message.recipients, vec!["newuser@example.com".to_string()]);
        assert!(message.body.contains("newuser"));
        assert!(message.body.contains("Temp1234!@#$Pass"));
        assert!(message.body.contains("required to set a new password"));
    }
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
