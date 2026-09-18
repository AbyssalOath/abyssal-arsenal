use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf, urlencoding_encode};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, ParishHostRow, ParishHostTemplate, ParishTemplate};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersView)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(ParishHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = ParishTemplate { base, hosts };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

async fn render_host(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(ctx, &theme::current(jar), &csrf_token, &state.elevation);

    let tpl = ParishHostTemplate {
        can_manage: ctx.has(Permission::HostUsersManage),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        result_label,
        result_output,
        result_error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn show_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

fn validate_account(name: &str, label: &str) -> Result<String, WebError> {
    let name = name.trim().to_string();
    if !abyssal_agent_protocol::is_valid_account_name(&name) {
        return Err(WebError(AppError::Validation(format!(
            "That doesn't look like a valid {label} name."
        ))));
    }
    Ok(name)
}

fn reject_protected(name: &str) -> Result<(), WebError> {
    if abyssal_agent_protocol::is_protected_account_name(name) {
        return Err(WebError(AppError::Validation(
            "That account is protected and can't be touched here.".into(),
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_read_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    sudo_password: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let tls_warning = match maybe_elevate(state, ctx, host_id, &host.name, sudo_password).await {
        Ok(warning) => warning.unwrap_or(""),
        Err(e) => return render_host(state, jar, ctx, host_id, result_label, None, Some(e)).await,
    };

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::HostUsersView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(format!("{tls_warning}{}", output.stdout)),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

pub async fn list_users(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListUsers,
        "Users",
        form.sudo_password,
    )
    .await
}

pub async fn list_groups(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListGroups,
        "Groups",
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct UsernameForm {
    csrf_token: String,
    username: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn user_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UsernameForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let username = validate_account(&form.username, "username")?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::UserDetail {
            username: username.clone(),
        },
        &format!("User Detail ({username})"),
        form.sudo_password,
    )
    .await
}

/// Shared by every Write op below (six of them): additive or trivially
/// reversible account/group mutations, none needing the explicit
/// confirmation a `Destructive` operation does.
#[allow(clippy::too_many_arguments)]
async fn run_write_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    sudo_password: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let tls_warning = match maybe_elevate(state, ctx, host_id, &host.name, sudo_password).await {
        Ok(warning) => warning.unwrap_or(""),
        Err(e) => return render_host(state, jar, ctx, host_id, result_label, None, Some(e)).await,
    };

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::HostUsersManage,
            OperationKind::Write,
            false,
            Duration::from_secs(20),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(format!("{tls_warning}{}", output.stdout)),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    csrf_token: String,
    username: String,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<CreateUserForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let username = validate_account(&form.username, "username")?;
    if !abyssal_agent_protocol::is_valid_gecos_comment(&form.comment) {
        return Err(WebError(AppError::Validation(
            "That comment isn't valid.".into(),
        )));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::CreateUser {
            username: username.clone(),
            comment: form.comment,
        },
        &format!("Create User ({username})"),
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct GroupForm {
    csrf_token: String,
    group: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn create_group(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<GroupForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let group = validate_account(&form.group, "group")?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::CreateGroup {
            group: group.clone(),
        },
        &format!("Create Group ({group})"),
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct UserGroupForm {
    csrf_token: String,
    username: String,
    group: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn add_user_to_group(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UserGroupForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let username = validate_account(&form.username, "username")?;
    let group = validate_account(&form.group, "group")?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::AddUserToGroup {
            username: username.clone(),
            group: group.clone(),
        },
        &format!("Add {username} to {group}"),
        form.sudo_password,
    )
    .await
}

pub async fn remove_user_from_group(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UserGroupForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let username = validate_account(&form.username, "username")?;
    let group = validate_account(&form.group, "group")?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RemoveUserFromGroup {
            username: username.clone(),
            group: group.clone(),
        },
        &format!("Remove {username} from {group}"),
        form.sudo_password,
    )
    .await
}

pub async fn lock_user_account(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UsernameForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let username = validate_account(&form.username, "username")?;
    reject_protected(&username)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::LockUserAccount {
            username: username.clone(),
        },
        &format!("Lock Account ({username})"),
        form.sudo_password,
    )
    .await
}

pub async fn unlock_user_account(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UsernameForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let username = validate_account(&form.username, "username")?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::UnlockUserAccount {
            username: username.clone(),
        },
        &format!("Unlock Account ({username})"),
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn run_destructive_op(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    target_name: &str,
    operation: AgentOperation,
    label: &str,
    form: ConfirmForm,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(format!(
            "{label} was not confirmed."
        ))));
    }
    crate::common::require_typed_confirmation(&form.confirm_text, target_name)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let tls_warning =
        match maybe_elevate(state, &ctx, host_id, &host.name, form.sudo_password).await {
            Ok(warning) => warning.unwrap_or(""),
            Err(e) => {
                return render_host(state, &jar, &ctx, host_id, result_label, None, Some(e)).await
            }
        };

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::HostUsersManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(20),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(format!("{tls_warning}{}", output.stdout)),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                &jar,
                &ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteUserQuery {
    username: String,
    #[serde(default)]
    remove_home: bool,
}

pub async fn delete_user_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<DeleteUserQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    let username = validate_account(&q.username, "username")?;
    reject_protected(&username)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let home_note = if q.remove_home {
        " and its home directory"
    } else {
        " (home directory is kept)"
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Delete user".to_string(),
        message: format!(
            "This will permanently delete the account \"{username}\"{home_note} on \"{}\". \
             This cannot be undone.",
            host.name
        ),
        action_url: format!(
            "/arsenals/parish/{host_id}/delete-user?username={}&remove_home={}",
            urlencoding_encode(&username),
            q.remove_home
        ),
        cancel_url: format!("/arsenals/parish/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "username".to_string(),
            expected: username.clone(),
        }),
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn delete_user(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<DeleteUserQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let username = validate_account(&q.username, "username")?;
    reject_protected(&username)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &username,
        AgentOperation::DeleteUser {
            username: username.clone(),
            remove_home: q.remove_home,
        },
        "Delete User",
        form,
    )
    .await
}

#[derive(Deserialize)]
pub struct GroupQuery {
    group: String,
}

pub async fn delete_group_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<GroupQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostUsersManage)?;
    let group = validate_account(&q.group, "group")?;
    reject_protected(&group)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Delete group".to_string(),
        message: format!(
            "This will permanently delete the group \"{group}\" on \"{}\". This cannot be undone.",
            host.name
        ),
        action_url: format!(
            "/arsenals/parish/{host_id}/delete-group?group={}",
            urlencoding_encode(&group)
        ),
        cancel_url: format!("/arsenals/parish/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "group name".to_string(),
            expected: group.clone(),
        }),
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn delete_group(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<GroupQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let group = validate_account(&q.group, "group")?;
    reject_protected(&group)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &group,
        AgentOperation::DeleteGroup {
            group: group.clone(),
        },
        "Delete Group",
        form,
    )
    .await
}
