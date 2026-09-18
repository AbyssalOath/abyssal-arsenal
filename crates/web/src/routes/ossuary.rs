use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::settings::HIGH_RISK_STORAGE_OPS_ENABLED;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf, urlencoding_encode};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, OssuaryHostRow, OssuaryHostTemplate, OssuaryTemplate};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;

    if let Some(host_id) = host_context::current(&jar) {
        if state.hosts.is_connected(host_id) {
            return Ok(Redirect::to(&format!("/arsenals/ossuary/{host_id}")).into_response());
        }
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

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(OssuaryHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = OssuaryTemplate { base, hosts };
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
    let high_risk_ops_enabled =
        repo::settings::get_bool(&state.pool, HIGH_RISK_STORAGE_OPS_ENABLED, false).await?;

    let tpl = OssuaryHostTemplate {
        can_manage: ctx.has(Permission::StorageManage),
        high_risk_ops_enabled,
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
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
}

/// The second gate the high-risk tier requires, on top of the normal
/// `storage.manage` permission and type-to-confirm: checked fresh at
/// every entry point that leads to a high-risk dispatch (both the
/// confirm-page GET and the dispatch POST), never assumed from an
/// earlier check.
async fn ensure_high_risk_enabled(state: &AppState) -> Result<(), WebError> {
    let enabled =
        repo::settings::get_bool(&state.pool, HIGH_RISK_STORAGE_OPS_ENABLED, false).await?;
    if !enabled {
        return Err(WebError(AppError::Validation(
            "High-risk storage operations are disabled. An admin must enable them on the \
             Settings page first."
                .into(),
        )));
    }
    Ok(())
}

fn validate_path(path: &str, label: &str) -> Result<String, WebError> {
    let path = path.trim().to_string();
    if !abyssal_agent_protocol::is_valid_mount_target(&path) {
        return Err(WebError(AppError::Validation(format!(
            "That doesn't look like a valid {label}."
        ))));
    }
    Ok(path)
}

/// Splits a comma/whitespace-separated device list from a plain text
/// input and validates each entry.
fn parse_device_list(raw: &str) -> Result<Vec<String>, WebError> {
    let devices: Vec<String> = raw
        .split([',', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if devices.is_empty() {
        return Err(WebError(AppError::Validation(
            "Provide at least one device.".into(),
        )));
    }
    for device in &devices {
        if !abyssal_agent_protocol::is_valid_mount_target(device) {
            return Err(WebError(AppError::Validation(format!(
                "\"{device}\" doesn't look like a valid device path."
            ))));
        }
    }
    Ok(devices)
}

// ---------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

#[allow(clippy::too_many_arguments)]
async fn run_read_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::StorageView,
            OperationKind::Read,
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
                Some(output.stdout),
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
pub struct DeviceForm {
    csrf_token: String,
    device: String,
}

pub async fn partition_table(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<DeviceForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let device = validate_path(&form.device, "device path")?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::PartitionTable {
            device: device.clone(),
        },
        &format!("Partition Table ({device})"),
    )
    .await
}

pub async fn lvm_summary(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::LvmSummary,
        "LVM Summary",
    )
    .await
}

pub async fn raid_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RaidStatus,
        "RAID Status",
    )
    .await
}

// ---------------------------------------------------------------------
// Write (conservative tier)
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_write_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::StorageManage,
            OperationKind::Write,
            false,
            Duration::from_secs(60),
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
                Some(output.stdout),
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
pub struct MountForm {
    csrf_token: String,
    device: String,
    target: String,
}

pub async fn mount_filesystem(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<MountForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let device = validate_path(&form.device, "device path")?;
    let target = validate_path(&form.target, "mount target")?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::MountFilesystem {
            device: device.clone(),
            target: target.clone(),
        },
        &format!("Mount ({device} -> {target})"),
    )
    .await
}

#[derive(Deserialize)]
pub struct ExtendLvForm {
    csrf_token: String,
    lv_path: String,
    size: String,
}

pub async fn extend_logical_volume(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ExtendLvForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let lv_path = validate_path(&form.lv_path, "logical volume path")?;
    if !abyssal_agent_protocol::is_valid_vacuum_size(&form.size) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid size (e.g. 10G, 500M).".into(),
        )));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ExtendLogicalVolume {
            lv_path: lv_path.clone(),
            size: form.size.clone(),
        },
        &format!("Extend LV ({lv_path} +{})", form.size),
    )
    .await
}

// ---------------------------------------------------------------------
// Shared Destructive confirm/dispatch machinery -- used by both the
// conservative tier's one Destructive op (unmount) and every high-risk
// op. `high_risk` controls whether `ensure_high_risk_enabled` is also
// checked; every call site still checks it again itself right before
// this, too -- belt and suspenders on the one gate this arsenal can't
// afford to get wrong.
#[allow(clippy::too_many_arguments)]
async fn destructive_confirm(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    title: &str,
    build_message: impl FnOnce(&str) -> String,
    action_url: String,
    type_to_confirm_label: &str,
    type_to_confirm_expected: &str,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageManage)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
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

    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: title.to_string(),
        message: build_message(&host.name),
        action_url,
        cancel_url: format!("/arsenals/ossuary/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: type_to_confirm_label.to_string(),
            expected: type_to_confirm_expected.to_string(),
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
pub struct ConfirmForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

#[allow(clippy::too_many_arguments)]
async fn run_destructive_op(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    expected_confirm_text: &str,
    operation: AgentOperation,
    label: &str,
    form: ConfirmForm,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(format!(
            "{label} was not confirmed."
        ))));
    }
    crate::common::require_typed_confirmation(&form.confirm_text, expected_confirm_text)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::StorageManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(180),
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
                Some(output.stdout),
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

// ---------------------------------------------------------------------
// Destructive (conservative tier): unmount
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SingleFieldQuery {
    value: String,
}

pub async fn unmount_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    let target = validate_path(&q.value, "mount target")?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/unmount?value={}",
        urlencoding_encode(&target)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Unmount filesystem",
        |host_name| {
            format!(
                "This will unmount \"{target}\" on \"{host_name}\". Whatever's using it loses \
                 access immediately -- the data itself is untouched, but this can disrupt \
                 anything relying on that mount."
            )
        },
        action_url,
        "mount target",
        &target,
    )
    .await
}

pub async fn unmount_filesystem(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let target = validate_path(&q.value, "mount target")?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &target,
        AgentOperation::UnmountFilesystem {
            target: target.clone(),
        },
        "Unmount Filesystem",
        form,
    )
    .await
}

// ---------------------------------------------------------------------
// Destructive (high-risk tier): partitions
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PartitionCreateQuery {
    device: String,
    start: String,
    end: String,
}

fn validate_partition_bounds(start: &str, end: &str) -> Result<(), WebError> {
    if !abyssal_agent_protocol::is_valid_partition_position(start)
        || !abyssal_agent_protocol::is_valid_partition_position(end)
    {
        return Err(WebError(AppError::Validation(
            "Start/end aren't valid partition positions (e.g. 0%, 50%, 1MiB).".into(),
        )));
    }
    Ok(())
}

pub async fn create_partition_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<PartitionCreateQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.device, "device path")?;
    validate_partition_bounds(&q.start, &q.end)?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/create-partition?device={}&start={}&end={}",
        urlencoding_encode(&device),
        urlencoding_encode(&q.start),
        urlencoding_encode(&q.end)
    );
    let (start, end) = (q.start.clone(), q.end.clone());
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Create partition",
        move |host_name| {
            format!(
                "This will create a new partition on \"{device}\" (on \"{host_name}\") from \
                 {start} to {end}. A wrong device here can corrupt or destroy the disk's \
                 existing layout. This cannot be undone."
            )
        },
        action_url,
        "device path",
        &q.device,
    )
    .await
}

pub async fn create_partition(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<PartitionCreateQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.device, "device path")?;
    validate_partition_bounds(&q.start, &q.end)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &device,
        AgentOperation::CreatePartition {
            device: device.clone(),
            start: q.start,
            end: q.end,
        },
        "Create Partition",
        form,
    )
    .await
}

#[derive(Deserialize)]
pub struct PartitionDeleteQuery {
    device: String,
    partition_number: u32,
}

pub async fn delete_partition_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<PartitionDeleteQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.device, "device path")?;
    if !abyssal_agent_protocol::is_valid_partition_number(q.partition_number) {
        return Err(WebError(AppError::Validation(
            "That isn't a valid partition number.".into(),
        )));
    }
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/delete-partition?device={}&partition_number={}",
        urlencoding_encode(&device),
        q.partition_number
    );
    let partition_number = q.partition_number;
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Delete partition",
        move |host_name| {
            format!(
                "This will delete partition {partition_number} on \"{device}\" (on \
                 \"{host_name}\"). This cannot be undone."
            )
        },
        action_url,
        "device path",
        &q.device,
    )
    .await
}

pub async fn delete_partition(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<PartitionDeleteQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.device, "device path")?;
    if !abyssal_agent_protocol::is_valid_partition_number(q.partition_number) {
        return Err(WebError(AppError::Validation(
            "That isn't a valid partition number.".into(),
        )));
    }
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &device,
        AgentOperation::DeletePartition {
            device: device.clone(),
            partition_number: q.partition_number,
        },
        "Delete Partition",
        form,
    )
    .await
}

// ---------------------------------------------------------------------
// Destructive (high-risk tier): RAID
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RaidCreateQuery {
    array_name: String,
    level: String,
    /// Comma/whitespace-separated device list -- a plain text field on
    /// the form, split and validated by `parse_device_list`.
    devices: String,
}

pub async fn create_raid_array_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<RaidCreateQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let array_name = validate_path(&q.array_name, "array name")?;
    if !abyssal_agent_protocol::is_valid_raid_level(&q.level) {
        return Err(WebError(AppError::Validation(
            "That isn't a supported RAID level.".into(),
        )));
    }
    let devices = parse_device_list(&q.devices)?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/create-raid?array_name={}&level={}&devices={}",
        urlencoding_encode(&array_name),
        urlencoding_encode(&q.level),
        urlencoding_encode(&devices.join(","))
    );
    let (level, device_list) = (q.level.clone(), devices.join(", "));
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Create RAID array",
        move |host_name| {
            format!(
                "This will create RAID{level} array \"{array_name}\" on \"{host_name}\" from: \
                 {device_list}. Every listed device is consumed -- any existing data on them is \
                 destroyed the moment the array is created. This cannot be undone."
            )
        },
        action_url,
        "array name",
        &q.array_name,
    )
    .await
}

pub async fn create_raid_array(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<RaidCreateQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let array_name = validate_path(&q.array_name, "array name")?;
    if !abyssal_agent_protocol::is_valid_raid_level(&q.level) {
        return Err(WebError(AppError::Validation(
            "That isn't a supported RAID level.".into(),
        )));
    }
    let devices = parse_device_list(&q.devices)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &array_name,
        AgentOperation::CreateRaidArray {
            array_name: array_name.clone(),
            level: q.level,
            devices,
        },
        "Create RAID Array",
        form,
    )
    .await
}

pub async fn stop_raid_array_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let array_name = validate_path(&q.value, "array name")?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/stop-raid?value={}",
        urlencoding_encode(&array_name)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Stop RAID array",
        move |host_name| {
            format!(
                "This will stop (deactivate) RAID array \"{array_name}\" on \"{host_name}\". \
                 Reassembling it later is possible but not automatic."
            )
        },
        action_url,
        "array name",
        &q.value,
    )
    .await
}

pub async fn stop_raid_array(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let array_name = validate_path(&q.value, "array name")?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &array_name,
        AgentOperation::StopRaidArray {
            array_name: array_name.clone(),
        },
        "Stop RAID Array",
        form,
    )
    .await
}

// ---------------------------------------------------------------------
// Destructive (high-risk tier): LVM
// ---------------------------------------------------------------------

pub async fn create_physical_volume_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.value, "device path")?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/create-pv?value={}",
        urlencoding_encode(&device)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Create physical volume",
        move |host_name| {
            format!(
                "This will initialize \"{device}\" on \"{host_name}\" as an LVM physical \
                 volume, wiping any existing filesystem signature on it. This cannot be undone."
            )
        },
        action_url,
        "device path",
        &q.value,
    )
    .await
}

pub async fn create_physical_volume(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.value, "device path")?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &device,
        AgentOperation::CreatePhysicalVolume {
            device: device.clone(),
        },
        "Create Physical Volume",
        form,
    )
    .await
}

pub async fn remove_physical_volume_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.value, "device path")?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/remove-pv?value={}",
        urlencoding_encode(&device)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Remove physical volume",
        move |host_name| {
            format!(
                "This will remove LVM physical volume metadata from \"{device}\" on \
                 \"{host_name}\". This cannot be undone."
            )
        },
        action_url,
        "device path",
        &q.value,
    )
    .await
}

pub async fn remove_physical_volume(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.value, "device path")?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &device,
        AgentOperation::RemovePhysicalVolume {
            device: device.clone(),
        },
        "Remove Physical Volume",
        form,
    )
    .await
}

#[derive(Deserialize)]
pub struct VolumeGroupCreateQuery {
    name: String,
    /// Comma/whitespace-separated physical volume list.
    physical_volumes: String,
}

pub async fn create_volume_group_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<VolumeGroupCreateQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let name = validate_path(&q.name, "volume group name")?;
    let pvs = parse_device_list(&q.physical_volumes)?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/create-vg?name={}&physical_volumes={}",
        urlencoding_encode(&name),
        urlencoding_encode(&pvs.join(","))
    );
    let pv_list = pvs.join(", ");
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Create volume group",
        move |host_name| {
            format!(
                "This will create volume group \"{name}\" on \"{host_name}\" from: {pv_list}. \
                 This cannot be undone."
            )
        },
        action_url,
        "volume group name",
        &q.name,
    )
    .await
}

pub async fn create_volume_group(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<VolumeGroupCreateQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let name = validate_path(&q.name, "volume group name")?;
    let physical_volumes = parse_device_list(&q.physical_volumes)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &name,
        AgentOperation::CreateVolumeGroup {
            name: name.clone(),
            physical_volumes,
        },
        "Create Volume Group",
        form,
    )
    .await
}

pub async fn remove_volume_group_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let name = validate_path(&q.value, "volume group name")?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/remove-vg?value={}",
        urlencoding_encode(&name)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Remove volume group",
        move |host_name| {
            format!(
                "This will remove volume group \"{name}\" on \"{host_name}\" (refused if it \
                 still has logical volumes). This cannot be undone."
            )
        },
        action_url,
        "volume group name",
        &q.value,
    )
    .await
}

pub async fn remove_volume_group(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let name = validate_path(&q.value, "volume group name")?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &name,
        AgentOperation::RemoveVolumeGroup { name: name.clone() },
        "Remove Volume Group",
        form,
    )
    .await
}

#[derive(Deserialize)]
pub struct LogicalVolumeCreateQuery {
    vg_name: String,
    lv_name: String,
    size: String,
}

pub async fn create_logical_volume_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<LogicalVolumeCreateQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let vg_name = validate_path(&q.vg_name, "volume group name")?;
    let lv_name = validate_path(&q.lv_name, "logical volume name")?;
    if !abyssal_agent_protocol::is_valid_vacuum_size(&q.size) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid size (e.g. 10G, 500M).".into(),
        )));
    }
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/create-lv?vg_name={}&lv_name={}&size={}",
        urlencoding_encode(&vg_name),
        urlencoding_encode(&lv_name),
        urlencoding_encode(&q.size)
    );
    let size = q.size.clone();
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Create logical volume",
        move |host_name| {
            format!(
                "This will create logical volume \"{lv_name}\" ({size}) in volume group \
                 \"{vg_name}\" on \"{host_name}\"."
            )
        },
        action_url,
        "volume group name",
        &q.vg_name,
    )
    .await
}

pub async fn create_logical_volume(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<LogicalVolumeCreateQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let vg_name = validate_path(&q.vg_name, "volume group name")?;
    let lv_name = validate_path(&q.lv_name, "logical volume name")?;
    if !abyssal_agent_protocol::is_valid_vacuum_size(&q.size) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid size.".into(),
        )));
    }
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &vg_name,
        AgentOperation::CreateLogicalVolume {
            vg_name: vg_name.clone(),
            lv_name,
            size: q.size,
        },
        "Create Logical Volume",
        form,
    )
    .await
}

pub async fn remove_logical_volume_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let lv_path = validate_path(&q.value, "logical volume path")?;
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/remove-lv?value={}",
        urlencoding_encode(&lv_path)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Remove logical volume",
        move |host_name| {
            format!(
                "This will remove logical volume \"{lv_path}\" and its data on \"{host_name}\". \
                 This cannot be undone."
            )
        },
        action_url,
        "logical volume path",
        &q.value,
    )
    .await
}

pub async fn remove_logical_volume(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let lv_path = validate_path(&q.value, "logical volume path")?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &lv_path,
        AgentOperation::RemoveLogicalVolume {
            lv_path: lv_path.clone(),
        },
        "Remove Logical Volume",
        form,
    )
    .await
}

// ---------------------------------------------------------------------
// Destructive (high-risk tier): create filesystem
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FilesystemCreateQuery {
    device: String,
    fstype: String,
}

pub async fn create_filesystem_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<FilesystemCreateQuery>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.device, "device path")?;
    if !abyssal_agent_protocol::is_valid_fstype(&q.fstype) {
        return Err(WebError(AppError::Validation(
            "That isn't a supported filesystem type.".into(),
        )));
    }
    let action_url = format!(
        "/arsenals/ossuary/{host_id}/mkfs?device={}&fstype={}",
        urlencoding_encode(&device),
        urlencoding_encode(&q.fstype)
    );
    let fstype = q.fstype.clone();
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Create filesystem",
        move |host_name| {
            format!(
                "This will create a {fstype} filesystem on \"{device}\" (on \"{host_name}\"), \
                 DESTROYING EVERYTHING currently on it, unconditionally and instantly. There is \
                 no partial-safety case here -- double-check this is the exact device you mean \
                 before confirming. This cannot be undone."
            )
        },
        action_url,
        "device path",
        &q.device,
    )
    .await
}

pub async fn create_filesystem(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<FilesystemCreateQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_high_risk_enabled(&state).await?;
    let device = validate_path(&q.device, "device path")?;
    if !abyssal_agent_protocol::is_valid_fstype(&q.fstype) {
        return Err(WebError(AppError::Validation(
            "That isn't a supported filesystem type.".into(),
        )));
    }
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &device,
        AgentOperation::CreateFilesystem {
            device: device.clone(),
            fstype: q.fstype,
        },
        "Create Filesystem",
        form,
    )
    .await
}

#[derive(Deserialize)]
pub struct ElevateForm {
    csrf_token: String,
    sudo_password: String,
}

pub async fn elevate(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ElevateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsElevate)?;
    require_csrf(&jar, &form.csrf_token)?;

    if form.sudo_password.trim().is_empty() {
        return Err(WebError(AppError::Validation(
            "Enter a sudo password to elevate.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match maybe_elevate(&state, &ctx, host_id, &host.name, Some(form.sudo_password)).await {
        Ok(warning) => {
            let message = format!("{}Elevated.", warning.unwrap_or(""));
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Elevate".to_string()),
                Some(message),
                None,
            )
            .await
        }
        Err(e) => {
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Elevate".to_string()),
                None,
                Some(e),
            )
            .await
        }
    }
}
