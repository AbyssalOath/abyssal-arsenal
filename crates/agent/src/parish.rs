//! User, group, account, permission, and access management ("Parish") --
//! on the managed host itself (Linux accounts/groups via
//! `useradd`/`usermod`/`groupadd`/`userdel`/`groupdel`), never the
//! control plane's own login accounts (that's `/admin/users`, a
//! completely separate system with its own permissions).

use abyssal_agent_protocol::{CommandOutcome, is_protected_account_name, is_valid_account_name};

use crate::elevation::ElevationState;

fn validate_account(name: &str) -> Result<(), String> {
    if !is_valid_account_name(name) {
        return Err(format!("refusing invalid account/group name: {name}"));
    }
    Ok(())
}

fn validate_not_protected(name: &str) -> Result<(), String> {
    if is_protected_account_name(name) {
        return Err(format!("refusing to touch the protected account: {name}"));
    }
    Ok(())
}

pub async fn list_users(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("getent", &["passwd"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn list_groups(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("getent", &["group"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn user_detail(username: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_account(&username) {
        return CommandOutcome::Err(e);
    }
    match elevation.run("id", &[username.as_str()]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn create_user(
    username: String,
    comment: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_account(&username) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_gecos_comment(&comment) {
        return CommandOutcome::Err(format!("refusing invalid comment: {comment}"));
    }
    match elevation
        .run(
            "useradd",
            &["-m", "-c", comment.as_str(), username.as_str()],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn create_group(group: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_account(&group) {
        return CommandOutcome::Err(e);
    }
    match elevation.run("groupadd", &[group.as_str()]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn add_user_to_group(
    username: String,
    group: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_account(&username) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_account(&group) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("usermod", &["-aG", group.as_str(), username.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_user_from_group(
    username: String,
    group: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_account(&username) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_account(&group) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("gpasswd", &["-d", username.as_str(), group.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(unix)]
pub async fn lock_user_account(username: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_account(&username) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_not_protected(&username) {
        return CommandOutcome::Err(e);
    }
    match elevation.run("usermod", &["-L", username.as_str()]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(unix)]
pub async fn unlock_user_account(username: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_account(&username) {
        return CommandOutcome::Err(e);
    }
    match elevation.run("usermod", &["-U", username.as_str()]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Windows equivalent of `lock_user_account`/`unlock_user_account` above
/// -- `Disable-LocalUser`/`Enable-LocalUser` via PowerShell rather than
/// `usermod -L`/`-U`. Uses `is_valid_windows_account_name`/
/// `is_protected_windows_account_name` (mixed-case-friendly, a different
/// built-in protected-name set) rather than the Unix validators above --
/// see those functions' own doc comments for why they're genuinely
/// separate, not just cfg-gated copies.
#[cfg(windows)]
pub async fn lock_user_account(username: String, _elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_windows_account_name(&username) {
        return CommandOutcome::Err(format!("refusing invalid account name: {username}"));
    }
    if abyssal_agent_protocol::is_protected_windows_account_name(&username) {
        return CommandOutcome::Err(format!(
            "refusing to touch the protected account: {username}"
        ));
    }
    let script = crate::process::ps_checked(&format!(
        "Disable-LocalUser -Name {}",
        crate::process::ps_quote(&username)
    ));
    match crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    )
    .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(windows)]
pub async fn unlock_user_account(username: String, _elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_windows_account_name(&username) {
        return CommandOutcome::Err(format!("refusing invalid account name: {username}"));
    }
    let script = crate::process::ps_checked(&format!(
        "Enable-LocalUser -Name {}",
        crate::process::ps_quote(&username)
    ));
    match crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    )
    .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn delete_user(
    username: String,
    remove_home: bool,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_account(&username) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_not_protected(&username) {
        return CommandOutcome::Err(e);
    }
    let mut args = Vec::with_capacity(2);
    if remove_home {
        args.push("-r");
    }
    args.push(username.as_str());
    match elevation.run("userdel", &args).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn delete_group(group: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_account(&group) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_not_protected(&group) {
        return CommandOutcome::Err(e);
    }
    match elevation.run("groupdel", &[group.as_str()]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}
