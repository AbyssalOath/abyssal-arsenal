//! User, group, account, permission, and access management ("Parish") --
//! on the managed host itself (Linux accounts/groups via
//! `useradd`/`usermod`/`groupadd`/`userdel`/`groupdel`), never the
//! control plane's own login accounts (that's `/admin/users`, a
//! completely separate system with its own permissions).

use abyssal_agent_protocol::{is_protected_account_name, is_valid_account_name, CommandOutcome};

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

pub async fn unlock_user_account(username: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_account(&username) {
        return CommandOutcome::Err(e);
    }
    match elevation.run("usermod", &["-U", username.as_str()]).await {
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
