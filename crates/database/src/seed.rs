use abyssal_core::{Permission, role};

use crate::{DbPool, repo};

/// Idempotently seeds the fixed permission catalogue and the built-in roles with
/// their default permission sets. Safe to call on every startup — existing rows
/// are left as-is aside from the permission catalogue itself, which always
/// reflects `Permission::ALL` (the Rust enum is the single source of truth).
pub async fn seed_core_defaults(pool: &DbPool) -> anyhow::Result<()> {
    for perm in Permission::ALL {
        sqlx::query("INSERT IGNORE INTO permissions (`key`, description) VALUES (?, ?)")
            .bind(perm.as_key())
            .bind(perm.as_key())
            .execute(pool)
            .await?;
    }

    seed_super_admin(pool).await?;

    seed_role(
        pool,
        role::SYSTEM_ADMIN,
        "General system administration: systems, storage, containers, backups.",
        vec![
            Permission::SystemsView,
            Permission::SystemsManage,
            Permission::HostUsersView,
            Permission::HostUsersManage,
            Permission::StorageView,
            Permission::StorageManage,
            Permission::StorageConnectionsView,
            Permission::StorageConnectionsManage,
            Permission::ContainersView,
            Permission::ContainersManage,
            Permission::BackupsView,
            Permission::BackupsCreate,
            Permission::BackupsRestore,
            Permission::AuditView,
            Permission::HostsView,
            Permission::HostsEnroll,
            Permission::HostsManage,
            Permission::HostsElevate,
        ],
    )
    .await?;

    seed_role(
        pool,
        role::NETWORK_ADMIN,
        "Network configuration and connectivity.",
        vec![
            Permission::SystemsView,
            Permission::NetworkView,
            Permission::NetworkManage,
            Permission::NetworkScan,
            Permission::NetworkNac,
            Permission::AuditView,
            Permission::HostsView,
            Permission::HostsEnroll,
            Permission::HostsElevate,
        ],
    )
    .await?;

    seed_role(
        pool,
        role::SECURITY_ADMIN,
        "Security hardening, incident response, and audit oversight.",
        vec![
            Permission::UsersView,
            Permission::SystemsView,
            Permission::NetworkView,
            Permission::HostUsersView,
            Permission::SecurityView,
            Permission::SecurityManage,
            Permission::IncidentsView,
            Permission::IncidentsRespond,
            Permission::AuditView,
            Permission::AuditExport,
            Permission::HostsView,
            Permission::HostsElevate,
            Permission::ScourgeView,
            Permission::ScourgeManage,
        ],
    )
    .await?;

    seed_role(
        pool,
        role::REGULAR_USER,
        "Read-only visibility across operational domains.",
        vec![
            Permission::SystemsView,
            Permission::NetworkView,
            Permission::SecurityView,
            Permission::ContainersView,
            Permission::StorageView,
            Permission::BackupsView,
            Permission::IncidentsView,
            Permission::HostsView,
        ],
    )
    .await?;

    upgrade_role_defaults(pool).await?;

    Ok(())
}

/// The version of the built-in roles' default permissions an install has
/// been brought up to. `seed_role` only sets a role's permissions when it's
/// first created (so an admin's customizations survive restarts), which means
/// a change to the defaults never reaches an existing install on its own --
/// each version below is that change, applied exactly once.
const ROLE_DEFAULTS_VERSION_KEY: &str = "rbac.role_defaults_version";
/// Installs from before this tracking existed are at version 1.
const ROLE_DEFAULTS_VERSION: u32 = 2;

/// One built-in role's change in a defaults version.
struct RoleDelta {
    role: &'static str,
    grant: &'static [Permission],
    revoke: &'static [Permission],
}

/// v2 (0.2.1): roles re-examined for least privilege.
/// - `hosts.enroll` and `network.nac` are new, split out of `hosts.manage`
///   and `network.manage`; see `upgrade_role_defaults` for how existing
///   holders keep them.
/// - Network Admin can now run discovery and switch polls (`network.scan`),
///   see managed hosts, add hosts through Panopticon (`hosts.enroll`, not the
///   much broader `hosts.manage`), and elevate a host it configures.
/// - System Admin gains Sepulchre (storage connectivity, used by Reliquary)
///   and elevation, and loses `users.view`: listing the control plane's own
///   login accounts isn't systems work.
/// - Security Admin gains read-only systems, network and host-account
///   visibility for investigations, the host list, and elevation for
///   hardening.
/// - Regular User gains the read-only host list.
const V2_DELTAS: &[RoleDelta] = &[
    RoleDelta {
        role: role::SYSTEM_ADMIN,
        grant: &[
            Permission::StorageConnectionsView,
            Permission::StorageConnectionsManage,
            Permission::HostsElevate,
        ],
        revoke: &[Permission::UsersView],
    },
    RoleDelta {
        role: role::NETWORK_ADMIN,
        grant: &[
            Permission::NetworkScan,
            Permission::HostsView,
            Permission::HostsEnroll,
            Permission::HostsElevate,
        ],
        revoke: &[],
    },
    RoleDelta {
        role: role::SECURITY_ADMIN,
        grant: &[
            Permission::SystemsView,
            Permission::NetworkView,
            Permission::HostUsersView,
            Permission::HostsView,
            Permission::HostsElevate,
        ],
        revoke: &[],
    },
    RoleDelta {
        role: role::REGULAR_USER,
        grant: &[Permission::HostsView],
        revoke: &[],
    },
];

/// Brings an existing install's roles up to the current defaults, once per
/// version. Touches only the permissions a version names, so anything else an
/// admin customized stays as it was. On a fresh install every step is a
/// no-op (the roles were just created with the current defaults).
async fn upgrade_role_defaults(pool: &DbPool) -> anyhow::Result<()> {
    let from = repo::settings::get_u32(pool, ROLE_DEFAULTS_VERSION_KEY, 1).await?;
    if from >= ROLE_DEFAULTS_VERSION {
        return Ok(());
    }

    if from < 2 {
        // Splitting a permission must not take anything away from a role --
        // custom roles and sub-roles included -- that could do it before.
        for role in repo::roles::list(pool).await? {
            let current = repo::roles::permissions_for_role(pool, role.id).await?;
            let mut grant = Vec::new();
            if current.contains(&Permission::HostsManage) {
                grant.push(Permission::HostsEnroll);
            }
            if current.contains(&Permission::NetworkManage) {
                grant.push(Permission::NetworkNac);
            }
            apply_delta(pool, role.id, &current, &grant, &[]).await?;
        }
        for delta in V2_DELTAS {
            if let Some(role) = repo::roles::find_by_name(pool, delta.role).await? {
                let current = repo::roles::permissions_for_role(pool, role.id).await?;
                apply_delta(pool, role.id, &current, delta.grant, delta.revoke).await?;
            }
        }
    }

    repo::settings::set(
        pool,
        ROLE_DEFAULTS_VERSION_KEY,
        serde_json::json!(ROLE_DEFAULTS_VERSION),
        None,
    )
    .await?;
    tracing::info!(
        from,
        to = ROLE_DEFAULTS_VERSION,
        "updated the built-in roles' default permissions"
    );
    Ok(())
}

async fn apply_delta(
    pool: &DbPool,
    role_id: uuid::Uuid,
    current: &[Permission],
    grant: &[Permission],
    revoke: &[Permission],
) -> anyhow::Result<()> {
    let updated = delta_result(current, grant, revoke);
    if updated.len() != current.len() || !updated.iter().all(|p| current.contains(p)) {
        repo::roles::set_permissions(pool, role_id, &updated).await?;
    }
    Ok(())
}

/// `current` plus `grant`, minus `revoke`, keeping `current`'s order.
fn delta_result(
    current: &[Permission],
    grant: &[Permission],
    revoke: &[Permission],
) -> Vec<Permission> {
    let mut updated: Vec<Permission> = current
        .iter()
        .copied()
        .filter(|p| !revoke.contains(p))
        .collect();
    for p in grant {
        if !updated.contains(p) {
            updated.push(*p);
        }
    }
    updated
}

async fn seed_role(
    pool: &DbPool,
    name: &str,
    description: &str,
    permissions: Vec<Permission>,
) -> anyhow::Result<()> {
    let role = match repo::roles::find_by_name(pool, name).await? {
        Some(existing) => existing,
        None => repo::roles::create(pool, name, description, true, None, None).await?,
    };

    // Only set the permission set the first time it's created; an admin may have
    // since customized it and startup shouldn't clobber that.
    let current = repo::roles::permissions_for_role(pool, role.id).await?;
    if current.is_empty() {
        repo::roles::set_permissions(pool, role.id, &permissions).await?;
    }

    Ok(())
}

/// Super Admin gets different treatment from every other system role:
/// its whole reason to exist is "holds every permission the platform
/// knows about, no exceptions" -- `has_no_ceiling()`
/// (`crates/web/src/common.rs`) is *computed* from that fact (holding
/// literally all of `Permission::ALL`) rather than a hardcoded role-name
/// check, specifically so a role is still "just a named collection of
/// permissions." That design only holds up if Super Admin's own
/// collection is actually kept complete -- `seed_role`'s normal
/// "only set on first creation" rule (correct for every *other* role,
/// where an admin narrowing it down is a deliberate, legitimate choice)
/// would otherwise silently leave Super Admin missing any permission
/// added after its row was first created, exactly as happened here: a
/// single missing permission (whichever arsenal or feature shipped most
/// recently) was enough to flip `has_no_ceiling()` to `false`, which
/// cascaded into Super Admin losing the ability to edit *any* role's
/// permissions -- including its own -- since `ensure_can_manage_role`
/// only bypasses the "system roles can't be edited" check for a
/// genuinely no-ceiling user. Union with whatever's already granted
/// (rather than a flat overwrite) so a manually-added, non-catalogue
/// permission key -- unusual, but not this function's business to
/// erase -- survives too; every current `Permission::ALL` variant is
/// guaranteed present either way, every single startup, not just once.
async fn seed_super_admin(pool: &DbPool) -> anyhow::Result<()> {
    let role = match repo::roles::find_by_name(pool, role::SUPER_ADMIN).await? {
        Some(existing) => existing,
        None => {
            repo::roles::create(
                pool,
                role::SUPER_ADMIN,
                "Full administrative control.",
                true,
                None,
                None,
            )
            .await?
        }
    };

    let current: std::collections::HashSet<Permission> =
        repo::roles::permissions_for_role(pool, role.id)
            .await?
            .into_iter()
            .collect();
    let complete: std::collections::HashSet<Permission> = current
        .union(&Permission::ALL.iter().copied().collect())
        .copied()
        .collect();
    if complete.len() != current.len() {
        let complete: Vec<Permission> = complete.into_iter().collect();
        repo::roles::set_permissions(pool, role.id, &complete).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_adds_and_removes_only_what_it_names() {
        let current = [Permission::UsersView, Permission::SystemsView];
        let out = delta_result(
            &current,
            &[Permission::HostsView, Permission::SystemsView],
            &[Permission::UsersView],
        );
        assert_eq!(out, [Permission::SystemsView, Permission::HostsView]);
        assert_eq!(delta_result(&current, &[], &[]), current);
    }

    #[test]
    fn v2_deltas_name_only_built_in_roles_and_never_grant_and_revoke_the_same_thing() {
        for delta in V2_DELTAS {
            assert!(role::BUILT_IN_ROLES.contains(&delta.role), "{}", delta.role);
            assert_ne!(delta.role, role::SUPER_ADMIN);
            assert!(delta.grant.iter().all(|p| !delta.revoke.contains(p)));
        }
    }
}
