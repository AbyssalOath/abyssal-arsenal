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
            Permission::UsersView,
            Permission::SystemsView,
            Permission::SystemsManage,
            Permission::HostUsersView,
            Permission::HostUsersManage,
            Permission::StorageView,
            Permission::StorageManage,
            Permission::ContainersView,
            Permission::ContainersManage,
            Permission::BackupsView,
            Permission::BackupsCreate,
            Permission::BackupsRestore,
            Permission::AuditView,
            Permission::HostsView,
            Permission::HostsManage,
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
            Permission::AuditView,
        ],
    )
    .await?;

    seed_role(
        pool,
        role::SECURITY_ADMIN,
        "Security hardening, incident response, and audit oversight.",
        vec![
            Permission::UsersView,
            Permission::SecurityView,
            Permission::SecurityManage,
            Permission::IncidentsView,
            Permission::IncidentsRespond,
            Permission::AuditView,
            Permission::AuditExport,
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
        ],
    )
    .await?;

    Ok(())
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
