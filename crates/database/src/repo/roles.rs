use std::collections::HashSet;

use abyssal_core::{Permission, Role};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

/// Purely defensive against a corrupted/hand-edited `parent_role_id`
/// chain -- `create`/`set_parent`'s own cycle and `MAX_ROLE_DEPTH` checks
/// are what actually keep a real chain this short. Any ancestor walk
/// bails out past this many hops rather than looping forever.
const MAX_ANCESTOR_WALK: u32 = 20;

#[derive(FromRow)]
struct RoleRow {
    id: String,
    name: String,
    description: String,
    is_system: bool,
    parent_role_id: Option<String>,
    created_by: Option<String>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<RoleRow> for Role {
    fn from(row: RoleRow) -> Self {
        Role {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            name: row.name,
            description: row.description,
            is_system: row.is_system,
            parent_role_id: row
                .parent_role_id
                .map(|id| Uuid::parse_str(&id).unwrap_or_default()),
            created_by: row
                .created_by
                .map(|id| Uuid::parse_str(&id).unwrap_or_default()),
            created_at: utc(row.created_at),
            updated_at: utc(row.updated_at),
        }
    }
}

pub async fn find_by_name(pool: &DbPool, name: &str) -> anyhow::Result<Option<Role>> {
    let row: Option<RoleRow> = sqlx::query_as("SELECT * FROM roles WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<Role>> {
    let row: Option<RoleRow> = sqlx::query_as("SELECT * FROM roles WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<Role>> {
    let rows: Vec<RoleRow> = sqlx::query_as("SELECT * FROM roles ORDER BY name ASC")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Direct children of `role_id` only (not grandchildren) -- what the
/// Add/Edit User sub-role picker offers once a parent role is chosen, and
/// what the Roles page's hierarchy view nests under each role.
pub async fn children_of(pool: &DbPool, role_id: Uuid) -> anyhow::Result<Vec<Role>> {
    let rows: Vec<RoleRow> =
        sqlx::query_as("SELECT * FROM roles WHERE parent_role_id = ? ORDER BY name ASC")
            .bind(role_id.to_string())
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Every descendant of `role_id` at any depth (children, grandchildren,
/// ...) -- what "manage only roles that descend from your own role"
/// scopes a delegated admin's role-management view to. `role_id` itself
/// is never included.
pub async fn descendants_of(pool: &DbPool, role_id: Uuid) -> anyhow::Result<Vec<Role>> {
    let mut result = Vec::new();
    let mut frontier = vec![role_id];
    let mut hops = 0u32;
    while !frontier.is_empty() && hops < MAX_ANCESTOR_WALK {
        hops += 1;
        let mut next_frontier = Vec::new();
        for id in frontier {
            let children = children_of(pool, id).await?;
            for child in children {
                next_frontier.push(child.id);
                result.push(child);
            }
        }
        frontier = next_frontier;
    }
    Ok(result)
}

/// `role_id` itself, then its parent, then its grandparent, and so on up
/// to (and including) the root -- capped at `MAX_ANCESTOR_WALK` hops as a
/// defensive backstop against a corrupted chain. `is_within_subtree`,
/// `depth_of`, and `would_create_cycle` are all just different questions
/// asked of this same walk, kept as one shared database round trip
/// rather than three.
async fn ancestor_chain(pool: &DbPool, role_id: Uuid) -> anyhow::Result<Vec<Uuid>> {
    let mut chain = vec![role_id];
    let mut current_id = role_id;
    let mut hops = 0u32;
    while hops < MAX_ANCESTOR_WALK {
        hops += 1;
        match find_by_id(pool, current_id)
            .await?
            .and_then(|r| r.parent_role_id)
        {
            Some(parent_id) => {
                chain.push(parent_id);
                current_id = parent_id;
            }
            None => break,
        }
    }
    Ok(chain)
}

/// Pure core of `is_within_subtree`: `root_id` appears somewhere in
/// `role_id`'s own ancestor chain (which always starts with `role_id`
/// itself, so this is also true when `role_id == root_id`). Exposed
/// separately from the database walk purely so this graph check -- and,
/// via `would_create_cycle`, the platform's actual cycle-safety guarantee
/// -- is unit-testable without a database; see `mod tests` below.
fn chain_contains(chain: &[Uuid], target: Uuid) -> bool {
    chain.contains(&target)
}

/// True when `role_id` is `root_id` itself or descends from it at any
/// depth -- the core "is this within my delegated subtree" check, used
/// both for role management scoping and for capping which role a
/// delegated admin may assign to a user.
pub async fn is_within_subtree(
    pool: &DbPool,
    role_id: Uuid,
    root_id: Uuid,
) -> anyhow::Result<bool> {
    let chain = ancestor_chain(pool, role_id).await?;
    Ok(chain_contains(&chain, root_id))
}

/// 1 for a root role, 2 for its direct child, 3 for a grandchild, and so
/// on -- what `create`/`set_parent` check against `MAX_ROLE_DEPTH`
/// before letting a role be nested any deeper.
pub async fn depth_of(pool: &DbPool, role_id: Uuid) -> anyhow::Result<u8> {
    let chain = ancestor_chain(pool, role_id).await?;
    Ok(chain.len() as u8)
}

/// Whether setting `role_id`'s parent to `proposed_parent_id` would
/// create a cycle -- true iff `role_id` is `proposed_parent_id` itself or
/// already one of its ancestors. Callers check this *before* the depth
/// check, since a cycle makes "depth" meaningless anyway.
pub async fn would_create_cycle(
    pool: &DbPool,
    role_id: Uuid,
    proposed_parent_id: Uuid,
) -> anyhow::Result<bool> {
    is_within_subtree(pool, proposed_parent_id, role_id).await
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &DbPool,
    name: &str,
    description: &str,
    is_system: bool,
    parent_role_id: Option<Uuid>,
    created_by: Option<Uuid>,
) -> anyhow::Result<Role> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO roles (id, name, description, is_system, parent_role_id, created_by) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(description)
    .bind(is_system)
    .bind(parent_role_id.map(|id| id.to_string()))
    .bind(created_by.map(|id| id.to_string()))
    .execute(pool)
    .await?;
    find_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("role vanished immediately after insert"))
}

/// Renames/re-describes a custom role and (if given) moves it under a new
/// parent. Callers must have already validated the new parent won't
/// create a cycle or exceed `MAX_ROLE_DEPTH`, and that the requested
/// permissions still fit under the new parent -- this layer just
/// persists whatever it's handed. Never call this for a system role (the
/// caller enforces that; system roles are always root and unrenameable).
pub async fn update(
    pool: &DbPool,
    id: Uuid,
    name: &str,
    description: &str,
    parent_role_id: Option<Uuid>,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE roles SET name = ?, description = ?, parent_role_id = ? WHERE id = ?")
        .bind(name)
        .bind(description)
        .bind(parent_role_id.map(|id| id.to_string()))
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-deletes a custom role. Callers must have already confirmed it has
/// no children and no assigned users -- this project's chosen guard
/// (block, don't auto-reassign) means this is only ever called once
/// that's true, so it doesn't re-check here.
pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM roles WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn user_count(pool: &DbPool, role_id: Uuid) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_roles WHERE role_id = ?")
        .bind(role_id.to_string())
        .fetch_one(pool)
        .await?;
    Ok(count)
}

pub async fn set_permissions(
    pool: &DbPool,
    role_id: Uuid,
    permissions: &[Permission],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_permissions WHERE role_id = ?")
        .bind(role_id.to_string())
        .execute(&mut *tx)
        .await?;
    for perm in permissions {
        sqlx::query("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)")
            .bind(role_id.to_string())
            .bind(perm.as_key())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// A role's own granted permissions, exactly as stored -- *not* capped by
/// its ancestors. See `effective_permissions_for_role` for the capped
/// version every permission check actually uses.
pub async fn permissions_for_role(pool: &DbPool, role_id: Uuid) -> anyhow::Result<Vec<Permission>> {
    let keys: Vec<(String,)> =
        sqlx::query_as("SELECT permission_key FROM role_permissions WHERE role_id = ?")
            .bind(role_id.to_string())
            .fetch_all(pool)
            .await?;
    Ok(keys
        .into_iter()
        .filter_map(|(key,)| Permission::from_key(&key))
        .collect())
}

/// A role's *effective* permissions: its own granted set intersected with
/// every ancestor's own granted set, all the way up to the root. This is
/// what "if a parent loses a permission, every descendant loses it too,
/// computed fresh, no stale grants" (GitHub issue #8) means in practice --
/// nothing is ever cached or materialized, so a parent's `role_permissions`
/// row changing takes effect on the very next check anywhere in the tree.
/// A root role's effective set is just its own grants (the recursion's
/// base case).
pub async fn effective_permissions_for_role(
    pool: &DbPool,
    role_id: Uuid,
) -> anyhow::Result<HashSet<Permission>> {
    let mut chain = Vec::new();
    let mut current_id = Some(role_id);
    let mut hops = 0u32;
    while let Some(id) = current_id {
        hops += 1;
        if hops > MAX_ANCESTOR_WALK {
            break;
        }
        let own: HashSet<Permission> = permissions_for_role(pool, id).await?.into_iter().collect();
        chain.push(own);
        current_id = find_by_id(pool, id).await?.and_then(|r| r.parent_role_id);
    }
    Ok(intersect_chain(&chain))
}

/// Pure core of `effective_permissions_for_role`: the intersection of
/// every set in `chain` (the role's own grants, then its parent's, then
/// its grandparent's, ...). Exposed separately from the database walk
/// above purely so this -- the actual "if a parent loses a permission,
/// every descendant loses it too" behavior GitHub issue #8 asks for -- is
/// unit-testable without a database; see `mod tests` below.
fn intersect_chain(chain: &[HashSet<Permission>]) -> HashSet<Permission> {
    let mut sets = chain.iter();
    let Some(first) = sets.next() else {
        return HashSet::new();
    };
    let mut acc = first.clone();
    for set in sets {
        acc = acc.intersection(set).copied().collect();
    }
    acc
}

pub async fn assign_role_to_user(
    pool: &DbPool,
    user_id: Uuid,
    role_id: Uuid,
) -> anyhow::Result<()> {
    sqlx::query("INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(user_id.to_string())
        .bind(role_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_role_from_user(
    pool: &DbPool,
    user_id: Uuid,
    role_id: Uuid,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?")
        .bind(user_id.to_string())
        .bind(role_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Replaces every role currently assigned to `user_id` with exactly
/// `role_id`. Per GitHub issue #8's chosen design, a user holds exactly
/// one assigned role at a time -- the Add/Edit User "role, then sub-role"
/// picker is a two-step *UI* for choosing that one role (pick a
/// top-level role, optionally narrow to one of its children), not two
/// simultaneous assignments. `user_roles` remains a many-to-many table
/// (unchanged schema) so nothing about `roles_for_user`/
/// `effective_permissions`'s existing union-across-roles behavior needs
/// touching; this just always keeps it at one row per user in practice.
pub async fn set_user_role(pool: &DbPool, user_id: Uuid, role_id: Uuid) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?")
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(user_id.to_string())
        .bind(role_id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn roles_for_user(pool: &DbPool, user_id: Uuid) -> anyhow::Result<Vec<Role>> {
    let rows: Vec<RoleRow> = sqlx::query_as(
        "SELECT r.* FROM roles r \
         INNER JOIN user_roles ur ON ur.role_id = r.id \
         WHERE ur.user_id = ? ORDER BY r.name ASC",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Resolves the union, across every role assigned to a user, of each
/// role's *effective* (ancestor-capped) permissions -- a fresh database
/// lookup every time, never a cached/long-lived claim set. In the common
/// case a user has exactly one assigned role (see `set_user_role`), so
/// this is just that role's effective set; the union is still correct
/// (and unchanged from today's behavior) for a root-only role, or in the
/// unlikely event a user ends up with more than one role assigned.
pub async fn effective_permissions(
    pool: &DbPool,
    user_id: Uuid,
) -> anyhow::Result<Vec<Permission>> {
    let roles = roles_for_user(pool, user_id).await?;
    let mut effective = HashSet::new();
    for role in roles {
        effective.extend(effective_permissions_for_role(pool, role.id).await?);
    }
    Ok(effective.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(perms: &[Permission]) -> HashSet<Permission> {
        perms.iter().copied().collect()
    }

    // -- intersect_chain: effective-permission computation, GitHub issue #8 --

    #[test]
    fn root_roles_effective_set_is_just_its_own_grants() {
        let chain = vec![set(&[Permission::NetworkView, Permission::NetworkManage])];
        assert_eq!(
            intersect_chain(&chain),
            set(&[Permission::NetworkView, Permission::NetworkManage])
        );
    }

    #[test]
    fn child_effective_set_is_capped_by_parent() {
        // Child was directly granted NetworkManage and SystemsView, but
        // its parent only has NetworkView and NetworkManage -- the child
        // should lose SystemsView (parent never had it) and keep
        // NetworkManage (parent has it too).
        let child = set(&[Permission::NetworkManage, Permission::SystemsView]);
        let parent = set(&[Permission::NetworkView, Permission::NetworkManage]);
        assert_eq!(
            intersect_chain(&[child, parent]),
            set(&[Permission::NetworkManage])
        );
    }

    #[test]
    fn parent_losing_a_permission_cascades_to_every_descendant() {
        // Grandchild and child both still directly have NetworkScan, but
        // after the parent's own grant no longer includes it (simulating
        // an admin revoking it from the parent), the whole chain's
        // effective set drops it too -- computed fresh, nothing stale.
        let grandchild = set(&[Permission::NetworkScan]);
        let child = set(&[Permission::NetworkScan]);
        let parent_before = set(&[Permission::NetworkScan]);
        let parent_after = set(&[Permission::NetworkView]); // NetworkScan revoked

        assert_eq!(
            intersect_chain(&[grandchild.clone(), child.clone(), parent_before]),
            set(&[Permission::NetworkScan])
        );
        assert_eq!(
            intersect_chain(&[grandchild, child, parent_after]),
            HashSet::new(),
            "revoking a permission from the root must cascade to every descendant"
        );
    }

    #[test]
    fn three_level_chain_intersects_all_three() {
        let grandchild = set(&[
            Permission::NetworkView,
            Permission::NetworkManage,
            Permission::NetworkScan,
        ]);
        let child = set(&[Permission::NetworkView, Permission::NetworkManage]);
        let root = set(&[Permission::NetworkView]);
        assert_eq!(
            intersect_chain(&[grandchild, child, root]),
            set(&[Permission::NetworkView])
        );
    }

    #[test]
    fn empty_chain_has_no_effective_permissions() {
        assert_eq!(intersect_chain(&[]), HashSet::new());
    }

    // -- chain_contains: subtree / cycle-safety checks --

    #[test]
    fn a_role_is_within_its_own_subtree() {
        let id = Uuid::new_v4();
        assert!(chain_contains(&[id], id));
    }

    #[test]
    fn a_descendant_is_within_its_ancestors_subtree() {
        let grandchild = Uuid::new_v4();
        let child = Uuid::new_v4();
        let root = Uuid::new_v4();
        // ancestor_chain always starts with the role itself.
        let chain = vec![grandchild, child, root];
        assert!(chain_contains(&chain, root));
        assert!(chain_contains(&chain, child));
    }

    #[test]
    fn an_unrelated_role_is_not_within_the_subtree() {
        let role = Uuid::new_v4();
        let other_root = Uuid::new_v4();
        let chain = vec![role]; // role is itself a root, no relation to other_root
        assert!(!chain_contains(&chain, other_root));
    }

    #[test]
    fn reparenting_a_role_under_its_own_descendant_is_a_cycle() {
        // would_create_cycle(role, proposed_parent) asks: is `role`
        // within `proposed_parent`'s own subtree? If a grandchild's
        // ancestor chain already contains the role being reparented,
        // making that grandchild the role's new parent would create a
        // loop.
        let role = Uuid::new_v4();
        let child = Uuid::new_v4();
        let grandchild = Uuid::new_v4();
        // grandchild's ancestor chain: grandchild -> child -> role
        let grandchild_chain = vec![grandchild, child, role];
        assert!(
            chain_contains(&grandchild_chain, role),
            "grandchild descends from role, so role can't become grandchild's child"
        );
    }

    #[test]
    fn reparenting_under_an_unrelated_role_is_not_a_cycle() {
        let role = Uuid::new_v4();
        let unrelated = Uuid::new_v4();
        let unrelated_chain = vec![unrelated]; // a root, unrelated to `role`
        assert!(!chain_contains(&unrelated_chain, role));
    }
}
