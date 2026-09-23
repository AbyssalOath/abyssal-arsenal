-- GitHub issue #8: custom roles with delegated sub-roles. A role may
-- have a parent (`parent_role_id`) -- `NULL` for every existing/system
-- role (a root), non-null for a delegated sub-role a Super Admin or a
-- roles.manage-holding admin created beneath their own role. Effective
-- permissions for a role are computed at check time as its own grants
-- intersected with its parent's effective set, recursively -- see
-- `crates/database/src/repo/roles.rs::effective_permissions_for_role`.
-- `created_by` records who created a custom role (`NULL` for the five
-- seeded system roles, which nothing "creates" at runtime). Existing
-- rows get `NULL` for both new columns and `CURRENT_TIMESTAMP` for the
-- new timestamps -- zero behavior change for any pre-existing role.

ALTER TABLE roles
    ADD COLUMN parent_role_id CHAR(36) NULL AFTER is_system,
    ADD COLUMN created_by CHAR(36) NULL AFTER parent_role_id,
    ADD COLUMN created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) AFTER created_by,
    ADD COLUMN updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6) AFTER created_at,
    -- RESTRICT, not CASCADE: a role with children must be explicitly
    -- reassigned/deleted first (this feature's chosen deletion-guard
    -- behavior), never silently orphaned.
    ADD CONSTRAINT fk_roles_parent FOREIGN KEY (parent_role_id) REFERENCES roles(id) ON DELETE RESTRICT,
    ADD CONSTRAINT fk_roles_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    ADD INDEX idx_roles_parent (parent_role_id);
