-- Per-role dashboard arsenal visibility. Purely a declutter layer on top
-- of (never instead of) the permission system: an arsenal never appears
-- here that the underlying permission wouldn't already have allowed
-- through `modules.view_permissions`, and removing a role's customization
-- here can never grant access to anything.
--
-- A role with no rows here is "uncustomized" -- the dashboard falls back
-- to showing every arsenal its permissions already allow, exactly
-- today's behavior. A role with any rows is "customized" -- the
-- dashboard shows exactly this set (still permission-gated) for that
-- role's contribution to a user's effective visibility.
CREATE TABLE role_module_visibility (
    role_id     CHAR(36)    NOT NULL,
    module_key  VARCHAR(64) NOT NULL,
    PRIMARY KEY (role_id, module_key),
    CONSTRAINT fk_role_module_visibility_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_module_visibility_module FOREIGN KEY (module_key) REFERENCES modules(`key`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
