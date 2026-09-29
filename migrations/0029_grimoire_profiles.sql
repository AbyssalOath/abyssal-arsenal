-- Grimoire config profiles: a named, reusable bundle of declarative config
-- settings (sysctl / module-blacklist / journald) applied to a host as a unit
-- -- config-as-code. Scoping mirrors the macros feature (personal to the
-- owner, or shared with a role), reusing MacroScope and the MacrosManageAll
-- permission rather than inventing a parallel model.
CREATE TABLE grimoire_profiles (
    id             CHAR(36)     NOT NULL PRIMARY KEY,
    name           VARCHAR(128) NOT NULL,
    owner_user_id  CHAR(36)     NOT NULL,
    scope          VARCHAR(16)  NOT NULL,
    role_id        CHAR(36)     NULL,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_grimoire_profiles_owner FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_grimoire_profiles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    INDEX idx_grimoire_profiles_owner (owner_user_id),
    INDEX idx_grimoire_profiles_role (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One config setting within a profile. `kind` selects the domain
-- (sysctl / module_blacklist / journald); `entry_key`/`entry_value` are that
-- domain's key and value (module_blacklist has no value).
CREATE TABLE grimoire_profile_entries (
    id           CHAR(36)     NOT NULL PRIMARY KEY,
    profile_id   CHAR(36)     NOT NULL,
    kind         VARCHAR(24)  NOT NULL,
    entry_key    VARCHAR(200) NOT NULL,
    entry_value  VARCHAR(200) NOT NULL DEFAULT '',
    position     INT          NOT NULL DEFAULT 0,
    CONSTRAINT fk_grimoire_profile_entries_profile FOREIGN KEY (profile_id) REFERENCES grimoire_profiles(id) ON DELETE CASCADE,
    INDEX idx_grimoire_profile_entries_profile (profile_id, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
