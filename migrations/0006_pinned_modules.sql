-- Per-user pinned/favorite arsenals shown above the grouped dashboard grid.

CREATE TABLE user_pinned_modules (
    user_id      CHAR(36)    NOT NULL,
    module_key   VARCHAR(64) NOT NULL,
    pinned_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, module_key),
    CONSTRAINT fk_user_pinned_modules_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_pinned_modules_module FOREIGN KEY (module_key) REFERENCES modules(`key`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
