use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// User, group, account, permission, and access management.
pub struct ParishArsenal;

impl Arsenal for ParishArsenal {
    fn key(&self) -> &'static str {
        "parish"
    }

    fn display_name(&self) -> &'static str {
        "Parish"
    }

    fn description(&self) -> &'static str {
        "User, group, account, permission, and access management."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::UsersView]
    }
}
