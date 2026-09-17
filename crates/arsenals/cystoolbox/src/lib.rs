use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// General Linux administration and miscellaneous sysadmin utilities.
pub struct CystoolboxArsenal;

impl Arsenal for CystoolboxArsenal {
    fn key(&self) -> &'static str {
        "cystoolbox"
    }

    fn display_name(&self) -> &'static str {
        "Cystoolbox"
    }

    fn description(&self) -> &'static str {
        "General Linux administration and miscellaneous sysadmin utilities."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
