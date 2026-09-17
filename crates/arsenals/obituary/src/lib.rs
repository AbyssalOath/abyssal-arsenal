use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Historical logging and audit record management.
pub struct ObituaryArsenal;

impl Arsenal for ObituaryArsenal {
    fn key(&self) -> &'static str {
        "obituary"
    }

    fn display_name(&self) -> &'static str {
        "Obituary"
    }

    fn description(&self) -> &'static str {
        "Historical logging and audit record management."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Observe
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::AuditView]
    }
}
