use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Security configuration, system hardening, security checks, and defensive operations.
pub struct CadavaultArsenal;

impl Arsenal for CadavaultArsenal {
    fn key(&self) -> &'static str {
        "cadavault"
    }

    fn display_name(&self) -> &'static str {
        "Cadavault"
    }

    fn description(&self) -> &'static str {
        "Security configuration, system hardening, security checks, and defensive operations."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Defend
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SecurityView]
    }
}
