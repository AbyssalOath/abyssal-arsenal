use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Secrets, credentials, certificates, keys, and sensitive configuration.
pub struct CryptkeeperArsenal;

impl Arsenal for CryptkeeperArsenal {
    fn key(&self) -> &'static str {
        "cryptkeeper"
    }

    fn display_name(&self) -> &'static str {
        "Cryptkeeper"
    }

    fn description(&self) -> &'static str {
        "Secrets, credentials, certificates, keys, and sensitive configuration."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Defend
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SecurityView]
    }
}
