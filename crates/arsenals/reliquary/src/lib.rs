use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::{Arsenal, Platforms};

/// Backup creation, verification, preservation, snapshots, and restoration.
pub struct ReliquaryArsenal;

impl Arsenal for ReliquaryArsenal {
    fn key(&self) -> &'static str {
        "reliquary"
    }

    fn display_name(&self) -> &'static str {
        "Reliquary"
    }

    fn description(&self) -> &'static str {
        "Backup creation, verification, preservation, snapshots, and restoration."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::PreserveRecover
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::BackupsView]
    }

    fn platforms(&self) -> Platforms {
        Platforms::Linux
    }
}
