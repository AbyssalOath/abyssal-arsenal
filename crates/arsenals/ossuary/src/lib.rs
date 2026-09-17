use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Disk, partition, LVM, RAID, volume, mount, and storage management.
pub struct OssuaryArsenal;

impl Arsenal for OssuaryArsenal {
    fn key(&self) -> &'static str {
        "ossuary"
    }

    fn display_name(&self) -> &'static str {
        "Ossuary"
    }

    fn description(&self) -> &'static str {
        "Disk, partition, LVM, RAID, volume, mount, and storage management."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::PreserveRecover
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::StorageView]
    }
}
