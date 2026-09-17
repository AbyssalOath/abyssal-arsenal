use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Network interfaces, routes, DNS, connectivity diagnostics, sockets, and network configuration.
pub struct NecrolinkArsenal;

impl Arsenal for NecrolinkArsenal {
    fn key(&self) -> &'static str {
        "necrolink"
    }

    fn display_name(&self) -> &'static str {
        "Necrolink"
    }

    fn description(&self) -> &'static str {
        "Network interfaces, routes, DNS, connectivity diagnostics, sockets, and network configuration."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::NetworkView]
    }
}
