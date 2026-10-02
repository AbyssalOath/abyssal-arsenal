use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Windows Active Directory / directory-services health diagnostics.
pub struct HaruspexArsenal;

impl Arsenal for HaruspexArsenal {
    fn key(&self) -> &'static str {
        "haruspex"
    }

    fn display_name(&self) -> &'static str {
        "Haruspex"
    }

    fn description(&self) -> &'static str {
        "Active Directory DNS and domain-controller health diagnostics (Windows)."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Observe
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
