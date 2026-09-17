use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Active incident response, investigation, containment, and remediation workflows.
pub struct InquestArsenal;

impl Arsenal for InquestArsenal {
    fn key(&self) -> &'static str {
        "inquest"
    }

    fn display_name(&self) -> &'static str {
        "Inquest"
    }

    fn description(&self) -> &'static str {
        "Active incident response, investigation, containment, and remediation workflows."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Defend
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::IncidentsView]
    }
}
