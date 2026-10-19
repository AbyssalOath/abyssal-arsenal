use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Active Directory management: the day-to-day of ADUC (users, groups, OUs,
/// onboarding/offboarding) from the web UI, domain-scoped and run through the
/// Haruspex DC agents under a delegated service account. Haruspex stays
/// read-only DC health; Parish stays local users on one host.
pub struct GravekeeperArsenal;

impl Arsenal for GravekeeperArsenal {
    fn key(&self) -> &'static str {
        "gravekeeper"
    }

    fn display_name(&self) -> &'static str {
        "Gravekeeper"
    }

    fn description(&self) -> &'static str {
        "Active Directory user, group and OU management across a domain or forest (Windows)."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::DirectoryView]
    }
}
