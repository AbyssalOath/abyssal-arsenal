use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Scourge -- the network intrusion detection/prevention (IDS/IPS) arsenal.
/// A per-host sensor and detector (Suricata today, behind an engine
/// abstraction): it inspects live traffic and forwards classified events into
/// Thanatos's existing ingest path. It is deliberately NOT a SIEM, a history
/// store, a device inventory, or a containment engine -- those are Thanatos,
/// Obituary, Panopticon, and Inquest respectively (see `docs/scourge.md`).
pub struct ScourgeArsenal;

impl Arsenal for ScourgeArsenal {
    fn key(&self) -> &'static str {
        "scourge"
    }

    fn display_name(&self) -> &'static str {
        "Scourge"
    }

    fn description(&self) -> &'static str {
        "Network intrusion detection and prevention (IDS/IPS): inspect live \
         traffic, surface and forward alerts, capture and analyze packets."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Defend
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::ScourgeView]
    }
}
