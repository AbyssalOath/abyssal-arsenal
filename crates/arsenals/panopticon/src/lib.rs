use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Network visibility and access control: discovery, device identification,
/// MAC/IP inventory, service and OS fingerprinting, topology mapping, NAC
/// visibility, IoT/OT coverage, and network policy enforcement.
///
/// Architectural boundary, deliberate and distinct from every other arsenal
/// in this workspace: Panopticon runs from the control-plane container
/// itself rather than being dispatched to a host's agent. Where every other
/// arsenal's operations are `AgentOperation` variants sent over a specific
/// enrolled host's connection via `Executor::execute_on_host`, Panopticon's
/// future operations (active discovery via nmap/ARP/ICMP/SNMP, passive
/// visibility from DHCP/ARP/switch telemetry, and correlation against known
/// agent-managed hosts) are in-process `Operation`s run directly against the
/// control plane's own network stack via `Executor::execute` — the same
/// "control plane's own diagnostics" pathway `Executor` already documents,
/// just not yet used by any shipped arsenal. This reflects that network
/// discovery doesn't require, and shouldn't require, installing an agent on
/// every device just to learn it exists.
///
/// Conceptually paired with Necrolink: Necrolink *is* the network (per-host
/// interface/route/DNS/socket administration), Panopticon *watches* it.
pub struct PanopticonArsenal;

impl Arsenal for PanopticonArsenal {
    fn key(&self) -> &'static str {
        "panopticon"
    }

    fn display_name(&self) -> &'static str {
        "Panopticon"
    }

    fn description(&self) -> &'static str {
        "Network visibility and access control: discovery, device inventory, \
         and topology mapping across the LAN, run from the control plane."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Observe
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::NetworkView]
    }
}
