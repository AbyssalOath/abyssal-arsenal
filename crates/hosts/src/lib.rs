pub mod control_plane_guard;
mod elevation_tracker;
mod registry;

pub use control_plane_guard::ControlPlaneProtection;
pub use elevation_tracker::{ElevatedHost, ElevationTracker};
pub use registry::{AgentProtocolStatus, DispatchError, HostConnectionRegistry};

pub use abyssal_agent_protocol as protocol;
