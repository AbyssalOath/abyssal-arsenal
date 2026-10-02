mod elevation_tracker;
mod registry;

pub use elevation_tracker::{ElevatedHost, ElevationTracker};
pub use registry::{AgentProtocolStatus, DispatchError, HostConnectionRegistry};

pub use abyssal_agent_protocol as protocol;
