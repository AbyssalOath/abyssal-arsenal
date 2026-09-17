mod elevation_tracker;
mod registry;

pub use elevation_tracker::{ElevatedHost, ElevationTracker};
pub use registry::{DispatchError, HostConnectionRegistry};

pub use abyssal_agent_protocol as protocol;
