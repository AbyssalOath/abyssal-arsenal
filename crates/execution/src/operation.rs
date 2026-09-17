use std::collections::HashMap;

use abyssal_core::Permission;

use crate::ExecutionError;

/// Shared with `abyssal-agent-protocol` so a result coming back from a remote
/// agent and a result produced by a local `Operation` have the exact same
/// shape — one definition, not two kept in sync by hand.
pub use abyssal_agent_protocol::OperationOutput;

/// How disruptive an operation is. This is what the confirmation requirement
/// and (in the web UI) the "informational / disruptive / destructive" styling
/// hang off of — it's a first-class property of every operation, not an
/// afterthought bolted onto individual handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Read,
    Write,
    Destructive,
}

#[derive(Debug, Clone, Default)]
pub struct OperationParams {
    pub args: HashMap<String, String>,
    /// Must be explicitly set for any `Destructive` operation to proceed — a
    /// user merely reaching the endpoint is never sufficient confirmation.
    pub confirm: bool,
}

/// A single controlled administrative action. Arsenals implement this instead
/// of running arbitrary shell commands from a handler — every operation
/// declares its own risk level and the permission required to invoke it, so
/// the executor can enforce both uniformly.
#[async_trait::async_trait]
pub trait Operation: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> OperationKind;
    fn required_permission(&self) -> Permission;
    async fn run(&self, params: &OperationParams) -> Result<OperationOutput, ExecutionError>;
}
