mod executor;
mod operation;
mod process;

pub use executor::Executor;
pub use operation::{Operation, OperationKind, OperationOutput, OperationParams};
pub use process::run_command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("operation timed out")]
    Timeout,
    #[error("operation was cancelled")]
    Cancelled,
    #[error("destructive operations require explicit confirmation")]
    ConfirmationRequired,
    #[error("permission denied")]
    Forbidden,
    #[error("execution failed: {0}")]
    Failed(String),
}
