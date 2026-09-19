//! Contextual Arsenal Workflow Navigation: a small, data-driven registry
//! that lets one arsenal's structured result suggest "go do this in another
//! arsenal" buttons, without either arsenal knowing about the other.
//!
//! This crate never imports an arsenal crate and never executes anything --
//! it only reads a structured result and a registry of conditions, and
//! returns which target arsenal/action buttons should render. The user
//! always has to click through; nothing here navigates or performs a system
//! operation on its own.
mod evaluator;
mod registry;
mod types;

pub use evaluator::evaluate;
pub use registry::WorkflowRegistry;
pub use types::{
    Condition, EvaluationFailure, EvaluationOutcome, LeafCondition, MatchedAction, Operator,
    WorkflowEntry,
};
