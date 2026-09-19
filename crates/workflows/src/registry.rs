use serde_json::Value;

use crate::evaluator::evaluate;
use crate::types::{EvaluationOutcome, WorkflowEntry};

/// The built-in registry, embedded at compile time from `registry.json` next
/// to this crate's `Cargo.toml`. Compiled in rather than read from disk at
/// request time -- this app ships as a single self-contained binary with no
/// other runtime-loaded config file, and embedding keeps that deployment
/// story intact while still keeping the data itself in its own file, edited
/// without touching any evaluator code.
const BUILTIN_REGISTRY_JSON: &str = include_str!("../registry.json");

pub struct WorkflowRegistry {
    entries: Vec<WorkflowEntry>,
}

impl WorkflowRegistry {
    /// Loads the built-in registry. Panics on malformed JSON, deliberately --
    /// a broken registry is a build-time mistake, not something to silently
    /// degrade around at runtime.
    pub fn load_builtin() -> Self {
        let entries: Vec<WorkflowEntry> = serde_json::from_str(BUILTIN_REGISTRY_JSON)
            .expect("crates/workflows/registry.json must be valid");
        Self { entries }
    }

    pub fn entries(&self) -> &[WorkflowEntry] {
        &self.entries
    }

    /// Evaluates one structured result object from `source_arsenal`'s
    /// `source_action` against the registry, returning every matching
    /// suggested action (there is no "best match" -- all of them render)
    /// alongside any genuine evaluation failures. See
    /// `evaluator::evaluate` for what counts as a failure.
    pub fn evaluate(&self, source_arsenal: &str, source_action: &str, result: &Value) -> EvaluationOutcome {
        evaluate(&self.entries, source_arsenal, source_action, result)
    }
}
