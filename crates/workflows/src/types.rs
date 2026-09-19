use serde::{Deserialize, Serialize};

/// The comparisons a leaf condition can make. `Exists` ignores `value`;
/// every other operator treats a missing field, a missing `value`, or a
/// value of the wrong shape (e.g. `contains` against a number) as "no
/// match" -- see `LeafCondition::matches` for that safety rule in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    GreaterThanOrEqual,
    LessThan,
    Contains,
    StartsWith,
    EndsWith,
    /// Regex match against a string field. `value` is the pattern. An
    /// invalid pattern is logged and treated as "no match" -- see
    /// `evaluator::regex_matches`.
    Matches,
    Exists,
}

impl Operator {
    /// A short infix/prefix symbol for `Condition::describe` -- the
    /// registry admin view's human-readable summary of a condition.
    fn symbol(self) -> &'static str {
        match self {
            Operator::Equals => "==",
            Operator::NotEquals => "!=",
            Operator::GreaterThanOrEqual => ">=",
            Operator::LessThan => "<",
            Operator::Contains => "contains",
            Operator::StartsWith => "starts with",
            Operator::EndsWith => "ends with",
            Operator::Matches => "matches",
            Operator::Exists => "exists",
        }
    }
}

/// A single field comparison against a source action's structured result.
/// `value` is absent for `Exists`, which only checks the field is present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafCondition {
    pub field: String,
    pub operator: Operator,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

impl LeafCondition {
    /// A one-line human summary, e.g. `usage_percent >= 90` or `mount_point
    /// exists` -- used by `Condition::describe`.
    pub fn describe(&self) -> String {
        match self.operator {
            Operator::Exists => format!("{} exists", self.field),
            _ => {
                let value = self
                    .value
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "?".to_string());
                format!("{} {} {}", self.field, self.operator.symbol(), value)
            }
        }
    }
}

/// A condition tree: either one field comparison, or an `all`/`any` group of
/// nested conditions (AND/OR respectively). An empty `all` is vacuously
/// true and an empty `any` is vacuously false, same as a normal boolean
/// fold over zero terms -- registries just shouldn't write one.
///
/// Untagged: a registry entry writes a leaf as `{"field": ..., "operator":
/// ..., "value": ...}` and a group as `{"all": [...]}` or `{"any": [...]}`,
/// with no extra wrapper to distinguish them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    All { all: Vec<Condition> },
    Any { any: Vec<Condition> },
    Leaf(LeafCondition),
}

impl Condition {
    /// A one-line human summary of the whole condition tree, e.g.
    /// `all(usage_percent >= 90, any(mount_point == "/tmp", mount_point ==
    /// "/var/tmp"))` -- used by the registry admin view so a debugging
    /// admin doesn't have to parse raw JSON to see what a rule checks.
    pub fn describe(&self) -> String {
        match self {
            Condition::All { all } => {
                format!(
                    "all({})",
                    all.iter()
                        .map(Condition::describe)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Condition::Any { any } => {
                format!(
                    "any({})",
                    any.iter()
                        .map(Condition::describe)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Condition::Leaf(leaf) => leaf.describe(),
        }
    }
}

/// One row of the workflow registry: "when this source arsenal/action's
/// result matches this condition, offer a button to this target
/// arsenal/action." Registry entries reference other arsenals only by their
/// string `key()` (see `abyssal_modules::Arsenal`), never by importing their
/// crates, so this stays the one place that knows about cross-arsenal
/// relationships.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEntry {
    pub source_arsenal: String,
    pub source_action: String,
    pub condition: Condition,
    pub target_arsenal: String,
    pub target_action: String,
    /// Button label. May reference structured-result fields as `{field_name}`,
    /// substituted in when a match is rendered.
    pub label: String,
    /// Fields copied from the structured result into the target URL's query
    /// string when this entry matches.
    pub context_fields: Vec<String>,
}

/// One matched, renderable "go do this in another arsenal" suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedAction {
    pub target_arsenal: String,
    pub target_action: String,
    pub label: String,
    /// Context fields as `(name, value)` string pairs, ready to append to a
    /// query string.
    pub context: Vec<(String, String)>,
}

/// A genuine authoring failure in the registry itself -- currently, only an
/// invalid regex pattern on a `matches` condition. Deliberately distinct
/// from an ordinary "no match": a missing or wrong-shaped field is normal,
/// expected, and never reported here (see `evaluator::evaluate`). Every
/// failure names the exact registry entry it came from, so an admin
/// reading it off the audit log can find and fix the right line in
/// `registry.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationFailure {
    pub source_arsenal: String,
    pub source_action: String,
    pub target_arsenal: String,
    pub target_action: String,
    pub field: String,
    pub message: String,
}

/// The result of evaluating one structured result against the registry:
/// every match (Phase 3's list of suggested buttons) alongside every
/// genuine evaluation failure encountered along the way. Kept as two
/// separate lists rather than, say, an error variant on `MatchedAction`,
/// because a failure on one registry entry must never affect any other
/// entry's evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvaluationOutcome {
    pub matches: Vec<MatchedAction>,
    pub failures: Vec<EvaluationFailure>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn describes_a_leaf_condition() {
        let leaf = LeafCondition {
            field: "usage_percent".to_string(),
            operator: Operator::GreaterThanOrEqual,
            value: Some(json!(90)),
        };
        assert_eq!(leaf.describe(), "usage_percent >= 90");
    }

    #[test]
    fn describes_an_exists_condition_without_a_value() {
        let leaf = LeafCondition {
            field: "mount_point".to_string(),
            operator: Operator::Exists,
            value: None,
        };
        assert_eq!(leaf.describe(), "mount_point exists");
    }

    #[test]
    fn describes_a_string_value_with_quotes() {
        let leaf = LeafCondition {
            field: "health_status".to_string(),
            operator: Operator::Equals,
            value: Some(json!("FAILED")),
        };
        assert_eq!(leaf.describe(), "health_status == \"FAILED\"");
    }

    #[test]
    fn describes_nested_compound_conditions() {
        let condition = Condition::All {
            all: vec![
                Condition::Leaf(LeafCondition {
                    field: "usage_percent".to_string(),
                    operator: Operator::GreaterThanOrEqual,
                    value: Some(json!(90)),
                }),
                Condition::Any {
                    any: vec![
                        Condition::Leaf(LeafCondition {
                            field: "mount_point".to_string(),
                            operator: Operator::Equals,
                            value: Some(json!("/tmp")),
                        }),
                        Condition::Leaf(LeafCondition {
                            field: "mount_point".to_string(),
                            operator: Operator::Equals,
                            value: Some(json!("/var/tmp")),
                        }),
                    ],
                },
            ],
        };

        assert_eq!(
            condition.describe(),
            "all(usage_percent >= 90, any(mount_point == \"/tmp\", mount_point == \"/var/tmp\"))"
        );
    }
}
