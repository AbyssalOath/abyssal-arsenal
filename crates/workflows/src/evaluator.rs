use serde_json::Value;

use crate::types::{
    Condition, EvaluationFailure, EvaluationOutcome, LeafCondition, MatchedAction, Operator,
    WorkflowEntry,
};

/// Evaluates every entry in `entries` whose `source_arsenal`/`source_action`
/// match, against one structured result object, and returns both the
/// matches (renderable actions) and any genuine evaluation failures.
/// Read-only: this never touches anything outside the data it's given, so
/// it can never trigger a system operation itself.
///
/// A field that's missing or the wrong shape for the operator makes that
/// condition evaluate to `false` -- it never panics and never propagates an
/// error, so a bad or partial result can't break the page it's rendered on,
/// and it is never reported as a failure (that's the normal, expected case
/// for a structured result that doesn't carry every field every condition
/// might check). The one thing that *is* a failure is an actual mistake in
/// the registry data itself (currently: an invalid regex pattern on a
/// `matches` condition) -- see `regex_matches` below. Callers decide what
/// to do with failures (the web layer persists them to the audit trail);
/// this crate stays pure and never performs I/O itself.
pub fn evaluate(
    entries: &[WorkflowEntry],
    source_arsenal: &str,
    source_action: &str,
    result: &Value,
) -> EvaluationOutcome {
    let mut outcome = EvaluationOutcome::default();

    for entry in entries.iter().filter(|entry| {
        entry.source_arsenal == source_arsenal && entry.source_action == source_action
    }) {
        let mut raw_failures = Vec::new();
        let matched = condition_matches(&entry.condition, result, &mut raw_failures);

        outcome
            .failures
            .extend(
                raw_failures
                    .into_iter()
                    .map(|(field, message)| EvaluationFailure {
                        source_arsenal: entry.source_arsenal.clone(),
                        source_action: entry.source_action.clone(),
                        target_arsenal: entry.target_arsenal.clone(),
                        target_action: entry.target_action.clone(),
                        field,
                        message,
                    }),
            );

        if matched {
            outcome.matches.push(build_matched_action(entry, result));
        }
    }

    outcome
}

/// Evaluates every leaf in the tree rather than short-circuiting on the
/// first decisive result -- a compound condition's overall true/false
/// answer might be settled early, but a registry authoring bug (e.g. a bad
/// regex) in a sibling branch should never go unreported just because it
/// didn't end up mattering to the boolean outcome.
fn condition_matches(
    condition: &Condition,
    result: &Value,
    failures: &mut Vec<(String, String)>,
) -> bool {
    match condition {
        Condition::All { all } => all
            .iter()
            .map(|c| condition_matches(c, result, failures))
            .collect::<Vec<_>>()
            .into_iter()
            .all(|matched| matched),
        Condition::Any { any } => any
            .iter()
            .map(|c| condition_matches(c, result, failures))
            .collect::<Vec<_>>()
            .into_iter()
            .any(|matched| matched),
        Condition::Leaf(leaf) => leaf_matches(leaf, result, failures),
    }
}

fn leaf_matches(
    condition: &LeafCondition,
    result: &Value,
    failures: &mut Vec<(String, String)>,
) -> bool {
    let actual = result.get(&condition.field);
    let expected = condition.value.as_ref();
    match condition.operator {
        Operator::Exists => actual.is_some(),
        Operator::Equals => match (actual, expected) {
            (Some(actual), Some(expected)) => actual == expected,
            _ => false,
        },
        Operator::NotEquals => match (actual, expected) {
            (Some(actual), Some(expected)) => actual != expected,
            _ => false,
        },
        Operator::GreaterThanOrEqual => numeric_cmp(actual, expected, |a, b| a >= b),
        Operator::LessThan => numeric_cmp(actual, expected, |a, b| a < b),
        Operator::Contains => string_cmp(actual, expected, |a, b| a.contains(b)),
        Operator::StartsWith => string_cmp(actual, expected, |a, b| a.starts_with(b)),
        Operator::EndsWith => string_cmp(actual, expected, |a, b| a.ends_with(b)),
        Operator::Matches => regex_matches(actual, expected, &condition.field, failures),
    }
}

fn numeric_cmp(
    actual: Option<&Value>,
    expected: Option<&Value>,
    cmp: impl Fn(f64, f64) -> bool,
) -> bool {
    match (
        actual.and_then(Value::as_f64),
        expected.and_then(Value::as_f64),
    ) {
        (Some(actual), Some(expected)) => cmp(actual, expected),
        _ => false,
    }
}

fn string_cmp(
    actual: Option<&Value>,
    expected: Option<&Value>,
    cmp: impl Fn(&str, &str) -> bool,
) -> bool {
    match (
        actual.and_then(Value::as_str),
        expected.and_then(Value::as_str),
    ) {
        (Some(actual), Some(expected)) => cmp(actual, expected),
        _ => false,
    }
}

/// A malformed `matches` pattern is a registry authoring mistake, not an
/// ordinary "field absent" case -- it's logged immediately (visible in
/// server logs regardless of whether the caller does anything with the
/// returned failure) and also collected into `failures` so the caller can
/// additionally persist it somewhere admin-visible, but it still resolves
/// to "no match" rather than blocking the source action's own result from
/// rendering.
fn regex_matches(
    actual: Option<&Value>,
    expected: Option<&Value>,
    field: &str,
    failures: &mut Vec<(String, String)>,
) -> bool {
    let (Some(actual), Some(pattern)) = (
        actual.and_then(Value::as_str),
        expected.and_then(Value::as_str),
    ) else {
        return false;
    };

    match regex::Regex::new(pattern) {
        Ok(re) => re.is_match(actual),
        Err(error) => {
            let message = format!("invalid regex pattern {pattern:?}: {error}");
            tracing::warn!(
                field,
                pattern,
                %error,
                "workflow registry: invalid regex in a `matches` condition, treating as no match"
            );
            failures.push((field.to_string(), message));
            false
        }
    }
}

fn build_matched_action(entry: &WorkflowEntry, result: &Value) -> MatchedAction {
    let context = entry
        .context_fields
        .iter()
        .filter_map(|field| {
            result
                .get(field)
                .map(|v| (field.clone(), value_to_string(v)))
        })
        .collect();

    MatchedAction {
        target_arsenal: entry.target_arsenal.clone(),
        target_action: entry.target_action.clone(),
        label: render_label(&entry.label, result),
        context,
    }
}

/// Renders a label template's `{field_name}` placeholders from the
/// structured result. A placeholder whose field is missing is left as-is
/// rather than causing an error -- a slightly odd label beats a crashed page.
fn render_label(template: &str, result: &Value) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            out.push_str(rest);
            return out;
        };
        let end = start + end;
        out.push_str(&rest[..start]);
        let field = &rest[start + 1..end];
        match result.get(field) {
            Some(value) => out.push_str(&value_to_string(value)),
            None => out.push_str(&rest[start..=end]),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Condition;
    use serde_json::json;

    fn leaf(field: &str, operator: Operator, value: Option<Value>) -> Condition {
        Condition::Leaf(LeafCondition {
            field: field.to_string(),
            operator,
            value,
        })
    }

    fn entry_with(condition: Condition) -> WorkflowEntry {
        WorkflowEntry {
            source_arsenal: "cystoolbox".to_string(),
            source_action: "resource_usage_disk".to_string(),
            condition,
            target_arsenal: "catacomb".to_string(),
            target_action: "directory_usage_breakdown".to_string(),
            label: "Investigate {mount_point} with Catacomb".to_string(),
            context_fields: vec!["mount_point".to_string(), "usage_percent".to_string()],
        }
    }

    fn eval_one(condition: Condition, result: Value) -> bool {
        let entries = vec![entry_with(condition)];
        !evaluate(&entries, "cystoolbox", "resource_usage_disk", &result)
            .matches
            .is_empty()
    }

    #[test]
    fn matches_when_condition_holds() {
        let entries = vec![entry_with(leaf(
            "usage_percent",
            Operator::GreaterThanOrEqual,
            Some(json!(90)),
        ))];
        let result =
            json!({ "filesystem": "/dev/sda1", "usage_percent": 97, "mount_point": "/tmp" });

        let outcome = evaluate(&entries, "cystoolbox", "resource_usage_disk", &result);

        assert_eq!(outcome.matches.len(), 1);
        assert!(outcome.failures.is_empty());
        assert_eq!(outcome.matches[0].target_arsenal, "catacomb");
        assert_eq!(outcome.matches[0].label, "Investigate /tmp with Catacomb");
        assert_eq!(
            outcome.matches[0].context,
            vec![
                ("mount_point".to_string(), "/tmp".to_string()),
                ("usage_percent".to_string(), "97".to_string()),
            ]
        );
    }

    #[test]
    fn no_match_below_threshold() {
        assert!(!eval_one(
            leaf(
                "usage_percent",
                Operator::GreaterThanOrEqual,
                Some(json!(90))
            ),
            json!({ "usage_percent": 42, "mount_point": "/tmp" })
        ));
    }

    #[test]
    fn missing_field_never_matches_and_never_panics() {
        assert!(!eval_one(
            leaf(
                "usage_percent",
                Operator::GreaterThanOrEqual,
                Some(json!(90))
            ),
            json!({ "filesystem": "/dev/sda1", "mount_point": "/tmp" })
        ));
    }

    #[test]
    fn missing_field_is_not_reported_as_a_failure() {
        let entries = vec![entry_with(leaf(
            "usage_percent",
            Operator::GreaterThanOrEqual,
            Some(json!(90)),
        ))];
        let result = json!({ "mount_point": "/tmp" });

        let outcome = evaluate(&entries, "cystoolbox", "resource_usage_disk", &result);

        assert!(outcome.matches.is_empty());
        assert!(outcome.failures.is_empty());
    }

    #[test]
    fn exists_operator_matches_presence_only() {
        assert!(eval_one(
            leaf("mount_point", Operator::Exists, None),
            json!({ "mount_point": "/tmp" })
        ));
        assert!(!eval_one(
            leaf("mount_point", Operator::Exists, None),
            json!({})
        ));
    }

    #[test]
    fn not_equals_operator() {
        let cond = leaf("status", Operator::NotEquals, Some(json!("ok")));
        assert!(eval_one(cond.clone(), json!({ "status": "critical" })));
        assert!(!eval_one(cond.clone(), json!({ "status": "ok" })));
        // Missing field is "no match", not vacuously "not equal."
        assert!(!eval_one(cond, json!({})));
    }

    #[test]
    fn less_than_operator() {
        let cond = leaf("usage_percent", Operator::LessThan, Some(json!(50)));
        assert!(eval_one(cond.clone(), json!({ "usage_percent": 10 })));
        assert!(!eval_one(cond.clone(), json!({ "usage_percent": 90 })));
        assert!(!eval_one(cond, json!({})));
    }

    #[test]
    fn contains_operator() {
        let cond = leaf("mount_point", Operator::Contains, Some(json!("tmp")));
        assert!(eval_one(cond.clone(), json!({ "mount_point": "/var/tmp" })));
        assert!(!eval_one(cond.clone(), json!({ "mount_point": "/home" })));
        // Wrong shape (number, not string) never matches.
        assert!(!eval_one(cond, json!({ "mount_point": 5 })));
    }

    #[test]
    fn starts_with_operator() {
        let cond = leaf("mount_point", Operator::StartsWith, Some(json!("/tmp")));
        assert!(eval_one(cond.clone(), json!({ "mount_point": "/tmp/foo" })));
        assert!(!eval_one(cond, json!({ "mount_point": "/var/tmp" })));
    }

    #[test]
    fn ends_with_operator() {
        let cond = leaf("service", Operator::EndsWith, Some(json!(".service")));
        assert!(eval_one(
            cond.clone(),
            json!({ "service": "nginx.service" })
        ));
        assert!(!eval_one(cond, json!({ "service": "nginx.socket" })));
    }

    #[test]
    fn matches_operator_with_valid_regex() {
        let cond = leaf(
            "mount_point",
            Operator::Matches,
            Some(json!("^/(tmp|var/tmp)$")),
        );
        assert!(eval_one(cond.clone(), json!({ "mount_point": "/tmp" })));
        assert!(!eval_one(cond, json!({ "mount_point": "/home" })));
    }

    #[test]
    fn matches_operator_with_invalid_regex_is_no_match_not_a_panic() {
        let cond = leaf("mount_point", Operator::Matches, Some(json!("(unclosed")));
        assert!(!eval_one(cond, json!({ "mount_point": "/tmp" })));
    }

    #[test]
    fn matches_operator_with_invalid_regex_is_reported_as_a_failure() {
        let entries = vec![entry_with(leaf(
            "mount_point",
            Operator::Matches,
            Some(json!("(unclosed")),
        ))];
        let result = json!({ "mount_point": "/tmp" });

        let outcome = evaluate(&entries, "cystoolbox", "resource_usage_disk", &result);

        assert!(outcome.matches.is_empty());
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].field, "mount_point");
        assert_eq!(outcome.failures[0].source_arsenal, "cystoolbox");
        assert_eq!(outcome.failures[0].target_arsenal, "catacomb");
        assert!(outcome.failures[0].message.contains("invalid regex"));
    }

    #[test]
    fn invalid_regex_inside_a_compound_condition_is_still_reported() {
        // The `all` short-circuits on the first false leaf in a boolean
        // sense, but evaluation must still visit the second leaf so its
        // bad regex isn't silently hidden.
        let cond = Condition::All {
            all: vec![
                leaf("usage_percent", Operator::Equals, Some(json!(1))),
                leaf("mount_point", Operator::Matches, Some(json!("(unclosed"))),
            ],
        };
        let entries = vec![entry_with(cond)];
        let result = json!({ "usage_percent": 97, "mount_point": "/tmp" });

        let outcome = evaluate(&entries, "cystoolbox", "resource_usage_disk", &result);

        assert!(outcome.matches.is_empty());
        assert_eq!(outcome.failures.len(), 1);
    }

    #[test]
    fn all_group_requires_every_condition() {
        let cond = Condition::All {
            all: vec![
                leaf(
                    "usage_percent",
                    Operator::GreaterThanOrEqual,
                    Some(json!(90)),
                ),
                leaf("mount_point", Operator::Equals, Some(json!("/tmp"))),
            ],
        };
        assert!(eval_one(
            cond.clone(),
            json!({ "usage_percent": 97, "mount_point": "/tmp" })
        ));
        assert!(!eval_one(
            cond,
            json!({ "usage_percent": 97, "mount_point": "/home" })
        ));
    }

    #[test]
    fn any_group_requires_one_condition() {
        let cond = Condition::Any {
            any: vec![
                leaf("mount_point", Operator::Equals, Some(json!("/tmp"))),
                leaf("mount_point", Operator::Equals, Some(json!("/var/tmp"))),
            ],
        };
        assert!(eval_one(cond.clone(), json!({ "mount_point": "/var/tmp" })));
        assert!(!eval_one(cond, json!({ "mount_point": "/home" })));
    }

    #[test]
    fn nested_compound_conditions() {
        // (usage_percent >= 90) AND (mount_point == /tmp OR mount_point == /var/tmp)
        let cond = Condition::All {
            all: vec![
                leaf(
                    "usage_percent",
                    Operator::GreaterThanOrEqual,
                    Some(json!(90)),
                ),
                Condition::Any {
                    any: vec![
                        leaf("mount_point", Operator::Equals, Some(json!("/tmp"))),
                        leaf("mount_point", Operator::Equals, Some(json!("/var/tmp"))),
                    ],
                },
            ],
        };
        assert!(eval_one(
            cond.clone(),
            json!({ "usage_percent": 95, "mount_point": "/var/tmp" })
        ));
        assert!(!eval_one(
            cond.clone(),
            json!({ "usage_percent": 95, "mount_point": "/home" })
        ));
        assert!(!eval_one(
            cond,
            json!({ "usage_percent": 10, "mount_point": "/tmp" })
        ));
    }
}
