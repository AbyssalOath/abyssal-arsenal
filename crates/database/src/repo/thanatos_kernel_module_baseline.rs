use std::collections::HashSet;

use uuid::Uuid;

use crate::DbPool;

/// Reconciles `current_modules` (every loaded kernel module/running
/// driver name the agent just reported) against what this host was
/// already known to have loaded, and returns just the subset that's
/// genuinely **new** -- structurally identical to `thanatos_network_
/// baseline::record_seen_ports` (see that function's own doc comment
/// for the full reasoning), applied to a different snapshot source:
/// - A host's first-ever scan records every module silently and returns
///   an empty `Vec` -- establishing a baseline is never itself a finding.
/// - A host with a prior baseline: any module not already tracked is
///   genuinely new and comes back in the result.
/// - A previously-tracked module no longer present is quietly dropped
///   from tracking, not alerted on -- unloading isn't a security concern
///   the way a new module loading is.
pub async fn record_seen_modules(
    pool: &DbPool,
    host_id: Uuid,
    current_modules: &[String],
) -> anyhow::Result<Vec<String>> {
    let host_id_str = host_id.to_string();

    let existing: Vec<(String,)> =
        sqlx::query_as("SELECT module_key FROM thanatos_kernel_module_baseline WHERE host_id = ?")
            .bind(&host_id_str)
            .fetch_all(pool)
            .await?;
    let had_baseline = !existing.is_empty();
    let known: HashSet<String> = existing.into_iter().map(|(key,)| key).collect();

    let new_modules: Vec<String> = if had_baseline {
        current_modules
            .iter()
            .filter(|key| !known.contains(*key))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

    for module_key in current_modules {
        sqlx::query(
            "INSERT INTO thanatos_kernel_module_baseline (host_id, module_key) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE observed_at = CURRENT_TIMESTAMP(6)",
        )
        .bind(&host_id_str)
        .bind(module_key)
        .execute(pool)
        .await?;
    }

    let current: HashSet<&str> = current_modules.iter().map(String::as_str).collect();
    for module_key in known.iter().filter(|key| !current.contains(key.as_str())) {
        sqlx::query(
            "DELETE FROM thanatos_kernel_module_baseline WHERE host_id = ? AND module_key = ?",
        )
        .bind(&host_id_str)
        .bind(module_key)
        .execute(pool)
        .await?;
    }

    Ok(new_modules)
}
