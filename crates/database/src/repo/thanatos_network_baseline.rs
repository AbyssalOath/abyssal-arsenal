use std::collections::HashSet;

use uuid::Uuid;

use crate::DbPool;

/// Reconciles `current_ports` (every `port_key` -- e.g. `"tcp:443"` --
/// the agent just reported as currently listening) against what this
/// host was already known to be listening on, and returns just the
/// subset that's genuinely **new**.
///
/// Three things happen in one call, matching how a scan always reports
/// the *complete* current set rather than an incremental diff (unlike
/// `thanatos_file_hashes::upsert_if_changed`, which is called once per
/// fixed path):
/// - A host with no prior baseline at all (its first-ever scan) has
///   every one of `current_ports` recorded silently and returns an empty
///   `Vec` -- reporting all of a host's *existing* ports as "new" on day
///   one would be noise, not signal, the same "establishing a baseline
///   never counts as drift" principle `thanatos_file_hashes` already
///   follows for a single value.
/// - A host with a prior baseline: any `port_key` in `current_ports` not
///   already tracked is genuinely new and comes back in the result.
/// - Any previously-tracked `port_key` **not** in `current_ports` this
///   time is quietly dropped from tracking, not alerted on -- a port
///   closing isn't itself a security concern the way a new one opening
///   is.
pub async fn record_seen_ports(
    pool: &DbPool,
    host_id: Uuid,
    current_ports: &[String],
) -> anyhow::Result<Vec<String>> {
    let host_id_str = host_id.to_string();

    let existing: Vec<(String,)> =
        sqlx::query_as("SELECT port_key FROM thanatos_network_baseline WHERE host_id = ?")
            .bind(&host_id_str)
            .fetch_all(pool)
            .await?;
    let had_baseline = !existing.is_empty();
    let known: HashSet<String> = existing.into_iter().map(|(key,)| key).collect();

    let new_ports: Vec<String> = if had_baseline {
        current_ports
            .iter()
            .filter(|key| !known.contains(*key))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

    for port_key in current_ports {
        sqlx::query(
            "INSERT INTO thanatos_network_baseline (host_id, port_key) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE observed_at = CURRENT_TIMESTAMP(6)",
        )
        .bind(&host_id_str)
        .bind(port_key)
        .execute(pool)
        .await?;
    }

    let current: HashSet<&str> = current_ports.iter().map(String::as_str).collect();
    for port_key in known.iter().filter(|key| !current.contains(key.as_str())) {
        sqlx::query("DELETE FROM thanatos_network_baseline WHERE host_id = ? AND port_key = ?")
            .bind(&host_id_str)
            .bind(port_key)
            .execute(pool)
            .await?;
    }

    Ok(new_ports)
}
