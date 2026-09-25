use uuid::Uuid;

use crate::DbPool;

/// Records `hash` as the current value for `host_id`+`path`, returning
/// whether it actually **changed** from a previously-recorded value --
/// `false` both when this is the very first sighting of that path on this
/// host (the baseline is just established silently, not treated as
/// "drift") and when the hash matches what was already on file. Only a
/// genuine change from one real observation to the next should ever raise
/// a finding; establishing a baseline never should.
pub async fn upsert_if_changed(
    pool: &DbPool,
    host_id: Uuid,
    path: &str,
    hash: &str,
) -> anyhow::Result<bool> {
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT hash FROM thanatos_file_hashes WHERE host_id = ? AND path = ?")
            .bind(host_id.to_string())
            .bind(path)
            .fetch_optional(pool)
            .await?;

    let changed = matches!(&existing, Some((old_hash,)) if old_hash != hash);

    sqlx::query(
        "INSERT INTO thanatos_file_hashes (host_id, path, hash) VALUES (?, ?, ?) \
         ON DUPLICATE KEY UPDATE hash = VALUES(hash), observed_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(host_id.to_string())
    .bind(path)
    .bind(hash)
    .execute(pool)
    .await?;

    Ok(changed)
}
