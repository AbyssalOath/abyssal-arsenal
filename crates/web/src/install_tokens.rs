//! Additional install tokens (docs/roadmap/0.2.4.md, section 2): AAT-format
//! tokens beside the default one (`crate::aat`), each with a label, an
//! optional expiry, a use count, its own approval setting and its own
//! revoke. They work everywhere the default token does -- the exe and MSI
//! `AAT=`, `install --aat`, the one-liners -- and key the CA proof the same
//! way. Sealed with `ENCRYPTION_KEY` like the default token, because the CA
//! proof needs the secret itself.

use abyssal_agent_protocol::aat::key_id;
use abyssal_core::EncryptionKey;
use abyssal_core::secret::hash_token;
use abyssal_database::repo::install_tokens::{InstallToken, NewInstallToken};
use abyssal_database::{DbPool, repo};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// The expiry choices offered when creating one, in days (`None`: never).
pub const EXPIRY_CHOICES: [(Option<u32>, &str); 6] = [
    (Some(1), "1 day"),
    (Some(7), "7 days"),
    (Some(30), "30 days"),
    (Some(90), "90 days"),
    (Some(365), "1 year"),
    (None, "Never"),
];

/// Creates a token and returns it with its ID. The token is shown to the
/// admin now; afterwards only through an audited reveal.
pub async fn create(
    pool: &DbPool,
    key: Option<&EncryptionKey>,
    label: &str,
    expires_in_days: Option<u32>,
    require_approval: bool,
    by: Option<Uuid>,
) -> anyhow::Result<(Uuid, String)> {
    let token = crate::aat::new_aat();
    let sealed = crate::aat::seal(&token, key)?;
    let id = repo::install_tokens::create(
        pool,
        &NewInstallToken {
            label,
            token_sealed: &sealed,
            token_hash: &hash_token(&token),
            key_id: &key_id(&token),
            require_approval,
            created_by: by,
            expires_at: expires_in_days.map(|d| Utc::now() + Duration::days(i64::from(d))),
        },
    )
    .await?;
    Ok((id, token))
}

/// The token in clear, for an audited reveal.
pub fn unseal(token: &InstallToken, key: Option<&EncryptionKey>) -> anyhow::Result<String> {
    crate::aat::unseal(&token.token_sealed, key)?.ok_or_else(|| {
        anyhow::anyhow!(
            "install token \"{}\" isn't readable -- revoke it and create a new one",
            token.label
        )
    })
}

/// Which token an `AAT1-` value presented at enrollment is.
pub enum Matched {
    Default,
    Additional(InstallToken),
}

/// Checks a presented AAT-format token: the default one, else an active
/// additional one. `None` when it's neither (rotated, revoked, expired, or
/// never valid).
pub async fn match_presented(
    pool: &DbPool,
    key: Option<&EncryptionKey>,
    presented: &str,
) -> anyhow::Result<Option<Matched>> {
    if crate::aat::matches(pool, key, presented).await? {
        return Ok(Some(Matched::Default));
    }
    Ok(
        repo::install_tokens::find_active_by_hash(pool, &hash_token(presented))
            .await?
            .map(Matched::Additional),
    )
}

/// The token to key a CA proof with, given the key ID the agent sent (if
/// any). An agent without one gets the default token. `Ok(None)`: the key ID
/// is neither the default token's nor an active additional one's.
pub async fn for_ca_proof(
    pool: &DbPool,
    key: Option<&EncryptionKey>,
    requested: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let default = crate::aat::current(pool, key).await?;
    let Some(requested) = requested else {
        return Ok(default);
    };
    if let Some(default) = default.filter(|d| key_id(d) == requested) {
        return Ok(Some(default));
    }
    match repo::install_tokens::find_active_by_key_id(pool, requested).await? {
        Some(token) => unseal(&token, key).map(Some),
        None => Ok(None),
    }
}

/// "Expires …" for the list: "Never", "Expired", or the date.
pub fn expiry_label(token: &InstallToken, now: DateTime<Utc>, tz: &str) -> String {
    match token.expires_at {
        None => "Never".to_string(),
        Some(t) if t <= now => format!("Expired {}", crate::common::format_in_tz(t, tz)),
        Some(t) => crate::common::format_in_tz(t, tz),
    }
}
