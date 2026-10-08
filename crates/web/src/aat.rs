//! Server side of the AAT (see `abyssal_agent_protocol::aat`): the one
//! reusable, viewable install token per control plane, and whether hosts
//! enrolling with it need an admin's approval first.
//!
//! Unlike every other token here it can't be stored as a hash: it has to be
//! shown again (on `/admin/hosts`, by `install.sh`), and it keys the CA proof,
//! which needs the secret itself. So it's encrypted at rest with
//! `ENCRYPTION_KEY` (AES-256-GCM, `abyssal_core::crypto` -- the same key and
//! primitive as SNMP community strings and Sepulchre secrets), keeping a
//! working enrollment secret out of database dumps and Reliquary backups.
//! Without a key (an install that predates it) it's stored as-is, with a
//! warning at every start, and encrypted on the first start after a key is
//! configured.

use abyssal_agent_protocol::aat::{AAT_PREFIX, is_aat};
use abyssal_core::EncryptionKey;
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_database::{DbPool, repo};
use uuid::Uuid;

const SECRET_KEY: &str = "agents.aat";
const REQUIRE_APPROVAL_KEY: &str = "agents.aat_require_approval";
/// Marks a stored value as `ENCRYPTION_KEY` ciphertext; anything else is a
/// plaintext AAT from before a key was configured.
const ENCRYPTED_PREFIX: &str = "enc:v1:";

fn new_aat() -> String {
    format!("{AAT_PREFIX}{}", generate_token())
}

/// The stored form of `aat`: encrypted when there's a key.
fn seal(aat: &str, key: Option<&EncryptionKey>) -> anyhow::Result<String> {
    match key {
        Some(key) => Ok(format!(
            "{ENCRYPTED_PREFIX}{}",
            key.encrypt(aat)
                .map_err(|e| anyhow::anyhow!("failed to encrypt the agent install token: {e}"))?
        )),
        None => Ok(aat.to_string()),
    }
}

/// Reverses [`seal`]. `Ok(None)` for nothing stored (or something that isn't
/// an AAT at all); an error when it's encrypted and can't be decrypted.
fn unseal(stored: &str, key: Option<&EncryptionKey>) -> anyhow::Result<Option<String>> {
    let aat = match stored.strip_prefix(ENCRYPTED_PREFIX) {
        Some(ciphertext) => {
            let key = key.ok_or_else(|| {
                anyhow::anyhow!(
                    "the agent install token is stored encrypted but ENCRYPTION_KEY isn't set"
                )
            })?;
            key.decrypt(ciphertext)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "the agent install token can't be decrypted ({e}) -- was ENCRYPTION_KEY \
                         changed? Rotate the token on /admin/hosts to replace it"
                    )
                })?
                .to_string()
        }
        None => stored.to_string(),
    };
    Ok(is_aat(&aat).then_some(aat))
}

async fn read_stored(pool: &DbPool) -> anyhow::Result<Option<String>> {
    Ok(repo::settings::get(pool, SECRET_KEY)
        .await?
        .and_then(|v| v.as_str().map(str::to_string)))
}

async fn store(
    pool: &DbPool,
    key: Option<&EncryptionKey>,
    aat: &str,
    by: Option<Uuid>,
) -> anyhow::Result<()> {
    let sealed = seal(aat, key)?;
    repo::settings::set(pool, SECRET_KEY, serde_json::json!(sealed), by).await
}

/// The current AAT, creating one if there's none yet (first start, or a
/// database from before AATs existed) and encrypting a plaintext one once a
/// key is available. Run at every startup.
pub async fn ensure(pool: &DbPool, key: Option<&EncryptionKey>) -> anyhow::Result<String> {
    let stored = read_stored(pool).await?;
    if let Some(aat) = stored
        .as_deref()
        .map(|s| unseal(s, key))
        .transpose()?
        .flatten()
    {
        let plaintext_at_rest = !stored
            .as_deref()
            .unwrap_or("")
            .starts_with(ENCRYPTED_PREFIX);
        if plaintext_at_rest {
            if key.is_some() {
                store(pool, key, &aat, None).await?;
                tracing::info!("encrypted the agent install token (AAT) at rest");
            } else {
                warn_unencrypted();
            }
        }
        return Ok(aat);
    }
    let aat = new_aat();
    store(pool, key, &aat, None).await?;
    tracing::info!("created this control plane's agent install token (AAT)");
    if key.is_none() {
        warn_unencrypted();
    }
    Ok(aat)
}

fn warn_unencrypted() {
    tracing::warn!(
        "ENCRYPTION_KEY isn't set, so the agent install token (AAT) is stored unencrypted -- \
         set it (openssl rand -base64 32) in .env and restart to encrypt it"
    );
}

pub async fn current(pool: &DbPool, key: Option<&EncryptionKey>) -> anyhow::Result<Option<String>> {
    match read_stored(pool).await? {
        Some(stored) => unseal(&stored, key),
        None => Ok(None),
    }
}

/// Replaces the AAT: the old one stops enrolling hosts immediately. Hosts it
/// already enrolled keep working -- each has its own credential. Also the
/// way out when the stored one can't be decrypted.
pub async fn rotate(
    pool: &DbPool,
    key: Option<&EncryptionKey>,
    by: Option<Uuid>,
) -> anyhow::Result<String> {
    let aat = new_aat();
    store(pool, key, &aat, by).await?;
    Ok(aat)
}

/// True when `presented` is the current AAT. Compares SHA-256 digests, so the
/// comparison's timing says nothing about the secret.
pub async fn matches(
    pool: &DbPool,
    key: Option<&EncryptionKey>,
    presented: &str,
) -> anyhow::Result<bool> {
    Ok(current(pool, key)
        .await?
        .is_some_and(|aat| hash_token(&aat) == hash_token(presented)))
}

/// Off by default: the AAT is meant for zero-touch rollouts (PDQ, Intune,
/// GPO), the way a CrowdStrike CID is.
pub async fn require_approval(pool: &DbPool) -> anyhow::Result<bool> {
    repo::settings::get_bool(pool, REQUIRE_APPROVAL_KEY, false).await
}

pub async fn set_require_approval(
    pool: &DbPool,
    required: bool,
    by: Option<Uuid>,
) -> anyhow::Result<()> {
    repo::settings::set(pool, REQUIRE_APPROVAL_KEY, serde_json::json!(required), by).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> EncryptionKey {
        use base64::Engine as _;
        EncryptionKey::from_base64(&base64::engine::general_purpose::STANDARD.encode([byte; 32]))
            .unwrap()
    }

    #[test]
    fn sealed_with_a_key_never_contains_the_token() {
        let aat = new_aat();
        let sealed = seal(&aat, Some(&key(1))).unwrap();
        assert!(sealed.starts_with(ENCRYPTED_PREFIX));
        assert!(!sealed.contains(&aat[AAT_PREFIX.len()..]));
        assert_eq!(unseal(&sealed, Some(&key(1))).unwrap(), Some(aat));
    }

    #[test]
    fn plaintext_is_kept_without_a_key_and_still_readable_with_one() {
        let aat = new_aat();
        let sealed = seal(&aat, None).unwrap();
        assert_eq!(sealed, aat);
        assert_eq!(unseal(&sealed, None).unwrap(), Some(aat.clone()));
        assert_eq!(unseal(&sealed, Some(&key(1))).unwrap(), Some(aat));
    }

    #[test]
    fn encrypted_needs_the_same_key() {
        let sealed = seal(&new_aat(), Some(&key(1))).unwrap();
        assert!(unseal(&sealed, None).is_err());
        assert!(unseal(&sealed, Some(&key(2))).is_err());
    }

    #[test]
    fn non_tokens_are_ignored() {
        assert_eq!(unseal("not-an-aat", None).unwrap(), None);
    }
}
