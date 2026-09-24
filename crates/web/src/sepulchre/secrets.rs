//! Sepulchre's own encrypted connection secrets -- reuses
//! `abyssal_core::crypto::EncryptionKey` exactly (the same AES-256-GCM
//! mechanism already backing Panopticon switch credentials and
//! Reliquary's encryption-keys backup component), never a second
//! encryption primitive. See `migrations/0019_sepulchre_storage.sql`'s
//! `storage_connection_secrets` table doc comment for why there's no
//! key-rotation support yet.
//!
//! Also holds control-plane SFTP keypair generation/import: per the
//! Cryptkeeper amendment, a keypair the *control plane* uses to reach a
//! remote SFTP server must be generated *here*, never through
//! Cryptkeeper's host-side keypair generation (which writes the key onto
//! a managed host's filesystem -- the wrong place for a credential this
//! process itself needs to present).

use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::SepulchreError;
use crate::state::AppState;

pub async fn decrypt_secret(
    state: &AppState,
    connection_id: Uuid,
) -> Result<Zeroizing<String>, SepulchreError> {
    let key = state
        .encryption_key
        .as_ref()
        .ok_or_else(|| SepulchreError::Config("ENCRYPTION_KEY is not set".to_string()))?;
    let record =
        abyssal_database::repo::storage_connections::find_secret(&state.pool, connection_id)
            .await?
            .ok_or_else(|| {
                SepulchreError::Config("this connection has no stored secret".to_string())
            })?;
    key.decrypt(&record.secret_ciphertext)
        .map_err(|e| SepulchreError::Config(e.to_string()))
}

/// Replaces a connection's password secret. Write-only by design -- there
/// is no corresponding "read the plaintext back" function anywhere in
/// Sepulchre's own route handlers, only `decrypt_secret` above, called
/// solely from inside a protocol backend at the moment of use.
pub async fn replace_password(
    state: &AppState,
    connection_id: Uuid,
    plaintext_password: &str,
    updated_by: Option<Uuid>,
) -> Result<(), SepulchreError> {
    let key = state
        .encryption_key
        .as_ref()
        .ok_or_else(|| SepulchreError::Config("ENCRYPTION_KEY is not set".to_string()))?;
    let ciphertext = key
        .encrypt(plaintext_password)
        .map_err(|e| SepulchreError::Config(e.to_string()))?;
    abyssal_database::repo::storage_connections::upsert_secret(
        &state.pool,
        connection_id,
        &ciphertext,
        None,
        None,
        updated_by,
    )
    .await?;
    Ok(())
}

pub struct GeneratedKeypair {
    pub private_key_openssh: Zeroizing<String>,
    pub public_key_openssh: String,
    pub fingerprint_sha256: String,
}

/// Generates a fresh Ed25519 keypair *inside the control plane*
/// (userspace, no filesystem write, no managed host involved). The seed
/// is sourced from `rand`'s `OsRng` (already a workspace dependency)
/// rather than `ssh-key`'s own `CryptoRng`-bounded `random()` --
/// `ssh-key` 0.7 (still a release candidate) pulls in a `rand_core 0.10`
/// trait bound incompatible with this workspace's `rand 0.8`/`rand_core
/// 0.6` stack; building the keypair from a 32-byte seed
/// (`Ed25519Keypair::from_seed`) sidesteps that entirely without adding
/// a second, conflicting `rand_core` major version as a dependency.
pub fn generate_control_plane_keypair(comment: &str) -> Result<GeneratedKeypair, SepulchreError> {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0); // the seed itself is as sensitive as the resulting private key

    let private_key = PrivateKey::new(KeypairData::Ed25519(keypair), comment)
        .map_err(|e| SepulchreError::Config(format!("key construction failed: {e}")))?;
    finish_keypair(private_key)
}

/// Imports an existing OpenSSH-format private key (optionally
/// passphrase-protected) pasted in by an admin. The plaintext key
/// material is held only in this function's stack and the returned
/// `Zeroizing` value -- callers must encrypt it (via
/// [`replace_control_plane_key`]) and never log or persist the raw
/// `openssh_private_key` argument beyond this call.
pub fn import_private_key(
    openssh_private_key: &str,
    passphrase: Option<&str>,
) -> Result<GeneratedKeypair, SepulchreError> {
    let private_key = PrivateKey::from_openssh(openssh_private_key)
        .map_err(|e| SepulchreError::Config(format!("not a valid OpenSSH private key: {e}")))?;
    let private_key = if private_key.is_encrypted() {
        let passphrase = passphrase.ok_or_else(|| {
            SepulchreError::Config(
                "this key is passphrase-protected; a passphrase is required".to_string(),
            )
        })?;
        private_key
            .decrypt(passphrase)
            .map_err(|_| SepulchreError::Config("wrong passphrase for this key".to_string()))?
    } else {
        private_key
    };
    finish_keypair(private_key)
}

fn finish_keypair(private_key: PrivateKey) -> Result<GeneratedKeypair, SepulchreError> {
    let fingerprint = private_key.fingerprint(HashAlg::Sha256).to_string();
    let public_key_openssh = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| SepulchreError::Config(format!("failed to encode public key: {e}")))?;
    let private_key_openssh = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| SepulchreError::Config(format!("failed to encode private key: {e}")))?;
    Ok(GeneratedKeypair {
        private_key_openssh,
        public_key_openssh,
        fingerprint_sha256: fingerprint,
    })
}

/// Encrypts and stores a control-plane SFTP keypair's *private* half,
/// alongside the *public* half and fingerprint in plaintext (both are
/// safe/expected to be shown in the UI for the admin to install on the
/// remote server -- see `storage_connection_secrets.public_key`/
/// `key_fingerprint`).
pub async fn replace_control_plane_key(
    state: &AppState,
    connection_id: Uuid,
    keypair: &GeneratedKeypair,
    updated_by: Option<Uuid>,
) -> Result<(), SepulchreError> {
    let key = state
        .encryption_key
        .as_ref()
        .ok_or_else(|| SepulchreError::Config("ENCRYPTION_KEY is not set".to_string()))?;
    let ciphertext = key
        .encrypt(&keypair.private_key_openssh)
        .map_err(|e| SepulchreError::Config(e.to_string()))?;
    abyssal_database::repo::storage_connections::upsert_secret(
        &state.pool,
        connection_id,
        &ciphertext,
        Some(&keypair.public_key_openssh),
        Some(&keypair.fingerprint_sha256),
        updated_by,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_usable_ed25519_keypair() {
        let generated = generate_control_plane_keypair("sepulchre-test").unwrap();
        assert!(generated.public_key_openssh.starts_with("ssh-ed25519 "));
        assert!(generated.fingerprint_sha256.starts_with("SHA256:"));
        assert!(
            generated
                .private_key_openssh
                .contains("BEGIN OPENSSH PRIVATE KEY")
        );
    }

    #[test]
    fn two_generated_keypairs_are_never_the_same() {
        let a = generate_control_plane_keypair("a").unwrap();
        let b = generate_control_plane_keypair("b").unwrap();
        assert_ne!(a.fingerprint_sha256, b.fingerprint_sha256);
    }

    #[test]
    fn imports_a_previously_generated_unencrypted_key() {
        let generated = generate_control_plane_keypair("roundtrip").unwrap();
        let imported = import_private_key(&generated.private_key_openssh, None).unwrap();
        assert_eq!(imported.fingerprint_sha256, generated.fingerprint_sha256);
        assert_eq!(imported.public_key_openssh, generated.public_key_openssh);
    }

    #[test]
    fn rejects_garbage_as_an_import() {
        assert!(import_private_key("not a key", None).is_err());
    }
}
