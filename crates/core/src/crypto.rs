//! Symmetric encryption at rest for the one class of secret this platform
//! didn't previously need to store reversibly: a switch's SNMP community
//! string (`crates/database/src/repo/panopticon_switches.rs`). Everything
//! else sensitive already persisted here -- session tokens, host
//! enrollment credentials, user passwords -- only ever needs to be
//! *verified* (hash-and-compare, see `crate::secret`), never read back in
//! plaintext. An SNMP community string is different: the background sweep
//! (`abyssal_web::spawn_panopticon_sweep`) has to present the actual
//! plaintext string on the wire to the switch on every poll, with nobody
//! present to type it in again, so it must be recoverable, not just
//! checkable -- hence a real (if narrowly-scoped) encryption-at-rest
//! primitive rather than another hash.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ENCRYPTION_KEY must be 32 bytes, base64-encoded")]
    InvalidKeyLength,
    #[error("ENCRYPTION_KEY is not valid base64: {0}")]
    InvalidKeyEncoding(base64::DecodeError),
    #[error("stored value is not valid base64")]
    InvalidCiphertextEncoding,
    #[error("stored value is too short to contain a nonce")]
    CiphertextTooShort,
    #[error("decryption failed -- wrong key, or the value was tampered with")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
}

/// A loaded AES-256-GCM master key, read once at startup from the
/// `ENCRYPTION_KEY` environment variable (see `crates/app/src/config.rs`).
/// Deliberately optional at the `Config` level rather than always
/// required: every deployment that predates this feature, or that simply
/// never configures a switch, shouldn't be forced to generate and manage a
/// new secret it doesn't use. Routes that need to store or read a switch
/// community string check for its presence and refuse cleanly
/// (`AppError::Validation`) when it's unset, the same "detect what's
/// present, refuse rather than guess" posture `agent/src/firewall.rs` uses
/// for a missing system tool.
pub struct EncryptionKey(Key<Aes256Gcm>);

impl EncryptionKey {
    /// Parses a base64-encoded 32-byte key, e.g. the output of `openssl
    /// rand -base64 32`.
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        let bytes = STANDARD
            .decode(encoded.trim())
            .map_err(CryptoError::InvalidKeyEncoding)?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        Ok(Self(*Key::<Aes256Gcm>::from_slice(&bytes)))
    }

    /// Encrypts `plaintext`, returning a base64 string of `nonce ||
    /// ciphertext` suitable for storing directly in a `TEXT` column. A
    /// fresh random nonce is generated for every call -- AES-GCM's
    /// security guarantee depends on never reusing a nonce under the same
    /// key, so this must never be memoized or reused across calls.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        let cipher = Aes256Gcm::new(&self.0);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(combined))
    }

    /// Reverses [`Self::encrypt`]. The result is wrapped in `Zeroizing` --
    /// a decrypted community string is exactly the kind of live secret
    /// `crates/web/src/common.rs`/`crates/agent/src/elevation.rs` already
    /// wipe from memory on drop rather than leaving it to be paged out or
    /// lingering in a freed allocation.
    pub fn decrypt(&self, encoded: &str) -> Result<Zeroizing<String>, CryptoError> {
        let raw = STANDARD
            .decode(encoded)
            .map_err(|_| CryptoError::InvalidCiphertextEncoding)?;
        if raw.len() < NONCE_LEN {
            return Err(CryptoError::CiphertextTooShort);
        }
        let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new(&self.0);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let s = String::from_utf8(plaintext).map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(Zeroizing::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> EncryptionKey {
        EncryptionKey::from_base64(&STANDARD.encode([7u8; 32])).unwrap()
    }

    #[test]
    fn round_trips() {
        let key = test_key();
        let encrypted = key.encrypt("s3cr3t-community").unwrap();
        assert_ne!(encrypted, "s3cr3t-community");
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(&*decrypted, "s3cr3t-community");
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let key = test_key();
        let a = key.encrypt("same-plaintext").unwrap();
        let b = key.encrypt("same-plaintext").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key_a = test_key();
        let key_b = EncryptionKey::from_base64(&STANDARD.encode([9u8; 32])).unwrap();
        let encrypted = key_a.encrypt("payload").unwrap();
        assert!(key_b.decrypt(&encrypted).is_err());
    }

    #[test]
    fn rejects_wrong_length_key() {
        assert!(matches!(
            EncryptionKey::from_base64(&STANDARD.encode([1u8; 16])),
            Err(CryptoError::InvalidKeyLength)
        ));
    }
}
