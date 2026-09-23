//! Streaming encryption at rest for a finished backup archive -- GitHub
//! issue #9. Deliberately not `crates/core/src/crypto.rs::EncryptionKey`:
//! that primitive encrypts a short string in one shot, held fully in
//! memory, which is exactly wrong for a multi-gigabyte archive. This uses
//! `aes-gcm`'s `stream` feature (the STREAM construction: a sequence of
//! AEAD-sealed chunks, each authenticated on its own and bound to its
//! position in the stream) so encryption/decryption only ever holds one
//! bounded chunk in memory regardless of archive size. No custom crypto --
//! both AES-256-GCM and the STREAM construction are the vetted primitives
//! the `aead`/`aes-gcm` crates already implement; this module is just the
//! file-chunking glue around them.
//!
//! Key derivation is passphrase-based (Argon2id, already this codebase's
//! own KDF for local account passwords -- `crates/auth/src/password.rs`)
//! rather than a raw key file, so "safely storing the backup's key" means
//! "remembering a passphrase," not another secret file to protect and
//! back up in turn.

use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::Argon2;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore;
use zeroize::Zeroizing;

use super::BackupError;
use abyssal_core::EncryptionMetadata;

/// Plaintext bytes per STREAM chunk. Encryption/decryption never holds
/// more than roughly this much of either plaintext or ciphertext in
/// memory at once.
const CHUNK_SIZE: usize = 512 * 1024;
/// AES-GCM's authentication tag, appended to every chunk's ciphertext.
const TAG_LEN: usize = 16;
/// `EncryptorBE32`/`DecryptorBE32`'s fixed nonce prefix length (the
/// remaining 5 bytes of the 12-byte GCM nonce are the STREAM
/// construction's own per-chunk counter + last-chunk flag).
const NONCE_PREFIX_LEN: usize = 7;
const SALT_LEN: usize = 16;

const ALGORITHM: &str = "aes-256-gcm-stream-be32";
const KDF: &str = "argon2id";
const KDF_PARAMS: &str = "m=19456,t=2,p=1"; // matches crates/auth/src/password.rs's defaults

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| BackupError::Crypto(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypts `in_path` to `out_path` (deleting neither on success -- the
/// caller decides whether to remove the plaintext intermediate) and
/// returns the metadata a restore needs to derive the same key again from
/// the same passphrase. The on-disk format is `[7-byte nonce prefix][16-byte
/// salt][chunk 0][chunk 1]...`, each chunk being `CHUNK_SIZE` plaintext
/// bytes sealed to `CHUNK_SIZE + 16` ciphertext bytes except the final
/// (possibly shorter) chunk.
pub fn encrypt_file_blocking(
    in_path: &Path,
    out_path: &Path,
    passphrase: &str,
) -> Result<EncryptionMetadata, BackupError> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_ref()));
    let mut encryptor = EncryptorBE32::from_aead(cipher, GenericArray::from_slice(&nonce_prefix));

    let plain_len = std::fs::metadata(in_path)
        .map_err(|e| BackupError::Crypto(format!("statting {}: {e}", in_path.display())))?
        .len();
    let mut in_file = std::fs::File::open(in_path)
        .map_err(|e| BackupError::Crypto(format!("opening {}: {e}", in_path.display())))?;
    let mut out_file = std::fs::File::create(out_path)
        .map_err(|e| BackupError::Crypto(format!("creating {}: {e}", out_path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        out_file
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| BackupError::Crypto(format!("setting archive permissions: {e}")))?;
    }

    out_file
        .write_all(&nonce_prefix)
        .and_then(|_| out_file.write_all(&salt))
        .map_err(|e| BackupError::Crypto(format!("writing encryption header: {e}")))?;

    let full_chunks = (plain_len / CHUNK_SIZE as u64) as usize;
    let remainder = (plain_len % CHUNK_SIZE as u64) as usize;
    // If the file's length is an exact multiple of CHUNK_SIZE, the last
    // full chunk read is itself the final chunk (sealed with
    // encrypt_last, not encrypt_next) -- there's no separate zero-length
    // remainder chunk after it. `encrypt_last` consumes the encryptor by
    // value (it can only ever be called once), so it's deliberately kept
    // out of this loop entirely and called exactly once afterward.
    let last_full_chunk_is_final = remainder == 0 && full_chunks > 0;
    let non_final_full_chunks = if last_full_chunk_is_final {
        full_chunks - 1
    } else {
        full_chunks
    };

    let mut buf = vec![0u8; CHUNK_SIZE];
    for _ in 0..non_final_full_chunks {
        in_file
            .read_exact(&mut buf)
            .map_err(|e| BackupError::Crypto(format!("reading plaintext: {e}")))?;
        let ciphertext = encryptor
            .encrypt_next(buf.as_slice())
            .map_err(|e| BackupError::Crypto(format!("sealing chunk: {e}")))?;
        out_file
            .write_all(&ciphertext)
            .map_err(|e| BackupError::Crypto(format!("writing ciphertext: {e}")))?;
    }

    let final_len = if last_full_chunk_is_final {
        CHUNK_SIZE
    } else {
        remainder
    };
    let mut tail = vec![0u8; final_len];
    in_file
        .read_exact(&mut tail)
        .map_err(|e| BackupError::Crypto(format!("reading final plaintext chunk: {e}")))?;
    let ciphertext = encryptor
        .encrypt_last(tail.as_slice())
        .map_err(|e| BackupError::Crypto(format!("sealing final chunk: {e}")))?;
    out_file
        .write_all(&ciphertext)
        .map_err(|e| BackupError::Crypto(format!("writing final ciphertext: {e}")))?;
    out_file
        .sync_all()
        .map_err(|e| BackupError::Crypto(format!("syncing encrypted archive: {e}")))?;

    Ok(EncryptionMetadata {
        algorithm: ALGORITHM.to_string(),
        kdf: KDF.to_string(),
        kdf_salt_base64: STANDARD.encode(salt),
        kdf_params: KDF_PARAMS.to_string(),
    })
}

/// Reverses [`encrypt_file_blocking`]. Fails closed on any authentication
/// failure (a wrong passphrase or a tampered/corrupted archive both
/// surface as the same `BackupError::Crypto`, deliberately not
/// distinguished -- telling an attacker which one it was is an oracle
/// this doesn't need to offer) and never writes partial output past the
/// point of failure.
pub fn decrypt_file_blocking(
    in_path: &Path,
    out_path: &Path,
    passphrase: &str,
    metadata: &EncryptionMetadata,
) -> Result<(), BackupError> {
    if metadata.algorithm != ALGORITHM {
        return Err(BackupError::Crypto(format!(
            "unsupported encryption algorithm in manifest: {}",
            metadata.algorithm
        )));
    }
    let salt = STANDARD
        .decode(&metadata.kdf_salt_base64)
        .map_err(|_| BackupError::Crypto("malformed encryption salt in manifest".to_string()))?;
    let key = derive_key(passphrase, &salt)?;

    let mut in_file = std::fs::File::open(in_path)
        .map_err(|e| BackupError::Crypto(format!("opening {}: {e}", in_path.display())))?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    let mut header_salt = vec![0u8; SALT_LEN];
    in_file
        .read_exact(&mut nonce_prefix)
        .and_then(|_| in_file.read_exact(&mut header_salt))
        .map_err(|e| BackupError::Crypto(format!("reading encryption header: {e}")))?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_ref()));
    let mut decryptor = DecryptorBE32::from_aead(cipher, GenericArray::from_slice(&nonce_prefix));

    let mut out_file = std::fs::File::create(out_path)
        .map_err(|e| BackupError::Crypto(format!("creating {}: {e}", out_path.display())))?;

    let sealed_chunk_len = CHUNK_SIZE + TAG_LEN;
    let mut buf = vec![0u8; sealed_chunk_len];
    let mut pending: Option<Vec<u8>> = None;
    const DECRYPT_ERR: &str =
        "decryption failed -- wrong passphrase, or the archive was tampered with or corrupted";

    // `decrypt_last` consumes the decryptor by value (it can only ever be
    // called once), so -- same restructuring as `encrypt_file_blocking`
    // above -- this loop only ever calls `decrypt_next` (`&mut self`) and
    // hands the final chunk's bytes out through `break`, with the single
    // `decrypt_last` call happening after the loop.
    let final_chunk = loop {
        let chunk = match pending.take() {
            Some(c) => c,
            None => {
                let n = read_up_to(&mut in_file, &mut buf)
                    .map_err(|e| BackupError::Crypto(format!("reading ciphertext: {e}")))?;
                buf[..n].to_vec()
            }
        };
        // Peek ahead one byte to tell whether `chunk` is the final one --
        // mirrors `encrypt_file_blocking`'s length bookkeeping, just
        // discovered on the way in instead of computed upfront, since
        // the ciphertext's exact chunking isn't otherwise recoverable
        // without re-deriving it from the ORIGINAL plaintext length,
        // which isn't available on the decrypt side.
        let mut probe = [0u8; 1];
        let probe_n = in_file
            .read(&mut probe)
            .map_err(|e| BackupError::Crypto(format!("reading ciphertext: {e}")))?;
        let is_last = probe_n == 0;
        if is_last {
            break chunk;
        }

        let mut next_buf = vec![0u8; sealed_chunk_len];
        next_buf[0] = probe[0];
        let rest_n = read_up_to(&mut in_file, &mut next_buf[1..])
            .map_err(|e| BackupError::Crypto(format!("reading ciphertext: {e}")))?;
        next_buf.truncate(1 + rest_n);
        pending = Some(next_buf);

        let plaintext = decryptor
            .decrypt_next(chunk.as_slice())
            .map_err(|_| BackupError::Crypto(DECRYPT_ERR.to_string()))?;
        out_file
            .write_all(&plaintext)
            .map_err(|e| BackupError::Crypto(format!("writing plaintext: {e}")))?;
    };

    let plaintext = decryptor
        .decrypt_last(final_chunk.as_slice())
        .map_err(|_| BackupError::Crypto(DECRYPT_ERR.to_string()))?;
    out_file
        .write_all(&plaintext)
        .map_err(|e| BackupError::Crypto(format!("writing final plaintext: {e}")))?;

    out_file
        .sync_all()
        .map_err(|e| BackupError::Crypto(format!("syncing decrypted output: {e}")))?;
    Ok(())
}

/// Like `Read::read`, but keeps reading until either `buf` is full or EOF
/// -- a plain `read()` call is allowed to return short even mid-stream,
/// which would otherwise be mistaken for a short final chunk.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = reader.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(plaintext: &[u8]) {
        let tmp =
            std::env::temp_dir().join(format!("reliquary-crypto-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let plain_path = tmp.join("plain.bin");
        let enc_path = tmp.join("enc.bin");
        let dec_path = tmp.join("dec.bin");
        std::fs::write(&plain_path, plaintext).unwrap();

        let metadata =
            encrypt_file_blocking(&plain_path, &enc_path, "correct horse battery staple").unwrap();
        assert_ne!(std::fs::read(&enc_path).unwrap(), plaintext);

        decrypt_file_blocking(
            &enc_path,
            &dec_path,
            "correct horse battery staple",
            &metadata,
        )
        .unwrap();
        assert_eq!(std::fs::read(&dec_path).unwrap(), plaintext);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn round_trips_empty_input() {
        roundtrip(b"");
    }

    #[test]
    fn round_trips_smaller_than_one_chunk() {
        roundtrip(b"hello reliquary backup encryption");
    }

    #[test]
    fn round_trips_exactly_one_chunk() {
        roundtrip(&vec![7u8; CHUNK_SIZE]);
    }

    #[test]
    fn round_trips_multiple_chunks_with_a_remainder() {
        let mut data = vec![0u8; CHUNK_SIZE * 2 + 123];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        roundtrip(&data);
    }

    #[test]
    fn wrong_passphrase_fails_to_decrypt() {
        let tmp =
            std::env::temp_dir().join(format!("reliquary-crypto-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let plain_path = tmp.join("plain.bin");
        let enc_path = tmp.join("enc.bin");
        let dec_path = tmp.join("dec.bin");
        std::fs::write(&plain_path, b"top secret manifest").unwrap();

        let metadata = encrypt_file_blocking(&plain_path, &enc_path, "right passphrase").unwrap();
        let result = decrypt_file_blocking(&enc_path, &dec_path, "wrong passphrase", &metadata);
        assert!(result.is_err());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
