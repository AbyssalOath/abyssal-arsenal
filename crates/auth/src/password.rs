use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::Rng;
use rand::seq::SliceRandom;

/// Hashes a password with Argon2id (the modern default for interactive login).
/// The returned string is the full PHC-format hash (algorithm, params, salt all
/// embedded) -- that's what gets persisted, never the raw password.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?;
    Ok(hash.to_string())
}

/// Constant-time verification against a stored PHC hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub const MIN_PASSWORD_LENGTH: usize = 15;
const GENERATED_PASSWORD_LENGTH: usize = 20;

// Ambiguous characters excluded on purpose (I/O/l/o and 0/1) so a generated
// password can be read back and retyped correctly from a screen or printout
// without guessing which glyph is meant.
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijkmnpqrstuvwxyz";
const DIGITS: &[u8] = b"23456789";
const SPECIAL: &[u8] = b"!@#$%^&*-_=+?";

/// Checks the four required character classes and the minimum length. Returns
/// a single human-readable message listing everything still missing, rather
/// than a list callers have to format themselves.
pub fn validate_strength(password: &str) -> Result<(), String> {
    let mut missing = Vec::new();

    if password.chars().count() < MIN_PASSWORD_LENGTH {
        missing.push(format!("at least {MIN_PASSWORD_LENGTH} characters"));
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        missing.push("an uppercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        missing.push("a lowercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        missing.push("a number".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_punctuation()) {
        missing.push("a special character".to_string());
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("Password must contain {}.", missing.join(", ")))
    }
}

/// Generates a random password that satisfies [`validate_strength`] using a
/// cryptographically secure RNG (the same class of source used for session
/// and host tokens) -- this produces a real credential, not just a UI demo
/// value, so it must hold up to the same scrutiny as any other secret this
/// codebase generates.
pub fn generate_strong_password() -> String {
    let mut rng = rand::rngs::OsRng;
    let mut chars: Vec<u8> = Vec::with_capacity(GENERATED_PASSWORD_LENGTH);

    // Guarantee at least one of each required class first.
    chars.push(*UPPER.choose(&mut rng).expect("UPPER is non-empty"));
    chars.push(*LOWER.choose(&mut rng).expect("LOWER is non-empty"));
    chars.push(*DIGITS.choose(&mut rng).expect("DIGITS is non-empty"));
    chars.push(*SPECIAL.choose(&mut rng).expect("SPECIAL is non-empty"));

    let all: Vec<u8> = [UPPER, LOWER, DIGITS, SPECIAL].concat();
    for _ in chars.len()..GENERATED_PASSWORD_LENGTH {
        let idx = rng.gen_range(0..all.len());
        chars.push(all[idx]);
    }

    chars.shuffle(&mut rng);
    String::from_utf8(chars).expect("all character pools are ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_round_trips() {
        let hash = hash_password("correct horse battery staple 1A!").unwrap();
        assert!(verify_password("correct horse battery staple 1A!", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn hashes_are_salted_uniquely() {
        let a = hash_password("same password 1A!").unwrap();
        let b = hash_password("same password 1A!").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn validate_strength_rejects_each_missing_requirement() {
        assert!(validate_strength("short1A!").is_err());
        assert!(validate_strength("all-lowercase-but-long-enough-1!").is_err());
        assert!(validate_strength("ALL-UPPERCASE-BUT-LONG-ENOUGH-1!").is_err());
        assert!(validate_strength("NoDigitsHereButLongEnough!!!!!").is_err());
        assert!(validate_strength("NoSpecialCharsHereButLongEnough123").is_err());
    }

    #[test]
    fn validate_strength_accepts_a_compliant_password() {
        assert!(validate_strength("Correct-Horse-Battery-9").is_ok());
    }

    #[test]
    fn generated_passwords_always_satisfy_validate_strength() {
        for _ in 0..200 {
            let password = generate_strong_password();
            assert_eq!(password.chars().count(), GENERATED_PASSWORD_LENGTH);
            assert!(
                validate_strength(&password).is_ok(),
                "generated password failed validation: {password}"
            );
        }
    }

    #[test]
    fn generated_passwords_avoid_ambiguous_characters() {
        let ambiguous = "IOl0Oo1";
        for _ in 0..200 {
            let password = generate_strong_password();
            assert!(
                password.chars().all(|c| !ambiguous.contains(c)),
                "generated password contained an ambiguous character: {password}"
            );
        }
    }

    #[test]
    fn generated_passwords_are_not_deterministic() {
        let a = generate_strong_password();
        let b = generate_strong_password();
        assert_ne!(a, b);
    }
}
