//! The Abyssal Arsenal Token (AAT): one long-lived, reusable enrollment
//! secret per control plane, for mass deployment -- the role CrowdStrike's
//! CID plays (`abyssal-agent.exe /install /quiet AAT=... SERVER=...`).
//! Unlike the single-use and deployment tokens, an operator can view it again
//! at any time on `/admin/hosts` (and `install.sh` prints it), and rotating
//! it is the only way to stop it working.
//!
//! It also authenticates the control plane's CA to a brand-new host, so no
//! CA fingerprint has to travel with it (one would go stale on the first CA
//! rotation): the agent sends a random nonce to `GET /api/agent/ca`, the
//! control plane answers with its CA bundle plus [`ca_proof`] over both, and
//! the agent accepts the bundle only if it can recompute the same proof.
//! Someone intercepting that unverified first request doesn't know the AAT,
//! so can't forge a proof for a CA of their own. The AAT itself is only sent
//! afterwards, over a connection that CA has verified.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Every AAT starts with this, so the enroll endpoint can tell it apart from
/// a single-use/deployment token, and a pasted value is recognizable.
pub const AAT_PREFIX: &str = "AAT1-";

/// Domain separation for [`ca_proof`]: this key is used for nothing else
/// today, but a MAC that only means one thing can never be replayed as
/// another.
const CA_PROOF_CONTEXT: &[u8] = b"abyssal-arsenal/aat-ca-proof/v1";

/// True for anything shaped like an AAT (prefix plus a non-empty secret).
pub fn is_aat(token: &str) -> bool {
    token
        .strip_prefix(AAT_PREFIX)
        .is_some_and(|secret| !secret.is_empty())
}

/// Domain separation for [`key_id`].
const KEY_ID_CONTEXT: &[u8] = b"abyssal-arsenal/aat-key-id/v1";

/// A short, non-secret name for an install token, which the agent sends with
/// its CA request (`GET /api/agent/ca?nonce=..&key=..`) so a control plane
/// with several install tokens knows which one to key the proof with. It's a
/// truncated, domain-separated SHA-256 of a high-entropy secret, so it says
/// nothing usable about the token, and it can't be confused with the lookup
/// hash stored server-side. An agent that predates it sends none, and gets a
/// proof keyed with the default token. 16 lower-case hex digits.
pub fn key_id(aat: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_CONTEXT);
    hasher.update(aat.as_bytes());
    hasher.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// HMAC-SHA256, keyed by the AAT, over the agent's nonce and the CA bundle
/// the control plane is vouching for (empty when it has no internal CA and
/// relies on a publicly trusted certificate). Lower-case hex.
pub fn ca_proof(aat: &str, nonce: &str, ca_pem: Option<&str>) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(aat.as_bytes())
        .expect("HMAC-SHA256 accepts a key of any length");
    for part in [
        CA_PROOF_CONTEXT,
        nonce.as_bytes(),
        ca_pem.unwrap_or("").as_bytes(),
    ] {
        // Length-prefixed, so no two different (nonce, pem) pairs can ever
        // serialize to the same input.
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Constant-time check of a proof from the wire against [`ca_proof`].
pub fn verify_ca_proof(aat: &str, nonce: &str, ca_pem: Option<&str>, proof: &str) -> bool {
    let expected = ca_proof(aat, nonce, ca_pem);
    expected.len() == proof.len()
        && expected
            .bytes()
            .zip(proof.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// `GET /api/agent/ca`'s response body.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaProofResponse {
    /// The CA bundle to trust (active + any pending CA during a rotation), or
    /// `None` when the control plane's certificate is publicly trusted.
    pub ca_pem: Option<String>,
    /// [`ca_proof`] over the request's nonce and `ca_pem`.
    pub proof: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ids_are_short_stable_and_distinct() {
        let a = key_id("AAT1-one");
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, key_id("AAT1-one"));
        assert_ne!(a, key_id("AAT1-two"));
        assert!(!a.contains("one"));
    }

    #[test]
    fn key_id_known_answer() {
        // sha256("abyssal-arsenal/aat-key-id/v1" || token), first 8 bytes:
        // the server looks tokens up by this, so it must never drift.
        assert_eq!(key_id("AAT1-known-answer"), "e427caa1c0a6f717");
    }

    const AAT: &str = "AAT1-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    const PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    #[test]
    fn recognizes_an_aat() {
        assert!(is_aat(AAT));
        assert!(!is_aat("AAT1-"));
        assert!(!is_aat("plain-deployment-token"));
    }

    #[test]
    fn proof_verifies_only_for_the_same_inputs() {
        let proof = ca_proof(AAT, "n1", Some(PEM));
        assert!(verify_ca_proof(AAT, "n1", Some(PEM), &proof));
        assert!(!verify_ca_proof("AAT1-other", "n1", Some(PEM), &proof));
        assert!(!verify_ca_proof(AAT, "n2", Some(PEM), &proof));
        assert!(!verify_ca_proof(AAT, "n1", Some("forged"), &proof));
        assert!(!verify_ca_proof(AAT, "n1", None, &proof));
        assert!(!verify_ca_proof(AAT, "n1", Some(PEM), ""));
    }

    #[test]
    fn nonce_and_pem_boundaries_are_unambiguous() {
        assert_ne!(
            ca_proof(AAT, "ab", Some("c")),
            ca_proof(AAT, "a", Some("bc"))
        );
    }
}
