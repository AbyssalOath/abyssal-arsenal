//! The public certificate of the CA that the control plane's TLS chains to,
//! when that's a private CA: the one `crate::internal_tls` manages (the
//! Caddy install with no public domain), or -- for an operator running their
//! own proxy with their own internal CA -- a PEM file named by
//! `PUBLIC_CA_FILE`.
//!
//! Used for two things: serving the certificate at `/ca.crt` so a fresh host
//! can fetch it before it trusts anything, and putting its SHA-256
//! fingerprint into the commands `/admin/hosts` generates, so that host can
//! verify what it fetched against a value the admin got over an
//! authenticated channel (trust on first use, pinned). Read per request, so a
//! regenerated CA is picked up without restarting the app.

use std::path::PathBuf;

use base64::Engine;
use sha2::{Digest, Sha256};

pub struct PublicCa {
    /// Exactly one `CERTIFICATE` PEM block, re-encoded from the DER -- never
    /// anything else that happened to be in the file.
    pub pem: String,
    /// SHA-256 of the DER, upper-case hex, no separators.
    pub fingerprint: String,
}

impl PublicCa {
    /// `AB:CD:...`, the form browsers and `openssl x509 -fingerprint` show.
    pub fn fingerprint_display(&self) -> String {
        self.fingerprint
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// `None` when no private CA is involved (Let's Encrypt, an operator's own
/// proxy with a publicly-trusted cert, plain HTTP) -- the normal case, not
/// an error. During a CA rotation this is still the *active* CA: that's
/// what the server presents until the admin activates the new one.
pub fn load() -> Option<PublicCa> {
    if let Some(text) = crate::internal_tls::active_ca_pem() {
        return parse(&text).ok();
    }
    let path = PathBuf::from(std::env::var("PUBLIC_CA_FILE").ok()?);
    let text = std::fs::read_to_string(&path).ok()?;
    match parse(&text) {
        Ok(ca) => Some(ca),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = e, "ignoring unusable public CA file");
            None
        }
    }
}

pub fn parse(text: &str) -> Result<PublicCa, &'static str> {
    // Belt and braces: if a key ever ends up in this file, serve nothing.
    if text.contains("PRIVATE KEY") {
        return Err("file contains a private key; refusing to serve it");
    }
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = text.find(BEGIN).ok_or("no CERTIFICATE block")? + BEGIN.len();
    let len = text[start..]
        .find(END)
        .ok_or("unterminated CERTIFICATE block")?;
    let body: String = text[start..start + len]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| "CERTIFICATE block is not valid base64")?;

    let fingerprint = Sha256::digest(&der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut pem = String::from(BEGIN);
    pem.push('\n');
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(END);
    pem.push('\n');
    Ok(PublicCa { pem, fingerprint })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Base64 framed as a certificate, not a complete one -- `parse` only
    // decodes and hashes, it doesn't interpret the DER.
    const SAMPLE: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBdzCCAR2gAwIBAgIUQ3ZpJ6m5m3y5o1pQK0a4n6wq2NIwCgYIKoZIzj0EAwIw\n\
ETEPMA0GA1UEAwwGdGVzdGNhMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAw\n\
MFowETEPMA0GA1UEAwwGdGVzdGNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn fingerprints_the_der_and_reencodes_one_block() {
        let ca = parse(&format!("junk before\n{SAMPLE}{SAMPLE}")).unwrap();
        assert_eq!(ca.fingerprint.len(), 64);
        assert_eq!(ca.pem.matches("BEGIN CERTIFICATE").count(), 1);
        assert!(!ca.pem.contains("junk"));
        // Same bytes, same fingerprint, regardless of surrounding text.
        assert_eq!(parse(SAMPLE).unwrap().fingerprint, ca.fingerprint);
        assert_eq!(ca.fingerprint_display().len(), 64 + 31);
    }

    #[test]
    fn refuses_anything_with_a_private_key() {
        let text =
            format!("{SAMPLE}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn rejects_non_certificates() {
        assert!(parse("hello").is_err());
        assert!(parse("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----").is_err());
    }
}
