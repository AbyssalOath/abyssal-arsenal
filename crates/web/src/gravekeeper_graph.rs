//! Microsoft Graph client for Gravekeeper's cloud (Microsoft 365) mail mode.
//!
//! App-only auth with a **certificate** (no client secret, per the roadmap): the
//! control plane signs a client-assertion JWT (RS256) with the app's private key
//! and exchanges it for a Graph token, then finds the synced user and provisions
//! its Microsoft 365 licence -- either by adding it to a licensing group
//! (group-based) or assigning a SKU directly. No agent is involved.
//!
//! The live path runs against a real tenant and cannot be exercised here; every
//! pure part (JWT header/claims assembly, the x5t thumbprint, base64url, the
//! request bodies) is unit-tested, and the whole path is flagged for lab
//! validation. Secrets (the certificate PEM) arrive already decrypted and are
//! never logged.

use base64::Engine;
use serde::Deserialize;

const GRAPH: &str = "https://graph.microsoft.com/v1.0";
const AUTHORITY: &str = "https://login.microsoftonline.com";
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The app registration's config plus its decrypted certificate PEM (cert +
/// private key). `licensing_method` is `group` | `direct` | `both`.
pub struct GraphConfig {
    pub tenant_id: String,
    pub app_id: String,
    pub cert_pem: String,
    pub licensing_method: String,
}

/// The per-template M365 licensing choices (from the template's mail settings).
#[derive(Default)]
pub struct M365Licensing {
    /// 2-letter usage location (required before a licence can be assigned).
    pub usage_location: String,
    /// Entra group id for group-based licensing.
    pub licensing_group: String,
    /// SKU id for direct licensing.
    pub license_sku: String,
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// x5t: base64url(SHA-1(cert DER)) from the first CERTIFICATE block in the PEM.
fn x5t_from_pem(pem_str: &str) -> Result<String, String> {
    use sha1::{Digest, Sha1};
    let blocks = pem::parse_many(pem_str).map_err(|e| format!("bad certificate PEM: {e}"))?;
    let cert = blocks
        .iter()
        .find(|b| b.tag() == "CERTIFICATE")
        .ok_or("no CERTIFICATE block in the configured PEM")?;
    Ok(b64url(&Sha1::digest(cert.contents())))
}

fn private_key_from_pem(pem_str: &str) -> Result<rsa::RsaPrivateKey, String> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs8_pem(pem_str)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem_str))
        .map_err(|e| format!("couldn't read the private key from the PEM: {e}"))
}

/// The JWT header/claims (public, so they can be unit-tested).
fn assertion_header(x5t: &str) -> serde_json::Value {
    serde_json::json!({ "alg": "RS256", "typ": "JWT", "x5t": x5t })
}

fn assertion_claims(app_id: &str, tenant_id: &str, now: i64, jti: &str) -> serde_json::Value {
    serde_json::json!({
        "aud": format!("{AUTHORITY}/{tenant_id}/oauth2/v2.0/token"),
        "iss": app_id,
        "sub": app_id,
        "jti": jti,
        "nbf": now - 60,
        "exp": now + 300,
    })
}

fn build_client_assertion(cfg: &GraphConfig) -> Result<String, String> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding, Signer};

    let x5t = x5t_from_pem(&cfg.cert_pem)?;
    let header = assertion_header(&x5t);
    let now = chrono::Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().to_string();
    let claims = assertion_claims(&cfg.app_id, &cfg.tenant_id, now, &jti);
    let signing_input = format!(
        "{}.{}",
        b64url(
            serde_json::to_string(&header)
                .unwrap_or_default()
                .as_bytes()
        ),
        b64url(
            serde_json::to_string(&claims)
                .unwrap_or_default()
                .as_bytes()
        ),
    );
    let key = private_key_from_pem(&cfg.cert_pem)?;
    let sk = SigningKey::<Sha256>::new(key);
    let sig = sk.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64url(&sig.to_bytes())))
}

fn http() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// Exchanges the client-assertion for a Graph access token.
pub async fn acquire_token(cfg: &GraphConfig) -> Result<String, String> {
    let assertion = build_client_assertion(cfg)?;
    let url = format!("{AUTHORITY}/{}/oauth2/v2.0/token", cfg.tenant_id);
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", cfg.app_id.as_str()),
        ("scope", "https://graph.microsoft.com/.default"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
    ];
    let resp = http()?
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("token request failed: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("token endpoint returned {status}: {}", body.trim()));
    }
    #[derive(Deserialize)]
    struct Tok {
        access_token: String,
    }
    serde_json::from_str::<Tok>(&body)
        .map(|t| t.access_token)
        .map_err(|e| format!("bad token response: {e}"))
}

async fn graph_get(token: &str, path: &str) -> Result<(reqwest::StatusCode, String), String> {
    let resp = http()?
        .get(format!("{GRAPH}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Graph GET {path} failed: {e}"))?;
    let status = resp.status();
    Ok((status, resp.text().await.unwrap_or_default()))
}

async fn graph_post(
    token: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<(reqwest::StatusCode, String), String> {
    let resp = http()?
        .post(format!("{GRAPH}{path}"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("Graph POST {path} failed: {e}"))?;
    let status = resp.status();
    Ok((status, resp.text().await.unwrap_or_default()))
}

async fn graph_patch(
    token: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<(reqwest::StatusCode, String), String> {
    let resp = http()?
        .patch(format!("{GRAPH}{path}"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("Graph PATCH {path} failed: {e}"))?;
    let status = resp.status();
    Ok((status, resp.text().await.unwrap_or_default()))
}

/// One subscribed SKU, for the licence picker / test output.
#[derive(Deserialize)]
pub struct SubscribedSku {
    #[serde(rename = "skuId", default)]
    pub sku_id: String,
    #[serde(rename = "skuPartNumber", default)]
    pub sku_part_number: String,
    #[serde(rename = "prepaidUnits", default)]
    pub prepaid_units: PrepaidUnits,
    #[serde(rename = "consumedUnits", default)]
    pub consumed_units: i64,
}

#[derive(Deserialize, Default)]
pub struct PrepaidUnits {
    #[serde(default)]
    pub enabled: i64,
}

impl SubscribedSku {
    pub fn available(&self) -> i64 {
        self.prepaid_units.enabled - self.consumed_units
    }
}

/// Lists the tenant's subscribed SKUs (needs `Organization.Read.All`).
pub async fn list_skus(token: &str) -> Result<Vec<SubscribedSku>, String> {
    let (status, body) = graph_get(token, "/subscribedSkus").await?;
    if !status.is_success() {
        return Err(format!("subscribedSkus returned {status}: {}", body.trim()));
    }
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        value: Vec<SubscribedSku>,
    }
    serde_json::from_str::<Resp>(&body)
        .map(|r| r.value)
        .map_err(|e| format!("bad subscribedSkus response: {e}"))
}

/// Test connection: acquire a token and read the organisation + SKUs.
pub async fn test_connection(cfg: &GraphConfig) -> Result<String, String> {
    let token = acquire_token(cfg).await?;
    let (status, body) = graph_get(&token, "/organization?$select=displayName").await?;
    if !status.is_success() {
        return Err(format!("organization returned {status}: {}", body.trim()));
    }
    #[derive(Deserialize)]
    struct Org {
        #[serde(rename = "displayName", default)]
        display_name: String,
    }
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        value: Vec<Org>,
    }
    let org = serde_json::from_str::<Resp>(&body)
        .ok()
        .and_then(|r| r.value.into_iter().next())
        .map(|o| o.display_name)
        .unwrap_or_default();
    let skus = list_skus(&token).await.unwrap_or_default();
    Ok(format!("Tenant: {org}. {} subscribed SKU(s).", skus.len()))
}

/// Resolves the Entra object id of a synced user by UPN. `Ok(None)` means the
/// user isn't in Entra yet (e.g. Entra Connect hasn't synced the AD account).
pub async fn find_user_id(token: &str, upn: &str) -> Result<Option<String>, String> {
    let path = format!("/users/{}?$select=id", urlencoding(upn));
    let (status, body) = graph_get(token, &path).await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("user lookup returned {status}: {}", body.trim()));
    }
    #[derive(Deserialize)]
    struct U {
        #[serde(default)]
        id: String,
    }
    serde_json::from_str::<U>(&body)
        .map(|u| (!u.id.is_empty()).then_some(u.id))
        .map_err(|e| format!("bad user response: {e}"))
}

/// Minimal percent-encoding for a UPN in a path segment.
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | '@' => c.to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

/// Sets the user's usage location (required before a licence can be assigned).
pub async fn set_usage_location(token: &str, user_id: &str, location: &str) -> Result<(), String> {
    let body = serde_json::json!({ "usageLocation": location });
    let (status, resp) = graph_patch(token, &format!("/users/{user_id}"), &body).await?;
    if !status.is_success() {
        return Err(format!(
            "set usageLocation returned {status}: {}",
            resp.trim()
        ));
    }
    Ok(())
}

/// The assignLicense request body for a single SKU (public for testing).
pub fn assign_license_body(sku_id: &str) -> serde_json::Value {
    serde_json::json!({
        "addLicenses": [ { "disabledPlans": [], "skuId": sku_id } ],
        "removeLicenses": [],
    })
}

/// Assigns a licence SKU directly to the user (needs `LicenseAssignment.ReadWrite.All`).
pub async fn assign_license(token: &str, user_id: &str, sku_id: &str) -> Result<(), String> {
    let body = assign_license_body(sku_id);
    let (status, resp) =
        graph_post(token, &format!("/users/{user_id}/assignLicense"), &body).await?;
    if !status.is_success() {
        return Err(format!("assignLicense returned {status}: {}", resp.trim()));
    }
    Ok(())
}

/// The add-group-member `$ref` body (public for testing).
pub fn add_member_body(user_id: &str) -> serde_json::Value {
    serde_json::json!({ "@odata.id": format!("{GRAPH}/directoryObjects/{user_id}") })
}

/// Adds the user to a licensing group (needs `GroupMember.ReadWrite.All`).
pub async fn add_to_group(token: &str, group_id: &str, user_id: &str) -> Result<(), String> {
    let body = add_member_body(user_id);
    let (status, resp) =
        graph_post(token, &format!("/groups/{group_id}/members/$ref"), &body).await?;
    // 204 No Content on success; 400 "already exists" is tolerated.
    if status.is_success() {
        return Ok(());
    }
    if status == reqwest::StatusCode::BAD_REQUEST && resp.contains("already exist") {
        return Ok(());
    }
    Err(format!("add to group returned {status}: {}", resp.trim()))
}

/// The full onboarding M365 flow: find the synced user, set usage location, and
/// license it (group-based and/or direct per `cfg.licensing_method` and the
/// template's choices). Returns a human success detail or an error.
pub async fn provision_user(
    cfg: &GraphConfig,
    upn: &str,
    lic: &M365Licensing,
) -> Result<String, String> {
    let token = acquire_token(cfg).await?;
    let user_id = match find_user_id(&token, upn).await? {
        Some(id) => id,
        None => {
            return Err(format!(
                "{upn} isn't in Entra yet (Entra Connect may not have synced the account). Retry the mail step after the next sync."
            ));
        }
    };
    if !lic.usage_location.is_empty() {
        set_usage_location(&token, &user_id, &lic.usage_location).await?;
    }

    let want_group = matches!(cfg.licensing_method.as_str(), "group" | "both")
        && !lic.licensing_group.is_empty();
    let want_direct =
        matches!(cfg.licensing_method.as_str(), "direct" | "both") && !lic.license_sku.is_empty();

    if !want_group && !want_direct {
        return Err(
            "No licensing target configured on the template (a licensing group or a SKU) for this method.".into(),
        );
    }

    let mut done = Vec::new();
    if want_group {
        add_to_group(&token, &lic.licensing_group, &user_id).await?;
        done.push("added to the licensing group");
    }
    if want_direct {
        assign_license(&token, &user_id, &lic.license_sku).await?;
        done.push("assigned the licence SKU");
    }
    Ok(format!("Microsoft 365: {}.", done.join(" and ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_is_unpadded_urlsafe() {
        // 0xFF 0xFF 0xFE -> standard "///+" -> url-safe "___-".
        assert_eq!(b64url(b"\xff\xff\xfe"), "___-");
        // No padding characters.
        assert!(!b64url(b"abc").contains('='));
    }

    #[test]
    fn assertion_header_and_claims_shape() {
        let h = assertion_header("THUMB");
        assert_eq!(h["alg"], "RS256");
        assert_eq!(h["typ"], "JWT");
        assert_eq!(h["x5t"], "THUMB");

        let c = assertion_claims("app-123", "tenant-abc", 1_000_000, "jti-1");
        assert_eq!(c["iss"], "app-123");
        assert_eq!(c["sub"], "app-123");
        assert_eq!(
            c["aud"],
            "https://login.microsoftonline.com/tenant-abc/oauth2/v2.0/token"
        );
        assert_eq!(c["jti"], "jti-1");
        assert_eq!(c["nbf"], 999_940);
        assert_eq!(c["exp"], 1_000_300);
    }

    #[test]
    fn x5t_matches_known_sha1() {
        // A tiny self-signed-ish CERTIFICATE block's DER -> SHA-1 -> base64url.
        // Here we just verify the function reads the block and base64url-encodes
        // a SHA-1 (20 bytes -> 27 base64url chars, no padding).
        let der = b"hello world cert der bytes";
        use sha1::{Digest, Sha1};
        let expected = b64url(&Sha1::digest(der));
        let pem_block = pem::Pem::new("CERTIFICATE", der.to_vec());
        let pem_str = pem::encode(&pem_block);
        assert_eq!(x5t_from_pem(&pem_str).unwrap(), expected);
        assert_eq!(expected.len(), 27); // 20-byte sha1 -> 27 url-safe chars
    }

    #[test]
    fn request_bodies() {
        let lic = assign_license_body("SKU-1");
        assert_eq!(lic["addLicenses"][0]["skuId"], "SKU-1");
        assert!(lic["removeLicenses"].as_array().unwrap().is_empty());

        let mem = add_member_body("user-1");
        assert_eq!(
            mem["@odata.id"],
            "https://graph.microsoft.com/v1.0/directoryObjects/user-1"
        );
    }

    #[test]
    fn upn_is_path_safe() {
        assert_eq!(urlencoding("jane.doe@corp.com"), "jane.doe@corp.com");
        assert_eq!(urlencoding("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn sku_available_math() {
        let s = SubscribedSku {
            sku_id: "x".into(),
            sku_part_number: "ENTERPRISEPACK".into(),
            prepaid_units: PrepaidUnits { enabled: 10 },
            consumed_units: 7,
        };
        assert_eq!(s.available(), 3);
    }
}
