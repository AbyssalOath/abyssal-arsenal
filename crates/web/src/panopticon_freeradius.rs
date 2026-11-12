//! FreeRADIUS as Panopticon's RADIUS front end, for 802.1X (0.2.7 N4, see
//! `docs/roadmap/0.2.7.md` and `deploy/freeradius/README.md`).
//!
//! The embedded server (`crate::panopticon_radius`) deliberately does MAC
//! Authentication Bypass only. Real 802.1X -- EAP-TLS here -- needs an EAP
//! stack, and FreeRADIUS is the one to trust with it. So with the
//! `freeradius` compose profile, FreeRADIUS runs in this container's network
//! namespace, owns UDP 1812/1813, and authenticates. Panopticon still decides:
//!
//! - `GET  /internal/radius/client?ip=` -- FreeRADIUS's *dynamic clients*: the
//!   shared secret of the NAS client matching a source address, so NAS
//!   clients stay defined in one place (Panopticon's RADIUS page).
//! - `POST /internal/radius/mab` -- a non-EAP request, from `authorize`:
//!   authorized as MAB with the same decision as the embedded server, or
//!   rejected (a password login that isn't MAB has no credential store).
//! - `POST /internal/radius/post-auth` -- after a successful EAP
//!   authentication: the device's admission decision (its VLAN, quarantine,
//!   or a reject) by its MAC.
//! - `POST /internal/radius/accounting` -- sessions, as the embedded server
//!   records them, so CoA (`crate::panopticon_coa`) keeps working.
//!
//! The endpoints exist only when `FREERADIUS_API_TOKEN` is set (at least 32
//! characters), answer only connections from loopback -- FreeRADIUS shares
//! this network namespace; everything else, Caddy included, arrives from
//! another address -- and require HTTP Basic `freeradius:<token>`. Bodies are
//! `rlm_rest`'s JSON attribute encoding; replies use its response encoding
//! (`{"reply:Tunnel-Type": "VLAN", ...}`).

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};

use abyssal_database::repo;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::panopticon_radius::{
    Admission, Decision, MacResolution, normalize_mac, resolve_mab_mac,
};
use crate::state::AppState;

/// Shortest token accepted; anything shorter leaves the integration off.
const MIN_TOKEN_LEN: usize = 32;
const BASIC_USER: &str = "freeradius";

static TOKEN: OnceLock<Option<Zeroizing<String>>> = OnceLock::new();
/// Unix seconds of the last authenticated call from FreeRADIUS (0 = never).
static LAST_CALL: AtomicI64 = AtomicI64::new(0);

fn token() -> Option<&'static str> {
    TOKEN
        .get_or_init(|| {
            let t = std::env::var("FREERADIUS_API_TOKEN").ok()?;
            let t = t.trim();
            if t.is_empty() {
                return None;
            }
            if t.len() < MIN_TOKEN_LEN {
                tracing::error!(
                    "FREERADIUS_API_TOKEN is shorter than {MIN_TOKEN_LEN} characters; the \
                     FreeRADIUS integration stays off"
                );
                return None;
            }
            Some(Zeroizing::new(t.to_string()))
        })
        .as_deref()
        .map(String::as_str)
}

/// Whether FreeRADIUS is configured as the RADIUS front end.
pub fn enabled() -> bool {
    token().is_some()
}

/// When FreeRADIUS last called in, for the RADIUS page.
pub fn last_call() -> Option<DateTime<Utc>> {
    match LAST_CALL.load(Ordering::Relaxed) {
        0 => None,
        t => DateTime::from_timestamp(t, 0),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Whether a request comes from FreeRADIUS: loopback, with the token.
fn authorized(expected: &str, peer: SocketAddr, headers: &HeaderMap) -> bool {
    if !peer.ip().is_loopback() {
        return false;
    }
    let Some(encoded) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
    else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let decoded = Zeroizing::new(decoded);
    let mut want = Zeroizing::new(format!("{BASIC_USER}:").into_bytes());
    want.extend_from_slice(expected.as_bytes());
    constant_time_eq(&decoded, &want)
}

/// The gate every endpoint passes: 404 when the integration is off (the
/// routes don't exist as far as anyone can tell), 401 otherwise.
fn gate(peer: SocketAddr, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(expected) = token() else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !authorized(expected, peer, headers) {
        tracing::warn!(peer = %peer, "FreeRADIUS API: refused an unauthenticated call");
        return Err(StatusCode::UNAUTHORIZED);
    }
    LAST_CALL.store(Utc::now().timestamp(), Ordering::Relaxed);
    Ok(())
}

/// A request's attributes in `rlm_rest`'s JSON encoding:
/// `{"User-Name": {"type": "string", "value": ["bob"]}, ...}`.
struct Attrs(Map<String, Value>);

impl Attrs {
    fn parse(body: &[u8]) -> Option<Attrs> {
        match serde_json::from_slice(body).ok()? {
            Value::Object(m) => Some(Attrs(m)),
            _ => None,
        }
    }

    /// The attribute's first value as text (attribute names are matched
    /// case-insensitively, as FreeRADIUS's dictionary does).
    fn get(&self, name: &str) -> Option<String> {
        let (_, v) = self.0.iter().find(|(k, _)| k.eq_ignore_ascii_case(name))?;
        let value = match v {
            Value::Object(o) => o.get("value")?,
            other => other,
        };
        let first = match value {
            Value::Array(a) => a.first()?,
            other => other,
        };
        match first {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }

    fn has(&self, name: &str) -> bool {
        self.0.keys().any(|k| k.eq_ignore_ascii_case(name))
    }

    fn mac(&self, name: &str) -> Option<String> {
        self.get(name).and_then(|s| normalize_mac(&s))
    }
}

/// A reply value FreeRADIUS takes literally. `rlm_rest` expands `%{...}` in
/// response values by default; a NAS client's name or secret (admin input)
/// containing `%` would otherwise be mangled -- or expanded.
fn lit(value: impl Into<Value>) -> Value {
    json!({ "value": value.into(), "do_xlat": false })
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (status, axum::Json(body)).into_response()
}

/// The `rlm_rest` reply attributes for a decision. `reject_with` is how the
/// calling section rejects: `authorize` sets `control:Auth-Type`, and
/// `post-auth` (where Auth-Type has already run) a flag its unlang checks.
fn decision_reply(decision: &Decision, accept_auth_type: bool) -> Value {
    let mut out = Map::new();
    match decision {
        Decision::Accept(vlan) => {
            if accept_auth_type {
                out.insert("control:Auth-Type".into(), lit("Accept"));
            }
            if let Some(vlan) = vlan {
                out.insert("reply:Tunnel-Type".into(), lit("VLAN"));
                out.insert("reply:Tunnel-Medium-Type".into(), lit("IEEE-802"));
                out.insert(
                    "reply:Tunnel-Private-Group-Id".into(),
                    lit(vlan.to_string()),
                );
            }
        }
        Decision::Reject => {
            if accept_auth_type {
                out.insert("control:Auth-Type".into(), lit("Reject"));
            } else {
                out.insert("control:Tmp-String-0".into(), lit("reject"));
            }
        }
    }
    Value::Object(out)
}

fn reject_reply(accept_auth_type: bool, why: &str) -> Value {
    let mut v = decision_reply(&Decision::Reject, accept_auth_type);
    if let Value::Object(o) = &mut v {
        o.insert("reply:Reply-Message".into(), lit(why));
    }
    v
}

/// `authorize` for a request without EAP: MAB, or rejected.
pub async fn mab(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(status) = gate(peer, &headers) {
        return status.into_response();
    }
    let Some(attrs) = Attrs::parse(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // FreeRADIUS sends EAP to its own eap module before calling this; one
    // that slipped through isn't ours to decide.
    if attrs.has("EAP-Message") {
        return json_response(StatusCode::OK, reject_reply(true, "unexpected EAP"));
    }
    // MAB: the User-Name is the device's MAC, and must be the MAC the switch
    // saw (Calling-Station-Id). A User-Name that isn't a MAC is a password
    // login, and there's no credential store to check it against.
    let username_mac = attrs.mac("User-Name");
    if username_mac.is_none() {
        return json_response(
            StatusCode::OK,
            reject_reply(
                true,
                "only 802.1X (EAP) and MAC authentication are accepted",
            ),
        );
    }
    let mac = match resolve_mab_mac(attrs.mac("Calling-Station-Id"), username_mac) {
        MacResolution::Resolved(m) => m,
        MacResolution::Conflict => {
            return json_response(
                StatusCode::OK,
                reject_reply(true, "User-Name MAC disagrees with Calling-Station-Id"),
            );
        }
        MacResolution::Missing => {
            return json_response(StatusCode::OK, reject_reply(true, "no MAC"));
        }
    };
    let (decision, trust, enforced) =
        crate::panopticon_radius::decide_for_mac(&state.pool, &mac, Admission::Mab).await;
    tracing::info!(
        mac = %mac,
        trust = trust.map(|t| t.as_str()).unwrap_or("unknown/none"),
        enforced = enforced.map(|k| k.as_str()).unwrap_or("none"),
        decision = ?decision,
        "FreeRADIUS MAB decision"
    );
    json_response(StatusCode::OK, decision_reply(&decision, true))
}

/// `post-auth` after a successful EAP authentication: the device's
/// admission by its MAC.
pub async fn post_auth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(status) = gate(peer, &headers) {
        return status.into_response();
    }
    let Some(attrs) = Attrs::parse(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let identity = attrs.get("User-Name").unwrap_or_default();
    let Some(mac) = attrs.mac("Calling-Station-Id") else {
        // No MAC, no device to decide for: admit as an unknown device would
        // be, under the configured policy.
        let (decision, _, _) =
            crate::panopticon_radius::decide_for_mac(&state.pool, "", Admission::Authenticated)
                .await;
        return json_response(StatusCode::OK, decision_reply(&decision, false));
    };
    let (decision, trust, enforced) =
        crate::panopticon_radius::decide_for_mac(&state.pool, &mac, Admission::Authenticated).await;
    tracing::info!(
        identity = %identity,
        mac = %mac,
        trust = trust.map(|t| t.as_str()).unwrap_or("unknown/none"),
        enforced = enforced.map(|k| k.as_str()).unwrap_or("none"),
        decision = ?decision,
        "FreeRADIUS 802.1X decision"
    );
    json_response(StatusCode::OK, decision_reply(&decision, false))
}

#[derive(Deserialize)]
pub struct AccountingQuery {
    /// The packet's source address (`%{Packet-Src-IP-Address}`), for a NAS
    /// that doesn't send NAS-IP-Address.
    #[serde(default)]
    src: Option<String>,
}

/// `accounting`: records the session the way the embedded server does.
pub async fn accounting(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<AccountingQuery>,
    body: Bytes,
) -> Response {
    if let Err(status) = gate(peer, &headers) {
        return status.into_response();
    }
    let Some(attrs) = Attrs::parse(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let username = attrs.get("User-Name");
    let mac = attrs.mac("Calling-Station-Id");
    let nas_ip = attrs
        .get("NAS-IP-Address")
        .or(q.src)
        .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok());
    let nas_port = attrs
        .get("NAS-Port-Id")
        .or_else(|| attrs.get("Called-Station-Id"));
    let framed_ip = attrs.get("Framed-IP-Address");
    let acct_session_id = attrs.get("Acct-Session-Id");
    // rlm_rest sends enumerated values by name ("Stop"), or by number.
    let status = attrs.get("Acct-Status-Type");
    let is_stop = matches!(status.as_deref(), Some("Stop" | "2"));
    let terminate_cause = attrs.get("Acct-Terminate-Cause");
    // MAB sessions are named by the device's own MAC; anything else came
    // through 802.1X.
    let method = if mac.is_some() && attrs.mac("User-Name") == mac {
        "mab"
    } else {
        "802.1X"
    };
    let update = repo::panopticon_radius::SessionUpdate {
        username: username.as_deref(),
        mac_address: mac.as_deref(),
        nas_ip: nas_ip.as_deref(),
        nas_port: nas_port.as_deref(),
        framed_ip: framed_ip.as_deref(),
        acct_session_id: acct_session_id.as_deref(),
        auth_method: Some(method),
        stop: is_stop,
        terminate_cause: terminate_cause.as_deref(),
    };
    if let Err(e) = repo::panopticon_radius::upsert_session(&state.pool, &update).await {
        tracing::warn!(error = %e, "FreeRADIUS accounting: failed to record the session");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub struct ClientQuery {
    ip: String,
}

/// Dynamic clients: the NAS client for a source address, as FreeRADIUS
/// control attributes, or 404 (FreeRADIUS then ignores the packet, as the
/// embedded server does for an unknown NAS).
pub async fn client(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<ClientQuery>,
) -> Response {
    if let Err(status) = gate(peer, &headers) {
        return status.into_response();
    }
    let Ok(ip) = q.ip.trim().parse::<std::net::IpAddr>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(key) = &state.encryption_key else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some((client, secret)) = crate::panopticon_radius::client_for(&state.pool, key, ip).await
    else {
        tracing::debug!(%ip, "FreeRADIUS dynamic client: no NAS client matches");
        return StatusCode::NOT_FOUND.into_response();
    };
    json_response(
        StatusCode::OK,
        json!({
            "control:FreeRADIUS-Client-IP-Address": lit(ip.to_string()),
            "control:FreeRADIUS-Client-Secret": lit(secret.as_str()),
            "control:FreeRADIUS-Client-Shortname": lit(client.name),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn basic(user_pass: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let v = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(user_pass)
        );
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(&v).unwrap());
        h
    }

    #[test]
    fn only_loopback_with_the_token_is_authorized() {
        let lo: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let lo6: SocketAddr = "[::1]:40000".parse().unwrap();
        let lan: SocketAddr = "172.18.0.5:40000".parse().unwrap();
        let good = basic(&format!("freeradius:{TOKEN}"));
        assert!(authorized(TOKEN, lo, &good));
        assert!(authorized(TOKEN, lo6, &good));
        // Caddy and everything else reach the app from another address.
        assert!(!authorized(TOKEN, lan, &good));
        assert!(!authorized(TOKEN, lo, &basic("freeradius:wrong")));
        assert!(!authorized(TOKEN, lo, &basic(&format!("admin:{TOKEN}"))));
        assert!(!authorized(TOKEN, lo, &HeaderMap::new()));
        let mut bearer = HeaderMap::new();
        bearer.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap(),
        );
        assert!(!authorized(TOKEN, lo, &bearer));
    }

    /// The body `rlm_rest` sends with `body = 'json'` (captured from
    /// FreeRADIUS 3.2.7 by `deploy/freeradius/test`).
    const RLM_REST_BODY: &str = r#"{
        "User-Name":{"type":"string","value":["AA-BB-CC-DD-EE-FF"]},
        "NAS-IP-Address":{"type":"ipaddr","value":["10.0.0.2"]},
        "NAS-Port":{"type":"integer","value":[50105]},
        "Calling-Station-Id":{"type":"string","value":["aa:bb:cc:dd:ee:ff"]},
        "Acct-Status-Type":{"type":"integer","value":["Stop"]}
    }"#;

    #[test]
    fn reads_rlm_rest_attributes() {
        let a = Attrs::parse(RLM_REST_BODY.as_bytes()).unwrap();
        assert_eq!(a.get("user-name").as_deref(), Some("AA-BB-CC-DD-EE-FF"));
        assert_eq!(a.mac("User-Name").as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(a.get("NAS-Port").as_deref(), Some("50105"));
        assert_eq!(a.get("Acct-Status-Type").as_deref(), Some("Stop"));
        assert!(!a.has("EAP-Message"));
        assert!(Attrs::parse(b"[1,2]").is_none());
        assert!(Attrs::parse(b"not json").is_none());
    }

    #[test]
    fn replies_use_rlm_rest_names() {
        // The exact JSON deploy/freeradius/test/fake_api.py returns, which
        // that test runs through FreeRADIUS 3.2.7.
        let l = |v: &str| json!({"value": v, "do_xlat": false});
        assert_eq!(
            decision_reply(&Decision::Accept(Some(10)), true),
            json!({
                "control:Auth-Type": l("Accept"),
                "reply:Tunnel-Type": l("VLAN"),
                "reply:Tunnel-Medium-Type": l("IEEE-802"),
                "reply:Tunnel-Private-Group-Id": l("10"),
            })
        );
        assert_eq!(decision_reply(&Decision::Accept(None), false), json!({}));
        assert_eq!(
            decision_reply(&Decision::Reject, true),
            json!({"control:Auth-Type": l("Reject")})
        );
        assert_eq!(
            decision_reply(&Decision::Reject, false),
            json!({"control:Tmp-String-0": l("reject")})
        );
        assert_eq!(reject_reply(true, "no")["reply:Reply-Message"], l("no"));
    }
}
