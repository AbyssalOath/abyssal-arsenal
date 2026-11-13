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
//! - `GET  /internal/radius/group-names` -- the groups the AD group rules
//!   name (0.2.8 P1), which FreeRADIUS checks a PEAP login's membership of.
//! - `POST /internal/radius/post-auth` -- after a successful EAP
//!   authentication: the device's admission decision (its VLAN, quarantine,
//!   or a reject) by its MAC, with the VLAN of the login's first matching
//!   AD group rule where the device is admitted.
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
    Query(q): Query<AccountingQuery>,
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
    let nas = nas_client(&state, &q, &attrs).await;
    let d =
        crate::panopticon_radius::decide_for_mac(&state.pool, &mac, Admission::Mab, nas.as_ref())
            .await;
    record(
        &state,
        &d,
        Admission::Mab,
        &mac,
        attrs.get("User-Name"),
        nas.as_ref(),
        &q,
        &attrs,
    );
    tracing::info!(
        mac = %mac,
        nas = nas.as_ref().map_or("unknown", |c| c.name.as_str()),
        trust = d.trust.map(|t| t.as_str()).unwrap_or("unknown/none"),
        enforced = d.enforced.map(|k| k.as_str()).unwrap_or("none"),
        signal = %d.signal_label(),
        reason = %d.reason,
        decision = ?d.decision,
        role = sent_role(&d, nas.as_ref()).unwrap_or("none"),
        session_timeout = d.session_timeout.unwrap_or(0),
        "FreeRADIUS MAB decision"
    );
    json_response(StatusCode::OK, admission_reply(&d, nas.as_ref(), true))
}

/// `post-auth` after a successful EAP authentication: the device's
/// admission by its MAC.
pub async fn post_auth(
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
    let identity = attrs.get("User-Name").unwrap_or_default();
    // PEAP against AD: the login's AD groups that have a group rule
    // (0.2.8 P1), looked up inside the tunnel by deploy/freeradius. An
    // internal attribute, so neither a NAS nor a client can supply it.
    let groups = attrs
        .get(AD_GROUPS_ATTR)
        .map(|g| abyssal_core::split_group_list(&g))
        .unwrap_or_default();
    let Some(mac) = attrs.mac("Calling-Station-Id") else {
        // No MAC, no device to decide for: admit as an unknown device would
        // be, under the configured policy.
        let nas = nas_client(&state, &q, &attrs).await;
        let d = crate::panopticon_radius::decide_for_mac(
            &state.pool,
            "",
            Admission::Authenticated,
            nas.as_ref(),
        )
        .await;
        record(
            &state,
            &d,
            Admission::Authenticated,
            "",
            Some(identity.clone()),
            nas.as_ref(),
            &q,
            &attrs,
        );
        return json_response(StatusCode::OK, admission_reply(&d, nas.as_ref(), false));
    };
    let nas = nas_client(&state, &q, &attrs).await;
    let d = crate::panopticon_radius::decide_for_login(
        &state.pool,
        &mac,
        Admission::Authenticated,
        nas.as_ref(),
        &groups,
    )
    .await;
    record(
        &state,
        &d,
        Admission::Authenticated,
        &mac,
        Some(identity.clone()),
        nas.as_ref(),
        &q,
        &attrs,
    );
    tracing::info!(
        identity = %identity,
        mac = %mac,
        nas = nas.as_ref().map_or("unknown", |c| c.name.as_str()),
        groups = %groups.join(";"),
        group_rule = d
            .group_rule
            .as_ref()
            .map(|r| {
                format!(
                    "{} -> VLAN {} role {}",
                    r.group_name,
                    r.vlan,
                    r.role.as_deref().unwrap_or("-")
                )
            })
            .unwrap_or_else(|| "none".into()),
        trust = d.trust.map(|t| t.as_str()).unwrap_or("unknown/none"),
        enforced = d.enforced.map(|k| k.as_str()).unwrap_or("none"),
        signal = %d.signal_label(),
        reason = %d.reason,
        decision = ?d.decision,
        role = sent_role(&d, nas.as_ref()).unwrap_or("none"),
        session_timeout = d.session_timeout.unwrap_or(0),
        "FreeRADIUS 802.1X decision"
    );
    json_response(StatusCode::OK, admission_reply(&d, nas.as_ref(), false))
}

/// The NAS client a request came from: by the packet's source address
/// (`?src=%{Packet-Src-IP-Address}`), else its NAS-IP-Address. `None` when
/// neither matches an enabled client; then no role is sent, and quarantine
/// can't fall back to a role (0.2.8 P2).
async fn nas_client(
    state: &AppState,
    q: &AccountingQuery,
    attrs: &Attrs,
) -> Option<abyssal_core::RadiusClient> {
    for candidate in [q.src.clone(), attrs.get("NAS-IP-Address")] {
        if let Some(ip) = candidate.and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
            && let Some(c) = crate::panopticon_radius::client_by_ip(&state.pool, ip).await
        {
            return Some(c);
        }
    }
    None
}

/// Records a FreeRADIUS decision (0.2.9 Q2). The NAS address is the one
/// accounting records sessions under (NAS-IP-Address, else the packet's
/// source), so a session finds its decision.
#[allow(clippy::too_many_arguments)]
fn record(
    state: &AppState,
    d: &crate::panopticon_radius::LoginDecision,
    admission: Admission,
    mac: &str,
    identity: Option<String>,
    nas: Option<&abyssal_core::RadiusClient>,
    q: &AccountingQuery,
    attrs: &Attrs,
) {
    use crate::panopticon_radius::{DecisionContext, FrontEnd};
    crate::panopticon_radius::record(
        &state.pool,
        d,
        DecisionContext {
            front_end: FrontEnd::FreeRadius,
            admission,
            mac,
            identity: identity.as_deref(),
            nas,
            nas_address: attrs
                .get("NAS-IP-Address")
                .or_else(|| q.src.clone())
                .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok()),
        },
    );
}

/// The role actually sent: only on an Accept, to a NAS that applies roles.
fn sent_role<'a>(
    d: &'a crate::panopticon_radius::LoginDecision,
    nas: Option<&abyssal_core::RadiusClient>,
) -> Option<&'a str> {
    match (&d.decision, nas) {
        (Decision::Accept(_), Some(c)) if c.role_attribute.sends_roles() => d.role.as_deref(),
        _ => None,
    }
}

/// [`decision_reply`] plus the role attribute for this NAS (0.2.8 P2).
fn admission_reply(
    d: &crate::panopticon_radius::LoginDecision,
    nas: Option<&abyssal_core::RadiusClient>,
    accept_auth_type: bool,
) -> Value {
    let mut v = decision_reply(&d.decision, accept_auth_type);
    if let (Some(role), Some(nas), Value::Object(o)) = (sent_role(d, nas), nas, &mut v) {
        insert_role(o, nas.role_attribute, role);
    }
    if let (Some(secs), Value::Object(o)) = (d.session_timeout, &mut v) {
        insert_session_timeout(o, secs);
    }
    v
}

/// Session-Timeout and Termination-Action = RADIUS-Request (0.2.8 P4), so
/// the NAS re-authenticates at the timeout without dropping the link.
fn insert_session_timeout(out: &mut Map<String, Value>, secs: u32) {
    out.insert("reply:Session-Timeout".into(), lit(secs.to_string()));
    out.insert("reply:Termination-Action".into(), lit("RADIUS-Request"));
}

/// The `rlm_rest` name of a role attribute, and the role (literal).
fn insert_role(out: &mut Map<String, Value>, kind: abyssal_core::RoleAttribute, role: &str) {
    use abyssal_core::RoleAttribute;
    let name = match kind {
        RoleAttribute::None => return,
        RoleAttribute::FilterId => "reply:Filter-Id",
        RoleAttribute::ArubaUserRole => "reply:Aruba-User-Role",
    };
    out.insert(name.into(), lit(role));
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

/// The AD groups of a PEAP login that have a group rule, `;`-separated
/// (`deploy/freeradius/image/dictionary.abyssal`).
const AD_GROUPS_ATTR: &str = "Abyssal-AD-Groups";
/// What `group-names` answers with: the rule groups FreeRADIUS checks a
/// login's membership of.
const AD_GROUP_CANDIDATES_ATTR: &str = "control:Abyssal-AD-Group-Candidates";
/// FreeRADIUS expands each command-line argument of the group helper into a
/// 2048-byte buffer (`deploy/freeradius/README.md`); stay clear of it.
pub(crate) const GROUP_CANDIDATES_MAX_LEN: usize = 1900;

/// Joins the distinct rule groups (case-insensitively, first spelling wins)
/// into the candidate list, in rule order, stopping before
/// [`GROUP_CANDIDATES_MAX_LEN`]. Returns the list and whether any group
/// didn't fit.
pub(crate) fn group_candidates(rules: &[abyssal_core::RadiusGroupRule]) -> (String, bool) {
    let mut seen = std::collections::HashSet::new();
    let mut out = String::new();
    let mut truncated = false;
    for r in rules {
        if !seen.insert(r.group_name.to_lowercase()) {
            continue;
        }
        let extra = r.group_name.len() + usize::from(!out.is_empty());
        if out.len() + extra > GROUP_CANDIDATES_MAX_LEN {
            truncated = true;
            continue;
        }
        if !out.is_empty() {
            out.push(abyssal_core::GROUP_LIST_SEPARATOR);
        }
        out.push_str(&r.group_name);
    }
    (out, truncated)
}

/// `GET /internal/radius/group-names`: the groups the AD group rules name,
/// for FreeRADIUS to check a PEAP login's membership against (0.2.8 P1). No
/// rules: an empty reply, and FreeRADIUS skips the lookup.
pub async fn group_names(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = gate(peer, &headers) {
        return status.into_response();
    }
    let rules = match repo::panopticon_radius::list_group_rules(&state.pool).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "FreeRADIUS API: couldn't read the RADIUS group rules");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let (candidates, truncated) = group_candidates(&rules);
    if truncated {
        tracing::warn!(
            "RADIUS group rules name more groups than fit in one lookup \
             ({GROUP_CANDIDATES_MAX_LEN} characters); the later rules' groups are skipped"
        );
    }
    if candidates.is_empty() {
        return json_response(StatusCode::OK, json!({}));
    }
    json_response(
        StatusCode::OK,
        json!({ AD_GROUP_CANDIDATES_ATTR: lit(candidates) }),
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
    fn group_candidates_are_distinct_ordered_and_bounded() {
        let rule = |g: &str| abyssal_core::RadiusGroupRule {
            id: uuid::Uuid::new_v4(),
            group_name: g.into(),
            vlan: 10,
            role: None,
            position: 0,
            created_at: Utc::now(),
        };
        let rules = vec![rule("CORP\\Staff"), rule("Finance"), rule("corp\\staff")];
        assert_eq!(
            group_candidates(&rules),
            ("CORP\\Staff;Finance".into(), false)
        );
        assert_eq!(group_candidates(&[]), (String::new(), false));
        let long: Vec<_> = (0..20)
            .map(|i| rule(&format!("{i:02}{}", "x".repeat(198))))
            .collect();
        let (c, truncated) = group_candidates(&long);
        assert!(truncated);
        assert!(c.len() <= GROUP_CANDIDATES_MAX_LEN);
        assert_eq!(c.split(';').count(), 9);
    }

    #[test]
    fn reads_ad_groups_from_post_auth() {
        let body = r#"{"Calling-Station-Id":{"type":"string","value":["aa:bb:cc:dd:ee:ff"]},
            "Abyssal-AD-Groups":{"type":"string","value":["TEST\\WiFi-Users;Staff"]}}"#;
        let a = Attrs::parse(body.as_bytes()).unwrap();
        assert_eq!(
            abyssal_core::split_group_list(&a.get(AD_GROUPS_ATTR).unwrap()),
            vec!["TEST\\WiFi-Users".to_string(), "Staff".to_string()]
        );
    }

    #[test]
    fn roles_use_rlm_rest_names() {
        use abyssal_core::RoleAttribute;
        let l = |v: &str| json!({"value": v, "do_xlat": false});
        let mut m = Map::new();
        insert_role(&mut m, RoleAttribute::FilterId, "QUARANTINE.in");
        insert_role(&mut m, RoleAttribute::ArubaUserRole, "guest");
        insert_role(&mut m, RoleAttribute::None, "ignored");
        assert_eq!(
            Value::Object(m),
            json!({"reply:Filter-Id": l("QUARANTINE.in"), "reply:Aruba-User-Role": l("guest")})
        );
    }

    #[test]
    fn session_timeout_uses_rlm_rest_names() {
        let l = |v: &str| json!({"value": v, "do_xlat": false});
        let mut m = Map::new();
        insert_session_timeout(&mut m, 900);
        assert_eq!(
            Value::Object(m),
            json!({"reply:Session-Timeout": l("900"), "reply:Termination-Action": l("RADIUS-Request")})
        );
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
