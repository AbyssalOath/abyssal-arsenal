//! Panopticon's embedded RADIUS server (NAC phase 5): MAC Auth Bypass with
//! dynamic VLAN assignment, plus accounting ingest for the "who authenticated
//! where" identity. It makes Panopticon the access-control decision point --
//! switches/APs point their 802.1X/MAB RADIUS config at it, and the device's
//! `TrustState` (plus a small policy of settings) decides accept / reject /
//! quarantine-VLAN.
//!
//! Scope: MAB (MAC-based) only. There is no RADIUS user credential store, so
//! the server cannot verify a password -- a request carrying User-Password,
//! CHAP-Password, or EAP-Message is *rejected* rather than silently authorized
//! on its MAC (authorizing a credentialed request without checking the
//! credential would be an authentication bypass). Real user auth (PAP against a
//! credential store, or EAP-TLS/PEAP) belongs with a dedicated stack like
//! FreeRADIUS. The wire codec lives in `crate::radius`.

use std::net::IpAddr;
use std::sync::Arc;

use abyssal_core::settings::{
    PANOPTICON_QUARANTINE_VLAN, PANOPTICON_QUARANTINE_VLAN_DEFAULT, PANOPTICON_RADIUS_ACCT_PORT,
    PANOPTICON_RADIUS_ACCT_PORT_DEFAULT, PANOPTICON_RADIUS_AUTH_PORT,
    PANOPTICON_RADIUS_AUTH_PORT_DEFAULT, PANOPTICON_RADIUS_GUEST_VLAN,
    PANOPTICON_RADIUS_GUEST_VLAN_DEFAULT, PANOPTICON_RADIUS_TRUSTED_VLAN,
    PANOPTICON_RADIUS_TRUSTED_VLAN_DEFAULT, PANOPTICON_RADIUS_UNKNOWN_ACTION,
    PANOPTICON_RADIUS_UNTRUSTED_ACTION,
};
use abyssal_core::{EncryptionKey, RadiusClient, TrustState, network_of, parse_cidr};
use abyssal_database::{DbPool, repo};

use crate::radius::{self, Packet};

const MAX_PACKET: usize = 4096;

/// Per-trust-state admission policy, read from settings once per packet (cheap).
struct RadiusPolicy {
    trusted_vlan: u32,
    quarantine_vlan: u32,
    /// "quarantine" | "reject"
    untrusted_action: String,
    /// "accept" | "guest" | "reject"
    unknown_action: String,
    guest_vlan: u32,
}

/// The MAB authorization outcome.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Access-Accept, optionally with a VLAN assignment.
    Accept(Option<u32>),
    /// Access-Reject.
    Reject,
}

/// The core MAB decision: maps a device's trust state (or its absence) to an
/// admission outcome under the configured policy. Pure and table-tested.
fn decide(trust: Option<TrustState>, p: &RadiusPolicy) -> Decision {
    match trust {
        Some(TrustState::Trusted) => {
            Decision::Accept((p.trusted_vlan > 0).then_some(p.trusted_vlan))
        }
        Some(TrustState::Untrusted) => match p.untrusted_action.as_str() {
            "reject" => Decision::Reject,
            // "quarantine": isolate onto the quarantine VLAN. With no quarantine
            // VLAN configured there's no way to isolate, so fail closed.
            _ => {
                if p.quarantine_vlan > 0 {
                    Decision::Accept(Some(p.quarantine_vlan))
                } else {
                    Decision::Reject
                }
            }
        },
        // Unknown trust, or a device not in inventory at all.
        _ => match p.unknown_action.as_str() {
            "reject" => Decision::Reject,
            "guest" => Decision::Accept((p.guest_vlan > 0).then_some(p.guest_vlan)),
            // "accept" (the safe default): admit with no VLAN assignment.
            _ => Decision::Accept(None),
        },
    }
}

/// Normalizes a MAC from whatever punctuation a NAS used (`aa-bb-..`,
/// `aabb.ccdd.eeff`, `AABBCCDDEEFF`, `aa:bb:..`) to lowercase colon form, or
/// `None` if it isn't 12 hex digits.
fn normalize_mac(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    let pairs: Vec<&str> = (0..12).step_by(2).map(|i| &hex[i..i + 2]).collect();
    Some(pairs.join(":"))
}

/// Outcome of resolving the MAC a MAB request authenticates as.
#[derive(Debug, PartialEq, Eq)]
enum MacResolution {
    /// A single, consistent MAC to authorize.
    Resolved(String),
    /// User-Name and Calling-Station-Id are both MACs but disagree -- a request
    /// trying to assert a different identity than its observed source MAC.
    Conflict,
    /// No MAC present at all -- nothing to MAB-authorize.
    Missing,
}

/// Resolves the MAB MAC from the (already normalized) Calling-Station-Id and
/// User-Name values. Calling-Station-Id (the switch-observed source MAC) is the
/// anchor; a User-Name MAC, if present, must match it.
fn resolve_mab_mac(calling: Option<String>, username_mac: Option<String>) -> MacResolution {
    match (calling, username_mac) {
        (Some(c), Some(u)) => {
            if c == u {
                MacResolution::Resolved(c)
            } else {
                MacResolution::Conflict
            }
        }
        (Some(c), None) => MacResolution::Resolved(c),
        (None, Some(u)) => MacResolution::Resolved(u),
        (None, None) => MacResolution::Missing,
    }
}

/// Whether a RADIUS client entry (bare IP or CIDR) matches a source address.
fn client_matches(nas_address: &str, src: IpAddr) -> bool {
    let nas_address = nas_address.trim();
    if let Some((net_addr, prefix)) = parse_cidr(nas_address) {
        let src_net = network_of(&src.to_string(), prefix, prefix);
        let cidr_net = network_of(&net_addr.to_string(), prefix, prefix);
        src_net.is_some() && src_net == cidr_net
    } else {
        nas_address == src.to_string()
    }
}

/// Finds the enabled RADIUS client matching a source address and returns its
/// decrypted shared secret, or `None` if no client matches / decryption fails.
async fn secret_for(
    pool: &DbPool,
    key: &EncryptionKey,
    src: IpAddr,
) -> Option<(RadiusClient, zeroize::Zeroizing<String>)> {
    let clients = repo::panopticon_radius::list_enabled_clients(pool)
        .await
        .ok()?;
    let client = clients
        .into_iter()
        .find(|c| client_matches(&c.nas_address, src))?;
    match key.decrypt(&client.shared_secret_encrypted) {
        Ok(secret) => Some((client, secret)),
        Err(e) => {
            tracing::warn!(error = %e, client = %client.name, "RADIUS: failed to decrypt client secret");
            None
        }
    }
}

async fn load_policy(pool: &DbPool) -> RadiusPolicy {
    let g = |k: &'static str, d: u32| {
        let pool = pool.clone();
        async move { repo::settings::get_u32(&pool, k, d).await.unwrap_or(d) }
    };
    RadiusPolicy {
        trusted_vlan: g(
            PANOPTICON_RADIUS_TRUSTED_VLAN,
            PANOPTICON_RADIUS_TRUSTED_VLAN_DEFAULT,
        )
        .await,
        quarantine_vlan: g(
            PANOPTICON_QUARANTINE_VLAN,
            PANOPTICON_QUARANTINE_VLAN_DEFAULT,
        )
        .await,
        untrusted_action: repo::settings::get_string(
            pool,
            PANOPTICON_RADIUS_UNTRUSTED_ACTION,
            "quarantine",
        )
        .await
        .unwrap_or_else(|_| "quarantine".to_string()),
        unknown_action: repo::settings::get_string(
            pool,
            PANOPTICON_RADIUS_UNKNOWN_ACTION,
            "accept",
        )
        .await
        .unwrap_or_else(|_| "accept".to_string()),
        guest_vlan: g(
            PANOPTICON_RADIUS_GUEST_VLAN,
            PANOPTICON_RADIUS_GUEST_VLAN_DEFAULT,
        )
        .await,
    }
}

/// Handles one Access-Request datagram, returning the response bytes to send
/// back (or `None` to silently drop -- unknown NAS, bad secret, parse failure).
async fn handle_auth(
    pool: &DbPool,
    key: &EncryptionKey,
    src: IpAddr,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let packet = Packet::parse(buf)?;
    if packet.code != radius::CODE_ACCESS_REQUEST {
        return None;
    }
    let (client, secret) = secret_for(pool, key, src).await?;
    let secret = secret.as_bytes();

    // Integrity: if the request carries a Message-Authenticator it must validate.
    if !packet.verify_message_authenticator(secret) {
        tracing::warn!(client = %client.name, "RADIUS: Access-Request Message-Authenticator mismatch (wrong shared secret?)");
        return None;
    }

    let include_msg_auth = packet.has(radius::ATTR_MESSAGE_AUTHENTICATOR);

    let reject = |reason: &str| {
        tracing::debug!(client = %client.name, reason, "RADIUS: Access-Reject");
        Some(radius::build_response(
            radius::CODE_ACCESS_REJECT,
            packet.id,
            &packet.authenticator,
            &[],
            secret,
            include_msg_auth,
        ))
    };

    // We don't speak EAP -- reject a real 802.1X supplicant so it can fall back
    // to MAB or a guest flow rather than hanging.
    if packet.has(radius::ATTR_EAP_MESSAGE) {
        return reject("EAP request (MAB only)");
    }

    // This server authenticates by MAC (MAB) only -- there is no RADIUS user
    // credential store, so it cannot verify a password. A request carrying
    // User-Password or CHAP-Password is a real credentialed auth attempt;
    // authorizing it on MAC alone would be an authentication bypass (the
    // credential would be silently ignored). Reject it rather than MAB-accept.
    if packet.has(radius::ATTR_USER_PASSWORD) || packet.has(radius::ATTR_CHAP_PASSWORD) {
        return reject("password-bearing request (PAP/CHAP not supported; MAB only)");
    }

    // Resolve the MAB MAC. The switch-observed source MAC (Calling-Station-Id)
    // is the identity anchor; if User-Name is also a MAC it must agree, so a
    // request can't assert one MAC as its source and a different (trusted) MAC
    // as its name. A request with no identifiable MAC can't be MAB-authorized
    // and is rejected rather than falling through to the "unknown" default.
    let calling = packet
        .get_string(radius::ATTR_CALLING_STATION_ID)
        .and_then(|s| normalize_mac(&s));
    let username_mac = packet
        .get_string(radius::ATTR_USER_NAME)
        .and_then(|s| normalize_mac(&s));
    let mac = match resolve_mab_mac(calling, username_mac) {
        MacResolution::Resolved(m) => m,
        MacResolution::Conflict => {
            return reject("User-Name MAC disagrees with Calling-Station-Id");
        }
        MacResolution::Missing => return reject("no MAC to authorize (MAB only)"),
    };

    let trust = repo::network_devices::find_by_mac(pool, &mac)
        .await
        .ok()
        .flatten()
        .map(|d| d.trust_state);

    let policy = load_policy(pool).await;
    let decision = decide(trust, &policy);

    let (code, attrs) = match &decision {
        Decision::Accept(vlan) => {
            let attrs = vlan.map(radius::vlan_attributes).unwrap_or_default();
            (radius::CODE_ACCESS_ACCEPT, attrs)
        }
        Decision::Reject => (radius::CODE_ACCESS_REJECT, Vec::new()),
    };
    tracing::info!(
        client = %client.name,
        mac = %mac,
        trust = trust.map(|t| t.as_str()).unwrap_or("unknown/none"),
        decision = ?decision,
        "RADIUS MAB decision"
    );
    Some(radius::build_response(
        code,
        packet.id,
        &packet.authenticator,
        &attrs,
        secret,
        include_msg_auth,
    ))
}

/// Handles one Accounting-Request datagram: verifies it, records/updates the
/// session, and returns the Accounting-Response bytes.
async fn handle_acct(
    pool: &DbPool,
    key: &EncryptionKey,
    src: IpAddr,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let packet = Packet::parse(buf)?;
    if packet.code != radius::CODE_ACCOUNTING_REQUEST {
        return None;
    }
    let (client, secret) = secret_for(pool, key, src).await?;
    let secret = secret.as_bytes();

    if !packet.verify_accounting_authenticator(secret) {
        tracing::warn!(client = %client.name, "RADIUS: Accounting-Request authenticator mismatch (wrong shared secret?)");
        return None;
    }

    let status = packet.get_u32(radius::ATTR_ACCT_STATUS_TYPE);
    let is_stop = status == Some(radius::ACCT_STATUS_STOP);
    let mac = packet
        .get_string(radius::ATTR_CALLING_STATION_ID)
        .and_then(|s| normalize_mac(&s));
    let nas_ip = packet
        .get_ipv4(radius::ATTR_NAS_IP_ADDRESS)
        .unwrap_or_else(|| src.to_string());
    let nas_port = packet
        .get_string(radius::ATTR_NAS_PORT_ID)
        .or_else(|| packet.get_string(radius::ATTR_CALLED_STATION_ID));
    let username = packet.get_string(radius::ATTR_USER_NAME);
    let framed_ip = packet.get_ipv4(radius::ATTR_FRAMED_IP_ADDRESS);
    let acct_session_id = packet.get_string(radius::ATTR_ACCT_SESSION_ID);
    let terminate_cause = packet
        .get_u32(radius::ATTR_ACCT_TERMINATE_CAUSE)
        .map(|c| c.to_string());

    let update = repo::panopticon_radius::SessionUpdate {
        username: username.as_deref(),
        mac_address: mac.as_deref(),
        nas_ip: Some(nas_ip.as_str()),
        nas_port: nas_port.as_deref(),
        framed_ip: framed_ip.as_deref(),
        acct_session_id: acct_session_id.as_deref(),
        auth_method: Some("accounting"),
        stop: is_stop,
        terminate_cause: terminate_cause.as_deref(),
    };
    if let Err(e) = repo::panopticon_radius::upsert_session(pool, &update).await {
        tracing::warn!(error = %e, "RADIUS: failed to record accounting session");
    }

    // Accounting-Response carries no attributes; just a signed acknowledgement.
    Some(radius::build_response(
        radius::CODE_ACCOUNTING_RESPONSE,
        packet.id,
        &packet.authenticator,
        &[],
        secret,
        false,
    ))
}

/// Spawns the RADIUS auth (1812) and accounting (1813) listeners if enabled.
/// No-ops when disabled or when no `ENCRYPTION_KEY` is configured (client shared
/// secrets are stored encrypted and couldn't be decrypted without it).
pub async fn spawn_panopticon_radius(pool: DbPool, encryption_key: Option<Arc<EncryptionKey>>) {
    let enabled = repo::settings::get_bool(
        &pool,
        abyssal_core::settings::PANOPTICON_RADIUS_ENABLED,
        false,
    )
    .await
    .unwrap_or(false);
    if !enabled {
        return;
    }
    let Some(key) = encryption_key else {
        tracing::warn!("Panopticon RADIUS is enabled but ENCRYPTION_KEY isn't set; not starting");
        return;
    };
    let auth_port = repo::settings::get_u32(
        &pool,
        PANOPTICON_RADIUS_AUTH_PORT,
        PANOPTICON_RADIUS_AUTH_PORT_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_RADIUS_AUTH_PORT_DEFAULT) as u16;
    let acct_port = repo::settings::get_u32(
        &pool,
        PANOPTICON_RADIUS_ACCT_PORT,
        PANOPTICON_RADIUS_ACCT_PORT_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_RADIUS_ACCT_PORT_DEFAULT) as u16;

    spawn_listener(pool.clone(), key.clone(), auth_port, Handler::Auth);
    spawn_listener(pool, key, acct_port, Handler::Acct);
}

#[derive(Clone, Copy)]
enum Handler {
    Auth,
    Acct,
}

fn spawn_listener(pool: DbPool, key: Arc<EncryptionKey>, port: u16, handler: Handler) {
    tokio::spawn(async move {
        let socket = match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, port, "Panopticon RADIUS listener failed to bind");
                return;
            }
        };
        let kind = match handler {
            Handler::Auth => "auth",
            Handler::Acct => "accounting",
        };
        tracing::info!(port, kind, "Panopticon RADIUS listener started");
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, kind, "RADIUS recv error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let datagram = buf[..n].to_vec();
            let pool = pool.clone();
            let key = key.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                let response = match handler {
                    Handler::Auth => handle_auth(&pool, &key, src.ip(), &datagram).await,
                    Handler::Acct => handle_acct(&pool, &key, src.ip(), &datagram).await,
                };
                if let Some(bytes) = response
                    && let Err(e) = socket.send_to(&bytes, src).await
                {
                    tracing::warn!(error = %e, kind, "RADIUS failed to send response");
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RadiusPolicy {
        RadiusPolicy {
            trusted_vlan: 10,
            quarantine_vlan: 999,
            untrusted_action: "quarantine".into(),
            unknown_action: "accept".into(),
            guest_vlan: 50,
        }
    }

    #[test]
    fn trusted_device_is_accepted_with_its_vlan() {
        assert_eq!(
            decide(Some(TrustState::Trusted), &policy()),
            Decision::Accept(Some(10))
        );
    }

    #[test]
    fn untrusted_device_is_quarantined_or_rejected() {
        let mut p = policy();
        assert_eq!(
            decide(Some(TrustState::Untrusted), &p),
            Decision::Accept(Some(999))
        );
        p.untrusted_action = "reject".into();
        assert_eq!(decide(Some(TrustState::Untrusted), &p), Decision::Reject);
        // Quarantine with no VLAN configured fails closed.
        p.untrusted_action = "quarantine".into();
        p.quarantine_vlan = 0;
        assert_eq!(decide(Some(TrustState::Untrusted), &p), Decision::Reject);
    }

    #[test]
    fn unknown_device_follows_unknown_action() {
        let mut p = policy();
        // Default "accept" admits with no VLAN.
        assert_eq!(decide(None, &p), Decision::Accept(None));
        assert_eq!(
            decide(Some(TrustState::Unknown), &p),
            Decision::Accept(None)
        );
        p.unknown_action = "guest".into();
        assert_eq!(decide(None, &p), Decision::Accept(Some(50)));
        p.unknown_action = "reject".into();
        assert_eq!(decide(None, &p), Decision::Reject);
    }

    #[test]
    fn normalize_mac_handles_common_formats() {
        let want = Some("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(normalize_mac("aa-bb-cc-dd-ee-ff"), want);
        assert_eq!(normalize_mac("AABBCCDDEEFF"), want);
        assert_eq!(normalize_mac("aabb.ccdd.eeff"), want);
        assert_eq!(normalize_mac("AA:BB:CC:DD:EE:FF"), want);
        assert_eq!(normalize_mac("nope"), None);
    }

    #[test]
    fn resolve_mab_mac_requires_consistency() {
        let m = "aa:bb:cc:dd:ee:ff".to_string();
        let other = "11:22:33:44:55:66".to_string();
        // Calling-Station-Id alone, or agreeing User-Name, resolve.
        assert_eq!(
            resolve_mab_mac(Some(m.clone()), None),
            MacResolution::Resolved(m.clone())
        );
        assert_eq!(
            resolve_mab_mac(Some(m.clone()), Some(m.clone())),
            MacResolution::Resolved(m.clone())
        );
        // User-Name MAC disagreeing with the source MAC is a conflict.
        assert_eq!(
            resolve_mab_mac(Some(m.clone()), Some(other)),
            MacResolution::Conflict
        );
        // No MAC at all -> nothing to authorize.
        assert_eq!(resolve_mab_mac(None, None), MacResolution::Missing);
        // User-Name MAC only (no Calling-Station-Id) still resolves.
        assert_eq!(
            resolve_mab_mac(None, Some(m.clone())),
            MacResolution::Resolved(m)
        );
    }

    #[test]
    fn client_matches_ip_and_cidr() {
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        assert!(client_matches("10.0.0.7", ip));
        assert!(client_matches("10.0.0.0/24", ip));
        assert!(!client_matches("10.0.1.0/24", ip));
        assert!(!client_matches("10.0.0.8", ip));
    }
}
