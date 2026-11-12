//! RADIUS Change of Authorization (RFC 5176) for Panopticon's NAC, 0.2.7 N2
//! (`docs/roadmap/0.2.7.md`).
//!
//! Without this, a change to a RADIUS-admitted device -- its trust state, or a
//! quarantine on its port -- only takes effect when the device next
//! authenticates. This asks the NAS that accounted the device's session to
//! re-authorize it now, so the embedded server's next decision (which honors
//! trust *and* any enforcement in effect on the port) applies straight away.
//!
//! Per NAS client (`RadiusClient::coa_mode`): off, an RFC 5176
//! Disconnect-Request (the session ends; the device re-authenticates), or a
//! Cisco `subscriber:command=reauthenticate` CoA-Request (authorization re-runs
//! without dropping the link). Sessions come from accounting; a device the
//! NAS never accounted has no session to target.
//!
//! Every request is sent from an ephemeral UDP port to the session's NAS
//! (`nas_ip`, `coa_port`), signed with that NAS's shared secret, retried, and
//! its ACK/NAK verified against the request. The outcome is stored on the
//! session and audited.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{CoaMode, EncryptionKey, RadiusSession};
use abyssal_database::{DbPool, repo};
use rand::RngCore;
use rand::rngs::OsRng;
use uuid::Uuid;

use crate::radius::{self, Packet};

/// Sessions per MAC a single change re-authorizes (newest first). A NAS that
/// never sends accounting Stop leaves old sessions open.
const MAX_SESSIONS_PER_MAC: u32 = 5;
const ATTEMPTS: usize = 3;
const WAIT: Duration = Duration::from_secs(2);

/// What the NAS said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoaOutcome {
    Ack,
    /// With the RFC 5176 Error-Cause, if the NAS sent one.
    Nak(Option<u32>),
    NoResponse,
    Failed(String),
}

impl CoaOutcome {
    pub fn summary(&self) -> String {
        match self {
            CoaOutcome::Ack => "ACK".into(),
            CoaOutcome::Nak(Some(c)) => format!("NAK: {} ({c})", radius::error_cause_name(*c)),
            CoaOutcome::Nak(None) => "NAK".into(),
            CoaOutcome::NoResponse => "no response".into(),
            CoaOutcome::Failed(e) => format!("not sent: {e}"),
        }
    }

    /// Whether the session is over afterwards, and why: a Disconnect the NAS
    /// acknowledged ended it, and "no such session" means it already had.
    fn closes_session(&self, mode: CoaMode) -> Option<&'static str> {
        match (self, mode) {
            (CoaOutcome::Ack, CoaMode::Disconnect) => Some("Disconnected (CoA)"),
            (CoaOutcome::Nak(Some(radius::ERROR_CAUSE_SESSION_NOT_FOUND)), _) => {
                Some("Session not found on NAS (CoA)")
            }
            _ => None,
        }
    }
}

/// RADIUS attributes as (type, value) pairs.
type Attributes = Vec<(u8, Vec<u8>)>;

/// `aa:bb:..` as the IETF Calling-Station-Id form `AA-BB-..` (RFC 3580).
fn calling_station_id(mac: &str) -> String {
    mac.to_ascii_uppercase().replace(':', "-")
}

/// The request for a session under a NAS's mode: its code and attributes, or
/// `None` when the mode is off or nothing identifies the session.
///
/// The session is identified by NAS-IP-Address plus Acct-Session-Id, the
/// NAS's own handle for it. Only without one does Calling-Station-Id stand in:
/// RFC 5176 has the NAS NAK a request whose identifying attributes don't all
/// match, and NASes disagree on MAC formatting.
fn build_attributes(mode: CoaMode, session: &RadiusSession) -> Option<(u8, Attributes)> {
    let code = match mode {
        CoaMode::Off => return None,
        CoaMode::Disconnect => radius::CODE_DISCONNECT_REQUEST,
        CoaMode::CiscoReauth => radius::CODE_COA_REQUEST,
    };
    let mut attrs = Vec::new();
    if let Some(IpAddr::V4(v4)) = session.nas_ip.as_deref().and_then(|ip| ip.parse().ok()) {
        attrs.push((radius::ATTR_NAS_IP_ADDRESS, v4.octets().to_vec()));
    }
    match (&session.acct_session_id, &session.mac_address) {
        (Some(id), _) if !id.is_empty() => {
            attrs.push((radius::ATTR_ACCT_SESSION_ID, id.as_bytes().to_vec()))
        }
        (_, Some(mac)) => attrs.push((
            radius::ATTR_CALLING_STATION_ID,
            calling_station_id(mac).into_bytes(),
        )),
        _ => return None,
    }
    if mode == CoaMode::CiscoReauth {
        attrs.push(radius::cisco_avpair("subscriber:command=reauthenticate"));
    }
    Some((code, attrs))
}

/// Sends `request` to `dest` and waits for a verified ACK/NAK, retrying.
async fn exchange(dest: SocketAddr, request: &[u8], secret: &[u8]) -> CoaOutcome {
    let Some(req_auth) = Packet::authenticator_of(request) else {
        return CoaOutcome::Failed("malformed request".into());
    };
    let (code, id) = (request[0], request[1]);
    let (ack, nak) = if code == radius::CODE_DISCONNECT_REQUEST {
        (radius::CODE_DISCONNECT_ACK, radius::CODE_DISCONNECT_NAK)
    } else {
        (radius::CODE_COA_ACK, radius::CODE_COA_NAK)
    };
    let bind: SocketAddr = if dest.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid")
    } else {
        "[::]:0".parse().expect("valid")
    };
    let socket = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => return CoaOutcome::Failed(format!("can't open a UDP socket: {e}")),
    };
    if let Err(e) = socket.connect(dest).await {
        return CoaOutcome::Failed(format!("can't reach {dest}: {e}"));
    }
    let mut buf = vec![0u8; 4096];
    for _ in 0..ATTEMPTS {
        if let Err(e) = socket.send(request).await {
            return CoaOutcome::Failed(format!("send to {dest} failed: {e}"));
        }
        let deadline = tokio::time::Instant::now() + WAIT;
        // Anything that isn't a verified answer to this request is ignored
        // until the deadline: a stray or forged datagram can't decide it.
        while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
            let Some(reply) = Packet::parse(&buf[..n]) else {
                continue;
            };
            if reply.id != id || !reply.verify_response(&req_auth, secret) {
                continue;
            }
            if reply.code == ack {
                return CoaOutcome::Ack;
            }
            if reply.code == nak {
                return CoaOutcome::Nak(reply.get_u32(radius::ATTR_ERROR_CAUSE));
            }
        }
    }
    CoaOutcome::NoResponse
}

/// Who asked, for the audit record. `None` = the system (a trust change's
/// follow-up, the policy engine, the revert sweep).
pub type Requester = Option<(Uuid, String)>;

/// Re-authorizes one accounted session through its NAS. `None` when the NAS's
/// CoA mode is off (nothing is sent or recorded).
pub async fn reauthorize_session(
    pool: &DbPool,
    key: &EncryptionKey,
    session: &RadiusSession,
    why: &str,
    requester: &Requester,
) -> Option<CoaOutcome> {
    let nas: Option<IpAddr> = session.nas_ip.as_deref().and_then(|ip| ip.parse().ok());
    let client = match nas {
        Some(ip) => crate::panopticon_radius::client_for(pool, key, ip).await,
        None => None,
    };
    let (outcome, mode, nas_name) = match (nas, client) {
        (None, _) => (
            CoaOutcome::Failed("the session has no NAS address".into()),
            CoaMode::Off,
            String::new(),
        ),
        (Some(ip), None) => (
            CoaOutcome::Failed(format!("no enabled NAS client matches {ip}")),
            CoaMode::Off,
            ip.to_string(),
        ),
        (Some(ip), Some((client, secret))) => {
            let Some((code, attrs)) = build_attributes(client.coa_mode, session) else {
                if client.coa_mode == CoaMode::Off {
                    return None;
                }
                return Some(CoaOutcome::Failed(
                    "the session has neither an Acct-Session-Id nor a MAC".into(),
                ));
            };
            let mut id = [0u8; 1];
            OsRng.fill_bytes(&mut id);
            let request = radius::build_request(code, id[0], &attrs, secret.as_bytes());
            let dest = SocketAddr::new(ip, client.coa_port);
            (
                exchange(dest, &request, secret.as_bytes()).await,
                client.coa_mode,
                client.name,
            )
        }
    };

    let summary = outcome.summary();
    if let Err(e) = repo::panopticon_radius::record_coa_result(
        pool,
        session.id,
        &summary,
        outcome.closes_session(mode),
    )
    .await
    {
        tracing::warn!(error = %e, "RADIUS CoA: failed to record the result");
    }
    let mac = session.mac_address.clone().unwrap_or_default();
    tracing::info!(nas = %nas_name, mac = %mac, mode = mode.as_str(), result = %summary, why, "RADIUS re-authorization");

    let audit_outcome = if outcome == CoaOutcome::Ack {
        AuditOutcome::Success
    } else {
        AuditOutcome::Failure
    };
    let mut event = AuditEvent::new(AuditAction::NetworkRadiusReauthorized, audit_outcome)
        .resource(&mac)
        .metadata(serde_json::json!({
            "nas": nas_name,
            "nas_ip": session.nas_ip,
            "session": session.acct_session_id,
            "mode": mode.as_str(),
            "result": summary,
            "why": why,
        }));
    if let Some((user_id, username)) = requester {
        event = event.actor(Actor {
            user_id: *user_id,
            username,
        });
    }
    if let Err(e) = abyssal_audit::record(pool, event).await {
        tracing::warn!(error = %e, "RADIUS CoA: failed to audit");
    }
    Some(outcome)
}

/// Re-authorizes every open session of a MAC. Returns how many requests were
/// sent (NASes with CoA off don't count).
pub async fn reauthorize_mac(
    pool: &DbPool,
    key: &EncryptionKey,
    mac: &str,
    why: &str,
    requester: &Requester,
) -> usize {
    let sessions =
        match repo::panopticon_radius::open_sessions_for_mac(pool, mac, MAX_SESSIONS_PER_MAC).await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, mac, "RADIUS CoA: couldn't list sessions");
                return 0;
            }
        };
    let mut sent = 0;
    for session in &sessions {
        if reauthorize_session(pool, key, session, why, requester)
            .await
            .is_some()
        {
            sent += 1;
        }
    }
    sent
}

/// [`reauthorize_mac`] in the background, so the page or sweep that changed
/// the device doesn't wait on a NAS. A no-op without an encryption key (NAS
/// secrets can't be decrypted).
pub fn spawn_reauthorize_mac(
    pool: DbPool,
    key: Option<Arc<EncryptionKey>>,
    mac: String,
    why: String,
    requester: Requester,
) {
    let Some(key) = key else {
        return;
    };
    tokio::spawn(async move {
        reauthorize_mac(&pool, &key, &mac, &why, &requester).await;
    });
}

/// Re-authorizes the sessions of every device located on a switch port --
/// after a quarantine is applied to it or released, so RADIUS-assigned VLANs
/// follow the port's enforcement instead of overriding it.
pub fn spawn_reauthorize_port(
    pool: DbPool,
    key: Option<Arc<EncryptionKey>>,
    switch_id: Uuid,
    port_label: String,
    why: String,
) {
    let Some(key) = key else {
        return;
    };
    tokio::spawn(async move {
        let devices = match repo::network_devices::list_on_switch(&pool, switch_id).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "RADIUS CoA: couldn't list the port's devices");
                return;
            }
        };
        for mac in devices
            .into_iter()
            .filter(|d| d.switch_port == port_label)
            .filter_map(|d| d.mac_address)
        {
            reauthorize_mac(&pool, &key, &mac, &why, &None).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn session(acct: Option<&str>, mac: Option<&str>) -> RadiusSession {
        RadiusSession {
            id: Uuid::new_v4(),
            username: Some("aabbccddeeff".into()),
            mac_address: mac.map(str::to_string),
            nas_ip: Some("10.0.0.2".into()),
            nas_port: Some("Gi1/0/5".into()),
            framed_ip: None,
            acct_session_id: acct.map(str::to_string),
            auth_method: Some("accounting".into()),
            started_at: Utc::now(),
            last_seen_at: Utc::now(),
            stopped_at: None,
            terminate_cause: None,
            last_coa_at: None,
            last_coa_result: None,
        }
    }

    fn attr(attrs: &[(u8, Vec<u8>)], t: u8) -> Option<&[u8]> {
        attrs
            .iter()
            .find(|(k, _)| *k == t)
            .map(|(_, v)| v.as_slice())
    }

    #[test]
    fn off_sends_nothing() {
        assert!(build_attributes(CoaMode::Off, &session(Some("1"), None)).is_none());
    }

    #[test]
    fn disconnect_identifies_the_session_by_its_id() {
        let s = session(Some("0A00000F"), Some("aa:bb:cc:dd:ee:ff"));
        let (code, attrs) = build_attributes(CoaMode::Disconnect, &s).unwrap();
        assert_eq!(code, radius::CODE_DISCONNECT_REQUEST);
        assert_eq!(
            attr(&attrs, radius::ATTR_NAS_IP_ADDRESS),
            Some(&[10, 0, 0, 2][..])
        );
        assert_eq!(
            attr(&attrs, radius::ATTR_ACCT_SESSION_ID),
            Some(&b"0A00000F"[..])
        );
        // With a session id, the MAC isn't sent (format mismatches NAK).
        assert_eq!(attr(&attrs, radius::ATTR_CALLING_STATION_ID), None);
    }

    #[test]
    fn without_a_session_id_the_mac_identifies_it() {
        let s = session(None, Some("aa:bb:cc:dd:ee:ff"));
        let (_, attrs) = build_attributes(CoaMode::Disconnect, &s).unwrap();
        assert_eq!(
            attr(&attrs, radius::ATTR_CALLING_STATION_ID),
            Some(&b"AA-BB-CC-DD-EE-FF"[..])
        );
        assert!(build_attributes(CoaMode::Disconnect, &session(None, None)).is_none());
    }

    #[test]
    fn cisco_reauth_is_a_coa_with_the_avpair() {
        let (code, attrs) =
            build_attributes(CoaMode::CiscoReauth, &session(Some("1"), None)).unwrap();
        assert_eq!(code, radius::CODE_COA_REQUEST);
        let vsa = attr(&attrs, radius::ATTR_VENDOR_SPECIFIC).unwrap();
        assert!(vsa.ends_with(b"subscriber:command=reauthenticate"));
    }

    #[test]
    fn outcomes_close_sessions_only_when_they_ended() {
        assert!(
            CoaOutcome::Ack
                .closes_session(CoaMode::Disconnect)
                .is_some()
        );
        // A reauthenticate keeps the session.
        assert!(
            CoaOutcome::Ack
                .closes_session(CoaMode::CiscoReauth)
                .is_none()
        );
        assert!(
            CoaOutcome::Nak(Some(503))
                .closes_session(CoaMode::CiscoReauth)
                .is_some()
        );
        assert!(
            CoaOutcome::Nak(Some(501))
                .closes_session(CoaMode::Disconnect)
                .is_none()
        );
        assert!(
            CoaOutcome::NoResponse
                .closes_session(CoaMode::Disconnect)
                .is_none()
        );
        assert_eq!(
            CoaOutcome::Nak(Some(503)).summary(),
            "NAK: Session-Context-Not-Found (503)"
        );
    }

    /// A full exchange against a fake NAS on localhost: it checks our
    /// signature the way a NAS would, answers once, and the answer verifies.
    #[tokio::test]
    async fn exchange_round_trips_with_a_nas() {
        let secret = b"nas-secret".to_vec();
        let nas = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = nas.local_addr().unwrap();
        let s2 = secret.clone();
        let fake = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            // Drop the first try, to exercise the retry.
            let _ = nas.recv_from(&mut buf).await.unwrap();
            let (n, from) = nas.recv_from(&mut buf).await.unwrap();
            let req = Packet::parse(&buf[..n]).unwrap();
            assert!(req.verify_accounting_authenticator(&s2));
            assert!(req.verify_message_authenticator_zeroed(&s2));
            // A forged reply first (wrong secret), then the real one.
            let auth = Packet::authenticator_of(&buf[..n]).unwrap();
            let forged = radius::build_response(
                radius::CODE_DISCONNECT_ACK,
                req.id,
                &auth,
                &[],
                b"x",
                false,
            );
            nas.send_to(&forged, from).await.unwrap();
            let nak = radius::build_response(
                radius::CODE_DISCONNECT_NAK,
                req.id,
                &auth,
                &[(radius::ATTR_ERROR_CAUSE, 503u32.to_be_bytes().to_vec())],
                &s2,
                false,
            );
            nas.send_to(&nak, from).await.unwrap();
        });
        let request = radius::build_request(radius::CODE_DISCONNECT_REQUEST, 9, &[], &secret);
        let outcome = exchange(dest, &request, &secret).await;
        fake.await.unwrap();
        assert_eq!(outcome, CoaOutcome::Nak(Some(503)));
    }
}
