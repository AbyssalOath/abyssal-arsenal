//! Rogue DHCP server detection (0.2.9 Q4, `docs/roadmap/0.2.9.md`).
//!
//! The capture (`panopticon_arp`) sees DHCP servers two ways: the server
//! identifier (option 54) in clients' REQUESTs -- which also arrive through
//! relays, and say which server a client actually chose -- and OFFER, ACK
//! and NAK replies on the captured segment. Each is recorded
//! (`panopticon_dhcp_servers`); a server that isn't on
//! `panopticon.dhcp_allowed_servers` (empty = detection off) is a rogue: an
//! alert goes to the rogue-device recipients and the audit log, once a day
//! per server (and at most `MAX_ALERTS_PER_HOUR` in all), and the
//! `rogue_dhcp` policy trigger matches the device that sent the replies.
//! Panopticon's own registration DHCP server is always allowed. Nothing is
//! enforced without a policy rule.
//!
//! What the trigger trusts: every field of a DHCP packet is whatever its
//! sender wrote, so any device can name any address as "its" server --
//! option 54 in a request, or in a forged reply. Matching devices by that
//! address would let anyone get another device quarantined. So enforcement
//! goes by the one thing a sender can't put on someone else: the Ethernet
//! source of an unrelayed reply it actually sent (`server_mac`, recorded
//! only then). A server only ever *named* -- by clients' requests, or
//! seen through a relay -- is shown and alerted on as unconfirmed, never
//! enforced.

use std::collections::HashSet;
use std::net::IpAddr;

use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    PANOPTICON_DHCP_ALLOWED_SERVERS, PANOPTICON_PORTAL_ADDRESS, PANOPTICON_ROGUE_ALERT_RECIPIENTS,
};
use abyssal_core::{AllowedServer, DhcpServer, is_rogue_dhcp_server, parse_allowed_dhcp_servers};
use abyssal_database::repo::panopticon_dhcp_servers::{self as servers, Seen};
use abyssal_database::{DbPool, repo};
use abyssal_notifications::{NotificationDispatcher, NotificationMessage};
use chrono::{DateTime, Duration, Utc};

/// How often a rogue server is alerted on at most.
const ALERT_EVERY_HOURS: i64 = 24;
/// Rogue alerts in all, per hour at most: a device forging requests that
/// name many addresses can't flood the recipients.
const MAX_ALERTS_PER_HOUR: i64 = 10;

/// The allowed list, and the servers always allowed (Panopticon's own
/// registration DHCP server). A list that doesn't parse counts as empty
/// (detection off), logged: better than alerting on every server.
pub(crate) async fn allowed(pool: &DbPool) -> (Vec<AllowedServer>, Vec<IpAddr>) {
    let raw = repo::settings::get_string(pool, PANOPTICON_DHCP_ALLOWED_SERVERS, "")
        .await
        .unwrap_or_default();
    let list = parse_allowed_dhcp_servers(&raw).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "the allowed DHCP server list doesn't parse; rogue DHCP detection is off");
        Vec::new()
    });
    let portal = repo::settings::get_string(pool, PANOPTICON_PORTAL_ADDRESS, "")
        .await
        .unwrap_or_default();
    let always = portal
        .split('/')
        .next()
        .and_then(|a| a.trim().parse().ok())
        .into_iter()
        .collect();
    (list, always)
}

/// Whether a rogue that was last alerted on at `alerted_at` is due again.
pub(crate) fn alert_due(alerted_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    alerted_at.is_none_or(|at| now - at >= Duration::hours(ALERT_EVERY_HOURS))
}

/// Records one sighting of a DHCP server, and alerts if it's a rogue that's
/// due. Errors are logged: a sighting is best-effort, like the capture.
pub(crate) async fn observe(
    pool: &DbPool,
    notifications: &NotificationDispatcher,
    server_ip: &str,
    server_mac: Option<&str>,
    client_mac: Option<&str>,
    seen: Seen,
) {
    let server = match servers::record(pool, server_ip, server_mac, client_mac, seen).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, server = server_ip, "couldn't record a DHCP server");
            return;
        }
    };
    let (list, always) = allowed(pool).await;
    if !is_rogue_dhcp_server(&server.server_ip, &list, &always)
        || !alert_due(server.alerted_at, Utc::now())
    {
        return;
    }
    match servers::alerted_since(pool, Utc::now() - Duration::hours(1)).await {
        Ok(n) if n >= MAX_ALERTS_PER_HOUR => {
            tracing::warn!(
                server = %server.server_ip,
                "rogue DHCP server not alerted on: {MAX_ALERTS_PER_HOUR} alerts in the last hour already"
            );
            return;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "couldn't count recent rogue DHCP alerts");
            return;
        }
    }
    if let Err(e) = servers::mark_alerted(pool, &server.server_ip).await {
        tracing::warn!(error = %e, "couldn't mark a rogue DHCP server alerted");
        return;
    }
    alert(pool, notifications, &server, seen).await;
}

async fn alert(
    pool: &DbPool,
    notifications: &NotificationDispatcher,
    server: &DhcpServer,
    seen: Seen,
) {
    let how = match seen {
        Seen::Reply => "a reply from it",
        Seen::Chosen => "a client's request naming it",
    };
    // Only an unrelayed reply's source MAC is evidence of the sender.
    let confirmed = server.server_mac.is_some();
    let evidence = if confirmed {
        "It answered DHCP itself, from the MAC above."
    } else {
        "Unconfirmed: so far only named (by a client's request, or through a relay), \
         which any device can fake; the rogue DHCP policy trigger won't act on it."
    };
    let mac = server.server_mac.as_deref().unwrap_or("unknown");
    let client = server.last_client_mac.as_deref().unwrap_or("unknown");
    tracing::warn!(server = %server.server_ip, mac, client, how, "rogue DHCP server");
    let event = AuditEvent::new(AuditAction::NetworkRogueDhcpServer, AuditOutcome::Failure)
        .resource(&server.server_ip)
        .metadata(serde_json::json!({
            "seen": how,
            "server_mac": server.server_mac,
            "client_mac": server.last_client_mac,
            "replies": server.replies,
            "chosen": server.chosen,
            "confirmed": confirmed,
        }));
    if let Err(e) = abyssal_audit::record(pool, event).await {
        tracing::warn!(error = %e, "couldn't audit a rogue DHCP server");
    }
    let recipients = repo::settings::get_string(pool, PANOPTICON_ROGUE_ALERT_RECIPIENTS, "")
        .await
        .unwrap_or_default();
    notifications
        .dispatch(&NotificationMessage {
            subject: format!("[Panopticon] Rogue DHCP server: {}", server.server_ip),
            body: format!(
                "server={} mac={mac} seen=\"{how}\" client={client} replies={} chosen_by_clients={}. \
                 It isn't on Panopticon's allowed DHCP servers. {evidence} Find it (its MAC, or the \
                 client's switch port) and remove it, or add it to the allowed list on Panopticon's \
                 DHCP page if it's legitimate.",
                server.server_ip, server.replies, server.chosen
            ),
            severity: abyssal_notifications::Severity::Critical,
            recipients: crate::panopticon_ops::parse_recipients(&recipients),
        })
        .await;
}

/// What the `rogue_dhcp` policy trigger matches devices against: the MACs
/// that sent unrelayed replies as a rogue server seen since `since`
/// (lowercase). Never addresses: see the module doc. Empty while detection
/// is off.
pub(crate) async fn rogue_macs_since(
    pool: &DbPool,
    since: DateTime<Utc>,
) -> anyhow::Result<HashSet<String>> {
    let (list, always) = allowed(pool).await;
    if list.is_empty() {
        return Ok(HashSet::new());
    }
    Ok(confirmed_rogue_macs(
        &servers::seen_since(pool, since).await?,
        &list,
        &always,
    ))
}

/// The source MACs of the rogue servers among `seen` that answered DHCP
/// themselves (an unrelayed reply recorded their MAC).
pub(crate) fn confirmed_rogue_macs(
    seen: &[DhcpServer],
    list: &[AllowedServer],
    always: &[IpAddr],
) -> HashSet<String> {
    seen.iter()
        .filter(|s| s.replies > 0 && is_rogue_dhcp_server(&s.server_ip, list, always))
        .filter_map(|s| s.server_mac.as_deref().map(str::to_ascii_lowercase))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(ip: &str, mac: Option<&str>, replies: u32, chosen: u32) -> DhcpServer {
        DhcpServer {
            server_ip: ip.into(),
            server_mac: mac.map(Into::into),
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
            replies,
            chosen,
            last_client_mac: None,
            alerted_at: None,
        }
    }

    #[test]
    fn only_a_rogue_that_answered_itself_is_enforceable() {
        let list = parse_allowed_dhcp_servers("10.0.0.10").unwrap();
        let seen = [
            // Answered from its own MAC: enforceable, by that MAC.
            server("10.0.0.56", Some("AA:BB:CC:00:00:06"), 3, 0),
            // Only named in clients' requests (forgeable): not.
            server("10.0.0.55", None, 0, 40),
            // Seen through a relay: no MAC, not.
            server("10.1.1.1", None, 2, 0),
            // The allowed server: not a rogue at all.
            server("10.0.0.10", Some("aa:bb:cc:00:00:10"), 9, 9),
        ];
        let macs = confirmed_rogue_macs(&seen, &list, &[]);
        assert_eq!(macs.len(), 1);
        assert!(macs.contains("aa:bb:cc:00:00:06"));
        // Detection off: nothing.
        assert!(confirmed_rogue_macs(&seen, &[], &[]).is_empty());
    }

    #[test]
    fn a_rogue_is_alerted_on_once_a_day() {
        let now = Utc::now();
        assert!(alert_due(None, now));
        assert!(!alert_due(Some(now - Duration::hours(1)), now));
        assert!(alert_due(Some(now - Duration::hours(25)), now));
    }
}
