//! Panopticon's registration portal (0.2.7 N5, see `docs/roadmap/0.2.7.md`
//! and `deploy/registration/README.md`), in the PacketFence style.
//!
//! With the RADIUS policy's unknown-device action set to "Registration
//! portal", an unknown device lands on the registration VLAN. There,
//! Panopticon runs its own DHCP server and captive DNS (`abyssal_portal_net`,
//! bound to the registration interface only) and this portal: a separate web
//! server on the portal address, port 80, serving nothing but the
//! registration pages. Every other URL redirects to `/register`, which is
//! what makes phones and laptops show their captive-portal sign-in sheet.
//!
//! A guest accepts the terms; in self-service mode they're approved at once,
//! in sponsor mode staff approve on the Registration portal page. Either way
//! Panopticon then re-authorizes the device's RADIUS session (CoA), and it
//! comes back on the guest VLAN until the approval expires.
//!
//! The guest is identified by their DHCP lease: the TCP peer address maps to
//! the MAC this server leased it to. Nothing a guest submits can name
//! another device.
//!
//! The admin UI is never reachable from the registration subnet:
//! [`admin_guard`] refuses every request to the main web server from it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    PANOPTICON_PORTAL_ACCESS_HOURS, PANOPTICON_PORTAL_ACCESS_HOURS_DEFAULT,
    PANOPTICON_PORTAL_ADDRESS, PANOPTICON_PORTAL_DHCP_END, PANOPTICON_PORTAL_DHCP_START,
    PANOPTICON_PORTAL_ENABLED, PANOPTICON_PORTAL_LEASE_SECONDS,
    PANOPTICON_PORTAL_LEASE_SECONDS_DEFAULT, PANOPTICON_PORTAL_MODE, PANOPTICON_PORTAL_TERMS,
};
use abyssal_core::{EncryptionKey, PortalMode};
use abyssal_database::{DbPool, repo};
use abyssal_portal_net::dhcp::{self, LeasePool};
use abyssal_portal_net::{bound_udp, dns};
use askama::Template;
use axum::Form;
use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use chrono::Utc;
use serde::Deserialize;

/// The portal's network settings, as stored.
#[derive(Debug, Clone)]
pub struct NetSettings {
    pub address: String,
    pub dhcp_start: String,
    pub dhcp_end: String,
    pub lease_seconds: u32,
}

impl NetSettings {
    pub async fn load(pool: &DbPool) -> Self {
        let s = |k: &'static str| async move {
            repo::settings::get_string(pool, k, "")
                .await
                .unwrap_or_default()
        };
        NetSettings {
            address: s(PANOPTICON_PORTAL_ADDRESS).await,
            dhcp_start: s(PANOPTICON_PORTAL_DHCP_START).await,
            dhcp_end: s(PANOPTICON_PORTAL_DHCP_END).await,
            lease_seconds: repo::settings::get_u32(
                pool,
                PANOPTICON_PORTAL_LEASE_SECONDS,
                PANOPTICON_PORTAL_LEASE_SECONDS_DEFAULT,
            )
            .await
            .unwrap_or(PANOPTICON_PORTAL_LEASE_SECONDS_DEFAULT),
        }
    }

    /// The DHCP server's configuration, or why these settings don't make one.
    pub fn dhcp_config(&self) -> Result<dhcp::Config, String> {
        let (ip, prefix) =
            self.address.trim().split_once('/').ok_or(
                "the portal address must be an IPv4 address with a prefix, e.g. 10.99.0.1/24",
            )?;
        let server_ip: Ipv4Addr = ip
            .parse()
            .map_err(|_| "the portal address isn't an IPv4 address".to_string())?;
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|_| "the portal address's prefix isn't a number".to_string())?;
        let range_start: Ipv4Addr = self
            .dhcp_start
            .trim()
            .parse()
            .map_err(|_| "the DHCP range start isn't an IPv4 address".to_string())?;
        let range_end: Ipv4Addr = self
            .dhcp_end
            .trim()
            .parse()
            .map_err(|_| "the DHCP range end isn't an IPv4 address".to_string())?;
        let cfg = dhcp::Config {
            server_ip,
            prefix_len,
            range_start,
            range_end,
            lease: Duration::from_secs(u64::from(self.lease_seconds)),
            portal_url: format!("http://{server_ip}/"),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

/// What's running, once the portal has started.
struct Runtime {
    server_ip: Ipv4Addr,
    network: u32,
    mask: u32,
    interface: String,
    leases: Arc<Mutex<LeasePool>>,
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Whether `ip` is on the registration subnet (only once the portal runs).
pub fn in_registration_subnet(ip: IpAddr) -> bool {
    let Some(rt) = RUNTIME.get() else {
        return false;
    };
    let ip = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
    };
    u32::from(ip) & rt.mask == rt.network
}

/// The running portal's interface and active lease count, for the admin page.
pub fn status() -> Option<(String, Ipv4Addr, usize)> {
    let rt = RUNTIME.get()?;
    let leases = rt
        .leases
        .lock()
        .map(|p| p.active_leases(Instant::now()))
        .unwrap_or(0);
    Some((rt.interface.clone(), rt.server_ip, leases))
}

/// The container interface carrying `ip`.
fn interface_for(ip: Ipv4Addr) -> Option<String> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|i| i.ips.iter().any(|n| n.ip() == IpAddr::V4(ip)))
        .map(|i| i.name)
}

/// Main-app middleware: nothing on the admin web server answers the
/// registration subnet. Guests can reach the container's address there, so
/// without this they'd reach the login page (and the agent endpoints).
pub async fn admin_guard(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if in_registration_subnet(peer.ip()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

#[derive(Clone)]
struct PortalState {
    pool: DbPool,
    key: Option<Arc<EncryptionKey>>,
    server_ip: Ipv4Addr,
    leases: Arc<Mutex<LeasePool>>,
    /// Last registration POST per MAC: one per few seconds is plenty.
    recent: Arc<Mutex<HashMap<String, Instant>>>,
}

/// Starts the portal if it's enabled and configured: DHCP and DNS on the
/// registration interface, the portal web server on its address, fingerprint
/// recording, and the expiry sweep. Network settings apply on restart.
pub async fn spawn_panopticon_portal(pool: DbPool, key: Option<Arc<EncryptionKey>>) {
    if !repo::settings::get_bool(&pool, PANOPTICON_PORTAL_ENABLED, false)
        .await
        .unwrap_or(false)
    {
        return;
    }
    let cfg = match NetSettings::load(&pool).await.dhcp_config() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "registration portal: not started");
            return;
        }
    };
    let Some(interface) = interface_for(cfg.server_ip) else {
        tracing::error!(
            address = %cfg.server_ip,
            "registration portal: no interface in this container has the portal address; \
             not started (see deploy/registration/README.md)"
        );
        return;
    };
    let mask = u32::from(cfg.netmask());
    let leases = Arc::new(Mutex::new(LeasePool::new(cfg.clone())));
    // Before any listener: the admin guard applies even if one fails.
    let _ = RUNTIME.set(Runtime {
        server_ip: cfg.server_ip,
        network: u32::from(cfg.server_ip) & mask,
        mask,
        interface: interface.clone(),
        leases: leases.clone(),
    });

    // DHCP, with fingerprints for device classification (N3).
    let (fp_tx, mut fp_rx) = tokio::sync::mpsc::unbounded_channel::<dhcp::Fingerprint>();
    match bound_udp(&interface, 67) {
        Ok(socket) => {
            let (cfg, leases) = (cfg.clone(), leases.clone());
            tokio::spawn(async move {
                if let Err(e) = dhcp::serve(socket, cfg, leases, Some(fp_tx)).await {
                    tracing::error!(error = %e, "registration DHCP stopped");
                }
            });
        }
        Err(e) => tracing::error!(error = %e, %interface, "registration DHCP: can't bind UDP 67"),
    }
    let fp_pool = pool.clone();
    tokio::spawn(async move {
        while let Some(f) = fp_rx.recv().await {
            let _ = repo::panopticon_fingerprints::upsert(
                &fp_pool,
                &f.mac,
                f.prl.as_deref(),
                f.vendor_class.as_deref(),
                f.hostname.as_deref(),
            )
            .await;
        }
    });

    // Captive DNS.
    match bound_udp(&interface, 53) {
        Ok(socket) => {
            let ip = cfg.server_ip;
            tokio::spawn(async move {
                if let Err(e) = dns::serve(socket, ip).await {
                    tracing::error!(error = %e, "registration DNS stopped");
                }
            });
        }
        Err(e) => tracing::error!(error = %e, %interface, "registration DNS: can't bind UDP 53"),
    }

    // The portal web server, on the portal address only.
    let state = PortalState {
        pool: pool.clone(),
        key: key.clone(),
        server_ip: cfg.server_ip,
        leases,
        recent: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = portal_router(state);
    let addr = SocketAddr::new(IpAddr::V4(cfg.server_ip), 80);
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            tokio::spawn(async move {
                let service = app.into_make_service_with_connect_info::<SocketAddr>();
                if let Err(e) = axum::serve(listener, service).await {
                    tracing::error!(error = %e, "registration portal web server stopped");
                }
            });
        }
        Err(e) => tracing::error!(error = %e, %addr, "registration portal: can't bind"),
    }

    spawn_expiry_sweep(pool, key);
    tracing::info!(%interface, address = %cfg.server_ip, "registration portal started");
}

/// Every minute: approvals past their expiry become expired, and the
/// devices are re-authorized back onto the registration VLAN.
fn spawn_expiry_sweep(pool: DbPool, key: Option<Arc<EncryptionKey>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match repo::panopticon_registrations::expire_due(&pool).await {
                Ok(macs) => {
                    for mac in macs {
                        crate::panopticon_coa::spawn_reauthorize_mac(
                            pool.clone(),
                            key.clone(),
                            mac,
                            "guest registration expired".into(),
                            None,
                        );
                    }
                }
                Err(e) => tracing::warn!(error = %e, "registration expiry sweep failed"),
            }
        }
    });
}

fn portal_router(state: PortalState) -> Router {
    Router::new()
        .route("/register", get(register_page).post(register_submit))
        // Captive-portal checks (captive.apple.com, connectivitycheck...,
        // msftconnecttest.com) and anything else land on the portal.
        .fallback(redirect_to_portal)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

async fn redirect_to_portal(State(state): State<PortalState>) -> Response {
    Redirect::temporary(&format!("http://{}/register", state.server_ip)).into_response()
}

#[derive(Template)]
#[template(path = "portal_page.html")]
struct PortalPage {
    title: String,
    message: Vec<String>,
    show_form: bool,
    sponsor: bool,
    terms: String,
    name: String,
    email: String,
    error: String,
    refresh: bool,
    mac: String,
}

impl PortalPage {
    fn info(title: &str, message: &[&str], mac: &str, refresh: bool) -> Self {
        PortalPage {
            title: title.into(),
            message: message.iter().map(|s| s.to_string()).collect(),
            show_form: false,
            sponsor: false,
            terms: String::new(),
            name: String::new(),
            email: String::new(),
            error: String::new(),
            refresh,
            mac: mac.into(),
        }
    }
}

fn render(page: PortalPage) -> Response {
    match page.render() {
        Ok(html) => (
            [
                (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
                // Never cache: a captive page must be re-fetched each time.
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            html,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The MAC holding the DHCP lease for the guest's address.
fn guest_mac(state: &PortalState, peer: SocketAddr) -> Option<String> {
    let IpAddr::V4(ip) = peer.ip() else {
        return None;
    };
    let leases = state.leases.lock().ok()?;
    leases
        .mac_for_ip(ip, Instant::now())
        .map(|m| abyssal_portal_net::dhcp::mac_string(&m))
}

async fn portal_settings(pool: &DbPool) -> (PortalMode, u32, String) {
    let mode = PortalMode::parse(
        &repo::settings::get_string(pool, PANOPTICON_PORTAL_MODE, "sponsor")
            .await
            .unwrap_or_default(),
    );
    let hours = repo::settings::get_u32(
        pool,
        PANOPTICON_PORTAL_ACCESS_HOURS,
        PANOPTICON_PORTAL_ACCESS_HOURS_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_PORTAL_ACCESS_HOURS_DEFAULT);
    let terms = repo::settings::get_string(pool, PANOPTICON_PORTAL_TERMS, "")
        .await
        .unwrap_or_default();
    (mode, hours, terms)
}

const UNIDENTIFIED: &[&str] = &[
    "This device didn't get its address from this network's DHCP server, so it can't be \
     identified.",
    "Turn off any fixed (static) IP address, reconnect, and open this page again.",
];

/// What the guest sees: their status, or the form.
async fn status_page(state: &PortalState, mac: &str, error: &str, form: &RegisterForm) -> Response {
    let (mode, _, terms) = portal_settings(&state.pool).await;
    let registration = repo::panopticon_registrations::find(&state.pool, mac)
        .await
        .ok()
        .flatten();
    use abyssal_core::RegistrationStatus as S;
    match registration {
        Some(r) if r.grants_access(Utc::now()) => render(PortalPage::info(
            "You're registered",
            &[
                "Your device is being moved to the guest network. That usually takes under a \
                 minute.",
                "If you're still not online after a minute, turn Wi-Fi off and on (or unplug and \
                 replug the cable).",
            ],
            mac,
            false,
        )),
        Some(r) if r.status == S::Pending && error.is_empty() => render(PortalPage::info(
            "Waiting for approval",
            &[
                "Your request was sent. A member of staff needs to approve it.",
                "This page checks again every 15 seconds; you'll be connected once it's approved.",
            ],
            mac,
            true,
        )),
        Some(r) if r.status == S::Denied => render(PortalPage::info(
            "Access denied",
            &["Your request for network access was denied. Ask a member of staff for help."],
            mac,
            false,
        )),
        _ => render(PortalPage {
            title: "Network access".into(),
            message: vec![match mode {
                PortalMode::SelfService => {
                    "Accept the terms of use below to connect to the guest network.".into()
                }
                PortalMode::Sponsor => {
                    "Request access to the guest network. A member of staff will approve it.".into()
                }
            }],
            show_form: true,
            sponsor: mode == PortalMode::Sponsor,
            terms,
            name: form.name.clone(),
            email: form.email.clone(),
            error: error.into(),
            refresh: false,
            mac: mac.into(),
        }),
    }
}

async fn register_page(
    State(state): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    let Some(mac) = guest_mac(&state, peer) else {
        return render(PortalPage::info(
            "Can't identify your device",
            UNIDENTIFIED,
            "unknown",
            false,
        ));
    };
    status_page(&state, &mac, "", &RegisterForm::default()).await
}

#[derive(Deserialize, Default)]
struct RegisterForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    accept: String,
}

/// Validates a registration: the name and (optional) email, cleaned.
fn validate(form: &RegisterForm) -> Result<(String, Option<String>), &'static str> {
    let name: String = form
        .name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if name.is_empty() {
        return Err("Enter your name.");
    }
    if name.chars().count() > 100 {
        return Err("That name is too long.");
    }
    let email = form.email.trim();
    let email = if email.is_empty() {
        None
    } else {
        let valid = email.len() <= 255
            && !email.chars().any(|c| c.is_control() || c.is_whitespace())
            && email
                .split_once('@')
                .is_some_and(|(u, d)| !u.is_empty() && d.contains('.') && !d.starts_with('.'));
        if !valid {
            return Err("That email address doesn't look right.");
        }
        Some(email.to_string())
    };
    if form.accept != "yes" {
        return Err("Accept the terms of use to continue.");
    }
    Ok((name, email))
}

async fn register_submit(
    State(state): State<PortalState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(form): Form<RegisterForm>,
) -> Response {
    let Some(mac) = guest_mac(&state, peer) else {
        return render(PortalPage::info(
            "Can't identify your device",
            UNIDENTIFIED,
            "unknown",
            false,
        ));
    };
    let (name, email) = match validate(&form) {
        Ok(v) => v,
        Err(e) => return status_page(&state, &mac, e, &form).await,
    };
    {
        let mut recent = state.recent.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        recent.retain(|_, t| now.duration_since(*t) < Duration::from_secs(5));
        if recent.contains_key(&mac) {
            return Redirect::to("/register").into_response();
        }
        recent.insert(mac.clone(), now);
    }
    let (mode, hours, _) = portal_settings(&state.pool).await;
    let approved_until = (mode == PortalMode::SelfService)
        .then(|| Utc::now() + chrono::Duration::hours(i64::from(hours)));
    if let Err(e) = repo::panopticon_registrations::request(
        &state.pool,
        &mac,
        &name,
        email.as_deref(),
        approved_until,
    )
    .await
    {
        tracing::warn!(error = %e, "registration portal: failed to record a request");
        return status_page(&state, &mac, "Something went wrong. Try again.", &form).await;
    }
    let status = if approved_until.is_some() {
        "approved"
    } else {
        "pending"
    };
    let _ = abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::NetworkGuestRegistered, AuditOutcome::Success)
            .resource(&mac)
            .metadata(serde_json::json!({
                "name": name,
                "email": email,
                "status": status,
                "hours": hours,
            })),
    )
    .await;
    if approved_until.is_some() {
        crate::panopticon_coa::spawn_reauthorize_mac(
            state.pool.clone(),
            state.key.clone(),
            mac,
            "guest self-registered".into(),
            None,
        );
    }
    Redirect::to("/register").into_response()
}

/// Staff decisions from the admin page: approve / deny / revoke. Returns
/// whether it changed anything.
pub async fn decide(
    pool: &DbPool,
    key: Option<Arc<EncryptionKey>>,
    mac: &str,
    action: &str,
    actor: (uuid::Uuid, &str),
) -> anyhow::Result<bool> {
    use abyssal_core::RegistrationStatus as S;
    let (to, expires_at) = match action {
        "approve" => {
            let (_, hours, _) = portal_settings(pool).await;
            (
                S::Approved,
                Some(Utc::now() + chrono::Duration::hours(i64::from(hours))),
            )
        }
        "deny" => (S::Denied, None),
        "revoke" => (S::Revoked, None),
        _ => return Ok(false),
    };
    let changed =
        repo::panopticon_registrations::decide(pool, mac, to, actor.1, expires_at).await?;
    if changed {
        abyssal_audit::record(
            pool,
            AuditEvent::new(
                AuditAction::NetworkGuestRegistrationDecided,
                AuditOutcome::Success,
            )
            .actor(abyssal_audit::Actor {
                user_id: actor.0,
                username: actor.1,
            })
            .resource(mac)
            .metadata(serde_json::json!({ "status": to.as_str() })),
        )
        .await?;
        // Approving and revoking change the device's VLAN; denying leaves it
        // on the registration VLAN.
        if to != S::Denied {
            crate::panopticon_coa::spawn_reauthorize_mac(
                pool.clone(),
                key,
                mac.to_string(),
                format!("guest registration {}", to.as_str()),
                Some((actor.0, actor.1.to_string())),
            );
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(name: &str, email: &str, accept: &str) -> RegisterForm {
        RegisterForm {
            name: name.into(),
            email: email.into(),
            accept: accept.into(),
        }
    }

    #[test]
    fn registration_input_is_validated() {
        assert_eq!(
            validate(&form("  Jane Doe ", "", "yes")),
            Ok(("Jane Doe".into(), None))
        );
        assert_eq!(
            validate(&form("Jane", "jane@example.com", "yes")),
            Ok(("Jane".into(), Some("jane@example.com".into())))
        );
        assert!(
            validate(&form("Jane", "", "")).is_err(),
            "terms not accepted"
        );
        assert!(validate(&form("   ", "", "yes")).is_err());
        assert!(validate(&form(&"x".repeat(101), "", "yes")).is_err());
        assert!(validate(&form("Jane", "not-an-email", "yes")).is_err());
        assert!(validate(&form("Jane", "a b@c.d", "yes")).is_err());
        // Control characters are dropped, not stored.
        assert_eq!(validate(&form("Ja\u{7}ne\n", "", "yes")).unwrap().0, "Jane");
    }

    #[test]
    fn net_settings_make_a_dhcp_config() {
        let mut s = NetSettings {
            address: "10.99.0.1/24".into(),
            dhcp_start: "10.99.0.100".into(),
            dhcp_end: "10.99.0.200".into(),
            lease_seconds: 60,
        };
        let cfg = s.dhcp_config().unwrap();
        assert_eq!(cfg.portal_url, "http://10.99.0.1/");
        s.address = "10.99.0.1".into();
        assert!(s.dhcp_config().is_err(), "no prefix");
        s.address = "10.99.0.1/24".into();
        s.dhcp_end = "10.98.0.200".into();
        assert!(s.dhcp_config().is_err(), "outside the subnet");
    }

    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    const PORTAL: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);

    fn cfg() -> dhcp::Config {
        NetSettings {
            address: "10.99.0.1/24".into(),
            dhcp_start: "10.99.0.100".into(),
            dhcp_end: "10.99.0.120".into(),
            lease_seconds: 60,
        }
        .dhcp_config()
        .unwrap()
    }

    /// A portal whose database is unreachable: the paths tested here never
    /// need it, or must cope without it.
    fn portal(leases: Arc<Mutex<LeasePool>>) -> Router {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("mysql://invalid:invalid@127.0.0.1:1/invalid")
            .expect("lazy pool");
        portal_router(PortalState {
            pool,
            key: None,
            server_ip: PORTAL,
            leases,
            recent: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn send(
        app: Router,
        method: &str,
        path: &str,
        from: &str,
        body: &str,
    ) -> (StatusCode, String, String) {
        let mut req = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap();
        let peer: SocketAddr = format!("{from}:50000").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let location = res
            .headers()
            .get("location")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            location,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    #[tokio::test]
    async fn captive_checks_are_redirected_to_the_portal() {
        let leases = Arc::new(Mutex::new(LeasePool::new(cfg())));
        for path in [
            "/hotspot-detect.html",
            "/generate_204",
            "/connecttest.txt",
            "/",
        ] {
            let (status, location, _) =
                send(portal(leases.clone()), "GET", path, "10.99.0.100", "").await;
            assert_eq!(status, StatusCode::TEMPORARY_REDIRECT, "{path}");
            assert_eq!(location, "http://10.99.0.1/register");
        }
    }

    #[tokio::test]
    async fn a_device_without_a_lease_cannot_register() {
        let leases = Arc::new(Mutex::new(LeasePool::new(cfg())));
        let (status, _, body) = send(
            portal(leases.clone()),
            "GET",
            "/register",
            "10.99.0.100",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Can&#x27;t identify your device")
                || body.contains("identify your device"),
            "{body}"
        );
        assert!(!body.contains("<form"));
        // Posting doesn't help either.
        let (_, _, body) = send(
            portal(leases),
            "POST",
            "/register",
            "10.99.0.100",
            "name=Eve&accept=yes",
        )
        .await;
        assert!(body.contains("identify your device"));
    }

    #[tokio::test]
    async fn a_leased_device_is_identified_by_its_lease_and_input_is_checked() {
        let leases = Arc::new(Mutex::new(LeasePool::new(cfg())));
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        {
            let mut p = leases.lock().unwrap();
            let ip = p.offer(mac, None, Instant::now()).unwrap();
            assert!(p.request(mac, ip, Instant::now()));
            assert_eq!(ip, Ipv4Addr::new(10, 99, 0, 100));
        }
        let (status, _, body) = send(
            portal(leases.clone()),
            "GET",
            "/register",
            "10.99.0.100",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("02:11:22:33:44:55"), "the guest's own MAC");
        assert!(body.contains("<form"));
        // Terms not accepted: the form comes back with the error and the
        // guest's input, escaped.
        let (_, _, body) = send(
            portal(leases),
            "POST",
            "/register",
            "10.99.0.100",
            "name=%3Cb%3EJane&email=",
        )
        .await;
        assert!(body.contains("Accept the terms of use to continue."));
        assert!(body.contains("&lt;b&gt;Jane"));
        assert!(!body.contains("<b>Jane"));
    }

    #[tokio::test]
    async fn the_admin_ui_refuses_the_registration_subnet() {
        let c = cfg();
        let mask = u32::from(c.netmask());
        let _ = RUNTIME.set(Runtime {
            server_ip: c.server_ip,
            network: u32::from(c.server_ip) & mask,
            mask,
            interface: "eth1".into(),
            leases: Arc::new(Mutex::new(LeasePool::new(c.clone()))),
        });
        let admin = Router::new()
            .route("/login", get(|| async { "login page" }))
            .layer(axum::middleware::from_fn(admin_guard));
        let (status, _, _) = send(admin.clone(), "GET", "/login", "10.99.0.100", "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = send(admin, "GET", "/login", "172.18.0.5", "").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "login page"));
        assert!(in_registration_subnet("::ffff:10.99.0.7".parse().unwrap()));
        assert!(!in_registration_subnet("10.98.0.7".parse().unwrap()));
    }
}
