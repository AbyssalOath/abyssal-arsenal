use std::path::PathBuf;

use axum::routing::{get, post};
use axum::Router;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::middleware::security_headers;
use crate::routes;
use crate::state::AppState;

pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/", get(routes::dashboard::show))
        .route(
            "/setup",
            get(routes::setup::show).post(routes::setup::submit),
        )
        .route(
            "/login",
            get(routes::login::show).post(routes::login::submit),
        )
        .route("/logout", post(routes::login::logout))
        .route(
            "/register",
            get(routes::register::show).post(routes::register::submit),
        )
        .route("/theme", post(routes::theme::set))
        .route("/admin/users", get(routes::users::list))
        .route("/admin/users/create", post(routes::users::create))
        .route(
            "/admin/users/:id/toggle-active",
            post(routes::users::toggle_active),
        )
        .route(
            "/admin/users/:id/revoke-sessions",
            post(routes::users::revoke_sessions),
        )
        .route(
            "/admin/users/:id/delete/confirm",
            get(routes::users::delete_confirm),
        )
        .route("/admin/users/:id/delete", post(routes::users::delete))
        .route("/admin/roles", get(routes::roles::list))
        .route(
            "/admin/roles/:id/permissions",
            post(routes::roles::update_permissions),
        )
        .route("/admin/audit", get(routes::audit::list))
        .route("/admin/audit/export", get(routes::audit::export))
        .route("/admin/modules", get(routes::modules::list))
        .route("/admin/modules/:key/toggle", post(routes::modules::toggle))
        .route("/admin/settings", get(routes::settings::show))
        .route(
            "/admin/settings/registration",
            post(routes::settings::set_registration),
        )
        .route("/admin/hosts", get(routes::hosts::list))
        .route(
            "/admin/hosts/enroll-token",
            post(routes::hosts::generate_enrollment_token),
        )
        .route(
            "/admin/hosts/:id/system-info",
            post(routes::hosts::run_system_info),
        )
        .route("/admin/hosts/:id/elevate", post(routes::hosts::elevate))
        .route(
            "/admin/hosts/:id/deescalate",
            post(routes::hosts::deescalate),
        )
        .route(
            "/admin/hosts/:id/elevation-status",
            post(routes::hosts::elevation_status),
        )
        .route(
            "/admin/hosts/:id/revoke/confirm",
            get(routes::hosts::revoke_confirm),
        )
        .route("/admin/hosts/:id/revoke", post(routes::hosts::revoke))
        .route(
            "/admin/hosts/:id/remove/confirm",
            get(routes::hosts::remove_confirm),
        )
        .route("/admin/hosts/:id/remove", post(routes::hosts::remove))
        .route("/arsenals/cystoolbox", get(routes::cystoolbox::show))
        .route(
            "/arsenals/cystoolbox/:host_id/system-overview",
            post(routes::cystoolbox::system_overview),
        )
        .route(
            "/arsenals/cystoolbox/:host_id/resource-usage",
            post(routes::cystoolbox::resource_usage),
        )
        .route(
            "/arsenals/cystoolbox/:host_id/logged-in-users",
            post(routes::cystoolbox::logged_in_users),
        )
        .route(
            "/arsenals/cystoolbox/:host_id/set-hostname",
            post(routes::cystoolbox::set_hostname),
        )
        .route(
            "/arsenals/cystoolbox/:host_id/reboot/confirm",
            get(routes::cystoolbox::reboot_confirm),
        )
        .route(
            "/arsenals/cystoolbox/:host_id/reboot",
            post(routes::cystoolbox::reboot),
        )
        .route("/arsenals/cadavault", get(routes::cadavault::show))
        .route(
            "/arsenals/cadavault/:host_id/firewall-status",
            post(routes::cadavault::firewall_status),
        )
        .route(
            "/arsenals/cadavault/:host_id/listening-ports",
            post(routes::cadavault::listening_ports),
        )
        .route(
            "/arsenals/cadavault/:host_id/recent-auth-log",
            post(routes::cadavault::recent_auth_log),
        )
        .route(
            "/arsenals/cadavault/:host_id/allow-port",
            post(routes::cadavault::allow_port),
        )
        .route(
            "/arsenals/cadavault/:host_id/firewall-enable/confirm",
            get(routes::cadavault::enable_firewall_confirm),
        )
        .route(
            "/arsenals/cadavault/:host_id/firewall-enable",
            post(routes::cadavault::enable_firewall),
        )
        .route("/arsenals/:key", get(routes::arsenals::show))
        .route("/api/health", get(routes::api::health))
        .route("/api/me", get(routes::api::me))
        .route("/api/hosts/enroll", post(routes::agent::enroll))
        .route("/ws/agent", get(routes::agent::ws_upgrade))
        .nest_service("/static", ServeDir::new(static_dir()))
        .layer(axum::middleware::from_fn(security_headers::apply))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Defaults to the path that works with `cargo run` from the workspace root;
/// the Docker image sets `STATIC_DIR=static` after copying
/// `crates/web/static/` alongside the binary.
fn static_dir() -> PathBuf {
    std::env::var("STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("crates/web/static"))
}
