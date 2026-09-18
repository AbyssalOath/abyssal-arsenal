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
        .route("/account/timezone", post(routes::account::set_timezone))
        .route("/style-guide", get(routes::style_guide::show))
        .route("/admin/users", get(routes::users::list))
        .route("/admin/users/create", post(routes::users::create))
        .route("/admin/users/:id/enable", post(routes::users::enable))
        .route(
            "/admin/users/:id/disable/confirm",
            get(routes::users::disable_confirm),
        )
        .route("/admin/users/:id/disable", post(routes::users::disable))
        .route(
            "/admin/users/:id/revoke-sessions/confirm",
            get(routes::users::revoke_sessions_confirm),
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
        .route(
            "/admin/roles/:id/permissions/apply",
            post(routes::roles::apply_permissions),
        )
        .route("/admin/audit", get(routes::audit::list))
        .route("/admin/audit/export", get(routes::audit::export))
        .route("/admin/modules", get(routes::modules::list))
        .route("/admin/modules/:key/enable", post(routes::modules::enable))
        .route(
            "/admin/modules/:key/disable/confirm",
            get(routes::modules::disable_confirm),
        )
        .route(
            "/admin/modules/:key/disable",
            post(routes::modules::disable),
        )
        .route("/admin/settings", get(routes::settings::show))
        .route(
            "/admin/settings/registration",
            post(routes::settings::set_registration),
        )
        .route(
            "/admin/settings/elevation-window",
            post(routes::settings::set_elevation_window),
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
        .route(
            "/admin/hosts/:id/deescalate",
            post(routes::hosts::deescalate),
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
            "/arsenals/cystoolbox/:host_id",
            get(routes::cystoolbox::show_host),
        )
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
            "/arsenals/cadavault/:host_id",
            get(routes::cadavault::show_host),
        )
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
        .route("/arsenals/necrolink", get(routes::necrolink::show))
        .route(
            "/arsenals/necrolink/:host_id",
            get(routes::necrolink::show_host),
        )
        .route(
            "/arsenals/necrolink/:host_id/interfaces",
            post(routes::necrolink::network_interfaces),
        )
        .route(
            "/arsenals/necrolink/:host_id/routes",
            post(routes::necrolink::network_routes),
        )
        .route(
            "/arsenals/necrolink/:host_id/dns",
            post(routes::necrolink::dns_config),
        )
        .route(
            "/arsenals/necrolink/:host_id/connections",
            post(routes::necrolink::active_connections),
        )
        .route(
            "/arsenals/necrolink/:host_id/connectivity-check",
            post(routes::necrolink::connectivity_check),
        )
        .route(
            "/arsenals/necrolink/:host_id/interface/up",
            post(routes::necrolink::interface_up),
        )
        .route(
            "/arsenals/necrolink/:host_id/interface/down/confirm",
            get(routes::necrolink::interface_down_confirm),
        )
        .route(
            "/arsenals/necrolink/:host_id/interface/down",
            post(routes::necrolink::interface_down),
        )
        .route(
            "/arsenals/necrolink/:host_id/scan/confirm",
            get(routes::necrolink::scan_confirm),
        )
        .route(
            "/arsenals/necrolink/:host_id/scan",
            post(routes::necrolink::network_scan),
        )
        .route("/arsenals/postmortem", get(routes::postmortem::show))
        .route(
            "/arsenals/postmortem/:host_id",
            get(routes::postmortem::show_host),
        )
        .route(
            "/arsenals/postmortem/:host_id/boot-history",
            post(routes::postmortem::boot_history),
        )
        .route(
            "/arsenals/postmortem/:host_id/kernel-ring-buffer",
            post(routes::postmortem::kernel_ring_buffer),
        )
        .route(
            "/arsenals/postmortem/:host_id/journal-errors",
            post(routes::postmortem::system_journal_errors),
        )
        .route(
            "/arsenals/postmortem/:host_id/failed-logins",
            post(routes::postmortem::failed_login_attempts),
        )
        .route(
            "/arsenals/postmortem/:host_id/oom-kills",
            post(routes::postmortem::oom_kill_events),
        )
        .route(
            "/arsenals/postmortem/:host_id/core-dumps",
            post(routes::postmortem::core_dumps),
        )
        .route(
            "/arsenals/postmortem/:host_id/modified-files",
            post(routes::postmortem::recently_modified_files),
        )
        .route("/arsenals/obituary", get(routes::obituary::show))
        .route(
            "/arsenals/obituary/:host_id",
            get(routes::obituary::show_host),
        )
        .route(
            "/arsenals/obituary/:host_id/journal-disk-usage",
            post(routes::obituary::journal_disk_usage),
        )
        .route(
            "/arsenals/obituary/:host_id/log-rotation-status",
            post(routes::obituary::log_rotation_status),
        )
        .route(
            "/arsenals/obituary/:host_id/archived-logs",
            post(routes::obituary::archived_log_listing),
        )
        .route(
            "/arsenals/obituary/:host_id/log-directory-sizes",
            post(routes::obituary::log_directory_sizes),
        )
        .route(
            "/arsenals/obituary/:host_id/vacuum-size/confirm",
            get(routes::obituary::vacuum_size_confirm),
        )
        .route(
            "/arsenals/obituary/:host_id/vacuum-size",
            post(routes::obituary::vacuum_by_size),
        )
        .route(
            "/arsenals/obituary/:host_id/vacuum-time/confirm",
            get(routes::obituary::vacuum_time_confirm),
        )
        .route(
            "/arsenals/obituary/:host_id/vacuum-time",
            post(routes::obituary::vacuum_by_time),
        )
        .route("/arsenals/reliquary", get(routes::reliquary::show))
        .route(
            "/arsenals/reliquary/:host_id",
            get(routes::reliquary::show_host),
        )
        .route(
            "/arsenals/reliquary/:host_id/list",
            post(routes::reliquary::list_backups),
        )
        .route(
            "/arsenals/reliquary/:host_id/verify",
            post(routes::reliquary::verify_backup),
        )
        .route(
            "/arsenals/reliquary/:host_id/create",
            post(routes::reliquary::create_backup),
        )
        .route(
            "/arsenals/reliquary/:host_id/restore/confirm",
            get(routes::reliquary::restore_confirm),
        )
        .route(
            "/arsenals/reliquary/:host_id/restore",
            post(routes::reliquary::restore_backup),
        )
        .route("/arsenals/mortiscope", get(routes::mortiscope::show))
        .route(
            "/arsenals/mortiscope/:host_id",
            get(routes::mortiscope::show_host),
        )
        .route(
            "/arsenals/mortiscope/:host_id/load-average",
            post(routes::mortiscope::load_average),
        )
        .route(
            "/arsenals/mortiscope/:host_id/top-cpu",
            post(routes::mortiscope::top_processes_by_cpu),
        )
        .route(
            "/arsenals/mortiscope/:host_id/top-memory",
            post(routes::mortiscope::top_processes_by_memory),
        )
        .route(
            "/arsenals/mortiscope/:host_id/memory-detail",
            post(routes::mortiscope::memory_detail),
        )
        .route(
            "/arsenals/mortiscope/:host_id/disk-io",
            post(routes::mortiscope::disk_io_stats),
        )
        .route(
            "/arsenals/mortiscope/:host_id/failed-services",
            post(routes::mortiscope::failed_services),
        )
        .route("/arsenals/incarnation", get(routes::incarnation::show))
        .route(
            "/arsenals/incarnation/:host_id",
            get(routes::incarnation::show_host),
        )
        .route(
            "/arsenals/incarnation/:host_id/list",
            post(routes::incarnation::list_services),
        )
        .route(
            "/arsenals/incarnation/:host_id/status",
            post(routes::incarnation::service_status),
        )
        .route(
            "/arsenals/incarnation/:host_id/logs",
            post(routes::incarnation::service_logs),
        )
        .route(
            "/arsenals/incarnation/:host_id/start",
            post(routes::incarnation::start_service),
        )
        .route(
            "/arsenals/incarnation/:host_id/enable",
            post(routes::incarnation::enable_service),
        )
        .route(
            "/arsenals/incarnation/:host_id/disable",
            post(routes::incarnation::disable_service),
        )
        .route(
            "/arsenals/incarnation/:host_id/stop/confirm",
            get(routes::incarnation::stop_confirm),
        )
        .route(
            "/arsenals/incarnation/:host_id/stop",
            post(routes::incarnation::stop_service),
        )
        .route(
            "/arsenals/incarnation/:host_id/restart/confirm",
            get(routes::incarnation::restart_confirm),
        )
        .route(
            "/arsenals/incarnation/:host_id/restart",
            post(routes::incarnation::restart_service),
        )
        .route("/arsenals/resurrection", get(routes::resurrection::show))
        .route(
            "/arsenals/resurrection/:host_id",
            get(routes::resurrection::show_host),
        )
        .route(
            "/arsenals/resurrection/:host_id/previous-boot-errors",
            post(routes::resurrection::previous_boot_errors),
        )
        .route(
            "/arsenals/resurrection/:host_id/system-state",
            post(routes::resurrection::system_running_state),
        )
        .route(
            "/arsenals/resurrection/:host_id/ro-filesystems",
            post(routes::resurrection::read_only_filesystems),
        )
        .route(
            "/arsenals/resurrection/:host_id/daemon-reload",
            post(routes::resurrection::reload_systemd_daemon),
        )
        .route(
            "/arsenals/resurrection/:host_id/reset-failed",
            post(routes::resurrection::reset_failed_units),
        )
        .route(
            "/arsenals/resurrection/:host_id/remount/confirm",
            get(routes::resurrection::remount_confirm),
        )
        .route(
            "/arsenals/resurrection/:host_id/remount",
            post(routes::resurrection::remount_read_write),
        )
        .route("/arsenals/necropsy", get(routes::necropsy::show))
        .route(
            "/arsenals/necropsy/:host_id",
            get(routes::necropsy::show_host),
        )
        .route(
            "/arsenals/necropsy/:host_id/cpu",
            post(routes::necropsy::cpu_info),
        )
        .route(
            "/arsenals/necropsy/:host_id/pci",
            post(routes::necropsy::pci_devices),
        )
        .route(
            "/arsenals/necropsy/:host_id/block-devices",
            post(routes::necropsy::block_devices),
        )
        .route(
            "/arsenals/necropsy/:host_id/memory-hardware",
            post(routes::necropsy::memory_hardware),
        )
        .route(
            "/arsenals/necropsy/:host_id/disk-health",
            post(routes::necropsy::disk_health),
        )
        .route("/arsenals/necropolis", get(routes::necropolis::show))
        .route(
            "/arsenals/necropolis/:host_id",
            get(routes::necropolis::show_host),
        )
        .route(
            "/arsenals/necropolis/:host_id/list",
            post(routes::necropolis::list_containers),
        )
        .route(
            "/arsenals/necropolis/:host_id/images",
            post(routes::necropolis::list_images),
        )
        .route(
            "/arsenals/necropolis/:host_id/info",
            post(routes::necropolis::runtime_info),
        )
        .route(
            "/arsenals/necropolis/:host_id/logs",
            post(routes::necropolis::container_logs),
        )
        .route(
            "/arsenals/necropolis/:host_id/inspect",
            post(routes::necropolis::container_inspect),
        )
        .route(
            "/arsenals/necropolis/:host_id/start",
            post(routes::necropolis::start_container),
        )
        .route(
            "/arsenals/necropolis/:host_id/stop/confirm",
            get(routes::necropolis::stop_confirm),
        )
        .route(
            "/arsenals/necropolis/:host_id/stop",
            post(routes::necropolis::stop_container),
        )
        .route(
            "/arsenals/necropolis/:host_id/restart/confirm",
            get(routes::necropolis::restart_confirm),
        )
        .route(
            "/arsenals/necropolis/:host_id/restart",
            post(routes::necropolis::restart_container),
        )
        .route(
            "/arsenals/necropolis/:host_id/remove/confirm",
            get(routes::necropolis::remove_confirm),
        )
        .route(
            "/arsenals/necropolis/:host_id/remove",
            post(routes::necropolis::remove_container),
        )
        .route("/arsenals/reanimation", get(routes::reanimation::show))
        .route(
            "/arsenals/reanimation/:host_id",
            get(routes::reanimation::show_host),
        )
        .route(
            "/arsenals/reanimation/:host_id/list",
            post(routes::reanimation::list_processes),
        )
        .route(
            "/arsenals/reanimation/:host_id/detail",
            post(routes::reanimation::process_detail),
        )
        .route(
            "/arsenals/reanimation/:host_id/renice",
            post(routes::reanimation::renice_priority),
        )
        .route(
            "/arsenals/reanimation/:host_id/signal/confirm",
            get(routes::reanimation::signal_confirm),
        )
        .route(
            "/arsenals/reanimation/:host_id/signal",
            post(routes::reanimation::send_signal),
        )
        .route("/arsenals/defleshing", get(routes::defleshing::show))
        .route(
            "/arsenals/defleshing/:host_id",
            get(routes::defleshing::show_host),
        )
        .route(
            "/arsenals/defleshing/:host_id/summary",
            post(routes::defleshing::cleanup_targets_summary),
        )
        .route(
            "/arsenals/defleshing/:host_id/rotate-logs",
            post(routes::defleshing::force_log_rotation),
        )
        .route(
            "/arsenals/defleshing/:host_id/clear-tmp/confirm",
            get(routes::defleshing::clear_tmp_confirm),
        )
        .route(
            "/arsenals/defleshing/:host_id/clear-tmp",
            post(routes::defleshing::clear_tmp_files),
        )
        .route(
            "/arsenals/defleshing/:host_id/clear-core-dumps/confirm",
            get(routes::defleshing::clear_core_dumps_confirm),
        )
        .route(
            "/arsenals/defleshing/:host_id/clear-core-dumps",
            post(routes::defleshing::clear_core_dumps),
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
