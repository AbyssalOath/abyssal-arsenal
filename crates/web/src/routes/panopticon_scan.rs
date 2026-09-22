//! Discovery scan progress: a scan started from `routes/panopticon.rs
//! ::scan` runs as a detached background job (`panopticon_ops::
//! run_scan_job`) instead of blocking that request, so this module gives
//! the browser something to watch while it's in progress -- a
//! server-rendered progress page (`scan_status`, with a `<meta
//! http-equiv="refresh">` fallback), a small JS-polled JSON endpoint
//! (`scan_status_json` -- one of only two pages in this app with any
//! client-side JavaScript, the other being the SSH deploy status page in
//! `routes/panopticon_deploy.rs`; both are deliberate, scoped exceptions
//! to the rest of the app's server-rendered-only house style), and the
//! results page once the job finishes (`scan_view`, which reproduces
//! exactly what `scan()` used to render inline before the progress bar
//! existed: the "Quick Add Host" picker when there's something to add,
//! otherwise the plain dashboard with the scan's output or error).

use std::sync::atomic::Ordering;

use abyssal_core::{AppError, Permission};
use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde_json::json;
use uuid::Uuid;

use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::panopticon_ops::ScanJobStatus;
use crate::state::AppState;
use crate::templates::{BaseCtx, PanopticonScanProgressTemplate};
use crate::theme;

pub async fn scan_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(job_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkScan)?;

    let job = state
        .scan_jobs
        .read()
        .await
        .get(&job_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let snapshot = job.read().await;

    // Once the job leaves Running, this page has nothing left to poll for
    // -- send anyone who lands here (a stale bookmark, a `<meta refresh>`
    // firing after the JS side already moved on) straight to the results
    // instead of re-rendering a progress bar stuck at 100%.
    if snapshot.status != ScanJobStatus::Running {
        return Ok(
            Redirect::to(&format!("/arsenals/panopticon/scan/status/{job_id}/view"))
                .into_response(),
        );
    }

    let target = snapshot.target.clone();
    let percent = snapshot.percent();
    let hosts_scanned = snapshot.hosts_scanned.load(Ordering::Relaxed);
    let hosts_total = snapshot.hosts_total;
    drop(snapshot);

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(
        &ctx,
        &theme::current(&jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(&jar),
    )
    .await?;

    let tpl = PanopticonScanProgressTemplate {
        base,
        job_id: job_id.to_string(),
        target,
        percent,
        hosts_scanned,
        hosts_total,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Polled by the progress page's own `<script>` -- the only JSON endpoint
/// in this arsenal, and the only page in the whole app with client-side
/// JS consuming it (see this module's doc comment).
pub async fn scan_status_json(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
    Path(job_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkScan)?;

    let job = state
        .scan_jobs
        .read()
        .await
        .get(&job_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let snapshot = job.read().await;
    let status = match snapshot.status {
        ScanJobStatus::Running => "running",
        ScanJobStatus::Complete => "complete",
        ScanJobStatus::Failed => "failed",
    };

    Ok(Json(json!({
        "percent": snapshot.percent(),
        "hosts_scanned": snapshot.hosts_scanned.load(Ordering::Relaxed),
        "hosts_total": snapshot.hosts_total,
        "status": status,
    })))
}

/// Renders a completed (or failed) job's results -- reproduces exactly
/// what `routes/panopticon.rs::scan` used to render inline before scans
/// ran as background jobs: the "Quick Add Host" picker when there's a
/// `hosts.manage`-permitted admin and at least one discovered device,
/// otherwise the plain Panopticon dashboard with the scan's output or
/// error. Redirects back to the progress page for a job that's still
/// running, so this URL is safe to hit directly (e.g. a bookmark) at any
/// point in the job's life.
pub async fn scan_view(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(job_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkScan)?;

    let job = state
        .scan_jobs
        .read()
        .await
        .get(&job_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let snapshot = job.read().await;

    match snapshot.status {
        ScanJobStatus::Running => {
            Ok(Redirect::to(&format!("/arsenals/panopticon/scan/status/{job_id}")).into_response())
        }
        ScanJobStatus::Complete => {
            let discovered = snapshot.discovered.clone();
            let result_label = snapshot.result_label.clone();
            let result_output = snapshot.result_output.clone();
            let rescan_notice = snapshot.rescan_notice.clone();
            drop(snapshot);
            if ctx.has(Permission::HostsManage) && !discovered.is_empty() {
                return super::panopticon_deploy::render_scan_picker_from_discovered(
                    &state,
                    &jar,
                    &ctx,
                    discovered,
                    rescan_notice,
                )
                .await;
            }
            super::panopticon::render(&state, &jar, &ctx, None, result_label, result_output, None)
                .await
        }
        ScanJobStatus::Failed => {
            let result_label = snapshot.result_label.clone();
            let result_error = snapshot.result_error.clone();
            drop(snapshot);
            super::panopticon::render(&state, &jar, &ctx, None, result_label, None, result_error)
                .await
        }
    }
}
