//! Cadavault's posture report (docs/roadmap/0.2.4.md, section 1): the
//! check-by-check report for one host, its CSV export, and the fleet view.
//! Running the checks is `crate::posture_ops`; the checks themselves are the
//! `abyssal-posture` catalog.

use std::collections::{BTreeMap, HashMap, HashSet};

use abyssal_agent_protocol::{AgentOperation, SshHardeningSetting};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_posture::{Fix, Status};
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, CadavaultPostureFleetTemplate, CadavaultPostureTemplate, PostureCheckRow,
    PostureFilterTab, PostureFixLink, PostureFleetHostRow, PostureRunLink, PostureTopCheckRow,
};
use crate::theme;

#[derive(Debug, Default, Deserialize)]
pub struct ReportQuery {
    /// failed, passed, na or all.
    #[serde(default)]
    status: String,
    #[serde(default)]
    q: String,
    /// A past run to show instead of the newest.
    #[serde(default)]
    run: Option<Uuid>,
    /// Why the last run didn't happen, carried over the redirect.
    #[serde(default)]
    error: Option<String>,
}

fn status_badge(status: Status) -> &'static str {
    match status {
        Status::Passed => "badge-success",
        Status::Failed => "badge-danger",
        Status::NotApplicable => "badge-muted",
    }
}

fn score_badge(score: Option<u8>) -> &'static str {
    match score {
        Some(80..) => "badge-success",
        Some(50..) => "badge-warning",
        Some(_) => "badge-danger",
        None => "badge-muted",
    }
}

/// `T1110.001` -> `https://attack.mitre.org/techniques/T1110/001/`.
fn mitre_url(technique: &str) -> String {
    format!(
        "https://attack.mitre.org/techniques/{}/",
        technique.replace('.', "/")
    )
}

/// The page's link to an existing Cadavault action for `fix`, and why it
/// would be refused on the control plane's own server, if it would.
fn fix_link(state: &AppState, host_id: Uuid, fix: Fix) -> (Option<PostureFixLink>, Option<String>) {
    let (link, op) = match fix {
        Fix::SshHardening(setting) => {
            let Some(parsed) = SshHardeningSetting::from_wire(setting) else {
                return (None, None);
            };
            (
                PostureFixLink {
                    label: format!("Apply with Cadavault: {}", parsed.label()),
                    href: format!(
                        "/arsenals/cadavault/{host_id}/harden-sshd/confirm?setting={setting}"
                    ),
                    post: false,
                },
                Some(AgentOperation::HardenSshd { setting: parsed }),
            )
        }
        Fix::FirewallEnable => (
            PostureFixLink {
                label: "Enable the firewall with Cadavault".to_string(),
                href: format!("/arsenals/cadavault/{host_id}/firewall-enable/confirm"),
                post: false,
            },
            Some(AgentOperation::FirewallEnable),
        ),
        Fix::SysctlBaseline => (
            PostureFixLink {
                label: "Open the kernel parameter baseline (Apply per setting)".to_string(),
                href: format!("/arsenals/cadavault/{host_id}/sysctl-posture"),
                post: true,
            },
            None,
        ),
    };
    let refused = op.and_then(|op| crate::control_plane::refusal(&state.hosts, host_id, &op));
    (Some(link), refused)
}

/// `GET /arsenals/cadavault/{host}/posture`: the newest run (or `?run=`).
pub async fn report(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let tz = &ctx.user.timezone;

    let history = repo::posture::runs_for_host(&state.pool, host_id, 30).await?;
    let current_index = match query.run {
        Some(id) => history.iter().position(|r| r.id == id),
        None => (!history.is_empty()).then_some(0),
    };
    let current = current_index.map(|i| &history[i]);
    let previous = current_index.and_then(|i| history.get(i + 1));

    let results = match current {
        Some(run) => repo::posture::results(&state.pool, run.id).await?,
        None => Vec::new(),
    };
    let previous_failed: HashSet<String> = match previous {
        Some(run) => repo::posture::results(&state.pool, run.id)
            .await?
            .into_iter()
            .filter(|r| r.status == "failed")
            .map(|r| r.check_id)
            .collect(),
        None => HashSet::new(),
    };
    let current_failed: HashSet<&str> = results
        .iter()
        .filter(|r| r.status == "failed")
        .map(|r| r.check_id.as_str())
        .collect();

    // What changed since the run before this one.
    let change = previous.map(|prev| {
        let newly: Vec<&str> = {
            let mut v: Vec<&str> = current_failed
                .iter()
                .copied()
                .filter(|id| !previous_failed.contains(*id))
                .collect();
            v.sort_unstable();
            v
        };
        let fixed: Vec<&str> = {
            let mut v: Vec<&str> = previous_failed
                .iter()
                .map(String::as_str)
                .filter(|id| !current_failed.contains(id))
                .collect();
            v.sort_unstable();
            v
        };
        let score = match (current.and_then(|c| c.score), prev.score) {
            (Some(now), Some(then)) if now != then => {
                format!("score {then}% → {now}%")
            }
            _ => "score unchanged".to_string(),
        };
        let mut parts = vec![score];
        if !newly.is_empty() {
            parts.push(format!("newly failing: {}", newly.join(", ")));
        }
        if !fixed.is_empty() {
            parts.push(format!("fixed: {}", fixed.join(", ")));
        }
        format!(
            "Since {}: {}.",
            crate::common::format_in_tz(prev.created_at, tz),
            parts.join("; ")
        )
    });

    let can_fix = ctx.has(Permission::SecurityManage);
    let mut rows: Vec<PostureCheckRow> = results
        .iter()
        .map(|r| {
            let status = Status::parse(&r.status).unwrap_or(Status::NotApplicable);
            let check = abyssal_posture::find(&r.check_id);
            let (fix, fix_refused) = match check.and_then(|c| c.fix) {
                Some(fix) if status == Status::Failed && can_fix => fix_link(&state, host_id, fix),
                _ => (None, None),
            };
            PostureCheckRow {
                id: r.check_id.clone(),
                title: check
                    .map(|c| c.title.to_string())
                    .unwrap_or_else(|| "(a check no longer in the catalog)".to_string()),
                category: check.map(|c| c.category).unwrap_or("").to_string(),
                status: status.as_str(),
                status_label: status.label(),
                badge: status_badge(status),
                evidence: r.evidence.clone(),
                rationale: check.map(|c| c.rationale).unwrap_or("").to_string(),
                remediation: check.map(|c| c.remediation).unwrap_or("").to_string(),
                command: check.and_then(|c| c.command).map(str::to_string),
                mitre: check
                    .map(|c| {
                        c.mitre
                            .iter()
                            .map(|t| (t.to_string(), mitre_url(t)))
                            .collect()
                    })
                    .unwrap_or_default(),
                fix,
                fix_refused,
                rank: status,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.rank.cmp(&b.rank).then_with(|| a.id.cmp(&b.id)));
    // Some facts weren't readable without root (an agent run by hand).
    let needs_root = rows
        .iter()
        .any(|r| r.status == "na" && r.evidence.contains("needs root"));

    let status_filter = match query.status.as_str() {
        "failed" | "passed" | "na" => query.status.as_str(),
        _ => "all",
    };
    let filter_href = |key: &str| {
        let mut params = form_urlencoded::Serializer::new(String::new());
        if key != "all" {
            params.append_pair("status", key);
        }
        if !query.q.trim().is_empty() {
            params.append_pair("q", query.q.trim());
        }
        if let Some(run) = query.run {
            params.append_pair("run", &run.to_string());
        }
        let params = params.finish();
        format!(
            "/arsenals/cadavault/{host_id}/posture{}",
            if params.is_empty() {
                String::new()
            } else {
                format!("?{params}")
            }
        )
    };
    let filter_tabs = [
        ("all", "All"),
        ("failed", "Failed"),
        ("passed", "Passed"),
        ("na", "Not applicable"),
    ]
    .into_iter()
    .map(|(key, label)| PostureFilterTab {
        label,
        count: rows
            .iter()
            .filter(|r| key == "all" || r.status == key)
            .count(),
        active: key == status_filter,
        href: filter_href(key),
    })
    .collect();
    let needle = query.q.trim().to_lowercase();
    rows.retain(|r| status_filter == "all" || r.status == status_filter);
    if !needle.is_empty() {
        rows.retain(|r| {
            [&r.id, &r.title, &r.category, &r.evidence]
                .iter()
                .any(|f| f.to_lowercase().contains(&needle))
        });
    }

    let runs = history
        .iter()
        .map(|r| PostureRunLink {
            href: format!("/arsenals/cadavault/{host_id}/posture?run={}", r.id),
            when: crate::common::format_in_tz(r.created_at, tz),
            by: r.started_by.clone(),
            score: r
                .score
                .map(|s| format!("{s}%"))
                .unwrap_or_else(|| "—".into()),
            current: current.is_some_and(|c| c.id == r.id),
        })
        .collect();

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
    let needs_update = state.hosts.is_connected(host_id)
        && !state.hosts.supports(host_id, &AgentOperation::PostureFacts);
    let tpl = CadavaultPostureTemplate {
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        platform: current.map(|r| r.platform.clone()).unwrap_or_default(),
        has_run: current.is_some(),
        run_id: current.map(|r| r.id.to_string()).unwrap_or_default(),
        run_when: current
            .map(|r| crate::common::format_in_tz(r.created_at, tz))
            .unwrap_or_default(),
        run_by: current.map(|r| r.started_by.clone()).unwrap_or_default(),
        viewing_latest: current_index == Some(0),
        score: current
            .and_then(|r| r.score)
            .map(|s| format!("{s}%"))
            .unwrap_or_else(|| "—".into()),
        score_badge: score_badge(current.and_then(|r| r.score)),
        passed: current.map(|r| r.passed).unwrap_or(0),
        failed: current.map(|r| r.failed).unwrap_or(0),
        not_applicable: current.map(|r| r.not_applicable).unwrap_or(0),
        change,
        filter_tabs,
        status_filter: status_filter.to_string(),
        q: query.q.clone(),
        run_query: query.run.map(|r| r.to_string()).unwrap_or_default(),
        rows,
        runs,
        needs_root,
        online: state.hosts.is_connected(host_id),
        needs_update,
        control_plane: crate::control_plane::page_note(&state.hosts, host_id),
        error: query.error.filter(|e| !e.is_empty()),
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RunForm {
    csrf_token: String,
}

/// `POST /arsenals/cadavault/{host}/posture`: runs the checks now, then
/// shows the report.
pub async fn run(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RunForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let target =
        match crate::posture_ops::run(&state, &host, crate::posture_ops::RunBy::User(&ctx)).await {
            Ok(_) => format!("/arsenals/cadavault/{host_id}/posture"),
            Err(e) => {
                let mut params = form_urlencoded::Serializer::new(String::new());
                params.append_pair("error", &e);
                format!("/arsenals/cadavault/{host_id}/posture?{}", params.finish())
            }
        };
    Ok(Redirect::to(&target).into_response())
}

/// Quotes a CSV field, and defuses spreadsheet formulas (a cell starting
/// with `=`, `+`, `-` or `@` would otherwise run when opened).
fn csv_field(value: &str) -> String {
    let value = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// `GET /arsenals/cadavault/{host}/posture/{run}/csv`: one run's results.
pub async fn csv(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
    Path((host_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    let run = repo::posture::find_run(&state.pool, run_id)
        .await?
        .filter(|r| r.host_id == host_id)
        .ok_or(AppError::NotFound)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mut results = repo::posture::results(&state.pool, run_id).await?;
    results.sort_by(|a, b| a.check_id.cmp(&b.check_id));
    let mut out =
        String::from("host,run_time,check_id,category,title,status,evidence,remediation,mitre\r\n");
    let when = run.created_at.to_rfc3339();
    for r in &results {
        let check = abyssal_posture::find(&r.check_id);
        let fields = [
            host.name.as_str(),
            when.as_str(),
            r.check_id.as_str(),
            check.map(|c| c.category).unwrap_or(""),
            check.map(|c| c.title).unwrap_or(""),
            r.status.as_str(),
            r.evidence.as_str(),
            check.map(|c| c.remediation).unwrap_or(""),
            &check.map(|c| c.mitre.join(" ")).unwrap_or_default(),
        ];
        out.push_str(
            &fields
                .iter()
                .map(|f| csv_field(f))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    let safe_name: String = host
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = format!(
        "posture-{safe_name}-{}.csv",
        run.created_at.format("%Y%m%d-%H%M")
    );
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        out,
    )
        .into_response())
}

/// `GET /arsenals/cadavault/posture`: every host's newest score and trend,
/// and the checks failing on the most hosts.
pub async fn fleet(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    let tz = &ctx.user.timezone;
    let hosts: HashMap<Uuid, abyssal_core::Host> = repo::hosts::list(&state.pool)
        .await?
        .into_iter()
        .filter(|h| h.is_active())
        .map(|h| (h.id, h))
        .collect();

    // Newest and previous run per host (rows come newest first per host).
    let mut by_host: BTreeMap<Uuid, Vec<repo::posture::Run>> = BTreeMap::new();
    for run in repo::posture::latest_two_per_host(&state.pool).await? {
        if hosts.contains_key(&run.host_id) {
            by_host.entry(run.host_id).or_default().push(run);
        }
    }
    let latest_ids: Vec<Uuid> = by_host.values().map(|runs| runs[0].id).collect();
    let run_host: HashMap<Uuid, Uuid> = by_host.iter().map(|(h, runs)| (runs[0].id, *h)).collect();

    let mut failing: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
    for (run_id, check_id) in repo::posture::failed_in_runs(&state.pool, &latest_ids).await? {
        if let Some(host_id) = run_host.get(&run_id) {
            failing.entry(check_id).or_default().push(*host_id);
        }
    }
    let host_name = |id: &Uuid| hosts.get(id).map(|h| h.name.clone()).unwrap_or_default();
    let mut top_failing: Vec<PostureTopCheckRow> = failing
        .into_iter()
        .map(|(check_id, host_ids)| {
            let check = abyssal_posture::find(&check_id);
            let mut on: Vec<(String, String)> = host_ids
                .iter()
                .map(|id| {
                    (
                        host_name(id),
                        format!("/arsenals/cadavault/{id}/posture?status=failed&q={check_id}"),
                    )
                })
                .collect();
            on.sort();
            PostureTopCheckRow {
                title: check.map(|c| c.title).unwrap_or("").to_string(),
                count: on.len(),
                hosts: on,
                id: check_id,
            }
        })
        .collect();
    top_failing.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.id.cmp(&b.id)));
    top_failing.truncate(25);

    let mut rows: Vec<PostureFleetHostRow> = by_host
        .iter()
        .map(|(host_id, runs)| {
            let latest = &runs[0];
            let trend = match (latest.score, runs.get(1).and_then(|r| r.score)) {
                (Some(now), Some(then)) if now > then => format!("▲ {}", now - then),
                (Some(now), Some(then)) if now < then => format!("▼ {}", then - now),
                (Some(_), Some(_)) => "—".to_string(),
                _ => String::new(),
            };
            PostureFleetHostRow {
                href: format!("/arsenals/cadavault/{host_id}/posture"),
                name: host_name(host_id),
                platform: latest.platform.clone(),
                score: latest
                    .score
                    .map(|s| format!("{s}%"))
                    .unwrap_or_else(|| "—".into()),
                score_value: latest.score.map(i32::from).unwrap_or(-1),
                score_badge: score_badge(latest.score),
                trend,
                passed: latest.passed,
                failed: latest.failed,
                not_applicable: latest.not_applicable,
                when: crate::common::format_in_tz(latest.created_at, tz),
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        a.score_value
            .cmp(&b.score_value)
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut never_run: Vec<(String, String)> = hosts
        .values()
        .filter(|h| !by_host.contains_key(&h.id) && !h.pending_approval)
        .map(|h| {
            (
                h.name.clone(),
                format!("/arsenals/cadavault/{}/posture", h.id),
            )
        })
        .collect();
    never_run.sort();

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
    let tpl = CadavaultPostureFleetTemplate {
        base,
        hosts: rows,
        top_failing,
        never_run,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_are_quoted_and_formulas_defused() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "\"'=cmd|' /C calc'!A0\"");
        assert_eq!(csv_field("-1"), "\"'-1\"");
    }
}
