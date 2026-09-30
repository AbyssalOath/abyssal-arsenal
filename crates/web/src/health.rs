//! Control-plane self-health: the checks behind `/healthz` (liveness) and
//! `/readyz` (readiness), plus the shared report type the admin diagnostics
//! page (later milestones) reuses. Deliberately cheap and cached/aggregate --
//! a readiness probe must never block on slow work -- and it never leaks
//! secrets: the deep detail lives behind auth on the diagnostics page, these
//! endpoints stay coarse.

use std::time::Instant;

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::state::AppState;

/// One named component's health, with a short human detail string. `detail`
/// is safe to expose unauthenticated: latency, "applied N migrations", never a
/// connection string or secret.
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

impl ComponentHealth {
    fn up(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok: true,
            detail: detail.into(),
        }
    }

    fn down(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok: false,
            detail: detail.into(),
        }
    }
}

/// The aggregate readiness of the control plane: ready only when every
/// component is ok.
#[derive(Debug, Clone)]
pub struct Readiness {
    pub components: Vec<ComponentHealth>,
}

impl Readiness {
    pub fn from_components(components: Vec<ComponentHealth>) -> Self {
        Self { components }
    }

    /// Ready iff every component is ok. An empty report is trivially ready
    /// (nothing is known to be wrong), which only happens if no checks ran.
    pub fn ok(&self) -> bool {
        self.components.iter().all(|c| c.ok)
    }

    /// `200 OK` when ready, `503 Service Unavailable` when any component is
    /// down -- the contract an external monitor / load balancer / k8s probe
    /// expects.
    pub fn status_code(&self) -> StatusCode {
        if self.ok() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }

    pub fn to_json(&self) -> Value {
        let checks: Vec<Value> = self
            .components
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "status": if c.ok { "ok" } else { "down" },
                    "detail": c.detail,
                })
            })
            .collect();
        json!({
            "status": if self.ok() { "ok" } else { "degraded" },
            "checks": checks,
        })
    }
}

/// Times a `SELECT 1` against the pool. Cheap; the point is latency + "does the
/// database answer at all," not a schema check (that's `migrations_check`).
pub async fn database_check(pool: &abyssal_database::DbPool) -> ComponentHealth {
    let start = Instant::now();
    match sqlx::query("SELECT 1").execute(pool).await {
        Ok(_) => ComponentHealth::up("database", format!("{} ms", start.elapsed().as_millis())),
        Err(_) => ComponentHealth::down("database", "unreachable"),
    }
}

/// Confirms migrations ran cleanly by reading sqlx's own `_sqlx_migrations`
/// bookkeeping table: any row with `success = 0` means a migration was left
/// half-applied (a "dirty" database), which is a not-ready condition.
pub async fn migrations_check(pool: &abyssal_database::DbPool) -> ComponentHealth {
    let row: Result<(i64, i64, i64), _> = sqlx::query_as(
        "SELECT COUNT(*), \
                COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0), \
                COALESCE(MAX(version), 0) \
         FROM _sqlx_migrations",
    )
    .fetch_one(pool)
    .await;
    match row {
        Ok((total, 0, latest)) => {
            ComponentHealth::up("migrations", format!("{total} applied, latest {latest}"))
        }
        Ok((_, failed, _)) => {
            ComponentHealth::down("migrations", format!("{failed} migration(s) left dirty"))
        }
        Err(_) => ComponentHealth::down("migrations", "bookkeeping table unavailable"),
    }
}

/// Whether a Reliquary restore is currently holding the app in maintenance
/// mode -- ready is false for its duration (the database is deliberately
/// off-limits), but liveness (`/healthz`) stays up so an orchestrator doesn't
/// kill the container mid-restore.
fn maintenance_check(state: &AppState) -> ComponentHealth {
    if state.maintenance_mode.is_active() {
        ComponentHealth::down("maintenance", "restore in progress")
    } else {
        ComponentHealth::up("maintenance", "normal operation")
    }
}

/// The full readiness report: database reachability, migration cleanliness,
/// and maintenance state. Later milestones extend this with background-task
/// liveness.
pub async fn readiness(state: &AppState) -> Readiness {
    Readiness::from_components(vec![
        database_check(&state.pool).await,
        migrations_check(&state.pool).await,
        maintenance_check(state),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_is_ready() {
        let r = Readiness::from_components(vec![]);
        assert!(r.ok());
        assert_eq!(r.status_code(), StatusCode::OK);
    }

    #[test]
    fn all_ok_is_ready_200() {
        let r = Readiness::from_components(vec![
            ComponentHealth::up("database", "2 ms"),
            ComponentHealth::up("migrations", "29 applied, latest 29"),
        ]);
        assert!(r.ok());
        assert_eq!(r.status_code(), StatusCode::OK);
        assert_eq!(r.to_json()["status"], "ok");
    }

    #[test]
    fn any_down_is_degraded_503() {
        let r = Readiness::from_components(vec![
            ComponentHealth::up("database", "2 ms"),
            ComponentHealth::down("migrations", "1 migration(s) left dirty"),
        ]);
        assert!(!r.ok());
        assert_eq!(r.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.to_json()["status"], "degraded");
    }

    #[test]
    fn json_lists_every_component_with_status() {
        let r = Readiness::from_components(vec![
            ComponentHealth::up("database", "2 ms"),
            ComponentHealth::down("migrations", "dirty"),
        ]);
        let checks = r.to_json()["checks"].as_array().unwrap().clone();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0]["name"], "database");
        assert_eq!(checks[0]["status"], "ok");
        assert_eq!(checks[1]["status"], "down");
        assert_eq!(checks[1]["detail"], "dirty");
    }
}
