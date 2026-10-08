//! Checks GitHub's releases API for a newer tagged release than this
//! build's own version, so the dashboard can show an update-available
//! notice without every page load reaching out to GitHub. Read-only and
//! best-effort: a failed check (offline, rate-limited, no network egress
//! allowed) just leaves the last-known status in place, never blocks or
//! errors anything else in the app.

use std::time::Duration;

use serde::Deserialize;

use crate::state::AppState;

/// This build's own version, embedded at compile time from the repository
/// root's `VERSION` file -- the single source of truth `install.sh`, the
/// release workflow, and this check all read from, rather than each
/// keeping their own copy in sync by hand.
pub const CURRENT_VERSION: &str = include_str!("../../../VERSION");

const GITHUB_RELEASES_API: &str =
    "https://api.github.com/repos/AbyssalOath/abyssal-arsenal/releases/latest";
/// Hourly: a release shows up on the dashboard within the hour, well inside
/// GitHub's 60-requests-an-hour limit for unauthenticated calls. "Check now"
/// on the dashboard (`check_now`) covers the rest.
const CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// What the dashboard's update notice needs. `latest_version` and
/// `release_url` stay `None` until the first successful check completes
/// (or forever, if this control plane has no outbound network access --
/// the notice just shows the current version alone in that case).
#[derive(Clone, Debug, Default)]
pub struct UpdateStatus {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub release_url: Option<String>,
    /// When the last check finished, successfully or not.
    pub checked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Why the last check failed (no outbound access, rate limit, ...);
    /// `None` after a success.
    pub last_error: Option<String>,
}

impl UpdateStatus {
    pub fn current() -> Self {
        Self {
            current_version: CURRENT_VERSION.trim().to_string(),
            latest_version: None,
            release_url: None,
            checked_at: None,
            last_error: None,
        }
    }

    /// True only once a newer release has actually been confirmed -- never
    /// true just because the check hasn't run yet or failed.
    pub fn update_available(&self) -> bool {
        let (Some(latest), Some(current)) = (
            self.latest_version.as_deref().and_then(parse_version),
            parse_version(&self.current_version),
        ) else {
            return false;
        };
        latest > current
    }
}

/// Parses `"v1.2.3"` or `"1.2.3"` into a comparable `(major, minor, patch)`
/// tuple. Anything else (a pre-release suffix, a malformed tag) is treated
/// as unparseable rather than guessed at.
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
}

async fn fetch_latest_release() -> anyhow::Result<GithubRelease> {
    let client = reqwest::Client::builder()
        .user_agent("abyssal-arsenal-update-check")
        .timeout(REQUEST_TIMEOUT)
        .build()?;
    let release = client
        .get(GITHUB_RELEASES_API)
        .send()
        .await?
        .error_for_status()?
        .json::<GithubRelease>()
        .await?;
    Ok(release)
}

/// Runs one check and records the result. A failure keeps the last-known
/// release (and says why it failed) rather than clearing it.
pub async fn check_now(state: &AppState) -> anyhow::Result<()> {
    let result = fetch_latest_release().await;
    let mut status = state.update_status.write().await;
    status.checked_at = Some(chrono::Utc::now());
    match result {
        Ok(release) => {
            status.latest_version = Some(release.tag_name);
            status.release_url = Some(release.html_url);
            status.last_error = None;
            Ok(())
        }
        Err(e) => {
            status.last_error = Some(format!("{e:#}"));
            Err(e)
        }
    }
}

/// Spawns the periodic check -- same shape as `thanatos_ops::spawn_thanatos_sweep`
/// and `health_ops::spawn_health_sweep`, except this one talks to GitHub
/// instead of an enrolled host, and checks once immediately on startup
/// rather than waiting a full interval first.
pub fn spawn_update_check_sweep(state: AppState) {
    use crate::task_health::names;
    let interval_secs = CHECK_INTERVAL.as_secs();
    tokio::spawn(async move {
        state
            .task_health
            .register(names::UPDATE_CHECK_SWEEP, interval_secs)
            .await;
        loop {
            match check_now(&state).await {
                Ok(()) => {
                    state
                        .task_health
                        .ok(names::UPDATE_CHECK_SWEEP, interval_secs)
                        .await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "update check failed, keeping last-known status");
                    state
                        .task_health
                        .error(names::UPDATE_CHECK_SWEEP, interval_secs, e.to_string())
                        .await;
                }
            }
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_with_and_without_v_prefix() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn rejects_malformed_versions() {
        assert_eq!(parse_version("not-a-version"), None);
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.x"), None);
    }

    #[test]
    fn no_update_when_versions_match() {
        let status = UpdateStatus {
            current_version: "0.1.0".to_string(),
            latest_version: Some("v0.1.0".to_string()),
            release_url: Some("https://example.com".to_string()),
            ..Default::default()
        };
        assert!(!status.update_available());
    }

    #[test]
    fn update_available_when_latest_is_newer() {
        let status = UpdateStatus {
            current_version: "0.1.0".to_string(),
            latest_version: Some("v0.2.0".to_string()),
            release_url: Some("https://example.com".to_string()),
            ..Default::default()
        };
        assert!(status.update_available());
    }

    #[test]
    fn no_update_when_latest_is_older_or_equal() {
        let status = UpdateStatus {
            current_version: "1.5.0".to_string(),
            latest_version: Some("v1.4.9".to_string()),
            release_url: Some("https://example.com".to_string()),
            ..Default::default()
        };
        assert!(!status.update_available());
    }

    #[test]
    fn no_update_when_check_has_not_run_yet() {
        let status = UpdateStatus::current();
        assert!(status.latest_version.is_none());
        assert!(!status.update_available());
    }
}
