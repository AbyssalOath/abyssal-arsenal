//! The host picker on each arsenal's landing page (`/arsenals/<name>`).
//!
//! Every arsenal used to build its own list of *connected* hosts, so an
//! offline host just wasn't there and nothing said why, and the list showed
//! names only. This lists every enrolled host with its OS and whether it's
//! online; offline ones are shown (with when they were last seen) but not
//! linked, since their page can't run anything. It also decides when the
//! landing page can skip itself: a host already picked in the nav's host
//! switcher, or the fleet's one and only host.

use chrono::Utc;
use serde::Deserialize;

use abyssal_database::repo;

use crate::common::os_label;
use crate::state::AppState;

/// One host on an arsenal's landing page.
pub struct PickerHost {
    pub id: String,
    pub name: String,
    /// The control plane's own server: shown with a badge.
    pub is_control_plane: bool,
    pub online: bool,
    /// "Linux", "Windows", ... (`common::os_label`).
    pub os: &'static str,
    /// "5m ago", "3d ago" or "never", for an offline host's badge.
    pub last_seen: String,
}

/// `?all=1` on a landing page: always show the list, even when it would
/// otherwise go straight to a host. The host pages' "Back to host list"
/// links use it, so they don't bounce straight back to the same host.
#[derive(Debug, Default, Deserialize)]
pub struct PickerQuery {
    #[serde(default)]
    pub all: Option<String>,
}

impl PickerQuery {
    pub fn show_list(&self) -> bool {
        self.all.is_some()
    }
}

/// Every enrolled host (revoked and awaiting-approval ones left out),
/// online hosts first, then by name.
pub async fn hosts(state: &AppState) -> anyhow::Result<Vec<PickerHost>> {
    let now = Utc::now();
    let mut rows: Vec<PickerHost> = repo::hosts::list(&state.pool)
        .await?
        .into_iter()
        .filter(|h| h.is_active() && !h.pending_approval)
        .map(|h| PickerHost {
            online: state.hosts.is_connected(h.id),
            os: os_label(h.os.as_deref()),
            last_seen: match h.last_seen_at {
                Some(ts) => ago((now - ts).num_seconds().max(0)),
                None => "never".to_string(),
            },
            is_control_plane: h.is_control_plane,
            id: h.id.to_string(),
            name: h.name,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(rows)
}

/// The host to go straight to when the fleet is exactly one host and it's
/// online -- there's nothing to pick.
pub fn sole_online_host(hosts: &[PickerHost]) -> Option<&str> {
    match hosts {
        [only] if only.online => Some(&only.id),
        _ => None,
    }
}

/// A whole-seconds age to `"12s ago"` / `"4m ago"` / `"2h ago"` / `"3d ago"`.
fn ago(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3_600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3_600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, online: bool) -> PickerHost {
        PickerHost {
            id: format!("id-{name}"),
            name: name.to_string(),
            is_control_plane: false,
            online,
            os: "Linux",
            last_seen: "never".to_string(),
        }
    }

    #[test]
    fn goes_straight_to_a_sole_online_host() {
        assert_eq!(sole_online_host(&[host("a", true)]), Some("id-a"));
    }

    #[test]
    fn lists_when_the_only_host_is_offline_or_there_are_several() {
        assert_eq!(sole_online_host(&[]), None);
        assert_eq!(sole_online_host(&[host("a", false)]), None);
        assert_eq!(sole_online_host(&[host("a", true), host("b", false)]), None);
    }

    #[test]
    fn ages_read_compactly() {
        assert_eq!(ago(5), "5s ago");
        assert_eq!(ago(125), "2m ago");
        assert_eq!(ago(7_300), "2h ago");
        assert_eq!(ago(3 * 86_400 + 5), "3d ago");
    }

    #[test]
    fn show_list_only_with_all() {
        assert!(!PickerQuery::default().show_list());
        assert!(
            PickerQuery {
                all: Some("1".into())
            }
            .show_list()
        );
    }
}
