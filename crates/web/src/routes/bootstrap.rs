//! Public, unauthenticated bootstrap installers the control plane serves at
//! `/install.sh` and `/install.ps1`, so enrolling a new host can be a single
//! copy-paste line (see `crates/web/src/routes/hosts.rs`'s enrollment
//! banner) instead of a manual download-extract-run.
//!
//! These scripts carry **no secrets**: the control-plane URL and the agent
//! version are the only things baked in at render time (both already public
//! for anyone who can reach the login page), and the one-time enrollment
//! token is supplied by the operator as an argument at run time, never
//! embedded in the served text. That's why they're safe to serve without
//! authentication -- a machine being provisioned generally can't present a
//! browser session anyway. The script only ever downloads the pinned
//! GitHub release for the version stamped in by this control plane and runs
//! the agent's own `install`; the actual trust boundary (a valid,
//! single-use token) is enforced server-side at `/api/hosts/enroll`, the
//! same as every other enrollment path.

use std::path::PathBuf;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

fn control_plane_base_url(state: &AppState, headers: &HeaderMap) -> String {
    let scheme = if state.config.cookie_secure {
        "https"
    } else {
        "http"
    };
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    format!("{scheme}://{host}")
}

const INSTALL_SH_TEMPLATE: &str = r#"#!/bin/sh
# Abyssal Arsenal agent bootstrap installer (Linux).
#
# Downloads the agent release matching this control plane and runs its
# non-interactive `install` (enroll + systemd service). Needs root, so pipe
# it through sudo:
#
#   curl -fsSL __CONTROL_PLANE_URL__/install.sh | sudo sh -s -- --enrollment-token <token>
#
# Generate a token at __CONTROL_PLANE_URL__/admin/hosts (valid 15 minutes).
set -eu

CONTROL_PLANE_URL="__CONTROL_PLANE_URL__"
AGENT_VERSION="__AGENT_VERSION__"
ENROLLMENT_TOKEN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --enrollment-token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
    --enrollment-token=*) ENROLLMENT_TOKEN="${1#*=}"; shift ;;
    --control-plane-url) CONTROL_PLANE_URL="${2:-}"; shift 2 ;;
    --control-plane-url=*) CONTROL_PLANE_URL="${1#*=}"; shift ;;
    *) if [ -z "$ENROLLMENT_TOKEN" ]; then ENROLLMENT_TOKEN="$1"; fi; shift ;;
  esac
done

if [ -z "$ENROLLMENT_TOKEN" ]; then
  echo "error: no enrollment token given." >&2
  echo "Generate one at $CONTROL_PLANE_URL/admin/hosts, then:" >&2
  echo "  curl -fsSL $CONTROL_PLANE_URL/install.sh | sudo sh -s -- --enrollment-token <token>" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "error: this needs root -- pipe it through sudo:" >&2
  echo "  curl -fsSL $CONTROL_PLANE_URL/install.sh | sudo sh -s -- --enrollment-token <token>" >&2
  exit 1
fi

ARCH="$(uname -m)"
if [ "$ARCH" != "x86_64" ]; then
  echo "error: no agent build for architecture '$ARCH' (x86_64 only today)." >&2
  echo "Build and install from source instead -- see crates/agent/README.md." >&2
  exit 1
fi

# Downloaded from THIS control plane (not GitHub), so an internal/air-gapped
# network only needs to reach the control plane, and gets whatever agent build
# the control plane is serving. See the project README's agent-distribution note.
URL="$CONTROL_PLANE_URL/agent/linux"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading abyssal-agent from $CONTROL_PLANE_URL ..."
curl -fsSL -o "$TMP/agent.tar.gz" "$URL"
tar -xzf "$TMP/agent.tar.gz" -C "$TMP"
# Find the binary wherever it sits in the archive, so packaging layout can vary.
AGENT_BIN="$(find "$TMP" -type f -name abyssal-agent | head -n1)"
if [ -z "$AGENT_BIN" ]; then
  echo "error: abyssal-agent binary not found in the downloaded archive." >&2
  exit 1
fi
chmod +x "$AGENT_BIN"
echo "Installing..."
"$AGENT_BIN" install \
  --control-plane-url "$CONTROL_PLANE_URL" \
  --enrollment-token "$ENROLLMENT_TOKEN"
"#;

const INSTALL_PS1_TEMPLATE: &str = r#"#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Abyssal Arsenal agent bootstrap installer (Windows).
.DESCRIPTION
  Downloads the agent release matching this control plane and runs its
  install (enroll + LocalSystem service). Run from an elevated PowerShell:

    & ([scriptblock]::Create((irm __CONTROL_PLANE_URL__/install.ps1))) -EnrollmentToken <token>

  Generate a token at __CONTROL_PLANE_URL__/admin/hosts (valid 15 minutes).

  If this control plane uses a self-signed or internal-CA certificate (the
  default when you install behind Caddy without a public domain), import that
  certificate into this machine's "Trusted Root Certification Authorities"
  store FIRST -- otherwise both this `irm` download and the agent's own
  enrollment will fail with a TLS trust error. In an AD environment, push it
  via Group Policy (see the project README's "Reverse proxy / TLS" section).
  A publicly-trusted certificate (e.g. Let's Encrypt) needs no such step.
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$EnrollmentToken,
  [string]$ControlPlaneUrl = "__CONTROL_PLANE_URL__",
  [string]$Version = "__AGENT_VERSION__"
)
$ErrorActionPreference = "Stop"

if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
  throw "No published agent release for architecture '$($env:PROCESSOR_ARCHITECTURE)' (x64 only today). Build from source instead."
}

# Downloaded from THIS control plane (not GitHub), so an internal/air-gapped
# network only needs to reach the control plane, and gets whatever agent build
# the control plane is serving. See the project README's agent-distribution note.
$url = "$ControlPlaneUrl/agent/windows"
$tmp = Join-Path $env:TEMP ("abyssal-agent-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading abyssal-agent from $ControlPlaneUrl ..."
  Invoke-WebRequest -Uri $url -OutFile (Join-Path $tmp "agent.zip")
  Expand-Archive -Path (Join-Path $tmp "agent.zip") -DestinationPath $tmp -Force
  # Find the binary wherever it sits in the archive, so packaging layout can vary.
  $exe = Get-ChildItem -Path $tmp -Recurse -Filter abyssal-agent.exe | Select-Object -First 1
  if (-not $exe) { throw "abyssal-agent.exe not found in the downloaded archive." }
  Write-Host "Installing..."
  & $exe.FullName install --control-plane-url $ControlPlaneUrl --enrollment-token $EnrollmentToken
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
"#;

fn render_script(template: &str, base_url: &str) -> String {
    template.replace("__CONTROL_PLANE_URL__", base_url).replace(
        "__AGENT_VERSION__",
        crate::update_check::CURRENT_VERSION.trim(),
    )
}

/// `GET /install.sh` -- the Linux bootstrap one-liner's target.
pub async fn install_sh(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let base_url = control_plane_base_url(&state, &headers);
    let body = render_script(INSTALL_SH_TEMPLATE, &base_url);
    ([(CONTENT_TYPE, "text/x-shellscript; charset=utf-8")], body).into_response()
}

/// `GET /install.ps1` -- the Windows bootstrap one-liner's target.
pub async fn install_ps1(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let base_url = control_plane_base_url(&state, &headers);
    let body = render_script(INSTALL_PS1_TEMPLATE, &base_url);
    ([(CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

/// Directory the control plane serves agent binaries from (a Docker volume in
/// the default compose). Operators populate it with locally-built archives --
/// essential on internal/air-gapped networks that can't reach GitHub, and the
/// way to serve an agent built from a newer branch than the latest release.
fn agent_dist_dir() -> PathBuf {
    std::env::var("AGENT_DIST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/agent-dist"))
}

struct AgentAsset {
    /// The release-style filename (also where a GitHub fetch is cached).
    versioned: String,
    /// A version-agnostic name an operator can drop a local build under.
    generic: &'static str,
    content_type: &'static str,
}

fn agent_asset(os: &str, version: &str) -> Option<AgentAsset> {
    match os {
        "linux" => Some(AgentAsset {
            versioned: format!("abyssal-agent-v{version}-x86_64-unknown-linux-gnu.tar.gz"),
            generic: "abyssal-agent-linux.tar.gz",
            content_type: "application/gzip",
        }),
        "windows" => Some(AgentAsset {
            versioned: format!("abyssal-agent-v{version}-x86_64-pc-windows-msvc.zip"),
            generic: "abyssal-agent-windows.zip",
            content_type: "application/zip",
        }),
        _ => None,
    }
}

fn serve_agent_bytes(bytes: Vec<u8>, asset: &AgentAsset) -> Response {
    (
        [
            (CONTENT_TYPE, asset.content_type.to_string()),
            (
                CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", asset.versioned),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// `GET /agent/{os}` (os = `linux` | `windows`) -- serves the agent archive so a
/// host being enrolled downloads it from this control plane instead of GitHub.
/// This is what makes an internal/air-gapped rollout self-contained, and what
/// lets the control plane distribute an agent build newer than the latest
/// public release. Resolution order: an operator-placed archive in the dist dir
/// (version-agnostic name first, then the release name), else a best-effort
/// fetch from GitHub (cached for next time). Unauthenticated, like the install
/// scripts -- the binary is non-secret; the enrollment token is the secret.
pub async fn serve_agent(Path(os): Path<String>) -> Response {
    let version = crate::update_check::CURRENT_VERSION.trim();
    let Some(asset) = agent_asset(&os, version) else {
        return (
            StatusCode::NOT_FOUND,
            "unknown agent OS -- use /agent/linux or /agent/windows",
        )
            .into_response();
    };

    let dir = agent_dist_dir();
    for name in [asset.generic.to_string(), asset.versioned.clone()] {
        if let Ok(bytes) = tokio::fs::read(dir.join(&name)).await {
            return serve_agent_bytes(bytes, &asset);
        }
    }

    // Not locally present: try GitHub once and cache it. Fails cleanly (not a
    // panic) when the control plane itself can't reach GitHub.
    let url = format!(
        "https://github.com/AbyssalOath/abyssal-arsenal/releases/download/v{version}/{}",
        asset.versioned
    );
    let fetched = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status);
    if let Ok(resp) = fetched
        && let Ok(bytes) = resp.bytes().await
    {
        let _ = tokio::fs::create_dir_all(&dir).await;
        let _ = tokio::fs::write(dir.join(&asset.versioned), &bytes).await;
        return serve_agent_bytes(bytes.to_vec(), &asset);
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!(
            "agent binary unavailable. Place a build at {}/{} (or {}), or give this \
             control plane outbound access to GitHub.",
            dir.display(),
            asset.generic,
            asset.versioned
        ),
    )
        .into_response()
}
