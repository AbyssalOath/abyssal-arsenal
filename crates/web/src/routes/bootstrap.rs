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

use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
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
  echo "error: no published agent release for architecture '$ARCH' (x86_64 only today)." >&2
  echo "Build and install from source instead -- see crates/agent/README.md." >&2
  exit 1
fi

ASSET="abyssal-agent-v${AGENT_VERSION}-x86_64-unknown-linux-gnu"
URL="https://github.com/AbyssalOath/abyssal-arsenal/releases/download/v${AGENT_VERSION}/${ASSET}.tar.gz"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading abyssal-agent v${AGENT_VERSION}..."
curl -fsSL -o "$TMP/agent.tar.gz" "$URL"
tar -xzf "$TMP/agent.tar.gz" -C "$TMP"
echo "Installing..."
"$TMP/${ASSET}/abyssal-agent" install \
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

$asset = "abyssal-agent-v$Version-x86_64-pc-windows-msvc"
$url = "https://github.com/AbyssalOath/abyssal-arsenal/releases/download/v$Version/$asset.zip"
$tmp = Join-Path $env:TEMP ("abyssal-agent-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading abyssal-agent v$Version..."
  Invoke-WebRequest -Uri $url -OutFile (Join-Path $tmp "agent.zip")
  Expand-Archive -Path (Join-Path $tmp "agent.zip") -DestinationPath $tmp -Force
  Write-Host "Installing..."
  & (Join-Path $tmp "$asset\abyssal-agent.exe") install --control-plane-url $ControlPlaneUrl --enrollment-token $EnrollmentToken
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
"#;

fn render_script(template: &str, base_url: &str) -> String {
    template
        .replace("__CONTROL_PLANE_URL__", base_url)
        .replace("__AGENT_VERSION__", crate::update_check::CURRENT_VERSION.trim())
}

/// `GET /install.sh` -- the Linux bootstrap one-liner's target.
pub async fn install_sh(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let base_url = control_plane_base_url(&state, &headers);
    let body = render_script(INSTALL_SH_TEMPLATE, &base_url);
    (
        [(CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        body,
    )
        .into_response()
}

/// `GET /install.ps1` -- the Windows bootstrap one-liner's target.
pub async fn install_ps1(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let base_url = control_plane_base_url(&state, &headers);
    let body = render_script(INSTALL_PS1_TEMPLATE, &base_url);
    ([(CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}
