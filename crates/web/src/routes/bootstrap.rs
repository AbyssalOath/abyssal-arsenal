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
//! browser session anyway. The script only ever downloads the agent build
//! this control plane serves and runs the agent's own `install`; the actual
//! trust boundary (a valid token) is enforced server-side at
//! `/api/hosts/enroll`, the same as every other enrollment path.
//!
//! The control plane's internal CA certificate (`/ca.crt`, see
//! `crate::public_ca`) is served here too. A host fetches it before it
//! trusts this server, so the scripts fetch it without validating the
//! connection -- and then refuse it unless it matches the fingerprint the
//! admin copied from `/admin/hosts`. That's the only request ever made with
//! validation relaxed, and the agent itself never relaxes it.

use std::path::PathBuf;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

fn control_plane_base_url(state: &AppState, headers: &HeaderMap) -> String {
    crate::common::request_base_url(state, headers)
}

const INSTALL_SH_TEMPLATE: &str = r#"#!/bin/sh
# Abyssal Arsenal agent bootstrap installer (Linux).
#
# Downloads the agent from this control plane and runs its non-interactive
# `install` (enroll + systemd service). Needs root. Copy the exact command
# from __CONTROL_PLANE_URL__/admin/hosts -- for a control plane with an
# internal (self-signed) CA it first fetches the CA, checks it against the
# fingerprint shown there, and passes it here with --ca-cert/--ca-fingerprint.
#
# Usage: install.sh [options]
#   --enrollment-token TOKEN     or ABYSSAL_ENROLLMENT_TOKEN in the environment,
#   --enrollment-token-file F    or the token in a file (keeps it out of `ps`)
#   --control-plane-url URL      default: __CONTROL_PLANE_URL__
#   --ca-cert FILE               PEM CA the control plane's cert chains to
#   --ca-fingerprint SHA256      expected CA fingerprint (from /admin/hosts); with
#                                no --ca-cert, the CA is fetched from <url>/ca.crt
#                                and verified against it
#   --trust-system               also add the CA to the OS trust store (the
#                                agent doesn't need this; curl/browsers might)
#   --remove-trust               remove the CA from the OS trust store, then exit
#   --uninstall                  remove the agent service, binary, credentials
#                                and any OS trust added here, then exit
#
# Exit codes: 0 ok; 1 other; 2 bad arguments; 3 not root; 10 certificate not
# trusted; 11 server cert is a CA cert (CaUsedAsEndEntity); 12 cert name
# mismatch; 13 other certificate problem; 14 CA fingerprint mismatch;
# 20 enrollment token rejected; 21 host name already in use; 30 control plane
# unreachable; 40 service registration failed.
set -eu

CONTROL_PLANE_URL="__CONTROL_PLANE_URL__"
ENROLLMENT_TOKEN="${ABYSSAL_ENROLLMENT_TOKEN:-}"
TOKEN_FILE=""
CA_CERT=""
CA_FINGERPRINT=""
TRUST_SYSTEM=0
REMOVE_TRUST=0
UNINSTALL=0

DEBIAN_ANCHOR=/usr/local/share/ca-certificates/abyssal-arsenal-ca.crt
RHEL_ANCHOR=/etc/pki/ca-trust/source/anchors/abyssal-arsenal-ca.pem

say() { printf '%s\n' "$*"; }
# Errors go to stdout as well as being reflected in the exit code, so RMM
# tools that only capture stdout still show why.
fail() {
  code="$1"; shift
  say "ERROR: $*"
  say "Install failed (exit code $code)."
  exit "$code"
}

describe() {
  case "$1" in
    10) say "The control plane's certificate isn't trusted. Use the command from /admin/hosts (it includes --ca-fingerprint)." ;;
    11) say "The control plane serves a CA certificate as its server certificate. Re-run ./install.sh on the control plane to replace it, then use a fresh command from /admin/hosts." ;;
    12) say "The certificate doesn't cover $CONTROL_PLANE_URL. Use the exact IP/hostname the control plane's certificate was made for (its PUBLIC_URL)." ;;
    13) say "The control plane's certificate was rejected (expired or otherwise unusable). Check this host's clock, then /admin/health/tls on the control plane." ;;
    14) say "The CA fingerprint doesn't match. Don't continue: something may be intercepting traffic, or the control plane's CA was regenerated -- copy a fresh command from /admin/hosts." ;;
    20) say "The enrollment token is invalid, expired, already used, or revoked. Generate a new one at /admin/hosts." ;;
    21) say "A connected host already uses this name. Remove it at /admin/hosts or pass a different --name." ;;
    30) say "Could not reach $CONTROL_PLANE_URL from this host (DNS, routing, firewall?)." ;;
    40) say "Enrolled, but the systemd service couldn't be set up. Re-run this command; enrollment is skipped once it has succeeded." ;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --enrollment-token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
    --enrollment-token=*) ENROLLMENT_TOKEN="${1#*=}"; shift ;;
    --enrollment-token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
    --control-plane-url) CONTROL_PLANE_URL="${2:-}"; shift 2 ;;
    --control-plane-url=*) CONTROL_PLANE_URL="${1#*=}"; shift ;;
    --ca-cert) CA_CERT="${2:-}"; shift 2 ;;
    --ca-fingerprint) CA_FINGERPRINT="${2:-}"; shift 2 ;;
    --trust-system) TRUST_SYSTEM=1; shift ;;
    --remove-trust) REMOVE_TRUST=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,32p' "$0" 2>/dev/null || true; exit 0 ;;
    -*) fail 2 "unknown option: $1" ;;
    *) if [ -z "$ENROLLMENT_TOKEN" ]; then ENROLLMENT_TOKEN="$1"; fi; shift ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  fail 3 "this needs root -- run it with sudo (copy the command from $CONTROL_PLANE_URL/admin/hosts)."
fi

refresh_system_trust() {
  if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates >/dev/null
  elif command -v update-ca-trust >/dev/null 2>&1; then
    update-ca-trust extract
  fi
}

remove_trust() {
  removed=0
  for anchor in "$DEBIAN_ANCHOR" "$RHEL_ANCHOR"; do
    if [ -f "$anchor" ]; then rm -f "$anchor"; removed=1; fi
  done
  if [ "$removed" -eq 1 ]; then
    refresh_system_trust
    say "Removed the Abyssal Arsenal CA from the system trust store."
  else
    say "No Abyssal Arsenal CA found in the system trust store."
  fi
}

if [ "$REMOVE_TRUST" -eq 1 ]; then
  remove_trust
  exit 0
fi

if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now abyssal-agent 2>/dev/null || true
  rm -f /etc/systemd/system/abyssal-agent.service
  systemctl daemon-reload 2>/dev/null || true
  rm -f /usr/local/bin/abyssal-agent
  rm -rf /etc/abyssal-agent
  remove_trust
  say "abyssal-agent uninstalled. Remove the host at $CONTROL_PLANE_URL/admin/hosts too, if you haven't."
  exit 0
fi

if [ -n "$TOKEN_FILE" ]; then
  [ -r "$TOKEN_FILE" ] || fail 2 "cannot read --enrollment-token-file $TOKEN_FILE"
  ENROLLMENT_TOKEN="$(tr -d ' \r\n' < "$TOKEN_FILE")"
fi
if [ -z "$ENROLLMENT_TOKEN" ] && [ ! -f /etc/abyssal-agent/credentials.json ]; then
  fail 2 "no enrollment token given. Generate one at $CONTROL_PLANE_URL/admin/hosts and copy the command shown there."
fi

ARCH="$(uname -m)"
if [ "$ARCH" != "x86_64" ]; then
  fail 1 "no agent build for architecture '$ARCH' (x86_64 only today). Build and install from source instead -- see crates/agent/README.md."
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sha256_of_pem() {
  # SHA-256 of the certificate's DER bytes -- the same value /admin/hosts
  # and `openssl x509 -fingerprint -sha256` show.
  if command -v sha256sum >/dev/null 2>&1; then
    sed '/-----/d' "$1" | base64 -d 2>/dev/null | sha256sum | cut -c1-64 | tr 'a-f' 'A-F'
  else
    sed '/-----/d' "$1" | base64 -d 2>/dev/null | openssl dgst -sha256 -r | cut -c1-64 | tr 'a-f' 'A-F'
  fi
}

if [ -n "$CA_FINGERPRINT" ]; then
  want="$(printf '%s' "$CA_FINGERPRINT" | tr -d ': -' | tr 'a-f' 'A-F')"
  [ "${#want}" -eq 64 ] || fail 2 "--ca-fingerprint must be a SHA-256 fingerprint (64 hex digits)."
  if [ -z "$CA_CERT" ]; then
    # Fetching the CA can't validate the connection -- that's the point, it
    # isn't trusted yet. The bytes are compared against the pinned
    # fingerprint below before anything uses them.
    CA_CERT="$TMP/ca.pem"
    curl -fsSk -o "$CA_CERT" "$CONTROL_PLANE_URL/ca.crt" \
      || fail 30 "could not download $CONTROL_PLANE_URL/ca.crt"
  fi
  got="$(sha256_of_pem "$CA_CERT")"
  if [ "$got" != "$want" ]; then
    describe 14
    fail 14 "CA fingerprint mismatch: expected $want, got $got."
  fi
  say "CA certificate verified (SHA-256 $got)."
fi
if [ -n "$CA_CERT" ]; then
  [ -r "$CA_CERT" ] || fail 2 "cannot read --ca-cert $CA_CERT"
  # Our own copy: the caller's may sit in a temp dir that vanishes.
  cp "$CA_CERT" "$TMP/trusted-ca.pem"
  CA_CERT="$TMP/trusted-ca.pem"
fi

if [ "$TRUST_SYSTEM" -eq 1 ]; then
  [ -n "$CA_CERT" ] || fail 2 "--trust-system needs --ca-fingerprint (or --ca-cert)."
  if [ -d "$(dirname "$DEBIAN_ANCHOR")" ] && command -v update-ca-certificates >/dev/null 2>&1; then
    cp "$CA_CERT" "$DEBIAN_ANCHOR"
  elif [ -d "$(dirname "$RHEL_ANCHOR")" ] && command -v update-ca-trust >/dev/null 2>&1; then
    cp "$CA_CERT" "$RHEL_ANCHOR"
  else
    fail 1 "don't know how to update this distribution's trust store. (Not needed for the agent itself, which trusts the CA via --ca-cert.)"
  fi
  refresh_system_trust
  say "Added the CA to the system trust store (undo with --remove-trust)."
fi

# Downloaded from THIS control plane (not GitHub), so an internal/air-gapped
# network only needs to reach the control plane, and gets whatever agent build
# the control plane is serving. See the project README's agent-distribution note.
say "Downloading abyssal-agent from $CONTROL_PLANE_URL ..."
if [ -n "$CA_CERT" ]; then
  set -- --cacert "$CA_CERT"
else
  set --
fi
rc=0
curl -fsSL "$@" -o "$TMP/agent.tar.gz" "$CONTROL_PLANE_URL/agent/linux" || rc=$?
case "$rc" in
  0) ;;
  60|77) describe 10; fail 10 "TLS: the control plane's certificate isn't trusted (curl exit $rc)." ;;
  51) describe 12; fail 12 "TLS: the certificate doesn't match $CONTROL_PLANE_URL (curl exit $rc)." ;;
  35|58|59|83|90|91) describe 13; fail 13 "TLS handshake failed (curl exit $rc)." ;;
  6|7|28) describe 30; fail 30 "could not reach $CONTROL_PLANE_URL (curl exit $rc)." ;;
  *) fail 1 "downloading $CONTROL_PLANE_URL/agent/linux failed (curl exit $rc)." ;;
esac
tar -xzf "$TMP/agent.tar.gz" -C "$TMP"
# Find the binary wherever it sits in the archive, so packaging layout can vary.
AGENT_BIN="$(find "$TMP" -type f -name abyssal-agent | head -n1)"
[ -n "$AGENT_BIN" ] || fail 1 "abyssal-agent binary not found in the downloaded archive."
chmod +x "$AGENT_BIN"

say "Installing..."
set -- install --control-plane-url "$CONTROL_PLANE_URL"
if [ -n "$CA_CERT" ]; then
  set -- "$@" --ca-cert "$CA_CERT"
fi
if [ -n "$CA_FINGERPRINT" ]; then
  set -- "$@" --ca-fingerprint "$CA_FINGERPRINT"
fi
# The token goes to the agent by environment variable, never on its command
# line, and is never echoed.
rc=0
ABYSSAL_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" "$AGENT_BIN" "$@" || rc=$?
if [ "$rc" -ne 0 ]; then
  describe "$rc"
  fail "$rc" "abyssal-agent install failed (see the agent's ERROR line above)."
fi
say "Done. The agent is enrolled and running: systemctl status abyssal-agent"
"#;

const INSTALL_PS1_TEMPLATE: &str = r#"<#
.SYNOPSIS
  Abyssal Arsenal agent bootstrap installer (Windows).
.DESCRIPTION
  Downloads the agent from this control plane and runs its install (enroll +
  LocalSystem service). Copy the exact command from
  __CONTROL_PLANE_URL__/admin/hosts and run it in an elevated PowerShell (or
  use the RMM variant shown there for PDQ / Intune / GPO, running as SYSTEM).

  For a control plane with an internal (self-signed) CA, -CaFingerprint makes
  this fetch __CONTROL_PLANE_URL__/ca.crt, verify it against that fingerprint,
  add it to this machine's Trusted Root store, and hand it to the agent.
  A publicly-trusted certificate (e.g. Let's Encrypt) needs none of that.

  Exit codes (returned with -ExitCode; otherwise failures throw):
    0 ok; 1 other; 2 bad arguments; 3 not elevated; 10 certificate not
    trusted; 11 server cert is a CA cert (CaUsedAsEndEntity); 12 certificate
    name mismatch; 13 other certificate problem; 14 CA fingerprint mismatch;
    20 enrollment token rejected; 21 host name already in use; 30 control
    plane unreachable; 40 service registration failed.
.PARAMETER EnrollmentToken
  Token from /admin/hosts. Alternatively set $env:ABYSSAL_ENROLLMENT_TOKEN or
  use -EnrollmentTokenFile, which keep it out of command-line logs.
.PARAMETER CaFingerprint
  SHA-256 fingerprint of the control plane's internal CA, from /admin/hosts.
.PARAMETER Uninstall
  Remove the agent service, binary, credentials, and the CA trust, then exit.
.PARAMETER RemoveTrust
  Remove only the Abyssal Arsenal CA from the machine's Trusted Root store.
.PARAMETER ExitCode
  Exit the PowerShell process with the codes above instead of throwing (for
  RMM tools). Don't use it interactively: it closes the window.
#>
# The parameters are read inside the helper functions below, which the
# analyzer's unused-parameter rule can't see.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[CmdletBinding()]
param(
  [string]$EnrollmentToken,
  [string]$EnrollmentTokenFile,
  [string]$ControlPlaneUrl = "__CONTROL_PLANE_URL__",
  [string]$Version = "__AGENT_VERSION__",
  [string]$CaFingerprint,
  [switch]$Uninstall,
  [switch]$RemoveTrust,
  [switch]$ExitCode
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest's progress bar slows 5.1 to a crawl

$script:Token = $null

# Throws a failure carrying its exit code; the top-level catch reports it.
function Exit-Install([int]$Code, [string]$Message) {
  $e = New-Object System.Exception $Message
  $e.Data['AbyssalExitCode'] = $Code
  throw $e
}

function Get-FailureHint([int]$Code) {
  switch ($Code) {
    3  { 'Run PowerShell as Administrator (or run this from your RMM tool as SYSTEM).' }
    10 { "This machine doesn't trust the control plane's certificate. Use the command from /admin/hosts -- it includes -CaFingerprint." }
    11 { 'The control plane serves a CA certificate as its server certificate. Re-run ./install.sh on the control plane to replace it, then use a fresh command from /admin/hosts.' }
    12 { "The certificate doesn't cover $ControlPlaneUrl. Use the exact IP/hostname the control plane's certificate was made for (its PUBLIC_URL)." }
    13 { "The control plane's certificate was rejected (expired or otherwise unusable). Check this machine's clock, then /admin/health/tls on the control plane." }
    14 { "The CA fingerprint doesn't match. Don't continue: something may be intercepting traffic, or the control plane's CA was regenerated -- copy a fresh command from /admin/hosts." }
    20 { 'The enrollment token is invalid, expired, already used, or revoked. Generate a new one at /admin/hosts.' }
    21 { 'A connected host already uses this name. Remove it at /admin/hosts first.' }
    30 { "Could not reach $ControlPlaneUrl from this machine (DNS, routing, firewall?)." }
    40 { 'Enrolled, but the Windows service could not be registered or started. Re-run the same command; enrollment is skipped once it has succeeded.' }
    default { '' }
  }
}

# Maps a failure in PowerShell's own web requests to an exit code. The
# agent classifies its own failures and exits with these same codes.
function Get-FailureCode($ErrorRecord) {
  $data = $ErrorRecord.Exception.Data
  if ($data -and $data.Contains('AbyssalExitCode')) { return [int]$data['AbyssalExitCode'] }
  $text = $ErrorRecord.Exception.ToString()
  if ($text -match 'RemoteCertificateNameMismatch|name on the certificate|does not match the host') { return 12 }
  if ($text -match 'trust relationship|UntrustedRoot|PartialChain|remote certificate is invalid') { return 10 }
  if ($text -match 'remote name could not be resolved|No such host|Unable to connect|actively refused|timed out|No connection could be made') { return 30 }
  return 1
}

function Hide-Token([string]$Text) {
  if ($script:Token) { return $Text.Replace($script:Token, '<redacted>') }
  return $Text
}

function Test-Elevated {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Sha256Hex([byte[]]$Bytes) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return -join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('X2') }) }
  finally { $sha.Dispose() }
}

# Fetches the CA without validating the connection -- it isn't trusted yet;
# that's the problem being solved. Safe because the caller compares the bytes
# with the pinned fingerprint before using them, and nothing else is fetched
# while validation is relaxed. The leading comma returns the byte[] as one
# object: PowerShell otherwise unrolls an array returned from a function, and
# the caller gets an object[] that X509Certificate2's constructor binds as a
# *file path* ("The system cannot find the path specified").
function Get-UntrustedContent([string]$Url) {
  if ($PSVersionTable.PSVersion.Major -ge 6) {
    return , (Invoke-WebRequest -Uri $Url -UseBasicParsing -SkipCertificateCheck).RawContentStream.ToArray()
  }
  $previous = [Net.ServicePointManager]::ServerCertificateValidationCallback
  [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  try { return , (New-Object Net.WebClient).DownloadData($Url) }
  finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $previous }
}

function Get-AbyssalRootCertificate {
  Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like 'CN=Abyssal Arsenal Internal CA*' }
}

function Remove-AbyssalTrust {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param()
  $certs = @(Get-AbyssalRootCertificate)
  if ($certs.Count -eq 0) { Write-Output 'No Abyssal Arsenal CA found in the Trusted Root store.'; return }
  $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
  $store.Open('ReadWrite')
  try {
    foreach ($c in $certs) {
      if ($PSCmdlet.ShouldProcess("$($c.Subject) ($($c.Thumbprint))", 'Remove from LocalMachine Trusted Root')) {
        $store.Remove($c)
        Write-Output "Removed trusted CA $($c.Subject) ($($c.Thumbprint))."
      }
    }
  } finally { $store.Close() }
}

function Uninstall-Agent {
  if (Get-Service -Name abyssal-agent -ErrorAction SilentlyContinue) {
    Stop-Service -Name abyssal-agent -Force -ErrorAction SilentlyContinue
    & sc.exe delete abyssal-agent | Out-Null
    Write-Output 'Removed the abyssal-agent service.'
  }
  foreach ($dir in @('C:\Program Files\AbyssalAgent', (Join-Path $env:ProgramData 'abyssal-agent'))) {
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir; Write-Output "Removed $dir." }
  }
  Remove-AbyssalTrust
  Write-Output "abyssal-agent uninstalled. Remove the host at $ControlPlaneUrl/admin/hosts too, if you haven't."
}

function Install-Agent {
  $is64 = ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
  if (-not $is64) {
    Exit-Install 1 "No agent build for architecture '$($env:PROCESSOR_ARCHITECTURE)' (x64 only today). Build from source instead."
  }

  if ($EnrollmentTokenFile) {
    if (-not (Test-Path $EnrollmentTokenFile)) { Exit-Install 2 "Cannot read -EnrollmentTokenFile $EnrollmentTokenFile." }
    $script:Token = (Get-Content -Raw $EnrollmentTokenFile).Trim()
  } elseif ($EnrollmentToken) {
    $script:Token = $EnrollmentToken.Trim()
  } elseif ($env:ABYSSAL_ENROLLMENT_TOKEN) {
    $script:Token = $env:ABYSSAL_ENROLLMENT_TOKEN.Trim()
  }
  $credentials = Join-Path $env:ProgramData 'abyssal-agent\credentials.json'
  if (-not $script:Token -and -not (Test-Path $credentials)) {
    Exit-Install 2 "No enrollment token given. Generate one at $ControlPlaneUrl/admin/hosts and copy the command shown there."
  }

  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072  # TLS 1.2 on older 5.1 hosts

  $tmp = Join-Path $env:TEMP ('abyssal-agent-' + [guid]::NewGuid().ToString())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $caFile = $null
    if ($CaFingerprint) {
      $want = ($CaFingerprint -replace '[:\s-]', '').ToUpperInvariant()
      if ($want -notmatch '^[0-9A-F]{64}$') { Exit-Install 2 '-CaFingerprint must be a SHA-256 fingerprint (64 hex digits).' }
      try { [byte[]]$bytes = Get-UntrustedContent "$ControlPlaneUrl/ca.crt" }
      catch { Exit-Install 30 "Could not download $ControlPlaneUrl/ca.crt: $($_.Exception.Message)" }
      $ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
      $got = Get-Sha256Hex $ca.RawData
      if ($got -ne $want) { Exit-Install 14 "CA fingerprint mismatch: expected $want, got $got." }
      Write-Output "CA certificate verified (SHA-256 $got)."

      # PowerShell's own download of the agent below validates against the
      # OS store, so the CA must be there. Undo with -RemoveTrust; the agent
      # keeps working regardless, because it's given the CA directly too.
      if (-not (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $ca.Thumbprint })) {
        $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
        $store.Open('ReadWrite')
        try { $store.Add($ca) } finally { $store.Close() }
        Write-Output "Added the CA to the LocalMachine Trusted Root store ($($ca.Subject))."
      }

      $caFile = Join-Path $tmp 'ca.pem'
      $pem = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($ca.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"
      [IO.File]::WriteAllText($caFile, $pem, [Text.Encoding]::ASCII)
    }

    # Downloaded from THIS control plane (not GitHub), so an internal/air-gapped
    # network only needs to reach the control plane, and gets whatever agent build
    # the control plane is serving. See the project README's agent-distribution note.
    Write-Output "Downloading abyssal-agent $Version from $ControlPlaneUrl ..."
    $zip = Join-Path $tmp 'agent.zip'
    Invoke-WebRequest -Uri "$ControlPlaneUrl/agent/windows" -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    # Find the binary wherever it sits in the archive, so packaging layout can vary.
    $exe = Get-ChildItem -Path $tmp -Recurse -Filter abyssal-agent.exe | Select-Object -First 1
    if (-not $exe) { Exit-Install 1 'abyssal-agent.exe not found in the downloaded archive.' }

    Write-Output 'Installing...'
    $agentArgs = @('install', '--control-plane-url', $ControlPlaneUrl)
    if ($caFile) { $agentArgs += @('--ca-cert', $caFile, '--ca-fingerprint', $want) }
    # The token reaches the agent by environment variable, never on its
    # command line, and is never echoed.
    $env:ABYSSAL_ENROLLMENT_TOKEN = $script:Token
    # Native stderr under 'Stop' would abort on the first line in 5.1; take
    # everything to stdout instead and judge by the exit code.
    $ErrorActionPreference = 'Continue'
    try {
      & $exe.FullName @agentArgs 2>&1 | ForEach-Object { Write-Output (Hide-Token "$_") }
      $rc = $LASTEXITCODE
    } finally {
      $ErrorActionPreference = 'Stop'
      Remove-Item Env:\ABYSSAL_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    }
    if ($rc -ne 0) { Exit-Install $rc "abyssal-agent install failed with exit code $rc (see its ERROR line above)." }

    $service = Get-Service -Name abyssal-agent -ErrorAction SilentlyContinue
    if (-not $service) { Exit-Install 40 'The abyssal-agent service is not registered after install.' }
    Write-Output "Done. abyssal-agent is enrolled; service status: $($service.Status)."
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

try {
  if (-not (Test-Elevated)) { Exit-Install 3 'Administrator privileges are required.' }
  if ($Uninstall) { Uninstall-Agent }
  elseif ($RemoveTrust) { Remove-AbyssalTrust }
  else { Install-Agent }
  if ($ExitCode) { exit 0 }
} catch {
  $code = Get-FailureCode $_
  Write-Output ('ERROR: ' + (Hide-Token $_.Exception.Message))
  $hint = Get-FailureHint $code
  if ($hint) { Write-Output "HINT: $hint" }
  Write-Output "Install failed (exit code $code)."
  if ($ExitCode) { exit $code }
  $global:LASTEXITCODE = $code
  throw "Abyssal Arsenal agent install failed (exit code $code) -- see the ERROR line above."
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

/// `GET /ca.crt` and `GET /ca.pem` -- the control plane's internal CA
/// certificate (public half only), so a fresh host can fetch it before it
/// trusts anything; the generated install commands verify it against the
/// fingerprint shown on `/admin/hosts` before using it. 404 when there's no
/// internal CA (Let's Encrypt or the operator's own proxy).
pub async fn ca_cert() -> Response {
    match crate::public_ca::load() {
        Some(ca) => (
            [
                (CONTENT_TYPE, "application/x-pem-file"),
                (
                    CONTENT_DISPOSITION,
                    "attachment; filename=\"abyssal-arsenal-ca.pem\"",
                ),
            ],
            ca.pem,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "this control plane has no internal CA certificate to serve",
        )
            .into_response(),
    }
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

/// Where the Docker image puts the agent it builds alongside the control
/// plane (see the Dockerfile) -- read-only, part of the image, so it's always
/// the agent this exact control plane was built with.
fn agent_bundle_dir() -> PathBuf {
    std::env::var("AGENT_BUNDLE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/app/agent-bundle"))
}

struct AgentAsset {
    /// The release-style filename (also where a GitHub fetch is cached).
    versioned: String,
    /// A version-agnostic name an operator can drop a local build under.
    generic: &'static str,
    content_type: &'static str,
    /// The filename the browser saves it as. The archives keep the release
    /// name; the Windows installers get the short names the AAT commands
    /// on /admin/hosts use.
    download_name: Option<&'static str>,
}

fn agent_asset(os: &str, version: &str) -> Option<AgentAsset> {
    match os {
        "linux" => Some(AgentAsset {
            versioned: format!("abyssal-agent-v{version}-x86_64-unknown-linux-gnu.tar.gz"),
            generic: "abyssal-agent-linux.tar.gz",
            content_type: "application/gzip",
            download_name: None,
        }),
        "windows" => Some(AgentAsset {
            versioned: format!("abyssal-agent-v{version}-x86_64-pc-windows-msvc.zip"),
            generic: "abyssal-agent-windows.zip",
            content_type: "application/zip",
            download_name: None,
        }),
        "windows-msi" => Some(AgentAsset {
            versioned: format!("abyssal-agent-v{version}-x86_64-pc-windows-msvc.msi"),
            generic: "abyssal-agent-windows.msi",
            content_type: "application/x-msi",
            download_name: Some("AbyssalAgent.msi"),
        }),
        "windows-exe" => Some(AgentAsset {
            versioned: format!("abyssal-agent-v{version}-x86_64-pc-windows-msvc.exe"),
            generic: "abyssal-agent-windows.exe",
            content_type: "application/vnd.microsoft.portable-executable",
            download_name: Some("abyssal-agent.exe"),
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
                format!(
                    "attachment; filename=\"{}\"",
                    asset.download_name.unwrap_or(&asset.versioned)
                ),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// `GET /agent/{os}` (os = `linux` | `windows` | `windows-msi` |
/// `windows-exe`) -- serves the agent archive or installer so a
/// host being enrolled downloads it from this control plane instead of GitHub.
/// This is what makes an internal/air-gapped rollout self-contained, and what
/// lets the control plane distribute an agent build newer than the latest
/// public release. Resolution order: an operator-placed archive in the dist dir
/// (version-agnostic name), then the build bundled into the image, then a
/// cached/operator-placed release archive in the dist dir, else a best-effort
/// fetch from GitHub (cached for next time).
///
/// The bundled build comes before any release archive on purpose: the install
/// commands this control plane generates use the flags *its* agent knows
/// (`--ca-cert`, `--ca-fingerprint`), and a release archive is only as new as
/// the last published tag -- serving that to a newer control plane fails the
/// install with "unexpected argument". Unauthenticated, like the install
/// scripts -- the binary is non-secret; the enrollment token is the secret.
pub async fn serve_agent(State(state): State<AppState>, Path(os): Path<String>) -> Response {
    match resolve_agent(&state, &os).await {
        Ok(agent) => serve_agent_bytes(agent.bytes, &agent.asset),
        Err(ResolveError::UnknownOs) => (
            StatusCode::NOT_FOUND,
            "unknown agent OS -- use /agent/linux, /agent/windows, /agent/windows-msi or \
             /agent/windows-exe",
        )
            .into_response(),
        Err(ResolveError::Unavailable(message)) => {
            (StatusCode::SERVICE_UNAVAILABLE, message).into_response()
        }
    }
}

/// The agent build `/agent/{os}` serves, and which version it is.
pub(crate) struct ResolvedAgent {
    pub bytes: Vec<u8>,
    asset: AgentAsset,
    /// `None` for an operator-placed build under a version-agnostic name.
    pub version: Option<String>,
}

pub(crate) enum ResolveError {
    UnknownOs,
    Unavailable(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::UnknownOs => write!(f, "no agent build for that OS"),
            ResolveError::Unavailable(message) => write!(f, "{message}"),
        }
    }
}

/// What `/agent/{os}` serves -- also what "Update agent" hashes and tells
/// a 0.2.3+ agent to download, so the two can't disagree. Resolution order
/// as documented on `serve_agent`.
pub(crate) async fn resolve_agent(
    state: &AppState,
    os: &str,
) -> Result<ResolvedAgent, ResolveError> {
    let current = crate::update_check::CURRENT_VERSION.trim().to_string();
    let asset = agent_asset(os, &current).ok_or(ResolveError::UnknownOs)?;

    let dir = agent_dist_dir();
    if let Ok(bytes) = tokio::fs::read(dir.join(asset.generic)).await {
        return Ok(ResolvedAgent {
            bytes,
            asset,
            version: None,
        });
    }
    if let Ok(bytes) = tokio::fs::read(agent_bundle_dir().join(asset.generic)).await {
        return Ok(ResolvedAgent {
            bytes,
            asset,
            version: Some(current),
        });
    }

    // A release archive: this build's own version first, then -- when this
    // build is ahead of anything published (built from main after a version
    // bump) -- the newest release, rather than failing every Windows
    // install until the release exists.
    let release = crate::update_check::agent_release_version(state).await;
    let mut versions = vec![current.clone()];
    if release != current {
        versions.push(release);
    }
    for version in &versions {
        let Some(asset) = agent_asset(os, version) else {
            continue;
        };
        if let Ok(bytes) = tokio::fs::read(dir.join(&asset.versioned)).await {
            note_fallback(os, version, &current);
            return Ok(ResolvedAgent {
                bytes,
                asset,
                version: Some(version.clone()),
            });
        }
        // Not cached: fetch from GitHub and cache it. Fails cleanly (not a
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
            note_fallback(os, version, &current);
            return Ok(ResolvedAgent {
                bytes: bytes.to_vec(),
                asset,
                version: Some(version.clone()),
            });
        }
    }

    Err(ResolveError::Unavailable(format!(
        "agent binary unavailable (tried release{} {}). Place a build at {}/{} (or {}), or \
         give this control plane outbound access to GitHub.",
        if versions.len() > 1 { "s" } else { "" },
        versions
            .iter()
            .map(|v| format!("v{v}"))
            .collect::<Vec<_>>()
            .join(", "),
        dir.display(),
        asset.generic,
        asset.versioned
    )))
}

/// Logged when an agent older than this control plane is served, so a
/// mismatch an admin later sees ("Agent out of date") has an explanation.
fn note_fallback(os: &str, served: &str, current: &str) {
    if served != current {
        tracing::warn!(
            os,
            served = %served,
            control_plane = %current,
            "this control plane's version isn't published as a release yet -- serving the \
             newest release's agent instead (put a matching build in AGENT_DIST_DIR to serve \
             that)"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;
    use crate::deploy_commands;
    use crate::public_ca::PublicCa;

    const URL: &str = "https://10.245.10.25";

    fn scratch(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("abyssal-bootstrap-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_ca() -> PublicCa {
        PublicCa {
            pem: String::new(),
            fingerprint: "AB".repeat(32),
        }
    }

    #[test]
    fn served_scripts_never_contain_a_token_or_fingerprint() {
        // Both come from the operator at run time, never from the server:
        // a fingerprint served alongside the CA it vouches for would pin
        // nothing.
        for template in [INSTALL_SH_TEMPLATE, INSTALL_PS1_TEMPLATE] {
            let script = render_script(template, URL);
            assert!(!script.contains("__"), "unrendered placeholder");
            assert!(!script.contains(&"AB".repeat(32)));
        }
    }

    #[test]
    fn shell_artifacts_are_valid_posix_sh() {
        let dir = scratch("sh");
        let ca = sample_ca();
        let files = [
            ("install.sh", render_script(INSTALL_SH_TEMPLATE, URL)),
            (
                "oneliner.sh",
                deploy_commands::linux_oneliner(URL, "-tok", Some(&ca)),
            ),
            (
                "manual.sh",
                deploy_commands::linux_manual(URL, "-tok", Some(&ca)),
            ),
            (
                "plain.sh",
                deploy_commands::linux_oneliner(URL, "tok", None),
            ),
        ];
        for (name, body) in files {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            let out = Command::new("sh").arg("-n").arg(&path).output().unwrap();
            assert!(
                out.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            // `sh -n` only parses; shellcheck also catches what fails when a
            // line runs (a bad `${...}` substitution, unquoted expansions).
            // Skipped without it locally, required in CI (ubuntu-latest has
            // it).
            match Command::new("shellcheck")
                .args(["-S", "warning", "-s", "sh"])
                .arg(&path)
                .output()
            {
                Ok(out) => assert!(
                    out.status.success(),
                    "{name}: shellcheck:\n{}",
                    String::from_utf8_lossy(&out.stdout)
                ),
                Err(_) => assert!(
                    std::env::var_os("CI").is_none(),
                    "shellcheck is required for this test in CI"
                ),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Parses install.ps1 and every generated Windows command with the real
    /// PowerShell parser, and runs PSScriptAnalyzer over them when it's
    /// installed. Needs `pwsh` on PATH: skipped without it locally, required
    /// in CI.
    #[test]
    fn powershell_artifacts_parse_and_pass_script_analyzer() {
        if Command::new("pwsh").arg("-Version").output().is_err() {
            assert!(
                std::env::var_os("CI").is_none(),
                "pwsh is required for this test in CI"
            );
            eprintln!("skipping: pwsh not on PATH");
            return;
        }
        let dir = scratch("ps1");
        let ca = sample_ca();
        let files = [
            ("install.ps1", render_script(INSTALL_PS1_TEMPLATE, URL)),
            (
                "interactive-oneliner.ps1",
                deploy_commands::windows_oneliner(URL, "-tok", Some(&ca)),
            ),
            (
                "manual.ps1",
                deploy_commands::windows_manual(URL, "-tok", Some(&ca)),
            ),
            (
                "rmm.ps1",
                deploy_commands::windows_rmm(URL, "-tok", Some(&ca)),
            ),
            (
                "interactive-plain.ps1",
                deploy_commands::windows_oneliner(URL, "tok", None),
            ),
            (
                "plain-rmm.ps1",
                deploy_commands::windows_rmm(URL, "tok", None),
            ),
        ];
        for (name, body) in &files {
            std::fs::write(dir.join(name), body).unwrap();
        }

        let check = r#"
$failed = $false
foreach ($f in Get-ChildItem -Path $env:ABYSSAL_PS_CHECK_DIR -Filter *.ps1) {
  $tokens = $null; $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
  foreach ($e in $errors) { "$($f.Name):$($e.Extent.StartLineNumber): parse error: $($e.Message)"; $failed = $true }
}
if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
  foreach ($f in Get-ChildItem -Path $env:ABYSSAL_PS_CHECK_DIR -Filter *.ps1) {
    # Typed-at-a-prompt one-liners may use idiomatic aliases (irm).
    $exclude = @()
    if ($f.Name -like 'interactive-*') { $exclude = @('PSAvoidUsingCmdletAliases') }
    foreach ($r in Invoke-ScriptAnalyzer -Path $f.FullName -Severity Error, Warning -ExcludeRule $exclude) {
      "$($r.ScriptName):$($r.Line): $($r.RuleName): $($r.Message)"; $failed = $true
    }
  }
} else {
  'PSScriptAnalyzer not installed -- parse check only'
}
if ($failed) { exit 1 }
"#;
        let out = Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command", check])
            .env("ABYSSAL_PS_CHECK_DIR", &dir)
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        let report = String::from_utf8_lossy(&out.stdout);
        eprintln!("{report}");
        assert!(
            out.status.success(),
            "{report}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
