# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
once it makes its first tagged release. Nothing has been tagged yet -- the
project is pre-release, so everything so far lives under "Unreleased".

## [Unreleased]

### Added

- **Platform core**: Axum + MariaDB (via sqlx) control-plane server. Local
  username/password authentication with Argon2id hashing, opaque
  database-backed sessions, and a first-run `/setup` wizard that creates the
  initial administrator (public self-registration stays disabled until an
  admin re-enables it).
- **Role-based access control**: a fixed, typed `Permission` catalog, roles
  as named permission sets, fail-closed enforcement checked explicitly in
  every protected handler, and a built-in role set (Super Admin, System
  Admin, Network Admin, Security/OPSEC Admin, Regular User).
- **Audit logging**: an append-only `audit_log` table and a typed
  `AuditAction` catalog covering login/logout, user and role management,
  module toggles, configuration changes, and executed commands. The
  `/admin/audit` page provides filtering, pagination, and CSV export.
- **Module system**: an `Arsenal` trait and `ModuleRegistry` covering all 21
  planned arsenals (`cystoolbox`, `cadavault`, `necrolink`, `postmortem`,
  `reliquary`, `mortiscope`, `incarnation`, `resurrection`, `necropsy`,
  `necropolis`, `obituary`, `reanimation`, `ossuary`, `catacomb`, `parish`,
  `apothecary`, `grimoire`, `cryptkeeper`, `defleshing`, `vivisection`,
  `inquest`). Each is registered with real metadata and permission gating;
  most currently render a placeholder page pending real capabilities.
- **Controlled execution layer**: an `Operation` trait and `Executor` with
  permission checks, timeouts, cooperative cancellation, and mandatory audit
  records for every attempt, plus an explicit confirmation requirement for
  destructive operations.
- **Agent / control-plane architecture**: a standalone `abyssal-agent`
  binary that runs on a managed Linux host and connects outbound to the
  control plane over an authenticated WebSocket (`/ws/agent`). Includes host
  enrollment via short-lived, single-use tokens (`/admin/hosts`,
  `/api/hosts/enroll`), a live connection registry, host
  online/offline status and revocation, and `Executor::execute_on_host()`
  for dispatching a fixed, versioned whitelist of operations
  (`AgentOperation`: `Ping`, `SystemInfo`, `ResourceUsage`, `LoggedInUsers`,
  `Reboot`) to a specific host.
- **Cystoolbox arsenal** (first arsenal with real capabilities): a
  per-host admin page (`/arsenals/cystoolbox`) listing online managed hosts
  with System Overview, Resource Usage (memory + disk), and Logged-in Users
  as read-only operations (`systems.view`), plus Reboot Host as a
  Destructive operation (`systems.manage`) requiring explicit confirmation.
  Proves the full Read/Destructive spectrum of the execution layer against
  a real managed host, not just in local unit tests.
- **Password policy**: local account passwords now require at least 15
  characters, an uppercase letter, a lowercase letter, a number, and a
  special character, enforced server-side (`abyssal_auth::password::
  validate_strength`) on `/setup`, `/register`, and admin-created users. A
  "Generate strong password" option produces a 20-character
  cryptographically random password satisfying the policy while excluding
  visually ambiguous characters (`I`, `O`, `l`, `o`, `0`, `1`).
- **Web UI**: server-rendered HTML (Askama), dark theme by default with a
  light theme toggle, no separate JavaScript build pipeline. Destructive
  actions require a real confirmation page rather than a client-side
  dialog. Security headers (CSP, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`) applied to every response.
- **Notifications**: a `NotificationProvider` trait and dispatcher with a
  working SMTP provider; additional channels are a documented extension
  point, not stubbed-out placeholders.
- **Deployment tooling**: multi-stage `Dockerfile` with dependency-layer
  caching across the full workspace, `docker-compose.yml` (MariaDB + app,
  optional Caddy reverse-proxy profile), an interactive `install.sh`, and
  `scripts/migrate.sh` / `backup-db.sh` / `restore-db.sh`.
- **CI**: `cargo check`, `cargo test`, `cargo clippy -D warnings`,
  `cargo fmt --check`, and a Docker build-validation job on every push/PR;
  separate workflows publish the control-plane image to GHCR and package
  release binaries for both `abyssal-arsenal` and `abyssal-agent`.

### Changed

- Project license set to AGPL-3.0-or-later (Copyright (C) 2026 AbyssalOath).

### Known limitations

- `LoginLimiter` and `HostConnectionRegistry` are in-memory and
  process-local; a multi-instance control plane would need both backed by
  shared state.
- SSO/OIDC, non-SMTP notification providers, and 20 of the 21 arsenals'
  real capabilities beyond metadata are not implemented yet (only
  `cystoolbox` has real operations so far).
- No Tauri desktop client yet; `/api/health` and `/api/me` establish the
  API seam it would use.
