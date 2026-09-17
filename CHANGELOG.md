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
  (`AgentOperation`) to a specific host. See the Cystoolbox, Cadavault, and
  Apotheosis entries below for the full current operation set.
- **Cystoolbox arsenal** (first arsenal with real capabilities): a
  per-host admin page (`/arsenals/cystoolbox`) listing online managed hosts
  with System Overview, Resource Usage (memory + disk), and Logged-in Users
  as read-only operations (`systems.view`); Set Hostname as a Write
  operation (`systems.manage`, no confirmation required); and Reboot Host as
  a Destructive operation (`systems.manage`) requiring explicit
  confirmation. Proves the full Read/Write/Destructive spectrum of the
  execution layer against a real managed host, not just in local unit
  tests. Hostnames are validated (RFC 1123 label rules) on both the control
  plane and the agent -- the agent never trusts a wire value just because
  the control plane already checked it.
- **Cadavault arsenal** (second arsenal with real capabilities): a
  per-host admin page (`/arsenals/cadavault`) with Firewall Status,
  Listening Ports (`ss -tulpn`), and Recent Auth Log (sshd journal) as
  read-only operations (`security.view`); Allow Port as a Write operation
  (`security.manage`, no confirmation required); and Enable Firewall as a
  Destructive operation (`security.manage`) requiring explicit
  confirmation since it can cut off remote access. Firewall operations
  auto-detect which management tool is actually present on the host
  (firewalld, ufw, nftables, or iptables, in that priority order) rather
  than assuming one -- the same detect-don't-assume approach the original
  bash toolbox used for package managers. Direct nftables rule management
  and "enable" for raw nftables/iptables are intentionally unsupported
  (clear error instead of a guess at an unfamiliar ruleset's table/chain
  layout); port/protocol input is validated on both the control plane and
  the agent, matching the hostname validation pattern.
- **Apotheosis**: time-boxed sudo elevation for managed hosts, modeled on
  Cockpit's "Administrative access" toggle. An admin with the new
  `hosts.elevate` permission (Super Admin only by default) can elevate a
  connected host's agent from `/admin/hosts` by submitting its sudo
  password; the agent validates it via `sudo -S -v` (the same mechanism
  interactive `sudo` already uses) and starts a 20-minute sliding idle
  window during which privileged operations run as `sudo -n` instead of
  failing outright. De-escalates automatically on idle timeout, or
  explicitly via a De-escalate button (which also runs `sudo -k`). The
  password is never persisted anywhere -- not hashed, not plaintext -- on
  either the control plane or the agent; it's held in memory only long
  enough to hand to `sudo` and is then actively zeroized
  (`zeroize::Zeroizing`), with `AgentOperation`'s `Debug` impl
  hand-written to redact it as a backstop. Elevating without TLS in front
  of the control plane produces a warning (not a hard block), matching the
  existing local-testing posture elsewhere in the app.
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

### Fixed

- `abyssal-agent`'s command runner now treats a non-zero exit code as a
  failure, not just a spawn error. Previously, a command that ran but
  failed partway (e.g. `hostnamectl` refusing for lack of privilege) came
  back as a reported success with empty-looking output -- silently
  claiming something happened when it hadn't. Caught while verifying Set
  Hostname; the same fix applies to every operation, including Reboot,
  where reporting a failed reboot as successful would have been worse.
- `abyssal-agent`'s enrollment step now verifies the credentials file's
  directory is actually writable *before* calling the control plane's
  enrollment endpoint, not after. The endpoint consumes the (single-use)
  enrollment token as soon as it accepts the request, before returning a
  credential; if the agent then failed to persist that credential locally
  (e.g. no permission to create `/etc/abyssal-agent` without root), the
  token was already unrecoverably burned and the run had to fail with a
  filesystem error that gave no hint the enrollment itself had actually
  succeeded server-side. Now a local write-permission problem fails fast,
  before the token is spent.
- The `/admin/hosts` enrollment-token banner now notes that
  `abyssal-agent` needs to be built/installed on the target host first
  (`cargo install --path crates/agent`, or see `crates/agent/README.md`
  for alternatives) -- the copy-paste command alone gave no indication the
  binary wasn't just already there.

### Security

- Upgraded `sqlx` from 0.7.4 to 0.8.6, resolving four Dependabot alerts: a
  reachable panic in CRL parsing and two name-constraint validation issues
  in the transitively-pulled `rustls-webpki` 0.101.7 (RUSTSEC-2026-0104,
  RUSTSEC-2026-0099, RUSTSEC-2026-0098 -- all came from sqlx-core's old
  `rustls` 0.21 dependency, now replaced by the same modern `rustls` 0.23
  stack already used elsewhere in the workspace), and a binary protocol
  misinterpretation issue in sqlx itself from truncating/overflowing casts
  (RUSTSEC-2024-0363). No API changes needed on our side (runtime-checked
  queries only, no compile-time `query!` macros); verified against a real
  MariaDB that migrations, login, and admin page reads/writes all still
  work correctly post-upgrade. Also incidentally dropped two now-unused
  unmaintained transitive dependencies (`paste`, `rustls-pemfile`).

### Changed

- Project license set to AGPL-3.0-or-later (Copyright (C) 2026 AbyssalOath).

### Known limitations

- `LoginLimiter` and `HostConnectionRegistry` are in-memory and
  process-local; a multi-instance control plane would need both backed by
  shared state.
- SSO/OIDC, non-SMTP notification providers, and 19 of the 21 arsenals'
  real capabilities beyond metadata are not implemented yet (only
  `cystoolbox` and `cadavault` have real operations so far).
- No Tauri desktop client yet; `/api/health` and `/api/me` establish the
  API seam it would use.
