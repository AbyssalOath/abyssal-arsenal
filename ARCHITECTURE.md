# Architecture

This document describes how Abyssal Arsenal is put together: the
control-plane / agent split, the crate layout, and the security-relevant
design decisions behind auth, RBAC, audit logging, and remote execution.

## Control plane vs. managed hosts

The Abyssal Arsenal container is a **control plane**. It is not the system
arsenals operate on. Real sysadmin work (disk management, network
diagnostics, hardening checks, and so on) happens on Linux hosts running the
`abyssal-agent` binary, which connects *out* to the control plane over an
authenticated WebSocket:

```
                    Abyssal Arsenal
                      Control Plane
                          |
              Axum . Web UI . REST/JSON API
              Auth / RBAC / Audit
              Notifications
                          |
                authenticated channel
                          |
        +-----------------+-----------------+
        |                 |                 |
        v                 v                 v
  Linux Host A       Linux Host B      Linux Host C
  "abyss agent"      "abyss agent"     "abyss agent"
        |                 |                 |
    Arsenals           Arsenals          Arsenals
```

This keeps dangerous system operations local to the machine they affect,
while giving an IT team one self-hosted place to authenticate, authorize,
audit, and dispatch that work from.

## Workspace layout

```
crates/
  core            domain types (User, Role, Host, Permission, AppError, ...)
  database        sqlx pool, migrations, repo:: query functions
  auth            password hashing, LocalAuthProvider, session issuance
  rbac            AuthContext, fail-closed permission checks
  audit           AuditAction catalog, append-only writer/reader
  notifications   NotificationProvider trait, SmtpProvider, dispatcher
  execution       Operation trait, Executor (local + host dispatch)
  hosts           HostConnectionRegistry (live agent connections)
  agent-protocol  wire types shared between control plane and abyssal-agent
  modules         Arsenal trait, ModuleRegistry
  web             Axum router, Askama templates, HTTP/WS handlers
  app             the abyssal-arsenal (control plane) binary
  agent           the abyssal-agent binary, runs on a managed host
  arsenals/<name> one crate per administrative domain
```

Each crate has one job. `app` and `agent` are the only crates that know
about every other crate in their half of the system; nothing else reaches
across the control-plane / agent boundary except through
`agent-protocol`'s wire types.

## Authentication and sessions

- Local accounts only today. Passwords are hashed with Argon2id
  (`crates/auth/src/password.rs`) and never stored or logged in plaintext.
- `AuthProvider` (`crates/auth/src/provider.rs`) is a trait specifically so
  an OIDC/SAML provider can be added later without touching session
  issuance, RBAC, or any handler that just wants "give me an authenticated
  user". SSO users would resolve to the same `User`/role model as local
  accounts.
- Sessions are opaque 256-bit tokens; only a SHA-256 hash is persisted
  (`abyssal_core::secret`). The cookie is `HttpOnly`, `SameSite=Lax`, and
  `Secure` outside local development.
- CSRF uses a double-submit cookie: a token is set in a readable-by-JS
  cookie and must be echoed back in every state-changing form. Machine
  clients (the agent's own endpoints) are authenticated a different way and
  are never behind this check -- see "Host enrollment" below.
- A simple in-memory sliding-window limiter locks out repeated failed
  logins per username+IP. This is process-local, the same limitation the
  host connection registry has -- see "Known limitations".

## Authorization (RBAC)

- `Permission` (`crates/core/src/permission.rs`) is a fixed enum, not a
  free-form string table. Every seeded permission maps to a stable key like
  `hosts.manage` or `audit.export`.
- A role is a named set of permissions, nothing more. Built-in roles (Super
  Admin, System Admin, Network Admin, Security/OPSEC Admin, Regular User)
  are seeded on startup with a sensible default permission set, but the
  seeding only sets permissions the first time a role is created -- an
  admin's later customization is never clobbered on restart.
- Enforcement is explicit and per-handler: every protected route calls
  `abyssal_rbac::ensure(&ctx, Permission::X)` itself. There is no blanket
  authorization middleware that could silently no-op or be bypassed by a
  route added later without thinking about it.
- **Fail closed.** Any failure to resolve a user's permissions (a database
  error, a missing session) is treated as denied, never allowed. This is a
  hard rule throughout the codebase, not just a comment.

## Audit logging

- `AuditAction` (`crates/audit/src/action.rs`) is a fixed, typed catalog
  (`USER_CREATED`, `LOGIN_FAILURE`, `HOST_ENROLLED`,
  `SYSTEM_COMMAND_EXECUTED`, and so on). Handlers cannot invent new
  free-form action strings.
- `abyssal_audit::record()` is the only function that writes to the
  `audit_log` table, and the codebase never issues an `UPDATE` or `DELETE`
  against it -- append-only by construction, not just convention.
- The `/admin/audit` page ("obituary" in the arsenal naming) is the
  paginated, filterable viewer; export is a separate, separately
  permissioned action (`audit.export`).

## Modules ("arsenals")

- `Arsenal` (`crates/modules/src/arsenal.rs`) is a small trait: a stable
  key, display name, description, category, and the permission(s) that
  gate viewing it. Each `crates/arsenals/<name>` crate implements it for
  exactly one struct.
- `ModuleRegistry` holds every arsenal the binary was built with and
  overlays the database's enabled/disabled state on top. `app` and `web`
  only ever iterate the registry -- adding a new arsenal crate means adding
  one line to `crates/app/src/arsenals.rs` and the workspace manifest,
  nothing else.
- Most arsenals currently exist as permission-gated metadata pages only.
  See [CHANGELOG.md](CHANGELOG.md) for which ones have real capabilities
  wired up.

## Controlled execution

Two different problems share one shape (permission check, then run, then
audit record, always), but are different substrates, so they are two
methods on `Executor` (`crates/execution/src/executor.rs`) rather than one
forced abstraction:

- **`execute()`** runs an in-process `Operation` -- a Rust async function
  the control plane itself performs (self-diagnostics, mostly). Every
  `Operation` declares its own `OperationKind` (`Read`, `Write`,
  `Destructive`) and the `Permission` it requires. A `Destructive`
  operation is refused unless the caller explicitly set `confirm: true` --
  reaching the endpoint is never sufficient confirmation on its own.
- **`execute_on_host()`** dispatches one of the fixed `AgentOperation`
  variants (`crates/agent-protocol`) to a specific enrolled host over its
  live connection, with the same permission/confirmation/audit handling.

Neither path ever builds a shell command from a string that came from an
HTTP request. Process-backed local operations use explicit argument
vectors (`crates/execution/src/process.rs`); the agent's whitelist of
`AgentOperation` variants is the actual security boundary for anything that
runs on a managed host.

## Host enrollment and the agent protocol

1. An admin generates a short-lived (15 minute), single-use enrollment
   token from `/admin/hosts` (requires `hosts.manage`).
2. The operator runs `abyssal-agent run --control-plane-url ...
   --enrollment-token ...` on the target host. The agent `POST`s the token
   to `/api/hosts/enroll` -- this endpoint is authenticated purely by the
   token, not a browser session, and is intentionally outside
   `CurrentUser`/CSRF.
3. The control plane creates a `Host` row, generates a long-lived opaque
   credential (same generate/hash pattern as sessions), and returns it once.
   The agent persists it locally (`/etc/abyssal-agent/credentials.json` by
   default, `0600`).
4. The agent connects to `/ws/agent` with `Authorization: Bearer
   <credential>`. A dedicated extractor (`AgentAuth`,
   `crates/web/src/extract.rs`) validates the credential before the
   WebSocket upgrade completes and rejects revoked/unknown credentials with
   a plain 401/403 -- never `CurrentUser`'s browser-oriented
   redirect-to-`/login` behavior.
5. `HostConnectionRegistry` (`crates/hosts`) tracks the live connection and
   routes `execute_on_host()` dispatches to it, matching responses back to
   the right caller by request ID. The control plane also sends a periodic
   `Ping` down the connection to refresh `last_seen_at` and detect dead
   connections.
6. Revoking a host (`/admin/hosts/<id>/revoke`) invalidates its credential
   immediately; the agent's own reconnect loop will keep retrying and
   failing with a clear error until it's re-enrolled with a fresh token.

`AgentOperation` (currently `Ping` and `SystemInfo`) is deliberately small.
Every new sysadmin capability an arsenal needs on a host means adding a
variant to `agent-protocol` and a handler in `crates/agent/src/ops.rs` --
there is no path from a wire message to running something outside that
fixed list.

## Web layer

- Server-rendered HTML via Askama, no separate JavaScript build pipeline.
  Interactivity is plain HTML forms, including a real confirmation page
  (not a JS `confirm()` dialog) for destructive actions.
- Dark theme by default with a light theme toggle, both defined as CSS
  custom properties (`crates/web/static/style.css`) for contrast/WCAG
  purposes.
- `/api/health` and `/api/me` establish the JSON API seam a future desktop
  (Tauri) client would reuse, without duplicating any business logic in
  that client.
- Security headers (CSP, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`) are applied to every response via middleware.

## Data model

Two migrations so far:

- `0001_init.sql` -- `users`, `roles`, `permissions`, `role_permissions`,
  `user_roles`, `sessions`, `audit_log`, `settings`, `modules`.
- `0002_hosts.sql` -- `hosts`, `host_enrollment_tokens`.

`crates/database` uses runtime-checked `sqlx::query`/`query_as` (still
fully parameterized, not string-built SQL) rather than the compile-time
`query!` macros, so `cargo build` never needs a live database or a
maintained offline query cache.

## Deployment architecture

- `docker-compose.yml` runs MariaDB and the control-plane app; an optional
  `caddy` profile adds a reverse proxy with automatic TLS. `abyssal-agent`
  is never containerized -- it has to run on the actual host it manages.
- The control-plane binary embeds its own database migrations
  (`sqlx::migrate!()`) and runs them on startup; nothing extra needs
  copying into the runtime image for that.
- `install.sh` generates secrets and asks only what it can't infer. See
  [CONTRIBUTING.md](CONTRIBUTING.md) for local development instead of the
  full Compose stack.

## Known limitations

These are documented tradeoffs for the current single-instance deployment
model, not oversights:

- `LoginLimiter` and `HostConnectionRegistry` are both in-memory and
  process-local. A multi-instance control plane would need both backed by
  shared state instead.
- SSO/OIDC, additional notification providers (Telegram, Slack, Teams,
  Discord), and 20 of the 21 arsenals' real capabilities beyond metadata are
  not implemented yet (only `cystoolbox` has real operations so far) --
  see [CHANGELOG.md](CHANGELOG.md) for current status.
- The agent does not sandbox or rate-limit operations beyond the fixed
  `AgentOperation` whitelist and does not manage privilege escalation
  itself; how it's deployed (as root, via `sudo`-scoped commands in a
  future revision, and so on) is a deployment decision today.
