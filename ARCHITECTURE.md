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
- All 23 arsenals have real capabilities wired up. See
  [CHANGELOG.md](CHANGELOG.md) for what each one actually does.

**Control-plane arsenals vs. host-agent arsenals.** Most arsenals
(Cystoolbox, Cadavault, Necrolink, Postmortem, Reliquary, Mortiscope,
Incarnation, Parish, Catacomb, Apothecary, Ossuary, Grimoire, Inquest,
Cryptkeeper, ...) dispatch their real work to a specific enrolled host via
`execute_on_host()` -- the arsenal's page always starts with picking a
host. Panopticon (`crates/arsenals/panopticon`, network visibility and
device discovery) is a **control-plane arsenal**: it runs directly
against the control plane's own network stack via `execute()`, not
against any one host's agent. This is a deliberate boundary, not a gap to
fill in later -- network discovery finds devices that may never have an
agent installed on them at all, so there's no host to dispatch to in the
first place. Thanatos (`crates/arsenals/thanatos`) is a **hybrid**: its
per-scan operation (`ScanSecurityEvents`) is an ordinary host-agent
dispatch, but the control plane additionally persists every result,
correlates them across time, and runs its own unattended background
sweep -- see "Background tasks" below. See "Controlled execution" below
for what `execute()` vs. `execute_on_host()` each mean concretely; a
future arsenal belongs in the host-agent camp if its work is inherently
per-host (something to run *on* a specific machine), in the
control-plane camp if it's work the control plane does about its
environment at large, and in the hybrid camp if it's per-host work whose
*results* the control plane also needs to reason about over time.

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

**Detect the tool present, don't assume one.** There is no single standard
Linux interface for most system-administration concerns -- firewalls alone
split across firewalld, ufw, nftables, and iptables depending on the
distro, and `hostnamectl`/`systemctl` (Cystoolbox's `SetHostname`/`Reboot`)
only exist at all on systemd-based hosts. `crates/agent/src/firewall.rs`
and `crates/agent/src/init_system.rs` each detect what's actually present
(same idea the original bash toolbox used for package managers) and
dispatch accordingly, refusing cleanly rather than guessing when an
operation isn't well-defined for what was detected (e.g. there's no single
"enable" command for raw nftables). `init_system.rs` is the simpler of the
two: unlike the firewall backends, the non-systemd fallback commands
(`hostname` + writing `/etc/hostname`; `reboot`) don't themselves vary by
*which* non-systemd init is running (OpenRC, runit, sysvinit, ...) --
they're provided by whichever init package owns PID 1, not the init
system's own tooling -- so detection only needs to answer systemd-or-not,
not identify a specific alternative. **Every future arsenal that shells
out to a command with more than one common Linux implementation should
follow this same pattern**: detect what's present (a file/directory that
tool creates, like `/run/systemd/system`, is usually more reliable than
checking whether a same-named binary happens to be on `PATH`, since some
distros ship non-functional compatibility shims) and dispatch accordingly,
rather than assuming the tool the developer's own machine happens to have.
Not every case needs a dedicated module, though: Necrolink's DNS
configuration read (`network::dns_config` in `crates/agent/src/network.rs`)
is the same detect-don't-assume idea handled inline, in a few lines --
try `resolvectl status`, fall back to reading `/etc/resolv.conf` directly
if that's not usable -- since it's a single yes/no fallback, not several
named backends worth their own enum and file the way firewalld/ufw/nftables
/iptables or systemd/non-systemd are.

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
   The host row itself stays (shown with a "Revoked" badge) so its audit
   history remains attributable.
7. Removing a host (`/admin/hosts/<id>/remove`) hard-deletes the row
   entirely -- a separate, stronger action from revoke, since revoke alone
   never took the host out of the list. Nothing else references
   `hosts.id` by foreign key (the audit log stores a free-text resource
   label, not an FK, by design), so this is safe on its own and the audit
   trail survives the host's deletion. This only removes Abyssal
   Arsenal's own record of the host; it does not (and, on an already
   offline/decommissioned host, often *can't*) reach out and uninstall
   the agent remotely. The confirmation flow instead shows a copy-paste
   uninstall command for the target host, the same UX as the enrollment
   command.

`AgentOperation` is deliberately a fixed, named whitelist. Every new
sysadmin capability an arsenal needs on a host means adding a variant to
`agent-protocol` and a handler in `crates/agent/src/ops.rs` -- there is no
path from a wire message to running something outside that fixed list.

**Protocol versioning.** A stale agent build (one compiled before some
`AgentOperation` variant it's now being sent) fails to deserialize the
`ServerMessage` and disconnects -- its own reconnect loop then quietly
brings it back online, which used to make a real incompatibility look like
a transient network blip. `agent-protocol::PROTOCOL_VERSION` exists to make
that loud instead: the agent sends it as an `X-Agent-Protocol-Version`
header on every connection, the control plane compares it against its own
copy, and a mismatch (including an agent old enough to predate this header
entirely) shows a warning banner on that host's pages
(`HostConnectionRegistry::agent_protocol_mismatch`) rather than silently
flapping. **Bump this constant whenever a change here could break an older
agent's ability to deserialize a message** -- most commonly, adding a new
`AgentOperation` variant. This is a coarse, conservative signal, not a real
compatibility check: an old agent might still handle everything actually
sent to it, but there's no cheap way to know that in advance, so any wire
change just calls the whole build "out of date." There is deliberately no
remote/self-update mechanism -- the agent only ever running its fixed,
named whitelist (never arbitrary code from the wire) is the actual security
boundary, and a binary-push update would mean the control plane could push
arbitrary code to every enrolled host, which is a categorically different
risk. Redeploying a flagged agent is a manual step (rebuild, reinstall,
restart -- see `crates/agent/README.md`).

### Apotheosis: time-boxed sudo elevation

Rather than requiring the agent to run permanently as root, an admin with
the dedicated `hosts.elevate` permission (Super Admin only by default) can
elevate a connected host's agent on demand, modeled on Cockpit's
"Administrative access" toggle. The mechanism is entirely on the agent
side and unchanged regardless of where it's triggered from:

- Elevating submits a sudo password, which the control plane forwards to
  the agent as an `AgentOperation::Elevate`. The agent validates it by
  running `sudo -S -v` -- the same mechanism interactive `sudo` already
  uses to populate its own timestamp cache -- rather than running an
  arbitrary command as root. On success, the agent starts a sliding idle
  window (`crates/agent/src/elevation.rs`, `ElevationState`) whose length
  is configurable, default 20 minutes, set on the control plane's Settings
  page (`apotheosis.elevation_window_minutes`) and sent to the agent on
  each `Elevate` call as `idle_timeout_secs` -- the agent has no database
  access of its own, so it can't look the value up locally. The window
  refreshes on every use, so activity keeps elevation alive but idleness
  lets it lapse on its own. Changing the setting only affects elevations
  granted after the change; a host already elevated keeps whatever window
  was in effect when it was elevated.
- While elevated, operations that need root (`SetHostname`, `Reboot`, the
  firewall operations) run as `sudo -n <command>` instead of unprivileged;
  everything else is unaffected.
- De-escalating clears the window early and also runs `sudo -k` to drop
  sudo's own cache, in case its configured `timestamp_timeout` is longer
  than Abyssal Arsenal's own configured window.
- Elevation state lives only in the agent process's memory -- a reboot or
  an agent restart clears it unconditionally, with nothing persisted to the
  control plane's database. The password itself is never written to disk,
  the database, or any log, on either side; it is held just long enough to
  hand to `sudo`'s stdin and is then actively zeroized
  (`zeroize::Zeroizing`), not just dropped. `AgentOperation`'s hand-written
  `Debug` impl redacts the password as a backstop, in case anything ever
  formats an operation with `{:?}`.
- Elevating posts a real password over the wire, so this is the one
  feature in the platform where running without TLS actively matters, not
  just generally recommended -- see [SECURITY.md](SECURITY.md).

**Where elevation is triggered from, and how it's surfaced in the UI**
(this part changed after the mechanism above was first built -- `/admin/hosts`
no longer has any elevate/de-escalate controls of its own):

- Every arsenal that dispatches host operations (all except Panopticon,
  which is control-plane-only) follows a host-picker -> per-host page
  navigation
  (`/arsenals/<name>` lists connected hosts; `/arsenals/<name>/<host_id>`
  is where operations actually run, one host at a time -- matching how
  elevation is itself scoped per host, not per arsenal). Every action form
  on that page carries an optional sudo password field, shown only while
  the host isn't already believed elevated. Submitting a password elevates
  first (`crate::common::maybe_elevate`) and, only on success, proceeds to
  dispatch the operation the admin actually wanted, in the same request --
  no separate confirmation step. A destructive action's own confirmation
  page (Reboot, Enable Firewall) carries the same optional field.
- The control plane keeps its own lightweight, best-effort mirror of which
  hosts are currently believed elevated (`abyssal_hosts::ElevationTracker`,
  `AppState.elevation`) purely so the UI can show status without an agent
  round-trip on every page load. This is **not** a security boundary --
  the agent's own `ElevationState` is what actually gates privileged
  commands. The mirror can drift (e.g. the agent's window lapses without
  the control plane finding out); the practical effect of drift is just
  that the sudo password field might not reappear immediately after a
  stale-positive entry, not that anything unauthorized runs -- a failed
  dispatch defensively clears the entry either way.
- A "Apotheosis" item in the top nav (visible only with `hosts.elevate`)
  pulses red whenever the tracker believes at least one host is elevated,
  and opens a panel listing every such host with its remaining time and a
  De-escalate button -- a status/control surface, not itself where
  elevation happens.

## The second-gate pattern for catastrophic-risk operations

Every Destructive operation already requires the caller to explicitly set
`confirm: true` and, in the web UI, type the exact target back
(`ConfirmTemplate`'s `type_to_confirm`). A handful of operations are
categorically worse than that tier was designed for -- not "this changes
something and should be double-checked," but "a single wrong input here
destroys or disconnects something with no remote way to undo it." For
those, a Destructive confirmation alone isn't enough: an admin has to
have deliberately decided, in advance and separately from any one
action, that this class of operation is allowed to run at all.

The pattern: a dedicated, off-by-default setting
(`abyssal_core::settings`, e.g. `ossuary.high_risk_storage_ops_enabled`,
`inquest.host_isolation_enabled`), checked fresh at *every* entry point
that leads to dispatching the operation -- both the GET confirm-page
route and the POST dispatch route, never assumed from an earlier check --
on top of (never instead of) the type-to-confirm the operation still
requires individually. Three operations use it so far: Ossuary's
partition/RAID/LVM-create and `mkfs` (a wrong device path destroys a
disk instantly), Inquest's full host network isolation (a wrong edge
case severs the agent's own manageability with no remote fix), and
Thanatos's background monitoring sweep (a different kind of risk -- not
one destructive action, but an unattended task that reads and persists
security-log content across the whole fleet on its own, which an admin
should have to consciously opt into). A future operation belongs behind
this pattern if getting it wrong once, unattended or with a typo, would
be worse than what the existing Destructive tier already assumes it
might be.

## Background tasks

Everything in the control plane is otherwise request-driven -- nothing
runs unless a browser or an agent connection causes it to. Two
exceptions, both `tokio::spawn`'d fixed-interval loops started once at
startup (`crates/app/src/main.rs`), following the same shape: no
`AuthContext` to check permissions against, since nothing initiated the
work, so each bypasses the request-oriented `Executor` entirely and
talks to the lower-level primitive underneath it directly.

- **Elevation expiry sweep** (`spawn_elevation_expiry_sweep`, every 60s):
  `ElevationTracker::is_elevated`/`snapshot` already evict lapsed entries
  lazily, only when something happens to look -- fine for UI correctness,
  but it means a natural expiry with nothing else touching that host
  would otherwise never get an audit record at all. This loop is the one
  active, unconditional check, writing a `HostElevationExpired` audit
  event per lapsed entry it finds.
- **Thanatos sweep** (`abyssal_web::spawn_thanatos_sweep`, every 60s):
  checked first against `thanatos.monitoring_enabled` (see "The
  second-gate pattern" above) -- does nothing on a tick where it's off,
  re-checked fresh every tick so toggling the setting takes effect on the
  next tick, not after a restart. When on, dispatches
  `AgentOperation::ScanSecurityEvents` to every connected host directly
  through `HostConnectionRegistry::dispatch` (bypassing
  `execute_on_host()`), then runs the same persist-and-correlate pipeline
  the on-demand scan route uses.

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

Five migrations so far:

- `0001_init.sql` -- `users`, `roles`, `permissions`, `role_permissions`,
  `user_roles`, `sessions`, `audit_log`, `settings`, `modules`.
- `0002_hosts.sql` -- `hosts`, `host_enrollment_tokens`.
- `0003_user_timezone.sql` -- adds `users.timezone`, so every timestamp in
  the app renders from each user's own point of view rather than a fixed
  server timezone.
- `0004_panopticon.sql` -- `panopticon_devices` (the discovered-device
  inventory) and `hosts.last_seen_ip` (the connecting agent's address,
  captured once at WebSocket upgrade time, used to correlate a discovered
  device against a known managed host).
- `0005_thanatos.sql` -- `thanatos_events` (classified security events and
  correlation findings, deduplicated by a content hash over host +
  source + raw line so re-scanning the same log tail window is a
  harmless no-op).

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
- `nmap` is included in the runtime image for Panopticon's discovery
  scans, which run unprivileged (`-sT`, no raw sockets needed) from
  wherever the control-plane process itself runs. Behind Docker's default
  bridge network, that's the Docker bridge, not the physical LAN --
  reaching a real network needs host networking, or running the binary
  directly outside Docker.

## Known limitations

These are documented tradeoffs for the current single-instance deployment
model, not oversights:

- `LoginLimiter` and `HostConnectionRegistry` are both in-memory and
  process-local. A multi-instance control plane would need both backed by
  shared state instead.
- SSO/OIDC and additional notification providers (Telegram, Slack, Teams,
  Discord) are not implemented yet -- see [CHANGELOG.md](CHANGELOG.md) for
  current status. All 23 arsenals have real capabilities.
- Thanatos is deliberately a pull-based, on-demand/periodic-sweep
  telemetry collector, not a continuous push-based EDR agent -- no eBPF,
  no live event stream, no offset-tracked log tailing (re-scanning the
  same window is expected and deduplicated, not prevented). A real
  push-based transport and endpoint telemetry are a documented later
  phase, not an oversight -- see the Thanatos entry in
  [CHANGELOG.md](CHANGELOG.md).
- The agent does not sandbox or rate-limit operations beyond the fixed
  `AgentOperation` whitelist. Privilege escalation for an unprivileged
  agent deployment is handled by Apotheosis (see "Host enrollment and the
  agent protocol" above); running the agent as root permanently remains a
  valid alternative deployment choice.
