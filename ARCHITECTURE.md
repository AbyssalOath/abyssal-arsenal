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
2. The operator runs `abyssal-agent` on the target host (with no arguments,
   it interactively prompts for the control plane URL and the token, then
   installs and enables a systemd service; `abyssal-agent run
   --control-plane-url ... --enrollment-token ...` is the same enrollment
   without the prompts or the service setup, for scripted installs). The
   agent `POST`s the token to `/api/hosts/enroll` -- this endpoint is
   authenticated purely by the token, not a browser session, and is
   intentionally outside `CurrentUser`/CSRF.
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
(this part changed twice after the mechanism above was first built --
`/admin/hosts` no longer has any elevate/de-escalate controls of its own,
and neither does any individual action form):

- Every arsenal that dispatches host operations (all except Panopticon,
  which is control-plane-only) follows a host-picker -> per-host page
  navigation
  (`/arsenals/<name>` lists connected hosts; `/arsenals/<name>/<host_id>`
  is where operations actually run, one host at a time -- matching how
  elevation is itself scoped per host, not per arsenal).
- Elevating is a single, dedicated control near the top of a host's page --
  one "Elevate this host" form, shown only while the host isn't already
  believed elevated -- rather than a password field duplicated onto every
  individual action form. Submitting it posts to that arsenal's own
  `POST /arsenals/<name>/:host_id/elevate` route, which calls
  `crate::common::maybe_elevate` and re-renders the same host page. Every
  other action form on the page (read, write, or destructive) no longer
  carries a password field or threads one through
  `run_read_op`/`run_write_op`/`run_destructive_op` -- elevating is a
  deliberate first step, not bundled into whichever action happens to be
  clicked first.
- The control plane keeps its own lightweight, best-effort mirror of which
  hosts are currently believed elevated (`abyssal_hosts::ElevationTracker`,
  `AppState.elevation`) purely so the UI can show status without an agent
  round-trip on every page load. This is **not** a security boundary --
  the agent's own `ElevationState` is what actually gates privileged
  commands. The mirror can drift (e.g. the agent's window lapses without
  the control plane finding out); the practical effect of drift is just
  that the "Elevate this host" control might not reappear immediately
  after a stale-positive entry, not that anything unauthorized runs -- a
  failed dispatch defensively clears the entry either way.
- A "Apotheosis" item in the top nav (visible only with `hosts.elevate`)
  pulses red whenever the tracker believes at least one host is elevated,
  and opens a panel listing every such host with its remaining time and a
  De-escalate button -- a status/control surface, not itself where
  elevation happens.

## Deploying agents over SSH ("Quick Add Host From Network Scan")

Enrollment above assumes an operator SSHing into the target by hand and
running `abyssal-agent run --control-plane-url ... --enrollment-token ...`
themselves. This feature bridges Panopticon's discovery scan directly to
that same enrollment path: pick devices a scan just found, supply SSH
credentials, and let the control plane SSH in and run the installer for
you. Nothing on the agent side changed -- `abyssal-agent install
--control-plane-url <url> --enrollment-token <token>` (`crates/agent/src/
main.rs`) was already fully non-interactive whenever both flags are given;
this is entirely a new control-plane capability.

**Flow** (`crates/web/src/routes/panopticon_deploy.rs`,
`crates/web/src/ssh_deploy.rs`): scan results -> picker (checkboxes,
"select all"/"none") -> SSH credentials (one shared set plus optional
per-host overrides) -> host-key review -> deploy status. Every step is a
plain server-rendered page, matching this app's no-client-JS house style
-- "select all"/"none" and the auto-refreshing status page
(`<meta http-equiv="refresh">`) both work without any JavaScript. A
discovery scan already upserts every device it finds into the inventory
unconditionally (`panopticon_ops::run_discovery_scan`), so cancelling out
of the picker loses nothing; only "Add Hosts" continues into this flow.

**Host keys: trust-on-first-use, never silently disabled.** The
credentials step's submit triggers a probe -- open an SSH connection far
enough to read the server's public key fingerprint, no authentication
attempted -- for every selected host, storable in `ssh_trusted_host_keys`
(`migrations/0013_ssh_deploy.sql`). A first sighting is shown for the
admin to confirm; an already-trusted, unchanged fingerprint skips the
review page entirely (`deploy_hostkeys`'s "every host already trusted"
fast path) so a repeat deploy doesn't need to carry credentials through
one extra hop unnecessarily; a **changed** fingerprint is a hard stop for
that host specifically -- it's simply excluded from what gets sent to the
confirm step, with no way to click past it in the same flow.

**Credentials are never persisted, anywhere, ever.** `SshCredentials`'
password/private-key/passphrase/sudo-password fields are all
`zeroize::Zeroizing<String>` (the same primitive `crates/web/src/
common.rs` and `crates/agent/src/elevation.rs` already use for exactly
this reason). There is no saved-credential store, on purpose --
`crates/web/src/ssh_deploy.rs`'s module comment and the original
implementation plan both call this out as a deliberately deferred, opt-in
feature if ever wanted, which would reuse `abyssal_core::crypto::
EncryptionKey` (built for Panopticon's SNMP community strings) rather than
inventing new storage. Between steps, credentials exist only as hidden
form fields in the rendered HTML and the next request's body -- the same
mechanism `confirm.html`'s existing `sudo_password` field already uses for
the single-step Apotheosis elevation confirm, just spanning a couple of
extra hops here since there's no server-side session to hold them in
instead. The sudo password and the enrollment token are never placed on
the remote command line at all: the sudo password is piped to `sudo -S`
over the SSH session's stdin (mirroring how `crates/agent/src/
elevation.rs` already sends a sudo password to `sudo -S -v` over the
agent's own WebSocket), and every other value interpolated into a remote
command string is both validated (`abyssal_agent_protocol::
is_valid_ip_address`, or `is_valid_hostname` before a hostname becomes
`--name`) and POSIX-single-quote-escaped (`ssh_deploy::shell_quote`) as
defense in depth, since an SSH `exec` channel takes one command string the
remote shell parses -- there's no safe argv-passing option the way a local
`Command::arg()` has.

**Enrollment tokens are one-per-host, not one-per-job.**
`host_enrollment_tokens::consume` is single-use by design (see host
enrollment above), so a deploy job generates and stores one fresh
15-minute token per selected host at the moment the job actually starts
(`start_deploy_job`) -- reusing a single token across multiple hosts would
only ever enroll the first one.

**Orchestration** (`ssh_deploy::run_deploy_job`): a `tokio::sync::
Semaphore`-gated `tokio::task::JoinSet`, default concurrency 5, so one
host's failure or a hung connection can never block or delay the others.
Each host gets its own connect timeout (10s) and command timeout (5
minutes). Confirming success is **not** "the install command exited 0" --
after a successful install, the task polls (bounded, 60s total) for a host
row matching the `--name` it told the agent to register as that has
actually connected back over its own WebSocket
(`HostConnectionRegistry::is_connected`), the same live-connection state
`/admin/hosts` itself reads. `HostDeployStarted`/`HostDeploySucceeded`/
`HostDeployFailed` audit rows (one per host per attempt, attributed to
whoever confirmed the deploy) are the durable record of what happened;
progress itself (`AppState.deploy_jobs`) is in-memory only, mirroring the
one other precedent for live shared state on `AppState`
(`update_status`) -- losing job progress on a restart isn't a durability
requirement worth a database table for, and every meaningful outcome is
already in the audit log regardless.

The one real implementation of the `SshClient`/`SshSession` traits this
all runs against is `russh` (`RusshClient`, `RusshSession`) -- a pure-Rust
SSH client, chosen specifically so password authentication and reading
stdin (`sudo -S`) don't need a subprocess wrapping the system `ssh`
binary. Everything above is built against the trait, not `russh` directly,
so `ssh_deploy`'s own tests exercise every named failure mode (connection
refused/timeout, auth failure, sudo denied, a changed host key, a failed
download/install, and "exited 0 but the agent never checked in") against a
fake implementation with no real network involved.

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
runs unless a browser or an agent connection causes it to. The exceptions
are all `tokio::spawn`'d, started once at startup (`crates/app/src/
main.rs`), and share one trait: no `AuthContext` to check permissions
against, since nothing initiated the work, so each bypasses the
request-oriented `Executor` entirely and talks to the lower-level
primitive underneath it directly. Most are fixed-interval sweeps that
always start; Panopticon's mDNS and ARP listeners are a different shape
-- event-driven receive loops, and each only starts at all if its
setting says to (checked once, here, not re-checked per-tick the way a
sweep's gate is, since starting one means binding a real socket or
opening a raw capture, not flipping a soft flag -- see their own bullets
below for what that implies for toggling them).

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
- **Panopticon sweep** (`abyssal_web::spawn_panopticon_sweep`, two
  independent loops): a passive refresh every 60s, unconditional --
  re-reads the control plane's own kernel neighbor table (`ip neigh`,
  no traffic sent) and records a sighting for every entry, the same
  best-effort MAC source the manual scan already uses -- and an active
  nmap sweep every 30 minutes, gated first against
  `panopticon.sweep_enabled` and a non-empty `panopticon.sweep_target`
  (both re-checked fresh every tick), which re-runs the same discovery
  scan the manual, admin-triggered scan uses. Both loops share one
  "record a sighting" pipeline with the on-demand scan route
  (`panopticon_ops.rs::run_discovery_scan`/`audit_sighting`): a device
  never seen before, or a device already classified `Untrusted` that
  reappears after having gone stale (`NetworkDevice::is_stale`), gets a
  `NetworkDeviceDiscovered`/`NetworkUntrustedDeviceSeen` audit event --
  edge-triggered, not per-tick, so a persistently-visible untrusted
  device doesn't spam the log.
- **Panopticon SNMP sweep** (`abyssal_web::spawn_panopticon_snmp_sweep`,
  every 5 minutes): polls every enabled row in `panopticon_switches` over
  SNMP v2c for BRIDGE-MIB's `dot1dTpFdbTable` (MAC -> bridge port,
  joined through `dot1dBasePortIfIndex` and IF-MIB's `ifDescr` for a
  human port label) -- the mechanism that gives a device's inventory row
  a `switch_id`/`switch_port`. Each switch's community string is stored
  encrypted (`abyssal_core::crypto::EncryptionKey`, AES-256-GCM,
  `ENCRYPTION_KEY` env var) -- the one credential this platform stores
  reversibly rather than hash-only, since the sweep has to present the
  actual plaintext to the switch with nobody around to type it in again.
  No-ops entirely when `ENCRYPTION_KEY` isn't set. Every SNMP request is
  individually timeout-bounded (`panopticon_snmp.rs::REQUEST_TIMEOUT`,
  5s) so one unreachable switch can't stall the sweep; per-switch success/
  failure is recorded on the switch row (`last_polled_at`/
  `last_poll_error`) and shown on `/arsenals/panopticon/switches`. Shares
  the manual "Poll now" button's exact polling code
  (`panopticon_snmp.rs::poll_and_record`) -- the only difference is
  `Executor`-gated vs. unattended, same split as every sweep/manual-action
  pair in this table. The same SNMP session also walks IF-MIB's 64-bit
  `ifHCIn/OutOctets` (falling back to the legacy 32-bit counters if a
  switch doesn't expose the HC ones) for every port it saw an `ifDescr`
  for, not just ports with a live FDB entry, and records one raw counter
  row per port into `panopticon_port_traffic_raw` -- the bandwidth
  history feature's only collection point, piggybacking on this sweep
  rather than polling separately.
- **Panopticon traffic rollup** (`abyssal_web::spawn_panopticon_traffic_rollup`,
  every hour): turns those raw counter rows into actual bandwidth graphs.
  Consecutive raw samples become rate points (bits/sec) in
  `panopticon_traffic.rs::rates_from_raw` -- a decrease between two
  readings is a wraparound for a legacy 32-bit counter (adds back 2^32,
  the standard MRTG/Cacti convention; a 32-bit counter can wrap multiple
  times between polls on a fast link, which this can't recover from, an
  inherent 32-bit-counter limitation) or a reset for a 64-bit one (skipped
  outright, since 2^64 bytes is never reached in practice). Every hour,
  and once a day, computes and upserts that period's rollup bucket
  (avg/max bps) directly from raw data for every known port -- the two
  rollup tiers are independent of each other, not chained, so either can
  be on while the other is off. Each tier's retention is admin-configurable
  (Settings page, `panopticon.traffic_{raw,hourly,daily}_retention_days`);
  `0` for the hourly or daily tier means fully off -- not computed, and
  every existing row for it deleted, not just left to stop growing. Raw
  retention has a 2-day floor (`panopticon_traffic.rs::MIN_RAW_RETENTION_DAYS`)
  regardless of what's configured, since the daily rollup needs a full
  elapsed day of raw data still on hand when it runs. The traffic page
  (`/arsenals/panopticon/switches/:id/traffic`) picks the coarsest tier
  that still fully covers whatever duration preset is selected (raw when
  it fits, else hourly, else daily) and renders the result as an inline
  SVG line chart computed server-side (`panopticon_traffic.rs::
  render_chart_svg`) -- no client-side JavaScript charting library, this
  app has none anywhere.
- **Panopticon mDNS listener** (`abyssal_web::spawn_panopticon_mdns_listener`,
  gated by `panopticon.mdns_enabled`): an ordinary UDP multicast socket
  join on port 5353, no elevated privileges needed -- picks up devices
  that self-announce a `*.local` hostname (most consumer/IoT gear) even
  if they never respond to an active scan. Hand-rolled DNS message
  parsing (`panopticon_mdns.rs`, including RFC 1035 name-compression
  pointers, bounded against a malicious/corrupt pointer loop) rather than
  a new dependency, consistent with this codebase's existing preference
  for hand-rolled parsing of a well-understood wire format over pulling
  in a crate for one field. Off by default; binding the socket is a real
  startup-time resource acquisition, so toggling this takes a server
  restart, the same posture a raw syslog UDP/TCP receiver would need.
- **Panopticon ARP listener** (`abyssal_web::spawn_panopticon_arp_listener`,
  gated by `panopticon.arp_enabled` + a non-empty `panopticon.arp_interface`):
  raw `AF_PACKET` capture via `pnet_datalink`, the one place in this
  entire workspace that needs elevated privileges (`CAP_NET_RAW`) --
  every other arsenal, including the rest of Panopticon, runs as an
  ordinary unprivileged process by design. Granted as a Linux file
  capability on the binary itself (Dockerfile's `setcap cap_net_raw+eip`),
  not by running the container as root, so `USER abyssal` still holds;
  docker-compose.yml's `cap_add: [NET_RAW]` makes the container-level
  grant explicit. `promiscuous: false` deliberately -- ARP is link-layer
  broadcast/direct-reply traffic an ordinary bridge port already receives,
  so promiscuous mode (which would additionally need `CAP_NET_ADMIN`)
  buys nothing here. The blocking `DataLinkReceiver::next()` call runs on
  a `spawn_blocking` task, forwarding parsed sightings to an ordinary
  async task over an `mpsc` channel rather than blocking a tokio worker
  on socket reads. Same Docker-bridge-vs-physical-LAN caveat the manual
  discovery scan's own page already states, and the same
  restart-to-toggle posture as the mDNS listener.
- **Dashboard health sweep** (`abyssal_web::spawn_health_sweep`, every 5
  minutes): dispatches `AgentOperation::FailedServices` (Mortiscope) to
  every connected host directly through `HostConnectionRegistry::dispatch`
  and upserts one row per host into `host_health_snapshots` (parsing
  `systemctl --failed`'s own trailing summary line for a failed-unit
  count, rather than counting rows, since that's robust to both the
  header row and the "no systemd on this host" message a non-systemd host
  returns instead). The dashboard's "hosts needing attention" reads this
  table instead of dispatching to every agent on every page load; a host
  is flagged when the sweep found failed units or couldn't reach it at
  all.
- **Update check sweep** (`abyssal_web::spawn_update_check_sweep`, every 6
  hours, plus once immediately on startup): the one background task that
  talks outbound to the internet rather than to a managed host -- a plain
  `GET` against GitHub's releases API (no auth token, no data sent beyond
  a fixed `User-Agent`), cached in `AppState.update_status`
  (`Arc<RwLock<UpdateStatus>>`) for the dashboard to read. Best-effort and
  read-only: a failed check (offline, rate-limited, self-hosted with no
  egress allowed) just leaves the last-known status in place -- see
  "Version tracking and update notice" below.

## Version tracking and update notice

`VERSION` at the repository root is the single source of truth for this
build's version -- `install.sh`, the release workflow, and the running
binary itself all read from it rather than each keeping a separate copy
in sync by hand. `crates/web/src/update_check.rs` embeds its contents at
compile time (`include_str!`) as `CURRENT_VERSION`, so the running binary
always knows its own version without a runtime file read.

The update check sweep (see "Background tasks" above) compares this
against the `tag_name` of GitHub's `/releases/latest` API response using a
plain `(major, minor, patch)` tuple comparison -- no `semver` crate
dependency, since release tags are always plain `vX.Y.Z` with no
pre-release suffixes to parse. The dashboard (`crates/web/templates/
dashboard.html`) shows the result as a small notice at the top of the
page: the current version alone, in muted styling, when no newer release
is known; or a red, pulsing, clickable notice (current version -> latest
version, linking to the release page) once one is. The arrow is written
as the HTML numeric entity `&#8594;`, not a literal Unicode character, so
it can never render as mojibake regardless of how the template file
itself gets edited or transferred.

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

### Global host context

A cookie-based host switcher (`abyssal_selected_host`, the same plain
per-browser-preference pattern as the existing theme cookie -- see
`crates/web/src/host_context.rs`) sits in the top nav on every
authenticated page and stays selected across arsenals. Selecting a host
posts to `/host-context/select`, which redirects back to wherever the
switcher was submitted from using the browser's own `Referer` header
(path and query only, scheme and host discarded, so a spoofed or
cross-origin `Referer` can only send the redirect back into the app
itself) -- deliberately not a hidden `redirect_to` field threaded through
every page. This is purely a UI convenience, never a security boundary:
every arsenal action still validates the host it's given from the URL
path, not from this cookie.

Every per-host arsenal's landing route (`/arsenals/<name>`) gained one
guard: if a host is selected and still connected, it redirects straight
to `/arsenals/<name>/<host_id>` instead of rendering the host-picker
list, falling back to the picker if the selected host is offline or
nothing is selected. Rendering the switcher itself (the connected-host
list and which one is selected) needed the full host list on every
authenticated page, not just per-host arsenal pages, so `BaseCtx::build`
became async and gained a `pool`/`hosts` dependency -- a larger blast
radius than the switcher's own UI (every one of the ~80 call sites across
the codebase that build a page's chrome), but unavoidable since the
switcher has to render everywhere, not just on arsenal pages.

## Data model

Twelve migrations so far:

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
- `0006_pinned_modules.sql` -- `user_pinned_modules`, a per-user favorites
  list for the dashboard's arsenal grid (see "Web UI overhaul" in
  [CHANGELOG.md](CHANGELOG.md)).
- `0007_dashboard_health_and_backups.sql` -- `host_health_snapshots` (the
  dashboard health sweep's per-host results, one row per host, upserted
  every tick) and `backup_records` (one row per backup Reliquary creates,
  so the dashboard can show fleet-wide backup status cheaply).
- `0008_password_resets.sql` -- `password_resets` (single-use, short-lived
  local-account reset tokens, hash-only at rest like every other bearer
  token this platform stores).
- `0009_role_module_visibility.sql` -- `role_module_visibility`, a
  per-role declutter layer on top of (never instead of) the permission
  system for the dashboard's arsenal grid.
- `0010_panopticon_enrichment.sql` -- adds `device_type`/`trust_state`/
  `notes` to `panopticon_devices` (the first NAC-adjacent primitive, an
  admin-assigned trust flag) and normalizes what had been a freeform
  `open_ports` string into its own `panopticon_device_ports` table.
- `0011_panopticon_switches.sql` -- `panopticon_switches` (managed
  switches Panopticon polls over SNMP, community string encrypted at
  rest) and `panopticon_devices.switch_id`/`switch_port`/
  `switch_port_seen_at`, populated by the SNMP sweep.
- `0012_panopticon_traffic.sql` -- `panopticon_switch_ports` (every port a
  poll has ever seen `ifDescr` for on a switch), `panopticon_
  port_traffic_raw` (raw per-poll octet counters), and the
  `panopticon_port_traffic_hourly`/`_daily` rollup tiers -- see the
  "Panopticon traffic rollup" background-task bullet above for how the
  three fit together.

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
- `ENCRYPTION_KEY` (optional; `install.sh` generates one unconditionally)
  is the AES-256-GCM master key for Panopticon switches' stored SNMP
  community strings. Unset it and the app still runs fine -- adding a
  switch just refuses cleanly until it's set.
- Panopticon's ARP listener (off by default) is the one place in this
  workspace that needs elevated privileges. The Dockerfile grants
  `CAP_NET_RAW` to the binary itself (`setcap`), not to the container's
  root user, so the process still runs as the unprivileged `abyssal` user;
  docker-compose.yml's `cap_add: [NET_RAW]` and the published `5353/udp`
  (for the mDNS listener, also off by default) exist for these two
  opt-in features and do nothing while both stay disabled.

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
- The control plane makes exactly one kind of outbound internet call: the
  update check sweep's plain `GET` against GitHub's releases API (see
  "Version tracking and update notice" above). A fully air-gapped
  deployment simply never gets a successful check -- the dashboard falls
  back to showing the current version alone, nothing else in the app
  depends on it, and there's no other outbound network dependency
  anywhere in the control plane.
