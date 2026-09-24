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
- Role membership itself (not just permissions) is also reused directly by
  feature code outside the auth system proper: Grimoire's macros (GitHub
  issue #7, `crates/core/src/macros.rs`) scope a saved macro to a role via
  the same `roles`/`user_roles` tables and
  `repo::roles::roles_for_user`, rather than a second, feature-specific
  notion of "team." A new `Permission::MacrosManageAll` (granted only to
  Super Admin, like `AuditManage`) is the one addition macros needed --
  everything else about "who can see/use/edit a macro" is ordinary
  ownership plus existing role membership.

## Delegated custom roles (GitHub issue #8)

Every role beyond the five built-in ones is a *custom role*, created by
whoever holds `roles.manage` -- typically not just Super Admin anymore,
since a Super Admin can grant `roles.manage` to any built-in or custom
role to turn it into a delegated admin. The whole feature rests on one
new column and one rule.

- **`roles.parent_role_id`** (nullable FK to `roles.id`) makes a role
  either a *root* (`NULL` -- every system role, always) or a *sub-role*
  of some other role, system or custom. Nesting is capped at
  `abyssal_core::MAX_ROLE_DEPTH` (3: root, child, grandchild), enforced
  in the route handlers at create/reparent time, not the schema (MariaDB
  can't express a bounded-depth tree constraint declaratively). A cycle
  (reparenting a role under its own descendant) is rejected the same way
  -- `repo::roles::would_create_cycle`.
- **Effective permissions are computed at check time, never cached or
  materialized**: a role's effective set is its own `role_permissions`
  grants intersected with every ancestor's own grants, all the way to
  the root (`repo::roles::effective_permissions_for_role`). A root role's
  effective set is just its own grants -- unchanged from today's
  behavior for every existing role and user, confirmed by
  `migrations/0017_custom_roles.sql` giving every pre-existing role
  `parent_role_id = NULL`. Because nothing is cached, an admin revoking a
  permission from a parent role takes effect for every descendant's next
  permission check immediately, with no stale grant anywhere -- the
  tradeoff (documented, deliberate) is one extra ancestor-chain walk per
  check rather than a single-row lookup.
- **A user holds exactly one assigned role at a time** (`user_roles`
  stays a many-to-many table unchanged, but `repo::roles::set_user_role`
  always replaces whatever was there). The Add/Edit User "role, then
  sub-role" picker is a two-step *UI* affordance for choosing that one
  role -- pick a top-level role, optionally narrow to one of its
  children -- not two simultaneous assignments; unioning a parent and its
  own (always-narrower-or-equal) sub-role would just collapse back to the
  parent's full set and defeat the sub-role's entire purpose. In this
  app's UI a flat, indented `<select>` stands in for a true cascading
  pair of selects, since there's no client-side JS to filter the second
  one -- see "Live-updating progress pages" above for the (unrelated,
  narrowly-scoped) exceptions to that rule.
- **Delegation scope, all enforced server-side**
  (`crates/web/src/common.rs`):
  - `has_no_ceiling(ctx)` -- true for a user holding every known
    permission (in practice, Super Admin). Deliberately *not* a
    hard-coded role-name check, matching "a role is just a named
    collection of permissions" above; it's the computed stand-in for "no
    delegation ceiling," used everywhere below instead of asking "is
    this Super Admin?" by name.
  - `grantable_permissions(ctx)` -- every permission for a no-ceiling
    user, or exactly `ctx`'s own current effective permissions
    otherwise. Every route that accepts a requested permission set
    (role creation, permission edits) intersects this with the chosen
    parent's own effective set before accepting anything, so a role's
    grants always fit under *both* its creator's ceiling and its
    parent's actual grants.
  - `ensure_can_manage_role(pool, ctx, role)` -- a no-ceiling user
    manages any role; otherwise `roles.manage` plus `role` being within
    the subtree rooted at `ctx`'s own assigned role
    (`repo::roles::is_within_subtree`), never a system role (those have
    no parent for a delegated admin's subtree to descend from, so
    editing one -- unchanged from today -- requires no ceiling), and
    never the role `ctx` is themselves currently assigned (stops
    widening your own grants by editing your own role).
  - `assignable_roles(pool, ctx)` -- a no-ceiling user may assign any
    role to a user; otherwise, `ctx`'s own role plus every descendant of
    it (`repo::roles::descendants_of`). Assigning your own unchanged
    role to someone else is always safe (they get exactly your own
    capped set, never more), which is what makes onboarding work for a
    delegated admin at all.
- **Permission-checklist UI capping.** A role's permission checkboxes
  only ever show permissions within the *viewer's* cap (their own
  ceiling intersected with the role's parent); anything the role
  actually has outside that cap is neither shown nor editable, and is
  explicitly *preserved* (never silently dropped) when a scoped admin
  saves a change to the fields they can see --
  `routes/roles.rs::apply_permissions` unions the submitted
  (already-capped) set back with whatever fell outside the editor's own
  cap before writing. The dashboard-arsenals picker is capped
  differently: by the role's own *effective* permission set (visible to
  anyone who can manage the role at all), not the viewer's personal
  ceiling, since "an arsenal never grants access on its own" already
  applied uniformly before this feature and keeps doing so per role.
- **Deletion is blocked, not auto-reassigned**, if a role has any users
  or child roles still assigned to it (documented, deliberate tradeoff:
  friendlier auto-reassignment risks silently changing what a real
  account can do). `routes/roles.rs::delete_role`/`delete_role_confirm`
  report the exact counts in the error.
- **Audit**: `RoleCreated`, `RoleDeleted`, and `UserRoleAssigned` are new
  `AuditAction` entries; permission and dashboard-visibility edits keep
  using the existing `RoleChanged`. Every one of these records a
  before/after diff in `metadata`, not just the actor and resource.
- **Known, deliberate scope boundary**: the built-in System
  Admin/Network Admin/Security-OPSEC Admin roles are *not* seeded with
  `roles.manage` or `users.create` by this change (seeding built-in role
  defaults was explicitly out of scope for GitHub issue #8). A Super
  Admin who wants, say, Network Admin to actually delegate sub-roles and
  onboard people has to grant it those two permissions through the
  existing permission editor first -- the delegation *mechanism* works
  the moment a role holds `roles.manage`, but no built-in role holds it
  out of the box beyond Super Admin.

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
   default, `0600`). `hosts.name` is unique, and there's no path by which
   uninstalling the agent (locally, on the host) ever deregisters its row
   here -- so re-enrolling the same machine (retrying a failed deploy,
   reinstalling after wiping local credentials) would otherwise hit that
   constraint and fail with a bare 500. `enroll` checks for an existing
   host with the same name first: a disconnected one is treated as stale
   and superseded (deleted, with a `HostRemoved` audit row noting why,
   then enrollment proceeds normally) since nothing else references
   `hosts.id` by foreign key; a currently-connected one is a real conflict
   and returns a clear 409 instead, asking the admin to remove it from
   `/admin/hosts` first.
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

## Panopticon discovery scanning

An on-demand scan (`panopticon_ops::run_discovery_scan`) runs `nmap -sT`
(a TCP connect scan -- this process is unprivileged, so it has no raw
sockets to do anything fancier) against an admin-supplied target, upserts
every device it finds into `panopticon_devices`, and runs as a detached
background job so the browser can watch it progress (see "Live-updating
progress pages" below) rather than the request blocking until nmap exits.
The unattended active sweep (`spawn_panopticon_sweep`) shares the exact
same scan function, just invoked on a timer instead of from a request.

- **MAC address** comes from the control plane's own kernel neighbor table
  (`ip neigh show`), not from nmap -- nmap can't do its own ARP-based MAC
  detection without raw sockets either. This only ever has entries for
  devices on the same L2 segment as the control plane; a routed subnet
  shows no MAC, which is expected, not a bug.
- **Vendor** is derived entirely from the MAC's OUI prefix
  (`abyssal_core::oui`), a small hand-curated table (not the full ~30k-row
  IEEE registry, by design) -- a MAC that resolves but whose vendor doesn't
  show just means that specific prefix isn't in the table yet, not that
  MAC resolution failed.
- **Hostname** comes from nmap's own reverse-DNS detection first, falling
  back to an explicit `getent hosts <ip>` lookup
  (`panopticon_ops::reverse_dns_lookup`) when nmap found nothing -- common
  on internal networks without a properly configured internal DNS server.
  `network_devices::upsert`'s `hostname` column is `COALESCE`d on every
  write, exactly like `mac_address` already was: a rescan that doesn't
  happen to resolve a hostname this time (flaky reverse DNS is the normal
  case, not the exception) must never blank out one an earlier scan
  already found.

**Rescanning an already-known target skips the "type the target to
confirm" dialog.** `has_scan_history` (`routes/panopticon.rs`) treats a
CIDR target as known once it already appears in the Topology table (some
inventory device's own `/24` matches it exactly) and a single host as
known once it's already in the inventory. The Topology page's own Rescan
button is always a known target by construction (it only exists for
subnets already listed there), so it posts straight to the scan endpoint
with no intermediate confirm page at all; the dashboard's free-text scan
form still shows a confirm step for a known target, just a lighter one
(no typed confirmation). The typed-confirmation requirement itself is
re-checked independently inside the scan handler, not just decided by
which confirm page rendered -- a hand-crafted request can't skip it for a
target that's genuinely new just because the UI didn't ask for it. Either
way, the resulting scan produces a small "Rescan of X complete" banner
(`ScanJob::rescan_notice`) so skipping the old dialog doesn't make a
rescan look like nothing happened.

**"Quick add"** on an already-discovered inventory row
(`panopticon.html`) skips straight to the SSH deploy credentials step for
that one host, reusing the exact same flow a post-scan picker selection
does -- see "Deploying agents over SSH" below.

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
per-host overrides) -> host-key review -> deploy status. The picker,
credentials, and host-key review steps are plain server-rendered pages --
"select all"/"none" works by resubmitting a normal HTML form, no
JavaScript involved. The final deploy status page is one of only two pages
in the whole app with any client-side JS: a small, scoped polling script
(`deploy_status_json`) that updates a progress bar and each host's row in
place instead of the page reloading itself every few seconds -- see
"Live-updating progress pages" below for why this exists and how it
degrades without JS. A discovery scan already upserts every device it
finds into the inventory unconditionally
(`panopticon_ops::run_discovery_scan`), so cancelling out of the picker
loses nothing; only "Add Hosts" continues into this flow.

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

**The host's own `hostname` output, not a pre-deploy guess, decides
`--name`.** `deploy_one_host` runs `hostname` over the same SSH session
right after confirming the architecture, before ever downloading anything,
and uses that (validated as a real RFC 1123 name) as the agent's
registered name -- falling back to whatever Panopticon's inventory already
had on file, and only then to the bare IP. The SSH-confirmed hostname is
also written straight back into `panopticon_devices` (fire-and-forget, so
a slow database write can never stall the deploy), regardless of whether
the install that follows actually succeeds. `HostDeployStatus::
hostname_is_fallback` tracks which case applied and the deploy status page
shows an explicit "IP fallback" badge when it's true, rather than letting
an IP quietly stand in for a real name.

**The downloaded binary is copied to a permanent location before
`install` ever runs, not run straight out of the temp download
directory.** `abyssal-agent install` writes the systemd unit's
`ExecStart` as wherever it's *currently running from*
(`std::env::current_exe()`, `crates/agent/src/main.rs::
install_systemd_service`) -- a manual install is just "wherever the
operator extracted it, and that's now permanent by convention," and the
agent has no other way to know where it's "meant" to live. An earlier
version of `ssh_deploy::build_install_command` downloaded to
`/tmp/abyssal-agent-deploy`, ran `install` from there, and then deleted
that same directory as its own cleanup step -- which left the systemd
service pointing at a binary that no longer existed, failing every
restart with systemd's `203/EXEC`. Confirmed against a real deploy, not
a theoretical concern. The install command now copies the binary to
`/opt/abyssal-agent` first and installs from there; only the temporary
staging directory and downloaded archive get cleaned up afterward, never
that permanent copy. Getting the resulting shell command right required
one more level of quoting than everywhere else in this flow --
`build_install_command` wraps an already-`shell_quote`d inner command in
`shell_quote` again so it survives as one argument to `sudo -S sh -c`,
and that nesting is exercised against a real `/bin/sh` (not just
eyeballed) in `ssh_deploy`'s own tests.

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

## Live-updating progress pages

This app is server-rendered HTML with no client-side JavaScript, almost
everywhere -- a deliberate house style, not an oversight. Two pages are the
deliberate exception: the discovery scan progress page
(`routes/panopticon_scan.rs::scan_status`) and the SSH deploy status page
(`routes/panopticon_deploy.rs::deploy_status`). Both watch a long-running
background job and need to show it moving in real time (a percentage, a
host count, per-host state changing from `Pending` through to `Succeeded`/
`Failed`) -- a `<meta http-equiv="refresh">` full-page reload every few
seconds, this app's usual answer to "keep a page current," makes that look
like a slideshow rather than progress. Both pages still ship that same
`<meta refresh>` tag as their fallback, and both pages' own small `<script>`
block removes it the moment it confirms it's running, so nothing changes
for a client with JS disabled or blocked -- it just gets the older,
plainer experience instead of a hard failure.

The shape is the same on both pages, and deliberately so:

- A JSON endpoint (`scan_status_json`, `deploy_status_json`) reports the
  job's current state -- percentage/counts for the scan, plus each host's
  row for the deploy job. Both read from the same in-memory job registries
  (`AppState.scan_jobs`/`deploy_jobs`) the page's own first, server-rendered
  load already reads from, so the two never disagree about where a job
  currently stands.
- The page's `<script>` polls that endpoint on a short interval (1-1.5s),
  updates the progress bar's width and the relevant page elements in
  place, and polls again -- or, for the scan page, redirects to the
  results page (`scan_view`) once the job leaves `Running`; the deploy
  page instead just stops polling once `complete` comes back true, since
  its per-host rows *are* the results, not a separate page.
- Anything derived from data a remote system produced (SSH command output,
  a resolved hostname) is written into the DOM with `textContent`/
  `createElement`, never `innerHTML` -- the same reason the server-rendered
  version of these pages relies on Askama's default HTML escaping. A
  compromised or simply misbehaving scan target or deploy host putting
  `<script>` in its own output must never get it executed in an admin's
  browser just because that output ended up on a progress page.
- Every request the polling script makes goes through the exact same
  `abyssal_rbac::ensure` permission check as the page itself
  (`network.scan` for the scan job, `hosts.manage` for the deploy job) --
  the JSON endpoint is a new URL, not a new permission boundary.

The scan progress bar's own percentage comes from reading nmap's stdout
incrementally rather than only after the process exits
(`panopticon_ops::run_nmap_streaming`): nmap prints one `Nmap scan report
for ...` line per host the moment it finishes probing that host, well
before the whole scan completes, so counting those lines as they stream by
gives real per-host progress without switching to nmap's XML output mode
or splitting one scan into many separate per-host nmap invocations (which
would lose nmap's own internal scheduling efficiency for no benefit).
`hosts_total` is computed upfront from the target's CIDR size
(`panopticon_ops::target_host_count` -- the same literal address-by-address
count nmap itself expands a CIDR into, including the network and broadcast
addresses) so the bar has a real denominator from the very first paint,
not just once the first host finishes.

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
  every 5 minutes): polls every enabled row in `panopticon_switches` --
  over SNMP v1, v2c, or v3, per-switch (`snmp_version`, GitHub issue #6)
  -- for BRIDGE-MIB's `dot1dTpFdbTable` (MAC -> bridge port,
  joined through `dot1dBasePortIfIndex` and IF-MIB's `ifDescr` for a
  human port label) -- the mechanism that gives a device's inventory row
  a `switch_id`/`switch_port`. `panopticon_snmp.rs::decrypt_credentials`
  reads whichever of `community_encrypted` (v1/v2c) or the `snmp_v3_*`
  fields (v3: username, security level, auth protocol/password, privacy
  protocol/password) the switch's own `snmp_version` says are live, and
  `poll_switch` opens the matching `snmp2::AsyncSession` (`new_v1`/
  `new_v2c`/`new_v3`) -- never a hardcoded version. Every secret
  (the v1/v2c community string, the v3 auth/privacy passwords) is stored
  encrypted (`abyssal_core::crypto::EncryptionKey`, AES-256-GCM,
  `ENCRYPTION_KEY` env var) -- the one kind of credential this platform
  stores reversibly rather than hash-only, since the sweep has to present
  the actual plaintext to the switch with nobody around to type it in
  again. A switch added before `snmp_version` existed keeps polling v2c
  unmodified -- the column defaults to `'v2c'` for every pre-existing row
  (`migrations/0014_panopticon_switch_snmp_version.sql`), and the same
  default is what a row's `FromStr` falls back to if it ever saw an
  unrecognized value. No-ops entirely when `ENCRYPTION_KEY` isn't set.
  Every SNMP request is individually timeout-bounded
  (`panopticon_snmp.rs::REQUEST_TIMEOUT`,
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
- **Reliquary scheduled backup loop**
  (`reliquary_backup::orchestrator::spawn_scheduled_backup_loop`, every 15
  minutes): off by default (`reliquary.backup_schedule_enabled`), re-checked
  every tick. When due (tracked from the most recent successful backup's
  own timestamp, not an in-process timer), runs one unencrypted
  Database+Configuration(+Audit logs, per its own setting) backup under
  the same `GET_LOCK`-based lock a manual backup or restore uses, then
  runs retention pruning. See "Reliquary native backups" below for the
  full feature.

## Reliquary native backups (GitHub issue #9)

The control plane's own backup/restore/disaster-recovery system for its
Docker Compose install -- a MariaDB logical dump, a redacted snapshot of
this process's own configuration, and (opt-in, always encrypted) the
`ENCRYPTION_KEY` used for Panopticon/macro secrets, sealed into one
compressed, checksummed, optionally-encrypted archive with a versioned
`manifest.json`. Full detail (what is/isn't backed up, DB grants,
scheduling, off-host storage, the disaster-recovery CLI walkthrough) lives
in [docs/reliquary-backups.md](docs/reliquary-backups.md); this section is
the architectural summary.

- **`BackupProvider`/`StorageDestination` traits**
  (`crates/web/src/reliquary_backup/provider.rs`,`storage.rs`) exist
  specifically so a second destination could be added without touching
  the job model, orchestrator, or UI -- `LocalFs` and a Sepulchre-backed
  destination are exactly that today (see "Sepulchre storage
  connectivity" below), chosen per job rather than fixed at startup; only
  `NativeProvider` exists as a `BackupProvider`, same reasoning as
  `AuthProvider` existing before there's a second auth backend.
- **Dump**: `mariadb-dump` (added to the runtime image via the Dockerfile's
  `mariadb-client` package), run as a real subprocess (never through a
  shell), credentials passed via a `0600` `--defaults-extra-file` -- never
  a `-p` flag or a `ps`-visible environment variable. `--databases <db>`
  embeds the dump's own `CREATE DATABASE`/`USE` statements, which is why a
  real restore needs no extra logic to recreate the database by name, and
  is also exactly why deep verification (below) is unimplemented.
- **Archive**: `tar` + `zstd`, composed in one `spawn_blocking` closure
  (both are sync crates; tar itself is sync regardless, so this is simpler
  and more correct than bridging to an async compression crate). Every
  entry's path is validated against traversal before extraction
  (`archive::validate_entry_path`), and only regular files/directories are
  ever unpacked -- symlink and hardlink tar entries are rejected outright.
- **Encryption**: AES-256-GCM in streaming mode (`aes-gcm`'s STREAM
  construction, 512KB chunks, bounded memory regardless of archive size),
  keyed by Argon2id-deriving an operator-supplied passphrase (same KDF
  style as this app's own password hashing). The passphrase is never
  stored anywhere; losing it means losing the ability to restore that
  archive, by design.
- **Job model**: `reliquary_backups` table
  (`migrations/0018_reliquary_backups.sql`) with a status lifecycle
  (queued/running/succeeded/failed/verifying/verified/cancelled), a
  MariaDB session-scoped named lock (`GET_LOCK('reliquary_backup', 0)`,
  non-blocking) serializing backups/restores against each other on one
  dedicated connection, and a startup sweep
  (`orchestrator::recover_interrupted_jobs`) that marks any job still
  non-terminal as failed (a crash releases the lock automatically, but not
  the job row).
- **Retention**: keep-last-N and/or keep-X-days, computed by a pure
  function (`orchestrator::select_prune_candidates`, unit-tested without a
  database) that never selects the only remaining backup whose
  verification is passing, even past its own age/count limits.
- **Verification**: quick verify (checksum, manifest sanity, archive
  readability) is implemented. Deep verify (scratch-database restore,
  `CHECK TABLE`, row-count comparison) is a documented, flagged gap --
  `verify::deep_verify` returns a clear "not implemented" error rather
  than a false pass; see docs/reliquary-backups.md for why.
- **Restore**: dry-run preview (schema-version and MariaDB-major-version
  comparison, refuses on a manifest-version mismatch) before any
  destructive action; requires the backup to be verified unless explicitly
  overridden; takes an automatic unencrypted safety backup of the current
  database first (its *file* survives a successful restore, but not its
  `reliquary_backups` row -- the restore overwrites that whole table too;
  recover it by file via the disaster-recovery CLI if needed, see
  docs/reliquary-backups.md); and enters **maintenance mode**
  (`middleware::maintenance_mode`, `reliquary_backup::restore::
  MaintenanceMode`) for its duration -- every request except static assets
  and the backups page itself gets a 503 page, cleared automatically via
  an RAII guard even on panic or early return.
- **Disaster-recovery CLI**: `crates/app/src/cli.rs`, the same binary as
  the server (`docker compose run --rm app reliquary backup
  list|verify|restore ...`), works against a totally fresh install with no
  web UI, session, or even an existing `reliquary_backups` row -- it
  operates directly on an archive file. The Dockerfile uses `ENTRYPOINT`
  (not `CMD`) specifically so this appends its arguments rather than
  replacing the binary outright; with no arguments at all, the same image
  still just runs the server, unchanged.

## Sepulchre storage connectivity

A shared storage-connection layer -- SFTP, SMB/CIFS, and allowlisted local
paths -- so other Arsenals (Reliquary first) consume a named connection
instead of each building its own SFTP/SMB client and credential handling.
Full detail lives in [docs/sepulchre.md](docs/sepulchre.md); this section
is the architectural summary.

- **Three separate concepts, not one**: `Protocol` (`sftp`/`smb`/`local`,
  `#[non_exhaustive]`), `AccessMethod` (*how* -- `native_client`/
  `diagnostic_client` are control-plane-only, `mount`/`rsync_ssh` are
  managed-host-only; the control-plane container never performs a kernel
  mount), and `ConnectionRole` (*what for* -- `backup_destination`/
  `file_transfer`/`remote_storage`/`other`, many-to-many). A connection is
  never inherently "a backup connection" -- consumers ask the resolver by
  role and required capability, never by protocol.
- **`StorageConnectionResolver::resolve(connection_id, RequiredUse)`**
  (`crates/web/src/sepulchre/backend/mod.rs`) is the only way a consumer
  gets a usable backend: enabled, holds the role, every required
  capability *verified* (not just declared) by a recent, passing
  validation run -- otherwise a typed `NotUsableReason`, never a bare
  error string. Capabilities are re-proven every validation run and
  cleared, not left stale, if a run doesn't re-verify them.
- **`StorageBackend` trait** -- `stat`/`list`/`open_read`/`open_write`/
  `delete`/`ensure_dir`/`free_space`, all async and streaming
  (`AsyncRead`/`AsyncWrite`, never a whole file buffered in memory on the
  SFTP/Local backends). Three implementations: `LocalBackend` (`cap-std`-
  rooted, TOCTOU-safe, allowlisted via `SEPULCHRE_LOCAL_ROOTS`),
  `SftpBackend` (`russh`+`russh-sftp`, mandatory pinned host-key
  verification -- a later mismatch is a hard `host_key_mismatch`, never a
  silent re-pin), and `SmbBackend` (shells out to `smbclient`, disk-
  buffered rather than a true zero-copy stream -- a documented trade-off,
  see docs/sepulchre.md).
- **Secrets** are Sepulchre's own, not Cryptkeeper's -- Cryptkeeper is a
  host-side security-inspection Arsenal with no credential vault of its
  own. `storage_connection_secrets` reuses the same
  `abyssal_core::crypto::EncryptionKey` (AES-256-GCM) Panopticon's switch
  SNMP strings already use; secret fields are write-only in every form
  (blank on submit means "keep the existing value"). Generating or
  importing an SFTP keypair, and any other key-material action, requires
  *both* `storage_connections.manage` and `security.manage` --
  deliberately distinct permissions from the pre-existing `StorageView`/
  `StorageManage` (Ossuary/Catacomb disk features), so holding one never
  silently grants the other.
- **Host-side provisioning** goes through the same agent-executor channel
  every other Arsenal uses (no new remote-execution mechanism), only ever
  edits a Sepulchre-owned drop-in/include file (never the distro's main
  `sshd_config`/`smb.conf`), validates (`sshd -t`/`testparm -s`) before
  every reload, and restores-and-reloads the previous config on any
  validation or reload failure -- a bad config is never left applied.
  Every SFTP directive is scoped inside a `Match User`/`Match Group`
  block. Cryptkeeper can generate a host-side SSH keypair and list/remove
  an `authorized_keys` entry, but never add one; Sepulchre writes its own,
  into a Sepulchre-reserved `AuthorizedKeysFile` path, to avoid ownership
  conflicts with a chrooted SFTP account. A host page wizard
  (`/arsenals/sepulchre/hosts/:id`) drives this end to end -- provisioning
  an SFTP or SMB share creates the host-side account, applies the config,
  and creates the matching Sepulchre connection (generating and installing
  a keypair for SFTP) in one step; a separate mount wizard creates or
  removes a CIFS mount backed by an existing SMB connection. Verified live
  against a real connected managed host, not just unit-tested.
- **Validation** is an ordered check list producing a stable `error_kind`
  per check (`unreachable`, `auth_failed`, `host_key_mismatch`,
  `permission_denied`, `method_unavailable`, `path_not_allowed`, ...),
  feeding the workflow registry the same way every other Arsenal's
  checks do.
- **Reliquary can write a backup directly to a Sepulchre connection**,
  picked per manual run (a Destination dropdown) or configured as the
  scheduled loop's own fixed answer. `NativeProvider` no longer holds a
  fixed `storage` field -- `BackupProvider::create()` takes
  `storage: &dyn StorageDestination` per call, resolved by
  `reliquary_backup::orchestrator::resolve_destination(state,
  connection_id)` (`None` = local, `Some` = a Sepulchre connection
  resolved the same way any other consumer is: `backup_destination`
  role, every capability verified). Every job row records its own
  `destination_connection_id` (`ON DELETE SET NULL`), so retention
  pruning and deletion each resolve the *right* destination per job
  rather than assuming one destination for everything. Reading a backup
  back from a Sepulchre connection (download/verify/restore) remains a
  documented, deliberate gap -- all three refuse cleanly for a
  Sepulchre-backed job rather than failing confusingly against a
  synthetic, non-real path. See docs/sepulchre.md's "How Reliquary
  consumes a Sepulchre connection today" for the full detail, including
  a real bug this wiring caught and fixed live
  (`LocalBackend::ensure_dir("")` rejecting the exact call
  `SepulchreDestination::open_write` always makes first).

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
  (not a JS `confirm()` dialog) for destructive actions. Two pages are a
  deliberate, narrow exception -- see "Live-updating progress pages"
  below.
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
- `0014_panopticon_switch_snmp_version.sql` -- adds `snmp_version` to
  `panopticon_switches` (`'v2c'` default, so every pre-existing switch
  keeps polling exactly as before) and the nullable `snmp_v3_*` columns
  (username, security level, auth protocol/password, privacy
  protocol/password) v3 switches use instead of `community_encrypted`,
  which becomes nullable for the same reason (GitHub issue #6).
- `0015_macros.sql` -- `macros` (GitHub issue #7): a saved, reusable
  Grimoire scheduled-task template (`job_name`/`schedule`/`run_as_user`/
  `command`, the exact fields `AgentOperation::SetCronJob` needs, minus a
  target host) an admin can replay across hosts instead of retyping.
  `scope` is `personal` (visible only to `owner_user_id`) or `role`
  (visible to every member of `role_id`, required exactly when
  `scope = 'role'`) -- reuses the existing `roles`/`user_roles` tables
  (`0001_init.sql`) rather than inventing a second role concept. See
  `crates/core/src/macros.rs::Macro` and
  `crates/database/src/repo/macros.rs::list_visible_to_user`.
- `0016_macro_types.sql` -- adds `macro_type` to `macros` (default
  `'cron_job'`, so every pre-existing macro keeps its original meaning)
  and a second payload: `secret_value_encrypted`, a saved SNMP community
  string for Panopticon's "add managed switch" form (`crates/core/src/
  macros.rs::MacroType`). The `job_name`/`schedule`/`run_as_user`/
  `command` columns become nullable, since a community-string macro has
  none of them, for the same reason `secret_value_encrypted` is nullable
  for a cron-job macro. `secret_value_encrypted` is AES-256-GCM
  ciphertext -- the same `ENCRYPTION_KEY` already used for a Panopticon
  switch's own stored SNMP credentials, not a second secret to manage.
  Account (`/account`) is where a community-string macro can be created
  directly, independent of adding a switch; its edit/remove pages are
  shared with Panopticon's add-switch macro list via a `return_to`
  parameter (`crates/web/src/common.rs::safe_return_to`), since the macro
  itself isn't tied to either page.
- `0017_custom_roles.sql` -- adds `parent_role_id`, `created_by`,
  `created_at`/`updated_at` to `roles` (GitHub issue #8: delegated
  custom sub-roles). Every pre-existing role gets `parent_role_id =
  NULL` -- a root, exactly its prior behavior -- and `created_by = NULL`
  (nothing "creates" the five seeded system roles at runtime).
  `parent_role_id` is `ON DELETE RESTRICT`, not `CASCADE`: this
  feature's chosen deletion-guard behavior (block, don't
  auto-reassign) is enforced at the application layer
  (`routes/roles.rs::delete_role`), but the FK is a second, structural
  backstop against ever silently orphaning a role's children. See
  "Delegated custom roles" above for the full model.
- `0018_reliquary_backups.sql` -- adds `reliquary_backups` (GitHub issue
  #9: native backup/restore). One row per backup job: status lifecycle,
  trigger source, selected components (JSON), encryption flags,
  destination path/file name, size, SHA-256, the full manifest (JSON),
  verification status/details, and timing columns. `created_by` is
  `ON DELETE SET NULL` -- a deleted user's past backups stay listed, not
  silently disappear. See "Reliquary native backups" above for the full
  model.

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
  credentials -- the v1/v2c community string, or the v3 auth/privacy
  passwords, whichever `snmp_version` applies. Unset it and the app still
  runs fine -- adding a switch just refuses cleanly until it's set.
- Panopticon's ARP listener (off by default) is the one place in this
  workspace that needs elevated privileges. The Dockerfile grants
  `CAP_NET_RAW` to the binary itself (`setcap`), not to the container's
  root user, so the process still runs as the unprivileged `abyssal` user;
  docker-compose.yml's `cap_add: [NET_RAW]` and the published `5353/udp`
  (for the mDNS listener, also off by default) exist for these two
  opt-in features and do nothing while both stay disabled.
- `mariadb-client` is included in the runtime image for Reliquary's native
  backups (`mariadb-dump`/`mariadb` -- GitHub issue #9). A dedicated
  `abyssal_backups` volume, mounted at `/backups` and deliberately separate
  from `abyssal_db_data`, is where archives land; `RELIQUARY_BACKUP_DB_USER`/
  `_DB_PASSWORD` optionally point the dump at a least-privilege user instead
  of the app's own database credentials (see
  [scripts/reliquary-backup-grants.sql](scripts/reliquary-backup-grants.sql)).
  The Dockerfile uses `ENTRYPOINT` rather than `CMD` so the disaster-recovery
  CLI's arguments (`docker compose run --rm app reliquary backup ...`) append
  to the binary instead of replacing it -- see "Reliquary native backups"
  above and [docs/reliquary-backups.md](docs/reliquary-backups.md) for the
  full picture, including the off-host-storage caveat: that volume is still
  local to this Docker host.

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
- Reliquary's native backups have no deep verify (scratch-database
  restore + `CHECK TABLE` + row-count comparison) -- only quick verify
  (checksum/manifest/readability), and quick verify (along with download
  and restore) doesn't work against a Sepulchre-backed destination yet,
  only the local one -- writing to one works today, reading one back
  doesn't. No S3/cloud-object-storage destination exists
  (`StorageDestination`/`BackupProvider` are traits so one can be added
  without a refactor). Scheduled/unattended backups are always
  unencrypted, since there's nobody present to supply a passphrase. A
  restored archive's Configuration/Encryption-keys components are only
  extracted to disk, never automatically re-applied. All flagged, not
  oversights -- see [docs/reliquary-backups.md](docs/reliquary-backups.md).
