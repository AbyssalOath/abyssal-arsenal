# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/). The
`main` branch is the active development line; tagged releases (`vX.Y.Z`) are
the stable checkpoints built from it. See [README.md](README.md#releases-and-branches)
for what that means for cloning and updating.

## [Unreleased]

### Added

- **Quick Add Host From Network Scan**: lets an admin go from a Panopticon
  discovery scan straight to enrolled managed hosts over SSH, instead of
  SSHing into each one by hand. After a scan, a picker lets you select
  which discovered devices to deploy the agent to (or add one later
  straight from the Device Inventory's new "Quick add" action); a
  credentials step collects one shared SSH login plus optional per-host
  overrides (username, password or private key, sudo password, SSH port);
  a host-key review step shows every fingerprint for trust-on-first-use
  confirmation before any credential is used, and hard-stops (never
  silently bypassed) if a previously-trusted host's key has changed since
  last seen. Deployment runs concurrently (bounded, default 5 at once) so
  one unreachable host never blocks the others, confirms success by
  polling for the agent actually connecting back over its own WebSocket
  rather than trusting the install command's exit code alone, and shows
  clear, specific failure reasons (connection refused/timeout, auth
  failed, sudo denied, host key changed, download/install error, agent
  never checked in) with command output on the results page. Passwords,
  private keys, and passphrases are never written to the database or a
  log line, anywhere -- see [ARCHITECTURE.md](ARCHITECTURE.md#deploying-agents-over-ssh-quick-add-host-from-network-scan)
  for the full design, including how a multi-step, no-persistent-session
  web flow carries a credential forward without ever storing it.
- **Live progress bars for long-running background jobs**: both the SSH
  deploy status page and Panopticon's discovery scan now show a
  determinate progress bar (percentage, plus supporting counts like
  "142 / 254 hosts" or "3 / 5 hosts complete") that updates smoothly via a
  small, page-scoped polling script, rather than the page reloading itself
  every few seconds. These are the only two pages in the app with any
  client-side JavaScript -- a deliberate, narrowly scoped exception to the
  rest of the app's server-rendered-only house style, and both still fall
  back to the old full-page-reload behavior if JavaScript is unavailable.
  Discovery scans also now run as background jobs instead of blocking the
  request that started them, which is what made a live progress bar
  possible in the first place. See [ARCHITECTURE.md](ARCHITECTURE.md#live-updating-progress-pages).
- Topology's Rescan button is now a single click for a subnet Panopticon
  already knows about -- no confirmation dialog, no retyping the target,
  just a small "Rescan of X complete" notice once it finishes. The typed
  "confirm the target" safety dialog still applies in full for a target
  that's never been scanned before.

### Fixed

- Panopticon's device inventory could lose a device's hostname on any
  rescan that didn't happen to resolve one that particular time (flaky
  reverse DNS is the normal case on most internal networks, not the
  exception) -- the underlying `UPDATE` was overwriting a known-good
  hostname with an empty result instead of keeping the old value, the
  same mistake the MAC address column next to it didn't have. Also added
  an explicit reverse-DNS (`getent hosts`) fallback for when nmap's own
  hostname detection finds nothing, and a handful of real-world OUI vendor
  prefixes verified against the IEEE registry.
- Remote agent installs deployed via SSH were registering under the
  target's IP address instead of its real hostname. The install now asks
  the host directly for its own `hostname` right over the same SSH
  session, which is authoritative in a way a pre-deploy guess never was,
  and writes it back into the inventory immediately; the deploy status
  page now shows an explicit "IP fallback" badge on the rare host where
  even that couldn't be confirmed, rather than silently showing an IP as
  if it were a real name.

### Changed

- The SSH deploy credentials form now labels its fields as "SSH Username"/
  "SSH Password" (not just "Username"/"Password"), adds a one-line inline
  explanation under each field, and only shows the Private key fields
  when Auth method is set to Key (and vice versa for Password) -- all
  without any client-side JavaScript beyond what "Live progress bars"
  above already introduces, using CSS `:has()` selectors instead. A new
  "Same as SSH password" checkbox next to Sudo password removes the need
  to retype the same password into two fields.

## [0.1.1] - 2026-09-19

### Added

- **Contextual Arsenal Workflow Navigation**: a new `abyssal-workflows` crate
  (pure, dependency-light, no I/O) evaluates a compile-time-embedded
  `registry.json` of trigger conditions against an arsenal's read-operation
  results and surfaces "suggested actions" -- buttons on the results page
  linking straight into another arsenal, prefilled with the context that
  triggered the suggestion (e.g. a disk-usage read in Cystoolbox crossing a
  threshold suggests jumping to Catacomb's large-file finder, Defleshing's
  cleanup, or Ossuary's volume management, each prefilled with the
  offending mount path). The condition registry supports a full operator
  set (`equals`, `not_equals`, `greater_than_or_equal`, `less_than`,
  `contains`, `starts_with`, `ends_with`, `matches` (regex), `exists`) and
  arbitrarily nested `all`/`any` compound conditions, deliberately
  evaluated without short-circuiting so a registry-authoring bug in an
  unreached branch still surfaces. 15 registry entries cover the
  cross-arsenal relationships with genuine operational signal: Cystoolbox
  to Catacomb/Defleshing/Ossuary (disk pressure), Necropsy to
  Ossuary/Resurrection/Mortiscope (failed health checks), Mortiscope to
  Vivisection/Reanimation (high CPU), Thanatos to Inquest/Postmortem
  (alerted security scans), Obituary to Defleshing (large journal size),
  Resurrection to Necropsy/Reliquary and Reliquary to Resurrection
  (read-only filesystem errors, both directions), and Cryptkeeper to
  Incarnation (certificate expiry, using a new `== Expiry ==` section the
  agent's `certificate_detail` now also collects via `openssl x509 -noout
  -enddate`). All 12 destination arsenals show an "arrived here because..."
  context banner naming which fields triggered the suggestion, and now
  also carry the source page's selected host forward as the global
  top-nav host selection when landing via a suggested action (not on
  ordinary manual navigation), including on the landing page's own nav so
  it's never stale for a single render. Evaluation failures (e.g. a bad
  regex in a registry entry) are recorded as a new
  `WORKFLOW_EVALUATION_FAILED` audit event rather than silently dropped or
  panicking, and a new optional read-only `/admin/workflows` page lists
  the full registry for anyone auditing what triggers what. Documented in
  full, including an "adding a new workflow relationship" checklist, in
  `crates/workflows/README.md`.
- **Rust edition bumped to 2024** (from 2021), inherited workspace-wide via
  `[workspace.package] edition`. Enables if-let chains
  (`if let Some(x) = y && cond { ... }`), which `cargo clippy`'s
  `collapsible_if` lint immediately started recommending in ~34 places
  that used to be a nested `if let { if ... }` -- mechanically rewritten
  everywhere via `cargo clippy --fix` and reformatted with `cargo fmt`
  (whose import-sorting default also changed slightly under the new
  edition). No functional changes: verified with a full `cargo build`,
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D
  warnings` (matching CI's own gate), and `cargo fmt --check` pass, all
  clean.
- **Version tracking and update notice**: a `VERSION` file at the repository
  root is now the single source of truth for this build's version, embedded
  into the control-plane binary at compile time. A new background sweep
  (`abyssal_web::spawn_update_check_sweep`) checks GitHub's releases API
  every 6 hours (and once immediately on startup) for a newer tagged release
  and caches the result in memory -- read-only, best-effort, never blocks
  startup or any request if GitHub is unreachable. The dashboard shows a
  small notice: the current version alone when up to date, or a red,
  pulsing, clickable notice (current version -> latest version, linking to
  the release) once a newer one is confirmed.
- **Self-service password change**: a new "Password" card on `/account`
  (current password, new password, confirmation) available to any logged-in
  user, wired onto the `must_change_password` flag and `repo::users::
  update_password` that already existed but were never enforced or exposed
  anywhere. `CurrentUser` now redirects to `/account` from every other page
  while `must_change_password` is set (an admin-created account with an
  unused temporary password), not just right after login, so a lingering
  session can't skip it; `/account` and its own POST target are the only
  exempt paths. Records a `PASSWORD_CHANGED` audit event on success.
- **Welcome email on user creation**: creating a user from `/admin/users`
  now emails them their username and temporary password (and that they'll
  be required to change it at first login) through whatever notification
  provider is configured, reusing the same `NotificationDispatcher` Thanatos
  alerts already go through. A no-op, never a reason to fail user creation
  itself, when no provider is configured or the account has no email
  address; the outcome is recorded on the `USER_CREATED` audit event
  (`welcome_email_sent`) either way.
- **Forgot password (emailed reset link)**: `/forgot-password` requests a
  reset by email, `/reset-password` sets a new one -- a single-use,
  SHA-256-hashed, 1-hour token (new `password_resets` table, same
  hash-only-at-rest pattern as sessions and host enrollment tokens),
  emailed as a clickable link when `PUBLIC_URL` is configured, or as a
  plain code to paste in when it isn't (deliberately not inferred from a
  request's `Host` header, since that's attacker-controllable and this is
  a security-sensitive link). Always shows the same "if an account with
  that email exists..." result regardless of whether it matched anything,
  so the form can't be used to enumerate registered emails, and caps one
  reset email per account per 15 minutes so repeated submissions can't be
  used to spam someone's inbox. A successful reset revokes every active
  session for that account (same reasoning as disabling a user) and
  records a `PASSWORD_RESET` audit event; a `PASSWORD_RESET_REQUESTED`
  event is recorded whenever a real reset email actually goes out.
- **Role-based dashboard view**: `/admin/roles` gained a "Dashboard
  arsenals" checkbox group per role, independent of (and always still
  bounded by) its permission checkboxes above -- checking an arsenal a
  role has no permission for has no effect, it never grants access on its
  own. A role with no customization keeps showing every arsenal its
  permissions already allow (today's exact behavior); customizing one
  narrows its members' dashboards to exactly the checked set. A user with
  multiple roles sees the union of what each contributes, and having even
  one uncustomized role removes the restriction entirely for that user
  (mirrors how permissions themselves already union across a user's
  roles, most-permissive-wins, rather than a new paradigm). New
  `role_module_visibility` table; addresses the gap where two roles with
  different purposes (e.g. Network Admin and Regular User) sharing a
  broad permission like `systems.view` also ended up seeing the same
  large pile
  of unrelated arsenal tiles on the dashboard.
- **`abyssal-agent install`**: an interactive setup command, and the
  default when the binary is run with no arguments at all -- prompts for
  the control plane URL and the enrollment token (skipping the token
  prompt entirely if credentials already exist), enrolls the host, then
  writes `/etc/systemd/system/abyssal-agent.service` and runs `systemctl
  daemon-reload` / `enable --now` itself, so a fresh install needs no
  hand-authored unit file. Both values can still be passed as flags for
  non-interactive/scripted installs (Ansible, cloud-init, ...); a
  non-systemd host enrolls and is told to run `abyssal-agent run`
  directly instead of failing. If it isn't already running as root, it
  asks (`Run this with sudo now? [Y/n]`, default yes) and re-execs itself
  under `sudo` (`std::os::unix::process::CommandExt::exec`, replacing its
  own process image, the same pattern common install scripts use) rather
  than failing partway through with a permission error -- declining, or
  running fully non-interactively, tells you to re-run as root instead of
  guessing.

### Fixed

- `Dockerfile`'s dependency-caching layer never learned about the new
  `crates/workflows` workspace member -- it copied every other member's
  `Cargo.toml` and stubbed its source for the dependency-only build, but
  not this one, so `cargo build --release --workspace` failed immediately
  trying to resolve a workspace member whose manifest was never copied
  into the build context. Caught by an actual CI Docker build failure
  (exit code 101 on the stub-and-build step), not just local `cargo
  build` (which sees the real source tree and never hits this). Fixed
  with one more `COPY` and one more entry in the stub-generation loop,
  verified by replicating the same Cargo.toml-only-copy-then-stub layer
  in isolation.
- `Dockerfile` never copied the new root-level `VERSION` file into the
  build stage, so `crates/web/src/update_check.rs`'s
  `include_str!("../../../VERSION")` would have failed the real Docker
  build outright, not just at runtime. Caught by actually building the
  image, not just `cargo build` locally, and fixed with one more `COPY`
  alongside the existing `crates`/`migrations` copies.
- `abyssal-agent run --enrollment-token <token>` failed with "unexpected
  argument" whenever a generated token happened to start with `-`
  (roughly a 1-in-64 chance -- tokens are base64url, which uses `-` as a
  real alphabet character, not just an artifact of some tokens). clap was
  reading the leading `-` as the start of a new flag rather than as part
  of the token's value. Both `--enrollment-token` flags (`run` and the
  new `install`) now set `allow_hyphen_values`, which was the actual
  fix -- quoting the value or using `--flag=value` does not reliably
  route around this in clap's default parsing.
- The release workflow's packaged `abyssal-arsenal`/`abyssal-agent`
  binaries weren't guaranteed to be executable after extraction,
  depending on the CI runner's umask at the `cp` step -- `chmod +x` is
  now explicit in the packaging script rather than assumed from the
  build output's own permissions.

## [0.1.0] - 2026-09-18

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
- **Module system**: an `Arsenal` trait and `ModuleRegistry` covering all 23
  arsenals (`cystoolbox`, `cadavault`, `necrolink`, `postmortem`,
  `reliquary`, `mortiscope`, `incarnation`, `resurrection`, `necropsy`,
  `necropolis`, `obituary`, `reanimation`, `ossuary`, `catacomb`, `parish`,
  `apothecary`, `grimoire`, `cryptkeeper`, `defleshing`, `vivisection`,
  `inquest`, `thanatos`, `panopticon`). Each is registered with real
  metadata, permission gating, and -- as of this changelog -- real
  capabilities; see the individual arsenal entries below for what each one
  actually does.
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
- **Necrolink arsenal** (third arsenal with real capabilities): network
  interfaces (`ip addr show`), routes (`ip route show`), DNS resolver
  configuration, and active TCP/UDP connections (`ss -tuanp`, complements
  Cadavault's listening-only view with a diagnostics-focused "what's
  connected right now" one) as read-only operations (`network.view`); a
  Connectivity Check (ping + DNS lookup against an operator-supplied
  target); bringing a network interface up (Write, `network.manage`) or
  down (Destructive, confirmation required -- can cut off remote access);
  and an active network scan via nmap TCP connect scan against an
  operator-supplied target/CIDR/hostname (Destructive, confirmation
  required, gated by a new dedicated `network.scan` permission --
  Super Admin only by default, independent of `network.manage` -- since it
  sends real traffic to a third-party target rather than managing the host
  itself). DNS configuration auto-detects systemd-resolved
  (`resolvectl status`) vs. falling back to reading `/etc/resolv.conf`
  directly. Scan/connectivity/interface targets are validated (IPv4
  address, IPv4 CIDR, or hostname; explicitly rejects anything starting
  with `-`) on both the control plane and the agent, matching the
  hostname/port validation pattern from the first two arsenals.
- **Parish arsenal**: Linux user, group, and account administration on a
  managed host (`/arsenals/parish`) -- listing users and groups, viewing a
  single account's detail (`id`) as read-only operations
  (`host_users.view`); creating a user or group, and adding/removing group
  membership, as Write operations (`host_users.manage`, no confirmation
  required); locking and unlocking an account as Write operations; and
  deleting a user or group as Destructive operations requiring
  confirmation. Deliberately gated by new, dedicated
  `host_users.view`/`host_users.manage` permissions rather than reusing
  the control plane's own `users.*` permissions -- managing who can log
  into Abyssal Arsenal itself and managing real OS accounts on the
  servers it administers are different responsibilities that were never
  meant to imply each other. The `root` account is hard-refused for lock
  and delete operations regardless of caller permissions, a check the
  agent enforces itself rather than trusting the control plane alone.
- **Catacomb arsenal**: filesystem inspection, maintenance, and repair on
  a managed host (`/arsenals/catacomb`) -- directory usage breakdown and
  finding files above a size threshold as read-only operations
  (`storage.view`); a filesystem check dry run and trimming a mounted
  filesystem (`fstrim`) as Write operations; and a real filesystem repair
  (`fsck -y`) as a Destructive operation requiring confirmation, with a
  mandatory mount-state check refusing to run against a currently-mounted
  device (repairing a live filesystem risks corrupting it further). Fixed
  a real bug found during live verification: `fsck`'s exit code is a
  bitmask of outcomes (clean, errors corrected, reboot needed, errors
  left uncorrected, ...), not a simple success/failure signal, so a naive
  "non-zero means failure" check misreported a successful repair as
  having failed.
- **Apothecary arsenal**: Linux package management on a managed host
  (`/arsenals/apothecary`), auto-detecting whichever of apt/dnf/yum/
  pacman/zypper is actually present rather than assuming one -- listing
  installed packages, searching the package index, viewing a single
  package's detail, and listing upgradable packages as read-only
  operations (`systems.view`); refreshing the package index and
  installing/upgrading a package as Write operations (`systems.manage`);
  and removing a package as a Destructive operation requiring
  confirmation. Fixed a real dnf5 compatibility bug found during live
  verification on a real Fedora host: `dnf list installed` (the classic
  dnf4 positional-keyword syntax) is parsed by dnf5 as a literal search
  for a package named "installed," silently returning no results instead
  of the real installed-package list -- fixed by switching to
  `dnf list --installed`, valid on both dnf4 and dnf5.
- **Ossuary arsenal**: disk, partition, LVM, RAID, volume, mount, and
  storage management on a managed host (`/arsenals/ossuary`). A
  conservative tier (partition table/LVM/RAID summaries, mounting and
  unmounting, extending a logical volume) is available by default, same
  as every other arsenal. A high-risk tier -- partition table create/
  delete, RAID array create/stop, LVM physical/volume-group/logical-
  volume create and remove, and creating a filesystem (`mkfs`) -- is
  gated behind a new admin-configurable Settings toggle
  (`ossuary.high_risk_storage_ops_enabled`), off by default, checked at
  every entry point that leads to dispatching one of these operations, in
  addition to (never instead of) the type-to-confirm each one still
  requires individually. This is the first use of that "second gate"
  pattern in the platform: for operations whose blast radius is
  categorically worse than a normal Destructive action (a single wrong
  device path can destroy a disk instantly and irrecoverably), requiring
  confirmation alone isn't enough -- an admin has to have deliberately
  decided, in advance and separately from any one action, that this
  class of operation is allowed to run at all.
- **Grimoire arsenal**: configuration management and repeatable system
  configuration on a managed host (`/arsenals/grimoire`) -- two tool-
  owned drop-in files, `/etc/sysctl.d/99-abyssal-arsenal.conf` and
  `/etc/cron.d/abyssal-arsenal`, deliberately never an arbitrary or
  pre-existing shared file (editing something like `/etc/hosts` in place
  risks corrupting it through a string-manipulation bug; a dedicated
  file this tool always fully owns and re-renders from scratch cannot
  have that failure mode). Viewing either managed file is a read-only
  operation (`systems.view`); setting or removing a single sysctl key or
  cron job is a Write operation (`systems.manage`); clearing an entire
  managed file is a Destructive operation, type-to-confirm on the
  hostname (there's no single named target for "delete everything this
  tool manages," matching the same pattern Obituary's journal vacuum and
  Defleshing's clear-tmp use).
- **Inquest arsenal**: active incident containment and remediation on a
  managed host (`/arsenals/inquest`) -- listing blocked IPs, isolation
  status, and quarantined files as read-only operations
  (`incidents.view`); blocking/unblocking a specific remote IP and
  quarantining/restoring a file as Write operations (`incidents.respond`,
  auto-detecting nftables vs. iptables); permanently deleting a
  quarantined file as a Destructive operation; and full host network
  isolation (block all traffic except the control plane's own
  connection) as the platform's highest-severity Destructive operation,
  gated behind a second, admin-opt-in Settings toggle
  (`inquest.host_isolation_enabled`, off by default) mirroring Ossuary's
  high-risk pattern, since a wrong edge case (NAT, a DNS-based
  control-plane address, a multi-homed host) can sever the agent's own
  manageability with no remote way to undo it. Isolation is built as a
  single atomic `nft -f`/`iptables-restore` transaction specifically to
  avoid a real race: a chain's drop policy takes effect the instant it's
  created, so applying it and its control-plane-accept exception as
  separate sequential commands would open a window where the agent's own
  connection has nothing accepting it. Quarantined files are renamed to
  encode their own restore path (`<timestamp>__<percent-encoded original
  path>`), so restoring one never depends on an admin-retyped, and
  therefore arbitrary, destination path.
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
- **Host removal**: revoking a host (`/admin/hosts/<id>/revoke`) only ever
  invalidated its credential -- it never took the host out of the list,
  and a revoked host was indistinguishable from a merely-offline one.
  Revoked hosts now show a "Revoked" badge, and a new, separate "Remove"
  action (`/admin/hosts/<id>/remove`, `hosts.manage`, confirmation
  required) hard-deletes the host row entirely; its audit history is
  unaffected since the audit log never referenced hosts by foreign key.
  Removal doesn't attempt to reach out and uninstall the agent remotely
  (often impossible anyway, since removing a host is frequently exactly
  what you do once it's already offline/decommissioned) -- it shows a
  copy-paste uninstall command instead, the same UX as the enrollment
  command.
- **Cryptkeeper arsenal**: secrets, credentials, certificates, keys, and
  sensitive configuration on a managed host (`/arsenals/cryptkeeper`) --
  listing SSH host keys and a user's authorized_keys (always fingerprinted
  via `ssh-keygen -lf`, never showing raw key material), discovering TLS
  certificates and viewing one's full detail, and scanning common
  locations for insecurely-permissioned private keys/authorized_keys
  files, all as read-only operations (`security.view`); generating a new
  SSH keypair and tightening a file's permissions to one of a fixed safe
  set (600/400/640/700, never loosening) as Write operations
  (`security.manage`); and removing one authorized_keys entry by its
  exact fingerprint, or permanently deleting an SSH keypair, as
  Destructive operations requiring confirmation. `ViewSensitiveFile`
  deliberately only ever reads a path the admin names explicitly --
  never an automatic crawler scraping the whole filesystem for anything
  that looks like a secret -- and its result does show real plaintext
  content, a deliberate design choice: the control plane is the trusted
  administrator surface for hosts it already fully manages, not an
  untrusted party, unlike a zero-knowledge password manager.
- **Thanatos arsenal**: security telemetry collection, threat detection,
  event correlation, endpoint monitoring, and security alerting
  (`/arsenals/thanatos`). Tails a managed host's security-relevant logs
  (`/var/log/auth.log` or `/var/log/secure`, falling back to `journalctl`
  for `sshd`/`sudo`/`su`/`systemd-logind` on hosts with neither) and
  classifies each line against a fixed, ordered rule table into a
  severity (Low/Medium/High) and a label, as a read-only, on-demand
  operation (`security.view`). The control plane persists every
  classified event (deduplicated by content hash, so re-scanning the
  same tail window is a harmless no-op) and runs a correlation check --
  5 or more High-severity events for one host within 5 minutes raises a
  `Critical` finding, cooldown-limited to one alert per host per window
  -- which is also pushed out through the existing notification
  infrastructure to an admin-configured recipient list
  (`thanatos.alert_recipients`) when one's set. A new unattended,
  fixed-interval background sweep (`abyssal_web::spawn_thanatos_sweep`,
  the second task of its kind after the elevation-expiry sweep) runs
  this same scan-and-correlate pipeline across every connected host on
  its own, gated behind an off-by-default Settings toggle
  (`thanatos.monitoring_enabled`) since it's meaningfully different in
  kind from Ossuary's/Inquest's high-risk gates -- it doesn't guard
  against one catastrophic action, it guards against an admin being
  surprised that something is reading and storing security-log content
  across their whole fleet automatically; manual, admin-triggered scans
  are unaffected by the setting either way. Deliberately scoped short of
  a full push-based EDR agent (no eBPF, no continuous telemetry stream)
  -- that's a genuinely different order of complexity (a new toolchain,
  a transport the current pull-based agent protocol doesn't have, a
  persisted correlation-rule engine) planned as a later phase, not
  something folded into this pass. Fixed a real bug found during live
  verification: the journal fallback's initial `journalctl -u sudo`
  silently returned nothing, since `sudo` is a one-off child process,
  not a systemd unit -- its PAM messages (including the "authentication
  failure" line the rule table matches on) are tagged with a syslog
  identifier instead, needing `journalctl -t sudo`, a genuinely
  different flag.
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
  point, not stubbed-out placeholders. Thanatos's correlation alerts are
  the first real caller of the dispatcher (see the Thanatos entry above).
- **Deployment tooling**: multi-stage `Dockerfile` with dependency-layer
  caching across the full workspace, `docker-compose.yml` (MariaDB + app,
  optional Caddy reverse-proxy profile), an interactive `install.sh`, and
  `scripts/migrate.sh` / `backup-db.sh` / `restore-db.sh`.
- **CI**: `cargo check`, `cargo test`, `cargo clippy -D warnings`,
  `cargo fmt --check`, and a Docker build-validation job on every push/PR;
  separate workflows publish the control-plane image to GHCR and package
  release binaries for both `abyssal-arsenal` and `abyssal-agent`.
- **Panopticon arsenal**: network visibility and access control --
  discovery, device inventory, and topology mapping across the LAN, run
  from the control plane itself (`/arsenals/panopticon`), not dispatched
  to any one host's agent -- network discovery has to work on devices
  that may never carry an agent at all. The first real use of
  `Executor::execute()` (the in-process counterpart to
  `execute_on_host()`, previously scaffolded but never actually called):
  a discovery scan runs an nmap TCP connect scan directly from the
  control plane's own process (`network.scan`, Destructive, type-to-
  confirm on the target, the same "only scan targets you're authorized
  to scan" posture Necrolink's own network scan already established),
  parses the results, and upserts each discovered device into a
  persisted inventory with best-effort MAC correlation from the control
  plane's own kernel neighbor table. Devices whose IP matches a
  currently enrolled host's last-known connecting address (a new
  `hosts.last_seen_ip` column, captured once at WebSocket connect time)
  show as "Managed"; everything else shows as "Unmanaged." A topology
  view groups the inventory by inferred /24 subnet -- deliberately not
  real L2/switch topology, which would need SNMP/LLDP access this
  platform doesn't have. Viewing the inventory and topology is
  `network.view`; removing a stale device from the inventory
  (`network.manage`) is Destructive, type-to-confirm on the IP.
- **Web UI overhaul**: a full pass on navigation and workflow across all 23
  arsenals, done in seven phases from least to most intensive.
  - **Account menu**: the top-nav dropdown shrank to identity and a link to
    a new `/account` page, which now holds the theme toggle and timezone
    selector that used to clutter the dropdown itself.
  - **Settings page**: rebuilt as a uniform list of rows (label, one-line
    description with a "learn more" expand, control aligned right) grouped
    into Access & Registration, Elevation & Risk Controls, and Monitoring &
    Alerts, replacing the previous inconsistently-sized cards.
  - **Consistency pass**: the `.kind-read`/`.kind-write`/`.kind-destructive`
    card border markers (defined in CSS but under-applied) now appear
    consistently across every arsenal's host page, and stray redundant
    inline styles were removed in favor of the existing spacing scale.
  - **One elevation control per host page**: previously, every action form
    on a host's page carried its own optional sudo-password field --
    Cystoolbox's page alone had four. Elevating is now a single, explicit
    "Elevate this host" control near the top of the page, shown only while
    not elevated; every other action form no longer carries a password
    field of its own. `Executor::execute_on_host()` and the per-arsenal
    `run_read_op`/`run_write_op`/`run_destructive_op` helpers no longer
    thread a password through every action, since elevation always happens
    through the one dedicated route first.
  - **Arsenal navigation**: the dashboard's module grid is now grouped by
    category (Operate, Observe, Defend, Preserve/Recover) into collapsible
    sections, with a server-side search box (`?q=`) and a new pin/unpin
    feature (`user_pinned_modules` table) that surfaces favorited arsenals
    in their own row above the grouped sections.
  - **Global host context**: a persistent host switcher in the top nav
    (`abyssal_selected_host` cookie, the same pattern as the existing theme
    cookie) that stays selected across arsenals. Every per-host arsenal's
    landing page now redirects straight to the selected host's page instead
    of showing the picker, falling back to the picker if the selected host
    is offline or nothing is selected.
  - **Dashboard redesign**: the permanent "Active tasks" placeholder is
    replaced with a real Fleet Health overview (host count/online-offline,
    open Thanatos alerts, hosts an unattended health sweep has flagged, and
    the most recent Reliquary backup). A new `AgentOperation::label()`
    gives every operation a human-readable phrase (e.g. `Reboot` ->
    "Rebooted"), which the audit trail now records alongside a
    Read/Write/Destructive kind tag; "Recent activity" uses this to show
    summarized entries like "Rebooted -- WEB-01" instead of a raw
    `SYSTEM_COMMAND_EXECUTED` row, and filters out routine reads entirely.
    A new background sweep (`abyssal_web::spawn_health_sweep`, the third
    task of its kind) polls `FailedServices` on every connected host every
    5 minutes and persists one snapshot row per host
    (`host_health_snapshots`); Reliquary now records every backup it
    creates (`backup_records`) so the dashboard can show fleet-wide backup
    status without dispatching to every agent on every page load.

### Fixed

- `HostConnectionRegistry::unregister()` never cleaned up requests still in
  flight to the connection that just dropped -- a `dispatch()` call waiting
  on a response from a host whose connection closed mid-request (e.g. a
  stale agent build disconnecting because it can't deserialize a newer
  `AgentOperation` variant, then reconnecting) would silently burn its
  *entire* timeout before failing, rather than failing immediately with
  the existing, clearer "host disconnected before responding" error.
  `unregister()` now also drops every pending request for that host,
  which resolves them right away via the dispatch loop's existing
  connection-closed handling. Caught live: every Necrolink read operation
  against a real host was timing out after exactly 10 seconds instead of
  surfacing an obvious error, traced to the host's agent build predating
  this session's new `AgentOperation` variants.
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
  `abyssal-agent` needs to be built/installed on the target host first --
  the copy-paste command alone gave no indication the binary wasn't just
  already there. `crates/agent/README.md` gained a proper "Building and
  installing" section, including the `sudo`-vs-`cargo install` gotcha
  found while writing it: `cargo install --path crates/agent` puts the
  binary in `~/.cargo/bin`, which is on the invoking user's `PATH` but not
  on `sudo`'s own restricted `secure_path` -- `sudo abyssal-agent` then
  fails with `command not found` even though it runs fine unprivileged.
  The recommended path installs to `/usr/local/bin` instead (also what the
  systemd unit example already assumed).
- Cystoolbox's `SetHostname` and `Reboot` hardcoded systemd-specific
  commands (`hostnamectl set-hostname`, `systemctl reboot`), which fail
  outright on non-systemd distros (Alpine/OpenRC, Void/runit, Devuan,
  Gentoo with OpenRC, ...) -- the exact class of bug Cadavault's firewall
  backend detection was already built to avoid. New
  `crates/agent/src/init_system.rs` detects systemd via `/run/systemd/
  system` (the same signal systemd's own `sd_booted()` uses) and falls
  back to `hostname` + writing `/etc/hostname` directly (via a new
  stdin-piping primitive, `process::run_command_with_stdin` /
  `ElevationState::run_with_stdin`, added because there was no existing
  way to write a file's contents through the agent's "explicit argument
  vectors, never a shell string" execution discipline) and plain `reboot`
  on non-systemd hosts. Live-verified against a real non-systemd host, not
  just the code: ran a container-native agent build inside a disposable,
  genuinely non-systemd Debian container on the same Docker network as the
  control plane, dispatched a real `SetHostname` through the web UI, and
  confirmed both the runtime hostname and `/etc/hostname` changed
  correctly; separately confirmed `Reboot`'s command selection correctly
  chose `reboot` over `systemctl` (the container's minimal image had no
  init package installed at all, so it failed with a clear, honest "no
  such file" error until a real init package was installed, at which
  point `reboot` was where every real non-systemd host's init package --
  `sysvinit-core`, `runit-init`, etc. -- puts it).

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
- **Apotheosis moved out of `/admin/hosts` into per-host arsenal pages.**
  The standalone Elevate/Check Elevation/De-escalate controls are gone
  from the hosts list; `/admin/hosts` is back to being purely host
  management (enroll, revoke, remove). In their place:
  - `cystoolbox` and `cadavault` changed from a single page listing every
    host with inline per-host buttons to a host picker
    (`/arsenals/<name>`) that leads to a dedicated per-host page
    (`/arsenals/<name>/<host_id>`) -- one host in view at a time, matching
    how elevation is itself scoped per host.
  - Every action form on a host's page carries an optional sudo password
    field, shown only while that host isn't already believed elevated.
    Submitting one elevates first and, only on success, proceeds to run
    the actual action in the same request -- no separate confirmation
    round trip. Destructive actions' own confirm pages (Reboot, Enable
    Firewall) carry the same field.
  - A new "Apotheosis" item in the top nav (visible only with
    `hosts.elevate`) pulses red whenever at least one host is believed
    elevated and opens a panel listing every such host with remaining
    time and a De-escalate button -- a status/control surface, not itself
    where elevation happens.
  - New `abyssal_hosts::ElevationTracker`: a lightweight, best-effort,
    control-plane-local mirror of which hosts are believed elevated,
    purely so the UI above can render without an agent round-trip on
    every page load. Explicitly not a security boundary -- see
    "Apotheosis" in [ARCHITECTURE.md](ARCHITECTURE.md).

### Known limitations

- `LoginLimiter` and `HostConnectionRegistry` are in-memory and
  process-local; a multi-instance control plane would need both backed by
  shared state.
- SSO/OIDC and non-SMTP notification providers (Telegram, Slack, Teams,
  Discord) are not implemented yet; all 23 arsenals now have real
  capabilities, so this is the remaining gap in the originally-planned
  scope.
- Thanatos is a pull-based, on-demand/periodic-sweep telemetry collector,
  not a continuous push-based EDR agent -- no eBPF, no live event stream.
  That's a deliberate, documented scope boundary for now (see the
  Thanatos changelog entry above), not an oversight.
- No Tauri desktop client yet; `/api/health` and `/api/me` establish the
  API seam it would use.
