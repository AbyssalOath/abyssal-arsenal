# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/). The
`main` branch is the active development line; tagged releases (`vX.Y.Z`) are
the stable checkpoints built from it. See [README.md](README.md#releases-and-branches)
for what that means for cloning and updating.

## [Unreleased]

> **Action needed for internal (self-signed) installs.** Pull and re-run
> `./install.sh` once: it moves the install onto the new web-managed private
> CA (the app creates it on its next start) and updates the Caddyfile.
> Every machine that trusted the old self-signed certificate must then trust
> the **new CA** -- the agent commands on `/admin/hosts` do that
> automatically; for GPO/browsers download it from `/ca.crt`. Existing
> agents need re-installing with the new command (they couldn't connect to
> the old certificate anyway). Agents report protocol version 36, so older
> builds show "Agent out of date". Let's Encrypt and own-proxy installs are
> unaffected.

### Fixed

- **Agents couldn't enroll against an internal (self-signed) control plane:
  `invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))`.** Root
  cause: `install.sh` generated its certificate with `openssl req -x509`,
  which marks it `basicConstraints: CA:TRUE`, and Caddy served that CA
  certificate as the TLS server certificate. Windows SChannel (browsers,
  `Invoke-WebRequest`) tolerates that, so importing the cert looked like it
  worked; rustls/webpki -- the agent's TLS stack -- correctly refuses a CA
  certificate in the end-entity position. The control plane now runs a small
  private CA (`CA:TRUE, pathlen:0`, name-constrained to its own addresses,
  10 years, ECDSA P-256) and serves a certificate issued by it (`CA:FALSE`,
  `serverAuth`, SANs = the addresses, 825 days) -- see "Web-managed internal
  TLS" below.
- **The Windows manual-install command didn't run** (`.\$a\abyssal-agent.exe`
  is not something PowerShell expands as a command path: "term is not
  recognized"). It now calls the exe with `&`, and finds it whether the zip
  extracts into a folder or flat.
- **Installer failures were invisible under RMM tools** (PDQ, Intune, SYSTEM
  account): truncated output, no exit code. The agent and both bootstrap
  scripts now print `ERROR:`/`HINT:` on stdout and exit with distinct codes
  (certificate untrusted / CA used as leaf / name mismatch / fingerprint
  mismatch / token rejected / unreachable / service registration -- see
  `crates/agent/README.md`). The agent's enrollment error now includes the
  control plane's explanation instead of a bare status.
- The Linux internal-CA one-liner no longer reports success when a download
  fails partway (`curl | sh` with an empty script exits 0).

### Added

- **Web-managed internal TLS** (`/admin/health/tls`, summarized on
  `/admin/health`). For installs with no public domain, the app owns the
  private CA and Caddy's server certificate (new `abyssal-internal-ca`
  crate); `install.sh` only records the address(es)
  (`INTERNAL_TLS_ADDRESSES`) and the app creates everything on first start,
  before Caddy starts. After that, nothing on the server needs touching:
  - the server certificate **renews automatically** 30 days before expiry
    (background task, every 6 h) and Caddy loads it live through its admin
    API on a Unix socket shared only by the two containers -- no restart, no
    re-trust; *Renew now* / *Reload Caddy* buttons too;
  - **changing addresses or rotating the CA** is two-phase: a pending CA is
    pushed with the current one to every connected agent (new protocol
    operation `UpdateTrustedCa`, also sent on every agent connect), the page
    shows which agents confirm it and offers it for download (GPO,
    browsers), then *Activate* switches the server over;
  - self-monitoring alerts when renewal is failing or the CA nears expiry;
  - every action is audited; `docker compose exec app /app/abyssal-arsenal
    tls status|renew|reload|ensure` is the break-glass CLI.
  Storage moved to Docker volumes owned by the app (`abyssal_tls_ca`, app
  only -- it holds the CA key; `abyssal_tls_server`, read-only in Caddy;
  `abyssal_caddy_admin`). Caddy now waits for the app to be healthy.
- **No-manual-step bootstrap against an internal CA.** The control plane
  serves its CA certificate (public half only) at `/ca.crt` / `/ca.pem`, and
  every command `/admin/hosts` generates -- single-use, deployment-token,
  Linux and Windows -- embeds the CA's SHA-256 fingerprint: it fetches the
  CA without trusting the connection, refuses to continue on a mismatch,
  then trusts it and installs. One command on a fresh machine; nothing to
  copy, rename, or import first.
- **Agent `--ca-cert` / `--ca-fingerprint`.** The agent trusts an
  operator-supplied CA in addition to the OS store for enrollment and the
  control-channel WebSocket (including reconnects), using one shared rustls
  configuration. `install` persists it next to the credentials and in the
  service definition, and the control plane keeps it current
  (`UpdateTrustedCa`); the agent re-reads it on every reconnect. Never
  auto-discovered from disk; certificate validation is never relaxed.
  Self-update downloads (from GitHub) deliberately use only the OS store, so
  the control plane's CA can never vouch for the agent's next binary.
- **`install.ps1`**: `-CaFingerprint`, `-Uninstall`, `-RemoveTrust`,
  `-ExitCode` (exit with the documented codes, for RMM tools),
  `-EnrollmentTokenFile` / `$env:ABYSSAL_ENROLLMENT_TOKEN`; the token is
  passed to the agent by environment variable and redacted from output.
  **`install.sh`**: `--ca-cert`, `--ca-fingerprint`, `--trust-system`,
  `--remove-trust`, `--uninstall`, `--enrollment-token-file` /
  `ABYSSAL_ENROLLMENT_TOKEN`.
- **Unattended Windows deployment script** on `/admin/hosts` for PDQ /
  Intune / GPO running as SYSTEM: no dependence on the working directory or
  an interactive session, token kept off the command line, non-zero exit on
  failure. It's now the primary command for Windows deployment tokens.
- SSH deploy hands the control plane's CA bundle to the agent
  (`--ca-cert`) as part of the remote install.
- `PUBLIC_CA_FILE`: an operator with their own proxy and their own internal
  CA can publish it at `/ca.crt` and get the same pinned install commands.
- Tests: the internal CA (constraints, SANs, renewal/rotation lifecycle,
  OpenSSL cross-check of the chain and extensions); agent tests that
  complete a real TLS handshake with the agent's own rustls client against
  those certificates trusting only the CA -- IP, FQDN, both, and an
  old+new rotation bundle -- and show the old installer's cert failing with
  `CaUsedAsEndEntity`; pushed CA bundles (atomic replace, key refused); the
  served `install.ps1` and every generated Windows command through the
  PowerShell parser and PSScriptAnalyzer.

### Added

- **Control plane serves the agent binary (self-contained / air-gapped
  rollout).** Hosts now download the agent from this control plane
  (`/agent/windows`, `/agent/linux`) rather than from GitHub, so an internal or
  air-gapped network only needs to reach the control plane -- and the control
  plane can distribute an agent build newer than the latest public release.
  Served from a volume an operator populates with a built archive (installer
  finds the binary anywhere inside it); if the volume is empty, the control plane
  fetches the matching release from GitHub once and caches it. The bootstrap
  one-liners and the deployment-token command both use this path.
- **Reusable deployment tokens for mass agent rollout (Wazuh/PDQ-style).**
  Alongside the existing single-use, short-lived enrollment token, `/admin/hosts`
  can now mint a **reusable deployment token** with a chosen OS, lifetime, and
  label. It generates a single install command to drop into PDQ Deploy, a GPO
  startup script, or Intune; every machine that runs it enrolls automatically
  under its own hostname, until the token expires or is revoked. Active
  deployment tokens are listed with their host-enrollment counts and a revoke
  button. (New `host_enrollment_tokens` columns; the single-use path is
  unchanged.)

### Changed

- **Agent TLS now validates against the OS trust store (native roots)** instead
  of a bundled CA list, for both the enrollment request and the WebSocket
  control channel. This lets the agent connect to a control plane behind an
  internal CA or a self-signed certificate once that certificate is trusted on
  the host (e.g. imported via Group Policy / `update-ca-certificates`) -- the
  on-prem/internal case; publicly-trusted certificates (Let's Encrypt) keep
  working via the OS's own public roots. Previously an internal/self-signed
  control plane could not be enrolled against at all. **Agents must be rebuilt
  to pick this up.**

### Added

- **Haruspex: Active Directory DNS & domain-controller health diagnostics (new
  arsenal).** A new Observe-category arsenal for Windows domain controllers that
  runs the classic AD health toolchain on demand through the agent and returns a
  sectioned report in the UI. Two read-only reports against a given domain FQDN:
  an **AD DNS check** (`dcdiag /test:dns`, a domain lookup, and the
  `_ldap._tcp.dc._msdcs.<domain>` SRV lookup) and an **AD health check**
  (`dcdiag /v`, `repadmin /replsummary` + `/showrepl`, `nltest /dsgetdc` +
  `/dclist`, `ipconfig /all`, time status, the core AD services, and the
  SYSVOL/NETLOGON shares). The domain FQDN is validated control-plane-side and
  again on the agent; a tool that isn't present (i.e. the host isn't a DC)
  becomes a note in its section rather than failing the report. Adds the
  `AdDnsReport` / `AdHealthReport` operations (protocol version 35); Windows-only
  (a clean "not supported on this platform" elsewhere).
- **Thanatos on Windows: log-offset tracking + high-volume event streams.** The
  Windows scan no longer re-reads a fixed 200-event window each sweep. The
  control plane now stores a per-host, per-channel Event Log high-water mark
  (`EventRecordID`) and hands it back to each scan, so the agent reads only
  events *newer* than it last saw -- via a server-side `FilterXml`
  `EventRecordID > offset` query -- with a first-scan bounded baseline and a
  per-scan safety cap. No burst is lost between sweeps and nothing is
  re-processed. That makes the high-volume streams affordable, so the scan now
  also covers native **4688 process creation** and, where Sysmon is deployed,
  **Sysmon process creation (event 1)** -- both classified only by the shared
  LOLBin/obfuscation command-line rules (the "specific signal, not the whole
  category" approach), never a blanket per-event finding. Adds a
  `channel_offsets` field to the `ScanSecurityEvents` operation (protocol
  version 34) and a `thanatos_windows_log_offsets` table; the Unix scan ignores
  it (Linux tails by log position, not record id).
- **Thanatos: Sysmon (Windows), host posture, and Linux persistence parity.**
  When Sysmon is deployed on a Windows host, Thanatos now ingests its
  low-volume/high-signal events (process injection, process tampering) -- opt-in,
  nothing assumed if Sysmon is absent. Windows hosts also get host-posture
  findings (SMBv1 enabled, UAC disabled, RDP without Network Level
  Authentication, LSASS not running protected). On Linux, the file-integrity
  watch list gains the persistence-sensitive files it was missing
  (`/etc/ld.so.preload`, `/etc/crontab`, `/etc/rc.local`, root and system shell
  rc files), so tampering or a rootkit preload appearing raises a finding.
  (Per-channel log-offset tracking, 4688 process-creation auditing, and the
  high-volume Kerberos/Sysmon streams are a documented follow-up.)
- **Thanatos on Windows: persistence, config-drift & posture detection.** The
  Windows Thanatos scan now baselines and change-alerts on the persistence and
  configuration surfaces a real EDR watches: service configuration (binary path,
  start mode, account), scheduled tasks, WMI event-subscription persistence,
  firewall profile state, machine-wide autorun locations beyond Run keys
  (Winlogon, Image File Execution Options, AppInit_DLLs), and Windows Defender
  exclusions -- all via the existing file-integrity hash-diff mechanism, so a
  change from a host's baseline raises a finding. It also emits direct findings
  for unquoted service paths and for Defender protection being off/tampered or
  its signatures stale.
- **Thanatos on Windows: auth fidelity & correlation parity.** The scan now
  covers the account-lifecycle and Kerberos-preauth event IDs the earlier set
  was missing (4722/4725/4726/4738/4728/4756/4733/4757/4771), and each Windows
  logon event now carries explicit source-IP and account fields extracted from
  the event (surviving the message-length cap). With that, the control plane's
  account-targeting correlation and the auto-disable-account response -- which
  were effectively Linux-only because the username couldn't be parsed from a
  Windows event -- now fire for Windows hosts too.
- **Windows agent: cross-platform telemetry foundation.** The core
  observability operations now have real Windows implementations instead of
  erroring on Linux-only shell-outs, so a Windows host reports genuine data on
  the fleet dashboard and in Mortiscope: `SystemInfo` (OS/version/uptime via
  CIM), `ResourceUsage` (memory + fixed-disk summary), `LoggedInUsers`
  (`query user`), `ListeningPorts` (`Get-NetTCPConnection`/`Get-NetUDPEndpoint`),
  `RecentAuthLog` (Security-log logon/failed-logon events), and the Mortiscope
  metric feeds `CpuUtilization`, `MemoryDetail`, and `DiskSpaceCritical` -- each
  emitting output the existing control-plane parsers read unchanged, so per-host
  CPU / memory / disk meters and sparklines populate for Windows hosts with no
  control-plane change. `LoadAverage` (a Unix concept) now returns a clean "not
  supported on this platform" rather than a fabricated value or a raw error,
  via a shared helper that later milestones reuse. No new protocol operations. The server running Abyssal
  Arsenal now watches, alerts on, and diagnoses itself. Real health endpoints:
  `/healthz` (liveness -- always 200 while serving, even mid-restore) and
  `/readyz` (readiness -- database reachable, migrations clean, not
  mid-restore; 200/503 with a compact component report), both unauthenticated
  for external monitors and load balancers. Every background sweep now records
  a liveness beat, so a stalled or panicked task becomes visible instead of
  failing silently. A new **Control-plane health** admin page (`/admin/health`,
  `SettingsManage`) shows readiness, per-task freshness/last-error, preflight/DR
  advisories (encryption key, public URL, cookie security, notification
  providers, backup destination writability and recency), and a self-monitoring
  config form. The control plane's own CPU/memory/disk are now kept as history
  (trend sparklines on the Control Plane card), and an opt-in self-monitor can
  alert -- through the existing notification providers -- on sustained resource
  pressure, a stalled background task, or overdue backups, firing once on the
  way into a bad state and clearing on recovery. No JavaScript required; all
  self-monitoring is off by default.
- **Dashboard: opt-in live updates (auto-refresh + optional htmx).** The
  dashboard, fleet, and activity views gained a per-browser "Live updates"
  control to pick an auto-refresh interval (off / 15s / 30s / 60s), stored as a
  cookie like the theme and selected-host preferences. By default this drives a
  plain `<meta http-equiv="refresh">` that reloads the current URL (query string
  preserved) -- **no JavaScript required**. A "Partial updates" checkbox
  additionally opts into a **vendored copy of htmx** (served same-origin, never
  a CDN) that polls per-section fragment endpoints and swaps just the changed
  region instead of reloading the whole page. New fragment routes
  `/dashboard/fragments/{control-plane,overview,hosts,activity}` render the same
  partials the full pages embed, enforce the same permission checks, carry the
  current filter/sort/page, and read only cached data -- never a live agent
  dispatch. Everything stays off by default and degrades cleanly to full-page
  reloads (or nothing) when JS is blocked. Documented in ARCHITECTURE.md.
- **Dashboard: activity feed.** A new Activity view (`/dashboard/activity`,
  reached from the dashboard's Recent activity card) shows the audit history
  grouped by day (Today / Yesterday / date, in the viewer's timezone), newest
  first, with numbered pagination. A **Show/Hide system events** toggle filters
  out background-job rows (those with no human actor) so the feed can focus on
  what people did; routine reads are always excluded. Filtering happens in SQL
  so pagination totals stay correct, and an out-of-range page clamps to the last
  real page rather than erroring. Gated on `AuditView`, with a link through to
  the full audit log. No JavaScript required.
- **Dashboard: fleet hosts table.** A new Fleet view (`/dashboard/hosts`,
  reached from the dashboard's Hosts tile) lists every managed host with its
  cached CPU / memory / disk usage (compact in-cell meters), a recent-CPU
  sparkline, online/offline state, and any health flag (unreachable, or N
  failed units). It supports name search, a status filter (all / online /
  offline / needs attention) with live counts, sortable columns, and
  pagination -- an out-of-range page clamps to the last real page rather than
  erroring. Each host has an **Open** action that sets it as the active host
  context so the next arsenal you open is scoped to it. Reads only cached data:
  the metrics sweep's latest sample and one batched query for the visible
  page's sparklines (no per-host queries, no live agent dispatch on load). The
  metrics sweep now also records each host's busiest-filesystem disk usage
  (`disk_used_percent`), so the disk meter and a disk threshold have data. No
  JavaScript required.
- **Dashboard: at-a-glance operations overview.** The dashboard now opens with
  a hero banner stating overall fleet state in a word (all systems healthy /
  degraded / fleet offline) plus a one-line summary, followed by five summary
  tiles (hosts online/offline, elevated hosts, open alerts, active sessions,
  recent audit failures) and a **Control plane** card showing the server's own
  CPU / memory / disk meters, uptime, build version, database reachability and
  active-session count. Every status uses a word + icon alongside colour, never
  colour alone, and reads only cached or cheaply-aggregated data -- no live
  agent dispatch on page load. The control-plane resources come from a new
  60-second background sampler (`sysinfo`); its card shows "collecting…" until
  the first sample lands and marks the reading stale if the sampler falls
  behind. All of it stays behind the existing `HostsView` check, and each tile
  drills into a fuller view only where the viewer has permission (the recent-
  failures tile links to the audit log only for `AuditView` holders). No
  JavaScript required.
- **Resurrection: fleet recovery console.** A new overview page (linked from
  the Resurrection landing and host pages) runs a light recovery poll of
  every connected host (system state, failed units, read-only filesystems,
  disk space) and shows them worst-first with a fleet summary -- "which hosts
  need rescuing right now," complementing the dashboard's needing-attention
  list. Each host links to its full triage, and the console aggregates the
  suggested next steps across every host with a problem. Built from the
  existing recovery reads; no new agent operations.
- **Resurrection: recoverability triage report.** A single "Triage this
  host" action runs every recovery check at once (system state, failed
  units, read-only filesystems, previous-boot errors, disk space, fstab) and
  presents one scored rollup: each check as ok / warning / critical /
  unavailable, with a weighted overall score (a warning counts as half;
  checks that couldn't run are excluded rather than dragging the grade
  down). It's built by reusing the individual recovery reads -- no new agent
  operation -- and aggregates and de-duplicates the suggested next steps
  from every sub-check, so one report can point at Incarnation, Postmortem,
  Defleshing, Ossuary and more together.
- **Resurrection: disk-full and fstab recovery checks.** Two more triage
  reads for the classic "won't come back cleanly" causes. **Disk Space**
  (`df -Ph`) surfaces filesystem usage, and a filesystem at or above 90%
  offers to free space with Defleshing, manage logs with Obituary, or
  inspect storage with Ossuary. **Fstab Check** validates `/etc/fstab`
  (`findmnt --verify`) to catch mount problems that would break the next
  boot, reporting a reliable ok/problems status derived from the tool's exit
  code. Adds `DiskSpaceCritical` and `FstabCheck` operations; bumps
  `PROTOCOL_VERSION` to 33.
- **Resurrection: failed-unit recovery.** A new **Failed Units** read lists
  the host's failed systemd units with their state and description (richer
  than a bare count, and distinct from the blunt "reset all failed state"),
  rendered as a table with a per-unit **Recover** button. Recovering a unit
  clears its failed state and restarts it (`reset-failed` + `restart`) --
  targeted recovery of one already-failed unit rather than an all-or-nothing
  clear. When any units are failed, the check offers "Manage services with
  Incarnation" and "Investigate the failures with Postmortem". Adds
  `ListFailedUnits` and `RecoverUnit` operations; bumps `PROTOCOL_VERSION`
  to 32.
- **Resurrection: structured recovery reads and a broader workflow graph.**
  The two recovery reads that were plain text now parse into structured
  results, so Resurrection can suggest next steps beyond its
  read-only-filesystem axis. **System Running State** reports whether the
  host is degraded and, when it is, offers "Investigate degraded state with
  Postmortem" and "Manage services with Incarnation". **Previous Boot
  Errors** counts real error lines (skipping journalctl markers) and offers
  "Investigate the previous boot with Postmortem" when any are present. All
  three recovery reads now share one structured-read path. No new agent
  operations; the parsing is on the control plane.

- **Grimoire: fleet config-drift hub.** A new overview page (linked from the
  Grimoire landing and host pages) polls every connected host's managed
  sysctl drift at once and shows, per host, whether its managed overrides
  still match their live values -- in sync / drifted / no-managed-config --
  sorted worst-first with a fleet summary. It's the "is the fleet in its
  desired state?" console, and the richest config source: hosts that have
  drifted aggregate the "Investigate config drift with Postmortem"
  suggestion. Built from the existing drift read, so no new agent operations.
  (Detecting hosts *missing* an expected profile is left for a future
  host-to-profile assignment.)
- **Grimoire: apply a config profile across the fleet.** A profile can now
  be applied to every connected host at once, not just one -- the
  "enforce it everywhere" force-multiplier. Because the blast radius is
  broad, it goes through a confirmation that lists exactly which hosts will
  be affected and requires typing the profile name, then applies each
  setting to each host and reports a per-host applied/failed summary
  (a failure on one host or setting never aborts the rest). Reuses the same
  per-host apply path as single-host apply, so a fleet apply is just that,
  fanned out. No new agent operations.
- **Grimoire: config profiles (config-as-code).** A profile is a named,
  reusable bundle of declarative settings -- any mix of sysctl, kernel
  module blacklist, and journald retention entries -- created on a new
  Config Profiles page and applied to a host as a unit, with per-entry
  results. Profiles reuse the Macros scoping model: **Personal** (visible
  only to you) or **Role** (shared with a role's members), and only the
  owner or an admin with `macros.manage_all` can edit or delete one.
  Applying dispatches each entry through the same operations the individual
  Grimoire actions use, so a profile is just those actions bundled. Adds a
  `grimoire_profiles`/`grimoire_profile_entries` schema (migration `0029`);
  no new agent operations.
- **Grimoire: two new managed config surfaces.** Grimoire's managed-drop-in
  idiom now extends beyond sysctl and cron to two more domains. **Kernel
  module blacklist** manages `/etc/modprobe.d/99-abyssal-arsenal.conf` --
  view, blacklist a module (so it isn't auto-loaded), un-blacklist, or clear
  the list; blacklisting takes effect on the next load/boot and never
  touches an already-loaded module. **Journald retention** manages a
  `/etc/systemd/journald.conf.d/` drop-in with a closed set of retention
  settings (SystemMaxUse, SystemKeepFree, MaxRetentionSec, MaxFileSec),
  applied by restarting `systemd-journald`. Both follow the same
  tool-owns-the-file, never-edit-in-place, validate-both-sides pattern
  sysctl/cron already use, with the destructive "clear" actions behind the
  usual typed confirmation. Adds seven `AgentOperation`s and bumps
  `PROTOCOL_VERSION` to 31.
- **Grimoire: managed-sysctl drift detection.** A new Check Sysctl Drift
  action compares every key in Grimoire's managed sysctl file against the
  host's live value and shows, per key, declared vs live with an in-sync /
  drifted / unavailable status -- answering "did my managed config actually
  take effect, or was it overridden out of band?", which Grimoire couldn't
  ask before. When any key has drifted it offers "Investigate config drift
  with Postmortem", Grimoire's first turn as a workflow source rather than
  only a target. Adds one read-only `AgentOperation::SysctlManagedDrift`
  (bumps `PROTOCOL_VERSION` to 30); the drift comparison is on the control
  plane.

- **Reanimation: fleet process hub.** A new overview page (linked from the
  Reanimation landing and host pages) polls every connected host for its
  top CPU-consuming process and shows them in one table -- process, PID,
  %CPU, %MEM per host -- each row linking straight to that host's
  Reanimation page with the PID pre-filled, ready to inspect, tame, or
  signal. It's the act-side complement to Mortiscope's observe overview:
  see the fleet's hottest processes and jump to acting on any of them. No
  new agent operations (it reuses the existing top-processes read).
- **Reanimation: deep process introspection.** Three new read-only checks
  for understanding a process before acting on it. **Open Files** lists a
  process's descriptors (`lsof -p` when present, else `/proc/<pid>/fd`) --
  sockets, held files, deleted-but-open files. **Limits & Info** shows a
  process's resource limits (`/proc/<pid>/limits`) plus its executable,
  working directory, and thread count; it deliberately omits the environment,
  which routinely holds secrets. **Zombie Report** scans every process on the
  host (not the truncated list) for defunct/`Z`-state ones and names the
  parent that hasn't reaped each, with guidance that signaling a zombie won't
  help -- and offers "Investigate defunct processes with Postmortem" when any
  are found. Bumps `PROTOCOL_VERSION` to 29.
- **Reanimation: resource control ("tame, don't kill").** Two reversible
  tuning controls for a running process, so a resource hog can be reined in
  instead of terminated. **I/O priority** (`ionice`) sets a process's I/O
  scheduling class and level -- e.g. drop a backup job to the idle class so
  it only uses disk when nothing else needs it. **OOM score adjustment**
  writes `/proc/<pid>/oom_score_adj` to bias the kernel's out-of-memory
  killer, protecting a critical process (down to -1000) or volunteering a
  disposable one (up to 1000) -- the direct lever for a Mortiscope
  memory-pressure finding. Both are Write (reversible), Linux-only (clear
  "unsupported" on Windows), and refuse the agent's own PID and PID 1.
  Bumps `PROTOCOL_VERSION` to 28. (cgroup CPU/memory *caps* are deliberately
  left to a future Incarnation change: capping an arbitrary PID means moving
  it between cgroups, which is fragile and better expressed per-service via
  `systemctl set-property`, respecting the Reanimation/Incarnation boundary.)
- **Reanimation: signal-by-name and graduated signal risk.** A new
  signal-by-name flow signals every process matching a name (pgrep-style),
  after a mandatory **preview** that dispatches a dry run and shows exactly
  which PIDs would be hit -- the agent always excludes itself and PID 1, so
  a by-name action can never take out the agent. Signals are now graded by
  risk instead of all going through the same gate: terminating or
  interrupting signals (TERM/KILL/QUIT/INT) still require typing the PID (or
  the name, for by-name) to confirm, while reversible ones
  (HUP/CONT/STOP/USR1/USR2) are a plain Write -- so the process table's new
  per-row **Pause** (SIGSTOP) and **Resume** (SIGCONT) buttons are one
  click. Adds `AgentOperation::SignalByName` (Unix only -- Windows has no
  pgrep/POSIX signals) and bumps `PROTOCOL_VERSION` to 27; existing agents
  need one redeploy or self-update to gain it.
- **Reanimation: structured process table and its first workflow
  suggestions.** Listing processes now returns a structured, highest-CPU-
  first view (`ps -eo pid,ppid,user,stat,pcpu,pmem,comm`, with the process
  state) instead of a flat text dump, rendered as a table with per-row
  Detail and Signal actions -- so a process picked out by a Mortiscope
  hand-off (which already pre-fills its PID) lands somewhere you can act.
  Zombie/defunct processes are flagged inline, and a list that contains any
  now offers "Investigate defunct processes with Postmortem" -- Reanimation's
  first turn as a workflow source rather than only a target. No new agent
  operations; the parsing is on the control plane.

## [0.1.3] - 2026-09-28

### Added

- **Mortiscope: fleet monitoring overview.** A new overview page (linked
  from the Mortiscope landing and host pages) shows every active host's
  latest core metrics -- load per core, CPU busy, memory used, swap used --
  in one table, each cell coloured against the configured thresholds and
  each host rolled up to its worst status, sorted worst-first, with a
  fleet summary (critical / warning / ok / no-data counts). It's built from
  the swept history in a single query rather than re-polling, works whether
  or not alerting is enabled, and aggregates the workflow suggestions for
  every host whose latest values cross a registry threshold -- so one page
  can point at Vivisection, Reanimation, and Necropsy across the whole
  fleet, making Mortiscope the richest workflow source in the app. No new
  agent operations.
- **Mortiscope: metric thresholds and alerting.** A new Monitoring &
  Thresholds page (linked from each host's Mortiscope page) lets an
  operator configure per-metric thresholds (a metric, a `>=`/`<=`
  condition, a value, and a severity), set alert recipients, and choose
  how many consecutive breaching samples count as sustained. When alerting
  is enabled -- opt-in, off by default, since trend history is collected
  regardless -- the metrics sweep compares each connected host's recent
  samples against the thresholds and dispatches a notification through the
  existing provider(s) on the transition into a sustained breach, then a
  recovery notice when it clears, tracking per-host/metric firing state so
  it never re-alerts every tick. Requiring N consecutive breaching samples
  guards against flapping and against alerting on a single spike. An
  "Evaluate now" action runs the same evaluation on demand. Reuses the
  Thanatos sweep/alert pattern and recipient format; adds migration
  `0028_mortiscope_thresholds` and the `mortiscope.monitoring_enabled` /
  `mortiscope.alert_recipients` / `mortiscope.sustained_samples` settings.
  No new agent operations.
- **Mortiscope: metric history and trends.** A new unattended metrics
  sweep polls a small core set (load per core, CPU busy %, memory used %,
  swap used %) across connected hosts every few minutes and records a
  time series in a new `host_metric_samples` table, pruned to a rolling
  seven-day window so it stays bounded. The Mortiscope host page now shows
  a "Recent trends" card with the latest value and an inline sparkline for
  each metric, drawn from that history rather than a fresh poll on every
  load. The sweep reuses the same parsers the on-demand read handlers use,
  so a swept sample and an on-demand reading are computed identically, and
  it follows the established system-initiated sweep pattern
  (`health_ops`/`thanatos_ops`). Adds migration `0027_mortiscope_metrics`;
  no new agent operations.
- **Mortiscope: broader metric coverage.** Four new read-only checks fill
  the gaps left by the point-in-time snapshots. **CPU Utilization** reports
  real busy % and iowait % from the delta between two `/proc/stat`
  snapshots (distinct from load average, which counts runnable tasks) --
  high busy offers profiling with Vivisection, and high iowait points at
  storage with Necropsy's disk-health check. **Network Throughput** reports
  per-interface receive/transmit rates from a `/proc/net/dev` delta.
  **Thermal Sensors** reads temperatures via `lm-sensors` when present and
  falls back to `/sys/class/thermal` otherwise (detected, not assumed),
  offering Necropsy hardware inspection when a zone crosses 80 °C.
  **Memory Pressure** reports the kernel's Pressure Stall Information for
  memory, IO, and CPU, offering Vivisection's VM statistics under sustained
  memory pressure (and reporting plainly when PSI isn't available on the
  host's kernel). `PROTOCOL_VERSION` bumps to 26 for the new operations --
  existing agents need one redeploy (or a self-update) to pick them up.
- **Mortiscope: structured readings and metric-driven workflows.** The
  monitoring reads now parse their output into numbers instead of only
  showing text, so a high reading can suggest where to act. Load Average
  reports load-per-core (the agent now appends the CPU core count, so raw
  load can be normalized; an older agent that doesn't just omits the
  per-core figure rather than misreporting it) and offers "Profile with
  Vivisection" when load exceeds two per core. Memory Detail computes
  used-memory and swap-used percentages from `/proc/meminfo` and offers
  Vivisection's VM statistics at >=90% memory and swappiness tuning at
  >=50% swap. Top Processes by Memory now, like Top Processes by CPU,
  offers "Investigate PID ... with Reanimation" for a process over half
  of RAM. No new agent operations -- the parsing is on the control plane,
  and the rendered text output is unchanged.

- **Cadavault: aggregate Security Posture Report.** A single **Run
  Security Posture Report** action runs every Cadavault check at once
  (firewall, SSH hardening, kernel/sysctl baseline, account policy,
  mandatory access control, automatic updates) and presents one scored
  rollup: each category as pass / warning / failing / unavailable, with a
  weighted overall score (a warning counts as half a pass; checks that
  couldn't run -- e.g. because the host isn't elevated -- are excluded
  from the denominator rather than dragging the grade down). It's built
  entirely by reusing the individual read operations, so it adds no new
  agent operation, and it's the richest workflow source in the app: it
  aggregates and de-duplicates the suggested next steps from every
  sub-check it ran, so one report can point at Cryptkeeper, Parish,
  Grimoire, and Apothecary together. The report page notes when a host
  isn't elevated and offers a one-click re-run.
- **Cadavault: account, MAC, and automatic-update audits.** Three new
  read-only posture checks, each handing remediation off to the arsenal
  that owns it via a contextual workflow suggestion rather than acting
  itself. **Account Policy Audit** reports UID-0 accounts other than
  root, empty-password accounts, `NOPASSWD` sudoers rules, and the
  password-aging defaults from `/etc/login.defs` (a check whose file
  needs root and isn't readable is reported `unknown`, never a
  misleading zero) -- extra privileged or passwordless accounts offer
  "Manage accounts with Parish". **MAC Status** detects SELinux
  (`getenforce`/`sestatus`) or AppArmor (`aa-status`) rather than
  assuming either, and a present-but-not-enforcing system offers
  "Enforce access control with Grimoire". **Automatic Updates** detects
  the package manager and checks that family's unattended-update
  mechanism (apt periodic / `dnf-automatic.timer` / ...), offering
  "Configure automatic updates with Apothecary" when it's disabled.
  Adds read-only `AccountPolicyAudit`, `MacStatus`, and
  `AutomaticUpdatesStatus` operations.
- **Cadavault: kernel/sysctl security posture.** A new **Sysctl Posture**
  read reports the host's current effective values for a curated,
  CIS-lite baseline of security-relevant kernel parameters
  (`SECURITY_SYSCTLS` -- network anti-spoofing and redirect hardening,
  ASLR, `dmesg`/kernel-pointer restrictions, filesystem link
  protections, and so on), scoring each as pass/fail/unavailable in a
  table. Where a value falls short, an **Apply** button sets it to the
  reviewed baseline value by reusing the existing shared
  `SetPersistentSysctl` operation (writing the Abyssal-managed sysctl
  drop-in and applying it immediately) -- narrow and reversible from
  Grimoire. Cadavault only ever applies a key that's in the baseline, and
  only ever to that key's reviewed value, so it can't be used to set an
  arbitrary sysctl. A posture check that turns up any failing parameters
  offers "Manage all sysctls with Grimoire". Adds one read-only
  `AgentOperation::SysctlSecurityPosture`; the fix path adds no new
  mutating operation.
- **Cadavault: firewall deny/remove and SSH hardening.** The security
  arsenal grows beyond its original allow-a-port-and-look scope. On the
  firewall side it now has **Deny Port** (a Write that adds an explicit
  block rule -- the complement of Allow Port) and **Remove Port** (a
  Destructive, type-the-hostname-to-confirm operation that revokes a
  previously-allowed port, since doing so can cut off remote access), both
  detecting firewalld/ufw/iptables the same way the existing firewall
  operations do and refusing raw nftables with a clear message rather than
  guessing at an unfamiliar ruleset. New too is an **SSH Config Audit**
  read (`sshd -T`, narrowed to the security-relevant directives -- root
  login, password auth, empty passwords, X11 forwarding, MaxAuthTries) and
  an **SSH Hardening** section that applies one known-safe directive at a
  time (disable root login, password auth, empty passwords, or X11
  forwarding) to a Cadavault-owned drop-in
  (`/etc/ssh/sshd_config.d/50-cadavault.conf`), validating the whole
  config with `sshd -t` and rolling back to the previous drop-in if
  validation or the reload fails -- the same managed-file,
  validate-before-reload idiom Sepulchre uses, so a bad change can never
  lock you out. The hardening set is a closed enum
  (`SshHardeningSetting`), never a free-form directive, so the control
  plane can't write an arbitrary line to a host's sshd. Tightening auth is
  Destructive and gated behind typed confirmation; **Clear SSH Hardening**
  resets the drop-in to its header. Cadavault is now also wired into the
  contextual workflow graph for the first time: an SSH audit that finds
  password authentication still enabled offers "Review authorized keys
  with Cryptkeeper before disabling password auth", and Postmortem's
  failed-login and Thanatos's alerted-scan results now both offer to
  harden the host with Cadavault. `PROTOCOL_VERSION` bumps to 25 for the
  new `AgentOperation` variants -- existing agents need one redeploy (or a
  self-update) before they understand them.

- **Agent lifecycle: one-click updates, self-update, and per-OS
  bootstrap installers.** A host showing "Agent out of date" in
  `/admin/hosts` now has an **Update agent** action that dispatches the
  new `AgentOperation::SelfUpdate` over the host's existing WebSocket:
  the agent downloads the release matching the control plane's own
  version for its platform (TLS-pinned to GitHub, the same source and
  trust model the SSH-deploy path already uses -- the wire only ever
  carries a version tag, never a URL), replaces its installed binary in
  place, and restarts its own service (a transient `systemd-run` unit on
  Linux, deliberately outside the service's cgroup so the restart isn't
  cut off mid-flight; a detached updater script on Windows, where a
  running `.exe` can't be overwritten and the swap has to happen after
  the service stops). An agent too old to understand the operation drops
  the connection instead of replying, which the Update action reports as
  a clear "re-deploy it first" rather than a silent failure -- the
  protocol bump to 24 means every existing agent needs that one
  re-deploy before it can self-update thereafter. Enrolling a host is now
  a single copy-paste line for either platform: the enrollment banner
  shows a **Linux** one-liner (`curl -fsSL <cp>/install.sh | sudo sh -s
  -- --enrollment-token <token>`) and a **Windows** one-liner (an
  elevated-PowerShell `scriptblock` over `<cp>/install.ps1`), both
  targeting new public, secret-free bootstrap scripts the control plane
  serves at `/install.sh` and `/install.ps1`; the manual download-and-run
  steps for each platform are still one click away. See
  `crates/agent/README.md`.
- **Sepulchre: storage and file-sharing connectivity**, a new Arsenal
  under Operate providing a shared connection layer -- SFTP, SMB/CIFS,
  and allowlisted local paths -- that other Arsenals consume instead of
  each building its own SFTP/SMB client and credential handling.
  Reliquary's native backups can now write directly to a Sepulchre
  connection -- picked per manual run from a Destination dropdown, or
  configured as the scheduled loop's own fixed destination -- verified
  live against a real connection (the archive was confirmed to land in
  that connection's own directory, not just via a success message).
  Reading a backup back from a Sepulchre connection (download/verify/
  restore) is a documented, deliberate gap for now -- refused with a
  clear message rather than failing confusingly; see
  docs/reliquary-backups.md's "Sepulchre-backed destinations" section. A
  connection's *protocol* (SFTP/SMB/local),
  *access method* (native client, mount, rsync-over-ssh, diagnostic
  client -- the control plane itself never performs a kernel mount), and
  *role* (backup destination, file transfer, remote storage, other) are
  three independent, many-to-many concepts, so a consumer always asks
  for a connection by role and capability, never by protocol. Every
  capability (read/list/write/delete) is only ever marked verified by an
  actual passing validation check, never left stale. Secrets (passwords,
  SSH keys) are Sepulchre's own -- encrypted at rest with the same
  `ENCRYPTION_KEY`-based mechanism Panopticon's switch credentials
  already use, write-only in every form -- not Cryptkeeper's, which
  remains a host-side security-inspection Arsenal with no credential
  vault. SFTP host-key verification is mandatory and pinned (a later
  mismatch is a hard failure, never a silent re-pin); host-side
  provisioning (SFTP chroot accounts, Samba shares, mount units) only
  ever touches a Sepulchre-owned drop-in config file, validates before
  every reload, and rolls back automatically on failure. A host page
  wizard (`/arsenals/sepulchre/hosts/:id`) provisions an SFTP chroot
  share or an SMB share end to end -- account creation, a control-plane
  keypair generated and installed as the account's authorized key (SFTP)
  or a Samba service user (SMB), the config drop-in applied, and the
  matching Sepulchre connection created and automatically validated, all
  in one step -- plus creating and removing a CIFS mount backed by an
  existing SMB connection. Verified end to end against real standalone
  SFTP/SMB servers and a real connected managed host (a disposable,
  systemd-enabled container, never the control plane's own host), which
  is also how a `smbclient` NT_STATUS-code gap in `error_kind` mapping,
  an SFTP chroot's base path colliding with `trim_end_matches`, an SMB
  share directory created root-owned (blocking the very account meant to
  write to it), a systemd mount-unit name that didn't escape a literal
  hyphen, and (once Reliquary was wired to it) `LocalBackend::ensure_dir`
  rejecting the empty-path call every Sepulchre-backed write makes first
  -- were all actually caught and fixed. See
  [ARCHITECTURE.md](ARCHITECTURE.md#sepulchre-storage-connectivity) and
  [docs/sepulchre.md](docs/sepulchre.md) for the full picture, including
  what's deliberately deferred (a control-plane rsync method, SSHFS
  mounts of an SFTP connection, and reading a backup back from a
  Sepulchre-backed destination).
- **Custom roles with delegated sub-roles**: an admin holding
  `roles.manage` (Super Admin, or anyone a Super Admin grants it to) can
  now create custom sub-roles nested under any role, up to 3 levels deep
  (e.g. Network Admin -> Network Tech). A sub-role's permissions and
  dashboard arsenals are always a subset of its parent's, computed fresh
  on every check rather than cached -- if a parent role loses a
  permission, every descendant loses it immediately, with no stale
  grants anywhere. A creator can only grant permissions they currently
  hold themselves; Super Admin can grant anything. Delegated
  role-management is scoped to your own subtree -- a Network Admin can
  manage roles descending from Network Admin, never a role under a
  different parent -- and nobody can edit their own role's permissions
  or assign a role outside their own delegated authority, enforced
  server-side on every request, not just hidden in the UI. The Add/Edit
  User flow gets a role picker restricted to what the admin may actually
  assign. Deleting a role with users or child roles still assigned is
  blocked with a clear error rather than silently reassigning them.
  System roles (Super Admin, System Admin, Network Admin, Security/OPSEC
  Admin, Regular User) are unchanged -- still can't be renamed or
  deleted, and existing users and roles keep working exactly as before.
  See [ARCHITECTURE.md](ARCHITECTURE.md#delegated-custom-roles-github-issue-8)
  for the full delegation model.
- **Macros for Grimoire scheduled tasks**: save a scheduled-task ("cron
  job") template's job name, schedule, run-as user, and command as a
  reusable macro instead of retyping it on every host. "Save as Macro"
  sits next to the normal "Set Scheduled Task" submit button on the same
  form; "Load" on any saved macro refills the form from it. A macro is
  either Personal (visible only to its owner) or scoped to one of the
  owner's roles (visible to, and usable by, every other member of that
  role -- handy for a small team sharing the same job templates). Only
  the owner, or an account with the new `macros.manage_all` permission,
  can edit or delete a macro. Reuses the existing role system end to end
  (no new "team" concept invented) -- see
  [ARCHITECTURE.md](ARCHITECTURE.md#authorization-rbac).
- **Macros for SNMP community strings**: Panopticon's "add managed
  switch" form gets the same macro treatment -- a "Community String
  Macros" list with a "Load" link per saved macro refills the community
  string field, and "Save Community String as Macro" (next to "Add
  switch") saves whatever's currently typed without needing a switch
  added first. Personal vs. role scoping, and edit/delete permissions,
  work exactly like the scheduled-task macros above -- the two share the
  same underlying `macros` table and access-control rule, just a
  different payload. Macros can also be created and managed directly from
  the Account page (`/account`), independent of adding a switch. Every
  community-string macro's value is encrypted at rest with the same
  `ENCRYPTION_KEY` already used for a switch's own stored SNMP
  credentials.
- **SNMP version selection for managed switches**: adding or editing a
  switch under Panopticon's managed-switches page now lets you pick SNMP
  v1, v2c, or v3 instead of always polling v2c. v3 adds its own fields
  (security username, security level, auth protocol/password, privacy
  protocol/password), shown or hidden based on the selected version and
  security level the same CSS-only way the SSH deploy credentials form
  already toggles password vs. private-key fields -- no client-side
  JavaScript. v3's auth/privacy passwords are encrypted at rest with the
  same `ENCRYPTION_KEY` (AES-256-GCM) already used for the v1/v2c
  community string. Every switch added before this feature existed keeps
  polling over v2c unmodified -- the new `snmp_version` column defaults to
  `'v2c'` for every pre-existing row. See
  [ARCHITECTURE.md](ARCHITECTURE.md#background-tasks) for how the poll
  itself picks credentials per-switch.
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
- **Reliquary native backups**: the control plane can now back up and
  restore its own database and configuration, from `/arsenals/reliquary/backups`
  (`backups.view`/`backups.create`/`backups.restore`, already-existing
  permissions this feature now actually uses). A backup selects any of
  Database (a `mariadb-dump` logical dump -- routines, triggers, events,
  hex-encoded blobs, utf8mb4), Configuration (a redacted snapshot of this
  process's own environment), Encryption keys (opt-in, always forces
  encryption), and Audit logs (whether the `audit_log` table's rows are
  included in the dump, on by default), sealed into one compressed
  (`tar`+`zstd`), checksummed, optionally AES-256-GCM-encrypted (streaming,
  Argon2id-derived passphrase, 512KB chunks) archive with a versioned
  `manifest.json`. Quick verify checks integrity and manifest sanity; deep
  verify (scratch-database restore) is a documented, flagged gap, not a
  silent one. Restore is a dry-run-preview-then-typed-confirmation flow
  that refuses an unverified backup unless explicitly overridden, takes an
  automatic safety backup first, and runs under a new maintenance-mode
  middleware that blocks the rest of the app for its short duration.
  Backups land in a dedicated `abyssal_backups` Docker volume, deliberately
  separate from the database's own volume, with an explicit off-host-
  storage warning in the UI (that volume is still local to this Docker
  host). Optional scheduling (off by default, unencrypted, since nobody's
  present to supply a passphrase) and retention (keep-last-N and/or
  keep-X-days, never pruning the only remaining verified backup) are
  configurable from the same page. A new disaster-recovery CLI subcommand
  (`docker compose run --rm app reliquary backup list|verify|restore`)
  works against a totally fresh install -- empty database, brand-new
  containers, no web UI or session required. See
  [ARCHITECTURE.md](ARCHITECTURE.md#reliquary-native-backups-github-issue-9)
  and [docs/reliquary-backups.md](docs/reliquary-backups.md) for the full
  picture. A genuinely off-host destination (an SFTP/SMB server or an
  allowlisted local path via a Sepulchre connection, not just S3/cloud
  storage specifically) was added later in this same changelog, once
  Sepulchre existed -- see that entry above for what's deferred there
  (reading a backup back from one) versus what's deferred here (deep
  verify, encrypted unattended backups).

### Fixed

- **Super Admin could silently fall out of "no ceiling" status, locking
  itself out of the Roles page entirely.** `has_no_ceiling()` (the
  computed stand-in for "this is Super Admin," deliberately not a
  hard-coded role-name check) requires holding *every* known permission;
  startup seeding only ever set a role's permission set the first time
  that role was created, so Super Admin's stored grants silently fell
  behind `Permission::ALL` every time a later release added a new
  permission (most recently, Sepulchre's two). One missing permission was
  enough to flip Super Admin to a normal, ceilinged user for role
  management purposes -- unable to edit *any* role's permissions,
  including its own, since only a no-ceiling user may edit a system role
  at all. Fixed by giving Super Admin specifically different seeding
  treatment: its stored grants are unioned with `Permission::ALL` on
  every startup, not just its first creation (every other system role
  keeps the original behavior, since an admin deliberately narrowing one
  of those down is legitimate). Takes effect on the control plane's next
  restart.
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
- The scan and deploy progress pages' `<meta http-equiv="refresh">`
  fallback could keep firing full-page reloads even with JavaScript
  running and successfully polling in the background -- removing that
  `<meta>` tag from the page after the browser has already parsed and
  armed it doesn't reliably cancel the reload in every browser. Moved the
  fallback into `<noscript>` instead, so a JS-enabled browser never parses
  or arms it in the first place.
- Re-enrolling the same machine over SSH (retrying a failed deploy, or
  reinstalling the agent locally after wiping its credentials) failed
  with a bare 500 -- uninstalling the agent on a host never deregisters
  its row here, and host names are unique, so the second enrollment
  attempt collided with the first. Re-enrolling under a name that's
  already on record now either supersedes a disconnected (stale) host
  automatically or returns a clear "already connected" error, instead of
  an opaque server error.
- Panopticon's discovery scan now runs nmap at `-T4` ("Aggressive")
  instead of the default `-T3` -- nmap's own recommendation for a fast,
  reliable network you control. Without it, a subnet with many silent or
  unreachable addresses (the common case for anything bigger than a
  small, fully-populated LAN segment) spent most of its time waiting out
  the much more conservative default per-host timeout, which is what made
  the scan progress bar sit still for long stretches instead of moving
  steadily.
- Extended how long a deploy waits for the agent to check in after a
  successful install (60s -> 150s) -- the agent's own reconnect backoff
  (1s/2s/4s/8s/16s/32s/60s/...) means a rough first connection attempt can
  genuinely take over a minute before the next retry even fires, and the
  shorter window risked reporting a host as never having checked in when
  it was actually about to connect fine on its own.
- Found the actual root cause of the SSH deploy check-in failures above:
  the install command ran `abyssal-agent install` straight out of its
  temporary download directory and then deleted that same directory as
  its own cleanup step. Since the agent's installer writes the systemd
  service to run from wherever it was executed, this left every deploy's
  service pointing at a binary that no longer existed -- confirmed
  against a real deploy as systemd's `203/EXEC`, and unrelated to network
  access or timing. The install now copies the binary to
  `/opt/abyssal-agent` first and installs from there, so the service
  keeps working after cleanup and across reboots.

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
- Reliquary's native backups (GitHub issue #9) have no deep verify
  (scratch-database restore + `CHECK TABLE` + row-count comparison), only
  quick verify (checksum/manifest/readability); no remote/cloud storage
  destination yet, though `StorageDestination`/`BackupProvider` are traits
  specifically so one can be added later without a refactor; and scheduled/
  unattended backups are always unencrypted, since there's nobody present
  to supply a passphrase. See
  [docs/reliquary-backups.md](docs/reliquary-backups.md).
