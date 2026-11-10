# Host OS awareness (roadmap)

**Status:** M1–M5 built on `Dev` (uncommitted); M6 (screenshots, per-arsenal
docs, release) remains. It comes before Windows push deploy's M3, since push
deploy will make Windows hosts much easier to add.

The control plane already knows each host's OS: the agent reports it when
it connects (`routes/agent.rs:412`), and it's stored in `hosts.os`
(`"linux"`, `"windows"`, `"macos"`). The host pickers show it. But almost
nothing *acts* on it. Most of the 27 arsenals are Linux-only, a few are
Windows-only, and several are mixed, yet every arsenal offers every action to
every host. A Linux-only action sent to a Windows host fails on the host,
usually with something unhelpful ("failed to run lscpu", "No systemd on this
host"), and a few even report success ("No thermal sensors available").

This plan makes the control plane tell hosts apart by OS, and stop offering,
and refuse, what a host's OS can't run.

## Decisions

Settled with the owner before M1, as proposed.

| Question | Decision |
| --- | --- |
| Where does "which OS does this support" live? | **On the operation, as data.** `AgentOperation::platforms()` in `abyssal-agent-protocol`, an exhaustive `match` with no catch-all, like `min_protocol()`, so a new operation can't be added without declaring it. Arsenals get `Arsenal::platforms()` next to `category()`. |
| Hide, or show greyed out? | **Hide** unsupported arsenals and actions, as asked. Where a whole list goes missing (a host picker), say why in one line ("3 Windows hosts not shown: Catacomb is Linux-only"), so it doesn't look like a bug. |
| Is hiding enough? | **No. The server refuses too.** `HostConnectionRegistry::dispatch` refuses an operation the host's OS can't run, the same way it already refuses an agent that's too old or a guarded action on the control plane's own server. Nothing is sent to the host. Hiding is for convenience; the refusal is the guarantee. |
| Which OS value counts? | **The one the live connection reported,** passed to `register` alongside the protocol version. `hosts.os` is used for offline hosts (pickers, menus). |
| A host with no OS on record? | **Treated as unknown: everything is shown and nothing is refused,** which is today's behaviour. This only applies to agents too old to report an OS. |
| macOS? | **Treated as unknown for now** (see *Open questions*). No macOS support has been analyzed. |

## Goals

- A Windows host is never offered a Linux-only arsenal or action, and the
  reverse.
- Sending one anyway (a typed URL, a stale page, a workflow button) gets a
  clear "not supported on Windows" message from the control plane, and
  nothing is sent to the host.
- Background sweeps and schedules skip hosts that can't run them, instead
  of logging a failure for every Windows host every cycle.
- One table of truth that a new operation or arsenal must fill in, so this
  doesn't drift back.

## Non-goals

- Porting Linux-only arsenals to Windows (or the reverse). This only stops
  offering what doesn't work. Ports are their own roadmap items.
- Per-distribution differences (apt vs dnf, systemd vs not). The agent
  already handles those at run time.
- macOS support.

## The audit

Every agent operation and arsenal, checked against the agent's code. "How it
fails today" is what a Windows host gets for a Linux-only action (or the
reverse).

### By arsenal

| Arsenal | Runs on | How unsupported calls fail today |
| --- | --- | --- |
| Apothecary | Linux | package backend not found |
| Catacomb | Linux | command not found |
| Cryptkeeper | Linux | runtime errors (`/etc/ssh` missing, and so on) |
| Defleshing | Linux | command not found, or Windows `find.exe` |
| Grimoire | Linux | runtime error |
| Incarnation | Linux | "No systemd on this host" |
| Necrolink | Linux | command not found, or bad `ping` arguments |
| Necropolis | Linux (in practice) | no container runtime detected |
| Necropsy | Linux | command not found |
| Obituary | Linux | runtime error |
| Ossuary | Linux | command not found |
| Postmortem | Linux | runtime error |
| Reliquary | Linux | runtime error |
| Scourge | Linux | explicit "not supported on this platform"; its sweep already skips non-Linux hosts (`scourge_ops.rs:342`) |
| Sepulchre | Linux | runtime error |
| Vivisection | Linux | runtime error |
| Gravekeeper | Windows | explicit; its DC picker already lists only Windows hosts |
| Haruspex | Windows | explicit, but **its picker lists every connected host** (`routes/haruspex.rs:63`) |
| Inquest | Both | each action has a Linux and a Windows version |
| Panopticon | Both | (scans run on the control plane; the deploy form already picks Linux or Windows) |
| Cadavault | Mixed | see below |
| Cystoolbox | Mixed | see below |
| Mortiscope | Mixed | see below |
| Parish | Mixed | see below |
| Reanimation | Mixed | see below |
| Resurrection | Mixed | see below |
| Thanatos | Mixed | see below |

### Mixed arsenals

| Arsenal | Both | Linux only | Windows only |
| --- | --- | --- | --- |
| Cadavault | posture report (`PostureFacts`), listening ports, recent auth log | SSH audit, harden and clear; sysctl posture; account policy; MAC; automatic updates; every firewall action | – |
| Cystoolbox | system info, resource usage, logged-in users | set hostname, reboot | – |
| Mortiscope | memory detail, CPU utilization, failed services | load average, top processes by CPU/memory, disk I/O, network throughput, thermal sensors, memory pressure | – |
| Parish | lock and unlock user | list users/groups, user detail, create/delete user/group, add/remove group member | – |
| Reanimation | send signal (only KILL and TERM on Windows) | list processes, process detail, renice, open files, limits, zombie report, I/O priority, OOM score, signal by name | – |
| Resurrection | disk space critical, failed units/services list, recover | previous boot errors, running state, reload systemd, reset failed units, read-only filesystems, fstab check, remount read-write | – |
| Thanatos | security event scan, isolate host, quarantine file, lock account | – | real-time event stream (turning it on) |

### Outside the arsenals

- **Elevation** (`Elevate`) always runs `sudo -S -v` (`crates/agent/src/elevation.rs:158`).
  The Windows agent runs as SYSTEM and mostly ignores elevation, so the
  elevation controls mean nothing on a Windows host.
- **Already OS-aware, and kept as is:** the dashboard's failed-services
  wording, the agent build picked for self-update (`routes/hosts.rs:879`),
  the uninstall command (`routes/hosts.rs:1428`), Inquest's and Thanatos's
  per-OS path and name checks, and Resurrection's "failed services" label.

### Settled in M1 (the audit couldn't)

- [x] Necropolis on Windows with Docker Desktop: unsupported (Linux only).
      A Windows branch would be its own port.
- [x] `which` from Git for Windows on `PATH`: moot. The agent now refuses
      every Linux-only operation before any of its code runs, so no
      detection runs on Windows.
- [x] Cadavault posture fix links on Windows: none render. Every Windows
      check in `crates/posture/src/windows.rs` has `fix: None`.
- [x] `ClearSepulchreConfig` has no sender in the web crate. It stays in the
      protocol (removing a variant is a wire change) and is Linux-only.

## Order of work

Work happens on `Dev`, one milestone at a time, each finished and checked
before the next.

| # | Milestone | Size | Agent change? |
| --- | --- | --- | --- |
| M1 | Platform data: `platforms()` on operations and arsenals, host OS parsing | Small–medium | No |
| M2 | Refuse at dispatch; sweeps skip unsupported hosts | Small–medium | No |
| M3 | Arsenal level: pickers, switchers, menu, dashboard, workflow buttons | Medium | No |
| M4 | Action level: hide unsupported actions in the mixed arsenals, and elevation on Windows | Medium | No |
| M5 | Agent: Linux-only operations refuse explicitly on Windows | Medium | Yes (no protocol bump) |
| M6 | Screenshots, docs, release | Small | – |

Why this order:

- **M1 first** because everything else reads from it, and its tests make
  every operation declare a platform.
- **M2 before any UI** so hiding is never the only thing stopping a bad
  request. It's also small and fixes the worst of it (silent wrong answers,
  failures on the host) on its own.
- **M3 before M4** because hiding whole arsenals is the biggest visible
  change for the least work: 18 of the 27 are one OS only.
- **M5 last** because the control plane already refuses by then. M5 covers
  older control planes and anything that reaches the agent another way, and
  fixes the operations that report success when they didn't run.

---

## M1. Platform data

- [ ] `abyssal-agent-protocol`: a `Platforms` type (Linux, Windows, both),
      and `AgentOperation::platforms()`, an exhaustive `match` with no `_`
      arm, filled in from the audit. `ThanatosStream` depends on its
      `enabled` field (turning it off works anywhere). `SendSignal` is both.
- [ ] A `HostOs` type parsed from `hosts.os` / the reported value: Linux,
      Windows or unknown (macOS and anything else count as unknown for now),
      with `Platforms::allows(HostOs)`. Unknown is always allowed.
- [ ] `Arsenal::platforms()` in `crates/modules/src/arsenal.rs`, filled in
      for all 27 arsenals. A mixed arsenal is "both"; its individual actions
      are filtered in M4.
- [ ] Tests:
  - every operation has a platform (the exhaustive `match` enforces it; a
    test pins the audit's answers so a change is deliberate);
  - for each arsenal, every operation its routes send is allowed on at
    least one of the arsenal's platforms (a table test listing each
    arsenal's operations);
  - `HostOs` parsing, including missing and unknown values.
- [ ] Settle the four questions under *Settled in M1*.

## M2. Refuse at dispatch

- [ ] `HostConnectionRegistry::register` takes the OS the agent reported,
      next to the protocol version (`routes/agent.rs`).
- [ ] `dispatch` refuses an operation whose `platforms()` doesn't allow the
      host's OS: a new `DispatchError::UnsupportedPlatform { operation, os }`
      whose message names both and ends "Nothing was sent to the host.", like
      `AgentTooOld`. It's checked before the version check, since a newer
      agent wouldn't help.
- [ ] `HostConnectionRegistry::supports(host_id, &operation)` for the UI,
      the way `guard()` already lets pages grey out control-plane-guarded
      actions.
- [ ] Background work skips hosts it can't run on, quietly, using the same
      check: the Mortiscope sweep, the health check's per-host operations,
      Cadavault's scheduled posture runs, and anything else that loops over
      the fleet. Scourge's hand-written skip (`scourge_ops.rs:342`) moves to
      the shared check.
- [ ] Tests: dispatch refuses a Linux-only operation to a Windows connection
      and a Windows-only one to a Linux connection, sends nothing in either
      case, and allows everything for an unknown OS.

## M3. Arsenal level

- [ ] **Arsenal host pickers** (`host_picker.rs`) list only hosts the
      arsenal supports, with a one-line note for the hosts left out.
      Haruspex's own picker is fixed the same way.
- [ ] **The breadcrumb host switcher** lists only hosts that support the
      current arsenal.
- [ ] **An arsenal page for an unsupported host** (a typed URL, a stale
      link) shows "Catacomb doesn't support Windows hosts" with a link back
      to the picker, instead of a page of actions that would all fail.
- [ ] **The Arsenals menu and the dashboard tiles,** when a host is
      selected in the host switcher (`host_context`), hide arsenals that
      don't support it. With no host selected, they're unchanged.
- [ ] **Workflow suggestion buttons** (the workflow registry) never point a
      host at an arsenal that doesn't support it.
- [ ] Tests: template tests for each of the above with a Linux, a Windows
      and an unknown-OS host.

## M4. Action level

- [ ] Each mixed arsenal's host page hides the actions its host's OS can't
      run, using `supports()` from M2: Cadavault, Cystoolbox, Mortiscope,
      Parish, Reanimation, Resurrection and Thanatos. Where a whole card or
      section ends up empty, the card goes too.
- [ ] Cadavault's posture page: no Linux-only fix links on a Windows host
      (confirm in M1, enforce here).
- [ ] Reanimation on Windows: only KILL and TERM are offered for a signal.
- [ ] **Elevation on Windows hosts:** hide the elevate controls and the
      elevated badge, since the agent already runs as SYSTEM. Check
      `Elevate` on a Windows agent first (see *Open questions*).
- [ ] Tests: per mixed arsenal, a Windows host page has none of the
      Linux-only actions and a Linux host page has none of the Windows-only
      ones.

## M5. Agent: refuse explicitly

The control plane already refuses by this point. This makes the agent agree,
for older control planes and as defense in depth.

- [ ] Every Linux-only operation returns `platform_unsupported()` on
      Windows instead of running a Linux command, one `cfg` arm per module,
      the way Scourge already does.
- [ ] `ThermalSensors` and `MemoryPressure` stop returning success on
      Windows.
- [ ] `SetIoPriority`, `SetOomScoreAdj` and `SignalByName` use
      `platform_unsupported()` instead of their own messages.
- [ ] A test (Windows target) that every operation `platforms()` calls
      Linux-only returns the unsupported error, so the agent and the
      control plane can't disagree.

## M6. Screenshots, docs, release

- [ ] Headless screenshot checks of a mixed fleet: the Arsenals menu with a
      Windows host selected, a Linux-only arsenal's picker, and Cadavault's
      host page for each OS, at desktop and phone widths.
- [x] Docs: each arsenal's page in `docs/` states which OS it supports.
      `ARCHITECTURE.md` says where platform support is declared, and that a
      new operation must declare it.
- [ ] CHANGELOG, version bump, `Dev` → `main`, tag.

## Open questions (answered)

- **Hosts with no OS on record:** shown everything, refused nothing (owner's
  choice), rather than treated as Linux.
- **macOS:** treated as unknown until someone tests an agent on a Mac.
- **Elevation on Windows:** `Elevate` runs `sudo` and fails on a Windows
  agent with a run error. The controls are hidden on Windows hosts (M4) and
  the agent now refuses `Elevate` there up front (M5).
- **Dashboard with no host selected:** left alone (owner's choice), so
  Windows-only arsenals stay discoverable on an all-Linux fleet. It filters
  only once a host is selected.

## Progress

- [x] M1 Platform data
- [x] M2 Refuse at dispatch
- [x] M3 Arsenal level
- [x] M4 Action level
- [x] M5 Agent: refuse explicitly
- [ ] M6 Screenshots, docs, release

### As built (M1–M5)

- **M1.** `Platforms` and `HostOs` live in `abyssal-agent-protocol`
  (`platforms.rs`), since the agent depends only on that crate;
  `abyssal-modules` re-exports them for `Arsenal::platforms()`. 34
  operations are `Both`, 25 `Windows` (Gravekeeper, Exchange, Haruspex) and
  190 `Linux`; `ThanatosStream` depends on `enabled`. `Elevate` is Linux
  (it runs `sudo`); `Deescalate` and `ElevationStatus` are `Both`. Arsenals:
  16 Linux, 2 Windows (Gravekeeper, Haruspex), 9 both. The per-arsenal
  "every operation its routes send" table test wasn't written: operations
  can't be built from names in a test without a hand-kept list per arsenal,
  which would be the same table twice. The tests pin a sample of each kind.
- **M2.** `register` takes the reported OS; `dispatch` refuses with
  `UnsupportedPlatform` before the version check; `supports()` includes the
  OS, plus `host_os()`. Sweeps: Scourge's hand-written skip now uses
  `supports()`, and the Mortiscope metrics sweep skips unsupported metrics.
  Health (`FailedServices`), posture and Thanatos already send only
  cross-platform operations.
- **M3.** `host_picker::hosts(state, key)` filters and returns a
  `PickerList` with the "not shown" note; the 24 landing pages only jump to
  the selected host when the arsenal fits it; Postmortem, Scourge and
  Haruspex filter their own lists; the breadcrumb switcher uses
  `BaseCtx::hosts_for`; a GET for an unsupported host's page redirects to
  `/arsenals/<key>?all=1` (`middleware::platform_guard`); the menu and
  dashboard filter by the selected (connected) host, and the dashboard says
  so; `suggested_actions_for` drops unsupported targets.
- **M4.** The mixed host pages carry a `HostPlatform` and hide Linux-only
  forms and cards. Resurrection's triage shows Linux-only checks as "doesn't
  apply" on Windows instead of failing them. Elevation: the agent's
  `Elevate` runs `sudo`, which fails on Windows; the controls are hidden and
  a "Runs as SYSTEM" badge shows instead. No agent change was needed for it.
- **M5.** One check at the top of `ops::run` instead of a `cfg` arm per
  module: anything `platforms()` says this OS can't run returns
  `platform_unsupported()` before any of it runs. That makes the agent and
  the control plane agree by construction; a test in `ops.rs` checks it
  (Linux-only operations on the Windows CI target, Windows-only ones on
  Linux). The Reanimation Windows stubs now use `platform_unsupported()`
  too, though they're no longer reachable.
