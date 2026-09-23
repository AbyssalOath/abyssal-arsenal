# Abyssal Arsenal

[![CI](https://github.com/AbyssalOath/abyssal-arsenal/actions/workflows/ci.yml/badge.svg)](https://github.com/AbyssalOath/abyssal-arsenal/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AbyssalOath/abyssal-arsenal)](https://github.com/AbyssalOath/abyssal-arsenal/releases/latest)

A self-hosted IT/sysadmin operations platform for Linux environments, written
in Rust. Individual administrative capabilities ("arsenals" -- networking,
security hardening, storage, backups, incident response, and so on) are
modular and sit on top of a shared core: local authentication, role-based
access control, append-only audit logging, and notifications.

Abyssal Arsenal is a **control plane**, not the system it manages. Real
sysadmin work happens on enrolled Linux hosts running the companion
`abyssal-agent` binary, which connects out to the control plane over an
authenticated WebSocket:

```
        Abyssal Arsenal (control plane)
     Auth . RBAC . Audit . Notifications . Web UI
                       |
            authenticated connection
                       |
        +--------------+--------------+
        v              v              v
   Linux Host A    Linux Host B    Linux Host C
  abyssal-agent    abyssal-agent   abyssal-agent
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit together.

## Arsenals

All 23 arsenals are fully implemented -- each gated by its own
permission(s) and, where the blast radius warrants it, a second layer of
admin opt-in on top of the usual confirmation. Grouped by function:

**Operate**

| Arsenal | Covers |
| --- | --- |
| Apothecary | Linux package management (apt/dnf/yum/pacman/zypper, auto-detected) |
| Cystoolbox | General Linux administration and misc sysadmin utilities |
| Defleshing | System cleanup and routine maintenance |
| Grimoire | Configuration management and repeatable system configuration |
| Incarnation | Application and service deployment/provisioning |
| Necrolink | Network interfaces, routes, DNS, sockets, connectivity diagnostics |
| Necropolis | Container and container-runtime administration |
| Parish | User, group, account, and access management |
| Reanimation | Process and service management |

**Observe**

| Arsenal | Covers |
| --- | --- |
| Mortiscope | System health and resource monitoring |
| Necropsy | Hardware inspection and diagnostics |
| Obituary | Historical logging and audit record management |
| Panopticon | Network discovery, device inventory, and topology mapping -- runs from the control plane itself, not a host agent |
| Vivisection | Performance analysis, profiling, and system tuning |

**Defend**

| Arsenal | Covers |
| --- | --- |
| Cadavault | Security configuration, hardening, and defensive operations |
| Cryptkeeper | Secrets, credentials, certificates, keys, sensitive configuration |
| Inquest | Incident containment and remediation (IP blocklisting, file quarantine, full host isolation) |
| Postmortem | Forensic examination after failures or suspected compromise |
| Thanatos | Security telemetry collection, threat detection, event correlation, and alerting |

**Preserve / Recover**

| Arsenal | Covers |
| --- | --- |
| Catacomb | Filesystem inspection, maintenance, and repair |
| Ossuary | Disk, partition, LVM, RAID, and storage management |
| Reliquary | Backup creation, verification, and restoration |
| Resurrection | Disaster recovery and restoration of failed systems |

Plus Apotheosis, time-boxed sudo elevation for managed hosts (not an
arsenal of its own -- a cross-cutting mechanism every host-dispatched
arsenal above can use). See [ARCHITECTURE.md](ARCHITECTURE.md) for how an
arsenal is wired up and [CHANGELOG.md](CHANGELOG.md) for the detail behind
each one's capabilities.

**Macros**: save a value or form you'd otherwise retype as a reusable
macro. Grimoire's scheduled-task ("cron job") form lets you save a job's
name/schedule/user/command; Panopticon's "add managed switch" form lets
you save an SNMP community string (also manageable directly from your
own Account page). Either way it's "Save as Macro" next to the
normal submit button, and "Load" on any saved macro to refill the form. A
macro is either **Personal** (visible only to you) or scoped to one of
your **roles** (visible to, and usable by, every other member of that
role too -- handy for a small team that shares the same templates or
credentials). Only the macro's owner (or an account with the
`macros.manage_all` permission) can edit or delete it; anyone in a role a
role-scoped macro is shared with can use it.

## Quickstart

```bash
git clone https://github.com/AbyssalOath/abyssal-arsenal.git
cd abyssal-arsenal
git checkout v0.1.2   # pin to the latest stable release; omit to run main
./install.sh
```

`install.sh` generates secrets, asks a handful of questions it can't infer
(host port, reverse proxy setup, optional SMTP), and brings the stack up with
Docker Compose. Once it's running:

1. Visit the app and go to `/setup` to create the first administrator
   account -- there's no default password, the account doesn't exist until
   you create it there.
2. Public self-registration stays disabled by default; toggle it later from
   `/admin/settings` if you want it.
3. To manage a Linux host, go to `/admin/hosts`, generate an enrollment
   token, then download `abyssal-agent` from the
   [latest release](https://github.com/AbyssalOath/abyssal-arsenal/releases/latest)
   onto that host and run `sudo ./abyssal-agent` -- with no arguments it
   prompts for the control plane URL and the token, then enrolls and
   installs itself as a systemd service in one step. See
   [`crates/agent/README.md`](crates/agent/README.md) for the full
   walkthrough and non-interactive/scripted install options.
4. Already have Panopticon's network discovery finding hosts you want to
   manage? Run a discovery scan from `/arsenals/panopticon`, then use "Add
   Hosts" on the results to deploy the agent to several of them over SSH at
   once, instead of repeating step 3 by hand for each one -- see
   [ARCHITECTURE.md](ARCHITECTURE.md#deploying-agents-over-ssh-quick-add-host-from-network-scan)
   for how credentials and host-key trust are handled.

The dashboard shows this build's version at all times and checks GitHub for
a newer tagged release every few hours; if one exists, the notice turns into
a linked, pulsing alert pointing at the release page.

## Releases and branches

- **`main`** is the active development branch. It moves fast and is where
  every change lands first -- clone or pull it if you want to build from
  source, contribute, or track development closely. It is not guaranteed to
  be at a stable checkpoint at any given commit.
- **Tagged releases** (`vX.Y.Z`, e.g. `v0.1.0`) are stable checkpoints cut
  from `main` at a point considered good enough to run. Each tag has a
  matching [GitHub release](https://github.com/AbyssalOath/abyssal-arsenal/releases)
  with prebuilt `abyssal-arsenal` (control-plane) and `abyssal-agent`
  binaries attached, and a matching container image published to GHCR (see
  `.github/workflows/release.yml` and `docker-publish.yml`).
- **For a production or otherwise long-lived deployment**, check out the
  latest tag (`git checkout v0.1.2`) rather than tracking `main`. Pull `main`
  only if you specifically want unreleased changes and accept the
  reduced stability that comes with it.
- **`VERSION`** at the repository root is the single source of truth for
  which release a given checkout is; the dashboard's update notice compares
  it against GitHub's latest release automatically.

## Development

This is a Cargo workspace. Useful commands:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

`scripts/migrate.sh`, `scripts/backup-db.sh`, and `scripts/restore-db.sh`
operate against the Compose-managed MariaDB instance (bound to
`127.0.0.1:3306`) -- see the comments in each for what they expect.

See [TESTING.md](TESTING.md) for what's actually covered by the test suite
today and [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Repository layout

- `crates/core`, `database`, `auth`, `rbac`, `audit`, `notifications`,
  `execution`, `modules` -- the shared control-plane foundation.
- `crates/hosts`, `agent-protocol` -- the host registry and the wire protocol
  shared between the control plane and `abyssal-agent`.
- `crates/web`, `crates/app` -- the Axum web/API layer and the control-plane
  binary.
- `crates/agent` -- the standalone binary that runs on managed hosts.
- `crates/arsenals/*` -- one crate per administrative domain (`cystoolbox`,
  `cadavault`, `necrolink`, ...). See the "Arsenals" section above for the
  full list and [CHANGELOG.md](CHANGELOG.md) for the detail behind what
  each one actually does.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) -- how the control plane, agents, and
  arsenals fit together.
- [CONTRIBUTING.md](CONTRIBUTING.md) -- dev setup, conventions, and how to
  add a new capability.
- [SECURITY.md](SECURITY.md) -- reporting a vulnerability and the security
  model this platform relies on.
- [TESTING.md](TESTING.md) -- what's tested, what isn't yet, and how to
  verify a change manually.
- [CHANGELOG.md](CHANGELOG.md) -- what's shipped so far.

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
See [LICENSE](LICENSE).
