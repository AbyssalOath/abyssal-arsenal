# Abyssal Arsenal

[![CI](https://github.com/AbyssalOath/abyssal-arsenal/actions/workflows/ci.yml/badge.svg)](https://github.com/AbyssalOath/abyssal-arsenal/actions/workflows/ci.yml)

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

## Quickstart

```bash
git clone https://github.com/AbyssalOath/abyssal-arsenal.git
cd abyssal-arsenal
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
   token, and run `abyssal-agent` on that host with it (see
   [`crates/agent/README.md`](crates/agent/README.md)).

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
  `cadavault`, `necrolink`, ...). See [ARCHITECTURE.md](ARCHITECTURE.md) for
  what each one covers; most are currently registered with the platform but
  not yet implemented beyond metadata -- that's ongoing work, not an
  oversight. See [CHANGELOG.md](CHANGELOG.md) for what's actually landed.

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
