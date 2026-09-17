# Contributing

Thanks for taking an interest in Abyssal Arsenal. This is a young project
with a specific architectural shape (see [ARCHITECTURE.md](ARCHITECTURE.md)
before making structural changes), so please read this file before opening
a pull request.

## Development setup

You need:

- Rust (stable toolchain; `rustup` recommended)
- Docker and the Docker Compose plugin
- `openssl` (only for `install.sh`'s secret generation)

Clone the repo and build the workspace:

```bash
git clone https://github.com/AbyssalOath/abyssal-arsenal.git
cd abyssal-arsenal
cargo build --workspace
```

To run against a real database locally, either use the full Compose stack
(`./install.sh`, or `docker compose up -d`) or point `DATABASE_URL` in a
local `.env` at your own MariaDB instance and run
`cargo run -p abyssal-arsenal`.

Before opening a PR, run:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All three are enforced in CI (`.github/workflows/ci.yml`) and a PR that
fails any of them will not be merged as-is.

## Code conventions

- **No unnecessary comments.** Code should be self-explanatory through
  naming; a comment is only worth adding when it explains a non-obvious
  *why* (a hidden constraint, a subtle invariant, a workaround for a
  specific bug), never a restatement of *what* the code does.
- **No unnecessary abstraction.** Don't introduce a trait, generic
  parameter, or configuration option for a single call site or a
  hypothetical future need. Three similar lines beat a premature
  abstraction.
- **Fail closed.** Any authorization check that can't be resolved (a
  database error, a missing session) must be treated as denied. This is a
  hard rule in `crates/rbac` and anywhere else permissions are checked --
  see [ARCHITECTURE.md](ARCHITECTURE.md#authorization-rbac).
- **Never build a shell command from a request-derived string.** Use
  explicit argument vectors (`tokio::process::Command::new(...).arg(...)`,
  not a formatted string passed to a shell). See
  `crates/execution/src/process.rs` for the existing pattern.
- **Every state-changing route needs its own permission check and its own
  audit record.** There is no blanket middleware that handles this for
  you, on purpose -- see `crates/web/src/routes/*.rs` for the existing
  per-handler pattern (`abyssal_rbac::ensure(...)` at the top of the
  handler, `abyssal_audit::record(...)` after the mutation).
- Match the existing style in the crate you're touching (`repo::` free
  functions in `crates/database`, `WebError`/`WebResult` in `crates/web`,
  and so on) rather than introducing a new pattern for the same kind of
  problem.

## Adding a new arsenal capability

Arsenals are currently mostly metadata-only placeholder pages (see
[CHANGELOG.md](CHANGELOG.md) for current status). To give one a real,
host-affecting capability:

1. Add a variant to `AgentOperation` in `crates/agent-protocol/src/lib.rs`.
2. Implement it in `crates/agent/src/ops.rs`. Keep it read-only unless
   there's a specific, reviewed reason not to, and if it can be
   destructive, make sure the caller has to explicitly confirm (see
   `OperationKind::Destructive` in `crates/execution`).
3. Wire a route in the relevant arsenal's admin page (or a new one) that
   calls `Executor::execute_on_host()` with the right `Permission` and
   `OperationKind`.
4. If it needs a new permission, add it to `Permission` in
   `crates/core/src/permission.rs` and seed it for the roles that should
   have it in `crates/database/src/seed.rs`.

## Adding a new arsenal (module) from scratch

A new arsenal is a small crate implementing the `Arsenal` trait
(`crates/modules/src/arsenal.rs`):

1. Create `crates/arsenals/<name>/` with a `Cargo.toml` depending on
   `abyssal-core` and `abyssal-modules`, following any existing arsenal
   crate as a template.
2. Add the crate to the workspace `Cargo.toml` (`members` and
   `workspace.dependencies`).
3. Register it in `crates/app/src/arsenals.rs`.

That's the whole integration surface -- `app` and `web` never need to know
about a specific arsenal beyond iterating `ModuleRegistry`.

## Testing expectations

See [TESTING.md](TESTING.md) for what's covered and how to add tests for
new logic. In short: pure unit tests for anything with real logic (permission
checks, token hashing, executor behavior, protocol handling), no test
database required since the persistence layer uses runtime-checked queries.

## Commit and PR style

- Keep commits focused; a commit message should explain *why*, not just
  restate the diff.
- Update [CHANGELOG.md](CHANGELOG.md) under "Unreleased" for any
  user-visible change.
- Reference the relevant section of [ARCHITECTURE.md](ARCHITECTURE.md) in
  your PR description if you're changing something structural, so
  reviewers know whether that document needs updating too.

## License of contributions

Abyssal Arsenal is licensed under the GNU Affero General Public License
v3.0 or later (AGPL-3.0-or-later); see [LICENSE](LICENSE). By submitting a
contribution, you agree it is licensed under the same terms.

## Reporting security issues

Do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for how to report one privately.
