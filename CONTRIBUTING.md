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

All 23 arsenals have real capabilities today (see
[CHANGELOG.md](CHANGELOG.md) for what each one does); adding a new
operation to an existing one, or extending its scope, follows the same
pattern every one of them was built with. For a host-affecting
capability (the common case -- everything except Panopticon, which is
control-plane-only, see [ARCHITECTURE.md](ARCHITECTURE.md)):

1. Add a variant to `AgentOperation` in `crates/agent-protocol/src/lib.rs`,
   with a doc comment explaining what it does and why it's the risk tier
   it is. Bump `PROTOCOL_VERSION` -- any change here needs it.
2. If the operation takes any value from the wire, add a validator
   function in `crates/agent-protocol/src/lib.rs` (with tests) rather
   than validating only on one side -- the agent is the actual execution
   boundary and should never trust a value just because the control
   plane already checked it. Reuse an existing validator if a suitable
   one already exists (`is_valid_absolute_path`, `is_valid_account_name`,
   and so on) instead of writing a near-duplicate.
3. Implement it in the arsenal's own `crates/agent/src/<name>.rs` module
   and wire it into the match in `crates/agent/src/ops.rs`. Keep it
   read-only unless there's a specific, reviewed reason not to; if it can
   be destructive, make sure the caller has to explicitly confirm (see
   `OperationKind::Destructive` in `crates/execution`). If it needs a
   command with more than one common Linux implementation (a firewall
   backend, an init system, a package manager), detect what's actually
   present rather than assuming one -- see `crates/agent/src/firewall.rs`
   and `crates/agent/src/init_system.rs` for the established pattern, and
   ARCHITECTURE.md's "Controlled execution" section for the reasoning.
4. Wire a route in the relevant arsenal's admin page (or a new one) that
   calls `Executor::execute_on_host()` with the right `Permission` and
   `OperationKind`. Prefer an existing permission over adding a new one
   (`crates/core/src/permission.rs`) unless the capability is genuinely a
   different responsibility from anything that permission already gates.
5. If the operation is categorically worse than a normal Destructive
   action -- a wrong input could destroy something instantly or sever a
   host's own manageability with no remote fix -- give it a second,
   off-by-default admin setting on top of (never instead of) the usual
   confirmation, following Ossuary's/Inquest's pattern. See "The
   second-gate pattern for catastrophic-risk operations" in
   [ARCHITECTURE.md](ARCHITECTURE.md).
6. If it needs a new permission, add it to `Permission` in
   `crates/core/src/permission.rs` and seed it for the roles that should
   have it in `crates/database/src/seed.rs`.
7. Live-verify it against a real enrolled agent before considering it
   done -- see "Per-arsenal capability verification" in
   [TESTING.md](TESTING.md).

A control-plane-only capability (work the control plane does about its
own environment, not on a specific managed host -- Panopticon is the
only current example) uses `Executor::execute()` and the `Operation`
trait instead of steps 1-4 above; see ARCHITECTURE.md's "Controlled
execution" section for how that path differs.

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
- Pull requests target `main`. See "Release process" below for how `main`
  becomes a tagged release; day-to-day contributions don't need to think
  about that step.

## Release process

This section is for maintainers cutting a release, not something a
regular contributor needs to do. `main` is the continuously-developed
branch; a release is a deliberate checkpoint cut from it (see
[README.md](README.md#releases-and-branches) for what that distinction
means for users).

1. Decide the next version following [Semantic Versioning](https://semver.org/)
   against what actually changed in `CHANGELOG.md`'s "Unreleased" section.
2. Update the `VERSION` file at the repository root and
   `workspace.package.version` in the root `Cargo.toml` to the new version
   -- both should always agree; `VERSION` is what the running binary and
   the dashboard's update check read, `Cargo.toml`'s version is what
   `cargo` itself reports.
3. In `CHANGELOG.md`, rename "## [Unreleased]" to
   "## [X.Y.Z] - YYYY-MM-DD" and add a fresh, empty "## [Unreleased]"
   above it.
4. Commit these as a single "Release vX.Y.Z" commit on `main`.
5. Tag it and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
6. `.github/workflows/release.yml` and `docker-publish.yml` both trigger
   off the tag push: the former builds and packages `abyssal-arsenal` and
   `abyssal-agent` binaries and creates the GitHub release (with
   auto-generated release notes) the tag points at; the latter builds and
   pushes the matching control-plane image to GHCR. Neither depends on
   the other, and both only ever proceed past their own test run.
7. The dashboard's update check (every 6 hours, or immediately on a
   restart) picks up the new release automatically on every deployment
   still running an older tagged version -- nothing else needs doing.

## License of contributions

Abyssal Arsenal is licensed under the GNU Affero General Public License
v3.0 or later (AGPL-3.0-or-later); see [LICENSE](LICENSE). By submitting a
contribution, you agree it is licensed under the same terms.

## Reporting security issues

Do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for how to report one privately.
