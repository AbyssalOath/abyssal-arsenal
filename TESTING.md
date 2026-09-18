# Testing

## Philosophy

Business logic gets pure unit tests, colocated with the code they test
(`#[cfg(test)] mod tests` at the bottom of the relevant file). No test
database is required to run the suite: `crates/database` uses
runtime-checked `sqlx::query`/`query_as` rather than the compile-time
`query!` macros, so nothing in `cargo test --workspace` needs a live
MariaDB connection.

## Running the suite

```bash
cargo test --workspace
```

CI (`.github/workflows/ci.yml`) also runs `cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets -- -D warnings`; run both locally
before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## What's covered today

- **`crates/core`**: permission key round-tripping (`Permission::as_key` /
  `from_key`), opaque token generation and hashing, and `Severity`
  (Thanatos) ordering/round-tripping plus its event-hash function being
  deterministic while still distinguishing host and source.
- **`crates/auth`**: Argon2id password hashing round-trips and produces
  unique salts; session token uniqueness and deterministic hashing; the
  login rate limiter's lock/clear behavior.
- **`crates/rbac`**: fail-closed behavior for an authorization context with
  every permission, with none, and with a partial set.
- **`crates/execution`**: the `Executor`'s permission checks, the
  destructive-operation confirmation requirement, cancellation-token
  interruption, and the equivalent checks for `execute_on_host()` (denies
  without permission, fails cleanly when the target host isn't connected)
  -- both without needing a real database (denial paths short-circuit
  before touching it; a lazily-connected pool that would panic on first
  real query is used to prove that).
- **`crates/hosts`**: `HostConnectionRegistry` dispatch behavior -- fails
  fast when a host isn't connected, times out when a host doesn't respond,
  and correctly resolves a dispatch when a response does arrive.
- **`crates/agent-protocol`**: the largest single suite -- every
  wire-value validator used on both the control plane and the agent
  (hostnames, paths, account names, device paths, port specs, SSH key
  types/fingerprints, permission modes, and so on), each checked for both
  reasonable input it must accept and malformed/injection-shaped input it
  must reject.
- **`crates/agent`**: `ElevationState`'s sliding idle-window behavior --
  not elevated by default, de-escalating clears it, an expired window is
  treated as not-elevated, checking status refreshes the window, and a
  per-elevation configured timeout is what's actually checked rather than
  a hardcoded default.
- **`crates/web`**: the dashboard health sweep's `systemctl --failed`
  output parsing (counts failed units from the trailing summary line,
  handles a clean host and a non-systemd host's informational message
  correctly) and the update check's version comparison (parses `vX.Y.Z`
  and bare `X.Y.Z`, rejects malformed input, and only reports an update
  available when a strictly newer version has actually been confirmed).

## What isn't covered yet

- **Integration tests against a real MariaDB.** The `repo::` query
  functions in `crates/database` are exercised manually via the Docker
  Compose stack, not by an automated integration suite. If you add one,
  prefer a `#[sqlx::test]`-style fixture over hand-rolled setup/teardown.
- **HTTP-level tests of `crates/web` routes and handlers.** Coverage today
  is manual (see "Manual verification" below). A `tower::ServiceExt::oneshot`
  based test harness against the router would be a reasonable way to add
  this.
- **End-to-end browser tests of the UI.**
- **An automated agent <-> control-plane integration test.** The
  enrollment -> connect -> dispatch -> revoke lifecycle has been verified
  manually (see below) but is not part of the automated suite.

Contributions filling in any of the above are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Manual verification checklist

This is the walkthrough used to verify the platform end-to-end during
development. Run it against a fresh `docker compose up -d --build` (or
`./install.sh`) whenever changing auth, RBAC, the module system, or the
agent protocol:

1. **Setup**: visiting `/` with no users yet redirects to `/setup`;
   creating the first administrator lands on the dashboard and shows all
   registered arsenal tiles.
2. **Login state**: `/login` does not show "Create Account" until public
   registration is explicitly enabled from `/admin/settings`, and stops
   showing it again once disabled.
3. **RBAC enforcement**: a Regular User account gets a real 403 (not just
   a hidden link) hitting an admin-only route directly.
4. **Module toggle**: disabling an arsenal from `/admin/modules` removes
   its tile from the dashboard and produces a `MODULE_DISABLED` entry in
   `/admin/audit`.
5. **CSRF**: a state-changing `POST` without a valid CSRF token is
   rejected.
6. **Host lifecycle**: generate an enrollment token from `/admin/hosts`,
   run `abyssal-agent run --control-plane-url ... --enrollment-token ...`
   on a real host, confirm it shows "online", run its "System Info" action
   and confirm the result is from the *host*, not the control-plane
   container. Kill the agent process and confirm it flips to "offline";
   restart it without a token and confirm it reconnects using its
   persisted credential. Revoke the host and confirm the agent's reconnect
   attempts start failing with 403. Since generated tokens are base64url
   and can start with `-`, regenerate a few until one does and confirm
   `--enrollment-token` still parses it correctly (a real, previously
   shipped regression -- clap otherwise reads the leading `-` as a flag).
   Separately, run bare `abyssal-agent` (no arguments), unprivileged, and
   confirm it prompts to re-exec under `sudo` (accept and confirm sudo's
   own password prompt takes over; decline and confirm it exits cleanly
   telling you to re-run as root, not a confusing failure partway
   through). Once elevated, confirm the interactive `install` prompts
   work and the host enrolls; on a systemd host, confirm it also writes
   and enables `abyssal-agent.service` and that `systemctl status
   abyssal-agent` shows it running.
7. **Audit trail**: confirm `HOST_ENROLLED`, `SYSTEM_COMMAND_EXECUTED`, and
   `HOST_REVOKED` all appear in `/admin/audit` with the right actor and
   timestamp.
8. **Dashboard and global host context**: with a host connected, selecting
   it from the top-nav switcher and then visiting any per-host arsenal
   redirects straight to that host's page instead of showing the picker;
   selecting "All hosts" restores the picker. The Fleet Health card shows
   the right host count/online count, and "Recent activity" shows
   summarized entries (e.g. "Rebooted -- <host>") rather than a raw
   `SYSTEM_COMMAND_EXECUTED` row, with routine reads absent from the list
   but still present in the full `/admin/audit` log. The version notice at
   the top shows the current version; confirm it correctly turns into a
   pulsing, linked "update available" notice when `VERSION` is set below
   the latest tagged GitHub release (restore it afterward).

**Per-arsenal capability verification.** Every arsenal capability in this
project was live-verified against a real enrolled agent before being
considered done, following the same discipline: a fresh disposable
MariaDB container, a real `abyssal-agent` process (not a mock), every
Read/Write/Destructive operation exercised through the actual web UI, and
the test environment fully torn down afterward. For anything genuinely
destructive or irreversible, the verification confirms the real dispatch
reaches the real command and fails cleanly (most often on privilege,
since the test agent runs unprivileged) rather than actually executing
it against a real shared machine -- never fabricate or skip this step by
reasoning about the code alone. Apply the same discipline to any new
capability: real agent, real dispatch, real (but safe) target.

## Adding tests for new logic

- New `Operation` or `AgentOperation` implementations should get the same
  kind of test the existing ones do in `crates/execution/src/executor.rs`'s
  test module: a fake implementation exercising the permission/confirmation/
  timeout paths, not a test that shells out for real.
- New permission checks should assert both the "granted" and "denied"
  paths, matching `crates/rbac/src/authz.rs`'s tests.
- If you add a `repo::` function with real query logic worth testing beyond
  what type-checking already guarantees, prefer testing the call site's
  business logic with a fake/trait boundary over standing up a real
  database in the test, unless you're specifically adding integration test
  infrastructure (see "What isn't covered yet").
