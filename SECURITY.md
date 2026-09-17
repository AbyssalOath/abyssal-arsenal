# Security Policy

## Supported versions

Abyssal Arsenal is pre-1.0 and has not made a tagged release yet. Only the
`main` branch is supported; there is no backport policy at this stage.

## Reporting a vulnerability

Please do not open a public GitHub issue for a security vulnerability.

- If this repository is hosted on GitHub, use **GitHub's private security
  advisory** feature (Security tab -> "Report a vulnerability") if it is
  enabled for this repo.
- Otherwise, email **lordsodomiser@proton.me** with a description of the
  issue, steps to reproduce it, and its potential impact.

This is a small, personal project, so response times are best-effort, not
covered by an SLA. You will get an acknowledgment as soon as it's seen, and
a fix or mitigation plan communicated once the report has been triaged.
Please give a reasonable amount of time to address a report before any
public disclosure.

## Scope

In scope:

- The Rust code in this repository (`crates/*`), including the
  control-plane server, the `abyssal-agent` binary, and the
  `agent-protocol` wire format.
- The deployment tooling in this repository (`Dockerfile`,
  `docker-compose.yml`, `install.sh`, `scripts/*.sh`, CI/CD workflows), to
  the extent a flaw there would result in an insecure default deployment.

Out of scope:

- Vulnerabilities in third-party dependencies (please report those
  upstream; a `Cargo.lock` bump here to pick up a fix is still welcome via
  a normal PR).
- Issues that only exist because of a self-hosted deployment's own
  misconfiguration (for example, disabling TLS and exposing the control
  plane directly to the internet against the documented recommendation).

## Security model

The design principles this codebase follows are documented in
[ARCHITECTURE.md](ARCHITECTURE.md), and include:

- **Fail closed.** Any authorization check that can't be resolved is
  treated as denied, never allowed. Checked explicitly per-handler
  (`crates/rbac`), not via middleware that could silently no-op.
- **No plaintext secrets at rest.** Passwords are hashed with Argon2id.
  Session tokens and host agent credentials are opaque, high-entropy
  values; only a SHA-256 hash of each is ever persisted
  (`crates/core/src/secret.rs`).
- **No arbitrary command execution from a request.** Local operations use
  explicit argument vectors, never a shell string built from user input
  (`crates/execution/src/process.rs`). Commands dispatched to a managed
  host are limited to a fixed, versioned whitelist
  (`AgentOperation` in `crates/agent-protocol`) -- an agent cannot be made
  to run anything outside that list.
- **CSRF protection** via a double-submit cookie on every state-changing
  form. Machine-to-machine endpoints (host enrollment, the agent
  WebSocket) are authenticated a different way and are never behind this
  check, since they have no browser session or CSRF cookie to check
  against.
- **Append-only audit log.** Security-sensitive actions (login
  success/failure, user and role changes, module toggles, configuration
  changes, executed commands, host enrollment/revocation) are recorded and
  the codebase contains no code path that updates or deletes an audit
  record.
- **Security headers** (`Content-Security-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`) are applied to every
  response.
- **No secrets committed to source control.** `.env` and anything deriving
  from `.env.example` is gitignored; `install.sh` generates strong random
  secrets rather than shipping defaults.
- **Sudo elevation ("Apotheosis") never persists the password.** A sudo
  password submitted alongside any host-dispatched arsenal action
  (permission `hosts.elevate`, Super Admin only by default) is validated
  once against the target host's own PAM stack (`sudo -S -v`) and is never
  written to the database, disk, or any log on either the control plane or
  the agent.
  It is held in process memory only for the minimum time needed and is
  actively zeroized (`zeroize::Zeroizing`), not just dropped, once
  consumed on the agent side. `AgentOperation`'s `Debug` implementation is
  hand-written specifically to redact this field, as a backstop against
  accidental logging. See "Apotheosis" in
  [ARCHITECTURE.md](ARCHITECTURE.md) for the full mechanism.

## Known limitations

These are documented tradeoffs, not something you need to report:

- `LoginLimiter` (login rate limiting) and `HostConnectionRegistry` are
  in-memory and process-local. A multi-instance deployment would need both
  backed by shared state to retain their guarantees across instances.
- TLS is expected to be terminated by a reverse proxy (Caddy, or your own)
  in front of the control plane; the Axum server itself does not terminate
  TLS. Running without TLS in front of it is only appropriate for local
  testing -- `install.sh` says as much when you choose that option. This
  matters most concretely for Apotheosis: elevating submits a real sudo
  password, and without TLS that password travels in plaintext over
  the network. The control plane warns (rather than blocks) when
  `COOKIE_SECURE` is off, for local-testing convenience, but does not
  refuse the request.
- The `abyssal-agent` binary does not sandbox itself beyond the fixed
  `AgentOperation` whitelist. Privilege escalation for an unprivileged
  agent deployment is handled by Apotheosis (see above); running the agent
  as root permanently remains a valid alternative, documented in
  `crates/agent/README.md`.
