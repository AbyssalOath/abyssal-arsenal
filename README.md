# Abyssal Arsenal

[![CI](https://github.com/AbyssalOath/abyssal-arsenal/actions/workflows/ci.yml/badge.svg)](https://github.com/AbyssalOath/abyssal-arsenal/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AbyssalOath/abyssal-arsenal)](https://github.com/AbyssalOath/abyssal-arsenal/releases/latest)

A self-hosted IT operations platform for Linux and Windows hosts, written in
Rust. Its capabilities -- 25 "arsenals" covering system administration,
security monitoring and EDR, Active Directory health, network discovery and
access control, storage, backups and disaster recovery, incident response,
and more -- are modular and sit on top of a shared core: local
authentication, role-based access control, append-only audit logging, and
notifications.

Abyssal Arsenal is a **control plane**, not the system it manages. Real work
happens on enrolled hosts running the companion `abyssal-agent`, which
connects out to the control plane over an authenticated WebSocket. Hosts are
enrolled one at a time with a single-use token, or rolled out en masse with
the reusable install token (a Windows MSI/exe for PDQ, Intune or GPO, much
like a CrowdStrike CID):

```
         Abyssal Arsenal (control plane)
    Auth . RBAC . Audit . Notifications . Web UI
                        |
             authenticated connection
                        |
        +---------------+---------------+
        v               v               v
   Linux host      Windows host     Linux host
  abyssal-agent   abyssal-agent    abyssal-agent
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit together.

## Arsenals

All 26 arsenals are fully implemented -- each gated by its own
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
| Sepulchre | Storage and file-sharing connectivity (SFTP, SMB/CIFS, local paths) shared across arsenals |

**Observe**

| Arsenal | Covers |
| --- | --- |
| Haruspex | Active Directory DNS and domain-controller health diagnostics (Windows) |
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
| Scourge | Network intrusion detection/prevention (IDS/IPS): a Suricata sensor that inspects live traffic, surfaces and forwards alerts to Thanatos, captures and analyzes packets, and (gated) runs inline IPS |
| Thanatos | Security telemetry (SIEM/EDR): MITRE-tagged detection, cross-host search & retention, correlation, suppression/allowlist & threat-intel IOC rules, multi-channel alerting (email/syslog/Slack/Teams/webhook), and inline response |

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
normal submit button. Grimoire's "Load" refills its form from a saved
macro; Panopticon's add/edit switch forms have a "Saved macro" dropdown
instead (the community string is looked up on the server and never sent
to the browser). A
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
git checkout v0.2.1   # pin to the latest stable release; omit to run main
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
4. To manage a Windows host, go to `/admin/hosts` and generate a deployment
   command (single-use, or a reusable deployment token for mass rollout). Run
   it in an elevated PowerShell on the host, or push it with PDQ Deploy / a GPO
   startup script / Intune; it downloads the agent from the control plane,
   trusts its CA, enrolls, and installs itself as a service in one step.
   For CrowdStrike-style rollouts, deploy the agent's exe or MSI with the
   **agent install token (AAT)** that `install.sh` prints:
   `abyssal-agent.exe /install /quiet /norestart SERVER=<url> AAT=<token>` (see
   [crates/agent/README.md](crates/agent/README.md#mass-deployment-with-the-install-token-aat)).
5. Already have Panopticon's network discovery finding hosts you want to
   manage? Run a discovery scan from `/arsenals/panopticon`, then use "Add
   Hosts" (or per-device "Quick add") on the results and pick the target OS:
   **Linux** deploys the agent over SSH at once, instead of repeating step 3
   by hand (see
   [ARCHITECTURE.md](ARCHITECTURE.md#deploying-agents-over-ssh-quick-add-host-from-network-scan)
   for how credentials and host-key trust are handled); **Windows** hands you
   the ready-to-run deploy command from step 4 for the selected hosts.

The dashboard shows this build's version at all times and checks GitHub for
a newer tagged release every few hours; if one exists, the notice turns into
a linked, pulsing alert pointing at the release page.

## Reverse proxy / TLS

The control plane expects to be reached over HTTPS: session cookies are
`Secure` by default, and the agent WebSocket follows the browser's scheme, so
over plain HTTP a login just loops (the browser drops the Secure cookie).
`install.sh` asks how you want TLS handled:

1. **I have my own reverse proxy** (NGINX Proxy Manager, Traefik, …) — you
   point it at `http://<this-host>:<HTTP_PORT>` and terminate HTTPS there. You
   provide the public HTTPS URL; it's stored as `PUBLIC_URL`.
2. **Set one up for me (Caddy)** — the bundled Caddy container terminates TLS
   and reverse-proxies the app over Docker's internal network. The app's own
   port is then bound to `127.0.0.1` only (not reachable over plain HTTP from
   the network), so all traffic goes through Caddy's HTTPS on **443**. Reach it
   at `https://<host>` — **no port number**; don't append `HTTP_PORT`.
3. **Just testing locally, skip HTTPS** — plain HTTP on `HTTP_PORT`,
   `COOKIE_SECURE=false`. Fine for a laptop, not for a real deployment.

### Caddy: public domain vs. internal IP/FQDN

When you choose Caddy, the installer asks for a domain:

- **Public domain** (DNS points at this host, ports 80/443 reachable): Caddy
  obtains a real, browser-trusted certificate automatically via Let's Encrypt.
  Nothing else to do.
- **Blank / internal only**: there's no public DNS, so the control plane
  runs its own small **private CA** and issues the server certificate Caddy
  serves. The installer asks for the IP address(es) and/or internal
  hostname(s) you'll use in the browser (comma-separated); they go onto the
  server certificate (as `IP:`/`DNS:` SANs), into the CA's name constraints,
  and the first one into `PUBLIC_URL`. (Caddy's automatic internal CA can't
  serve a *bare IP* reliably -- browsers send no SNI for an IP, so there's no
  name for it to pick a cert for -- which is why an explicit certificate is
  used instead.) The app creates the CA on its first start, before Caddy
  starts, and the installer prints its SHA-256 fingerprint at the end.

  **From then on everything is managed in the web UI**, under
  **Control-plane health → Internal TLS certificate** (`/admin/health/tls`):

  - **Renewal is automatic.** The server certificate (825 days, `CA:FALSE`,
    `serverAuth`) is re-issued from the same CA 30 days before it expires
    and Caddy is told to load it -- no restart, and nothing to re-trust:
    clients only ever trust the CA. *Renew now* and *Reload Caddy* buttons
    are there too.
  - **Changing addresses / rotating the CA** (to add an FQDN, follow an IP
    change, or replace the 10-year CA well before it expires) is two-phase so
    nothing gets stranded: *Create new CA* makes a **pending** CA and pushes
    it, alongside the current one, to every connected agent (agents that
    connect later get it on connect); the page shows which agents confirm it
    and lets you download it for GPO/browsers. *Activate* then switches the
    server over -- by which point the agents already trust it.
  - **Expiry alerts**: with self-monitoring on, you're notified if renewal
    starts failing or the CA nears its end.

  | Where | What | Who can read it |
  |---|---|---|
  | `abyssal_tls_ca` volume | CA certificate + private key, pending CA during a rotation | The app container only |
  | `abyssal_tls_server` volume | Server certificate (+ CA chain) and key | The app, and Caddy read-only |
  | `abyssal_caddy_admin` volume | Caddy's admin API socket (how the app makes Caddy reload) | The app and Caddy -- never on a network |

  The CA's key lives inside the app container, which is what makes web
  management possible. It's name-constrained to the control plane's own
  addresses, so even a leaked key can't vouch for anything else -- and the
  app container already controls every enrolled agent anyway.

  Break-glass, if the web UI itself is unreachable:
  `docker compose exec app /app/abyssal-arsenal tls status` (also `renew`,
  `reload`, `ensure`).

**IP vs FQDN — which to pick?** Either works, and you can use both (and
change your mind later from the web UI). An **IP** is zero-setup. An
**internal FQDN** (e.g. `arsenal.corp.local`) is nicer long-term: it's stable
if the IP changes. If you go the FQDN route, add an A record for it in your
internal DNS (e.g. Active Directory DNS) first. Either way, the certificate
covers exactly the addresses you gave -- reach the control plane by anything
else and TLS fails with a name mismatch (see Troubleshooting below).

### Trusting a self-signed / internal cert

The agent validates the control plane's certificate against the **host's OS
trust store**, plus -- for an internal CA -- the CA certificate it was given
at install time (`--ca-cert`, kept beside its credentials). A
publicly-trusted certificate (Let's Encrypt) needs nothing extra. For the
internal CA:

**A single machine (or a handful): nothing to do by hand.** Generate a token
at `/admin/hosts` and run the command shown there. When the control plane has
an internal CA, that command:

1. fetches the CA certificate from `https://<host>/ca.crt` -- without
   trusting the connection, since nothing trusts it yet;
2. refuses to go any further unless the certificate's SHA-256 fingerprint
   matches the one embedded in the command (and shown on `/admin/hosts` --
   the same value `install.sh` printed). The admin got that fingerprint over
   an authenticated session, so a tampered `/ca.crt` can't get past it;
3. trusts it: on Windows it's added to `Cert:\LocalMachine\Root` (PowerShell
   needs that for its own download of the agent), on Linux it's only used via
   `curl --cacert` (add `--trust-system` to also put it in the OS store);
4. installs the agent with `--ca-cert`, so the agent's enrollment request
   and its control-channel WebSocket (and every reconnect) trust that CA --
   independently of the OS store. When you rotate the CA from
   `/admin/health/tls`, the control plane updates that file on the agent
   over the control channel. (Self-update downloads come from GitHub and
   only ever use the OS store: the control plane's CA can't vouch for them.)

The Windows command must run in an **elevated** PowerShell (or as SYSTEM
from an RMM tool -- `/admin/hosts` shows an unattended variant for PDQ /
Intune / GPO startup scripts that exits non-zero with the error on stdout).
The Linux one needs `sudo`.

**A whole fleet (Active Directory)** -- push the **CA** to the **Trusted Root
Certification Authorities** store via Group Policy. That also makes browsers
trust the control plane:

1. Download the CA from `https://<host>/ca.crt` (or the *Download CA*
   button on `/admin/health/tls`) onto a domain controller, renamed to
   `.cer` if your tooling wants it -- same PEM content. **Distribute the CA,
   not the server certificate** your browser shows: the server certificate
   is renewed automatically; the CA isn't. When you rotate the CA, import the
   pending one (downloadable on `/admin/health/tls`) *before* activating it.
2. Group Policy Management → edit a GPO linked to the relevant OU →
   *Computer Configuration → Policies → Windows Settings → Security Settings →
   Public Key Policies → Trusted Root Certification Authorities* → **Import**.
3. `gpupdate /force` on a client (or wait for the next refresh).

With the CA already trusted that way, the deployment-token command works
as-is (it still verifies the fingerprint before running anything).

**Browsers on admin workstations** show an "unknown issuer" warning until the
CA is trusted -- import `ca.pem` into the machine's trusted roots (or let the
GPO above do it). By hand: `Import-Certificate -FilePath ca.cer
-CertStoreLocation Cert:\LocalMachine\Root` (Windows, elevated), or
`sudo cp ca.pem /usr/local/share/ca-certificates/abyssal-arsenal-ca.crt &&
sudo update-ca-certificates` (Debian/Ubuntu).

**Removing trust (test machines).** Windows, elevated:
`& ([scriptblock]::Create((irm https://<host>/install.ps1))) -RemoveTrust`
(only the CA), or `-Uninstall` (service, binary, credentials, and the CA).
Linux: `curl -fsSLk https://<host>/install.sh | sudo sh -s -- --remove-trust`
or `--uninstall`. (Those two fetch the script without verifying the
connection; fine for removing things, but if that bothers you, run the same
switches on a copy you already trust.)

### Troubleshooting TLS

The agent and the install scripts exit with distinct codes, and print an
`ERROR:` line plus a `HINT:` on stdout:

| Exit | Symptom | Cause / fix |
|---|---|---|
| 11 | `invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))` | The control plane is serving a CA certificate as its server certificate -- what installs before the private CA did (`openssl req -x509` makes `CA:TRUE` certs; Windows tolerates them, the agent's TLS stack correctly doesn't). Pull and re-run `./install.sh`: it moves the install onto the managed CA. Then re-trust (next row). |
| 10 | `UnknownIssuer`, `unable to get local issuer certificate`, PowerShell *"Could not establish trust relationship"* | The machine doesn't trust the control plane's CA -- or trusts an **old** one: after a legacy migration, or a rotation activated while this agent was offline (online agents are updated automatically), it has to trust the new CA. Re-run the command from `/admin/hosts` (it carries the new fingerprint), or re-import `ca.pem` via GPO; remove the old one with `-RemoveTrust`. |
| 12 | `certificate not valid for name ...`, `RemoteCertificateNameMismatch` | You're reaching the control plane by a name or IP that isn't on the certificate (e.g. its IP, when the cert was made for an FQDN). Use one of the certificate's addresses, or add this one at `/admin/health/tls` (*Create new CA* with both addresses, then *Activate*). |
| 13 | expired / not yet valid | Check the client's clock; check `/admin/health/tls` (renewal is automatic -- its last error shows under background tasks). |
| 14 | `CA fingerprint mismatch` | What the host fetched isn't the CA `/admin/hosts` knows about. Stop: either traffic is being intercepted, or the CA was regenerated after you copied the command -- copy a fresh one. |
| 20 | `enrollment rejected ... (HTTP 401)` | Token invalid, expired (single-use tokens last 15 minutes), already used, or revoked. |
| 21 | `(HTTP 409)` | A connected host already has that name. |
| 30 | connection refused / DNS / timeout | The host can't reach the control plane. |
| 40 | service registration failed | Enrollment worked; re-run the same command (it skips enrollment). |

## Agent distribution (internal / air-gapped networks)

Hosts download the agent from **this control plane** (`/agent/windows`,
`/agent/linux`), not from GitHub — so an internal or air-gapped network only
needs to reach the control plane, and every host gets whatever agent build the
control plane is serving. The bootstrap one-liners and the reusable
deployment-token command both use this.

The control plane serves from a volume (`abyssal_agent_dist`, mounted at
`/agent-dist`):

- **Empty volume (default):** on the first `/agent/{os}` request the control
  plane fetches the matching release from GitHub once and caches it there. Works
  only if the *control plane itself* can reach GitHub.
- **Air-gapped, or serving a build newer than the latest release** (e.g. one
  with a fix that isn't released yet): drop a built archive into the volume and
  it's served as-is, no internet needed:

  ```bash
  # Build the agent (per target), package it, and place it in the volume:
  #   Windows archive -> abyssal-agent-windows.zip   containing abyssal-agent.exe
  #   Linux archive   -> abyssal-agent-linux.tar.gz  containing abyssal-agent
  docker compose cp ./abyssal-agent-windows.zip app:/agent-dist/abyssal-agent-windows.zip
  ```

  The installer finds the binary anywhere inside the archive, so the internal
  layout doesn't matter. A version-agnostic name (`abyssal-agent-windows.zip` /
  `abyssal-agent-linux.tar.gz`) is matched first, then the release filename.

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
  latest tag (`git checkout v0.2.1`) rather than tracking `main`. Pull `main`
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
