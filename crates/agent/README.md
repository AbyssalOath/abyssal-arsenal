# abyssal-agent

Runs on a managed Linux or Windows host, not on the Abyssal Arsenal control
plane (macOS is not yet supported -- see "Windows and macOS" below). It
connects *out* to the control plane over an authenticated WebSocket and
executes a fixed, versioned whitelist of operations locally
(`abyssal-agent-protocol::AgentOperation`) -- it never accepts an arbitrary
command from the wire.

Everything below the "Windows" section is written for Linux; Windows install
steps are their own section further down, since enough of the mechanics
(service manager, privilege model, default paths) genuinely differ that
interleaving them would be more confusing than a clean split. Both platforms
share the same binary crate, the same wire protocol, and -- for arsenals
that support it -- the same behavior; see `crates/agent/src/thanatos.rs`'s
module doc comment for how Thanatos's own detection differs by platform
underneath an identical output format.

Everything below is the manual path: an operator SSHing into the host
themselves and running these steps by hand. If the host already turned up
in Panopticon's network discovery, the control plane can do this over SSH
for you instead -- see "Add Hosts" on a scan's results in
`/arsenals/panopticon`, and the "Deploying agents over SSH" section of
[ARCHITECTURE.md](../../ARCHITECTURE.md#deploying-agents-over-ssh-quick-add-host-from-network-scan)
for how it works. It ultimately runs the same non-interactive install
described below (`abyssal-agent install --control-plane-url ...
--enrollment-token ...`), just without you typing it in yourself.

## One-line bootstrap (fastest)

Generate an enrollment token at `/admin/hosts` and copy the ready-made
command shown for the target host's platform. Each one fetches a small,
secret-free bootstrap script the control plane serves (`/install.sh`,
`/install.ps1`), which downloads the agent from the control plane and runs the
same non-interactive `install` described below. With a publicly-trusted
certificate the commands are simply:

```bash
# Linux (the script needs root)
curl -fsSL https://your-control-plane.example.com/install.sh | sudo sh -s -- --enrollment-token <token>
```

```powershell
# Windows, from an *administrator* PowerShell
& ([scriptblock]::Create((irm https://your-control-plane.example.com/install.ps1))) -EnrollmentToken '<token>'
```

When the control plane uses the **internal CA** `install.sh` creates (no
public domain), the generated commands are longer: they first fetch
`/ca.crt`, check its SHA-256 fingerprint against the one embedded in the
command, and only then trust it and continue -- so a fresh host needs no
certificate copied to it beforehand. See the top-level README's "Trusting a
self-signed / internal cert". `/admin/hosts` also shows an unattended Windows
variant for RMM tools (PDQ, Intune, GPO startup scripts) running as SYSTEM.

The scripts carry no secrets -- only the control-plane URL and agent
version, both already public. The token and the CA fingerprint come from the
command you copied, never from the server, so the real gates stay the token
enforced server-side at `/api/hosts/enroll` and the fingerprint you pinned.
Everything below is the same install those scripts run, step by step, for
when you'd rather do it by hand.

### Install options worth knowing

| Option | Purpose |
|---|---|
| `--ca-cert <ca.pem>` | Trust this CA (PEM) for the control plane, in addition to the OS store. `install` copies it next to the credentials file and puts it into the service definition, so enrollment, the WebSocket, and its reconnects use it (self-update downloads come from GitHub and use only the OS store). The control plane keeps this file current when it rotates its CA (`UpdateTrustedCa`, pushed on every connect). Never picked up implicitly. |
| `--ca-fingerprint <sha256>` | With `--ca-cert`: refuse to install unless the CA matches (hex, colons optional). |
| `--enrollment-token-file <file>` / `ABYSSAL_ENROLLMENT_TOKEN` | Supply the token without putting it on a command line (visible in `ps` and in RMM job logs). |
| `--aat <token>` / `ABYSSAL_AAT` | Enroll with the control plane's reusable install token (AAT) instead of a single-use one. It also verifies the control plane's CA (no `--ca-cert` needed). See [Mass deployment with the install token](#mass-deployment-with-the-install-token-aat). |
| `--non-interactive` | Never prompt; fail with an exit code if something is missing or the process isn't elevated. |

### Exit codes

`install` (and `run`, if it can't start) prints `ERROR:` and, when it
recognises the cause, `HINT:` on **stdout**, and exits with:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Other error |
| 2 | Bad arguments (unknown installer switch, or `--non-interactive` with `SERVER`/`AAT` missing) |
| 3 | Not root/elevated (with `--non-interactive`) |
| 10 | Control plane's certificate isn't trusted (`UnknownIssuer`) |
| 11 | Control plane serves a CA certificate as its server cert (`CaUsedAsEndEntity`) |
| 12 | Certificate doesn't cover the `--control-plane-url` address |
| 13 | Other certificate problem (expired, not yet valid, ...) |
| 14 | `--ca-cert` doesn't match `--ca-fingerprint`, or the control plane couldn't prove its CA with the AAT |
| 20 | Enrollment token rejected (invalid, expired, used, revoked), or the AAT was rotated |
| 21 | Host name already in use (by a connected host; with the AAT, by any enrolled host) |
| 30 | Control plane unreachable |
| 40 | Enrolled, but service registration/start failed |

The served `install.sh` / `install.ps1` pass these through unchanged.

## Mass deployment with the install token (AAT)

Every control plane has one **agent install token (AAT)**, a reusable secret
like a CrowdStrike CID. `install.sh` prints it at the end of a server install,
and `/admin/hosts` shows it (audit-logged) with **Rotate** and a **Require
approval** switch. Put it in a deployment package once; every machine that
runs the installer enrolls under its own hostname.

Windows release assets: `abyssal-agent-vX.Y.Z-x86_64-pc-windows-msvc.exe` and
`.msi` (also served by the control plane at `/agent/windows-exe` and
`/agent/windows-msi`). Both run unattended as SYSTEM:

```text
abyssal-agent.exe /install /quiet /norestart SERVER=https://arsenal.corp AAT=AAT1-...
msiexec /i AbyssalAgent.msi /qn /norestart SERVER=https://arsenal.corp AAT=AAT1-...
```

In PDQ Deploy, add the exe as an Install step and put
`/install /quiet /norestart SERVER=... AAT=...` in **Parameters** (or add the
MSI and the same `SERVER=... AAT=...` as its parameters). Optional `NAME=`
overrides the host name. The exe adds an **Apps & features** entry
("Abyssal Arsenal Agent", uninstalling with `/uninstall`); the MSI is listed
as itself.

On Linux, `/admin/hosts` shows a one-liner that downloads the control plane's
version of the agent from the GitHub release (publicly trusted HTTPS, so no
CA setup) and installs it; for hosts without internet access, copy the agent
from `/agent/linux` with your own tooling and run `sudo ./abyssal-agent
install --control-plane-url https://arsenal.corp --aat AAT1-...`.

- **No CA fingerprint needed.** Before trusting the control plane, the agent
  sends a random nonce to `/api/agent/ca`; the control plane answers with its
  CA and an HMAC (keyed by the AAT) over both. Only a server that knows the
  AAT can produce it, so it survives CA rotation. The AAT itself is sent
  only after that CA is verified.
- **Upgrades** need no parameters: install the newer exe/MSI and it reuses
  the existing enrollment and remembered control plane.
- **Uninstall**: `abyssal-agent.exe /uninstall /quiet`, or remove it from
  Apps & features (or `msiexec /x` for the MSI). An MSI install can only be
  removed as the MSI -- `/uninstall` refuses, rather than leave Windows
  Installer listing a product whose files are gone. It keeps this host's enrollment, so a
  reinstall reconnects as the same host; add `PURGE=1` to delete it too.
  Remove the host on `/admin/hosts` to decommission it there.
- **Approval**: with *Require approval* on, AAT-enrolled hosts show as
  *Pending approval* and can't connect until approved (they keep retrying,
  so they come online within a minute of approval).
- **Security**: anyone holding the AAT can enroll a machine. Treat it as a
  secret, rotate it if it leaks (enrolled hosts are unaffected), and turn on
  approval if that matters more than zero-touch. The control plane stores it
  encrypted with `ENCRYPTION_KEY` (which `install.sh` generates), so database
  dumps and backups don't carry a usable token; without that key it's stored
  unencrypted, with a warning at every start. If the key changes, the old
  token can't be read: rotate it on `/admin/hosts`. An AAT enrollment can never
  replace an existing host of the same name -- remove the old one first.
- **Troubleshooting**: a failed unattended install leaves its reason in
  `C:\ProgramData\abyssal-agent\agent.log` and exits with one of the codes
  above (the MSI reports 1603; see the log). The binaries aren't
  Authenticode-signed yet, so running one by hand shows a SmartScreen prompt;
  deploying as SYSTEM doesn't.

## Keeping an agent up to date

When a host's agent is older than the control plane, `/admin/hosts` shows
an **Agent out of date** badge next to it. Use the **Update agent** action
there to push the control plane's current version to the connected host
over its existing WebSocket: the agent downloads the matching release for
its own platform (TLS-pinned to GitHub -- the wire only carries a version
tag, never a URL), replaces its installed binary, and restarts its service
so the new build takes over (a couple of seconds' disconnect/reconnect).

This works on any agent new enough to understand the update operation. An
agent that predates it can't -- it drops the connection instead of
replying, and the Update action says so -- so give such a host one
re-deploy first (the bootstrap one-liner above, or the SSH quick-add from
a Panopticon scan); after that, future updates are one click from here.

## Quick install (recommended)

1. In the control plane's web UI, go to `/admin/hosts` and generate an
   enrollment token (valid 15 minutes, single-use).
2. On the target host, download and extract the
   [latest release](https://github.com/AbyssalOath/abyssal-arsenal/releases/latest)
   (`abyssal-agent-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`):

   ```bash
   curl -LO https://github.com/AbyssalOath/abyssal-arsenal/releases/latest/download/abyssal-agent-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
   tar -xzf abyssal-agent-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
   cd abyssal-agent-vX.Y.Z-x86_64-unknown-linux-gnu
   ```

   The binary is already executable inside the archive; if your download
   method stripped that (some browsers and archive tools do), just
   `chmod +x abyssal-agent` before the next step.
3. Run it and follow the prompts:

   ```bash
   ./abyssal-agent
   ```

   With no arguments at all, `abyssal-agent` runs its interactive `install`
   command: it asks for the control plane URL and the enrollment token,
   enrolls the host, copies itself to `/usr/local/bin/abyssal-agent`
   (`root:root`, mode `755`) if it isn't running from there already, then
   writes and enables a systemd service pointed at that copy
   (`systemctl enable --now abyssal-agent`) so it survives a reboot
   without you having to hand-author a unit file. That's the whole
   install -- nothing else to configure. The binary copy step matters:
   the extracted archive you ran `install` from is typically sitting
   somewhere your own unprivileged account can write to, and a `User=
   root` unit must never point at a binary anyone but root can replace --
   that combination is exactly the local-privilege-escalation pattern a
   vulnerability scan flags. `install` always copies to a root-owned
   path and hardens it before wiring the unit to it, rather than trusting
   wherever it happened to be run from.

   Installing needs root, but you don't have to remember `sudo` yourself --
   if it isn't already running as root, it asks (`Run this with sudo now?
   [Y/n]`) and re-execs itself under `sudo` on your behalf, which then
   prompts for your password the normal way. Answering no, or running
   fully non-interactively, just tells you to re-run it as root instead of
   guessing.

   Prefer a non-interactive/scripted install instead (Ansible, cloud-init,
   ...)? Pass the same two values as flags and it skips the prompts:

   ```bash
   sudo ./abyssal-agent install \
     --control-plane-url https://your-control-plane.example.com \
     --enrollment-token <token>
   ```

   Re-running `install` on an already-enrolled host skips straight to the
   service setup (useful if you need to repair or recreate the systemd
   unit without re-enrolling). On a non-systemd host (Alpine/OpenRC,
   Void/runit, ...), it enrolls and tells you to run `abyssal-agent run`
   directly under whatever supervisor you're using instead -- there's no
   first-class support for every alternative init system yet.

Once it's running, `systemctl status abyssal-agent` shows its state, and it
reconnects automatically with exponential backoff if the control plane is
unreachable. If its credential is ever revoked from `/admin/hosts`, it keeps
retrying (and failing) rather than crash -- re-run `install` with a fresh
token to restore access.

## Building from source instead

No local release binary for your architecture, or you're working on the
agent itself? Build and install it manually:

```bash
cargo build --release -p abyssal-agent
sudo install -m 755 target/release/abyssal-agent /usr/local/bin/abyssal-agent
sudo abyssal-agent
```

`/usr/local/bin` is on `sudo`'s own restricted `secure_path`, so
`sudo abyssal-agent` finds it there. `cargo install --path crates/agent`
also works for quick, unprivileged local testing (installs to
`~/.cargo/bin`, **not** on `sudo`'s `secure_path` -- either run it
unprivileged with `--credentials-file` pointing somewhere you own, or
invoke it by full path when you do need `sudo`).

## Manual setup (no interactive install)

Everything the `install` command above does, by hand -- useful for
understanding what it's actually doing, or if you'd rather manage the
systemd unit yourself:

```bash
abyssal-agent run \
  --control-plane-url https://your-control-plane.example.com \
  --enrollment-token <token>
```

This enrolls the host (storing a long-lived credential at
`/etc/abyssal-agent/credentials.json` by default -- needs root to create
that directory; override with `--credentials-file` to use an unprivileged
path instead, e.g. `~/.abyssal-agent/credentials.json` for local testing)
and then connects and serves commands. On subsequent runs, drop
`--enrollment-token`; the stored credential is reused automatically.

```ini
# /etc/systemd/system/abyssal-agent.service
[Unit]
Description=Abyssal Arsenal agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/abyssal-agent run --control-plane-url https://your-control-plane.example.com
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Run the enrollment step manually once first (or pass `--enrollment-token` on
the unit's first start and remove it afterwards), then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now abyssal-agent
```

## Windows

The same `abyssal-agent` binary crate builds and runs on Windows
(`x86_64-pc-windows-msvc`), registering itself as a native Windows service
(`LocalSystem`) instead of a systemd unit -- the CI release job
(`.github/workflows/release.yml`) publishes both as separate archives on
every tagged release, `abyssal-agent-vX.Y.Z-x86_64-pc-windows-msvc.zip`
alongside the Linux `.tar.gz`.

1. In the control plane's web UI, go to `/admin/hosts` and generate an
   enrollment token (valid 15 minutes, single-use).
2. On the target host, in an **administrator** Command Prompt or
   PowerShell, download and extract the
   [latest release](https://github.com/AbyssalOath/abyssal-arsenal/releases/latest)
   zip, then run the extracted `abyssal-agent.exe` with no arguments (or
   `abyssal-agent.exe install --control-plane-url ... --enrollment-token
   ...` for a scripted install). This asks for the control plane URL and
   enrollment token if not already given as flags, enrolls the host,
   copies itself to `C:\Program Files\AbyssalAgent\abyssal-agent.exe`
   (hardened with `icacls` to full control for `SYSTEM`/Administrators
   only, read-and-execute for standard users) if it isn't running from
   there already, then registers and starts an auto-start `LocalSystem`
   service pointed at that copy, named `abyssal-agent` -- the Windows
   analog of `systemctl enable --now`. Same reasoning as the Linux path's
   own binary copy step: a `LocalSystem` service must never point at a
   binary sitting wherever it was extracted to, which a standard user can
   typically overwrite.
3. Not running elevated? Unlike the Linux path, there's no automatic
   re-exec-under-`sudo` equivalent available on every supported Windows
   version -- `install` just tells you to re-run from an administrator
   terminal ("Run as administrator") and exits.

Once installed, `sc query abyssal-agent` shows its state, or use the
Services console (`services.msc`). Re-running `install` reconfigures the
existing service in place (same "safe to re-run" behavior as the systemd
path) rather than failing if it's already registered.

The service logs to `C:\ProgramData\abyssal-agent\agent.log` (rotated to
`agent.log.1` at 10 MB) -- the place to look when it stops or never shows up
as connected. A setup failure (unreadable CA, missing credentials) stops the
service with a service-specific exit code (`sc query` shows it as
`SERVICE_EXIT_CODE`), the same codes the install scripts document.

**Model divergences from Linux**, both deliberate:

- **No Apotheosis (time-boxed sudo elevation) equivalent.** The service
  always runs as `LocalSystem`, which already has the access Thanatos's
  read-only Security/System event log queries need -- there's no
  unprivileged-by-default mode to elevate *from* the way Linux's
  sudo-based `ElevationState` provides.
- **Thanatos detection reads the Security/System event logs** (plus,
  best-effort, PowerShell script block logging, Windows Defender's
  operational log, and Sysmon where deployed), via `Get-WinEvent`, shelled
  through `powershell.exe` instead of tailing `/var/log/auth.log`/the kernel
  ring buffer/systemd. It also covers LSASS-access detection, process
  ancestry, host-posture and persistence (registry/service/task/WMI/ASEP)
  file-integrity checks, and an optional short-interval fast sweep for a
  curated high-signal set (`fast_only`) -- see the module doc comment in
  `crates/agent/src/thanatos.rs` for the exact signals watched and why
  they're matched on event ID rather than message text, and the Thanatos
  entries in [CHANGELOG.md](../../CHANGELOG.md) for the full SIEM/EDR feature
  set (search, retention, suppression/IOC rules, response, alerting).
- **Inquest's response/containment actions go through Windows Defender
  Firewall** (`New-NetFirewallRule`/`Set-NetFirewallProfile`, shelled
  through `powershell.exe`) instead of nftables/iptables, and quarantine
  moves files under `C:\ProgramData\abyssal-agent\quarantine` instead of
  `/var/lib/abyssal-arsenal/quarantine` -- see the module doc comment in
  `crates/agent/src/inquest.rs`. Host isolation specifically carries a
  real, documented model divergence there (no single-transaction
  primitive the way `nft -f`/`iptables-restore` provide) -- read
  `windows::isolate_host`'s own doc comment, and see "The second-gate
  pattern for catastrophic-risk operations" in
  [ARCHITECTURE.md](../../ARCHITECTURE.md), before isolating a production
  Windows host with it for the first time.
- Every other arsenal that shells out to a Linux-only tool (Parish's
  `useradd`, Firewall's `iptables`, Cryptkeeper's `ssh-keygen`/`openssl`,
  ...) still simply isn't functional on Windows -- Thanatos and Inquest
  are the two arsenals brought to parity so far.

## Windows and macOS

Windows support (above) covers Thanatos's detection depth and Inquest's
response/containment actions, plus the install/service-manager story; it
does not extend every other arsenal's Linux-specific tooling (Parish's
`useradd`, Cryptkeeper's `ssh-keygen`, ...) to Windows equivalents yet.
macOS isn't supported at all: distributing a
`launchd`-installed background agent without Gatekeeper blocking every
install needs code-signing/notarization, which needs an active Apple
Developer Program membership. If that's ever obtained, the shape would
mirror Windows exactly -- `cfg(target_os = "macos")` in this same crate,
Apple unified logging (`log show`/`oslog`) for Thanatos's auth/sudo-
equivalent events, a `launchd` `.plist` for persistence, the same wire
format either way.

## Why it runs as root (usually)

Most real sysadmin operations (disk, network, service management, ...)
need root. Two ways to give the agent that access:

- **Run it as root permanently** (the systemd unit above does this).
  Simple, and the whitelist of what it will run at all
  (`AgentOperation`) is the actual safety boundary either way, not the
  user it runs as.
- **Run it unprivileged and elevate on demand ("Apotheosis")**: an admin
  with the `hosts.elevate` permission can elevate a connected host from
  its arsenal page in the control-plane web UI by submitting a sudo
  password. The agent validates it via `sudo -S -v` (the same mechanism
  interactive `sudo` already uses) and starts a sliding idle window
  during which privileged operations run as `sudo -n` instead of failing
  outright; the password itself is never persisted anywhere on either
  side. See "Apotheosis: time-boxed sudo elevation" in
  [ARCHITECTURE.md](../../ARCHITECTURE.md) for the full mechanism.
