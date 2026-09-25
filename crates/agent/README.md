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
   enrolls the host, then writes and enables a systemd service for itself
   (`systemctl enable --now abyssal-agent`) so it survives a reboot without
   you having to hand-author a unit file. That's the whole install --
   nothing else to configure.

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
   enrollment token if not already given as flags, enrolls the host, then
   registers and starts an auto-start `LocalSystem` service named
   `abyssal-agent` -- the Windows analog of `systemctl enable --now`.
3. Not running elevated? Unlike the Linux path, there's no automatic
   re-exec-under-`sudo` equivalent available on every supported Windows
   version -- `install` just tells you to re-run from an administrator
   terminal ("Run as administrator") and exits.

Once installed, `sc query abyssal-agent` shows its state, or use the
Services console (`services.msc`). Re-running `install` reconfigures the
existing service in place (same "safe to re-run" behavior as the systemd
path) rather than failing if it's already registered.

**Model divergences from Linux**, both deliberate:

- **No Apotheosis (time-boxed sudo elevation) equivalent.** The service
  always runs as `LocalSystem`, which already has the access Thanatos's
  read-only Security/System event log queries need -- there's no
  unprivileged-by-default mode to elevate *from* the way Linux's
  sudo-based `ElevationState` provides.
- **Thanatos detection reads the Security/System event logs** (plus,
  best-effort, PowerShell script block logging and Windows Defender's
  operational log where enabled), via `Get-WinEvent`, shelled through
  `powershell.exe` instead of tailing `/var/log/auth.log`/the kernel ring
  buffer/systemd -- see the module doc comment in
  `crates/agent/src/thanatos.rs` for the exact signals watched and why
  they're matched on event ID rather than message text.
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
