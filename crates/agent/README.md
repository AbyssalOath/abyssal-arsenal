# abyssal-agent

Runs on a managed Linux host, not on the Abyssal Arsenal control plane. It
connects *out* to the control plane over an authenticated WebSocket and
executes a fixed, versioned whitelist of operations locally
(`abyssal-agent-protocol::AgentOperation`) -- it never accepts an arbitrary
command from the wire.

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
