# abyssal-agent

Runs on a managed Linux host, not on the Abyssal Arsenal control plane. It
connects *out* to the control plane over an authenticated WebSocket and
executes a fixed, versioned whitelist of operations locally
(`abyssal-agent-protocol::AgentOperation`) -- it never accepts an arbitrary
command from the wire.

## Building and installing

There's no published package yet, so `abyssal-agent` isn't just already on
`PATH` -- you need to build and place it there yourself, on the target host,
from a clone of this repo. Two ways, and it matters which one you pick:

- **System-wide (recommended, needed for the systemd setup below and for
  the default `/etc/abyssal-agent/credentials.json` path, both of which
  need root):**

  ```bash
  cargo build --release -p abyssal-agent
  sudo install -m 755 target/release/abyssal-agent /usr/local/bin/abyssal-agent
  ```

  `/usr/local/bin` is on `sudo`'s own restricted `secure_path`, so
  `sudo abyssal-agent ...` finds it.

- **User-local, for quick testing without root:**

  ```bash
  cargo install --path crates/agent
  ```

  This installs to `~/.cargo/bin/abyssal-agent`, which is on *your* shell's
  `PATH` but almost certainly **not** on `sudo`'s -- `sudo`'s `secure_path`
  is a fixed list that ignores the invoking user's `PATH` entirely, home
  directories included. `sudo abyssal-agent ...` will fail with `command not
  found` even though it runs fine unprivileged. If you use this route,
  either run unprivileged with `--credentials-file` pointing somewhere you
  own (see below -- no root needed at all), or invoke it by full path when
  you do need `sudo`: `sudo ~/.cargo/bin/abyssal-agent ...`.

## Enrolling a host

1. In the control plane's web UI, go to `/admin/hosts` and generate an
   enrollment token (valid 15 minutes, single-use).
2. On the target host, run:

   ```bash
   abyssal-agent run \
     --control-plane-url https://your-control-plane.example.com \
     --enrollment-token <token>
   ```

   This enrolls the host (storing a long-lived credential at
   `/etc/abyssal-agent/credentials.json` by default -- needs root to create
   that directory; override with `--credentials-file` to use an
   unprivileged path instead, e.g. `~/.abyssal-agent/credentials.json` for
   local testing) and then connects and serves commands. On subsequent
   runs, drop `--enrollment-token`; the stored credential is reused
   automatically.

## Running it as a systemd service

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

The agent reconnects automatically with exponential backoff if the control
plane is unreachable, and if its credential is ever revoked from
`/admin/hosts`, it will keep retrying (and failing) rather than crash --
re-enroll it with a fresh token to restore access.

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
