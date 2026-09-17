# abyssal-agent

Runs on a managed Linux host, not on the Abyssal Arsenal control plane. It
connects *out* to the control plane over an authenticated WebSocket and
executes a fixed, versioned whitelist of operations locally
(`abyssal-agent-protocol::AgentOperation`) -- it never accepts an arbitrary
command from the wire.

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
   `/etc/abyssal-agent/credentials.json` by default -- override with
   `--credentials-file`) and then connects and serves commands. On
   subsequent runs, drop `--enrollment-token`; the stored credential is
   reused automatically.

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
need root. The agent itself doesn't elevate privileges on your behalf beyond
however it's started -- running it as root, or via `sudo`-scoped operations
in a future revision, is a deployment decision, not something this binary
does implicitly today. The whitelist of what it will run at all
(`AgentOperation`) is the actual safety boundary, not the user it runs as.
