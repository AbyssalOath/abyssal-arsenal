# The control plane monitors itself

The control plane runs in Docker and only sees the world through its agents.
Its container is on a private bridge network, runs as an unprivileged user,
and has no view of the server's disks, services or network traffic. That's
deliberate: a compromised web app shouldn't be root on the server.

To manage the server it runs on, Abyssal Arsenal uses the same approach as
Puppet, Salt and Wazuh. It installs an ordinary agent on that server. The
agent is enrolled like any other host and shows up on `/admin/hosts` with a
**Control plane** badge. Every arsenal then works on it as usual: Mortiscope
metrics, Thanatos detections, Apothecary updates, Scourge in IDS mode, and so
on. The one difference is that operations that would take the control plane
down are refused for it.

## How it's installed

`install.sh` does it after the containers start, unless you pass
`--no-agent`, answer **n** at the prompt, or set
`ABYSSAL_SELF_AGENT=no`. The installer records your answer as
`CONTROL_PLANE_AGENT` in `.env`, so a re-run won't ask again. The steps are:

1. Copy the agent out of the app image
   (`/app/agent-bundle/abyssal-agent-linux.tar.gz`), so its version always
   matches the control plane's.
2. Mint a single-use, 15-minute enrollment token with
   `abyssal-arsenal control-plane enrollment-token`. That token flags the
   host enrolling with it as the control plane.
3. Get the CA to trust with `abyssal-arsenal control-plane ca-bundle`. This
   is the internal CA, or nothing when the certificate is publicly trusted.
4. Run `abyssal-agent install --non-interactive` against `PUBLIC_URL`.

The agent connects to `PUBLIC_URL`, the same address every other agent
uses, not to loopback. Its traffic goes through Caddy and TLS like
everyone else's, and anything that breaks agents in general shows up here
too.

The installer skips the agent when:

- the server already has an enrolled agent;
- the server isn't x86_64 Linux (the bundled agent's only target);
- there's no root or `sudo` available.

When it skips, it says so; the control plane itself is unaffected.

To add or remove the flag by hand, use **Mark as control plane** or **Not
the control plane** on `/admin/hosts`. Both need `hosts.manage`, and both
are audited as `HOST_CONTROL_PLANE_CHANGED`. Use this for an agent you
installed yourself, or after moving the control plane to another server.

## The guardrails

These checks run in `HostConnectionRegistry::dispatch`, the single point
every operation passes through on its way to an agent. That includes the
background sweeps and Thanatos's inline responses, not just the buttons. A
refused operation is never sent. The admin sees the reason, and the audit
trail records the attempt as a failure with the same reason. The checks
themselves are a pure function, `abyssal_hosts::control_plane_guard::check`,
with unit tests.

| Refused | Why |
| --- | --- |
| Inquest host isolation | It would cut every agent and browser off, and the UI is how isolation is lifted. |
| Scourge inline IPS (`ScourgeSetMode { ips: true }`) | A bad rule or a stopped Suricata would cut the control plane off. IDS mode and packet captures are allowed. |
| Firewall: closing or removing a rule for a protected port; turning the firewall on | Closing these would lock out the UI, the agents or SSH. `ufw enable` defaults to deny-incoming. |
| Bringing a network interface down | It could take the server off the network. |
| Stop, restart or disable `docker`, `docker.socket`, `containerd` or `abyssal-agent` | Stopping Docker stops the control plane. |
| Stop, restart or remove an `abyssal*` container, or any container named only by an ID | These are the control plane's own containers; an ID can't be checked here. |
| Signal by name (not a dry run) matching `dockerd`, `containerd*`, `docker-proxy`, `mariadbd`, `mysqld`, `caddy` or `abyssal*`, or any pattern | The agent uses `pgrep`, which takes an unanchored regex, so short or wildcard names match far more than they look like. A dry run is allowed. |
| Signal PID 1, or a PID that is one of the processes above | The control plane looks the PID up first (`ProcessDetail`) and refuses the control plane's own processes. If it can't tell which process a PID is, it refuses. |
| Upgrade or remove `docker*`, `containerd*`, `moby*`, `runc` or `crun` | It restarts every container. Do it in a maintenance window from a shell. |
| Quarantine files under `/var/lib/docker`, `/var/lib/containerd`, Docker's binaries, or the agent's own files | These are files the control plane runs on. |
| Unmount, mount over, or remove a mount unit for `/`, `/var`, `/var/lib`, `/var/lib/docker`, or the device Docker's data is on | That would hide or remove the database. |
| Partition, format, repair, add to RAID, or create or remove LVM PVs or VGs on the device holding `/var/lib/docker` or its disk | Doing so destroys the database. |

Protected ports are 22, 80, 443, 8080, `HTTP_PORT`, the `PUBLIC_URL` port,
1812 and 1813 (Panopticon RADIUS), plus anything in `CONTROL_PLANE_PORTS`.
That last variable is a comma-separated list in `.env`, for example for a
non-standard SSH port.

The Docker device comes from the agent itself. Each time it connects, the
control plane runs `ResourceUsage` (`df`) and picks the filesystem whose
mount point covers `/var/lib/docker`. The disk checks fail closed:

- Until the agent has answered, every destructive disk operation on the
  server is refused.
- If the device is LVM, md RAID, or anything other than a plain disk or
  partition, every destructive disk operation on the server is refused.
  This includes `/dev/root` and ZFS, because the physical disks underneath
  aren't known.
- A plain partition protects its whole disk. Other disks, and other
  partitions on the same disk, are still allowed.

Rebooting the server is allowed. Docker brings the containers back with
`restart: unless-stopped`.

## What you see before clicking

Every arsenal page for this host carries a banner listing what's refused
there. Actions the guard always refuses on this server are disabled, with
the reason as a tooltip:

- Isolate (Inquest, and the Thanatos shortcut);
- Enable firewall;
- inline IPS;
- Bring interface down.

Forms that take a name or a number carry a note naming what's protected.
These are the port, service, container, process, package, disk and
quarantine forms. The Reanimation process list disables Pause, Resume and
Signal on the control plane's own processes. Everything is still enforced
when it's sent, however the request arrives.

## What isn't covered

The guardrails stop accidents and keep the UI from cutting its own branch.
They are not a security boundary against someone who has admin rights.
Anything refused here can still be done from a shell on the server, on
purpose. Some known gaps:

- **`BlockRemoteIp`.** The control plane can't know which addresses its
  admins and agents use, so blocking an IP is allowed. Blocking the address
  you're browsing from will lock you out until you unblock it from a shell
  (`nft`/`iptables`).
- **The deployment directory.** `docker-compose.yml` and `.env` are
  wherever you cloned the repo, which the control plane doesn't know.
  Catacomb and Grimoire don't refuse edits there.
- **Other control planes.** A server running a second deployment isn't
  flagged unless you mark it.

## Removing it

```bash
sudo abyssal-agent uninstall --purge
```

After that, remove the host on `/admin/hosts`. Set
`CONTROL_PLANE_AGENT=no` in `.env` so a later `./install.sh` doesn't put the
agent back.
