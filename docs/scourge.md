# Scourge: network intrusion detection and prevention

Scourge is the Defend lifecycle's **sensor and detector** -- a Suricata
deployment, managed over the agent channel, that inspects live traffic on a
host, surfaces its alerts, captures packets for forensics, and (gated, and
conservative by design) runs inline IPS. It is the counterpart to the
other Defend Arsenals:

> **Panopticon** answers *"what is on my network?"*
> **Scourge** answers *"what is actually happening on my network?"*

The Defend lifecycle is **Cadavault** (harden) -> **Scourge/Thanatos**
(inspect and detect) -> **Inquest** (respond) -> **Postmortem**
(investigate). Scourge is the inspection point: it watches the wire and
hands what it finds to the rest of that chain.

This document covers what Scourge owns versus what it deliberately does
*not* build, the fixed agent-operation whitelist, engine detection and the
Linux-only story, the control-plane sweep and alert cache, the
validate-before-apply config model, the Thanatos telemetry handoff, the
second-gate settings, the inline-IPS design and its mandatory lockout
protection, the workflow-registry entries, the known limitations, and how
to test the whole thing manually.

Scourge's UI uses the same server-rendered HTML + htmx pattern as the rest
of the app: plain POST/redirect/GET forms, with htmx only for the live
"latest alerts" polling region (see "Alert inspection" below). There is no
hand-written client-side JavaScript.

## Responsibilities

| Concern | Owner |
| --- | --- |
| Suricata lifecycle on a host: detect/install the engine, read sensor status, start/stop/restart the service | **Scourge** |
| Ruleset management: list rules, enable/disable a SID, suppress/threshold a SID, run `suricata-update` | **Scourge** |
| Sensor config: edit/validate/apply `suricata.yaml` with backup + rollback (the Sepulchre validate-before-apply model) | **Scourge** |
| Alert inspection: a read-only cache of recent EVE alerts, swept from each sensor on an interval | **Scourge** |
| Packet capture: bounded, host-local pcaps started and cancelled from the control plane; pcaps never stream over the agent channel | **Scourge** |
| Inline IPS: switch a sensor to NFQUEUE inline mode, set per-SID `drop`/`reject` actions, revert to passive -- all behind a second gate and a mandatory always-allow lockout | **Scourge** |
| Long-term event storage, correlation, MITRE tagging, cross-host search, alerting channels | **Thanatos** (Scourge forwards to it, never stores there itself) |
| Device inventory / NAC | **Panopticon** (Scourge is a read-only consumer, not a writer) |
| Containment (IP blocklist, host isolation, quarantine) | **Inquest** |
| General network/firewall config | **Necrolink** / **firewall.rs** |

## Hard boundaries (what Scourge does *not* build)

These are deliberate non-goals. Scourge stays a sensor; the moment it starts
doing one of these, it has grown into another Arsenal's job.

- **No correlation engine or security event store.** That is Thanatos.
  Scourge forwards alerts into Thanatos's existing push-telemetry ingest
  (`ingest_pushed_telemetry`) using the established tab-separated wire
  format. It never writes `thanatos_events` directly.
- **No long-term history.** Scourge's own cache is a short-lived,
  sweep-populated convenience for the alert-inspection UI, pruned on a
  retention timer (`scourge.event_retention_days`). Durable history is
  Obituary/Thanatos.
- **No device inventory or NAC.** Panopticon owns that; Scourge only reads.
- **No containment logic.** Scourge detects and (in IPS mode) drops at the
  sensor, but blocklisting, isolation, and quarantine are Inquest. The
  workflow registry wires a high-severity Scourge alert straight to those
  Inquest actions rather than reimplementing them.
- **No general network configuration.** Necrolink owns switch/network
  config; Scourge only manages the sensor's own Suricata install and the
  minimal netfilter hookup IPS mode requires.

## The agent-operation whitelist

Like every host-agent Arsenal, Scourge dispatches only a fixed set of
`AgentOperation` variants (declared in `crates/agent-protocol/src/lib.rs`,
dispatched exhaustively in `crates/agent/src/ops.rs`, implemented in
`crates/agent/src/scourge.rs`). Each carries an `OperationKind`
(`Read`/`Write`/`Destructive`); a `Destructive` operation is refused unless
the request is confirmed, the caller holds `scourge.manage`, and the action
is audited.

| Operation | Kind | What it does |
| --- | --- | --- |
| `ScourgeInstall` | Write | Install Suricata via Apothecary (never a raw package-manager call) |
| `ScourgeSensorStatus` | Read | Engine presence/version, service state, EVE-log readability |
| `ScourgeCollectEvents` | Read | The unattended sweep's reader: tail new EVE alerts from a cursor/offset |
| `ScourgeListRules` | Read | List/search the active ruleset |
| `ScourgeUpdateRules` | Write | Run `suricata-update` |
| `ScourgeSetSidEnabled` | Write | Enable/disable a SID |
| `ScourgeSuppressSid` | Write | Suppress/threshold a SID (`threshold.conf`) |
| `ScourgeApplyConfig` | Write | Validate, back up, then apply a new `suricata.yaml`; rollback on failure |
| `ScourgeServiceAction` | Write | Start/stop/restart/reload the sensor service |
| `ScourgeRuleTest` | Write | Test a rule/pcap pair (gated behind capture-enabled) |
| `ScourgeCaptureStart` | Write | Start a bounded host-local packet capture |
| `ScourgeCaptureStatus` | Read | Poll a running capture job |
| `ScourgeCaptureCancel` | Write | Cancel a running capture |
| `ScourgePcapList` | Read | List host-local pcap files |
| `ScourgePcapDelete` | Destructive | Delete (shred) a pcap on the host |
| `ScourgeIpsStatus` | Read | Report inline-mode state (NFQUEUE hookup, drop-in, mode file) |
| `ScourgeSetMode` | Destructive | Switch to inline IPS / revert to passive IDS |
| `ScourgeSetSidAction` | Write/Destructive | Set a SID's action to `alert` (Write) or `drop`/`reject` (Destructive) |

## Engine detection and the Linux-only story

Scourge is **Linux-only**. On a Windows host every operation returns
`process::platform_unsupported()`; the agent compiles a `linux` module under
`#[cfg(target_os = "linux")]` and a `stubs` module otherwise, with a
`cfg`'d `pub use` so the dispatch surface is identical on both targets (and
`cargo check --target x86_64-pc-windows-gnu -p abyssal-agent` stays green).

Engine detection prefers **file probing over `PATH`**, the same approach
`firewall.rs` uses: it looks for the Suricata binary and config at their
known locations rather than trusting `which`. That makes the unattended
sweep robust even when the agent's `PATH` is minimal.

## Privilege and the unattended sweep

Privilege is obtained through Apotheosis (`sudo -n`, via
`ElevationState::run` / `run_allow_failure` / `run_with_stdin`, which prefix
`sudo -n` only when the host is elevated). Installation goes through
Apothecary, never a raw package-manager call.

Crucially, **the sweep must work from file permissions alone**. If the agent
runs as root, or the EVE log is group-readable to the agent's user, the
sweep reads alerts without any elevation. When the EVE log is unreadable,
the sweep does not fail silently or demand a password -- it records a clear
**"unreadable, needs permissions"** state that surfaces on the
alert-inspection page ("Logs unreadable" tile and per-sensor state), so an
admin knows exactly what to fix.

## The control-plane sweep and alert cache

Two background tasks run on the control plane (spawned in
`crates/web/src/lib.rs`, pattern mirrored on Thanatos's sweep):

- **`spawn_scourge_sweep`** (`scourge_ops.rs`): every
  `scourge.sweep_seconds` it re-reads settings, checks the
  `scourge.monitoring_enabled` gate, and for each host dispatches
  `ScourgeCollectEvents` from the host's stored cursor. New alerts are
  content-hash-deduped into the cache (`repo::scourge`), the cursor/offset
  advances monotonically (`GREATEST`), and -- when monitoring is enabled and
  the alert meets `scourge.min_forward_severity` -- the alert is forwarded to
  Thanatos. Registered with `TaskHeartbeats` (`task_health::SCOURGE_SWEEP`)
  so its health shows on the task-health page.
- **`spawn_scourge_retention`**: prunes cached alerts older than
  `scourge.event_retention_days` and enforces a row cap, so the cache stays
  a short window, never a history store.

The cache exists only to back the alert-inspection UI; it is not an event
store and is not authoritative. Thanatos is.

## Alert inspection

`/arsenals/scourge/alerts` is a read-only view over the cache
(`scourge.view`): summary tiles, severity/signature/top-talker breakdowns, a
filterable alert table (host, severity, signature, src/dst IP, port, proto,
category, time range), and pagination. The "latest" view (page 1, a relative
range) is pollable via htmx (`live_updates_control` / a `.live-region` with
`hx-trigger="every Ns"`); the refresh choices include 5s. The live fragment
and the full page render the same inner partial from the same view, so a
poll and a full load are byte-identical.

The page also renders **Suggested Next Steps** derived from the
high-severity alerts currently on screen -- see "Workflow registry entries".

## Packet capture

Captures are bounded host-local jobs, following the scan/deploy-job pattern:
`AppState.scourge_capture_jobs` holds in-memory `ScourgeCaptureJob`s (lost on
restart, by design). `ScourgeCaptureStart` begins a capture bounded by a
byte cap (stop-at-N-MB) and a BPF filter; `ScourgeCaptureStatus` polls it;
`ScourgeCaptureCancel` stops it. **Pcaps stay on the host** -- their contents
never stream over the agent channel. `ScourgePcapList` lists them and
`ScourgePcapDelete` shreds one (a `Destructive` op, second-gated, with the
witness/shred options the rest of the app uses for data destruction). Total
pcap footprint is bounded by `scourge.pcap_max_total_mb` and aged out by
`scourge.pcap_retention_days`.

Capture inputs are hardened: BPF filters reject any whitespace token
starting with `-` and the filter is passed after a `--` argv separator so
`tcpdump`/Suricata stop option parsing; temp working directories are created
with `mktemp -d` under a root-owned `/var/lib/abyssal-arsenal/scourge` (0700)
with a path-prefix sanity check, never in world-writable `/tmp`. All host
commands use argument vectors, never shell strings, and pcap/rule paths are
traversal-checked.

## The validate-before-apply config model

Config and ruleset changes follow Sepulchre's validate-before-apply pattern:
Scourge validates the candidate `suricata.yaml` (`suricata -T`), backs up the
current config, applies the new one, reloads, and **rolls back to the backup
on any validation or reload failure**. The same applies to IPS rule and mode
changes. An operator never ends up with a sensor that won't start because a
bad config was applied blind.

## The Thanatos handoff

Scourge forwards alerts into Thanatos using the **existing** push-telemetry
contract -- no new ingest path. Each forwarded alert is emitted in the
tab-separated wire format (`severity \t label \t source \t raw_line`, plus
the optional `port \t` / `module \t` / `fim \t` / `offset \t` / `info \t`
fields) and fed through `ingest_pushed_telemetry`, which content-hash-dedups
and upserts the monotonic offset. Forwarding is gated on
`thanatos.monitoring_enabled` and `scourge.monitoring_enabled`, and only
alerts at or above `scourge.min_forward_severity` are sent. Scourge never
touches `thanatos_events` directly.

## Second-gate settings (all off by default)

The higher-risk capabilities sit behind their own settings, re-checked fresh
at **both** the GET confirm route and the POST dispatch route (the same
`ensure_*_enabled` pattern Inquest's host-isolation gate uses), so toggling a
setting off takes effect immediately even mid-flow. The Scourge settings form
its own section on the admin settings page, managed with `scourge.manage`
(not `settings.manage`).

| Setting | Default | Gates |
| --- | --- | --- |
| `scourge.monitoring_enabled` | off | Sweep forwarding to Thanatos |
| `scourge.config_changes_enabled` | off | Config/ruleset/SID mutations |
| `scourge.capture_enabled` | off | Packet capture and rule testing |
| `scourge.ips_enabled` | off | Inline IPS (mode switch + per-SID drop/reject) |
| `scourge.min_forward_severity` | configurable | Minimum severity forwarded to Thanatos |
| `scourge.sweep_seconds` | configurable | Sweep interval |
| `scourge.event_retention_days` | configurable | Cache pruning window |
| `scourge.pcap_max_total_mb` / `scourge.pcap_retention_days` | configurable | Pcap footprint bounds |

## Inline IPS

IPS is the highest-risk capability and is built last, conservatively, and
fully gated behind `scourge.ips_enabled` plus type-to-confirm on every
state-changing step.

- **Mode switch (`ScourgeSetMode`, Destructive).** Enabling inline mode
  writes the always-allow lockout rules and an IPS include, ensures the
  include is referenced from `suricata.yaml` (with a backup), installs the
  NFQUEUE netfilter hookup (a `SCOURGE_IPS` chain in the **mangle** table,
  for both `iptables` and `ip6tables`, that ACCEPTs loopback, established
  flows, the control-plane src/dst, and inbound SSH (`--dport 22`) *before*
  a `NFQUEUE --queue-num 0 --queue-bypass` target hooked into
  INPUT/FORWARD/OUTPUT -- see "Why the mangle table" below), writes a
  systemd drop-in
  (`ExecStart ... -q 0`), writes the mode file, then validates and restarts
  -- rolling the whole thing back to passive on any failure. Disabling
  reverses it (remove the nfqueue chain + drop-in, daemon-reload, mode file
  back to `ids`, restart).
- **Per-SID action (`ScourgeSetSidAction`).** Sets a SID's action via a
  `modify.conf` line plus `suricata-update`, then validate + reload with
  rollback. `alert` is a `Write`; `drop`/`reject` are `Destructive`
  (type-to-confirm). The action is allowlisted to exactly
  `alert`/`drop`/`reject`.
- **Status (`ScourgeIpsStatus`, Read, `scourge.view`).** Reports the
  nfqueue hookup, the drop-in, and the mode file so an operator can see what
  inline mode is actually doing before changing it. It's in the host page's
  Read card, available to anyone who can view Scourge.

### Mandatory lockout protection

Lockout protection is not optional. Both the netfilter layer and the
Suricata rule layer always permit the agent's control-plane connection and
SSH:

- The `SCOURGE_IPS` chain ACCEPTs loopback, established/related, the
  control-plane IP (both directions), and inbound SSH (`--dport 22`)
  *before* any packet reaches `NFQUEUE`, and the queue target uses
  `--queue-bypass` so a dead Suricata fails **open**, not closed. There is
  deliberately no `--sport 22` bypass: SSH replies are already covered by
  established/related, and a source-port bypass would let an attacker skip
  inspection just by sending from port 22.
- The IPS ruleset is prepended with `pass` rules covering the same traffic
  (the control plane in both directions, inbound SSH), so even a `drop`
  ruleset cannot override them.

### Why the mangle table

The chain lives in `mangle`, not `filter`. In `filter`, an ACCEPT is final
for that chain: a `SCOURGE_IPS` jump at the top of INPUT would let its
bypasses -- and every packet Suricata's verdict allows -- skip the host's
own firewall rules after it. Enabling IPS would then open SSH past a
firewall that restricts it, and keep established sessions alive through an
Inquest isolation. In `mangle`, an ACCEPT only ends the mangle table; the
packet still goes through every `filter` rule, so the host firewall and
isolation keep working. A Suricata drop still drops. Disabling (and
re-enabling) also removes any chain an earlier build left in `filter`.

### IPv4 and IPv6

In NFQUEUE mode Suricata sees only queued packets, so an unhooked address
family would be neither blocked nor even alerted on. Inline mode therefore
hooks `iptables` and `ip6tables` alike. If one can't be hooked (the tool is
missing or the kernel lacks it), enabling still succeeds for the other but
the result says plainly which family is not inspected; if neither can be
hooked, it stays in passive IDS.

The control-plane address is **derived**, the same way `inquest.rs`
isolation derives it (`resolve_control_plane_ip`), and is **not
operator-editable** -- exactly like Inquest's isolation always-allow list.
This is a deliberate, documented deviation from an editable "always-allow
list": a non-editable, auto-derived lockout is strictly safer and cannot be
fat-fingered into cutting the agent off. Because IPS cannot sever the
control plane and is type-to-confirm + second-gated, it does not additionally
require the witness/shred sign-off that irreversible data destruction does.

Inline IPS is **refused on the control plane's own server** (see
[control-plane-host.md](control-plane-host.md)). IDS mode and captures are
allowed there, but inline mode puts every packet, including the agents' and
browsers' connections, behind Suricata. For inline protection in front of
the control plane, use a separate sensor host.

Inline NFQUEUE hookup is vendor- and kernel-dependent; validate in a lab
before enabling in production. Safety rests on the mandatory always-allow
bypass at both layers, `--queue-bypass` fail-open, validate-before-reload,
and full rollback to passive.

## Watching the network from the control plane's server

The control-plane container can't see network traffic. It sits on a Docker
bridge, as an unprivileged user, with only `NET_RAW`. Scourge always runs
through an agent. To use the control plane's server as a sensor, use the
agent `install.sh` puts on it (the **Control plane** host, see
[control-plane-host.md](control-plane-host.md)), and deploy Suricata there
in IDS mode, as on any other host.

On its own, that sensor sees only the server's own traffic. To watch a
network segment from it, mirror the segment's traffic to a spare NIC on the
server:

1. **Add a dedicated capture NIC.** Leave it unaddressed so the server
   doesn't route or answer on it:

   ```bash
   sudo ip link set eth1 up
   sudo ip link set eth1 promisc on
   # Keep it unconfigured: no DHCP or NetworkManager profile, no IP.
   nmcli device set eth1 managed no   # if NetworkManager is in use
   ```

   Don't mirror into the NIC that carries the control plane's own traffic.
   Mirrored packets would compete with the agents' and browsers'
   connections, and a busy span can saturate the link.

2. **Configure the switch's mirror (SPAN) port.** Choose the source ports
   or VLANs, and set the destination to the port `eth1` is plugged into.
   Some examples:

   - Cisco IOS:

     ```
     monitor session 1 source vlan 10 both
     monitor session 1 destination interface Gi1/0/48
     ```

   - Aruba/HPE: `mirror-port 48` plus `monitor` on the sources.
   - UniFi: port profile, then **Port Mirroring**.
   - Juniper: `set forwarding-options analyzer`.

   For a remote switch, use RSPAN or ERSPAN. A passive network TAP is
   better still for a busy link, since a switch drops mirrored frames under
   load.

3. **Point Suricata at it.** On the host's Scourge page, set **Monitored
   interface(s)** to `eth1` (or `eth0, eth1` to keep watching the server's
   own traffic as well), then validate and apply. Mirrored traffic needs no checksum validation or offload
   handling, because Suricata only reads it.

4. **Check it's seeing traffic.** Start a short capture on `eth1` from the
   Scourge page, or run `sudo tcpdump -ni eth1 -c 20`. The alert feed
   should begin to fill.

Captures from a span can be large. The stop-at-N-MB limit and pcap shred
apply as usual. Inline IPS stays refused on this host whatever interface it
uses. A span is receive-only anyway, so it couldn't block anything.

## Workflow registry entries

Scourge participates in the cross-Arsenal workflow registry
(`crates/workflows/registry.json`) as a **source**. The alert-inspection
page evaluates each high-severity alert on the current page against the
registry and renders the matches as "Suggested Next Steps" buttons, grouped
and deduped per host (each button links to the right host's target Arsenal,
carrying context in the query string). This is the Defend lifecycle wired
into the UI -- detection (Scourge) handing off to response (Inquest),
detection (Thanatos), investigation (Postmortem), and hardening (Cadavault):

| Condition on a Scourge alert | Suggests |
| --- | --- |
| `severity` is `high`/`critical` and `src_ip` present | **Inquest**: block `{src_ip}` (context `src_ip`) |
| `severity` is `high`/`critical` and `src_ip` present | **Thanatos**: correlate `{src_ip}` (context `src_ip`) |
| `severity` is `high`/`critical` | **Postmortem**: investigate this host |
| `signature`/`category` matches scan/brute-force | **Cadavault**: harden exposed services |

Panopticon is intentionally *not* a target here: it has no host-detail route
for a `/arsenals/{target}/{host_id}` suggestion button to land on, so a
suggestion would 404. Panopticon enrichment stays a read path, not a
workflow button.

## Known limitations

- The alert cache is short-lived and non-authoritative; it is not a history
  store. Durable, searchable, correlated history is Thanatos/Obituary.
- Capture and deploy jobs are in-memory and lost on control-plane restart
  (by design, like scan jobs).
- Inline IPS is Linux/NFQUEUE-specific and kernel/vendor-dependent; it ships
  conservatively and must be lab-validated before production use.
- Panopticon enrichment is read-only; Scourge does not write inventory.
- On the control plane's own server, inline IPS is refused (IDS and
  captures work); see [control-plane-host.md](control-plane-host.md).
- Windows is unsupported; every operation returns
  `process::platform_unsupported()` there.

## Manual test steps

1. **Install + status.** On a Linux host, run `ScourgeInstall` (via the UI),
   then `ScourgeSensorStatus`: confirm engine version, service state, and EVE
   readability. On a host where the EVE log is not agent-readable, confirm
   the status and the alert page both show the "unreadable, needs
   permissions" state rather than an error.
2. **Sweep + cache.** With `scourge.sweep_seconds` short and some Suricata
   alerts present, confirm alerts appear on `/arsenals/scourge/alerts`, the
   tiles populate, the 5s live poll updates page 1, and filters work.
3. **Thanatos handoff.** Enable `scourge.monitoring_enabled` and
   `thanatos.monitoring_enabled`, set `scourge.min_forward_severity`, and
   confirm only alerts at/above that severity appear in Thanatos, deduped.
4. **Config apply + rollback.** Apply a valid `suricata.yaml` and confirm
   reload. Apply a deliberately invalid one and confirm it is rejected,
   rolled back, and the sensor stays running on the old config.
5. **Capture.** With `scourge.capture_enabled`, start a bounded capture,
   watch it stop at the byte cap, list the pcap, and shred it (confirm the
   Destructive confirm + audit). Confirm pcap contents never cross the agent
   channel.
6. **Workflow suggestions.** Produce a high-severity alert with a source IP
   and confirm the alert page shows Inquest (block IP), Thanatos (correlate),
   and Postmortem (investigate) buttons, each linking to the right host with
   `src_ip` in the query where applicable.
7. **IPS (lab only).** With `scourge.ips_enabled`, switch a sensor to inline
   mode (type-to-confirm), confirm `ScourgeIpsStatus` reports the nfqueue
   hookup + drop-in, verify the control-plane connection and SSH stay up,
   set a benign SID to `drop` and confirm it blocks, then revert to passive
   and confirm the nfqueue chain and drop-in are removed. Kill Suricata
   mid-test and confirm traffic still flows (`--queue-bypass` fail-open).
