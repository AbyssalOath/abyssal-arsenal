# Windows push deploy (roadmap)

**Target:** not yet scheduled. M0 is a prototype that decides whether the
WinRM half is built as described here, so the release is set after it.

Today, Windows hosts get the agent from the PowerShell one-liner, the MSI
(`msiexec /i AbyssalAgent.msi /qn SERVER=… AAT=…`), or PDQ. Linux hosts can
also be added from the UI: Panopticon's **Add hosts** SSHes in and runs the
agent's own install (`crates/web/src/ssh_deploy.rs`). This plan brings that
to Windows: an admin picks hosts, enters credentials for them, and the
control plane installs the signed MSI over **WinRM (HTTPS + Kerberos)** or
**OpenSSH**. GPO, Intune and MECM stay documented alternatives, not
something the control plane drives.

## Decisions

| Question | Decision |
| --- | --- |
| Transports? | **WinRM over HTTPS with Kerberos** (primary) and **OpenSSH** (secondary, for non-domain hosts or orgs that already run it). GPO, Intune and MECM are documented only. |
| WinRM over HTTP (5985) with message encryption? | **Not in v1.** HTTPS (5986) only, which avoids writing MS-WSMV message encryption. The UI and docs say plainly that hosts without an HTTPS listener should use GPO or Intune. Revisit only if the lab matrix shows HTTPS-only is blocking real rollouts. |
| How does the token reach the MSI? | **`AAT_FILE=<path>`, never `AAT=<token>`.** The deployer writes a single-use, per-host token to a file in a locked-down staging folder; the agent's install reads it, then deletes it. The token never appears on a command line (Event ID 4688), in a PowerShell script (script block logging), or in an MSI log. |
| Which token? | **A single-use token minted per host at deploy time**, like Linux SSH deploy already does. Never the default install token. |
| What counts as success? | **The agent connects back with that host's token** within the check-in timeout, as `ssh_deploy` already requires (`NeverCheckedIn`). An exit code of 0 alone is not success. |
| SMB + service control manager (PsExec style)? | **Excluded on purpose.** It pushes toward NTLM and looks like lateral movement to EDR, rightly. |
| Hidden or quiet install? | **No.** The agent shows in Add/Remove Programs (`ARPSYSTEMCOMPONENT` is never set), and nothing tries to avoid AV or EDR. |

## Goals

- From the UI: pick Windows hosts, enter credentials, watch per-host
  progress, and get a specific reason for every failure.
- Credentials used in memory only: never in the database, a job record, a
  log line or a retry. A retry asks the admin again.
- Per-host audit entries, recording the operator, the method, the MSI
  version and hash, and the outcome. The username is recorded, the secret
  never is.
- Clean uninstall through the existing `UninstallAgent` custom action.

## Non-goals (v1)

- WinRM over HTTP, CredSSP, or any credential delegation. The target
  downloads the MSI from the control plane itself, so nothing double-hops.
- Setting up WinRM HTTPS listeners or OpenSSH on targets. That's GPO's job;
  we document an example.
- Driving GPO, Intune or MECM from the control plane.
- Uninstall or upgrade by push. Upgrades already happen through agent
  self-update.

## Order of work

Work happens on `Dev`, one milestone at a time, each finished and checked
before the next.

| # | Milestone | Size | Agent change? |
| --- | --- | --- | --- |
| M0 | `sspi` prototype against a lab domain | Small | No |
| M1 | `AAT_FILE`: agent, installer arguments and MSI | Small | Yes (installer only, no protocol bump) |
| M2 | Split the transport-neutral parts out of `ssh_deploy.rs` | Medium | No |
| M3 | Windows over OpenSSH | Medium | No |
| M4 | Windows over WinRM (HTTPS + Kerberos) | Large | No |
| M5 | UI, permission and scope | Medium | No |
| M6 | Lab matrix, docs, release | Medium | - |

Why this order:

- **M0 first** because it's the biggest unknown and decides M4's shape.
  If `sspi` falls short, M4 uses `libgssapi` instead, and it's better to
  know before writing anything else.
- **M1 early** because it's the only agent change, so it gets the longest
  testing time, and it's useful on its own: the MSI's custom action
  currently passes `--aat "[AAT]"` on `abyssal-agent.exe`'s command line,
  which `Hidden="yes"` doesn't cover.
- **M2 before any Windows code** so Linux SSH deploy is untouched in
  behaviour and its existing tests prove it.
- **M3 before M4.** SSH is a transport we already ship, so the Windows
  on-host steps (staging folder, verify, install, exit codes) get built and
  tested before the hard transport is in the way.

---

## M0. `sspi` prototype

A standalone example binary, on a branch off `Dev`, not wired into the
product. It needs a lab domain name, a DC address and one test host with a
WinRM HTTPS listener.

Confirm, and write the answers into this section:

- [ ] Getting a Kerberos ticket from a username and password, with no
      credential cache on disk.
- [ ] Reaching the KDC: direct TCP to port 88, or whether a KDC proxy is
      needed.
- [ ] SPNEGO in the `Authorization` header against WinRM on 5986, and one
      WS-Man round trip (create a shell, run `hostname`, delete the shell).
- [ ] Channel binding (`tls-server-end-point`) against a host with
      `CbtHardeningLevel=Strict`.
- [ ] Where the password is copied inside `sspi`, and whether those copies
      are zeroed.
- [ ] Whether russh supports `gssapi-with-mic` (expected: no, so SSH stays
      password or key).

**If `sspi` fails** any of the first four, M4 uses `libgssapi` with an
in-memory credential cache (MIT krb5 becomes a build dependency). If it
fails only the last two, note it and carry on.

## M1. `AAT_FILE`

- [ ] Agent: `install --aat-file <path>`. Read the token, delete the file,
      then enroll exactly as `--aat` does. Refuse if both `--aat` and
      `--aat-file` are given, and fail clearly if the file is missing or
      empty.
- [ ] `crates/agent/src/installer_args.rs`: translate `AAT_FILE=` like
      `AAT=`, with tests alongside the existing ones.
- [ ] `crates/agent/wix/abyssal-agent.wxs`: add `AAT_FILE` (`Secure="yes"`;
      it's a path, so it doesn't need `Hidden`), pass
      `--aat-file "[AAT_FILE]"` from `InstallAgent`, and update the header
      comment.
- [ ] Confirm a single-use enrollment token works through the MSI path.
      Linux SSH deploy uses `--enrollment-token`, and the MSI uses `--aat`
      with the CA proof (`aat::key_id`), so check whether the per-host
      token needs `--enrollment-token-file` instead or as well.
- [ ] Manual installs keep `AAT=` unchanged.

## M2. Transport-neutral deploy core

`ssh_deploy.rs` already has the parts this needs: `DeployJob` progress
polling, `run_deploy_job` (a `Semaphore` plus a `JoinSet`), per-host audit,
the `NeverCheckedIn` check-in poll, `Zeroizing` credentials, and fake-client
tests. Move them out so SSH-to-Linux, SSH-to-Windows and WinRM-to-Windows
share them.

- [ ] Move the job, concurrency, check-in and audit pieces into a shared
      module. `SshClient` stays as is; WinRM gets its own trait in M4.
- [ ] Give `DeployFailureReason` the stage it failed at (connect,
      authenticate, preflight, download, verify, install, check-in).
- [ ] Credentials stay `Zeroizing`, the type already used here, in
      `common.rs` and in `elevation.rs`. Don't add `secrecy` for this.
- [ ] Every existing `ssh_deploy` test passes unchanged.

## M3. Windows over OpenSSH

The on-host steps, which M4 reuses:

1. **Preflight:** OS version, architecture, free space, and whether the
   agent's `UpgradeCode` is already installed.
2. **Staging folder.** If `%ProgramData%\Abyssal` exists, its owner must be
   SYSTEM or Administrators and its DACL protected and granting only those
   two; otherwise stop and report it as a host problem (an ordinary user
   can create folders under `%ProgramData%`, so it may be theirs). Create a
   new random subfolder for this deployment.
3. **Download** the MSI from the control plane over HTTPS with a short-lived
   URL that only works for this host.
4. **Verify,** in PowerShell that never sees the token:
   `Get-AuthenticodeSignature` is `Valid` with a pinned signer thumbprint,
   and the SHA-256 matches. `msiexec` doesn't enforce signatures.
5. **Token file:** write it into the subfolder over **SFTP**, never via a
   command.
6. **Install,** run directly, not inside `powershell -Command`:
   `msiexec /i <msi> /qn /norestart SERVER=… AAT_FILE=<path> /l*v <log>`
7. **Exit code:** 0 succeeded; 3010 and 1641 succeeded with a reboot
   pending; 1638 already installed; 1618 another install is running (retry
   with backoff); 1603 failed, with the log tail attached.
8. **Clean up** the subfolder whatever the outcome, then wait for check-in.

SSH specifics:

- [ ] Host keys go through the existing trusted-host-key flow
      (`ssh_trusted_host_keys`): confirmed before credentials are used, and
      a changed key is a hard stop.
- [ ] Windows OpenSSH's default shell is `cmd`, so PowerShell steps are
      invoked explicitly.

## M4. Windows over WinRM (HTTPS + Kerberos)

- [ ] A minimal WS-Man client on `reqwest` and `quick-xml`: Create Shell,
      Command, **Send** (stdin), Receive, Signal, Delete Shell. No
      PowerShell Remoting protocol.
- [ ] Kerberos through `sspi` (or `libgssapi`, per M0), with channel binding.
- [ ] Certificates verified against the domain CA with rustls. There's no
      "ignore certificate errors" option.
- [ ] **The token file is written over stdin.** WinRM has no SFTP, and a
      command or script that contains the token would be logged. Run a
      fixed script that reads one line from stdin and writes it to the
      file, and send the token with WS-Man Send. This is the same idea as
      `sudo -S` in the Linux deploy.
- [ ] Preflight checks that 5986 answers before trying to authenticate. If
      it doesn't, report "No WinRM HTTPS listener: use GPO or Intune, or
      enable the HTTPS listener", not an authentication failure.
- [ ] Golden-file tests for every SOAP message, and a fake WinRM client for
      the orchestration tests, matching how `ssh_deploy` tests against a
      fake `SshClient`.

## M5. UI, permission and scope

- [ ] Panopticon's **Add hosts** offers Windows, with a choice of WinRM or
      SSH.
- [ ] Only hosts already in inventory, or inside an admin-defined scope,
      can be targeted.
- [ ] A per-job limit on concurrency (default 5, as now) and a per-operator
      limit on how many deploy jobs can start in a time window.
- [ ] Per-host progress and failure reasons on the job page, as for Linux.
- [ ] The permission (see *Open questions*).

## M6. Lab matrix, docs, release

- [ ] Lab matrix: a domain-joined server, a workgroup host (SSH), a host
      with `CbtHardeningLevel=Strict`, and a host with EDR active. On the
      EDR host, record what alerts fire; don't suppress them.
- [ ] Docs: requirements (HTTPS listener, firewall, rights), an example GPO
      that sets up the HTTPS listener with AD CS autoenrollment, and the
      GPO, Intune and MECM alternatives (GPO software installation can't
      pass MSI properties, so it needs a transform or a startup script).
- [ ] CHANGELOG, version bump, `Dev` → `main`, tag.

## Open questions

- **Permission.** `hosts.enroll` already covers Linux **Add hosts**. Reuse
  it, or add a separate one (e.g. `hosts.deploy`) because this takes
  domain credentials? Recommendation: a separate permission, granted to
  admins by default.
- **Linux SSH deploy passes `--enrollment-token` on the command line.**
  Out of scope here, but once M1 lands the same file-based fix applies
  there too.

## Progress

- [ ] M0 `sspi` prototype
- [ ] M1 `AAT_FILE`
- [ ] M2 Deploy core split
- [ ] M3 Windows over OpenSSH
- [ ] M4 Windows over WinRM
- [ ] M5 UI, permission and scope
- [ ] M6 Lab matrix, docs, release
