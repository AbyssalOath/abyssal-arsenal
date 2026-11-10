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

- [x] Agent: `install --aat-file <path>`. Read the token, delete the file,
      then enroll exactly as `--aat` does. Refuse if both `--aat` and
      `--aat-file` are given, and fail clearly if the file is missing or
      empty.
- [x] `crates/agent/src/installer_args.rs`: translate `AAT_FILE=` like
      `AAT=`, with tests alongside the existing ones.
- [x] `crates/agent/wix/abyssal-agent.wxs`: add `AAT_FILE` (`Secure="yes"`;
      it's a path, so it doesn't need `Hidden`), pass
      `--aat-file "[AAT_FILE]"` from `InstallAgent`, and update the header
      comment.
- [x] Confirm a single-use enrollment token works through the MSI path.
      Linux SSH deploy uses `--enrollment-token`, and the MSI uses `--aat`
      with the CA proof (`aat::key_id`), so check whether the per-host
      token needs `--enrollment-token-file` instead or as well.
- [x] Manual installs keep `AAT=` unchanged.

### As built (M1)

- **The token file is deleted as soon as it's read,** before any network
  call, so it doesn't outlive a failed install. A file that can't be read,
  is empty, or can't be deleted fails the install (exit code 2, bad
  arguments) rather than leave the token on disk.
- **"Both given" is checked after blanks are dropped,** not by clap: the
  MSI always passes `--aat "[AAT]" --aat-file "[AAT_FILE]"`, with an unset
  property as `""`. For the same reason `--aat-file` takes a string, since
  clap's path parser refuses an empty value.
- **The per-host token has to be an install token (AAT format), not a
  single-use enrollment token.** The MSI path never passes `--ca-cert`, so
  on a control plane with an internal CA the only way the agent can verify
  the CA is the AAT proof, which only an AAT-format token produces. So the
  deployer uses `--aat-file`, and `--enrollment-token-file` isn't needed.
  Install tokens have no use limit today, so for M2/M4: mint one per host
  with a short expiry, and either add a single-use option to install
  tokens or revoke the token once the host checks in (or the deploy
  fails).
- **Not yet tested:** the real MSI on a Windows host. CI builds the MSI
  with WiX on push, and the token handling is unit-tested.

## M2. Transport-neutral deploy core

`ssh_deploy.rs` already has the parts this needs: `DeployJob` progress
polling, `run_deploy_job` (a `Semaphore` plus a `JoinSet`), per-host audit,
the `NeverCheckedIn` check-in poll, `Zeroizing` credentials, and fake-client
tests. Move them out so SSH-to-Linux, SSH-to-Windows and WinRM-to-Windows
share them.

- [x] Move the job, concurrency, check-in and audit pieces into a shared
      module. `SshClient` stays as is; WinRM gets its own trait in M4.
- [x] Give `DeployFailureReason` the stage it failed at (connect,
      authenticate, preflight, download, verify, install, check-in).
- [x] Credentials stay `Zeroizing`, the type already used here, in
      `common.rs` and in `elevation.rs`. Don't add `secrecy` for this.
- [x] Every existing `ssh_deploy` test passes unchanged.

### As built (M2)

- **`crates/web/src/host_deploy.rs`** holds the shared parts:
  `CommandResult`, `DeployFailureReason`, `DeployStage`, the job types
  (`DeployJob`, `HostDeployStatus`, `HostDeployState`, `DeployOutcome`),
  `wait_for_checkin`, the per-host audit, and `run_job`. `ssh_deploy.rs`
  keeps everything SSH- and Linux-specific and re-exports the shared types,
  so callers didn't change.
- **`run_job` takes one future per host** (paired with its IP) rather than
  a client trait. Each transport builds its futures however it likes;
  `ssh_deploy::run_deploy_job` is now a thin wrapper with its old
  signature. A future does nothing until its turn under the concurrency
  limit, and a per-host token is zeroed when its future finishes.
- **The stage is tracked beside the reason, not inside it.**
  `DeployFailureReason` is unchanged; `DeployOutcome` and
  `HostDeployStatus` gained `failed_stage`, set by the deploy as it moves
  through its steps (SSH connects and authenticates in one step, so the
  reason decides between those two). The status page shows "Failed at
  download: ..." and the `HostDeployFailed` audit row records the stage.
  Putting the stage inside the reason would have changed every existing
  test's expected value.
- **Tests:** every existing `ssh_deploy` test passes with its assertions
  unchanged. The two that build a `HostDeployStatus` by hand (and one
  helper in `panopticon_deploy.rs`) gained `failed_stage: None`. New tests
  cover the stage reported at each step.
- **For M3:** `DeployFailureReason::NeverCheckedIn`'s message still
  suggests `systemctl status abyssal-agent`. It needs a Windows wording
  (`Get-Service AbyssalAgent`) once Windows targets exist. The token-file
  write is counted as the install stage.

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

- [x] Host keys go through the existing trusted-host-key flow
      (`ssh_trusted_host_keys`): confirmed before credentials are used, and
      a changed key is a hard stop.
- [x] Windows OpenSSH's default shell is `cmd`, so PowerShell steps are
      invoked explicitly.

### As built (M3)

- **`crates/web/src/windows_deploy.rs`** holds the on-host scripts (for M4
  to reuse), `deploy_one_host` over SSH, `mint_deploy_token`, and
  `run_ssh_deploy_job`, which goes through `host_deploy::run_job`. It isn't
  reachable from the UI yet: **Add hosts** offering Windows is M5.
- **Every step is `powershell.exe -EncodedCommand`,** including the
  install (`Start-Process msiexec … -Wait -PassThru`, exiting with its
  code), rather than `msiexec` typed straight into the SSH channel. That
  works whether the host's OpenSSH default shell is `cmd` or PowerShell, and
  needs no quoting for either. No script holds a secret; the token is only
  named, by its file.
- **The MSI is copied over SFTP, not downloaded by the host.** The SSH
  session is already authenticated with a pinned host key, and an HTTPS
  download would need the host to trust the control plane's internal CA,
  which Windows PowerShell can't easily be told to do for one request. So
  there's no short-lived per-host download URL yet; **M4 still needs one**
  (WinRM has no file transfer), along with that CA problem.
- **Verification is the SHA-256 of the exact bytes the control plane sent.**
  Release MSIs aren't Authenticode-signed yet (`release.yml` doesn't sign),
  so the signature can't be required. Setting
  `AGENT_MSI_SIGNER_THUMBPRINT` turns on the signed-and-from-this-signer
  check (`Get-AuthenticodeSignature`); without it, the deploy output says
  the signature wasn't checked. **Signing the MSI in CI** is the follow-up
  that makes the check mandatory.
- **Token:** a per-host install token (AAT format, per the M1 note), no
  approval step, expiring in an hour, **revoked as soon as that host's
  deploy ends**, whatever the outcome. It shows in the install-token list
  as "Push deploy to <ip>". Written over SFTP; the agent deletes the file
  on reading it, and the cleanup removes the folder regardless.
- **Staging folder:** `%ProgramData%\Abyssal` must be a real folder (not a
  link) owned by SYSTEM or Administrators, with protected permissions
  granting only those two. A missing one is created that way (owner set to
  Administrators, so the next deploy's check passes). Each deploy then
  creates `deploy-<random>` inside it, which must not already exist.
- **Preflight** also requires a local administrator (a new
  `NotAdministrator` reason), AMD64, and 200 MB free on the system drive,
  and records any agent already installed. The host's own name
  (`[Net.Dns]::GetHostName()`) becomes the agent's `NAME` and the check-in
  key.
- **Exit codes:** 1618 is retried twice (after 30 s, then 60 s) before
  `InstallerBusy`; 3010/1641 count as installed, with "wants a reboot" in
  the output; 1638 goes on to the check-in, which decides; anything else
  fails with the last 25 lines of the MSI log.
- **New failure reasons:** `UploadFailed`, `NotAdministrator`,
  `StagingFolderUnsafe`, `VerifyFailed`, `InstallerBusy`.
  `NeverCheckedIn` now names `Get-Service abyssal-agent` for Windows beside
  `systemctl` for Linux.
- **Tests:** a fake session that decodes each `-EncodedCommand` and answers
  per script covers the happy path (the token only ever in an SFTP write,
  never in a script or the output), not an administrator, an unsafe staging
  folder, a hash mismatch (no token written, no install), a failed install
  with the log tail, 1618 retries, and 1618-then-3010. Every on-host script
  is run through PowerShell's parser (required in CI; run locally here
  through the `mcr.microsoft.com/powershell` image).
- **Not tested here:** a real Windows host over OpenSSH. Things to check in
  the lab: that SFTP takes `/C:/ProgramData/...` paths, that `Set-Acl` can
  set the owner to Administrators from an SSH session, and that the
  session's token is elevated for a local administrator (it is for password
  logons; check key-based logons too).

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

- [x] Panopticon's **Add hosts** offers Windows, with a choice of WinRM or
      SSH. (SSH only until M4; the page says WinRM isn't available yet.)
- [x] Only hosts already in inventory, or inside an admin-defined scope,
      can be targeted. (Inventory only; no separate scope setting.)
- [x] A per-job limit on concurrency (default 5, as now) and a per-operator
      limit on how many deploy jobs can start in a time window.
- [x] Per-host progress and failure reasons on the job page, as for Linux.
- [x] The permission (see *Open questions*).

### As built (M5)

- **Permission:** `hosts.deploy`, needed (on top of `hosts.enroll`) to push
  to Windows. Granted to the built-in System Admin role (role defaults v5)
  and, as always, Super Admin. Linux **Add hosts** stays on `hosts.enroll`
  alone, so no existing role lost anything.
- **Flow:** the existing Windows page (install commands for the selected
  hosts) gains **Push over SSH**, shown only with `hosts.deploy`. It leads
  into the same credentials, host-key review and status pages as Linux,
  with `target_os=windows` carried between steps and re-checked (with the
  permission) at every step. The Windows credentials form drops the sudo
  fields and asks for a local administrator. The deploy itself is M3's
  `windows_deploy::run_ssh_deploy_job`; the MSI is loaded (and hashed)
  before anything else, so a control plane with no MSI to serve stops with
  a message instead of starting a job.
- **Scope:** every step checks that each IP is in Panopticon's inventory
  (`network_devices`), Linux included: the IPs round-trip through the
  browser, so a typed-in one mustn't get credentials sent to it. Scan
  results are saved to the inventory before the picker shows them, so this
  doesn't change the normal flow. An admin-defined CIDR scope wasn't added:
  the inventory is already the set of hosts someone chose to scan.
- **Limits:** at most 50 hosts per job; "Hosts at once" on the credentials
  form (1-10, default 5); at most 5 jobs per operator per 10 minutes,
  counted in memory when a job starts.
- **Not tested here:** the pages in a browser against a real Windows host.
  Render tests cover the Windows page with and without `hosts.deploy` and
  the Windows credentials form.

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

- ~~**Permission.**~~ Decided: a separate `hosts.deploy` (see M5's as-built
  notes).
- ~~**Linux SSH deploy passes `--enrollment-token` on the command line.**~~
  Done alongside M1: the token goes over stdin into a file in a private,
  random staging directory (`mkdir -m 700`, so it can't be pre-created) and
  the install uses `--enrollment-token-file`. The staging directory used to
  be a fixed `/tmp` path, which also let another local user swap the binary
  `sudo` runs; the random directory fixes that too. M3's Windows-over-SSH
  staging folder follows the same rules.

## Progress

- [ ] M0 `sspi` prototype
- [x] M1 `AAT_FILE`
- [x] M2 Deploy core split
- [x] M3 Windows over OpenSSH (backend; UI is M5)
- [ ] M4 Windows over WinRM
- [x] M5 UI, permission and scope
- [ ] M6 Lab matrix, docs, release
