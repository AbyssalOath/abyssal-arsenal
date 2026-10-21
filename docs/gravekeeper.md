# Gravekeeper: Active Directory management

Gravekeeper is the Operate group's **directory** arsenal -- everything day to
day that Active Directory Users and Computers (ADUC) is used for, from the web
UI: find, create, edit, enable/disable, unlock, reset passwords, move and delete
users; create and delete groups and manage membership; see the OU tree and
computer objects; onboard from templates (singly or in bulk) with mailbox
provisioning; and offboard in one flow with an undo. It is **domain-scoped** and
works across a multi-domain forest.

Gravekeeper is deliberately narrow in a few directions:

> **Haruspex** stays read-only DC/DNS health diagnostics.
> **Parish** stays local users on one host.
> **Gravekeeper** manages the directory itself.

Directory changes run **on a domain controller**, through the same agent
Haruspex already uses, with the `ActiveDirectory` PowerShell module that ships
with the AD DS role -- so there is no LDAPS or Kerberos plumbing on the control
plane. It is **Windows-only**: every operation returns
`process::platform_unsupported()` on anything else.

This document covers what Gravekeeper owns and deliberately does not, how and
where its work runs, the agent-operation whitelist, the permission/role model,
the required delegated service account and its guardrails, each capability
(browse, help desk, onboarding, mail, bulk, groups, move/delete, offboarding,
stale accounts), the Thanatos hand-off, the data model, how secrets are handled,
the known limitations, and how to test it manually.

Gravekeeper's UI is the same server-rendered HTML + POST/redirect/GET the rest
of the app uses; there is no hand-written client-side JavaScript.

## Responsibilities

| Concern | Owner |
| --- | --- |
| AD users/groups/OUs/computers: find, create, edit, enable/disable, unlock, reset password, move, delete | **Gravekeeper** |
| Onboarding (templates, create-from-template, bulk CSV) and offboarding (+ undo) | **Gravekeeper** |
| Mailbox provisioning as part of on/offboarding: Exchange on-prem/hybrid, Microsoft 365 | **Gravekeeper** |
| The delegated service account per domain and the mail-connection secrets | **Gravekeeper** (encrypted at rest with `ENCRYPTION_KEY`) |
| DC / DNS health diagnostics | **Haruspex** (read-only; Gravekeeper reuses its DC agents) |
| Local (non-domain) users on a single host | **Parish** |
| Secrets/keys/certs on a host | **Cryptkeeper** |
| Long-term SIEM/EDR, correlation, alerting | **Thanatos** (Gravekeeper is a jump-off target, not a consumer) |

## Hard boundaries (what Gravekeeper does *not* do)

- **No Group Policy, DNS zone, schema, trust, FSMO, or sites-and-services
  editing.** Haruspex diagnoses DNS; Gravekeeper does not edit zones.
- **It doesn't replace Entra Connect or a Microsoft 365 admin portal.** It
  creates and licenses accounts; it doesn't run tenant administration.
- **Privileged groups are not everyday objects.** Domain/Enterprise/Schema
  Admins, Administrators and the Operators groups, `adminCount=1` objects, and
  the built-in `Administrator`/`krbtgt`/`Guest` accounts are out of reach by
  default (see *Guardrails*).

## Where the work runs

- Each managed **domain** is bound to a **write DC** (the PDC emulator by
  default) -- a connected, Windows, host-agent host. Every change for that
  domain is an ordinary `execute_on_host()` dispatch to that DC's agent.
- **Writes run under a delegated service account's `-Credential`**, never the
  agent's SYSTEM identity. Reads (browse, search, the stale report) run under
  the agent's own identity, which is sufficient on a DC.
- **Microsoft 365 is the one exception** that leaves the agent model: the
  control plane calls Microsoft Graph directly over HTTPS with certificate auth
  (`crates/web/src/gravekeeper_graph.rs`), because a cloud tenant has no host to
  dispatch to. Exchange Online shared-mailbox/hide for cloud-only is a noted
  gap (see *Known limitations*).
- **Typed agent operations, never raw scripts.** Every value is validated on
  both sides (DNs, sAMAccountName rules, UPN suffixes, an attribute allowlist),
  and PowerShell is fixed text with untrusted values passed as single-quoted
  literals (`process::ps_quote`) -- a value can never become code. Output is
  JSON. Passwords travel over **stdin**, never argv, never a log line, and are
  redacted in each operation's hand-written `Debug`.
- **Reads run concurrently; writes are exclusive** (`AgentOperation::runs_concurrently`).

## The agent-operation whitelist

New in protocol **47**. All are Windows-only (Unix returns
`platform_unsupported()`); `Debug` redacts every password.

| Operation | Kind | What it does |
| --- | --- | --- |
| `DirectoryDiscoverForest` | Read | Forest root, domains (DNS/NetBIOS/PDC), UPN suffixes, GCs |
| `DirectoryTestDelegation` | Read | Validate a service account: can bind, not privileged, which OUs it can manage |
| `DirectoryOuTree` | Read | The domain's OU hierarchy |
| `DirectorySearch` | Read | ANR search for users/groups/computers (query LDAP-escaped) |
| `DirectoryGetObject` | Read | One object's detail (+ memberships / members, with DNs) |
| `DirectoryStaleAccounts` | Read | Enabled users with no logon in N days (or never) |
| `DirectoryUnlockAccount` | Write | Unlock a user |
| `DirectorySetEnabled` | Write | Enable / disable a user |
| `DirectorySetPassword` | Write | Reset password, must change at next logon |
| `DirectoryCreateUser` | Write | Create a user from a change-set (collision-resolve sAMAccountName) |
| `DirectoryCreateGroup` | Write | Create a group (scope + category) |
| `DirectoryDeleteGroup` | Write | Delete a group |
| `DirectoryAddGroupMember` / `DirectoryRemoveGroupMember` | Write | Membership (scope rules + privileged guard) |
| `DirectoryMove` | Write | Move an object to another OU |
| `DirectoryDeleteObject` | Write | Delete a user/group/computer (respects accidental-deletion protection) |
| `DirectoryOffboard` / `DirectoryUndoOffboard` | Write | Offboard (disable/strip/move) and undo |
| `ExchangeTestConnection` | Read | Test an on-prem/hybrid Exchange remote-PS connection |
| `ExchangeEnableMailbox` | Write | `Enable-Mailbox` (on-prem) / `Enable-RemoteMailbox` (hybrid) |
| `ExchangeSetMailboxOffboard` | Write | Hide from address lists / convert to shared |

## Permissions and roles

Six new permissions, finer-grained than a view/manage pair because directory
work spans front-line help desk through destructive and privileged changes:

| Permission | Allows |
| --- | --- |
| `directory.view` | Browse/search; read attributes; view templates |
| `directory.helpdesk` | Unlock, reset password (must-change), enable/disable |
| `directory.manage` | Create/edit users and groups, membership, moves, onboarding/offboarding, templates, bulk |
| `directory.delete` | Delete users, groups and computer objects |
| `directory.privileged` | Act on protected objects (see *Guardrails*); granted to nobody by default |
| `directory.configure` | Domains, write DCs, service accounts, mail connections |

Role defaults (seeded fresh and applied once to existing installs via
role-defaults **v4**):

- **System Admin** -> `view`, `helpdesk`, `manage`.
- **Security / OPSEC Admin** -> `view`, `configure` (it owns the service
  accounts and mail connections).
- A new built-in **Help Desk** role -> `view`, `helpdesk` only.
- `directory.delete` and `directory.privileged` are deliberately granted to
  nobody -- they are explicit, per-person/per-role grants.
- **Super Admin** holds all six, like every permission: `has_no_ceiling()` is
  *computed* from Super Admin holding literally all of `Permission::ALL`, so it
  cannot be excluded from one without breaking Super Admin's ability to edit
  roles. "Granted to nobody by default" is about every *other* role.

## The service account (required)

- **Per domain** (or one account delegated across the forest): a username (UPN)
  and password, stored encrypted with `ENCRYPTION_KEY` (the same mechanism AAT
  install tokens and SNMP communities use). Every write runs its cmdlets with
  `-Credential` for that account.
- **Least privilege, validated before trusted.** `DirectoryTestDelegation` runs
  on save and refuses the account if it **cannot bind** or **is a member
  (directly or nested) of a privileged group** (Domain/Enterprise/Schema
  Admins, Administrators, Account/Server/Backup Operators -- matched by SID, not
  localized name). It reports the OUs the account can actually manage. Only on a
  pass is the password sealed and stored and the domain made writable.
- **Re-validated daily.** `spawn_gravekeeper_delegation_recheck` decrypts and
  re-runs the check for each domain, flipping it back to read-only if the
  account later drifts into a privileged group or stops binding (see
  ARCHITECTURE's Background tasks).
- **Credential re-targeting is refused.** A stored credential is tied to a
  specific write DC / Exchange host. Changing a domain's write DC clears the
  stored service-account credential (forcing re-validation on the new DC), and
  the mail-connection save refuses a blank-password change of the Exchange URI /
  account / agent host -- so a stored secret can never be silently pointed at a
  new, unvetted destination.

## Browsing

`/arsenals/gravekeeper/domains/:id/browse` (`directory.view`) shows the OU tree
(indented by DN depth) and a per-domain search; results link to an object-detail
page (attributes plus a user's group memberships or a group's members, each
carrying its DN). A cross-domain **Find** page
(`/arsenals/gravekeeper/find?q=`) searches every connected domain at once.

## Help-desk actions

On a user's detail page, with `directory.helpdesk` and a writable domain:
**Unlock**, **Enable/Disable**, and **Reset password**. A reset generates a
strong temporary password (shown once) and always sets *must change at next
logon*; the password is never stored, logged or audited.

### Guardrails

Enforced agent-side, at the execution boundary:

- **Built-in accounts** (`Administrator`/`krbtgt`/`Guest`, RID 500/501/502)
  cannot be modified at all.
- **Protected objects** (`adminCount=1`, or a privileged well-known group)
  cannot be changed in membership, password, enable state or location, and
  protected groups cannot gain/lose members, unless the caller holds
  `directory.privileged`.

## Onboarding

- **Templates** (`directory.manage`) fix the OU, groups, attribute defaults, the
  username/UPN/email patterns (`{first}`/`{last}`/`{f}`/`{l}` tokens), the
  mailbox mode, and whether a manager is required.
- **Create from template** asks for a name, computes the exact change-set, shows
  it for **preview**, and on confirm recomputes server-side (never trusting the
  client), creates the user (resolving a free sAMAccountName), sets a temporary
  password (shown once, must-change), and records an **onboarding job**.
- **Jobs** record each step; a failed **mail step** can be **retried** without
  re-creating the AD account.
- **Bulk CSV** (`/onboard/bulk`): paste `First,Last` rows, preview the planned
  logons (capped by `gravekeeper.bulk_import_cap`, default 200), create them as
  one bulk job (a step per row, each user's temp password shown once), and
  **retry failed rows**.

### Mail

Each domain's mail connection (`directory.configure`) picks one mode, with a
**Test connection** button:

1. **None** -- only the `mail` attribute is set (from the template's pattern).
2. **Exchange on-premises** (2016 / 2019 / SE) -- remote PowerShell from a
   domain-joined agent host under a Recipient Management account;
   `Enable-Mailbox`.
3. **Exchange hybrid** -- `Enable-RemoteMailbox -RemoteRoutingAddress
   <user>@<routing-domain>`.
4. **Microsoft 365** (cloud) -- the control plane calls Microsoft Graph with an
   app registration and **certificate** auth (no client secret): it finds the
   synced user, sets the usage location, and licenses it **group-based** (adds
   to a licensing group) or **direct** (assigns a SKU), per the template.

A mail failure never rolls back the AD account: the onboarding job ends
"partial" and the mail step is retriable.

## Groups, moves, offboarding

- **Groups** (`directory.manage`): create (scope global/universal/domain-local,
  category security/distribution) and delete (`directory.delete`); add/remove
  members with the **scope rules** (a global group only takes same-domain
  members; a universal group any forest domain) and the privileged-group guard.
- **Move** an object to another OU (`directory.manage`); **delete** a
  user/computer (`directory.delete`) -- which **respects *protect from
  accidental deletion*** (the cmdlet refuses and the message is surfaced; the
  flag is never cleared) and reports whether the **AD Recycle Bin** is enabled.
- **Offboard** a user in one flow (`directory.manage`): disable, strip its
  groups (captured in a snapshot), move it to the domain's disabled OU, and hide
  its mailbox -- recorded as an offboard job. **Undo** re-enables it, restores
  the groups, and moves it back. Deleting is a separate, later step.

## Stale accounts

`/arsenals/gravekeeper/domains/:id/stale?days=N` (`directory.view`) lists
enabled users whose replicated `LastLogonDate` is older than N days (or who have
never logged on), with an inline **Disable** (`directory.helpdesk`).

## Thanatos hand-off

A Thanatos security-scan alert surfaces an **"Open in directory (Gravekeeper)"**
button through the workflow registry, which lands on Gravekeeper's cross-domain
Find so an operator can jump from an alert straight to the account and act.
(Thanatos's suggestion carries only a count + alerted flag, not the specific
locked-out account, so there is no pre-filled account or one-click Unlock yet --
that would need Thanatos to surface the account; see *Known limitations*.)

## Data model

- `directory_domains` -- the managed domains: DNS/NetBIOS/forest, write DC,
  sealed service account, disabled OU, deletion grace period, mail mode, last
  delegation result.
- `directory_mail_connections` -- one per domain: Exchange version/URI/sealed
  account/agent host/routing domain, or the M365 tenant/app/sealed certificate/
  licensing method.
- `directory_templates` -- onboarding templates (OU, patterns, groups, attribute
  defaults, mail settings incl. M365 licensing).
- `directory_jobs` / `directory_job_steps` -- onboarding/offboarding/bulk runs,
  step by step, with retry context (`target_upn`, `template_id`, bulk
  `payload_json`).
- `directory_offboard_snapshots` -- original OU + stripped groups for undo.

## How secrets are handled

Service-account passwords and the M365 certificate are sealed with
`ENCRYPTION_KEY` (AES-256-GCM), stored as ciphertext, and decrypted only to
dispatch. Passwords reach the agent in the operation (over the authenticated,
TLS-pinned control-plane channel) and are piped to PowerShell over **stdin**,
never argv; every operation's hand-written `Debug` redacts them, so they never
reach a log or the audit trail. Temporary passwords generated for new users are
shown once and never stored.

## Known limitations

- The agent AD/Exchange PowerShell paths and the Microsoft 365 Graph path are
  written to spec but have not been exercised against a live directory/tenant in
  this project's sandbox -- **validate in a lab** before production use.
- **Microsoft 365 Exchange Online** actions beyond licensing (shared-mailbox
  conversion, address-list hiding for cloud-only) are not wired yet: the
  offboard mail step records a clear "skipped" for `m365` domains. On-prem and
  hybrid Exchange hide/convert do work.
- The **deletion grace period** is surfaced but not strictly enforced on the
  delete path (delete isn't yet blocked until the grace window elapses).
- Windows is required; there is no Linux/macOS directory backend.
- A group-managed service account (gMSA) isn't usable with `-Credential`; a
  standard delegated account is required.

## Manual test steps

A two-domain lab (parent + child) with a delegated account is the target
environment.

1. **Setup.** Discover the forest from a connected DC, add a domain, and enter a
   service account. Confirm an **overprivileged** account (in Domain Admins) is
   refused, and a correctly delegated one is accepted and the domain becomes
   writable. Change the write DC and confirm the stored credential is cleared.
2. **Browse.** Confirm the OU tree, search, and user/group detail render; cross-
   domain Find returns results from both domains.
3. **Help desk.** Unlock, reset a password (shown once, must-change), and
   enable/disable a test user. Confirm a built-in account and an `adminCount=1`
   account are refused without `directory.privileged`.
4. **Onboarding.** Create a template; onboard a user with a preview; confirm the
   temp password shows once and the job records the steps. Break the mail step
   and confirm the job is "partial" and the mail step retries.
5. **Mail.** For each configured mode, Test connection; onboard a user and
   confirm the mailbox/licence. (M365 needs a developer tenant + app cert.)
6. **Bulk.** Paste a CSV over and under the cap; confirm the cap is enforced,
   the preview flags bad rows, created users list their passwords once, and
   failed rows retry.
7. **Groups.** Create/delete a group; add a cross-domain member to a global
   group and confirm it's refused; confirm protected-group membership needs
   `directory.privileged`.
8. **Move/delete.** Move an object; delete a user (confirm accidental-deletion
   protection is respected and the Recycle Bin state is reported).
9. **Offboard.** Offboard a user (disabled, stripped, moved, mailbox hidden),
   then **undo** and confirm it is re-enabled, re-grouped and moved back.
10. **Stale + Thanatos.** Run the stale report and disable from it; from a
    Thanatos alert, confirm the "Open in directory" button lands on Find.
