# Gravekeeper: Active Directory management (roadmap)

**Target:** after 0.2.4. Phases 1 and 2 ship together as the first release.

This plan covers managing Active Directory from Abyssal Arsenal: everything
day to day that Active Directory Users and Computers (ADUC) is used for. That
means users, groups, OUs, onboarding and offboarding, plus mailbox setup in
Exchange or Microsoft 365. Haruspex stays read-only DC health diagnostics,
and Parish stays local users on one host. This is a new, **domain-scoped**
arsenal: **Gravekeeper**, at `/arsenals/gravekeeper`.

It sits in the **Operate** group next to Parish, and uses the Haruspex
DC agents. The name is close to Cryptkeeper (secrets and keys), so the UI
always shows each one's description beside the name.

## Decisions

| Question | Decision |
| --- | --- |
| Name? | **Gravekeeper** (`/arsenals/gravekeeper`). |
| Single domain or forest? | **Both.** One domain works with no extra setup, and a multi-domain forest is supported from the first release (see *Forests*). |
| Exchange / Microsoft 365? | **Yes**, as an optional step of onboarding and offboarding: on-premises Exchange, Exchange hybrid, and cloud-only Microsoft 365 (see *Mail*). |
| Which Exchange version? | **Chosen per installation**, when Gravekeeper is first set up or later in its settings: 2016, 2019 or Subscription Edition (SE), each with its own connection details (see *Mail*). |
| Microsoft 365 licensing? | **Chosen per installation, at setup or later in settings:** group-based, direct, or both. Templates then pick a licensing group, a license (SKU), or both. |
| Where do offboarded accounts go? | **An OU named `Disabled Users` by default** (created, if missing, at setup). It can be changed per domain at setup or later in settings. |
| Whose authority do changes run under? | **A delegated service account, required.** There's no fallback to the agent's SYSTEM account: without a configured, validated account, the arsenal is read-only (see *Service account*). |

## Goals

- Everything day to day in ADUC, from the web UI: find, create, edit,
  enable/disable, unlock, reset passwords, move, and delete users;
  create, edit, and delete groups and manage their members; see the OU tree;
  see computer objects.
- **Onboarding from templates.** A department or role template sets the OU,
  groups, attributes, the username and UPN format, and the mailbox type. The
  admin types a name and a start date, reviews exactly what will be created,
  and confirms.
- **Offboarding in one flow:** disable, remove groups, move to a disabled
  OU, hide from the address list or convert the mailbox, then delete later.
- **Safe by construction:** least privilege, privileged groups out of reach
  by default, passwords never logged, and a full audit trail of who did what.

## Non-goals (first releases)

- Group Policy editing, DNS zone editing (Haruspex diagnoses DNS),
  schema changes, trusts, FSMO moves, sites and services.
- Replacing Entra Connect or a Microsoft 365 admin portal. This creates and
  links accounts, it doesn't run tenant administration.
- Managing Domain Admins, Enterprise Admins and the other privileged
  groups as everyday operations (see *Guardrails*).

## Setup and settings

Gravekeeper has a **first-run setup**, shown the first time someone with
`directory.configure` opens it. Every choice made there can be changed
later at **Settings → Gravekeeper**, a section visible only with
`directory.configure`, following the per-role settings pattern. Each step
can be skipped and finished later; until a domain has a validated service
account, Gravekeeper stays read-only for that domain.

1. **Domain or forest.** Pick a connected DC agent; the forest is
   discovered from it (see *Forests*). Confirm the domains to manage, and
   each one's write DC (the PDC emulator is suggested).
2. **Service account**, per domain (or one for the forest). Enter it, then
   validate it with the delegation check. It's refused if overprivileged,
   and the OUs it can manage are shown (see *Service account*).
3. **Disabled OU**, per domain. The default is `OU=Disabled Users` at the
   domain root, created if it doesn't exist (the service account needs
   create-OU rights there, or an admin creates it). Any OU the account can
   manage can be picked instead.
4. **Deletion grace period:** how long an offboarded account waits in the
   disabled OU before it can be deleted. It's 30 days by default; 0 lets
   "Delete" be offered immediately (still a separate step).
5. **Mail**, per domain: one of the modes below. For on-premises or hybrid
   Exchange, pick **2016, 2019 or Subscription Edition**, then enter the
   server URL and the Recipient Management account. For Microsoft 365, enter
   the tenant, app and certificate, then choose the **licensing method**
   (group-based, direct, or both). Each one has a **Test connection**
   button.
6. **A first template** (optional): a starting department template,
   prefilled from the choices above.

## Architecture

### Where the work runs

- Directory changes run **on a domain controller**, through the agent that
  is already there for Haruspex. They use the `ActiveDirectory` PowerShell
  module that ships with the AD DS role, so there's no LDAPS or Kerberos
  setup on the control plane.
- Each domain has a **write DC**, the PDC emulator by default, and every
  change for that domain goes to it, so changes replicate from one place. If
  the write DC is offline, reads fall back to any connected DC in the
  domain, and changes wait.
- **Typed agent operations, never raw scripts.** For example:
  `DirectoryFind`, `DirectoryGetObject`, `DirectoryCreateUser`,
  `DirectorySetAttributes`, `DirectorySetPassword`, `DirectoryEnable`,
  `DirectoryMove`, `DirectoryGroupMembers`, `DirectoryCreateGroup`,
  `DirectoryDelete`, `DirectoryTestDelegation`.
  - Every field is validated on both sides: distinguished names, the
    sAMAccountName rules, UPN suffixes against the forest's list, and an
    allowlist of attribute names.
  - The PowerShell is fixed text with parameters passed as data, so a value
    can never become code.
  - Output is JSON.
  - The operations get a new protocol version and an entry in the
    `min_protocol` table, like every other operation.
- **Reads can run concurrently; writes are exclusive** (see
  `AgentOperation::runs_concurrently`).

### Service account (required)

- **Per domain** (or one for the whole forest, if the admin has delegated
  it across domains): a username and password, stored encrypted with
  `ENCRYPTION_KEY`, the same way as the AAT and the SNMP communities. Every
  directory operation runs its cmdlets with `-Credential` for that account.
  The agent's SYSTEM identity is **never** used for writes, and no write
  operation runs if no account is configured.
- **Least privilege, delegated by the admin** with ADUC's *Delegate Control*
  wizard on the managed OUs only. The doc ships a script to do it:
  - create, delete and manage user accounts;
  - reset passwords and read/write `pwdLastSet` and `lockoutTime`;
  - manage group membership, for the managed groups' OUs.
- **Validated before it's trusted.** `DirectoryTestDelegation` runs on
  save and every day after:
  - The account must be able to sign in.
  - It must **not** be a member, directly or through nesting, of Domain
    Admins, Enterprise Admins, Schema Admins, Administrators, or Account,
    Server or Backup Operators. If it is, saving is refused with an
    explanation. Overprivilege is exactly what this design avoids.
  - It reports which configured OUs the account can actually create and
    modify users in, by reading their effective permissions, so the UI only
    offers OUs that will work.
  - It warns before the password expires, and offers to rotate it: set a
    new one in AD and update the stored copy in one step.
- **Accountability on both sides.** AD's own Security log shows the
  service account, and Abyssal's audit trail shows the admin who clicked,
  the target object, and the changed attributes (with password values
  removed).
- A group-managed service account (gMSA) isn't possible with `-Credential`.
  It's noted as a later option, through a scheduled-task runner.

### Forests

- **On first connect**, the arsenal discovers the forest:
  `Get-ADForest` and `Get-ADDomain` for each domain, plus the UPN suffixes,
  the global catalogs, and each domain's PDC emulator.
- **Search across the forest** goes through a global catalog (port 3268).
  Each result shows its domain, and changes go to that domain's write DC.
- **Group scope rules are enforced** and explained in the UI:
  - global groups only take members from their own domain;
  - universal groups take members from any domain in the forest;
  - domain-local groups take any member, but can only be used for access in
    their own domain.
- **Templates name a domain**, and the UPN-suffix and OU pickers follow it.
- **A single-domain forest just has one entry**; nothing about forests
  shows up in the UI.

### Mail

Mail is an optional step in templates, onboarding and offboarding. Each
domain picks one of these mail modes at setup or in settings, and can
change it later:

1. **None.** Only the `mail` attribute is set (it can come from a
   pattern).
2. **Exchange on-premises**, version **2016, 2019 or Subscription
   Edition**, as chosen in setup. The version decides which cmdlet
   parameters and behaviours are used, and what the connection test
   expects. It runs through Exchange's remote PowerShell
   (`Microsoft.Exchange` endpoint, Kerberos), run by an agent on a
   domain-joined host that can reach it. It uses its own delegated account
   with only the **Recipient Management** role. Onboarding runs
   `Enable-Mailbox` (database chosen per template, or automatically);
   offboarding hides the mailbox from the address lists, or runs
   `Set-Mailbox -Type Shared` before the account is disabled.
3. **Exchange hybrid**, with the same version choice. The same endpoint,
   or the Exchange management tools (2019 CU12 or later and SE can run
   without an Exchange server), runs `Enable-RemoteMailbox -RemoteRoutingAddress
   user@tenant.mail.onmicrosoft.com`, so the mailbox lives in Exchange
   Online.
   - Then the account has to reach Entra ID. The arsenal can trigger a
     delta sync (`Start-ADSyncSyncCycle -PolicyType Delta`) through an
     agent on the Entra Connect server, if one is managed. Otherwise it
     waits for the next scheduled sync.
   - Then it assigns the license by the method chosen in setup (see
     *Licensing*).
4. **Cloud-only Microsoft 365** (no on-premises Exchange): the control plane
   calls **Microsoft Graph** directly, over HTTPS, with no agent involved.
   - It uses an app registration with **certificate** authentication. The
     certificate's private key is encrypted at rest, and there are no
     client secrets.
   - It needs only the application permissions for what it does:
     `User.ReadWrite.All` (create the user and set usage location) and
     `Organization.Read.All` (to list licenses), plus whatever the chosen
     licensing method needs (see *Licensing*).
   - Exchange Online settings beyond the mailbox's existence (shared
     mailbox conversion, address-list hiding) use Exchange Online
     PowerShell (app-only, certificate). That runs through an agent, with
     the **Exchange Recipient Administrator** role on the app.

#### Licensing (Microsoft 365, hybrid or cloud-only)

The method is chosen at setup or later in settings, per tenant:

- **Group-based:** templates name a licensing group, and onboarding adds
  the user to it, so Microsoft 365 assigns the license. In hybrid, that can
  be an on-premises group that syncs; in cloud-only it's an Entra group,
  through Graph `GroupMember.ReadWrite.All`, limited to the chosen
  licensing groups. This is the recommended method: it needs fewer
  permissions, and licenses follow group membership on offboarding too.
- **Direct:** templates name one or more licenses (SKUs, listed from the
  tenant, with free counts shown), and onboarding assigns them through
  Graph `LicenseAssignment.ReadWrite.All`. Offboarding removes them, or
  keeps them for a shared mailbox, per template.
- **Both:** templates can use either, per template.

The setup step checks the method actually works: the app can read the
licensing groups or the SKUs, and it warns when a chosen license has no
free seats left.

For every mode:

- A **"Test connection"** button checks the credentials and the minimum
  rights, the same way `DirectoryTestDelegation` does.
- Mail steps run **after** the AD step succeeds. Each step is shown, and
  can be retried, in the onboarding job's progress page.
- A mail failure never rolls back the AD account. The job ends as
  "account created, mailbox pending", with a **Retry mail step** button.
- On-premises Exchange and Exchange Online are shown under one "Mail"
  card; the mode decides which actions are offered.

## Guardrails

- **Privileged objects are out of reach by default.** Members of the
  protected groups and objects with `adminCount=1` can't be changed in
  membership, password, enable state or location. The groups themselves
  can't have members added or removed, and built-in accounts
  (`Administrator`, `krbtgt`, `Guest`) can't be touched at all. A separate
  `directory.privileged` permission, granted to nobody by default, lifts
  the first two, never the third. The delegated account usually lacks these
  rights anyway; this is the second layer.
- **Disable before delete.** Offboarding disables the account, strips its
  groups (keeping a record of them, for an undo), and moves it to the
  domain's disabled OU (`Disabled Users` unless changed in settings).
  Deleting is a separate, later step, offered once the grace period from
  settings has passed:
  - it needs typed confirmation;
  - it respects *Protect object from accidental deletion*;
  - it says whether the AD Recycle Bin is on (and so whether a restore is
    possible).
- **Passwords:**
  - Temporary passwords are generated (to the domain's policy, read from
    `Get-ADDefaultDomainPasswordPolicy` and the fine-grained policies) or
    entered by the admin.
  - They're shown once, for the admin to hand over, and always set "must
    change at next logon".
  - They're never stored, logged or audited, and are hidden in the
    operation's `Debug` output, like `Elevate`'s password.
- **Preview before every write.** Create, bulk import, offboard, group
  changes and moves all show the exact list of changes (object, attribute,
  old value → new value) and need confirmation. Destructive steps also
  need typed confirmation.
- **Rate and scope limits.** A bulk import is capped per job (default 200),
  and an operation can only target the OUs the delegation check confirmed.

## Permissions (new)

| Permission | Allows |
| --- | --- |
| `directory.view` | Browse and search users, groups, computers and OUs; read attributes; view templates. |
| `directory.helpdesk` | Unlock, reset passwords (with must-change), enable/disable users. |
| `directory.manage` | Create and edit users and groups, group membership, moves, onboarding and offboarding, templates, bulk import, mail steps. |
| `directory.delete` | Delete users, groups and computer objects. |
| `directory.privileged` | Act on privileged objects (see *Guardrails*). Granted to nobody by default. |
| `directory.configure` | Domains, write DCs, service accounts, mail connections. |

Defaults for the existing roles (a new role-defaults version, so existing
installs get them once and keep their own changes):

- **Super Admin** gets everything except `directory.privileged`, which
  stays an explicit grant.
- **System Admin** gets `view`, `helpdesk` and `manage`.
- **Security / OPSEC Admin** gets `view` and `configure` (it owns the
  service accounts and mail connections).
- **Network Admin** and **Regular User** get nothing.
- `delete` and `privileged` are granted on purpose, per person or role.

A new built-in **Help Desk** role (`view` and `helpdesk` only) is
proposed alongside, for front-line staff who should unlock and reset but
not create or delete.

## Data model

- `directory_domains`: the domain, its NetBIOS name, the write DC host,
  the encrypted service account, the disabled OU (default
  `OU=Disabled Users,<domain root>`), the deletion grace period in days
  (default 30), the mail mode, the last delegation check and its result.
- `directory_mail_connections`: the Exchange version (`2016`, `2019` or
  `se`), endpoint and encrypted account, or the Graph tenant ID, app ID,
  encrypted certificate and licensing method (`group`, `direct` or
  `both`).
- `directory_settings`: whether setup has been completed, and who last
  changed what (each change is also audited).
- `directory_templates`: name, domain, OU, groups, attribute defaults,
  username/UPN/email patterns, mail settings, and whether a manager is
  required.
- `directory_jobs` and `directory_job_steps`: onboarding, offboarding and
  bulk runs, step by step, so they can be retried and checked later.
- `directory_offboard_snapshots`: the groups and OU of an offboarded
  account, for undo.

## Phases

1. **Browse and help desk** (first release, with phase 2):
   - domain, service account and delegation-check setup;
   - forest discovery;
   - the OU tree, and search across the forest;
   - user and group details;
   - unlock, reset password, and enable/disable.
2. **Onboarding** (first release):
   - templates, and creating a user from one with a preview;
   - all four mail modes, with test connection;
   - a job page with step retries.
3. **Groups and offboarding:**
   - create and delete groups, and add/remove members (with the scope
     rules and privileged guard);
   - the offboarding flow and its undo;
   - moving objects;
   - deleting, under its own permission.
4. **Bulk and hygiene:**
   - CSV onboarding with a preview, capped and resumable;
   - a stale-accounts report (no logon in N days), with disable from it;
   - Thanatos integration: a lockout or a privileged-group change event
     gets **Unlock** and **Open in directory** buttons through the workflow
     registry.

## Testing

- **PowerShell:** every operation's script is parsed in CI. Parameter
  passing is tested so hostile input (quotes, `$()`, newlines in a name)
  stays data.
- **Unit tests:**
  - validators: DNs, sAMAccountName, UPN suffixes, the attribute
    allowlist;
  - group-scope rules;
  - the privileged guard (direct and nested membership, `adminCount`,
    built-ins);
  - the template-to-change-set planner (the preview is the plan that gets
    run).
- **A lab forest:** a two-domain lab, with a parent and a child. It covers:
  - a delegated account with and without enough rights, and an
    overprivileged one (which must be refused);
  - onboarding, offboarding and undo, plus cross-domain universal-group
    membership;
  - Exchange 2016, 2019 and Subscription Edition, on-premises and
    hybrid, in the lab (each installation can pick any of them);
  - a Microsoft 365 developer tenant for Graph, with group-based and
    direct licensing both set up;
  - the setup flow end to end: defaults (`Disabled Users`, 30 days)
    accepted, then each one changed later in settings.
- **Secrets:** nothing reaches logs, audit metadata or `Debug`; checked by
  a test that walks the operation's `Debug` and `label()` output for a
  sample password.

## Still open

Nothing blocks starting. The defaults above (the `Disabled Users` OU and a
30-day grace period) can all be changed in settings, and the Exchange
version and licensing method are each installation's own choice.

For testing, the lab needs **all three Exchange versions** (2016, 2019 and
SE) and a Microsoft 365 developer tenant with both a licensing group and
direct SKUs, since every installation can pick any of them.
