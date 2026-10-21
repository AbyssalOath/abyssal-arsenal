//! Gravekeeper: Active Directory management, run on a domain controller
//! through the `ActiveDirectory` PowerShell module. Windows-only; anything
//! else returns `platform_unsupported()`.
//!
//! Phase 1 ships two read-only operations:
//!
//! - [`discover_forest`] (`DirectoryDiscoverForest`) runs under the agent's own
//!   identity and reports the forest: root, every domain (DNS/NetBIOS/PDC), the
//!   UPN suffixes and the global catalogs.
//! - [`test_delegation`] (`DirectoryTestDelegation`) validates a delegated
//!   service account: that it can bind, that it is **not** a member (directly or
//!   nested) of the privileged groups, and which OUs it can actually create
//!   users in. The password arrives in the operation and is piped to PowerShell
//!   over **stdin** -- never argv, never a log line.
//!
//! Both emit JSON on stdout (the control plane parses it). Untrusted values
//! (the domain FQDN and the service-account UPN) are validated here, as a second
//! layer after the control plane, and interpolated only as single-quoted
//! PowerShell literals (`process::ps_quote`), never as code.

use abyssal_agent_protocol::CommandOutcome;
#[cfg(windows)]
use abyssal_agent_protocol::{is_valid_hostname, is_valid_ldap_dn, is_valid_user_principal_name};

/// `DirectoryDiscoverForest`: forest/domain topology as JSON.
#[cfg(windows)]
pub async fn discover_forest() -> CommandOutcome {
    // Fixed script; no untrusted interpolation. Runs under the agent's own
    // (SYSTEM) identity -- discovery is a read and needs no -Credential.
    let script = crate::process::ps_checked(
        "$forest = Get-ADForest; \
         $domains = @(); \
         foreach ($d in $forest.Domains) { \
           try { \
             $dom = Get-ADDomain -Identity $d; \
             $domains += [ordered]@{ dns = $dom.DNSRoot; netbios = $dom.NetBIOSName; pdc = $dom.PDCEmulator; forest_root = $forest.RootDomain } \
           } catch { \
             $domains += [ordered]@{ dns = \"$d\"; netbios = $null; pdc = $null; forest_root = $forest.RootDomain; error = \"$_\" } \
           } \
         }; \
         $result = [ordered]@{ forest_root = $forest.RootDomain; upn_suffixes = @($forest.UPNSuffixes | ForEach-Object { \"$_\" }); global_catalogs = @($forest.GlobalCatalogs | ForEach-Object { \"$_\" }); domains = $domains }; \
         $result | ConvertTo-Json -Compress -Depth 5",
    );
    run_powershell(&script).await
}

/// `DirectoryTestDelegation`: validate a delegated service account. Output JSON:
/// `{ ok, domain, account_found, overprivileged_groups: [..], manageable_ous: [..] }`.
#[cfg(windows)]
pub async fn test_delegation(
    domain_dns: String,
    service_account_upn: String,
    password: String,
) -> CommandOutcome {
    if !is_valid_hostname(&domain_dns) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {domain_dns}"));
    }
    if !is_valid_user_principal_name(&service_account_upn) {
        return CommandOutcome::Err(format!(
            "refusing invalid service-account UPN: {service_account_upn}"
        ));
    }

    // The two untrusted values become single-quoted PowerShell literals. The
    // password is NOT in the script -- it is read from stdin at runtime.
    let upn_lit = crate::process::ps_quote(&service_account_upn);
    let server_lit = crate::process::ps_quote(&domain_dns);
    let body = format!(
        "$pw = [Console]::In.ReadLine(); \
         $sec = ConvertTo-SecureString -String $pw -AsPlainText -Force; \
         $upn = {upn_lit}; \
         $server = {server_lit}; \
         $cred = New-Object System.Management.Automation.PSCredential($upn, $sec); \
         $dom = Get-ADDomain -Server $server -Credential $cred; \
         $domSid = $dom.DomainSID.Value; \
         $acct = Get-ADUser -Server $server -Credential $cred -LDAPFilter \"(&(objectClass=user)(userPrincipalName=$upn))\" -Properties objectSid; \
         if (-not $acct) {{ \
           $out = [ordered]@{{ ok = $false; domain = $dom.DNSRoot; account_found = $false; overprivileged_groups = @(); manageable_ous = @() }}; \
           $out | ConvertTo-Json -Compress -Depth 5; return \
         }}; \
         $groups = @(Get-ADAccountAuthorizationGroups -Server $server -Credential $cred -Identity $acct.DistinguishedName); \
         $acctSids = @($acct.objectSid.Value) + @($groups | ForEach-Object {{ $_.SID.Value }}); \
         $protected = @(\"$domSid-512\",\"$domSid-518\",\"$domSid-519\",\"S-1-5-32-544\",\"S-1-5-32-548\",\"S-1-5-32-549\",\"S-1-5-32-551\"); \
         $over = @($groups | Where-Object {{ $protected -contains $_.SID.Value }} | ForEach-Object {{ $_.Name }}); \
         $userClass = [GUID]'bf967aba-0de6-11d0-a285-00aa003049e2'; \
         $manageable = @(); \
         $ous = @(Get-ADOrganizationalUnit -Server $server -Credential $cred -Filter * -ResultSetSize 500); \
         foreach ($ou in $ous) {{ \
           try {{ \
             $acl = (Get-Acl -Path (\"AD:\\\" + $ou.DistinguishedName)).Access; \
             foreach ($ace in $acl) {{ \
               if ($ace.AccessControlType -ne 'Allow') {{ continue }}; \
               $sid = $null; \
               try {{ $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }} catch {{ continue }}; \
               if ($acctSids -notcontains $sid) {{ continue }}; \
               $rights = $ace.ActiveDirectoryRights.ToString(); \
               $createsUsers = ($rights -match 'CreateChild' -and ($ace.ObjectType -eq [GUID]::Empty -or $ace.ObjectType -eq $userClass)) -or ($rights -match 'GenericAll'); \
               if ($createsUsers) {{ $manageable += $ou.DistinguishedName; break }} \
             }} \
           }} catch {{ }} \
         }}; \
         $out = [ordered]@{{ ok = ($over.Count -eq 0); domain = $dom.DNSRoot; account_found = $true; overprivileged_groups = @($over); manageable_ous = @($manageable) }}; \
         $out | ConvertTo-Json -Compress -Depth 5"
    );
    let script = crate::process::ps_checked(&body);
    run_powershell_with_password(&script, &password).await
}

/// `DirectoryOuTree`: the domain's OUs (DN + name) as JSON. Read-only, runs
/// under the agent's own identity.
#[cfg(windows)]
pub async fn ou_tree(domain_dns: String) -> CommandOutcome {
    if !is_valid_hostname(&domain_dns) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {domain_dns}"));
    }
    let server_lit = crate::process::ps_quote(&domain_dns);
    let script = crate::process::ps_checked(&format!(
        "$server = {server_lit}; \
         Get-ADOrganizationalUnit -Server $server -Filter * -ResultSetSize 2000 \
         | Select-Object Name, DistinguishedName | Sort-Object DistinguishedName \
         | ConvertTo-Json -Depth 3"
    ));
    run_powershell(&script).await
}

/// `DirectorySearch`: users/groups/computers matching `query` (ANR) as JSON.
/// `query` is free text, so it is LDAP-escaped before it reaches a filter.
#[cfg(windows)]
pub async fn search(domain_dns: String, query: String) -> CommandOutcome {
    if !is_valid_hostname(&domain_dns) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {domain_dns}"));
    }
    let trimmed = query.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return CommandOutcome::Err("search query must be 1-256 characters".to_string());
    }
    let server_lit = crate::process::ps_quote(&domain_dns);
    let query_lit = crate::process::ps_quote(trimmed);
    // $q is a safe single-quoted literal; $esc LDAP-escapes the five filter
    // metacharacters so the value is only ever matched as data in `(anr=...)`.
    let script = crate::process::ps_checked(&format!(
        "$server = {server_lit}; \
         $q = {query_lit}; \
         $esc = $q -replace '\\\\','\\5c' -replace '\\*','\\2a' -replace '\\(','\\28' -replace '\\)','\\29' -replace '/','\\2f'; \
         $filter = \"(anr=$esc)\"; \
         $users = @(Get-ADUser -Server $server -LDAPFilter $filter -ResultSetSize 50 -Properties DisplayName,Enabled,UserPrincipalName | ForEach-Object {{ [ordered]@{{ type='user'; name=$_.Name; sam=$_.SamAccountName; upn=$_.UserPrincipalName; dn=$_.DistinguishedName; enabled=$_.Enabled; display=$_.DisplayName }} }}); \
         $groups = @(Get-ADGroup -Server $server -LDAPFilter $filter -ResultSetSize 50 | ForEach-Object {{ [ordered]@{{ type='group'; name=$_.Name; sam=$_.SamAccountName; dn=$_.DistinguishedName }} }}); \
         $computers = @(Get-ADComputer -Server $server -LDAPFilter $filter -ResultSetSize 50 -Properties Enabled | ForEach-Object {{ [ordered]@{{ type='computer'; name=$_.Name; sam=$_.SamAccountName; dn=$_.DistinguishedName; enabled=$_.Enabled }} }}); \
         @($users + $groups + $computers) | ConvertTo-Json -Depth 3"
    ));
    run_powershell(&script).await
}

/// `DirectoryGetObject`: full detail of one object by DN as JSON (user, group or
/// computer), with group memberships (user) or members (group).
#[cfg(windows)]
pub async fn get_object(domain_dns: String, dn: String) -> CommandOutcome {
    if !is_valid_hostname(&domain_dns) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {domain_dns}"));
    }
    if !is_valid_ldap_dn(&dn) {
        return CommandOutcome::Err(format!("refusing invalid distinguished name: {dn}"));
    }
    let server_lit = crate::process::ps_quote(&domain_dns);
    let dn_lit = crate::process::ps_quote(&dn);
    let script = crate::process::ps_checked(&format!(
        "$server = {server_lit}; \
         $dn = {dn_lit}; \
         $u = Get-ADUser -Server $server -Identity $dn -Properties DisplayName,Enabled,LockedOut,Description,EmailAddress,Department,Title,UserPrincipalName,whenCreated,LastLogonDate,MemberOf -ErrorAction SilentlyContinue; \
         if ($u) {{ \
           $groups = @($u.MemberOf | ForEach-Object {{ try {{ $og=Get-ADGroup -Server $server -Identity $_; [ordered]@{{ name=$og.Name; dn=$og.DistinguishedName }} }} catch {{ [ordered]@{{ name=\"$_\"; dn=\"$_\" }} }} }}); \
           $out = [ordered]@{{ type='user'; name=$u.Name; sam=$u.SamAccountName; upn=$u.UserPrincipalName; dn=$u.DistinguishedName; display=$u.DisplayName; enabled=$u.Enabled; locked=$u.LockedOut; description=$u.Description; email=$u.EmailAddress; department=$u.Department; title=$u.Title; created=\"$($u.whenCreated)\"; last_logon=\"$($u.LastLogonDate)\"; groups=$groups }}; \
           $out | ConvertTo-Json -Depth 4; return \
         }}; \
         $g = Get-ADGroup -Server $server -Identity $dn -Properties Description,GroupScope,GroupCategory,Members,MemberOf -ErrorAction SilentlyContinue; \
         if ($g) {{ \
           $members = @($g.Members | Select-Object -First 200 | ForEach-Object {{ try {{ $om=Get-ADObject -Server $server -Identity $_; [ordered]@{{ name=$om.Name; dn=$om.DistinguishedName }} }} catch {{ [ordered]@{{ name=\"$_\"; dn=\"$_\" }} }} }}); \
           $out = [ordered]@{{ type='group'; name=$g.Name; sam=$g.SamAccountName; dn=$g.DistinguishedName; description=$g.Description; scope=\"$($g.GroupScope)\"; category=\"$($g.GroupCategory)\"; members=$members }}; \
           $out | ConvertTo-Json -Depth 4; return \
         }}; \
         $c = Get-ADComputer -Server $server -Identity $dn -Properties Enabled,Description,OperatingSystem,DNSHostName -ErrorAction SilentlyContinue; \
         if ($c) {{ \
           $out = [ordered]@{{ type='computer'; name=$c.Name; sam=$c.SamAccountName; dn=$c.DistinguishedName; enabled=$c.Enabled; description=$c.Description; os=$c.OperatingSystem; dns=$c.DNSHostName }}; \
           $out | ConvertTo-Json -Depth 4; return \
         }}; \
         throw \"object not found: $dn\""
    ));
    run_powershell(&script).await
}

// --- Help-desk writes (run under the delegated service account) ------------

/// The shared script preamble for a help-desk write: read the service-account
/// password from stdin, build its `-Credential`, resolve the target user, and
/// enforce the guardrails (built-in accounts refused outright; an
/// `adminCount=1` protected target refused unless `allow_privileged`). Leaves
/// `$cred`, `$server`, `$dn` and `$target` in scope for the caller's action.
#[cfg(windows)]
fn cred_and_guard(server_lit: &str, upn_lit: &str, dn_lit: &str, allow_privileged: bool) -> String {
    let allow = if allow_privileged { "$true" } else { "$false" };
    format!(
        "$sapw = [Console]::In.ReadLine(); \
         $sec = ConvertTo-SecureString -String $sapw -AsPlainText -Force; \
         $upn = {upn_lit}; $server = {server_lit}; $dn = {dn_lit}; \
         $cred = New-Object System.Management.Automation.PSCredential($upn, $sec); \
         $target = Get-ADUser -Server $server -Credential $cred -Identity $dn -Properties objectSid,adminCount; \
         if (-not $target) {{ throw 'target user not found' }}; \
         $tsid = $target.SID.Value; \
         if ($tsid -match '-(500|501|502)$') {{ throw 'refused: a built-in account (Administrator/krbtgt/Guest) cannot be modified' }}; \
         if ($target.adminCount -eq 1 -and -not {allow}) {{ throw 'refused: protected/privileged object (adminCount=1) requires directory.privileged' }}; "
    )
}

/// Validates the three identifiers every help-desk write shares.
#[cfg(windows)]
fn validate_write(domain_dns: &str, upn: &str, target_dn: &str) -> Result<(), String> {
    if !is_valid_hostname(domain_dns) {
        return Err(format!("refusing invalid AD domain: {domain_dns}"));
    }
    if !is_valid_user_principal_name(upn) {
        return Err(format!("refusing invalid service-account UPN: {upn}"));
    }
    if !is_valid_ldap_dn(target_dn) {
        return Err(format!("refusing invalid target DN: {target_dn}"));
    }
    Ok(())
}

/// The credential preamble (no object lookup): read the service-account password
/// from stdin and build `$cred`/`$server`.
#[cfg(windows)]
fn cred_preamble(server_lit: &str, upn_lit: &str) -> String {
    format!(
        "$sapw = [Console]::In.ReadLine(); \
         $sec = ConvertTo-SecureString -String $sapw -AsPlainText -Force; \
         $upn = {upn_lit}; $server = {server_lit}; \
         $cred = New-Object System.Management.Automation.PSCredential($upn, $sec); "
    )
}

/// A PowerShell snippet that loads the group at `$gdn` into `$grp` and throws if
/// it is protected (adminCount=1 or a privileged well-known group) unless
/// `allow_privileged`.
#[cfg(windows)]
fn group_guard(allow_privileged: bool) -> String {
    let allow = if allow_privileged { "$true" } else { "$false" };
    format!(
        "$grp = Get-ADGroup -Server $server -Credential $cred -Identity $gdn -Properties adminCount,groupScope; \
         $gsid = $grp.SID.Value; \
         if ((($grp.adminCount -eq 1) -or ($gsid -match '-(512|518|519|544|548|549|551)$')) -and -not {allow}) {{ \
           throw 'refused: protected/privileged group; needs directory.privileged' }}; "
    )
}

/// A PowerShell snippet that loads the object at `$dn` into `$o` and throws if
/// it is a built-in account (RID 500/501/502, refused outright) or protected
/// (adminCount=1) without `allow_privileged`.
#[cfg(windows)]
fn object_guard(allow_privileged: bool) -> String {
    let allow = if allow_privileged { "$true" } else { "$false" };
    format!(
        "$o = Get-ADObject -Server $server -Credential $cred -Identity $dn -Properties adminCount,objectSid; \
         if (-not $o) {{ throw 'object not found' }}; \
         $osid = $null; try {{ $osid = $o.objectSid.Value }} catch {{ }}; \
         if ($osid -and ($osid -match '-(500|501|502)$')) {{ throw 'refused: a built-in account (Administrator/krbtgt/Guest) cannot be modified' }}; \
         if (($o.adminCount -eq 1) -and -not {allow}) {{ throw 'refused: protected/privileged object (adminCount=1); needs directory.privileged' }}; "
    )
}

/// `DirectoryMove`.
#[cfg(windows)]
pub async fn move_object(
    domain_dns: String,
    service_account_upn: String,
    service_account_password: String,
    target_dn: String,
    new_parent_ou: String,
    allow_privileged: bool,
) -> CommandOutcome {
    if let Err(e) = validate_write(&domain_dns, &service_account_upn, &target_dn) {
        return CommandOutcome::Err(e);
    }
    if !is_valid_ldap_dn(&new_parent_ou) {
        return CommandOutcome::Err(format!("refusing invalid destination OU: {new_parent_ou}"));
    }
    let preamble = cred_preamble(
        &crate::process::ps_quote(&domain_dns),
        &crate::process::ps_quote(&service_account_upn),
    );
    let guard = object_guard(allow_privileged);
    let script = crate::process::ps_checked(&format!(
        "{preamble} $dn = {dn}; $ou = {ou}; {guard} \
         Move-ADObject -Server $server -Credential $cred -Identity $dn -TargetPath $ou; \
         Write-Output 'Object moved.'",
        dn = crate::process::ps_quote(&target_dn),
        ou = crate::process::ps_quote(&new_parent_ou),
    ));
    run_ps_stdin(&script, &format!("{service_account_password}\n")).await
}

/// `DirectoryDeleteObject`. Respects *Protect object from accidental deletion*
/// (Remove-ADObject refuses; the error is surfaced). Reports the Recycle Bin
/// state so the UI can say whether a restore is possible.
#[cfg(windows)]
pub async fn delete_object(
    domain_dns: String,
    service_account_upn: String,
    service_account_password: String,
    target_dn: String,
    allow_privileged: bool,
) -> CommandOutcome {
    if let Err(e) = validate_write(&domain_dns, &service_account_upn, &target_dn) {
        return CommandOutcome::Err(e);
    }
    let preamble = cred_preamble(
        &crate::process::ps_quote(&domain_dns),
        &crate::process::ps_quote(&service_account_upn),
    );
    let guard = object_guard(allow_privileged);
    let script = crate::process::ps_checked(&format!(
        "{preamble} $dn = {dn}; {guard} \
         $rb = $false; try {{ $rb = ((Get-ADOptionalFeature -Server $server -Credential $cred -Filter \"name -eq 'Recycle Bin Feature'\").EnabledScopes.Count -gt 0) }} catch {{ }}; \
         Remove-ADObject -Server $server -Credential $cred -Identity $dn -Confirm:$false; \
         [ordered]@{{ ok = $true; recycle_bin = $rb }} | ConvertTo-Json -Compress",
        dn = crate::process::ps_quote(&target_dn),
    ));
    run_ps_stdin(&script, &format!("{service_account_password}\n")).await
}

/// `DirectoryOffboard`: disable, strip groups (capturing them), move to the
/// disabled OU. Returns the snapshot the control plane stores for undo.
#[cfg(windows)]
pub async fn offboard(
    domain_dns: String,
    service_account_upn: String,
    service_account_password: String,
    target_dn: String,
    disabled_ou: String,
    allow_privileged: bool,
) -> CommandOutcome {
    if let Err(e) = validate_write(&domain_dns, &service_account_upn, &target_dn) {
        return CommandOutcome::Err(e);
    }
    if !is_valid_ldap_dn(&disabled_ou) {
        return CommandOutcome::Err(format!("refusing invalid disabled OU: {disabled_ou}"));
    }
    let preamble = cred_preamble(
        &crate::process::ps_quote(&domain_dns),
        &crate::process::ps_quote(&service_account_upn),
    );
    let guard = object_guard(allow_privileged);
    let script = crate::process::ps_checked(&format!(
        "{preamble} $dn = {dn}; $disabled = {disabled}; {guard} \
         $u = Get-ADUser -Server $server -Credential $cred -Identity $dn -Properties MemberOf; \
         $origou = ($dn -split ',',2)[1]; $leaf = ($dn -split ',',2)[0]; \
         Disable-ADAccount -Server $server -Credential $cred -Identity $dn; \
         $removed = @(); \
         foreach ($g in @($u.MemberOf)) {{ try {{ Remove-ADGroupMember -Server $server -Credential $cred -Identity $g -Members $dn -Confirm:$false; $removed += $g }} catch {{ }} }}; \
         Move-ADObject -Server $server -Credential $cred -Identity $dn -TargetPath $disabled; \
         $newdn = \"$leaf,$disabled\"; \
         [ordered]@{{ original_ou = $origou; groups = @($removed); new_dn = $newdn }} | ConvertTo-Json -Compress",
        dn = crate::process::ps_quote(&target_dn),
        disabled = crate::process::ps_quote(&disabled_ou),
    ));
    run_ps_stdin(&script, &format!("{service_account_password}\n")).await
}

/// Arguments for [`undo_offboard`].
#[cfg_attr(not(windows), allow(dead_code))]
pub struct UndoOffboardArgs {
    pub domain_dns: String,
    pub service_account_upn: String,
    pub service_account_password: String,
    pub target_dn: String,
    pub original_ou: String,
    pub groups: Vec<String>,
    pub allow_privileged: bool,
}

/// `DirectoryUndoOffboard`: move back to the original OU, re-add the captured
/// groups, and re-enable.
#[cfg(windows)]
pub async fn undo_offboard(args: UndoOffboardArgs) -> CommandOutcome {
    if let Err(e) = validate_write(&args.domain_dns, &args.service_account_upn, &args.target_dn) {
        return CommandOutcome::Err(e);
    }
    if !is_valid_ldap_dn(&args.original_ou) {
        return CommandOutcome::Err(format!(
            "refusing invalid original OU: {}",
            args.original_ou
        ));
    }
    for g in &args.groups {
        if !is_valid_ldap_dn(g) {
            return CommandOutcome::Err(format!("refusing invalid group DN: {g}"));
        }
    }
    let preamble = cred_preamble(
        &crate::process::ps_quote(&args.domain_dns),
        &crate::process::ps_quote(&args.service_account_upn),
    );
    let guard = object_guard(args.allow_privileged);
    let groups_arr = if args.groups.is_empty() {
        "@()".to_string()
    } else {
        let items: Vec<String> = args
            .groups
            .iter()
            .map(|g| crate::process::ps_quote(g))
            .collect();
        format!("@({})", items.join(","))
    };
    let script = crate::process::ps_checked(&format!(
        "{preamble} $dn = {dn}; $origou = {origou}; {guard} \
         $leaf = ($dn -split ',',2)[0]; \
         Move-ADObject -Server $server -Credential $cred -Identity $dn -TargetPath $origou; \
         $newdn = \"$leaf,$origou\"; \
         foreach ($g in {groups}) {{ try {{ Add-ADGroupMember -Server $server -Credential $cred -Identity $g -Members $newdn -Confirm:$false }} catch {{ }} }}; \
         Enable-ADAccount -Server $server -Credential $cred -Identity $newdn; \
         Write-Output 'Offboarding undone.'",
        dn = crate::process::ps_quote(&args.target_dn),
        origou = crate::process::ps_quote(&args.original_ou),
        groups = groups_arr,
    ));
    run_ps_stdin(&script, &format!("{}\n", args.service_account_password)).await
}

/// `ExchangeSetMailboxOffboard`: hide from address lists, optionally convert to
/// a shared mailbox, through Exchange remote PowerShell.
#[cfg(windows)]
pub async fn exchange_set_mailbox_offboard(
    uri: String,
    account_upn: String,
    account_password: String,
    target_identity: String,
    convert_to_shared: bool,
) -> CommandOutcome {
    if !is_valid_exchange_uri(&uri) {
        return CommandOutcome::Err(format!("refusing invalid Exchange connection URI: {uri}"));
    }
    if !is_valid_user_principal_name(&account_upn) {
        return CommandOutcome::Err(format!("refusing invalid Exchange account: {account_upn}"));
    }
    if !is_valid_user_principal_name(&target_identity) {
        return CommandOutcome::Err(format!(
            "refusing invalid mailbox identity: {target_identity}"
        ));
    }
    let preamble = exchange_session(
        &crate::process::ps_quote(&uri),
        &crate::process::ps_quote(&account_upn),
    );
    let id_lit = crate::process::ps_quote(&target_identity);
    let convert = if convert_to_shared {
        format!("Set-Mailbox -Identity {id_lit} -Type Shared | Out-Null; ")
    } else {
        String::new()
    };
    let script = crate::process::ps_checked(&format!(
        "{preamble} try {{ \
           Import-PSSession $s -DisableNameChecking -AllowClobber -CommandName Set-Mailbox | Out-Null; \
           {convert}Set-Mailbox -Identity {id_lit} -HiddenFromAddressListsEnabled $true | Out-Null; \
           [ordered]@{{ ok = $true }} | ConvertTo-Json -Compress \
         }} finally {{ Remove-PSSession $s }}"
    ));
    run_ps_stdin(&script, &format!("{account_password}\n")).await
}

/// Arguments for [`create_group`].
#[cfg_attr(not(windows), allow(dead_code))]
pub struct CreateGroupArgs {
    pub domain_dns: String,
    pub service_account_upn: String,
    pub service_account_password: String,
    pub name: String,
    pub target_ou: String,
    pub scope: String,
    pub category: String,
    pub description: String,
}

/// Maps the wire scope/category to the exact AD cmdlet values (allowlisted, so
/// safe to inline into the script).
#[cfg(windows)]
fn group_scope_value(scope: &str) -> Option<&'static str> {
    match scope {
        "global" => Some("Global"),
        "universal" => Some("Universal"),
        "domainlocal" => Some("DomainLocal"),
        _ => None,
    }
}

#[cfg(windows)]
fn group_category_value(category: &str) -> Option<&'static str> {
    match category {
        "security" => Some("Security"),
        "distribution" => Some("Distribution"),
        _ => None,
    }
}

/// `DirectoryCreateGroup`.
#[cfg(windows)]
pub async fn create_group(args: CreateGroupArgs) -> CommandOutcome {
    if !is_valid_hostname(&args.domain_dns) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {}", args.domain_dns));
    }
    if !is_valid_user_principal_name(&args.service_account_upn) {
        return CommandOutcome::Err(format!(
            "refusing invalid service-account UPN: {}",
            args.service_account_upn
        ));
    }
    let name = abyssal_agent_protocol::sanitize_sam_account_name(&args.name);
    if !abyssal_agent_protocol::is_valid_sam_account_name(&name) {
        return CommandOutcome::Err("the group name is not a valid account name".to_string());
    }
    if !args.target_ou.is_empty() && !is_valid_ldap_dn(&args.target_ou) {
        return CommandOutcome::Err(format!("refusing invalid target OU: {}", args.target_ou));
    }
    let Some(scope) = group_scope_value(&args.scope) else {
        return CommandOutcome::Err(format!("invalid group scope: {}", args.scope));
    };
    let Some(category) = group_category_value(&args.category) else {
        return CommandOutcome::Err(format!("invalid group category: {}", args.category));
    };
    let preamble = cred_preamble(
        &crate::process::ps_quote(&args.domain_dns),
        &crate::process::ps_quote(&args.service_account_upn),
    );
    let mut params = format!(
        "$params = @{{ Name = {name}; SamAccountName = {name}; GroupScope = '{scope}'; \
         GroupCategory = '{category}'; Server = $server; Credential = $cred }}; ",
        name = crate::process::ps_quote(&name),
    );
    if !args.target_ou.is_empty() {
        params.push_str(&format!(
            "$params['Path'] = {}; ",
            crate::process::ps_quote(&args.target_ou)
        ));
    }
    if !args.description.trim().is_empty() {
        params.push_str(&format!(
            "$params['Description'] = {}; ",
            crate::process::ps_quote(args.description.trim())
        ));
    }
    let script = crate::process::ps_checked(&format!(
        "{preamble} {params} $g = New-ADGroup @params -PassThru; \
         [ordered]@{{ dn = $g.DistinguishedName; name = $g.Name }} | ConvertTo-Json -Compress"
    ));
    run_ps_stdin(&script, &format!("{}\n", args.service_account_password)).await
}

/// `DirectoryDeleteGroup`.
#[cfg(windows)]
pub async fn delete_group(
    domain_dns: String,
    service_account_upn: String,
    service_account_password: String,
    target_dn: String,
    allow_privileged: bool,
) -> CommandOutcome {
    if let Err(e) = validate_write(&domain_dns, &service_account_upn, &target_dn) {
        return CommandOutcome::Err(e);
    }
    let preamble = cred_preamble(
        &crate::process::ps_quote(&domain_dns),
        &crate::process::ps_quote(&service_account_upn),
    );
    let gdn = crate::process::ps_quote(&target_dn);
    let guard = group_guard(allow_privileged);
    let script = crate::process::ps_checked(&format!(
        "{preamble} $gdn = {gdn}; {guard} \
         Remove-ADGroup -Server $server -Credential $cred -Identity $gdn -Confirm:$false; \
         Write-Output 'Group deleted.'"
    ));
    run_ps_stdin(&script, &format!("{service_account_password}\n")).await
}

/// Which way a membership change goes.
pub enum GroupMemberChange {
    Add,
    Remove,
}

/// `DirectoryAddGroupMember` / `DirectoryRemoveGroupMember`. Add enforces the
/// group-scope rules; both enforce the privileged-group guard.
#[cfg(windows)]
pub async fn change_group_member(
    change: GroupMemberChange,
    domain_dns: String,
    service_account_upn: String,
    service_account_password: String,
    group_dn: String,
    member_dn: String,
    allow_privileged: bool,
) -> CommandOutcome {
    if !is_valid_hostname(&domain_dns) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {domain_dns}"));
    }
    if !is_valid_user_principal_name(&service_account_upn) {
        return CommandOutcome::Err(format!(
            "refusing invalid service-account UPN: {service_account_upn}"
        ));
    }
    if !is_valid_ldap_dn(&group_dn) {
        return CommandOutcome::Err(format!("refusing invalid group DN: {group_dn}"));
    }
    if !is_valid_ldap_dn(&member_dn) {
        return CommandOutcome::Err(format!("refusing invalid member DN: {member_dn}"));
    }
    let preamble = cred_preamble(
        &crate::process::ps_quote(&domain_dns),
        &crate::process::ps_quote(&service_account_upn),
    );
    let gdn = crate::process::ps_quote(&group_dn);
    let mdn = crate::process::ps_quote(&member_dn);
    let guard = group_guard(allow_privileged);

    let (action, msg) = match change {
        GroupMemberChange::Add => (
            // Scope rule: a global group only accepts same-domain members.
            "if ($grp.GroupScope -eq 'Global') { \
               $gdom = (($gdn -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_ -replace '^DC=','' }) -join '.'); \
               $mdom = (($mdn -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_ -replace '^DC=','' }) -join '.'); \
               if ($gdom -ne $mdom) { throw \"a global group only takes members from its own domain ($gdom); the member is in $mdom\" } \
             }; \
             Add-ADGroupMember -Server $server -Credential $cred -Identity $gdn -Members $mdn -Confirm:$false"
                .to_string(),
            "Member added.",
        ),
        GroupMemberChange::Remove => (
            "Remove-ADGroupMember -Server $server -Credential $cred -Identity $gdn -Members $mdn -Confirm:$false".to_string(),
            "Member removed.",
        ),
    };
    let script = crate::process::ps_checked(&format!(
        "{preamble} $gdn = {gdn}; $mdn = {mdn}; {guard} {action}; Write-Output '{msg}'"
    ));
    run_ps_stdin(&script, &format!("{service_account_password}\n")).await
}

/// `DirectoryUnlockAccount`.
#[cfg(windows)]
pub async fn unlock_account(
    domain_dns: String,
    service_account_upn: String,
    service_account_password: String,
    target_dn: String,
    allow_privileged: bool,
) -> CommandOutcome {
    if let Err(e) = validate_write(&domain_dns, &service_account_upn, &target_dn) {
        return CommandOutcome::Err(e);
    }
    let preamble = cred_and_guard(
        &crate::process::ps_quote(&domain_dns),
        &crate::process::ps_quote(&service_account_upn),
        &crate::process::ps_quote(&target_dn),
        allow_privileged,
    );
    let script = crate::process::ps_checked(&format!(
        "{preamble} Unlock-ADAccount -Server $server -Credential $cred -Identity $dn; \
         Write-Output 'Account unlocked.'"
    ));
    run_ps_stdin(&script, &format!("{service_account_password}\n")).await
}

/// `DirectorySetEnabled`.
#[cfg(windows)]
pub async fn set_enabled(
    domain_dns: String,
    service_account_upn: String,
    service_account_password: String,
    target_dn: String,
    enabled: bool,
    allow_privileged: bool,
) -> CommandOutcome {
    if let Err(e) = validate_write(&domain_dns, &service_account_upn, &target_dn) {
        return CommandOutcome::Err(e);
    }
    let preamble = cred_and_guard(
        &crate::process::ps_quote(&domain_dns),
        &crate::process::ps_quote(&service_account_upn),
        &crate::process::ps_quote(&target_dn),
        allow_privileged,
    );
    let (cmdlet, msg) = if enabled {
        ("Enable-ADAccount", "Account enabled.")
    } else {
        ("Disable-ADAccount", "Account disabled.")
    };
    let script = crate::process::ps_checked(&format!(
        "{preamble} {cmdlet} -Server $server -Credential $cred -Identity $dn; \
         Write-Output '{msg}'"
    ));
    run_ps_stdin(&script, &format!("{service_account_password}\n")).await
}

/// `DirectorySetPassword`: reset + require change at next logon. Two secrets on
/// stdin: the service-account password, then the new password.
#[cfg(windows)]
pub async fn set_password(
    domain_dns: String,
    service_account_upn: String,
    service_account_password: String,
    target_dn: String,
    new_password: String,
    allow_privileged: bool,
) -> CommandOutcome {
    if let Err(e) = validate_write(&domain_dns, &service_account_upn, &target_dn) {
        return CommandOutcome::Err(e);
    }
    if new_password.is_empty() {
        return CommandOutcome::Err("refusing to set an empty password".to_string());
    }
    let preamble = cred_and_guard(
        &crate::process::ps_quote(&domain_dns),
        &crate::process::ps_quote(&service_account_upn),
        &crate::process::ps_quote(&target_dn),
        allow_privileged,
    );
    let script = crate::process::ps_checked(&format!(
        "{preamble} $newpw = [Console]::In.ReadLine(); \
         $nsec = ConvertTo-SecureString -String $newpw -AsPlainText -Force; \
         Set-ADAccountPassword -Server $server -Credential $cred -Identity $dn -Reset -NewPassword $nsec; \
         Set-ADUser -Server $server -Credential $cred -Identity $dn -ChangePasswordAtLogon $true; \
         Write-Output 'Password reset; the user must change it at next logon.'"
    ));
    // Service-account password first, the new password second -- the script's
    // two ReadLine() calls consume them in that order. Neither is ever argv.
    run_ps_stdin(
        &script,
        &format!("{service_account_password}\n{new_password}\n"),
    )
    .await
}

/// Arguments for [`create_user`] -- a struct to keep the op's many fields
/// together (and the dispatch arm readable). The fields are read only in the
/// Windows implementation; the Unix stub ignores them.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct CreateUserArgs {
    pub domain_dns: String,
    pub service_account_upn: String,
    pub service_account_password: String,
    pub target_ou: String,
    pub sam_base: String,
    pub upn_suffix: String,
    pub given_name: String,
    pub surname: String,
    pub display_name: String,
    pub email: String,
    pub password: String,
    pub attributes: Vec<(String, String)>,
    pub groups: Vec<String>,
    pub allow_privileged: bool,
}

/// Attribute names set from their own fields (or never settable at create via
/// OtherAttributes), skipped if they appear in the template's attribute list.
#[cfg(windows)]
const RESERVED_CREATE_ATTRS: &[&str] = &[
    "samaccountname",
    "userprincipalname",
    "givenname",
    "sn",
    "displayname",
    "name",
    "cn",
    "unicodepwd",
    "useraccountcontrol",
];

/// `DirectoryCreateUser`: create a user from a template's change-set.
#[cfg(windows)]
pub async fn create_user(args: CreateUserArgs) -> CommandOutcome {
    if !is_valid_hostname(&args.domain_dns) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {}", args.domain_dns));
    }
    if !is_valid_user_principal_name(&args.service_account_upn) {
        return CommandOutcome::Err(format!(
            "refusing invalid service-account UPN: {}",
            args.service_account_upn
        ));
    }
    if !is_valid_hostname(&args.upn_suffix) {
        return CommandOutcome::Err(format!("refusing invalid UPN suffix: {}", args.upn_suffix));
    }
    let sam_base = abyssal_agent_protocol::sanitize_sam_account_name(&args.sam_base);
    if !abyssal_agent_protocol::is_valid_sam_account_name(&sam_base) {
        return CommandOutcome::Err("the computed logon name is not valid".to_string());
    }
    if args.password.is_empty() {
        return CommandOutcome::Err("refusing to create a user with an empty password".to_string());
    }
    if !args.target_ou.is_empty() && !is_valid_ldap_dn(&args.target_ou) {
        return CommandOutcome::Err(format!("refusing invalid target OU: {}", args.target_ou));
    }
    for g in &args.groups {
        if !is_valid_ldap_dn(g) {
            return CommandOutcome::Err(format!("refusing invalid group DN: {g}"));
        }
    }

    // OtherAttributes hashtable statements, skipping reserved/unknown names.
    let mut other_stmts = String::new();
    for (k, v) in &args.attributes {
        let kl = k.to_lowercase();
        if RESERVED_CREATE_ATTRS.contains(&kl.as_str()) {
            continue;
        }
        if !abyssal_agent_protocol::is_writable_ad_user_attribute(k) {
            return CommandOutcome::Err(format!("refusing non-allowlisted attribute: {k}"));
        }
        other_stmts.push_str(&format!(
            "$other[{}]={};",
            crate::process::ps_quote(k),
            crate::process::ps_quote(v)
        ));
    }

    // Groups as a PowerShell array literal.
    let groups_arr = if args.groups.is_empty() {
        "@()".to_string()
    } else {
        let items: Vec<String> = args
            .groups
            .iter()
            .map(|g| crate::process::ps_quote(g))
            .collect();
        format!("@({})", items.join(","))
    };
    let allow = if args.allow_privileged {
        "$true"
    } else {
        "$false"
    };

    let body = format!(
        "$sapw = [Console]::In.ReadLine(); \
         $newpw = [Console]::In.ReadLine(); \
         $sec = ConvertTo-SecureString -String $sapw -AsPlainText -Force; \
         $nsec = ConvertTo-SecureString -String $newpw -AsPlainText -Force; \
         $server = {server}; $saupn = {saupn}; \
         $cred = New-Object System.Management.Automation.PSCredential($saupn, $sec); \
         $base = {base}; $suffix = {suffix}; $targetOu = {targetou}; \
         $given = {given}; $surname = {surname}; $display = {display}; $email = {email}; \
         $allow = {allow}; \
         $sam = $base; $n = 1; \
         while (Get-ADUser -Server $server -Credential $cred -LDAPFilter \"(sAMAccountName=$sam)\" -ErrorAction SilentlyContinue) {{ \
           $n++; $cand = \"$base$n\"; if ($cand.Length -gt 20) {{ $cand = $cand.Substring(0,20) }}; $sam = $cand; \
           if ($n -gt 50) {{ throw 'could not find a free sAMAccountName' }} \
         }}; \
         $upn = \"$sam@$suffix\"; \
         $name = if ($display) {{ $display }} else {{ $sam }}; \
         $other = @{{}}; {other} \
         $params = @{{ Name = $name; SamAccountName = $sam; UserPrincipalName = $upn; \
           AccountPassword = $nsec; Enabled = $true; ChangePasswordAtLogon = $true; \
           Server = $server; Credential = $cred }}; \
         if ($given) {{ $params['GivenName'] = $given }}; \
         if ($surname) {{ $params['Surname'] = $surname }}; \
         if ($display) {{ $params['DisplayName'] = $display }}; \
         if ($email) {{ $params['EmailAddress'] = $email }}; \
         if ($targetOu) {{ $params['Path'] = $targetOu }}; \
         if ($other.Count -gt 0) {{ $params['OtherAttributes'] = $other }}; \
         New-ADUser @params; \
         foreach ($gdn in {groups}) {{ \
           $grp = Get-ADGroup -Server $server -Credential $cred -Identity $gdn -Properties adminCount; \
           $gsid = $grp.SID.Value; \
           $prot = ($grp.adminCount -eq 1) -or ($gsid -match '-(512|518|519|544|548|549|551)$'); \
           if ($prot -and -not $allow) {{ throw \"refused: group $gdn is protected (adminCount=1 or a privileged group); needs directory.privileged\" }}; \
           Add-ADGroupMember -Server $server -Credential $cred -Identity $gdn -Members $sam \
         }}; \
         [ordered]@{{ sam = $sam; upn = $upn; created = $true }} | ConvertTo-Json -Compress",
        server = crate::process::ps_quote(&args.domain_dns),
        saupn = crate::process::ps_quote(&args.service_account_upn),
        base = crate::process::ps_quote(&sam_base),
        suffix = crate::process::ps_quote(&args.upn_suffix),
        targetou = crate::process::ps_quote(&args.target_ou),
        given = crate::process::ps_quote(&args.given_name),
        surname = crate::process::ps_quote(&args.surname),
        display = crate::process::ps_quote(&args.display_name),
        email = crate::process::ps_quote(&args.email),
        allow = allow,
        other = other_stmts,
        groups = groups_arr,
    );
    let script = crate::process::ps_checked(&body);
    run_ps_stdin(
        &script,
        &format!("{}\n{}\n", args.service_account_password, args.password),
    )
    .await
}

/// `DirectoryStaleAccounts`: enabled users with no logon in `days` days (or
/// never), as JSON. Read-only, under the agent's own identity.
#[cfg(windows)]
pub async fn stale_accounts(domain_dns: String, days: u32) -> CommandOutcome {
    if !is_valid_hostname(&domain_dns) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {domain_dns}"));
    }
    let days = days.min(100_000); // bound; the value is interpolated as a number
    let server_lit = crate::process::ps_quote(&domain_dns);
    let script = crate::process::ps_checked(&format!(
        "$server = {server_lit}; $cut = (Get-Date).AddDays(-{days}); \
         $stale = @(Get-ADUser -Server $server -Filter 'Enabled -eq $true' -Properties LastLogonDate,DisplayName -ResultSetSize 2000 \
           | Where-Object {{ (-not $_.LastLogonDate) -or ($_.LastLogonDate -lt $cut) }} \
           | ForEach-Object {{ [ordered]@{{ name=$_.Name; sam=$_.SamAccountName; upn=$_.UserPrincipalName; dn=$_.DistinguishedName; last_logon = $(if ($_.LastLogonDate) {{ \"$($_.LastLogonDate)\" }} else {{ '' }}) }} }}); \
         @($stale) | ConvertTo-Json -Depth 3"
    ));
    run_powershell(&script).await
}

#[cfg(not(windows))]
pub async fn stale_accounts(_domain_dns: String, _days: u32) -> CommandOutcome {
    crate::process::platform_unsupported()
}

// --- Exchange mail (on-prem / hybrid, remote PowerShell) -------------------

/// An Exchange remote-PowerShell connection URI: http(s), bounded, no control
/// characters. The value is passed to `New-PSSession -ConnectionUri` as a
/// single-quoted literal; this is the up-front sanity check.
#[cfg(windows)]
fn is_valid_exchange_uri(uri: &str) -> bool {
    (uri.starts_with("http://") || uri.starts_with("https://"))
        && uri.len() <= 512
        && !uri.chars().any(|c| c.is_control())
}

/// The shared Exchange remote-session preamble: read the account password from
/// stdin, build its `-Credential`, and open a Kerberos
/// `Microsoft.Exchange` session as `$s`. The caller imports the cmdlets it needs
/// and must `Remove-PSSession $s` in a `finally`.
#[cfg(windows)]
fn exchange_session(uri_lit: &str, acct_lit: &str) -> String {
    format!(
        "$pw = [Console]::In.ReadLine(); \
         $sec = ConvertTo-SecureString -String $pw -AsPlainText -Force; \
         $acct = {acct_lit}; $uri = {uri_lit}; \
         $cred = New-Object System.Management.Automation.PSCredential($acct, $sec); \
         $s = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $uri -Authentication Kerberos -Credential $cred; "
    )
}

/// `ExchangeTestConnection`.
#[cfg(windows)]
pub async fn exchange_test_connection(
    uri: String,
    account_upn: String,
    account_password: String,
) -> CommandOutcome {
    if !is_valid_exchange_uri(&uri) {
        return CommandOutcome::Err(format!("refusing invalid Exchange connection URI: {uri}"));
    }
    if !is_valid_user_principal_name(&account_upn) {
        return CommandOutcome::Err(format!("refusing invalid Exchange account: {account_upn}"));
    }
    let preamble = exchange_session(
        &crate::process::ps_quote(&uri),
        &crate::process::ps_quote(&account_upn),
    );
    let script = crate::process::ps_checked(&format!(
        "{preamble} try {{ \
           Import-PSSession $s -DisableNameChecking -AllowClobber -CommandName Get-OrganizationConfig | Out-Null; \
           $org = Get-OrganizationConfig; \
           [ordered]@{{ ok = $true; org = \"$($org.Name)\" }} | ConvertTo-Json -Compress \
         }} finally {{ Remove-PSSession $s }}"
    ));
    run_ps_stdin(&script, &format!("{account_password}\n")).await
}

/// `ExchangeEnableMailbox`: on-prem `Enable-Mailbox` (empty routing address) or
/// hybrid `Enable-RemoteMailbox -RemoteRoutingAddress`.
#[cfg(windows)]
pub async fn exchange_enable_mailbox(
    uri: String,
    account_upn: String,
    account_password: String,
    target_identity: String,
    remote_routing_address: String,
) -> CommandOutcome {
    if !is_valid_exchange_uri(&uri) {
        return CommandOutcome::Err(format!("refusing invalid Exchange connection URI: {uri}"));
    }
    if !is_valid_user_principal_name(&account_upn) {
        return CommandOutcome::Err(format!("refusing invalid Exchange account: {account_upn}"));
    }
    if !is_valid_user_principal_name(&target_identity) {
        return CommandOutcome::Err(format!(
            "refusing invalid mailbox identity: {target_identity}"
        ));
    }
    let hybrid = !remote_routing_address.is_empty();
    if hybrid && !is_valid_user_principal_name(&remote_routing_address) {
        return CommandOutcome::Err(format!(
            "refusing invalid remote routing address: {remote_routing_address}"
        ));
    }
    let preamble = exchange_session(
        &crate::process::ps_quote(&uri),
        &crate::process::ps_quote(&account_upn),
    );
    let id_lit = crate::process::ps_quote(&target_identity);
    let action = if hybrid {
        format!(
            "Import-PSSession $s -DisableNameChecking -AllowClobber -CommandName Enable-RemoteMailbox | Out-Null; \
             Enable-RemoteMailbox -Identity {id} -RemoteRoutingAddress {rra} | Out-Null",
            id = id_lit,
            rra = crate::process::ps_quote(&remote_routing_address),
        )
    } else {
        format!(
            "Import-PSSession $s -DisableNameChecking -AllowClobber -CommandName Enable-Mailbox | Out-Null; \
             Enable-Mailbox -Identity {id} | Out-Null",
            id = id_lit,
        )
    };
    let script = crate::process::ps_checked(&format!(
        "{preamble} try {{ {action}; [ordered]@{{ ok = $true }} | ConvertTo-Json -Compress }} \
         finally {{ Remove-PSSession $s }}"
    ));
    run_ps_stdin(&script, &format!("{account_password}\n")).await
}

/// Runs a PowerShell script (no stdin) and returns its JSON stdout.
#[cfg(windows)]
async fn run_powershell(script: &str) -> CommandOutcome {
    match crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
    .await
    {
        Ok(out) => CommandOutcome::Ok(out),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Runs a PowerShell script with the password supplied on stdin (read by the
/// script's `[Console]::In.ReadLine()`), so it never touches argv or a log.
#[cfg(windows)]
async fn run_powershell_with_password(script: &str, password: &str) -> CommandOutcome {
    run_ps_stdin(script, &format!("{password}\n")).await
}

/// Runs a PowerShell script with arbitrary stdin (one or more secret lines the
/// script consumes with `[Console]::In.ReadLine()`), so secrets never touch
/// argv or a log line.
#[cfg(windows)]
async fn run_ps_stdin(script: &str, stdin_data: &str) -> CommandOutcome {
    match crate::process::run_command_with_stdin(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", script],
        stdin_data,
    )
    .await
    {
        Ok(out) => CommandOutcome::Ok(out),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(not(windows))]
pub async fn discover_forest() -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn test_delegation(
    _domain_dns: String,
    _service_account_upn: String,
    _password: String,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn ou_tree(_domain_dns: String) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn search(_domain_dns: String, _query: String) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn get_object(_domain_dns: String, _dn: String) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn unlock_account(
    _domain_dns: String,
    _service_account_upn: String,
    _service_account_password: String,
    _target_dn: String,
    _allow_privileged: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn set_enabled(
    _domain_dns: String,
    _service_account_upn: String,
    _service_account_password: String,
    _target_dn: String,
    _enabled: bool,
    _allow_privileged: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn set_password(
    _domain_dns: String,
    _service_account_upn: String,
    _service_account_password: String,
    _target_dn: String,
    _new_password: String,
    _allow_privileged: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn create_user(_args: CreateUserArgs) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn exchange_test_connection(
    _uri: String,
    _account_upn: String,
    _account_password: String,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn exchange_enable_mailbox(
    _uri: String,
    _account_upn: String,
    _account_password: String,
    _target_identity: String,
    _remote_routing_address: String,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn create_group(_args: CreateGroupArgs) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn delete_group(
    _domain_dns: String,
    _service_account_upn: String,
    _service_account_password: String,
    _target_dn: String,
    _allow_privileged: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
#[allow(clippy::too_many_arguments)]
pub async fn change_group_member(
    _change: GroupMemberChange,
    _domain_dns: String,
    _service_account_upn: String,
    _service_account_password: String,
    _group_dn: String,
    _member_dn: String,
    _allow_privileged: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn move_object(
    _domain_dns: String,
    _service_account_upn: String,
    _service_account_password: String,
    _target_dn: String,
    _new_parent_ou: String,
    _allow_privileged: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn delete_object(
    _domain_dns: String,
    _service_account_upn: String,
    _service_account_password: String,
    _target_dn: String,
    _allow_privileged: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn offboard(
    _domain_dns: String,
    _service_account_upn: String,
    _service_account_password: String,
    _target_dn: String,
    _disabled_ou: String,
    _allow_privileged: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn undo_offboard(_args: UndoOffboardArgs) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(not(windows))]
pub async fn exchange_set_mailbox_offboard(
    _uri: String,
    _account_upn: String,
    _account_password: String,
    _target_identity: String,
    _convert_to_shared: bool,
) -> CommandOutcome {
    crate::process::platform_unsupported()
}
