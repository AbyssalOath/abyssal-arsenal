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
           $groups = @($u.MemberOf | ForEach-Object {{ try {{ (Get-ADGroup -Server $server -Identity $_).Name }} catch {{ \"$_\" }} }}); \
           $out = [ordered]@{{ type='user'; name=$u.Name; sam=$u.SamAccountName; upn=$u.UserPrincipalName; dn=$u.DistinguishedName; display=$u.DisplayName; enabled=$u.Enabled; locked=$u.LockedOut; description=$u.Description; email=$u.EmailAddress; department=$u.Department; title=$u.Title; created=\"$($u.whenCreated)\"; last_logon=\"$($u.LastLogonDate)\"; groups=$groups }}; \
           $out | ConvertTo-Json -Depth 4; return \
         }}; \
         $g = Get-ADGroup -Server $server -Identity $dn -Properties Description,GroupScope,GroupCategory,Members,MemberOf -ErrorAction SilentlyContinue; \
         if ($g) {{ \
           $members = @($g.Members | Select-Object -First 200 | ForEach-Object {{ try {{ (Get-ADObject -Server $server -Identity $_).Name }} catch {{ \"$_\" }} }}); \
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
