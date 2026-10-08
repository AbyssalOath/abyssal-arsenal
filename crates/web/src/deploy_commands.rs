//! The copy-paste agent install commands `/admin/hosts` generates, for both
//! single-use enrollment tokens and reusable deployment tokens.
//!
//! When the control plane has an internal CA (`public_ca`), every command
//! first fetches `/ca.crt` without trusting the connection, checks the bytes
//! against the CA fingerprint embedded here -- which the admin is reading over
//! an authenticated session -- and only then trusts it. Nothing is trusted
//! blindly, and no manual certificate copying is needed on a fresh host.
//! Without an internal CA (Let's Encrypt, the operator's own proxy) the
//! commands are the plain ones and rely on the OS trust store as before.
//!
//! Tokens are always single-quoted for PowerShell: a base64url token can
//! start with `-`, which PowerShell would otherwise parse as a parameter
//! name.

use crate::public_ca::PublicCa;

/// PowerShell statements (5.1 and 7) that leave the verified CA in `$c`/`$b`
/// and add it to the machine's Trusted Root store, given `$u` (control-plane
/// URL) and `$fp` (expected fingerprint). The fetch has to tolerate the
/// not-yet-trusted certificate: a temporary validation callback on 5.1,
/// `-SkipCertificateCheck` on 7. That's safe because nothing fetched over it
/// is used until its SHA-256 matches `$fp`. Importing into the machine store
/// (rather than only handing the CA to the agent) is what lets PowerShell's
/// own follow-up downloads -- install.ps1 and the agent zip -- validate
/// normally; neither PowerShell edition offers a per-request CA option.
const WINDOWS_CA_BOOTSTRAP: &str = r#"[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
  if ($PSVersionTable.PSVersion.Major -ge 6) { $b = (Invoke-WebRequest "$u/ca.crt" -UseBasicParsing -SkipCertificateCheck).RawContentStream.ToArray() }
  else { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; try { $b = (New-Object Net.WebClient).DownloadData("$u/ca.crt") } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $null } }
  $c = [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$b)
  $h = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData) | ForEach-Object { $_.ToString('X2') })
  if ($h -ne $fp) { throw "CA fingerprint mismatch: expected $fp, got $h -- not trusting $u/ca.crt" }
  $s = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine'); $s.Open('ReadWrite'); $s.Add($c); $s.Close()"#;

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Linux: `curl | sudo sh`, preceded (internal CA) by a pinned fetch of the
/// CA that `curl --cacert` then uses for every later request.
pub fn linux_oneliner(base_url: &str, token: &str, ca: Option<&PublicCa>) -> String {
    match ca {
        None => format!(
            "curl -fsSL {base_url}/install.sh | sudo sh -s -- --enrollment-token {}",
            sh_quote(token)
        ),
        // Everything lands in a private temp dir and runs from a file rather
        // than `curl | sh`, so a failed download can't masquerade as success;
        // the exit code (the agent's, for install failures) is preserved
        // without `exit`, which would close an interactive terminal.
        Some(ca) => format!(
            "U={u} FP={fp}; D=$(mktemp -d) && curl -fsSk \"$U/ca.crt\" -o \"$D/ca.pem\" && \
             {{ [ \"$(sed '/-----/d' \"$D/ca.pem\" | base64 -d | sha256sum | cut -c1-64 | tr a-f A-F)\" = \"$FP\" ] \
             || {{ echo \"ERROR: CA fingerprint mismatch -- not trusting $U/ca.crt\"; false; }}; }} \
             && curl -fsSL --cacert \"$D/ca.pem\" -o \"$D/install.sh\" \"$U/install.sh\" \
             && sudo sh \"$D/install.sh\" --ca-cert \"$D/ca.pem\" --ca-fingerprint \"$FP\" \
             --enrollment-token {token}; rc=$?; rm -rf \"$D\"; [ $rc -eq 0 ] || {{ echo \"ERROR: \
             install failed (exit $rc). A CA download or fingerprint failure stops before anything \
             is installed.\"; (exit $rc); }}",
            u = sh_quote(base_url),
            fp = ca.fingerprint,
            token = sh_quote(token),
        ),
    }
}

/// Linux, step by step, for operators who'd rather see each command.
pub fn linux_manual(base_url: &str, token: &str, ca: Option<&PublicCa>) -> String {
    let mut out = format!("U={}\n", sh_quote(base_url));
    let mut trust = String::new();
    if let Some(ca) = ca {
        out.push_str(&format!(
            "FP={}\n\
             curl -fsSk \"$U/ca.crt\" -o abyssal-ca.pem\n\
             # Must print $FP -- stop here if it doesn't:\n\
             sed '/-----/d' abyssal-ca.pem | base64 -d | sha256sum\n",
            ca.fingerprint
        ));
        trust = " --cacert abyssal-ca.pem".to_string();
    }
    out.push_str(&format!(
        "curl -fsSL{trust} -o abyssal-agent.tar.gz \"$U/agent/linux\"\n\
         mkdir -p abyssal-agent && tar -xzf abyssal-agent.tar.gz -C abyssal-agent\n\
         sudo \"$(find abyssal-agent -type f -name abyssal-agent | head -n1)\" install \\\n  \
         --control-plane-url \"$U\""
    ));
    if ca.is_some() {
        out.push_str(" --ca-cert abyssal-ca.pem --ca-fingerprint \"$FP\"");
    }
    out.push_str(&format!(" \\\n  --enrollment-token {}", sh_quote(token)));
    out
}

/// Windows, from an elevated PowerShell. One `& { }` block, not a sequence of
/// lines: pasted into a console, separate lines keep running after one
/// throws, so a fingerprint mismatch must abort everything that follows.
pub fn windows_oneliner(base_url: &str, token: &str, ca: Option<&PublicCa>) -> String {
    match ca {
        None => format!(
            "& ([scriptblock]::Create((irm {base_url}/install.ps1))) -EnrollmentToken {}",
            ps_quote(token)
        ),
        Some(ca) => format!(
            "& {{\n  $ErrorActionPreference = 'Stop'\n  $u = {u}; $fp = '{fp}'\n  \
             {WINDOWS_CA_BOOTSTRAP}\n  \
             & ([scriptblock]::Create((Invoke-RestMethod \"$u/install.ps1\" -UseBasicParsing))) \
             -CaFingerprint $fp -EnrollmentToken {token}\n}}",
            u = ps_quote(base_url),
            fp = ca.fingerprint,
            token = ps_quote(token),
        ),
    }
}

/// Windows, step by step. Extracts into its own folder and finds the exe
/// wherever it sits, so both the release layout (`<asset>\abyssal-agent.exe`)
/// and a flat operator-built zip work, and calls it with `&` -- PowerShell
/// won't expand a variable in a bare `.\$a\...` command path.
pub fn windows_manual(base_url: &str, token: &str, ca: Option<&PublicCa>) -> String {
    let version = crate::update_check::CURRENT_VERSION.trim();
    let asset = format!("abyssal-agent-v{version}-x86_64-pc-windows-msvc");
    let mut out = format!(
        "& {{\n  $ErrorActionPreference = 'Stop'\n  $u = {}; $a = '{asset}'\n",
        ps_quote(base_url)
    );
    let mut ca_args = String::new();
    if let Some(ca) = ca {
        out.push_str(&format!(
            "  $fp = '{}'\n  {WINDOWS_CA_BOOTSTRAP}\n  \
             [IO.File]::WriteAllBytes((Join-Path $PWD 'abyssal-ca.pem'), $b)\n",
            ca.fingerprint
        ));
        ca_args = " --ca-cert (Join-Path $PWD 'abyssal-ca.pem') --ca-fingerprint $fp".to_string();
    }
    out.push_str(&format!(
        "  Invoke-WebRequest \"$u/agent/windows\" -OutFile \"$a.zip\" -UseBasicParsing\n  \
         Expand-Archive \"$a.zip\" -DestinationPath $a -Force\n  \
         $exe = (Get-ChildItem $a -Recurse -Filter abyssal-agent.exe | Select-Object -First 1).FullName\n  \
         if (-not $exe) {{ throw \"abyssal-agent.exe not found in $a.zip\" }}\n  \
         & $exe install --control-plane-url $u{ca_args} --enrollment-token {}\n}}",
        ps_quote(token)
    ));
    out
}

/// Windows script body for RMM tools (PDQ, Intune, a GPO startup script)
/// running as SYSTEM: no dependence on the working directory or an
/// interactive session, the token passed by environment variable (not on a
/// command line the tool may log), full error text on stdout, and a non-zero
/// exit code on any failure (install.ps1's `-ExitCode` -- the codes are
/// documented at the top of install.ps1).
pub fn windows_rmm(base_url: &str, token: &str, ca: Option<&PublicCa>) -> String {
    let mut out = format!(
        "# Abyssal Arsenal agent deployment -- runs unattended as SYSTEM.\n\
         # Exit code 0 = enrolled and the service is running; see {base_url}/install.ps1\n\
         # for the meaning of any other code.\n\
         $ErrorActionPreference = 'Stop'\n\
         $u = {}\n",
        ps_quote(base_url)
    );
    let mut ca_arg = "";
    if let Some(ca) = ca {
        out.push_str(&format!("$fp = '{}'\n", ca.fingerprint));
        ca_arg = " -CaFingerprint $fp";
    }
    out.push_str(&format!(
        "$env:ABYSSAL_ENROLLMENT_TOKEN = {}\n\
         try {{\n",
        ps_quote(token)
    ));
    if ca.is_some() {
        out.push_str(&format!("  {WINDOWS_CA_BOOTSTRAP}\n"));
    }
    out.push_str(&format!(
        "  $script = Invoke-RestMethod \"$u/install.ps1\" -UseBasicParsing\n  \
         & ([scriptblock]::Create($script)){ca_arg} -ExitCode\n\
         }} catch {{\n  \
         Write-Output \"ERROR: $($_.Exception.Message)\"\n  \
         exit 1\n\
         }} finally {{\n  \
         Remove-Item Env:\\ABYSSAL_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue\n\
         }}"
    ));
    out
}

/// What the AAT card on `/admin/hosts` shows: the CrowdStrike-style
/// unattended install lines for the Windows exe and MSI, plus Linux. The AAT
/// is a placeholder unless it's being revealed. No CA fingerprint anywhere:
/// the agent authenticates the CA with the AAT itself
/// (`abyssal_agent_protocol::aat`).
pub struct AatCommands {
    /// Download links served by this control plane (`GET /agent/{os}`).
    pub exe_url: String,
    pub msi_url: String,
    pub linux_url: String,
    /// What goes in PDQ Deploy's "Parameters" box for the exe.
    pub exe_parameters: String,
    pub exe: String,
    pub msi: String,
    /// Agent already on the host (pushed by your tooling, or no internet).
    pub linux: String,
    /// Downloads this control plane's release from GitHub first -- safe
    /// without any CA setup because GitHub's certificate is publicly
    /// trusted, unlike a fetch from an internal-CA control plane.
    pub linux_github: String,
}

pub fn aat_commands(base_url: &str, aat: Option<&str>) -> AatCommands {
    aat_commands_for_version(base_url, aat, crate::update_check::CURRENT_VERSION.trim())
}

fn aat_commands_for_version(base_url: &str, aat: Option<&str>, version: &str) -> AatCommands {
    let aat = aat.unwrap_or("<AAT>");
    let install =
        format!("sudo ./abyssal-agent install --control-plane-url '{base_url}' --aat '{aat}'");
    let exe_parameters = format!("/install /quiet /norestart SERVER={base_url} AAT={aat}");
    AatCommands {
        exe_url: format!("{base_url}/agent/windows-exe"),
        msi_url: format!("{base_url}/agent/windows-msi"),
        exe: format!("abyssal-agent.exe {exe_parameters}"),
        msi: format!("msiexec /i AbyssalAgent.msi /qn /norestart SERVER={base_url} AAT={aat}"),
        // Like the exe/MSI, the binary is assumed to be on the host already
        // (pushed by your tooling, or from the download link): fetching it
        // here would need an unverified connection, and the AAT only
        // authenticates the CA, not a binary.
        linux: install.clone(),
        linux_url: format!("{base_url}/agent/linux"),
        linux_github: format!(
            "cd \"$(mktemp -d)\" && curl -fsSL \
             'https://github.com/AbyssalOath/abyssal-arsenal/releases/download/v{version}/\
             abyssal-agent-v{version}-x86_64-unknown-linux-gnu.tar.gz' | \
             tar -xz --strip-components=1 && \\\n  {install}"
        ),
        exe_parameters,
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn aat_commands_fill_in_server_and_token() {
        let c = aat_commands_for_version("https://10.0.0.5", Some("AAT1-abc"), "9.9.9");
        assert_eq!(
            c.exe_parameters,
            "/install /quiet /norestart SERVER=https://10.0.0.5 AAT=AAT1-abc"
        );
        assert!(c.msi.contains("SERVER=https://10.0.0.5 AAT=AAT1-abc"));
        assert!(c.linux_github.contains(
            "https://github.com/AbyssalOath/abyssal-arsenal/releases/download/v9.9.9/\
             abyssal-agent-v9.9.9-x86_64-unknown-linux-gnu.tar.gz"
        ));
        // Never an unverified download.
        assert!(!c.linux_github.contains("curl -fsSLk") && !c.linux_github.contains(" -k "));
        assert!(c.linux_github.ends_with("--aat 'AAT1-abc'"));
        let hidden = aat_commands_for_version("https://x", None, "1.0.0");
        assert!(hidden.exe.contains("AAT=<AAT>"));
    }

    #[test]
    fn linux_aat_commands_are_valid_sh() {
        let c = aat_commands_for_version("https://10.0.0.5", Some("AAT1--dash"), "1.2.3");
        for body in [&c.linux, &c.linux_github] {
            let out = std::process::Command::new("sh")
                .arg("-n")
                .arg("-c")
                .arg(body)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{body}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    use super::*;

    fn ca() -> PublicCa {
        PublicCa {
            pem: String::new(),
            fingerprint: "AB".repeat(32),
        }
    }

    #[test]
    fn plain_commands_have_no_ca_handling() {
        let cmd = windows_oneliner("https://arsenal.example.com", "-TOK", None);
        assert!(!cmd.contains("ca.crt"));
        // A leading '-' must not be parsed as a parameter name.
        assert!(cmd.ends_with("-EnrollmentToken '-TOK'"));
        assert!(!linux_oneliner("https://arsenal.example.com", "TOK", None).contains("ca.crt"));
    }

    #[test]
    fn internal_ca_commands_pin_the_fingerprint() {
        let fp = "AB".repeat(32);
        for cmd in [
            windows_oneliner("https://10.0.0.5", "TOK", Some(&ca())),
            windows_manual("https://10.0.0.5", "TOK", Some(&ca())),
            windows_rmm("https://10.0.0.5", "TOK", Some(&ca())),
        ] {
            assert!(cmd.contains(&format!("$fp = '{fp}'")), "{cmd}");
            assert!(cmd.contains("$h -ne $fp"), "{cmd}");
            assert!(cmd.contains("/ca.crt"), "{cmd}");
        }
        for cmd in [
            linux_oneliner("https://10.0.0.5", "TOK", Some(&ca())),
            linux_manual("https://10.0.0.5", "TOK", Some(&ca())),
        ] {
            assert!(cmd.contains(&fp), "{cmd}");
            assert!(cmd.contains("--cacert"), "{cmd}");
            assert!(cmd.contains("--ca-fingerprint"), "{cmd}");
        }
    }

    #[test]
    fn windows_manual_invokes_the_exe_with_the_call_operator() {
        let cmd = windows_manual("https://x", "TOK", None);
        // The original bug: `.\$a\abyssal-agent.exe install` isn't a command
        // PowerShell can resolve.
        assert!(!cmd.contains(r".\$a\abyssal-agent.exe"));
        assert!(cmd.contains("Get-ChildItem $a -Recurse -Filter abyssal-agent.exe"));
        assert!(cmd.contains("& $exe install"));
    }

    #[test]
    fn windows_commands_abort_as_a_single_block() {
        for cmd in [
            windows_oneliner("https://x", "TOK", Some(&ca())),
            windows_manual("https://x", "TOK", Some(&ca())),
        ] {
            assert!(cmd.starts_with("& {\n"), "{cmd}");
            assert!(cmd.ends_with('}'), "{cmd}");
        }
    }

    #[test]
    fn rmm_script_keeps_the_token_off_the_command_line_and_sets_exit_codes() {
        let cmd = windows_rmm("https://x", "TOK", Some(&ca()));
        assert!(cmd.contains("$env:ABYSSAL_ENROLLMENT_TOKEN = 'TOK'"));
        assert!(!cmd.contains("-EnrollmentToken"));
        assert!(cmd.contains("-ExitCode"));
        assert!(cmd.contains("exit 1"));
        assert!(!cmd.contains("Set-Location") && !cmd.contains("$PWD"));
    }
}
