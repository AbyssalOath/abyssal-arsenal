//! Host-side SFTP/SMB share provisioning and mounts -- renders the
//! actual `sshd_config`/`smb.conf`/mount-unit *content* from strictly
//! validated inputs, then applies it through the existing executor
//! (`AgentOperation`, never a new remote-execution channel). Every
//! render function here re-validates its own inputs defensively (even
//! though callers should have already validated them at the route
//! layer) -- this is the one place a rejected value would otherwise
//! become an injected directive in a live config file, so it never
//! trusts "the caller probably checked already."

use abyssal_agent_protocol::{AgentOperation, is_valid_absolute_path, is_valid_account_name};
use abyssal_core::Permission;
use abyssal_execution::{Executor, OperationKind};
use abyssal_hosts::HostConnectionRegistry;
use abyssal_rbac::AuthContext;
use uuid::Uuid;

use super::SepulchreError;

fn require_account_name(name: &str) -> Result<&str, SepulchreError> {
    if is_valid_account_name(name) {
        Ok(name)
    } else {
        Err(SepulchreError::Config(format!(
            "not a valid account name: {name}"
        )))
    }
}

fn require_absolute_path(path: &str) -> Result<&str, SepulchreError> {
    if is_valid_absolute_path(path) {
        Ok(path)
    } else {
        Err(SepulchreError::Config(format!(
            "not a valid absolute path: {path}"
        )))
    }
}

/// A share/user name as it appears inside a config stanza -- narrower
/// than a full account name (no leading-`-`/POSIX constraints needed,
/// but still never a newline or the characters that end/open a new
/// `smb.conf` section or `sshd_config` directive).
fn require_config_safe_token<'a>(value: &'a str, field: &str) -> Result<&'a str, SepulchreError> {
    let safe = !value.is_empty()
        && value.len() <= 255
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        && !value.starts_with(' ')
        && !value.ends_with(' ');
    if safe {
        Ok(value)
    } else {
        Err(SepulchreError::Config(format!(
            "{field} contains characters not allowed in a config file: {value}"
        )))
    }
}

/// Validates a share name at the route layer, before it's ever persisted
/// or reaches [`render_samba_share_stanza`] -- same character allowlist
/// that function already enforces, exposed here so a bad name is
/// rejected on the create form rather than only when the share is
/// actually rendered into `smb.conf`.
pub fn validate_share_name(name: &str) -> Result<(), SepulchreError> {
    require_config_safe_token(name, "share name").map(|_| ())
}

/// Renders the `Match User` block that restricts one SFTP chroot
/// account -- `ChrootDirectory`/`ForceCommand internal-sftp` plus the
/// lockout-protection directives from `docs/sepulchre.md` (no TCP/X11
/// forwarding, no PTY). Scoped to `Match User <username>` only, so this
/// can never affect any other account's access path, including the
/// control plane's own admin login to this host.
pub fn render_sftp_match_block(username: &str, chroot_dir: &str) -> Result<String, SepulchreError> {
    let username = require_account_name(username)?;
    let chroot_dir = require_absolute_path(chroot_dir)?;
    Ok(format!(
        "\nMatch User {username}\n    ChrootDirectory {chroot_dir}\n    ForceCommand internal-sftp\n    AllowTcpForwarding no\n    X11Forwarding no\n    PermitTTY no\n    AuthorizedKeysFile /etc/ssh/sepulchre/authorized_keys/%u\n"
    ))
}

/// Combines the managed header with every currently-desired `Match`
/// block into the full drop-in content -- callers pass the complete set
/// every time (this file is always rendered from scratch, never
/// incrementally patched), same as `grimoire.rs`'s sysctl/cron files.
pub fn render_full_sshd_dropin(match_blocks: &[String]) -> String {
    let mut content =
        "# Managed by Abyssal Arsenal (Sepulchre) -- do not edit manually\n".to_string();
    for block in match_blocks {
        content.push_str(block);
    }
    content
}

/// Renders one SMB share stanza. `valid_users` are already-validated
/// account names (joined with a space, `smb.conf`'s own list syntax);
/// guest access is never enabled, matching the amendment's explicit
/// "never enable anonymous/guest access" requirement.
pub fn render_samba_share_stanza(
    share_name: &str,
    path: &str,
    valid_users: &[String],
    read_only: bool,
) -> Result<String, SepulchreError> {
    let share_name = require_config_safe_token(share_name, "share name")?;
    let path = require_absolute_path(path)?;
    for user in valid_users {
        require_account_name(user)?;
    }
    let users = valid_users.join(" ");
    Ok(format!(
        "\n[{share_name}]\n    path = {path}\n    valid users = {users}\n    read only = {}\n    guest ok = no\n    browseable = yes\n    create mask = 0640\n    directory mask = 0750\n",
        if read_only { "yes" } else { "no" }
    ))
}

/// Combines the managed `[global]` protocol/security settings with
/// every currently-desired share stanza. SMB3 minimum, signing
/// required, encryption per the connection's own `SmbEncryption`
/// setting -- rendered once here rather than trusting each stanza to
/// repeat it.
pub fn render_full_samba_include(encryption_required: bool, share_stanzas: &[String]) -> String {
    let mut content = format!(
        "# Managed by Abyssal Arsenal (Sepulchre) -- do not edit manually\n[global]\n    server min protocol = SMB3\n    server signing = mandatory\n    server smb encrypt = {}\n",
        if encryption_required {
            "required"
        } else {
            "desired"
        }
    );
    for stanza in share_stanzas {
        content.push_str(stanza);
    }
    content
}

/// Renders a systemd `.mount` unit for an SSHFS or CIFS source.
/// `_netdev`/`nofail`/`x-systemd.automount`-equivalent behavior comes
/// from the unit's own `Options=`/`[Automount]` section, not fstab --
/// credentials (if any) live in a separate root-owned `0600` file
/// referenced by path, never inline here.
pub fn render_mount_unit_content(
    what: &str,
    where_: &str,
    fs_type: &str,
    options: &str,
) -> Result<(String, String), SepulchreError> {
    let where_ = require_absolute_path(where_)?;
    let unit_name = format!("{}.mount", systemd_escape_path(where_));
    let content = format!(
        "[Unit]\nDescription=Sepulchre-managed mount for {where_}\nAfter=network-online.target\nWants=network-online.target\n\n[Mount]\nWhat={what}\nWhere={where_}\nType={fs_type}\nOptions={options},_netdev,nofail\n\n[Install]\nWantedBy=multi-user.target\n"
    );
    Ok((unit_name, content))
}

/// A `systemd-escape --path`-equivalent. systemd validates that a
/// `.mount` unit's `Where=` decodes back to exactly the unit's own name,
/// so an under-escaped name is refused outright at unit-load time --
/// caught live against a real systemd instance: `/mnt/sepulchre-test`
/// (an entirely ordinary path containing a literal hyphen) produced the
/// unit name `mnt-sepulchre-test.mount`, which systemd rejected with
/// "Where= setting doesn't match unit name" because it can't tell that
/// hyphen apart from one substituted for a `/`. Every `-` converted from
/// a path separator has to be told apart from a *literal* `-` in a path
/// component, which only works if every literal `-` (and anything else
/// outside `[A-Za-z0-9:_.]`) is `\xHH` hex-escaped first, exactly as
/// `systemd-escape --path` itself does.
pub(crate) fn systemd_escape_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return "-".to_string();
    }
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        match ch {
            '/' => out.push('-'),
            'a'..='z' | 'A'..='Z' | '0'..='9' | ':' | '_' | '.' => out.push(ch),
            other => {
                for byte in other.to_string().into_bytes() {
                    out.push_str(&format!("\\x{byte:02x}"));
                }
            }
        }
    }
    out
}

/// Where a CIFS mount's `credentials=` file must live -- checked here and
/// re-checked by the agent itself (`crates/agent/src/sepulchre.rs`),
/// never trusting the caller already did.
pub const MOUNT_CREDENTIALS_DIR: &str = "/etc/sepulchre/mounts";

fn require_mount_credentials_path(path: &str) -> Result<&str, SepulchreError> {
    require_absolute_path(path)?;
    if path.starts_with(&format!("{MOUNT_CREDENTIALS_DIR}/")) {
        Ok(path)
    } else {
        Err(SepulchreError::Config(format!(
            "mount credentials must live under {MOUNT_CREDENTIALS_DIR}: {path}"
        )))
    }
}

/// Renders a `mount.cifs` `credentials=` file's contents. Rejects an
/// embedded newline in any field -- the format is line-based
/// (`key=value` per line), so a value containing one could otherwise
/// smuggle in an extra key the mount helper wasn't meant to see.
pub fn render_cifs_credentials_file(
    username: &str,
    password: &str,
    domain: Option<&str>,
) -> Result<String, SepulchreError> {
    for (field, value) in [("username", username), ("password", password)]
        .into_iter()
        .chain(domain.map(|d| ("domain", d)))
    {
        if value.contains(['\n', '\r']) {
            return Err(SepulchreError::Config(format!(
                "{field} may not contain a newline"
            )));
        }
    }
    let mut content = format!("username={username}\npassword={password}\n");
    if let Some(domain) = domain {
        content.push_str(&format!("domain={domain}\n"));
    }
    Ok(content)
}

pub struct HostDispatch<'a> {
    pub executor: &'a Executor,
    pub hosts: &'a HostConnectionRegistry,
    pub ctx: &'a AuthContext,
    pub host_id: Uuid,
    pub host_name: &'a str,
}

impl HostDispatch<'_> {
    async fn run(
        &self,
        operation: AgentOperation,
        kind: OperationKind,
        label: &str,
    ) -> Result<abyssal_agent_protocol::OperationOutput, SepulchreError> {
        self.executor
            .execute_on_host(
                self.ctx,
                self.hosts,
                self.host_id,
                self.host_name,
                operation,
                Permission::StorageConnectionsManage,
                kind,
                true,
                std::time::Duration::from_secs(30),
                None,
                false,
            )
            .await
            .map_err(|e| SepulchreError::Backend(format!("{label} failed: {e}")))
    }

    pub async fn detect_package_backend(&self) -> Result<String, SepulchreError> {
        let output = self
            .run(
                AgentOperation::DetectPackageBackend,
                OperationKind::Read,
                "detect package backend",
            )
            .await?;
        Ok(output.stdout.trim().to_string())
    }

    pub async fn render_config(
        &self,
        target: abyssal_agent_protocol::SepulchreConfigTarget,
        content: String,
    ) -> Result<(), SepulchreError> {
        self.run(
            AgentOperation::RenderSepulchreConfig { target, content },
            OperationKind::Write,
            "render config",
        )
        .await?;
        Ok(())
    }

    pub async fn check_include_directive(
        &self,
        target: abyssal_agent_protocol::SepulchreConfigTarget,
    ) -> Result<bool, SepulchreError> {
        let output = self
            .run(
                AgentOperation::CheckSepulchreConfigIncludeDirective { target },
                OperationKind::Read,
                "check include directive",
            )
            .await?;
        Ok(output.stdout.trim() == "present")
    }

    pub async fn create_sftp_chroot_account(
        &self,
        username: String,
        chroot_dir: String,
    ) -> Result<(), SepulchreError> {
        self.run(
            AgentOperation::CreateSftpChrootAccount {
                username,
                chroot_dir,
            },
            OperationKind::Write,
            "create SFTP chroot account",
        )
        .await?;
        Ok(())
    }

    pub async fn install_authorized_key(
        &self,
        username: String,
        public_key: String,
    ) -> Result<(), SepulchreError> {
        self.run(
            AgentOperation::InstallSepulchreAuthorizedKey {
                username,
                public_key,
            },
            OperationKind::Write,
            "install authorized key",
        )
        .await?;
        Ok(())
    }

    pub async fn remove_sftp_chroot_account(&self, username: String) -> Result<(), SepulchreError> {
        self.run(
            AgentOperation::RemoveSftpChrootAccount { username },
            OperationKind::Destructive,
            "remove SFTP chroot account",
        )
        .await?;
        Ok(())
    }

    pub async fn create_samba_service_user(
        &self,
        username: String,
        password: String,
    ) -> Result<(), SepulchreError> {
        self.run(
            AgentOperation::CreateSambaServiceUser { username, password },
            OperationKind::Write,
            "create Samba service user",
        )
        .await?;
        Ok(())
    }

    pub async fn remove_samba_service_user(&self, username: String) -> Result<(), SepulchreError> {
        self.run(
            AgentOperation::RemoveSambaServiceUser { username },
            OperationKind::Destructive,
            "remove Samba service user",
        )
        .await?;
        Ok(())
    }

    pub async fn render_mount_unit(
        &self,
        unit_name: String,
        mount_point: String,
        content: String,
    ) -> Result<(), SepulchreError> {
        self.run(
            AgentOperation::RenderMountUnit {
                unit_name,
                mount_point,
                content,
            },
            OperationKind::Write,
            "render mount unit",
        )
        .await?;
        Ok(())
    }

    pub async fn remove_mount_unit(
        &self,
        unit_name: String,
        mount_point: String,
    ) -> Result<(), SepulchreError> {
        self.run(
            AgentOperation::RemoveMountUnit {
                unit_name,
                mount_point,
            },
            OperationKind::Destructive,
            "remove mount unit",
        )
        .await?;
        Ok(())
    }

    pub async fn create_share_directory(
        &self,
        path: String,
        owner: String,
    ) -> Result<(), SepulchreError> {
        require_absolute_path(&path)?;
        require_account_name(&owner)?;
        self.run(
            AgentOperation::CreateSepulchreShareDirectory { path, owner },
            OperationKind::Write,
            "create share directory",
        )
        .await?;
        Ok(())
    }

    pub async fn write_mount_credentials(
        &self,
        path: String,
        contents: String,
    ) -> Result<(), SepulchreError> {
        require_mount_credentials_path(&path)?;
        self.run(
            AgentOperation::WriteSepulchreMountCredentials { path, contents },
            OperationKind::Write,
            "write mount credentials",
        )
        .await?;
        Ok(())
    }

    pub async fn check_mount_status(&self, mount_point: String) -> Result<bool, SepulchreError> {
        let output = self
            .run(
                AgentOperation::CheckMountStatus { mount_point },
                OperationKind::Read,
                "check mount status",
            )
            .await?;
        Ok(output.stdout.trim() == "mounted")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_valid_sftp_match_block() {
        let block =
            render_sftp_match_block("sepulchre-sftp1", "/srv/sftp/sepulchre-sftp1").unwrap();
        assert!(block.contains("Match User sepulchre-sftp1"));
        assert!(block.contains("ChrootDirectory /srv/sftp/sepulchre-sftp1"));
        assert!(block.contains("ForceCommand internal-sftp"));
        assert!(block.contains("AllowTcpForwarding no"));
    }

    #[test]
    fn rejects_an_invalid_username_in_the_match_block() {
        assert!(render_sftp_match_block("not a user\nMatch User root", "/srv/x").is_err());
    }

    #[test]
    fn rejects_a_relative_chroot_path() {
        assert!(render_sftp_match_block("validuser", "relative/path").is_err());
    }

    #[test]
    fn renders_a_valid_samba_share_stanza() {
        let stanza = render_samba_share_stanza(
            "backups",
            "/srv/smb/backups",
            &["svc-backup".to_string()],
            false,
        )
        .unwrap();
        assert!(stanza.contains("[backups]"));
        assert!(stanza.contains("path = /srv/smb/backups"));
        assert!(stanza.contains("guest ok = no"));
        assert!(stanza.contains("read only = no"));
    }

    #[test]
    fn rejects_a_share_name_that_could_inject_a_new_section() {
        assert!(
            render_samba_share_stanza(
                "backups]\n[global",
                "/srv/smb/backups",
                &["svc".to_string()],
                false
            )
            .is_err()
        );
    }

    #[test]
    fn full_samba_include_never_enables_guest_access_by_construction() {
        let content = render_full_samba_include(true, &[]);
        assert!(!content.contains("guest ok = yes"));
        assert!(content.contains("server smb encrypt = required"));
    }

    #[test]
    fn mount_unit_name_is_derived_from_the_mount_point() {
        let (unit_name, content) =
            render_mount_unit_content("//host/share", "/mnt/backups", "cifs", "ro").unwrap();
        assert_eq!(unit_name, "mnt-backups.mount");
        assert!(content.contains("Where=/mnt/backups"));
        assert!(content.contains("_netdev"));
        assert!(content.contains("nofail"));
    }

    /// Regression test: caught live against a real systemd instance,
    /// which refused a unit named `mnt-sepulchre-test.mount` for
    /// `/mnt/sepulchre-test` with "Where= setting doesn't match unit
    /// name" -- the literal hyphen in the path was indistinguishable from
    /// one substituted for `/` until it was hex-escaped.
    #[test]
    fn mount_unit_name_escapes_a_literal_hyphen_in_the_path() {
        let (unit_name, _) =
            render_mount_unit_content("//host/share", "/mnt/sepulchre-test", "cifs", "rw").unwrap();
        assert_eq!(unit_name, "mnt-sepulchre\\x2dtest.mount");
    }

    #[test]
    fn rejects_a_relative_mount_point() {
        assert!(render_mount_unit_content("//host/share", "relative", "cifs", "ro").is_err());
    }

    #[test]
    fn renders_a_valid_cifs_credentials_file() {
        let content =
            render_cifs_credentials_file("svc-backup", "s3cret", Some("WORKGROUP")).unwrap();
        assert!(content.contains("username=svc-backup"));
        assert!(content.contains("password=s3cret"));
        assert!(content.contains("domain=WORKGROUP"));
    }

    #[test]
    fn rejects_a_credentials_field_containing_a_newline() {
        assert!(render_cifs_credentials_file("svc\nbackup", "s3cret", None).is_err());
        assert!(render_cifs_credentials_file("svc-backup", "s3\ncret", None).is_err());
    }

    #[test]
    fn accepts_a_path_under_the_reserved_mount_credentials_directory() {
        assert!(require_mount_credentials_path("/etc/sepulchre/mounts/conn-a.cred").is_ok());
    }

    #[test]
    fn rejects_a_mount_credentials_path_outside_the_reserved_directory() {
        assert!(require_mount_credentials_path("/etc/passwd").is_err());
        assert!(require_mount_credentials_path("/etc/sepulchre-mounts-evil/x").is_err());
    }
}
