//! Init-system detection, mirroring `firewall.rs`'s "detect the tool
//! present, don't assume one" pattern. `hostnamectl` and `systemctl` --
//! Cystoolbox's `SetHostname` and `Reboot` -- only exist on systemd-based
//! hosts; non-systemd distros (Alpine/OpenRC, Void/runit, Devuan, Gentoo
//! with OpenRC, ...) need a different command for the same operation.
//!
//! Unlike firewalld vs. ufw vs. nftables vs. iptables, the *non*-systemd
//! fallback doesn't itself vary by which init system is actually running --
//! `hostname`/`/etc/hostname` and `reboot` are universal across sysvinit,
//! OpenRC, runit, and friends alike (all provided by util-linux/coreutils,
//! not the init system itself). So detection only needs to answer a single
//! yes/no question, not identify which non-systemd init is present.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    Other,
}

/// Checks for `/run/systemd/system`, the same signal systemd's own
/// `sd_booted()` uses internally -- more reliable than checking whether
/// `systemctl`/`hostnamectl` are on `PATH`, since some non-systemd distros
/// ship compatibility shims for those binaries that don't actually work.
pub async fn detect() -> InitSystem {
    if tokio::fs::metadata("/run/systemd/system").await.is_ok() {
        InitSystem::Systemd
    } else {
        InitSystem::Other
    }
}
