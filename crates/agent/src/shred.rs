//! Secure deletion ("shred") for the operations that remove a sensitive
//! file -- a quarantined sample, a private key: overwrite its contents with
//! random data `passes` times, then delete it, so it can't simply be undeleted
//! or carved back off the disk.
//!
//! Linux uses GNU `shred` itself (`-f -n <passes> -u`), Windows (which has no
//! shred) an equivalent PowerShell overwrite loop. Neither can promise more
//! than the storage underneath allows: on SSDs/flash (wear levelling),
//! copy-on-write filesystems (btrfs, ZFS), journalled data, snapshots and
//! backups, old copies of the blocks can survive an in-place overwrite.

use abyssal_agent_protocol::MAX_SHRED_PASSES;

pub fn validate_passes(passes: u8) -> Result<(), String> {
    if passes > MAX_SHRED_PASSES {
        return Err(format!(
            "refusing {passes} shred passes -- the maximum is {MAX_SHRED_PASSES}"
        ));
    }
    Ok(())
}

/// GNU shred's arguments for `passes` > 0: `-f` (make it writable first),
/// `-n` passes of random data, `-u` (truncate and remove afterwards), and
/// `--` so a path can never be read as an option.
#[cfg(unix)]
pub fn shred_args(path: &str, passes: u8) -> Vec<String> {
    vec![
        "-f".into(),
        "-n".into(),
        passes.to_string(),
        "-u".into(),
        "--".into(),
        path.into(),
    ]
}

/// A PowerShell body (to wrap in `ps_checked`) that overwrites `path` with
/// cryptographically random bytes `passes` times, flushing each pass through
/// to the disk, then deletes it -- what `shred -n <passes> -u` does on Linux.
#[cfg(windows)]
pub fn shred_script(path: &str, passes: u8) -> String {
    let p = crate::process::ps_quote(path);
    format!(
        "$p = {p}; $item = Get-Item -LiteralPath $p -Force; $item.Attributes = 'Normal'; \
         $len = $item.Length; \
         $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); \
         $buf = New-Object byte[] 1048576; \
         for ($i = 0; $i -lt {passes}; $i++) {{ \
           $fs = [IO.File]::Open($p, 'Open', 'Write', 'None'); \
           try {{ $left = $len; while ($left -gt 0) {{ \
             $n = [Math]::Min($buf.Length, $left); $rng.GetBytes($buf); \
             $fs.Write($buf, 0, $n); $left -= $n }}; $fs.Flush($true) }} \
           finally {{ $fs.Dispose() }} }}; \
         $rng.Dispose(); Remove-Item -LiteralPath $p -Force"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_are_bounded() {
        assert!(validate_passes(0).is_ok());
        assert!(validate_passes(MAX_SHRED_PASSES).is_ok());
        assert!(validate_passes(MAX_SHRED_PASSES + 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn shred_arguments_end_options_before_the_path() {
        assert_eq!(
            shred_args("-rf /", 3),
            ["-f", "-n", "3", "-u", "--", "-rf /"]
        );
    }

    /// The real GNU shred, against a real file: gone afterwards.
    #[cfg(unix)]
    #[test]
    fn gnu_shred_removes_the_file() {
        if std::process::Command::new("shred")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: shred not installed");
            return;
        }
        let dir = std::env::temp_dir().join(format!("abyssal-shred-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret.key");
        std::fs::write(&file, b"PRIVATE KEY MATERIAL").unwrap();
        let path = file.to_str().unwrap();
        let status = std::process::Command::new("shred")
            .args(shred_args(path, 2))
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
