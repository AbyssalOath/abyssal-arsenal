//! CrowdStrike-style installer arguments, so the agent drops into an existing
//! PDQ Deploy / Intune / GPO workflow the same way the Falcon sensor does:
//!
//! ```text
//! abyssal-agent.exe /install /quiet /norestart SERVER=https://arsenal.corp AAT=AAT1-...
//! abyssal-agent.exe /uninstall /quiet [PURGE=1]
//! ```
//!
//! [`translate`] rewrites that form into the ordinary `install` / `uninstall`
//! subcommands before clap sees it, so there's exactly one implementation of
//! each. `/quiet` maps to `--non-interactive`: fail with an exit code instead
//! of prompting. The same syntax works on Linux, though `install --aat` is the
//! more natural spelling there.

use std::ffi::OsString;

/// What went wrong translating; reported as exit code 2 (bad arguments).
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidInstallerArgs(pub String);

impl std::fmt::Display for InvalidInstallerArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -- usage: abyssal-agent /install /quiet /norestart SERVER=<url> AAT=<token> \
             [NAME=<hostname>], or abyssal-agent /uninstall /quiet [PURGE=1]",
            self.0
        )
    }
}

impl std::error::Error for InvalidInstallerArgs {}

/// `None` when `args` (including argv[0]) aren't installer-style -- parse
/// them with clap as-is. Otherwise the equivalent subcommand line.
pub fn translate(args: &[OsString]) -> Option<Result<Vec<OsString>, InvalidInstallerArgs>> {
    let rest: Vec<String> = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let first = rest.first()?;
    // Only the first argument decides: every real subcommand is a bare word,
    // so a leading `/switch` or `KEY=value` can't be anything else.
    if !(first.starts_with('/') || property(first).is_some()) {
        return None;
    }
    Some(translate_rest(args[0].clone(), &rest))
}

/// `KEY=value` with one of the keys below, the key matched
/// case-insensitively (msiexec property style).
fn property(arg: &str) -> Option<(String, &str)> {
    let (key, value) = arg.split_once('=')?;
    let key = key.to_ascii_uppercase();
    matches!(key.as_str(), "SERVER" | "AAT" | "NAME" | "PURGE").then_some((key, value))
}

fn translate_rest(argv0: OsString, rest: &[String]) -> Result<Vec<OsString>, InvalidInstallerArgs> {
    let mut uninstall = false;
    let mut install = false;
    let mut quiet = false;
    let mut server = None;
    let mut aat = None;
    let mut name = None;
    let mut purge = false;

    for arg in rest {
        if let Some(switch) = arg.strip_prefix('/') {
            match switch.to_ascii_lowercase().as_str() {
                "install" => install = true,
                "uninstall" => uninstall = true,
                "quiet" | "silent" | "passive" | "q" | "qn" => quiet = true,
                // Nothing this installer does needs a reboot; accepted so a
                // command line copied from another product just works.
                "norestart" | "forcerestart" | "promptrestart" => {}
                other => return Err(InvalidInstallerArgs(format!("unknown switch /{other}"))),
            }
            continue;
        }
        match property(arg) {
            Some((key, value)) => {
                let value = value.trim().trim_matches('"').to_string();
                match key.as_str() {
                    "SERVER" => server = Some(value),
                    "AAT" => aat = Some(value),
                    "NAME" => name = Some(value),
                    "PURGE" => purge = matches!(value.as_str(), "1" | "true" | "yes"),
                    _ => unreachable!("property() only returns known keys"),
                }
            }
            None => return Err(InvalidInstallerArgs(format!("unexpected argument {arg:?}"))),
        }
    }

    if install && uninstall {
        return Err(InvalidInstallerArgs(
            "/install and /uninstall can't be combined".into(),
        ));
    }

    let mut out = vec![argv0];
    if uninstall {
        if server.is_some() || aat.is_some() || name.is_some() {
            return Err(InvalidInstallerArgs(
                "SERVER=, AAT= and NAME= only apply to /install".into(),
            ));
        }
        out.push("uninstall".into());
        if purge {
            out.push("--purge".into());
        }
    } else {
        // `/install` is implied by SERVER=/AAT= alone, like msiexec properties.
        if purge {
            return Err(InvalidInstallerArgs(
                "PURGE= only applies to /uninstall".into(),
            ));
        }
        out.push("install".into());
        for (flag, value) in [
            ("--control-plane-url", server),
            ("--aat", aat),
            ("--name", name),
        ] {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                out.push(flag.into());
                out.push(value.into());
            }
        }
    }
    if quiet {
        out.push("--non-interactive".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Option<Result<Vec<String>, InvalidInstallerArgs>> {
        let args: Vec<OsString> = std::iter::once("abyssal-agent.exe")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect();
        translate(&args).map(|r| {
            r.map(|v| {
                v.into_iter()
                    .skip(1)
                    .map(|a| a.into_string().unwrap())
                    .collect()
            })
        })
    }

    #[test]
    fn ordinary_subcommands_are_left_alone() {
        assert_eq!(run(&["install", "--aat", "AAT1-x"]), None);
        assert_eq!(run(&["run", "--control-plane-url", "https://x"]), None);
        assert_eq!(run(&[]), None);
    }

    #[test]
    fn crowdstrike_style_install_line() {
        let out = run(&[
            "/install",
            "/quiet",
            "/norestart",
            "SERVER=https://10.0.0.5",
            "AAT=AAT1--starts-with-a-dash",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            out,
            [
                "install",
                "--control-plane-url",
                "https://10.0.0.5",
                "--aat",
                "AAT1--starts-with-a-dash",
                "--non-interactive"
            ]
        );
    }

    #[test]
    fn switches_and_keys_are_case_insensitive_and_install_is_implied() {
        let out = run(&["server=https://x", "Aat=AAT1-y", "/QUIET", "name=web01"])
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            [
                "install",
                "--control-plane-url",
                "https://x",
                "--aat",
                "AAT1-y",
                "--name",
                "web01",
                "--non-interactive"
            ]
        );
    }

    #[test]
    fn empty_values_are_dropped() {
        // What an MSI passes for a property that wasn't set.
        let out = run(&["/install", "SERVER=", "AAT="]).unwrap().unwrap();
        assert_eq!(out, ["install"]);
    }

    #[test]
    fn uninstall_with_purge() {
        assert_eq!(
            run(&["/uninstall", "/quiet", "PURGE=1"]).unwrap().unwrap(),
            ["uninstall", "--purge", "--non-interactive"]
        );
    }

    #[test]
    fn rejects_what_it_doesnt_understand() {
        assert!(run(&["/install", "/bogus"]).unwrap().is_err());
        assert!(run(&["/install", "FOO=bar"]).unwrap().is_err());
        assert!(run(&["/install", "/uninstall"]).unwrap().is_err());
        assert!(run(&["/uninstall", "AAT=x"]).unwrap().is_err());
        assert!(run(&["/install", "PURGE=1"]).unwrap().is_err());
    }
}
