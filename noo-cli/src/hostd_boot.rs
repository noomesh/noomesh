// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
//! The controller's noo-hostd at boot (i1160, risk 5): onboard's linger step
//! and the `hostd at boot` verify row read the same facts from here.
//!
//! A controller installs noo-hostd as a systemd USER unit
//! (`WantedBy=default.target`, node-agent-go/internal/hostd/install.go). A
//! user's units start at boot only when that user lingers
//! (`loginctl enable-linger <user>`); otherwise the user manager, and so
//! hostd, starts at the user's first login. hostd's BootRestore is what
//! brings the stack back after a reboot with no command, so on a headless
//! controller nobody logs into, nothing restores it.
//!
//! On a Mac, `noo-hostd install --mode controller` writes a LaunchAgent
//! (`net.personifai.noo-hostd`), which likewise runs only in a login
//! session. Onboard refuses a Mac controller today (upfront.rs), so only a
//! hand install reaches it.
use std::path::Path;
use std::process::Command;

/// Where `noo-hostd install --mode controller` writes its user unit, under
/// the installing user's home.
pub(crate) const USER_UNIT_REL: &str = ".config/systemd/user/noo-hostd.service";
/// Where `noo-hostd install --system` writes (also the worker unit's path).
pub(crate) const SYSTEM_UNIT: &str = "/etc/systemd/system/noo-hostd.service";
/// The controller LaunchAgent on a Mac, under the installing user's home.
pub(crate) const LAUNCH_AGENT_REL: &str = "Library/LaunchAgents/net.personifai.noo-hostd.plist";

/// The user's linger, as `loginctl show-user <user> -p Linger` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Linger {
    On,
    Off,
    /// Why it could not be read.
    Unreadable(String),
}

/// Judge `loginctl show-user <user> -p Linger`. Pure.
///
/// - exit 0 with `Linger=yes` / `Linger=no`: on / off;
/// - a user with no session and no linger is not known to logind at all:
///   loginctl exits 1 with "... is not logged in or lingering", which IS the
///   answer (off);
/// - anything else is unreadable, with the reason.
pub(crate) fn parse_linger(success: bool, stdout: &str, stderr: &str) -> Linger {
    if success {
        return match stdout.lines().find_map(|l| l.trim().strip_prefix("Linger=")) {
            Some("yes") => Linger::On,
            Some("no") => Linger::Off,
            Some(v) => Linger::Unreadable(format!("loginctl answered Linger={v}")),
            None => Linger::Unreadable("loginctl gave no Linger property".into()),
        };
    }
    if stderr.contains("not logged in or lingering") {
        return Linger::Off;
    }
    let why = stderr.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("loginctl failed with no message");
    Linger::Unreadable(why.to_string())
}

/// Read `user`'s linger on this host.
pub(crate) fn read_linger(user: &str) -> Linger {
    match Command::new("loginctl").args(["show-user", user, "-p", "Linger"]).output() {
        Ok(o) => parse_linger(o.status.success(), &String::from_utf8_lossy(&o.stdout), &String::from_utf8_lossy(&o.stderr)),
        Err(e) => Linger::Unreadable(format!("loginctl could not run: {e}")),
    }
}

/// Onboard's plan: the root command that turns linger on for `user`, or
/// None when it is already on. An unreadable state is enabled anyway
/// (`enable-linger` is idempotent). Pure.
pub(crate) fn enable_plan(user: &str, linger: &Linger) -> Option<Vec<String>> {
    match linger {
        Linger::On => None,
        Linger::Off | Linger::Unreadable(_) => Some(vec!["loginctl".into(), "enable-linger".into(), user.into()]),
    }
}

/// The exact command a person runs for `user`.
pub(crate) fn remedy(user: &str) -> String {
    format!("sudo loginctl enable-linger {user}")
}

/// How this host's controller noo-hostd is supervised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostdKind {
    /// A systemd user unit: starts at boot only with linger.
    UserUnit,
    /// A systemd system unit: starts at boot.
    SystemUnit,
    /// A macOS LaunchAgent: starts at login only.
    LaunchAgent,
    /// No unit or agent here (not installed, or run by hand).
    Absent,
}

/// Which kind, from what exists. The user unit is looked for first: a
/// controller that is also a node has the worker's system unit at
/// [`SYSTEM_UNIT`] beside its own user unit. Pure.
pub(crate) fn kind_from(macos: bool, launch_agent: bool, user_unit: bool, system_unit: bool) -> HostdKind {
    if macos {
        return if launch_agent { HostdKind::LaunchAgent } else { HostdKind::Absent };
    }
    if user_unit {
        HostdKind::UserUnit
    } else if system_unit {
        HostdKind::SystemUnit
    } else {
        HostdKind::Absent
    }
}

/// [`kind_from`] for this host and the user running this command.
pub(crate) fn kind_here() -> HostdKind {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
    let in_home = |rel: &str| !home.as_os_str().is_empty() && home.join(rel).is_file();
    kind_from(cfg!(target_os = "macos"), in_home(LAUNCH_AGENT_REL), in_home(USER_UNIT_REL), Path::new(SYSTEM_UNIT).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linger_reads_from_loginctl_output() {
        assert_eq!(parse_linger(true, "Linger=yes\n", ""), Linger::On);
        assert_eq!(parse_linger(true, "Linger=no\n", ""), Linger::Off);
        assert_eq!(
            parse_linger(false, "", "Failed to get user: User ID 1001 is not logged in or lingering\n"),
            Linger::Off
        );
        match parse_linger(false, "", "Failed to connect to bus: No such file or directory\n") {
            Linger::Unreadable(why) => assert!(why.contains("Failed to connect to bus"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(parse_linger(true, "", ""), Linger::Unreadable(_)));
    }

    #[test]
    fn onboard_enables_linger_only_when_it_is_not_on() {
        assert_eq!(enable_plan("alex", &Linger::On), None);
        let want = Some(vec!["loginctl".to_string(), "enable-linger".into(), "alex".into()]);
        assert_eq!(enable_plan("alex", &Linger::Off), want);
        assert_eq!(enable_plan("alex", &Linger::Unreadable("x".into())), want);
        assert_eq!(remedy("alex"), "sudo loginctl enable-linger alex");
    }

    #[test]
    fn the_user_unit_wins_over_the_worker_system_unit() {
        assert_eq!(kind_from(false, false, true, true), HostdKind::UserUnit);
        assert_eq!(kind_from(false, false, false, true), HostdKind::SystemUnit);
        assert_eq!(kind_from(false, false, false, false), HostdKind::Absent);
        assert_eq!(kind_from(true, true, false, false), HostdKind::LaunchAgent);
        assert_eq!(kind_from(true, false, true, true), HostdKind::Absent);
    }
}
