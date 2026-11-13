// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
//! `noo-netns-restore.service`: the one place that renders, reads, installs and
//! removes it, so onboard, `noo upgrade`, `noo cluster verify`, `noo offboard`
//! and `noo stack clean` cannot drift (we remove what we install).
//!
//! It runs `scripts/noo-netns-restore.sh` at every dockerd start: dockerd's
//! own restore can start a container that joins another's network namespace
//! (noo-ollama-embed joins noo-stunnel-ollama-embed) before its door, fails it
//! with exit 128 and never retries it (rc.2 install matrix, one dockerd start
//! in five on a hosted 22.04 runner).
use std::path::Path;
use std::process::Command;

pub(crate) const UNIT_NAME: &str = "noo-netns-restore.service";
pub(crate) const UNIT_PATH: &str = "/etc/systemd/system/noo-netns-restore.service";
/// What installs it on an existing controller: the stack stage's reconcile
/// (a same-tag `noo upgrade --stack` re-runs it), in a terminal so sudo can ask.
pub(crate) const REMEDY: &str = "noo upgrade --stack";

pub(crate) fn systemd_here() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// The install owner (who runs the unit): the user running this command.
pub(crate) fn owner() -> String {
    Command::new("id").arg("-un").output().ok().filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

/// The unit text. Pure.
///
/// - `WantedBy=docker.service`: started whenever dockerd starts, boot included.
/// - `PartOf=docker.service`: re-run when dockerd is restarted (a package
///   upgrade, `systemctl restart docker`).
/// - `After=docker.service`: behind dockerd's own restore.
/// - `Type=oneshot` + `RemainAfterExit=yes`: one bounded pass, nothing left
///   running, and the unit then reads "active (exited)" (what the verify row
///   shows). RemainAfterExit does not stop the re-run: on systemd 249 a
///   throwaway door unit with two PartOf=/WantedBy= oneshots, one with and one
///   without it, re-ran both on every door restart and on stop-then-start
///   (fa, 2026-11-12; i677a/#1108).
/// - `User=<owner>` (in the docker group): the script lives in the owner's
///   install, so root never executes a file the owner can write.
pub(crate) fn render(owner: &str, install_root: &str) -> Result<String, String> {
    if owner.is_empty() || owner == "root" || !owner.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
        return Err(format!("not a usable install owner for the unit: {owner:?}"));
    }
    if !install_root.starts_with('/') || install_root.contains(['"', '\n', '\\', '%']) {
        return Err(format!("not a usable install path for the unit: {install_root:?}"));
    }
    Ok(format!(
        "[Unit]\n\
         Description=noomesh: start the containers that join another's network after dockerd starts\n\
         After=docker.service\n\
         PartOf=docker.service\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         User={owner}\n\
         ExecStart=/bin/bash \"{install_root}/scripts/noo-netns-restore.sh\"\n\
         \n\
         [Install]\n\
         WantedBy=docker.service\n"
    ))
}

/// What is on this host compared with the unit this install would write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// Installed, the current text, enabled.
    Current,
    /// Installed but not the text this install writes (an older one, a moved install).
    Stale,
    /// The current text, not enabled: dockerd starts do not run it.
    Disabled,
    Missing,
}

/// Pure over what was read.
pub(crate) fn state_of(on_disk: Option<&str>, expected: &str, enabled: bool) -> State {
    match on_disk {
        None => State::Missing,
        Some(t) if t != expected => State::Stale,
        Some(_) if !enabled => State::Disabled,
        Some(_) => State::Current,
    }
}

pub(crate) fn state(expected: &str) -> State {
    let disk = std::fs::read_to_string(UNIT_PATH).ok();
    let enabled = Command::new("systemctl").args(["is-enabled", UNIT_NAME]).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled").unwrap_or(false);
    state_of(disk.as_deref(), expected, enabled)
}

/// Write the unit (root:root 0644), reload, enable. `may_prompt`: sudo may ask
/// on a terminal; otherwise `sudo -n`, which fails instead of blocking.
pub(crate) fn install(may_prompt: bool, unit: &str) -> Result<(), String> {
    crate::onboard::steps::sudo_write_root_file(may_prompt, UNIT_PATH, unit)?;
    for argv in [&["systemctl", "daemon-reload"][..], &["systemctl", "enable", UNIT_NAME][..]] {
        if !crate::onboard::steps::sudo_cmd(may_prompt).args(argv).status().map(|s| s.success()).unwrap_or(false) {
            return Err(format!("`sudo {}` failed", argv.join(" ")));
        }
    }
    Ok(())
}

/// Disable and delete it. Ok(false): it was not there.
pub(crate) fn remove(may_prompt: bool) -> Result<bool, String> {
    if !Path::new(UNIT_PATH).exists() {
        return Ok(false);
    }
    let _ = crate::onboard::steps::sudo_cmd(may_prompt).args(["systemctl", "disable", UNIT_NAME]).status();
    if !crate::onboard::steps::sudo_cmd(may_prompt).args(["rm", "-f", UNIT_PATH]).status().map(|s| s.success()).unwrap_or(false) {
        return Err(format!("could not remove {UNIT_PATH} (sudo rm)"));
    }
    let _ = crate::onboard::steps::sudo_cmd(may_prompt).args(["systemctl", "daemon-reload"]).status();
    Ok(true)
}

/// The manual commands, for a host where sudo could not run here.
pub(crate) fn manual_removal() -> String {
    format!("sudo systemctl disable {UNIT_NAME}; sudo rm -f {UNIT_PATH}; sudo systemctl daemon-reload")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_runs_at_every_dockerd_start_as_the_owner() {
        let u = render("alex", "/home/alex/.noo").unwrap();
        for line in ["After=docker.service", "PartOf=docker.service", "WantedBy=docker.service", "Type=oneshot",
                     "User=alex", "ExecStart=/bin/bash \"/home/alex/.noo/scripts/noo-netns-restore.sh\""] {
            assert!(u.lines().any(|l| l == line), "{line} missing:\n{u}");
        }
        assert_eq!(UNIT_NAME, "noo-netns-restore.service");
    }

    /// RemainAfterExit=yes is deliberate: the unit reads "active (exited)"
    /// after a pass, and it does NOT stop the re-run on a dockerd restart
    /// (systemd 249 experiment cited on `render`).
    #[test]
    fn remain_after_exit_is_set() {
        let u = render("alex", "/home/alex/.noo").unwrap();
        assert!(u.lines().any(|l| l == "RemainAfterExit=yes"), "{u}");
    }

    #[test]
    fn root_and_odd_paths_are_refused() {
        assert!(render("root", "/root/.noo").is_err(), "root never runs the owner's script");
        assert!(render("a b", "/x").is_err());
        assert!(render("alex", "relative").is_err());
        assert!(render("alex", "/a\"b").is_err());
        assert!(render("alex", "/a%b").is_err());
    }

    #[test]
    fn state_reads_missing_stale_disabled_and_current() {
        let want = render("alex", "/home/alex/.noo").unwrap();
        assert_eq!(state_of(None, &want, false), State::Missing);
        assert_eq!(state_of(Some("[Unit]\nold\n"), &want, true), State::Stale);
        assert_eq!(state_of(Some(&want), &want, false), State::Disabled);
        assert_eq!(state_of(Some(&want), &want, true), State::Current);
    }
}
