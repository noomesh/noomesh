// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Run a `noo` command with the docker group active when the user was added
//! to it in THIS login session (i677 finding 10).
//!
//! On a fresh box `noo onboard` installs Docker and adds the user to the
//! `docker` group. A running shell never picks up a new group, so onboard
//! relaunches ITSELF through `sg docker` and finishes. The shell it returns
//! to still lacks the group, though, and the README's next command,
//! `noo stack start`, failed with "permission denied … /var/run/docker.sock"
//! (install matrix, stranger cell, runs 1–3).
//!
//! The fix is the same relaunch, for any `noo` command that needs docker:
//! when docker says "permission denied" AND /etc/group already lists this
//! user in `docker` AND this process does not carry that group, re-run the
//! same command through `sg docker` (`sudo -g docker` where `sg` is missing),
//! once. Anything else (the user is not in the group, the daemon is down,
//! another error) is not this case and is left to the caller's refusal.

use std::process::Command;

/// Set in the relaunched child, so it never relaunches again.
pub(crate) const RELAUNCHED_ENV: &str = "NOO_DOCKER_GROUP_RELAUNCHED";

/// Whether this is the case a relaunch fixes. Pure.
pub(crate) fn should_relaunch(docker_err: &str, listed_in_group: bool, process_has_group: bool, already: bool) -> bool {
    !already && listed_in_group && !process_has_group && docker_err.to_ascii_lowercase().contains("permission denied")
}

/// The `docker` group's gid when /etc/group lists `user` as a member. Pure.
pub(crate) fn docker_gid_listing(etc_group: &str, user: &str) -> Option<u32> {
    if user.is_empty() {
        return None;
    }
    etc_group.lines().find_map(|l| {
        let mut f = l.split(':');
        let (name, _pw, gid, members) = (f.next()?, f.next()?, f.next()?, f.next().unwrap_or(""));
        if name == "docker" && members.split(',').any(|m| m.trim() == user) {
            gid.parse().ok()
        } else {
            None
        }
    })
}

/// This process's group ids from /proc/self/status (`Gid:` effective and the
/// supplementary `Groups:`). Pure.
pub(crate) fn process_gids(status: &str) -> Vec<u32> {
    let mut gids = Vec::new();
    for l in status.lines() {
        if let Some(rest) = l.strip_prefix("Groups:") {
            gids.extend(rest.split_whitespace().filter_map(|g| g.parse::<u32>().ok()));
        } else if let Some(rest) = l.strip_prefix("Gid:") {
            if let Some(eg) = rest.split_whitespace().nth(1).and_then(|g| g.parse::<u32>().ok()) {
                gids.push(eg);
            }
        }
    }
    gids
}

/// Re-run this exact `noo` invocation with the docker group active, when
/// [`should_relaunch`] says that is the fix. `Some(exit code)` when it ran
/// the command that way (the caller returns it); `None` when this is not the
/// case, or no relaunch path worked (the caller then refuses as before).
pub(crate) fn relaunch_if_needed(docker_err: &str) -> Option<i32> {
    let already = std::env::var_os(RELAUNCHED_ENV).is_some();
    let user = std::env::var("USER").unwrap_or_default();
    let etc = std::fs::read_to_string("/etc/group").ok()?;
    let gid = docker_gid_listing(&etc, &user);
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let has = gid.is_some_and(|g| process_gids(&status).contains(&g));
    if !should_relaunch(docker_err, gid.is_some(), has, already) {
        return None;
    }
    eprintln!(
        "→ {user} was added to the docker group in this session, and this shell does not have it yet: \
         running this command through it (open a new terminal to make it permanent)"
    );
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "noo".into());
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let quoted: Vec<String> = std::iter::once(&exe)
        .chain(argv.iter())
        .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
        .collect();
    Command::new("sg")
        .args(["docker", "-c", &quoted.join(" ")])
        .env(RELAUNCHED_ENV, "1")
        .status()
        .ok()
        .and_then(|s| s.code())
        .or_else(|| {
            // Ubuntu 25.10 ships without `sg` (onboard found it live): the
            // same user, docker as the effective group. sudo resets the
            // environment, so the marker rides on `env`.
            // Never a password prompt nobody can answer: -n without a terminal.
            let mut sudo = Command::new("sudo");
            if unsafe { libc::isatty(0) } != 1 {
                sudo.arg("-n");
            }
            sudo.args(["-g", "docker", "env", &format!("{RELAUNCHED_ENV}=1"), &exe])
                .args(&argv)
                .status()
                .ok()
                .and_then(|s| s.code())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENIED: &str = "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock";

    /// Only the case it fixes: listed in /etc/group, not in this process,
    /// docker said permission denied, not already relaunched.
    #[test]
    fn it_relaunches_only_the_fresh_group_case() {
        assert!(should_relaunch(DENIED, true, false, false));
        assert!(!should_relaunch(DENIED, false, false, false), "not in the group at all: a relaunch cannot help");
        assert!(!should_relaunch(DENIED, true, true, false), "the process already has it: something else is wrong");
        assert!(!should_relaunch(DENIED, true, false, true), "never twice");
        assert!(!should_relaunch("Cannot connect to the Docker daemon … Is the docker daemon running?", true, false, false),
            "a daemon that is down is not a group problem");
    }

    /// Every docker-gated `noo` path tries the relaunch before it refuses,
    /// and run_script tries it before any launcher runs.
    #[test]
    fn every_docker_gate_tries_the_relaunch_before_refusing() {
        let off = crate::test_src::own_code(include_str!("commands/offboard.rs"));
        let walk = crate::test_src::fn_body(&off, "pub fn offboard(");
        let r = walk.find("crate::docker_group::relaunch_if_needed(&why)").expect("offboard tries it");
        let refuse = walk.find("docker_unreachable_refusal(&why, \"noo offboard\")").expect("then refuses");
        assert!(r < refuse, "{walk}");
        let mesh = crate::test_src::own_code(include_str!("commands/mesh.rs"));
        for (f, verb) in [("pub fn mesh_clean(", "noo stack clean"), ("pub fn mesh_stop(", "noo stack stop --volumes")] {
            let body = crate::test_src::fn_body(&mesh, f);
            let r = body.find("crate::docker_group::relaunch_if_needed(&why)").unwrap_or_else(|| panic!("{f} tries it"));
            let refuse = body.find(&format!("docker_unreachable_refusal(&why, \"{verb}\")")).unwrap_or_else(|| panic!("{f} refuses"));
            assert!(r < refuse, "{body}");
        }
        let run = crate::test_src::fn_body(&mesh, "fn run_script(");
        let r = run.find("crate::docker_group::relaunch_if_needed(&why)").expect("run_script tries it");
        let script = run.find("let script = root.join(\"scripts\").join(name);").expect("before the launcher");
        assert!(r < script, "{run}");
    }

    /// onboard's own relaunch (after it installs Docker) carries the marker,
    /// so its closing block can say what the user's shell still lacks.
    #[test]
    fn onboards_relaunch_carries_the_marker_and_the_closing_block_uses_it() {
        let steps = crate::test_src::own_code(include_str!("onboard/steps.rs"));
        let pre = crate::test_src::fn_body(&steps, "pub fn prerequisites(");
        assert!(pre.contains(".env(marker, \"1\")"), "sg path: {pre}");
        assert!(pre.contains(".args([\"-g\", \"docker\", \"env\", &format!(\"{marker}=1\"), &exe])"), "sudo path: {pre}");
        assert_eq!(crate::onboard::docker_group_closing_line(false), None);
        let l = crate::onboard::docker_group_closing_line(true).expect("a line");
        assert!(l.contains("newgrp docker") && l.contains("`noo` commands work"), "{l}");
    }

    #[test]
    fn the_group_listing_and_the_process_groups_are_read_exactly() {
        let etc = "root:x:0:\nsudo:x:27:runner\ndocker:x:999:alice,runner\nrunnerx:x:1002:\n";
        assert_eq!(docker_gid_listing(etc, "runner"), Some(999));
        assert_eq!(docker_gid_listing(etc, "run"), None, "a member is a whole name, not a prefix");
        assert_eq!(docker_gid_listing(etc, "bob"), None);
        assert_eq!(docker_gid_listing(etc, ""), None);
        assert_eq!(docker_gid_listing("docker:x:999:\n", "runner"), None, "an empty member list");
        let status = "Name:\tnoo\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\nGroups:\t4 24 27 1001 \n";
        assert_eq!(process_gids(status), vec![1001, 4, 24, 27, 1001]);
        assert!(!process_gids(status).contains(&999));
        let status_after = "Gid:\t1001\t999\t1001\t1001\nGroups:\t4 27\n";
        assert!(process_gids(status_after).contains(&999), "sg makes docker the effective gid");
    }
}
