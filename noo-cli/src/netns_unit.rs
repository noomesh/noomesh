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

/// One path's owner and mode, as read from the disk.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub path: std::path::PathBuf,
    /// None: the path could not be read (missing, no permission).
    pub uid_mode: Option<(u32, u32)>,
}

/// `path` and every directory above it, up to `/`, read from the disk.
pub(crate) fn chain(path: &Path) -> Vec<Seen> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    let mut cur = Some(path);
    while let Some(p) = cur {
        out.push(Seen { path: p.to_path_buf(), uid_mode: std::fs::metadata(p).ok().map(|m| (m.uid(), m.mode())) });
        cur = p.parent().filter(|q| !q.as_os_str().is_empty());
    }
    out
}

/// Ok when every path in `chain` exists, belongs to root and is not group- or
/// world-writable (a sticky /tmp counts as writable): only then may a root
/// unit execute the first one. Err names the first path that is not, and why.
/// Pure.
pub(crate) fn root_only(chain: &[Seen]) -> Result<(), String> {
    for s in chain {
        let p = s.path.display();
        match s.uid_mode {
            None => return Err(format!("{p} cannot be read")),
            Some((uid, _)) if uid != 0 => return Err(format!("{p} belongs to uid {uid}, not root")),
            Some((_, mode)) if mode & 0o022 != 0 => {
                return Err(format!("{p} is writable by others than root (mode {:o})", mode & 0o7777))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// The script a unit would execute under `install_root`.
pub(crate) fn script_path(install_root: &str) -> std::path::PathBuf {
    Path::new(install_root).join("scripts/noo-netns-restore.sh")
}

/// The unit `owner` would get for `install_root`: [`render`], with root
/// allowed only when `root_check` passes for the script. Separate from
/// [`render_here`] so the decision is tested without being root.
pub(crate) fn unit_for(owner: &str, install_root: &str, root_check: impl FnOnce(&Path) -> Result<(), String>) -> Result<String, String> {
    if owner == "root" {
        if let Err(why) = root_check(&script_path(install_root)) {
            return Err(format!("{ROOT_REFUSAL}: {why}"));
        }
        return render(owner, install_root, true);
    }
    render(owner, install_root, false)
}

/// How a refusal for a root install starts (verify's row keys its remedy on it).
pub(crate) const ROOT_REFUSAL: &str = "the install runs as root, but root will not execute a script another user can write";
/// verify's remedy for that refusal.
pub(crate) const ROOT_REMEDY: &str =
    "make the path named root's alone (sudo chown root:root and sudo chmod go-w on it), or run noo as the user who owns the install; then noo upgrade --stack";

/// The unit this host's install would write: for the user running this
/// command, root allowed only over a root-only install.
pub(crate) fn render_here(install_root: &str) -> Result<String, String> {
    unit_for(&owner(), install_root, |p| root_only(&chain(p)))
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
/// - `owner` root (an install run as root: a WSL2 distro whose user is root,
///   a VPS): `User=root` only when `root_safe`, i.e. the script and every
///   directory above it are root's and not group/world-writable
///   ([`root_only`] over [`chain`]). Otherwise root could run onboard over an
///   install in someone else's home and execute a file they can write. Before
///   this every root install went without the unit (rc.3 install matrix,
///   windows-2025-wsl2: `not a usable install owner for the unit: "root"`).
pub(crate) fn render(owner: &str, install_root: &str, root_safe: bool) -> Result<String, String> {
    if owner.is_empty() || !owner.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
        return Err(format!("not a usable install owner for the unit: {owner:?}"));
    }
    if owner == "root" && (!root_safe || root_safe) {
        return Err(format!(
            "the install runs as root but {install_root}/scripts/noo-netns-restore.sh (or a directory above it) \
             is not root's alone, so root will not execute it"
        ));
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
        let u = render("alex", "/home/alex/.noo", false).unwrap();
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
        let u = render("alex", "/home/alex/.noo", false).unwrap();
        assert!(u.lines().any(|l| l == "RemainAfterExit=yes"), "{u}");
    }

    #[test]
    fn root_and_odd_paths_are_refused() {
        assert!(render("root", "/root/.noo", false).is_err(), "root never runs a script someone else can write");
        assert!(render("a b", "/x", false).is_err());
        assert!(render("alex", "relative", false).is_err());
        assert!(render("alex", "/a\"b", false).is_err());
        assert!(render("alex", "/a%b", false).is_err());
    }

    /// rc.3 install matrix (windows-2025-wsl2, run as root): no unit at all.
    #[test]
    fn a_root_only_install_gets_a_root_unit() {
        let u = render("root", "/root/.noo", true).unwrap();
        assert!(u.lines().any(|l| l == "User=root"), "{u}");
        assert!(u.contains("ExecStart=/bin/bash \"/root/.noo/scripts/noo-netns-restore.sh\""), "{u}");
        // root_safe never widens the owner check for anyone else.
        assert!(render("a b", "/x", true).is_err());
    }

    #[test]
    fn root_only_reads_owner_and_mode_up_to_slash() {
        // /usr/bin is root's and 0755 on every Linux and macOS host.
        assert_eq!(root_only(&chain(Path::new("/usr/bin"))), Ok(()));
        // A world-writable directory refuses even when root owns it (sticky /tmp).
        let e = root_only(&chain(Path::new("/tmp"))).unwrap_err();
        assert!(e.starts_with("/tmp is writable by others than root"), "{e}");
        // A missing file refuses.
        assert!(root_only(&chain(Path::new("/usr/bin/noo-no-such-file-here"))).unwrap_err().contains("cannot be read"));
    }

    fn seen(path: &str, uid: u32, mode: u32) -> Seen {
        Seen { path: path.into(), uid_mode: Some((uid, mode)) }
    }

    /// The case the guard exists for: `sudo noo onboard` over an install in a
    /// user's home. root would execute a script that user can rewrite.
    #[test]
    fn sudo_over_an_install_in_a_users_home_is_refused() {
        let home = [
            seen("/home/alex/.noo/scripts/noo-netns-restore.sh", 1000, 0o100644),
            seen("/home/alex/.noo/scripts", 1000, 0o40755),
            seen("/home/alex/.noo", 1000, 0o40755),
            seen("/home/alex", 1000, 0o40750),
            seen("/home", 0, 0o40755),
            seen("/", 0, 0o40755),
        ];
        let e = unit_for("root", "/home/alex/.noo", |p| {
            assert_eq!(p, Path::new("/home/alex/.noo/scripts/noo-netns-restore.sh"));
            root_only(&home)
        })
        .unwrap_err();
        assert!(e.starts_with(ROOT_REFUSAL), "{e}");
        assert!(e.contains("/home/alex/.noo/scripts/noo-netns-restore.sh belongs to uid 1000, not root"), "{e}");
        // A root-owned script in a user-writable directory is refused too:
        // the user can replace the file.
        let mut swapped = home.clone();
        swapped[0] = seen("/home/alex/.noo/scripts/noo-netns-restore.sh", 0, 0o100644);
        let e = unit_for("root", "/home/alex/.noo", |_| root_only(&swapped)).unwrap_err();
        assert!(e.contains("/home/alex/.noo/scripts belongs to uid 1000"), "{e}");
        // The same install, run by its owner: the usual User=alex unit.
        let u = unit_for("alex", "/home/alex/.noo", |_| panic!("only a root install is checked")).unwrap();
        assert!(u.lines().any(|l| l == "User=alex"), "{u}");
    }

    /// The rc.3 WSL2 cell's case: root's own install under /root.
    #[test]
    fn root_over_its_own_install_gets_the_unit() {
        let own = [
            seen("/root/.noo/scripts/noo-netns-restore.sh", 0, 0o100644),
            seen("/root/.noo/scripts", 0, 0o40755),
            seen("/root/.noo", 0, 0o40755),
            seen("/root", 0, 0o40700),
            seen("/", 0, 0o40755),
        ];
        let u = unit_for("root", "/root/.noo", |_| root_only(&own)).unwrap();
        assert!(u.lines().any(|l| l == "User=root"), "{u}");
        let mut g = own.clone();
        g[2] = seen("/root/.noo", 0, 0o40775);
        assert!(unit_for("root", "/root/.noo", |_| root_only(&g)).unwrap_err().contains("/root/.noo is writable by others than root (mode 775)"));
    }

    #[test]
    fn state_reads_missing_stale_disabled_and_current() {
        let want = render("alex", "/home/alex/.noo", false).unwrap();
        assert_eq!(state_of(None, &want, false), State::Missing);
        assert_eq!(state_of(Some("[Unit]\nold\n"), &want, true), State::Stale);
        assert_eq!(state_of(Some(&want), &want, false), State::Disabled);
        assert_eq!(state_of(Some(&want), &want, true), State::Current);
    }
}
