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
    if owner == "root" && !root_safe {
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

/// i907 step 1b: the bundle kind the controller's self-node applier renders
/// the unit from (scripts/noo-apply.sh, block `netns_unit`). The unit text is
/// the applier's own template; the kind carries only [`payload`].
pub(crate) const KIND: &str = "netns-unit";
/// This machine's root applier: the self-node's, installed by prep-host
/// (root:root 0755, so readable here without root).
pub(crate) const APPLIER_PATH: &str = "/usr/local/bin/noo-apply";
/// The applier generation that has the release check (i908) and, from the
/// same release on, the `netns-unit` kind.
pub(crate) const MIN_APPLIER_GENERATION: u32 = 2;

/// The kind's payload: the install owner and root, nothing else. The applier
/// refuses any other line and checks both against the host. Pure.
pub(crate) fn payload(owner: &str, install_root: &str) -> String {
    format!("user={owner}\nroot={install_root}\n")
}

/// What an applier can do, read from its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Applier {
    pub generation: u32,
    /// Its KNOWN_KINDS names [`KIND`]: an applier without it exits 76 on the
    /// whole bundle.
    pub knows_kind: bool,
}

/// [`Applier`] from the applier's own text (`NOO_APPLY_GENERATION=` and
/// `KNOWN_KINDS="…"` lines). Pure.
pub(crate) fn applier_of(text: &str) -> Applier {
    let generation = text.lines().find_map(|l| l.strip_prefix("NOO_APPLY_GENERATION="))
        .and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(0);
    let knows_kind = text.lines().find_map(|l| l.strip_prefix("KNOWN_KINDS=\""))
        .map(|v| v.trim_end_matches('"').split_whitespace().any(|k| k == KIND)).unwrap_or(false);
    Applier { generation, knows_kind }
}

/// This machine's applier, if it has one.
pub(crate) fn applier_here() -> Option<Applier> {
    std::fs::read_to_string(APPLIER_PATH).ok().map(|t| applier_of(&t))
}

/// How the unit reaches this controller (i907 step 1b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Route {
    /// The self-node's applier knows the kind: stage it, no sudo.
    Stage,
    /// The self-node's applier (this generation) predates the kind; staging it
    /// would refuse the bundle (exit 76). Named, nothing run, no sudo.
    OldApplier(u32),
    /// No applier here (or a root install, which the applier never renders):
    /// the one stated root step, which `root_step_runs` lets run.
    Sudo,
    /// The same, refused: no terminal, no `--root-ok`, not root. The line says
    /// the step and the command.
    Stated(String),
}

/// The decision. Pure over what was read: whether the install owner is root
/// (the applier never renders `User=root`), this machine's applier, whether
/// it has a self node, and [`crate::onboard::steps::root_step`]'s inputs.
pub(crate) fn route(owner_is_root: bool, applier: Option<Applier>, self_node: bool, at_terminal: bool, root_ok: bool) -> Route {
    if self_node {
        match applier {
            Some(a) if a.generation >= MIN_APPLIER_GENERATION && a.knows_kind => return Route::Stage,
            Some(a) => return Route::OldApplier(a.generation),
            None => {}
        }
    }
    // root_step's rule, worded here: `noo upgrade` has no `--root-ok` to offer.
    if crate::onboard::steps::root_step_runs(at_terminal, root_ok) {
        Route::Sudo
    } else {
        Route::Stated(format!(
            "installing {UNIT_NAME} needs root, this controller has no self-node applier to do it, and this run has \
             no terminal to ask at: run it once at a terminal: {REMEDY}"))
    }
}

/// `noo cluster verify`'s remedy for a missing/stale/disabled unit, by route.
pub(crate) fn remedy_for(owner_is_root: bool, applier: Option<Applier>, self_node: bool) -> &'static str {
    // The terminal question does not change the remedy: it is run at one.
    match route(owner_is_root, applier, self_node, true, false) {
        Route::Stage => STAGE_REMEDY,
        Route::OldApplier(_) => OLD_APPLIER_REMEDY,
        Route::Sudo | Route::Stated(_) => SUDO_REMEDY,
    }
}
/// The self-node's applier installs it; nothing asks for a password.
pub(crate) const STAGE_REMEDY: &str = "noo upgrade --stack (the self-node's applier installs it; no sudo)";
/// One roll brings the self-node an applier that knows the kind, the next installs the unit.
pub(crate) const OLD_APPLIER_REMEDY: &str =
    "noo upgrade --all (it brings the self-node an applier that knows netns-unit), then noo upgrade --stack installs it with no sudo";
/// No applier on this controller: the one stated sudo.
pub(crate) const SUDO_REMEDY: &str =
    "noo upgrade --stack at a terminal (sudo asks once: this controller has no self-node applier to install it)";

/// The self-node's verdict on the kind, from its apply report. Pure.
pub(crate) fn apply_verdict(apply_msg: &str) -> Result<(), String> {
    for t in apply_msg.split_whitespace() {
        if let Some(v) = t.strip_prefix("netns-unit=") {
            if v.starts_with("REFUSED") || v == "NOT-ENABLED" {
                return Err(format!("the self-node's applier said netns-unit={v}"));
            }
        }
    }
    Ok(())
}

/// Stage the kind to the self node `node` and wait for its applier (the
/// rail's pull, a poke, the apply report). Ok only for an exit-0 apply that
/// did not refuse the kind.
pub(crate) fn stage_to_self_node(g: &crate::Globals, node: &str, owner: &str, install_root: &str) -> Result<(), String> {
    use crate::commands::security_local as sl;
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    if !ca.ca_exists() {
        return Err("no cluster CA here".into());
    }
    let work = crate::private_tmp::dir(&format!("noo-{KIND}-{node}"))?;
    let files = [(KIND, payload(owner, install_root).into_bytes())];
    let out = sl::build_signed_bundle(&ca, node, &files, &work).map(|b| sl::deliver_signed_bundle(g, node, &b, &work, None));
    let _ = std::fs::remove_dir_all(&work);
    match out? {
        sl::CertDelivery::Applied => apply_verdict(&crate::commands::provision::reported_apply_msg(g, node)),
        other => Err(other.label()),
    }
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

    const GEN2_WITH_KIND: &str = "#!/bin/bash\nNOO_APPLY_GENERATION=2\nKNOWN_KINDS=\"ca.crt applier netns-unit\"\n";
    const GEN2_WITHOUT: &str = "#!/bin/bash\nNOO_APPLY_GENERATION=2\nKNOWN_KINDS=\"ca.crt applier\"\n";
    const GEN1: &str = "#!/bin/bash\nNOO_APPLY_GENERATION=1\nKNOWN_KINDS=\"ca.crt applier\"\n";

    #[test]
    fn the_applier_is_read_from_its_own_text() {
        assert_eq!(applier_of(GEN2_WITH_KIND), Applier { generation: 2, knows_kind: true });
        assert_eq!(applier_of(GEN2_WITHOUT), Applier { generation: 2, knows_kind: false });
        assert_eq!(applier_of(GEN1), Applier { generation: 1, knows_kind: false });
        assert_eq!(applier_of("#!/bin/sh\n"), Applier { generation: 0, knows_kind: false });
        // A kind whose name only contains ours is not ours.
        assert!(!applier_of("KNOWN_KINDS=\"netns-unit-2\"\n").knows_kind);
    }

    /// The shipped applier knows the kind and is the generation the route
    /// stages to: the pair the controller decides from.
    #[test]
    fn the_shipped_applier_takes_the_kind() {
        let Some(p) = crate::test_support::repo_file_or_skip("scripts/noo-apply.sh") else { return };
        let src = std::fs::read_to_string(p).expect("scripts/noo-apply.sh");
        let a = applier_of(&src);
        assert!(a.knows_kind && a.generation >= MIN_APPLIER_GENERATION, "{a:?}");
    }

    /// i907 step 1b: an applier of generation 2 that knows the kind gets it
    /// staged; nothing runs sudo.
    #[test]
    fn a_gen2_self_node_applier_is_staged_to() {
        let a = applier_of(GEN2_WITH_KIND);
        for tty in [true, false] {
            assert_eq!(route(false, Some(a), true, tty, false), Route::Stage);
        }
        assert_eq!(remedy_for(false, Some(a), true), STAGE_REMEDY);
    }

    /// An older applier would exit 76 on the whole bundle: skipped and named,
    /// never sudo, terminal or not.
    #[test]
    fn an_old_applier_is_skipped_and_named_never_sudo() {
        for (text, generation) in [(GEN1, 1), (GEN2_WITHOUT, 2)] {
            for tty in [true, false] {
                assert_eq!(route(false, Some(applier_of(text)), true, tty, true), Route::OldApplier(generation));
            }
            assert_eq!(remedy_for(false, Some(applier_of(text)), true), OLD_APPLIER_REMEDY);
        }
    }

    /// No applier (or no self node): the one stated sudo, under root_step's
    /// rule (#1287): a terminal, --root-ok, or already root; else said, not run.
    #[test]
    fn no_applier_is_a_stated_sudo_per_root_step() {
        let gen2 = Some(applier_of(GEN2_WITH_KIND));
        for (applier, self_node) in [(None, true), (None, false), (gen2, false)] {
            assert_eq!(route(false, applier, self_node, true, false), Route::Sudo);
            assert_eq!(route(false, applier, self_node, false, true), Route::Sudo);
            let Route::Stated(why) = route(false, applier, self_node, false, false) else { panic!("no terminal, no --root-ok, not root") };
            assert!(why.contains(REMEDY) && why.contains(UNIT_NAME), "{why}");
            assert_eq!(remedy_for(false, applier, self_node), SUDO_REMEDY);
        }
        crate::onboard::steps::AS_ROOT.with(|c| c.set(true));
        let as_root = route(false, None, true, false, false);
        crate::onboard::steps::AS_ROOT.with(|c| c.set(false));
        assert_eq!(as_root, Route::Sudo, "a root process runs its root step");
    }

    /// The applier never renders User=root: a root install takes the root
    /// step even beside an applier that knows the kind.
    #[test]
    fn a_root_install_is_never_staged() {
        assert_eq!(route(true, Some(applier_of(GEN2_WITH_KIND)), true, true, false), Route::Sudo);
        assert!(matches!(route(true, Some(applier_of(GEN2_WITH_KIND)), true, false, false), Route::Stated(_)));
    }

    /// i907 step 1b: the roll reaches `install` (sudo_write_root_file's
    /// `sudo tee` of the unit) only from its no-applier arm; the stage arm
    /// and the old-applier arm run no sudo.
    #[test]
    fn the_roll_installs_with_sudo_only_where_there_is_no_applier() {
        let up = crate::test_src::own_code(include_str!("commands/upgrade.rs"));
        let body = crate::test_src::fn_body(&up, "fn reconcile_netns_unit(");
        assert_eq!(body.matches("nu::install(").count(), 1, "{body}");
        let stage = body.find("nu::Route::Stage =>").expect("the stage arm");
        let sudo = body.find("nu::Route::Sudo =>").expect("the no-applier arm");
        let at = body.find("nu::install(").unwrap();
        let stated = body.find("nu::Route::Stated(").expect("the stated arm");
        assert!(stage < sudo && sudo < at && at < stated, "{body}");
        assert!(body[stage..sudo].contains("nu::stage_to_self_node("), "{body}");
        assert!(!body.contains("sudo_write_root_file") && !body.contains("sudo_cmd"), "{body}");
    }

    #[test]
    fn the_payload_is_two_lines_and_the_verdict_reads_a_refusal() {
        assert_eq!(payload("alex", "/home/alex/.noo"), "user=alex\nroot=/home/alex/.noo\n");
        assert_eq!(apply_verdict("applied: netns-unit release-check: generation=2"), Ok(()));
        assert_eq!(apply_verdict("applied: netns-unit=unchanged"), Ok(()));
        assert!(apply_verdict("applied: netns-unit=REFUSED:root-owner").unwrap_err().contains("REFUSED:root-owner"));
        assert!(apply_verdict("applied: netns-unit=NOT-ENABLED").is_err());
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
