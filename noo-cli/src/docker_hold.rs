// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
//! The apt holds `noo onboard` places on the Docker it installs (i1098 row 12,
//! operator 2026-11-21). This file decides which packages are held, records
//! them, releases them and words them, so onboard, `noo offboard` and
//! `noo cluster verify` agree. We release what we hold, and nothing else.
//!
//! An unattended upgrade of `docker-ce` or `containerd.io` restarts dockerd,
//! and a dockerd restart restarts every container on the machine. Onboard
//! holds only the packages its own Docker install added: absent before the
//! install, present after it. A Docker that was already on the machine
//! belongs to the person and is never held, on any run.
//!
//! Only apt: onboard installs Docker only where apt is (get.docker.com from
//! the prerequisites step). On dnf or zypper it installs nothing, so it holds
//! nothing there.

use std::process::{Command, Stdio};

/// The record of what onboard held: one package per line. Machine-level, like
/// the holds themselves, so it outlives the install home and a residue-mode
/// `noo offboard` still releases them. World-readable, so `noo cluster verify`
/// reads it without sudo.
pub(crate) const RECORD_PATH: &str = "/etc/noo/onboard-docker-holds";

/// The Docker packages onboard may hold: the Docker part of the platform set
/// that verify's `holds` row judges (hostd's PlatformPackagePattern). The
/// get.docker.com extras (rootless, model plugin) are not in it and are never
/// held.
pub(crate) const CANDIDATES: [&str; 5] = ["containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli", "docker-compose-plugin"];

const RECORD_HEADER: &str = "# noo onboard installed these Docker packages and held them (apt-mark hold),\n\
# so an unattended upgrade cannot restart dockerd. noo offboard releases exactly these.\n";

/// Whether `dpkg-query -W -f='${Status}'` says installed: its third word
/// (a held package reads "hold ok installed"). Pure.
pub(crate) fn status_installed(status: &str) -> bool {
    status.split_whitespace().nth(2) == Some("installed")
}

/// Whether the same status says held: its first word (the selection state)
/// is "hold". Pure.
pub(crate) fn status_held(status: &str) -> bool {
    status.split_whitespace().next() == Some("hold")
}

/// What the hold steps do to the machine. Every decision is in this file, so
/// a test drives it with a fake.
pub(crate) trait HoldHost {
    /// Whether dpkg says `pkg` is installed now.
    fn installed(&mut self, pkg: &str) -> bool;
    /// Whether dpkg says `pkg` is held now.
    fn held(&mut self, pkg: &str) -> bool;
    /// Run `argv` as root; true when it exited 0.
    fn run_root(&mut self, argv: &[String]) -> bool;
    /// The record's text; `None` when there is none.
    fn read_record(&mut self) -> Option<String>;
    fn write_record(&mut self, body: &str) -> Result<(), String>;
    /// Delete the record; true when it is gone.
    fn remove_record(&mut self) -> bool;
}

/// The candidates dpkg says are installed now, in [`CANDIDATES`] order.
pub(crate) fn installed_now(h: &mut impl HoldHost) -> Vec<String> {
    CANDIDATES.iter().filter(|p| h.installed(p)).map(|p| p.to_string()).collect()
}

/// What this run installed: in `after` and not in `before`. Pure.
pub(crate) fn installed_by_this_run(before: &[String], after: &[String]) -> Vec<String> {
    after.iter().filter(|p| !before.contains(p)).cloned().collect()
}

/// `apt-mark hold <pkgs>` (run as root). Pure.
pub(crate) fn hold_argv(pkgs: &[String]) -> Vec<String> {
    ["apt-mark", "hold"].iter().map(|s| s.to_string()).chain(pkgs.iter().cloned()).collect()
}

/// `apt-mark unhold <pkgs>` (run as root). Pure.
pub(crate) fn unhold_argv(pkgs: &[String]) -> Vec<String> {
    ["apt-mark", "unhold"].iter().map(|s| s.to_string()).chain(pkgs.iter().cloned()).collect()
}

/// The record's packages, sorted. Blank and `#` lines are skipped, and only
/// [`CANDIDATES`] count, so an edited record can never make offboard unhold a
/// package outside Docker's set. Pure.
pub(crate) fn parse_record(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| CANDIDATES.contains(l))
        .map(str::to_string)
        .collect();
    v.sort();
    v.dedup();
    v
}

/// The record's text for `pkgs`. Pure.
pub(crate) fn render_record(pkgs: &[String]) -> String {
    let mut s = String::from(RECORD_HEADER);
    for p in pkgs {
        s.push_str(p);
        s.push('\n');
    }
    s
}

/// What onboard recorded as held; empty when there is no record.
pub(crate) fn recorded(h: &mut impl HoldHost) -> Vec<String> {
    h.read_record().map(|t| parse_record(&t)).unwrap_or_default()
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HoldOutcome {
    /// This run installed none of the candidates: nothing was held.
    Nothing,
    /// Held and recorded.
    Held(Vec<String>),
    /// `apt-mark hold` failed: nothing recorded.
    HoldFailed(Vec<String>),
    /// Held, but the record could not be written (why).
    Unrecorded(Vec<String>, String),
}

/// After onboard's own Docker install succeeded: hold what that install
/// added, then record it beside what an earlier run recorded. `before` is
/// [`installed_now`], read before the install started.
pub(crate) fn hold_what_this_run_installed(h: &mut impl HoldHost, before: &[String]) -> HoldOutcome {
    let after = installed_now(h);
    let new = installed_by_this_run(before, &after);
    if new.is_empty() {
        return HoldOutcome::Nothing;
    }
    if !h.run_root(&hold_argv(&new)) {
        return HoldOutcome::HoldFailed(new);
    }
    let mut all = recorded(h);
    all.extend(new.iter().cloned());
    all.sort();
    all.dedup();
    match h.write_record(&render_record(&all)) {
        Ok(()) => HoldOutcome::Held(new),
        Err(why) => HoldOutcome::Unrecorded(new, why),
    }
}

/// The line onboard prints right after placing (or failing to place) the
/// hold: (true = a success line, the line). `None` for [`HoldOutcome::Nothing`],
/// which the closing summary words. Pure.
pub(crate) fn outcome_line(o: &HoldOutcome) -> Option<(bool, String)> {
    match o {
        HoldOutcome::Nothing => None,
        HoldOutcome::Held(p) => Some((true, format!(
            "held {} (apt-mark hold): an unattended upgrade cannot restart dockerd; recorded in {RECORD_PATH}", p.join(", ")))),
        HoldOutcome::HoldFailed(p) => Some((false, format!(
            "could not hold {}: an unattended upgrade can restart dockerd. Hold them: sudo apt-mark hold {}", p.join(", "), p.join(" ")))),
        HoldOutcome::Unrecorded(p, why) => Some((false, format!(
            "held {} but could not record it in {RECORD_PATH} ({why}), so noo offboard will not release them. Release them by hand: sudo apt-mark unhold {}",
            p.join(", "), p.join(" ")))),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReleaseOutcome {
    /// No record: onboard held nothing here, so nothing is unheld.
    Nothing,
    /// Unheld, and the record removed.
    Released(Vec<String>),
    /// What failed, with the command that finishes it by hand.
    Failed(String),
}

/// Teardown: release exactly the recorded set, then drop the record. A name is
/// unheld only when it is in Docker's fixed set AND in the record AND held now,
/// so a package onboard did not record, or a name planted in the file, is never
/// unheld, and a hold the operator already released is left alone.
pub(crate) fn release_recorded(h: &mut impl HoldHost) -> ReleaseOutcome {
    let Some(text) = h.read_record() else { return ReleaseOutcome::Nothing };
    let pkgs: Vec<String> = parse_record(&text).into_iter().filter(|p| h.held(p)).collect();
    if !pkgs.is_empty() && !h.run_root(&unhold_argv(&pkgs)) {
        return ReleaseOutcome::Failed(format!("apt-mark unhold failed; by hand: sudo apt-mark unhold {} && sudo rm -f {RECORD_PATH}", pkgs.join(" ")));
    }
    if !h.remove_record() {
        return ReleaseOutcome::Failed(format!("released, but {RECORD_PATH} is still there; by hand: sudo rm -f {RECORD_PATH}"));
    }
    if pkgs.is_empty() { ReleaseOutcome::Nothing } else { ReleaseOutcome::Released(pkgs) }
}

/// How to take a Docker update while onboard's holds stand: unhold, upgrade,
/// verify, hold again. Pure.
pub(crate) fn update_path(pkgs: &[String]) -> String {
    let p = pkgs.join(" ");
    format!("sudo apt-mark unhold {p} && sudo apt-get update && sudo apt-get install --only-upgrade {p}, then noo cluster verify, then sudo apt-mark hold {p}")
}

/// The closing summary's Docker lines. `held` is the record; `installed_this_session`
/// is true when this run installed Docker (the relaunch marker); `docker_present`
/// is true when a Docker is on the machine. Nothing when there is no Docker to
/// speak of. Pure.
pub(crate) fn summary_lines(held: &[String], installed_this_session: bool, docker_present: bool) -> Vec<String> {
    if !held.is_empty() {
        return vec![
            format!("Docker packages held: {} (onboard installed them): held so an unattended upgrade cannot restart dockerd, which restarts every container", held.join(", ")),
            format!("to take an update: {}", update_path(held)),
        ];
    }
    if installed_this_session {
        return vec!["Docker packages: NOT held: onboard installed Docker in this session but the hold did not take (the warning above says why); \
                     the `holds` row of noo cluster verify gives the hold command".to_string()];
    }
    if docker_present {
        return vec!["Docker packages: not held: it was already installed (onboard holds only a Docker it installs itself)".to_string()];
    }
    Vec::new()
}

/// What onboard recorded on THIS machine (empty without a record). Read
/// without sudo: the record is 0644.
pub(crate) fn recorded_here() -> Vec<String> {
    std::fs::read_to_string(RECORD_PATH).map(|t| parse_record(&t)).unwrap_or_default()
}

/// Whether this machine has apt (the only place onboard installs, and holds,
/// Docker).
pub(crate) fn apt_here() -> bool {
    Command::new("apt-get").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

/// The machine, through sudo (`may_prompt`: whether sudo may ask for a password).
pub(crate) struct LiveHold {
    pub may_prompt: bool,
}

impl HoldHost for LiveHold {
    fn installed(&mut self, pkg: &str) -> bool {
        Command::new("dpkg-query")
            .args(["-W", "-f=${Status}", pkg])
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|o| o.status.success() && status_installed(&String::from_utf8_lossy(&o.stdout)))
    }
    fn held(&mut self, pkg: &str) -> bool {
        Command::new("dpkg-query")
            .args(["-W", "-f=${Status}", pkg])
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|o| o.status.success() && status_held(&String::from_utf8_lossy(&o.stdout)))
    }
    fn run_root(&mut self, argv: &[String]) -> bool {
        crate::onboard::steps::sudo_cmd(self.may_prompt)
            .args(argv)
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
    fn read_record(&mut self) -> Option<String> {
        std::fs::read_to_string(RECORD_PATH).ok()
    }
    fn write_record(&mut self, body: &str) -> Result<(), String> {
        // mkdir -p keeps an existing /etc/noo's owner and mode.
        if !self.run_root(&["mkdir".to_string(), "-p".to_string(), "/etc/noo".to_string()]) {
            return Err("could not create /etc/noo".into());
        }
        crate::onboard::steps::sudo_write_root_file(self.may_prompt, RECORD_PATH, body)
    }
    fn remove_record(&mut self) -> bool {
        self.run_root(&["rm".to_string(), "-f".to_string(), RECORD_PATH.to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake machine: dpkg's installed set (which the fake Docker install
    /// grows), the record, and every root command, in order.
    #[derive(Default)]
    struct FakeHost {
        installed: Vec<String>,
        record: Option<String>,
        ran: Vec<Vec<String>>,
        refuse_root: bool,
        refuse_write: bool,
        /// Packages the operator has unheld since; every other one reads held.
        not_held: Vec<String>,
    }

    impl HoldHost for FakeHost {
        fn installed(&mut self, pkg: &str) -> bool {
            self.installed.iter().any(|p| p == pkg)
        }
        fn held(&mut self, pkg: &str) -> bool {
            !self.not_held.iter().any(|p| p == pkg)
        }
        fn run_root(&mut self, argv: &[String]) -> bool {
            self.ran.push(argv.to_vec());
            !self.refuse_root
        }
        fn read_record(&mut self) -> Option<String> {
            self.record.clone()
        }
        fn write_record(&mut self, body: &str) -> Result<(), String> {
            if self.refuse_write {
                return Err("tee failed".into());
            }
            self.record = Some(body.to_string());
            Ok(())
        }
        fn remove_record(&mut self) -> bool {
            self.record = None;
            true
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    const ALL: [&str; 5] = CANDIDATES;

    #[test]
    fn dpkg_status_reads_installed_from_its_third_word() {
        assert!(status_installed("install ok installed"));
        assert!(status_installed("hold ok installed"));
        assert!(!status_installed("deinstall ok config-files"));
        assert!(!status_installed("install ok half-installed"));
        assert!(!status_installed("unknown ok not-installed"));
        assert!(!status_installed(""));
    }

    /// A fresh box: nothing before, the install adds all five, all five are
    /// held with one exact argv and recorded.
    #[test]
    fn a_fresh_install_holds_everything_it_installed() {
        let mut h = FakeHost::default();
        let before = installed_now(&mut h);
        assert!(before.is_empty());
        h.installed = s(&ALL); // get.docker.com ran
        let o = hold_what_this_run_installed(&mut h, &before);
        assert_eq!(o, HoldOutcome::Held(s(&ALL)));
        assert_eq!(h.ran, vec![s(&["apt-mark", "hold", "containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli", "docker-compose-plugin"])]);
        assert_eq!(parse_record(h.record.as_deref().unwrap()), s(&ALL));
    }

    /// Docker present before: nothing new, nothing held, nothing recorded.
    #[test]
    fn a_docker_already_installed_is_never_held() {
        let mut h = FakeHost { installed: s(&ALL), ..Default::default() };
        let before = installed_now(&mut h);
        let o = hold_what_this_run_installed(&mut h, &before);
        assert_eq!(o, HoldOutcome::Nothing);
        assert!(h.ran.is_empty(), "no apt-mark at all: {:?}", h.ran);
        assert!(h.record.is_none());
        assert_eq!(outcome_line(&o), None);
    }

    /// Part present before (containerd.io from another source): only what
    /// this run added is held.
    #[test]
    fn only_what_this_run_installed_is_held() {
        let mut h = FakeHost { installed: s(&["containerd.io"]), ..Default::default() };
        let before = installed_now(&mut h);
        h.installed = s(&ALL);
        let o = hold_what_this_run_installed(&mut h, &before);
        let new = s(&["docker-buildx-plugin", "docker-ce", "docker-ce-cli", "docker-compose-plugin"]);
        assert_eq!(o, HoldOutcome::Held(new.clone()));
        assert_eq!(h.ran, vec![hold_argv(&new)]);
        assert!(!h.ran[0].contains(&"containerd.io".to_string()));
        assert_eq!(installed_by_this_run(&s(&["docker-ce"]), &s(&["docker-ce", "docker-ce-cli"])), s(&["docker-ce-cli"]));
    }

    /// A re-run finds Docker present (installed and held by the first run):
    /// no new hold, and the record is untouched.
    #[test]
    fn a_rerun_changes_nothing() {
        let first = render_record(&s(&ALL));
        let mut h = FakeHost { installed: s(&ALL), record: Some(first.clone()), ..Default::default() };
        let before = installed_now(&mut h);
        assert_eq!(hold_what_this_run_installed(&mut h, &before), HoldOutcome::Nothing);
        assert!(h.ran.is_empty());
        assert_eq!(h.record.as_deref(), Some(first.as_str()));
    }

    /// A later run that reinstalls one package keeps the earlier record and
    /// adds only that one.
    #[test]
    fn a_later_hold_is_added_to_the_record() {
        let mut h = FakeHost { installed: s(&["containerd.io", "docker-ce"]), record: Some(render_record(&s(&["containerd.io", "docker-ce"]))), ..Default::default() };
        let before = installed_now(&mut h);
        h.installed = s(&["containerd.io", "docker-ce", "docker-ce-cli"]);
        assert_eq!(hold_what_this_run_installed(&mut h, &before), HoldOutcome::Held(s(&["docker-ce-cli"])));
        assert_eq!(h.ran, vec![s(&["apt-mark", "hold", "docker-ce-cli"])]);
        assert_eq!(recorded(&mut h), s(&["containerd.io", "docker-ce", "docker-ce-cli"]));
    }

    #[test]
    fn a_failed_hold_records_nothing_and_says_the_command() {
        let mut h = FakeHost { refuse_root: true, installed: s(&["docker-ce"]), ..Default::default() };
        let o = hold_what_this_run_installed(&mut h, &[]);
        assert_eq!(o, HoldOutcome::HoldFailed(s(&["docker-ce"])));
        assert!(h.record.is_none());
        let (good, line) = outcome_line(&o).unwrap();
        assert!(!good);
        assert!(line.ends_with("Hold them: sudo apt-mark hold docker-ce"), "{line}");
    }

    #[test]
    fn an_unrecorded_hold_says_offboard_cannot_release_it() {
        let mut h = FakeHost { refuse_write: true, installed: s(&["docker-ce"]), ..Default::default() };
        let o = hold_what_this_run_installed(&mut h, &[]);
        assert_eq!(o, HoldOutcome::Unrecorded(s(&["docker-ce"]), "tee failed".into()));
        let (good, line) = outcome_line(&o).unwrap();
        assert!(!good);
        assert!(line.contains("noo offboard will not release them") && line.ends_with("sudo apt-mark unhold docker-ce"), "{line}");
    }

    #[test]
    fn the_hold_and_unhold_argv_are_exact() {
        let p = s(&["docker-ce", "containerd.io"]);
        assert_eq!(hold_argv(&p), s(&["apt-mark", "hold", "docker-ce", "containerd.io"]));
        assert_eq!(unhold_argv(&p), s(&["apt-mark", "unhold", "docker-ce", "containerd.io"]));
    }

    /// The record round-trips, and only Docker's set is ever read from it.
    #[test]
    fn the_record_reads_only_dockers_set() {
        assert_eq!(parse_record(&render_record(&s(&["docker-ce", "containerd.io"]))), s(&["containerd.io", "docker-ce"]));
        assert_eq!(parse_record("# note\n\ndocker-ce\nopenssh-server\ntailscale\n docker-ce-cli \n"), s(&["docker-ce", "docker-ce-cli"]));
        assert!(render_record(&[]).starts_with("# noo onboard installed"));
    }

    /// Teardown releases exactly the recorded set, never a package onboard
    /// did not hold (tailscale here was held by the person), and drops the
    /// record.
    #[test]
    fn teardown_unholds_only_the_recorded_set() {
        let mut h = FakeHost { installed: s(&ALL), record: Some(render_record(&s(&["docker-ce", "docker-ce-cli"]))), ..Default::default() };
        assert_eq!(release_recorded(&mut h), ReleaseOutcome::Released(s(&["docker-ce", "docker-ce-cli"])));
        assert_eq!(h.ran, vec![s(&["apt-mark", "unhold", "docker-ce", "docker-ce-cli"])]);
        assert!(h.record.is_none());
    }

    #[test]
    fn a_name_planted_in_the_record_is_never_unheld() {
        // Someone edits the root-owned record to name another package: only
        // Docker's fixed set counts, whatever the file says.
        let planted = format!("{}openssh-server\nlibc6\n../../etc/passwd\ndocker-ce\n docker-ce-cli \n", RECORD_HEADER);
        let mut h = FakeHost { installed: s(&ALL), record: Some(planted), ..Default::default() };
        assert_eq!(release_recorded(&mut h), ReleaseOutcome::Released(s(&["docker-ce", "docker-ce-cli"])));
        assert_eq!(h.ran, vec![s(&["apt-mark", "unhold", "docker-ce", "docker-ce-cli"])]);
    }

    #[test]
    fn a_recorded_package_no_longer_held_is_left_alone() {
        let mut h = FakeHost {
            installed: s(&ALL),
            record: Some(render_record(&s(&["docker-ce", "docker-ce-cli"]))),
            not_held: s(&["docker-ce-cli"]),
            ..Default::default()
        };
        assert_eq!(release_recorded(&mut h), ReleaseOutcome::Released(s(&["docker-ce"])));
        assert_eq!(h.ran, vec![s(&["apt-mark", "unhold", "docker-ce"])]);
        assert!(h.record.is_none());
    }

    #[test]
    fn dpkg_status_reads_held_from_its_first_word() {
        assert!(status_held("hold ok installed"));
        assert!(!status_held("install ok installed"));
        assert!(!status_held(""));
    }

    #[test]
    fn teardown_without_a_record_unholds_nothing() {
        let mut h = FakeHost { installed: s(&ALL), ..Default::default() };
        assert_eq!(release_recorded(&mut h), ReleaseOutcome::Nothing);
        assert!(h.ran.is_empty());
        // An empty record: nothing unheld, the file still goes.
        let mut h = FakeHost { record: Some(render_record(&[])), ..Default::default() };
        assert_eq!(release_recorded(&mut h), ReleaseOutcome::Nothing);
        assert!(h.ran.is_empty(), "{:?}", h.ran);
        assert!(h.record.is_none());
    }

    #[test]
    fn a_failed_unhold_keeps_the_record_and_gives_the_command() {
        let mut h = FakeHost { refuse_root: true, record: Some(render_record(&s(&["docker-ce"]))), ..Default::default() };
        match release_recorded(&mut h) {
            ReleaseOutcome::Failed(why) => assert!(why.contains("sudo apt-mark unhold docker-ce && sudo rm -f /etc/noo/onboard-docker-holds"), "{why}"),
            o => panic!("{o:?}"),
        }
        assert!(h.record.is_some(), "the record stays until the holds are gone");
    }

    /// The closing summary: held (what and why, and the way out), already
    /// installed, a hold that did not take, and no Docker at all.
    #[test]
    fn the_summary_says_what_is_held_and_why() {
        let held = s(&["containerd.io", "docker-ce"]);
        assert_eq!(summary_lines(&held, true, true), vec![
            "Docker packages held: containerd.io, docker-ce (onboard installed them): held so an unattended upgrade cannot restart dockerd, which restarts every container".to_string(),
            "to take an update: sudo apt-mark unhold containerd.io docker-ce && sudo apt-get update && sudo apt-get install --only-upgrade containerd.io docker-ce, then noo cluster verify, then sudo apt-mark hold containerd.io docker-ce".to_string(),
        ]);
        // A re-run reads the record: the same lines without this session's install.
        assert_eq!(summary_lines(&held, false, true), summary_lines(&held, true, true));
        assert_eq!(summary_lines(&[], false, true),
            vec!["Docker packages: not held: it was already installed (onboard holds only a Docker it installs itself)".to_string()]);
        let failed = summary_lines(&[], true, true);
        assert_eq!(failed.len(), 1);
        assert!(failed[0].starts_with("Docker packages: NOT held: onboard installed Docker in this session"), "{failed:?}");
        assert!(summary_lines(&[], false, false).is_empty());
    }

    /// Onboard reads dpkg BEFORE its Docker install and holds after it, before
    /// the relaunch that ends the process; the closing summary words the
    /// record on every run.
    #[test]
    fn onboard_reads_before_installs_then_holds_before_relaunching() {
        let steps = crate::test_src::own_code(include_str!("onboard/steps.rs"));
        let pre = crate::test_src::fn_body(&steps, "pub fn prerequisites(");
        let before = pre.find("let docker_before = crate::docker_hold::installed_now(&mut hold_host);").expect("dpkg read before");
        let install = pre.find("let ok = run_logged(ctx_sudo(ctx).args([\"sh\", \"-c\", &docker_cmd]), &log);").expect("the Docker install");
        let hold = pre.find("crate::docker_hold::hold_what_this_run_installed(&mut hold_host, &docker_before);").expect("the hold");
        let relaunch = pre.find("Some(c) => std::process::exit(c),").expect("the relaunch");
        assert!(before < install && install < hold && hold < relaunch, "{pre}");
        let ok_branch = pre[install..hold].find("if ok {").expect("only after a good install");
        assert!(install + ok_branch < hold);

        let closing = crate::test_src::own_code(include_str!("onboard/mod.rs"));
        let summary = crate::test_src::fn_body(&closing, "fn print_final_summary(");
        assert!(summary.contains("crate::docker_hold::summary_lines(\n            &crate::docker_hold::recorded_here(),"), "{summary}");
        assert!(summary.contains("for line in docker_lines {\n                ctx.info(&line);"), "{summary}");
    }

    /// Offboard releases through the record, under its own question, in
    /// residue mode too (the gate is the record, not the install home), and
    /// the audit lists a record left behind.
    #[test]
    fn offboard_releases_through_the_record_and_audits_it() {
        let off = crate::test_src::own_code(include_str!("commands/offboard.rs"));
        let walk = crate::test_src::fn_body(&off, "pub fn offboard(");
        let gate = walk.find("if Path::new(crate::docker_hold::RECORD_PATH).exists() {").expect("gated on the record");
        let ask = walk.find("ctx_confirm(g, false, &docker_holds_question(&recorded), false)").expect("asked");
        let release = walk.find("crate::docker_hold::release_recorded(&mut host)").expect("released");
        assert!(gate < ask && ask < release, "{walk}");
        assert!(walk[release..].contains("removal_failed.push(\"docker holds\".into());"), "a failed release fails the walk");
        assert!(!walk.contains("unhold_argv(&CANDIDATES") && !off.contains("\"apt-mark\", \"unhold\""), "offboard never builds its own unhold");
        let audit = crate::test_src::fn_body(&off, "fn audit_leftovers(");
        assert!(audit.contains("item(\"docker holds\", Path::new(crate::docker_hold::RECORD_PATH).exists(),"), "{audit}");
        assert_eq!(crate::commands::offboard::docker_holds_question(&s(&["docker-ce", "containerd.io"])),
            "Release the apt holds onboard placed on the Docker it installed (docker-ce, containerd.io)? Docker stays installed; apt can then upgrade it");
    }
}
