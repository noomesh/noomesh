// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! i263b: onboard installs the sandbox's AppArmor profile where AppArmor is
//! the host's LSM.
//!
//! Docker's `docker-default` profile denies `mount` on every AppArmor host
//! (Ubuntu and its derivatives, Debian, SUSE), so Bubblewrap in the sandbox
//! container stops at "Failed to make / slave: Permission denied" and
//! `/exec` refuses every call. `docker/apparmor-noo-sandbox` is
//! docker-default plus the mount and userns rules bwrap needs; until this
//! step an operator had to install it by hand, so every fresh 24.04+ install
//! came up with an unhealthy sandbox. The step keys on the ACTIVE LSM
//! (`/sys/kernel/security/lsm`), never on the distribution name:
//!
//! * AppArmor: install and load the profile (sudo), and set
//!   `NOO_SANDBOX_APPARMOR=noo-sandbox`. A run that cannot (sudo needs a
//!   password it cannot ask for, or the install fails) refuses loudly: a
//!   hard failure carrying the exact commands.
//! * SELinux, no LSM, or a host that does not say: nothing to install; the
//!   `sandbox executor` verify row says whether the jail runs.
//!
//! The profile does not loosen anything docker-default allows beyond what
//! bwrap needs to build its namespaces (see the profile's header); the
//! jail's own self-test still has to pass before the sandbox reports
//! healthy (PR #516, i277b).

use std::path::Path;

use super::steps::{ctx_sudo, ctx_sudo_may_prompt, passwordless_sudo};
use super::Ctx;

/// The profile's name inside the kernel and the compose `apparmor=` value.
pub(crate) const PROFILE: &str = "noo-sandbox";
/// Where the bundled profile sits in the install root.
pub(crate) const BUNDLED: &str = "docker/apparmor-noo-sandbox";
/// Where AppArmor loads it from at boot.
pub(crate) const INSTALLED: &str = "/etc/apparmor.d/noo-sandbox";
const LSM_LIST: &str = "/sys/kernel/security/lsm";
/// One directory per loaded profile, each with a `name` file. Readable by
/// any user, unlike `apparmor/profiles` (root only).
const LOADED_PROFILES: &str = "/sys/kernel/security/apparmor/policy/profiles";
const ENV_KEY: &str = "NOO_SANDBOX_APPARMOR";

/// The host's major LSM, from the comma list in `/sys/kernel/security/lsm`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lsm {
    AppArmor,
    SeLinux,
    /// The list names neither (Arch, a kernel built without either).
    Neither,
    /// The list could not be read (no securityfs: WSL2, some containers).
    Unknown,
}

pub(crate) fn active_lsm(list: Option<&str>) -> Lsm {
    let Some(list) = list else { return Lsm::Unknown };
    let names: Vec<&str> = list.trim().split(',').map(str::trim).collect();
    if names.contains(&"apparmor") {
        Lsm::AppArmor
    } else if names.contains(&"selinux") {
        Lsm::SeLinux
    } else {
        Lsm::Neither
    }
}

/// What the step does on this host. Pure, so every answer is pinned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Not an AppArmor host: nothing to install. The text is the info line.
    Skip(&'static str),
    /// Loaded, and the file at `INSTALLED` is the bundled one: only the
    /// `.env` key may still need setting.
    Loaded,
    /// Install the file (new, or a release changed it) and (re)load it.
    Install,
}

pub(crate) fn plan(lsm: Lsm, loaded: bool, installed_is_bundled: bool) -> Plan {
    match lsm {
        Lsm::AppArmor if loaded && installed_is_bundled => Plan::Loaded,
        Lsm::AppArmor => Plan::Install,
        Lsm::SeLinux => Plan::Skip(
            "SELinux host: the noo-sandbox AppArmor profile does not apply here (`noo cluster verify`'s sandbox executor row says whether the jail runs)",
        ),
        Lsm::Neither => Plan::Skip("no AppArmor on this host: the sandbox needs no profile"),
        Lsm::Unknown => Plan::Skip(
            "the host's LSM could not be read (/sys/kernel/security/lsm): no AppArmor profile installed (`noo cluster verify`'s sandbox executor row says whether the jail runs)",
        ),
    }
}

/// Is a profile named `PROFILE` loaded? `false` when the list cannot be read.
pub(crate) fn profile_loaded(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else { return false };
    entries
        .flatten()
        .any(|e| std::fs::read_to_string(e.path().join("name")).map(|n| n.trim() == PROFILE).unwrap_or(false))
}

/// The value `.env` should get: `Some` when it must change. A value the
/// operator chose (anything but empty or Docker's default) is left alone.
pub(crate) fn env_change(current: &str) -> Option<&'static str> {
    match current.trim() {
        "" | "docker-default" => Some(PROFILE),
        _ => None,
    }
}

/// The two commands, as the operator would type them from the install root.
fn install_commands(src: &Path) -> String {
    format!(
        "sudo install -m 0644 {} {INSTALLED} && sudo apparmor_parser -r {INSTALLED}, then: noo onboard --only services",
        src.display()
    )
}

fn refuse(ctx: &mut Ctx, why: &str, src: &Path) {
    let line = format!("sandbox AppArmor profile: {why} — the sandbox cannot isolate code on this AppArmor host until it is loaded; run: {}", install_commands(src));
    ctx.error(&line);
    ctx.state.hard_failures.push(line);
}

/// The services step's call, on the controller, before the stack starts.
pub(crate) fn ensure(ctx: &mut Ctx) {
    let lsm = active_lsm(std::fs::read_to_string(LSM_LIST).ok().as_deref());
    let src = ctx.repo_root.join(BUNDLED);
    let bundled = std::fs::read(&src).ok();
    let same = bundled.is_some() && std::fs::read(INSTALLED).ok() == bundled;
    match plan(lsm, profile_loaded(Path::new(LOADED_PROFILES)), same) {
        Plan::Skip(why) => {
            ctx.info(why);
            return;
        }
        Plan::Loaded => {}
        Plan::Install => {
            if ctx.dry_run {
                ctx.dry(&format!("install and load the sandbox AppArmor profile ({INSTALLED}, uses sudo)"));
                return;
            }
            if bundled.is_none() {
                refuse(ctx, &format!("{} is missing from the install root", src.display()), &src);
                return;
            }
            if !ctx_sudo_may_prompt(ctx) && !passwordless_sudo() {
                // Loud in every mode, not only --ci (sudo_refused's rule): a
                // full-screen run cannot prompt either, and a sandbox that
                // refuses every call is not a warning.
                refuse(ctx, "sudo needs a password and this run cannot ask", &src);
                return;
            }
            ctx.progress("Installing the sandbox AppArmor profile (Bubblewrap needs mount under AppArmor)...");
            let run = |ctx: &Ctx, args: &[&str]| ctx_sudo(ctx).args(args).status().map(|s| s.success()).unwrap_or(false);
            let src_s = src.to_string_lossy().into_owned();
            if !run(ctx, &["install", "-m", "0644", &src_s, INSTALLED]) {
                refuse(ctx, &format!("could not install {INSTALLED}"), &src);
                return;
            }
            if !run(ctx, &["apparmor_parser", "-r", INSTALLED]) {
                refuse(ctx, "apparmor_parser could not load it", &src);
                return;
            }
            ctx.success(&format!("sandbox AppArmor profile {PROFILE} installed and loaded"));
        }
    }
    let current = ctx.read_env(ENV_KEY);
    match env_change(&current) {
        Some(v) => {
            ctx.update_env(ENV_KEY, v);
            std::env::set_var(ENV_KEY, v);
            ctx.info(&format!("{ENV_KEY}={v} in .env (a running sandbox takes it on its next start: noo stack restart --force sandbox)"));
        }
        None if current.trim() != PROFILE => {
            ctx.warn(&format!("{ENV_KEY}={} in .env was set by hand and is left as it is; the bundled profile is {PROFILE}", current.trim()));
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lsm_comes_from_the_kernel_list_not_the_distribution() {
        assert_eq!(active_lsm(Some("lockdown,capability,landlock,yama,apparmor,ima,evm\n")), Lsm::AppArmor, "aserve, Ubuntu 26.04");
        assert_eq!(active_lsm(Some("lockdown,capability,yama,apparmor")), Lsm::AppArmor, "Debian");
        assert_eq!(active_lsm(Some("lockdown,capability,yama,selinux,bpf,landlock")), Lsm::SeLinux, "Fedora");
        assert_eq!(active_lsm(Some("capability,landlock,lockdown,yama,bpf")), Lsm::Neither, "Arch");
        assert_eq!(active_lsm(Some("")), Lsm::Neither);
        assert_eq!(active_lsm(None), Lsm::Unknown, "no securityfs (WSL2)");
        // A substring is not a name.
        assert_eq!(active_lsm(Some("capability,notapparmor")), Lsm::Neither);
    }

    #[test]
    fn an_apparmor_host_installs_unless_the_same_profile_is_loaded() {
        assert_eq!(plan(Lsm::AppArmor, false, false), Plan::Install, "a fresh 24.04+ box: today's onboard leaves this undone (i263b)");
        assert_eq!(plan(Lsm::AppArmor, false, true), Plan::Install, "the file is there but not loaded");
        assert_eq!(plan(Lsm::AppArmor, true, false), Plan::Install, "a release changed the profile: reload it");
        assert_eq!(plan(Lsm::AppArmor, true, true), Plan::Loaded);
        for lsm in [Lsm::SeLinux, Lsm::Neither, Lsm::Unknown] {
            assert!(matches!(plan(lsm, true, true), Plan::Skip(_)));
        }
        let Plan::Skip(why) = plan(Lsm::SeLinux, false, false) else { unreachable!() };
        assert!(why.contains("SELinux") && why.contains("sandbox executor"), "{why}");
    }

    #[test]
    fn a_loaded_profile_is_found_by_its_name_file() {
        let dir = std::env::temp_dir().join(format!("noo-aa-profiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (d, n) in [("Xorg.34", "Xorg"), ("docker-default.3", "docker-default")] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
            std::fs::write(dir.join(d).join("name"), format!("{n}\n")).unwrap();
        }
        assert!(!profile_loaded(&dir), "docker-default is not ours");
        std::fs::create_dir_all(dir.join("noo-sandbox.7")).unwrap();
        std::fs::write(dir.join("noo-sandbox.7").join("name"), "noo-sandbox\n").unwrap();
        assert!(profile_loaded(&dir));
        assert!(!profile_loaded(&dir.join("absent")), "an unreadable list is not a loaded profile");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_is_set_unless_the_operator_chose_a_profile() {
        assert_eq!(env_change(""), Some(PROFILE));
        assert_eq!(env_change("docker-default"), Some(PROFILE), "Docker's default is the one that blocks bwrap");
        assert_eq!(env_change("noo-sandbox"), None);
        assert_eq!(env_change("my-site-profile"), None, "a hand-set profile is left alone");
    }

    #[test]
    fn the_refusal_names_both_commands() {
        let c = install_commands(Path::new("/opt/noo/docker/apparmor-noo-sandbox"));
        assert!(c.starts_with("sudo install -m 0644 /opt/noo/docker/apparmor-noo-sandbox /etc/apparmor.d/noo-sandbox"), "{c}");
        assert!(c.contains("sudo apparmor_parser -r /etc/apparmor.d/noo-sandbox"), "{c}");
    }

    /// The services step runs this on the controller (pinned in source, as
    /// the hostd call is): without it a fresh AppArmor box has a sandbox
    /// that refuses every call.
    #[test]
    fn the_services_step_installs_the_profile() {
        let src = include_str!("steps.rs");
        let body = &src[src.find("pub fn services(ctx: &mut Ctx)").expect("services step")..];
        let body = &body[..body.find("\n}\n").expect("end of services")];
        let at = body.find("super::sandbox_apparmor::ensure(ctx)").expect("services() must call sandbox_apparmor::ensure (i263b)");
        let start = body.find("run_compose").unwrap_or(usize::MAX);
        assert!(at < start, "the profile is installed before the stack starts");
    }
}
