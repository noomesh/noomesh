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
/// The one rule an AppArmor 3.x parser (Ubuntu 22.04: 3.0) cannot read.
pub(crate) const USERNS_RULE: &str = "userns,";
/// Where the profile as rendered for THIS host's parser is kept for the
/// operator's hand install, under the install root, when it differs from
/// the bundled file.
pub(crate) const RENDERED: &str = ".noo-apparmor-noo-sandbox";

/// What `render` writes in place of the rule; how verify tells the two
/// forms apart in the installed file.
pub(crate) const OMITTED_MARK: &str = "# userns, omitted:";

/// Which form of the profile a file is, for verify's `sandbox executor`
/// row: `None` when there is no installed profile to read.
pub(crate) fn installed_form(installed: Option<&str>) -> Option<&'static str> {
    let text = installed?;
    Some(if text.lines().any(|l| l.trim_start().starts_with(OMITTED_MARK)) {
        "profile: 3.x form, userns rule omitted"
    } else {
        "profile: bundled"
    })
}

/// The major version in `apparmor_parser --version`'s first line
/// ("AppArmor parser version 3.0.4"). `None` when it cannot be read.
pub(crate) fn parser_major(version: &str) -> Option<u32> {
    let line = version.lines().next()?;
    let v = line.rsplit(' ').next()?;
    v.split('.').next()?.parse().ok()
}

/// The profile this host's parser is given. AppArmor 4.0 added the `userns`
/// rule class; a 3.x parser (Ubuntu 22.04) refuses the whole file on that
/// one line ("syntax error, unexpected TOK_END_OF_RULE, expecting
/// TOK_MODE"), and onboard stopped there. A 3.x parser compiles policy for
/// an ABI with no user-namespace mediation, so the kernel does not ask the
/// profile about user namespaces at all: dropping the line grants and
/// withholds nothing there. Every other rule is the bundled file's, byte for
/// byte. A 4.x parser, or one whose version cannot be read, gets the bundled
/// file unchanged.
pub(crate) fn render(bundled: &str, parser_major: Option<u32>) -> String {
    if !matches!(parser_major, Some(m) if m < 4) {
        return bundled.to_string();
    }
    bundled
        .split_inclusive('\n')
        .map(|l| {
            if l.trim() == USERNS_RULE {
                let indent = &l[..l.len() - l.trim_start().len()];
                format!("{indent}{OMITTED_MARK} this host's AppArmor parser predates the rule (4.0); its policy does not mediate user namespaces\n")
            } else {
                l.to_string()
            }
        })
        .collect()
}

/// `apparmor_parser --version`, run without sudo. The parser sits in
/// /usr/sbin or /sbin, which an ordinary user's PATH may lack.
fn parser_version() -> Option<String> {
    ["apparmor_parser", "/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"].iter().find_map(|bin| {
        let out = std::process::Command::new(bin).arg("--version").output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    })
}

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
    let bundled_src = ctx.repo_root.join(BUNDLED);
    let major = parser_version().as_deref().and_then(parser_major);
    // What this host's parser is given (the bundled file, or it without the
    // one rule a 3.x parser cannot read), and the file a hand install uses.
    let bundled = std::fs::read_to_string(&bundled_src).ok().map(|b| render(&b, major).into_bytes());
    let rendered_differs = bundled.is_some() && std::fs::read(&bundled_src).ok() != bundled;
    let src = if rendered_differs {
        let p = ctx.repo_root.join(RENDERED);
        if !ctx.dry_run {
            if let Some(b) = &bundled {
                let _ = std::fs::write(&p, b);
            }
        }
        p
    } else {
        bundled_src
    };
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
                refuse(ctx, &format!("{} is missing from the install root", ctx.repo_root.join(BUNDLED).display()), &src);
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
            if rendered_differs {
                ctx.info(&format!("AppArmor parser {}.x: the profile is installed without its `{USERNS_RULE}` rule, which this parser cannot read and its policy does not mediate (every other rule unchanged)",
                    major.unwrap_or(0)));
            }
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
    fn verify_can_tell_which_form_is_installed() {
        let bundled = include_str!("../../../docker/apparmor-noo-sandbox");
        assert_eq!(installed_form(Some(bundled)), Some("profile: bundled"));
        assert_eq!(installed_form(Some(&render(bundled, Some(3)))), Some("profile: 3.x form, userns rule omitted"));
        assert_eq!(installed_form(None), None);
        assert!(render(bundled, Some(3)).contains(OMITTED_MARK), "render writes the mark verify reads");
    }

    #[test]
    fn the_parser_version_is_read_from_its_first_line() {
        assert_eq!(parser_major("AppArmor parser version 3.0.4\nCopyright (C) 1999-2008 Novell Inc.\n"), Some(3));
        assert_eq!(parser_major("AppArmor parser version 4.0.1\n"), Some(4));
        assert_eq!(parser_major(""), None);
        assert_eq!(parser_major("garbage"), None);
    }

    #[test]
    fn a_3x_parser_gets_the_profile_without_userns_and_nothing_else_changes() {
        let bundled = include_str!("../../../docker/apparmor-noo-sandbox");
        assert_eq!(render(bundled, Some(4)), bundled, "24.04: the bundled file, byte for byte");
        assert_eq!(render(bundled, Some(5)), bundled);
        assert_eq!(render(bundled, None), bundled, "an unread version keeps the bundled file");
        let old = render(bundled, Some(3));
        assert!(!old.lines().any(|l| l.trim() == USERNS_RULE), "no userns rule for a 3.x parser");
        let a: Vec<&str> = bundled.lines().collect();
        let b: Vec<&str> = old.lines().collect();
        assert_eq!(a.len(), b.len(), "one line replaced, none added or lost");
        let changed: Vec<(&str, &str)> = a.iter().zip(&b).filter(|(x, y)| x != y).map(|(x, y)| (*x, *y)).collect();
        assert_eq!(changed.len(), 1, "{changed:?}");
        assert_eq!(changed[0].0.trim(), USERNS_RULE);
        assert!(changed[0].1.trim_start().starts_with('#'), "the line becomes a comment: {}", changed[0].1);
        for rule in ["mount,", "pivot_root,", "umount,", "deny @{PROC}/kcore rwklx,", "ptrace (trace,read,tracedby,readby) peer=noo-sandbox,"] {
            assert!(b.iter().any(|l| l.trim() == rule), "{rule} kept");
        }
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
        let src = crate::test_src::own_code(include_str!("steps.rs"));
        let body = crate::test_src::fn_body(&src, "pub fn services(ctx: &mut Ctx)");
        let at = body.find("super::sandbox_apparmor::ensure(ctx)").expect("services() must call sandbox_apparmor::ensure (i263b)");
        let start = body.find("run_compose").unwrap_or(usize::MAX);
        assert!(at < start, "the profile is installed before the stack starts");
    }
}
