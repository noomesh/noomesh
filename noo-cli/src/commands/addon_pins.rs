// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons upgrade | verify | launch-pins`: the licensed add-ons' signed
//! locks and digest pins on the controller (`crate::addons`).
//!
//! - `upgrade [<name>…] [--check] [--allow-downgrade]` re-resolves each
//!   add-on's lock for the running stack tag, verifies it against the
//!   entitlement, pulls by digest and rewrites its pin. `--check` only says
//!   what is installed and what is offered.
//! - `verify` re-verifies the cached locks offline, checks each pinned image
//!   is local, and compares running containers with the pins.
//! - `launch-pins <tag> [<name>…]` (hidden) is the launcher's reader: one
//!   `pin <addon> <VAR> <ref>` or `refuse <addon> <why>` line per add-on.
//!
//! Nothing here restarts anything: a new pin takes effect on the operator's
//! next `noo stack restart --force`.

use std::path::Path;

use serde_json::json;

use crate::addons::{self, pins, resolve};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

const UPGRADE_USAGE: &str = "usage: noo addons upgrade [<name>...] [--check] [--allow-downgrade]";

/// The add-ons a verb acts on: the named ones (licensed only), else every
/// licensed add-on declared on.
fn targets(g: &Globals, root: &Path, named: &[String]) -> Vec<&'static str> {
    if named.is_empty() {
        return addons::licensed_addons().filter(|a| addons::declared_on(root, a)).collect();
    }
    named
        .iter()
        .map(|n| match crate::commands::addons::row(n) {
            Some(r) if r.licensed.is_some() => r.key,
            Some(r) => fail(g.json, ExitCode::Usage, "not_licensed",
                &format!("{} ships with the stack and has no signed lock of its own", r.key), Some("noo addons list")),
            None => fail(g.json, ExitCode::Usage, "unknown_addon", &format!("unknown add-on `{n}`"), Some("noo addons list")),
        })
        .collect()
}

fn require_tag(g: &Globals, root: &Path) -> String {
    match addons::current_tag(root) {
        Some(t) => t,
        None => fail(g.json, ExitCode::Generic, "no_stack_tag",
            &format!("{} pins no stack tag (NOO_IMAGE_TAG), so there is no stack to resolve add-on locks for", root.display()),
            Some("noo upgrade --stack")),
    }
}

/// `noo addons upgrade`
pub fn addons_upgrade(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut check, mut allow_downgrade, mut named) = (false, false, Vec::new());
    for a in args {
        match a.as_str() {
            "--check" => check = true,
            "--allow-downgrade" => allow_downgrade = true,
            "--help" | "-h" => {
                println!("{UPGRADE_USAGE}");
                return Ok(0);
            }
            s if s.starts_with('-') => fail(g.json, ExitCode::Usage, "usage", &format!("unknown flag {s}"), Some(UPGRADE_USAGE)),
            s => named.push(s.to_string()),
        }
    }
    let root = crate::envfile::repo_root();
    let tag = require_tag(g, &root);
    let list = targets(g, &root, &named);
    if list.is_empty() {
        if g.json {
            println!("{}", json!({"stack": tag, "addons": []}));
        } else {
            println!("{}", ui::muted("no licensed add-on is on: nothing to pin"));
        }
        return Ok(0);
    }
    let stack_lock = resolve::installed_stack_lock(&root, &tag);
    let cred = addons::lock_fetch::installed_credential();
    let client = addons::lock_fetch::Client::new(cred.clone());
    let current = pins::read(&root).unwrap_or_default();
    let ctx = addons::Ctx { root: &root, tag: &tag, stack_lock: stack_lock.as_deref(), allow_downgrade, client: &client, cred: cred.as_ref() };
    let mut rows = Vec::new();
    let mut failed = 0;
    for addon in list {
        let installed = current.get(addon).cloned();
        let outcome = if check {
            resolve::installed_anchor(addon)
                .and_then(|anchor| {
                    let want = resolve::Want {
                        addon,
                        stack_tag: &tag,
                        stack_lock: stack_lock.as_deref(),
                        pinned: installed.as_ref().map(|p| p.version.as_str()),
                        allow_downgrade,
                    };
                    resolve::fetch_and_check(&client, &anchor, &want)
                })
                .map(|(v, _)| (pins::Pin::from_verified(&v, &tag), 0usize))
        } else {
            addons::prepare(&ctx, addon, &mut resolve::LiveDocker)
                .and_then(|p| addons::commit(&root, &p, &tag).map(|pin| (pin, p.pulled)))
        };
        match outcome {
            Ok((offered, pulled)) => {
                let changed = installed.as_ref() != Some(&offered);
                rows.push(json!({
                    "addon": addon, "installed": installed.as_ref().map(|p| &p.version),
                    "offered": offered.version, "stack": tag, "key_index": offered.key_index,
                    "changed": changed, "pulled": pulled, "pinned": !check,
                }));
                if !g.json {
                    let was = installed.as_ref().map(|p| format!("{} for {}", p.version, p.stack)).unwrap_or_else(|| "not pinned".into());
                    if check {
                        let state = if changed { ui::bad("update available") } else { ui::good("current") };
                        println!("  {addon}  installed {was}; offered {} (add-on key #{})  {state}", offered.version, offered.key_index);
                    } else if changed {
                        ui::done(&format!("{addon} {} pinned for stack {tag} (was {was}; add-on key #{}; {pulled} image(s) pulled)",
                            offered.version, offered.key_index));
                    } else {
                        ui::done(&format!("{addon} {} already pinned for stack {tag}: nothing changed", offered.version));
                    }
                }
            }
            Err(r) => {
                failed += 1;
                let fix = crate::commands::addon_enable::pin_fix(addon, &r);
                rows.push(json!({"addon": addon, "error": r.why(addon), "fix": fix}));
                if !g.json {
                    ui::failed(&format!("{addon}: {}", r.why(addon)), Some(&fix));
                }
            }
        }
    }
    if g.json {
        println!("{}", json!({"stack": tag, "check": check, "addons": rows}));
    } else if !check && rows.iter().any(|r| r["changed"] == true) {
        ui::guide(&[
            ("noo stack restart --force", "runs the new pins; nothing was restarted for you"),
            ("noo addons verify", "re-checks the pins, the local images and what runs"),
        ]);
    }
    Ok(if failed == 0 { 0 } else { 1 })
}

/// One add-on's verify verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub addon: String,
    pub pin: Option<pins::Pin>,
    pub problem: Option<String>,
    pub notes: Vec<String>,
}

/// Verify one add-on: anchor, offline lock, local images, running state.
pub(crate) fn verify_one(
    root: &Path,
    addon: &str,
    tag: &str,
    anchor: Result<crate::addon_lock::TrustAnchor, resolve::Refusal>,
    docker: &mut dyn resolve::Docker,
    ps: &[(String, String)],
) -> Verdict {
    let mut v = Verdict { addon: addon.to_string(), pin: None, problem: None, notes: Vec::new() };
    let anchor = match anchor {
        Ok(a) => a,
        Err(r) => {
            v.problem = Some(r.why(addon));
            return v;
        }
    };
    let pin = match resolve::offline_check(root, addon, tag, &anchor) {
        Ok(p) => p,
        Err(e) => {
            v.problem = Some(e);
            return v;
        }
    };
    for (name, r) in &pin.images {
        if !docker.image_present(r) {
            v.problem = Some(format!("{r} is not in the local image store"));
        }
        match resolve::running_state(r, ps) {
            resolve::Running::Pinned(_) => {}
            resolve::Running::Drift(d) => {
                let who: Vec<String> = d.iter().map(|(n, i)| format!("{n} runs {i}")).collect();
                v.problem = Some(format!("not the pinned image: {}", who.join(", ")));
            }
            resolve::Running::Absent => v.notes.push(format!("{name} is not running")),
        }
    }
    v.pin = Some(pin);
    v
}

/// `noo addons verify`
pub fn addons_verify(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let root = crate::envfile::repo_root();
    let tag = require_tag(g, &root);
    let list = targets(g, &root, &[]);
    let mut docker = resolve::LiveDocker;
    let ps = resolve::Docker::running(&mut docker).unwrap_or_default();
    let verdicts: Vec<Verdict> =
        list.iter().map(|a| verify_one(&root, a, &tag, resolve::installed_anchor(a), &mut docker, &ps)).collect();
    let bad = verdicts.iter().filter(|v| v.problem.is_some()).count();
    if g.json {
        let rows: Vec<_> = verdicts
            .iter()
            .map(|v| json!({
                "addon": v.addon, "ok": v.problem.is_none(), "problem": v.problem, "notes": v.notes,
                "version": v.pin.as_ref().map(|p| &p.version), "stack": v.pin.as_ref().map(|p| &p.stack),
                "key_index": v.pin.as_ref().map(|p| p.key_index), "images": v.pin.as_ref().map(|p| &p.images),
            }))
            .collect();
        println!("{}", json!({"stack": tag, "verified": verdicts.len() - bad, "failed": bad, "addons": rows}));
        return Ok(if bad == 0 { 0 } else { 1 });
    }
    println!("{}", ui::header("add-on pins", Some(&format!("stack {tag}"))));
    if verdicts.is_empty() {
        println!("{}", ui::muted("no licensed add-on is on: nothing is pinned"));
        return Ok(0);
    }
    for v in &verdicts {
        match (&v.problem, &v.pin) {
            (None, Some(p)) => {
                let notes = if v.notes.is_empty() { String::new() } else { ui::muted(&format!("  ({})", v.notes.join("; "))) };
                println!("{}", ui::status_line(ui::Glyph::Ok, &format!(
                    "{} {} @{} for {}, signed by add-on key #{}{notes}", v.addon, p.version, p.short_digest(), p.stack, p.key_index)));
            }
            (Some(why), _) => println!("{}", ui::status_line(ui::Glyph::Err, &format!("{}: {why}", v.addon))),
            (None, None) => {}
        }
    }
    if bad > 0 {
        ui::guide(&[("noo addons upgrade", "re-resolves, verifies, pulls and re-pins every add-on that is on")]);
    }
    Ok(if bad == 0 { 0 } else { 1 })
}

/// The launcher's protocol lines for `names` against `tag`.
pub(crate) fn launch_lines(root: &Path, tag: &str, names: &[String], anchor: &dyn Fn(&str) -> Result<crate::addon_lock::TrustAnchor, resolve::Refusal>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for n in names {
        let Some(r) = crate::commands::addons::row(n) else { continue };
        if r.licensed.is_none() || !seen.insert(r.key) {
            continue;
        }
        let addon = r.key;
        let res = anchor(addon).map_err(|e| e.why(addon)).and_then(|a| resolve::offline_check(root, addon, tag, &a));
        match res {
            Ok(pin) => {
                for (image, reference) in &pin.images {
                    match pins::image_env_var(image) {
                        Some(var) => out.push(format!("pin {addon} {var} {reference}")),
                        None => out.push(format!("refuse {addon} its lock names image {image:?}, which has no variable name")),
                    }
                }
            }
            Err(why) => out.push(format!("refuse {addon} {}", why.replace('\n', " "))),
        }
    }
    out
}

/// `noo addons launch-pins <tag> [<name>…]` (hidden; the launcher's reader).
pub fn addons_launch_pins(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Some((tag, names)) = args.split_first() else {
        fail(g.json, ExitCode::Usage, "usage", "launch-pins needs the stack tag", Some("noo addons launch-pins <tag> [<name>...]"));
    };
    // The launcher runs from the install root; read the pins there.
    let root = std::env::current_dir().unwrap_or_else(|_| crate::envfile::repo_root());
    for l in launch_lines(&root, tag, names, &|a| resolve::installed_anchor(a)) {
        println!("{l}");
    }
    Ok(0)
}

/// `addons list` cells for one add-on's pin: version, stack, digest, key.
pub(crate) fn pin_cells(pin: Option<&pins::Pin>) -> [String; 4] {
    match pin {
        Some(p) => [p.version.clone(), p.stack.clone(), p.short_digest(), format!("#{}", p.key_index)],
        None => [String::new(), String::new(), String::new(), String::new()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addons::resolve::tests::{anchor, lock, signed, FakeDocker, ROOT};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-addon-pins-cmd-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pinned_root(tag: &str) -> (std::path::PathBuf, String) {
        let d = scratch(tag);
        let f = signed(&lock("1.2.0", &["v0.6.0"], None));
        let want = resolve::Want { addon: "trellion_intel", stack_tag: "v0.6.0", stack_lock: None, pinned: None, allow_downgrade: false };
        let v = resolve::check(&f, &anchor(), &want).unwrap();
        resolve::record(&d, "trellion_intel", &v, &f, "v0.6.0").unwrap();
        let r = v.lock.images["trellion-intel"].clone();
        (d, r)
    }

    #[test]
    fn launch_lines_pin_what_verifies_and_refuse_the_rest() {
        let (d, reference) = pinned_root("launch");
        let names = vec!["trellion-intel".to_string(), "evolve".to_string(), "voice".to_string(), "trellion_intel".to_string()];
        let lines = launch_lines(&d, "v0.6.0", &names, &|a| if a == "trellion_intel" { Ok(anchor()) } else { Err(resolve::Refusal::NoAnchor) });
        assert_eq!(lines[0], format!("pin trellion_intel NOO_ADDON_IMAGE_TRELLION_INTEL {reference}"));
        assert!(lines[1].starts_with("refuse evolve the installed entitlement names no signing key"), "{lines:?}");
        assert_eq!(lines.len(), 2, "voice is not licensed and a duplicate spelling is one add-on: {lines:?}");

        let other_tag = launch_lines(&d, "v0.6.1", &names[..1], &|_| Ok(anchor()));
        assert!(other_tag[0].starts_with("refuse trellion_intel trellion_intel is pinned for stack v0.6.0"), "{other_tag:?}");
    }

    #[test]
    fn verify_reports_missing_images_and_drift_and_notes_not_running() {
        let (d, reference) = pinned_root("verify");
        let mut docker = FakeDocker { local: vec![reference.clone()], ..Default::default() };
        let ok = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &[("noo-trellion-intel".into(), reference.clone())]);
        assert!(ok.problem.is_none() && ok.notes.is_empty(), "{ok:?}");

        let idle = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &[]);
        assert!(idle.problem.is_none(), "{idle:?}");
        assert_eq!(idle.notes, ["trellion-intel is not running"]);

        let drift = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &[("noo-trellion-intel".into(), format!("{ROOT}:v0.6.0"))]);
        assert!(drift.problem.unwrap().contains("not the pinned image"));

        let mut empty = FakeDocker::default();
        let gone = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut empty, &[]);
        assert!(gone.problem.unwrap().contains("not in the local image store"));

        let no_anchor = verify_one(&d, "trellion_intel", "v0.6.0", Err(resolve::Refusal::NoAnchor), &mut docker, &[]);
        assert!(no_anchor.problem.unwrap().contains("names no signing key"));
    }

    #[test]
    fn list_cells() {
        assert_eq!(pin_cells(None), [String::new(), String::new(), String::new(), String::new()]);
        let (d, _) = pinned_root("cells");
        let p = pins::read(&d).unwrap();
        let c = pin_cells(p.get("trellion_intel"));
        assert_eq!(c[0], "1.2.0");
        assert_eq!(c[1], "v0.6.0");
        assert_eq!(c[2], "sha256:111111111111");
        assert_eq!(c[3], "#0");
    }
}
