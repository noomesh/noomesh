// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons upgrade | verify | launch-pins`: the licensed add-ons' signed
//! locks and digest pins on the controller (`crate::addons`).
//!
//! - `upgrade [<name>…] [--check] [--allow-downgrade]` re-resolves each
//!   add-on's lock for the running stack tag, verifies it against the
//!   entitlement, pulls by digest and rewrites its pin. `--check` only says
//!   what is installed and what is offered.
//! - `verify` re-verifies the cached locks offline, holds each add-on's
//!   materialised bundle files (`<root>/addons/<name>/`) to its signed lock,
//!   checks each pinned image is local, and compares running containers with
//!   the pins.
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
const VERIFY_USAGE: &str = "usage: noo addons verify";

/// The add-ons a verb acts on: the named ones (licensed only), else every
/// licensed add-on declared on.
fn targets(g: &Globals, root: &Path, named: &[String]) -> Vec<&'static str> {
    if named.is_empty() {
        return match addons::licensed_on(root) {
            Ok(l) => l,
            Err(e) => fail(g.json, ExitCode::Generic, "config", &format!("{e} — refusing to guess which add-ons are on"), Some("noo addons list")),
        };
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
    let cred = match addons::lock_fetch::installed_credential() {
        Ok(c) => c,
        Err(e) => fail(g.json, ExitCode::Generic, "store_unreadable", &e, Some("noo security secrets audit")),
    };
    let client = addons::lock_fetch::Client::new(cred.clone());
    let current = match pins::read(&root) {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "pins_unreadable", &e, Some("noo addons verify")),
    };
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
                .map(|(v, f)| (pins::Pin::from_verified(&v, &tag, &f.lock), 0usize))
        } else {
            addons::prepare(&ctx, addon, &mut resolve::LiveDocker::new(&root))
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
    running: &[resolve::Container],
) -> Verdict {
    let mut v = Verdict { addon: addon.to_string(), pin: None, problem: None, notes: Vec::new() };
    let anchor = match anchor {
        Ok(a) => a,
        Err(r) => {
            v.problem = Some(r.why(addon));
            return v;
        }
    };
    let pin = match resolve::offline_check_bundle(root, addon, tag, &anchor) {
        Ok((p, how)) => {
            match how {
                resolve::Overlay::Bundled => {}
                resolve::Overlay::Legacy(Some(path)) => v.notes.push(format!(
                    "its lock predates overlay bundles; running the deprecated {} (re-sign the add-on for this stack)",
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("overlay")
                )),
                resolve::Overlay::Legacy(None) => {
                    // Nothing can be composed: the images are beside the point.
                    v.problem = Some(legacy_refusal(tag));
                    v.pin = Some(p);
                    return v;
                }
            }
            p
        }
        Err(e) => {
            v.problem = Some(e);
            return v;
        }
    };
    for (name, r) in &pin.images {
        let pinned_id = if docker.image_present(r) {
            match docker.image_id(r) {
                Ok(id) => Some(id),
                Err(e) => {
                    v.problem = Some(format!("could not read the image id of {r}: {e}"));
                    None
                }
            }
        } else {
            v.problem = Some(format!("{r} is not in the local image store"));
            None
        };
        match resolve::running_state(r, pinned_id.as_deref(), running) {
            resolve::Running::Pinned(_) => {}
            resolve::Running::Drift(d) => {
                let who: Vec<String> = d.iter().map(|(n, why)| format!("{n} {why}")).collect();
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
    match args {
        [] => {}
        [h] if h == "--help" || h == "-h" => {
            println!("{VERIFY_USAGE}");
            return Ok(0);
        }
        _ => fail(g.json, ExitCode::Usage, "usage", &format!("unexpected argument {}", args[0]), Some(VERIFY_USAGE)),
    }
    let root = crate::envfile::repo_root();
    let tag = require_tag(g, &root);
    let list = targets(g, &root, &[]);
    let mut docker = resolve::LiveDocker::new(&root);
    // Unreadable containers are not "nothing running": fail, do not guess.
    let running = if list.is_empty() {
        Vec::new()
    } else {
        match resolve::Docker::running(&mut docker) {
            Ok(r) => r,
            Err(e) => fail(g.json, ExitCode::Generic, "docker_unreadable", &format!("could not list running containers: {e}"), Some("noo stack status")),
        }
    };
    let verdicts: Vec<Verdict> =
        list.iter().map(|a| verify_one(&root, a, &tag, resolve::installed_anchor(a), &mut docker, &running)).collect();
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

/// Why an add-on whose lock predates bundles cannot be composed.
fn legacy_refusal(tag: &str) -> String {
    format!(
        "its signed lock for {tag} predates overlay bundles, so no compose overlay came with it, and this install has \
         no earlier overlay to fall back on (the add-on's release must re-sign a bundle for {tag})"
    )
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
        let res = anchor(addon).map_err(|e| e.why(addon)).and_then(|a| resolve::offline_check_bundle(root, addon, tag, &a));
        match res {
            Ok((_, resolve::Overlay::Legacy(None))) => out.push(format!("refuse {addon} {}", legacy_refusal(tag))),
            Ok((pin, _)) => {
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

/// The `NOO_ADDON_IMAGE_*` variables composed overlay texts read in an
/// `image:` line — `scripts/lib-dist.sh` `addon_image_vars`, in Rust.
pub(crate) fn overlay_image_vars(texts: &[String]) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for t in texts {
        for line in t.lines() {
            let Some(rest) = line.strip_prefix("    image:") else { continue };
            let Some(v) = rest.trim_start().strip_prefix("${NOO_ADDON_IMAGE_") else { continue };
            let name: String = v.chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_').collect();
            if !name.is_empty() {
                out.insert(format!("NOO_ADDON_IMAGE_{name}"));
            }
        }
    }
    out
}

/// What a non-launcher that composes the add-on overlays (the onboard
/// wizard) needs to know to run them.
pub(crate) struct PinEnvInput<'a> {
    pub root: &'a Path,
    pub dist: bool,
    pub tag: &'a str,
    /// The dev build's namespace (`NOO_IMAGE_PREFIX`, else `noomesh`).
    pub image_prefix: &'a str,
    /// The texts of every compose file that will be composed.
    pub compose_texts: Vec<String>,
    /// The add-ons whose overlay is composed.
    pub composed_addons: Vec<String>,
}

/// One refusal: `(add-on or variable, why, remedy)`.
pub(crate) type PinRefusal = (String, String, String);

/// The add-on image environment, with the launcher's semantics
/// (`require_addon_pins`): dev = the dev build's names; dist = only images a
/// verified pin for `tag` names, present locally by digest, covering every
/// variable a composed overlay reads. Refusals name the add-on and
/// `noo addons upgrade <name>`.
pub(crate) fn addon_image_env(
    input: &PinEnvInput,
    anchor: &dyn Fn(&str) -> Result<crate::addon_lock::TrustAnchor, resolve::Refusal>,
    present: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, String)>, Vec<PinRefusal>> {
    let vars = overlay_image_vars(&input.compose_texts);
    if vars.is_empty() {
        return Ok(Vec::new());
    }
    if !input.dist {
        return Ok(vars
            .iter()
            .map(|v| {
                let name = v.trim_start_matches("NOO_ADDON_IMAGE_").to_ascii_lowercase().replace('_', "-");
                let tag = if input.tag.is_empty() { "latest" } else { input.tag };
                (v.clone(), format!("{}/{name}:{tag}", input.image_prefix))
            })
            .collect());
    }
    let mut env = Vec::new();
    let mut refused: Vec<PinRefusal> = Vec::new();
    for line in launch_lines(input.root, input.tag, &input.composed_addons, anchor) {
        let mut parts = line.splitn(3, ' ');
        let (kind, addon, rest) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let fix = format!("noo addons upgrade {addon}");
        match kind {
            "pin" => {
                let (var, reference) = rest.split_once(' ').unwrap_or((rest, ""));
                if present(reference) {
                    env.push((var.to_string(), reference.to_string()));
                } else {
                    refused.push((addon.to_string(), format!("its pinned image {reference} is not on this host"), fix));
                }
            }
            _ => refused.push((addon.to_string(), format!("no verified pin for {}: {rest}", input.tag), fix)),
        }
    }
    if refused.is_empty() {
        for v in &vars {
            if !env.iter().any(|(k, _)| k == v) {
                refused.push((
                    v.clone(),
                    format!("a composed add-on overlay runs ${{{v}}} and no verified pin supplies it"),
                    "noo addons verify".to_string(),
                ));
            }
        }
    }
    if refused.is_empty() { Ok(env) } else { Err(refused) }
}

/// Split an optional `--root <dir>` (or `--root=<dir>`) off the front of the
/// launch-pins arguments.
fn launch_root_arg(args: &[String]) -> Result<(Option<std::path::PathBuf>, &[String]), String> {
    match args.first().map(String::as_str) {
        Some("--root") => match args.get(1) {
            Some(d) if !d.is_empty() => Ok((Some(d.into()), &args[2..])),
            _ => Err("--root needs a directory".to_string()),
        },
        Some(a) if a.starts_with("--root=") && a.len() > 7 => Ok((Some(a[7..].into()), &args[1..])),
        _ => Ok((None, args)),
    }
}

/// `noo addons launch-pins [--root <dir>] <tag> [<name>…]` (hidden; the launcher's reader).
pub fn addons_launch_pins(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (explicit, rest) = match launch_root_arg(args) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Usage, "usage", &e, Some("noo addons launch-pins [--root <dir>] <tag> [<name>...]")),
    };
    let Some((tag, names)) = rest.split_first() else {
        fail(g.json, ExitCode::Usage, "usage", "launch-pins needs the stack tag", Some("noo addons launch-pins [--root <dir>] <tag> [<name>...]"));
    };
    // The install root, never the cwd: the launcher inherits the operator's
    // directory (`~`), and the pins live under the state home.
    let root = explicit.unwrap_or_else(crate::envfile::repo_root);
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
    use crate::addons::resolve::tests::{anchor, lock, signed, signed_bundle, FakeDocker, OVERLAY, ROOT};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-addon-pins-cmd-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pinned_root(tag: &str) -> (std::path::PathBuf, String) {
        let d = scratch(tag);
        let f = signed_bundle(&lock("1.2.0", &["v0.6.0"], None));
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
    fn a_lock_without_a_bundle_runs_the_legacy_overlay_or_is_refused() {
        let d = scratch("legacy");
        let f = signed(&lock("1.2.0", &["v0.6.0"], None));
        let want = resolve::Want { addon: "trellion_intel", stack_tag: "v0.6.0", stack_lock: None, pinned: None, allow_downgrade: false };
        let v = resolve::check(&f, &anchor(), &want).unwrap();
        resolve::record(&d, "trellion_intel", &v, &f, "v0.6.0").unwrap();
        let names = vec!["trellion_intel".to_string()];
        let lines = launch_lines(&d, "v0.6.0", &names, &|_| Ok(anchor()));
        assert!(lines[0].starts_with("refuse trellion_intel its signed lock for v0.6.0 predates overlay bundles"), "{lines:?}");
        let mut docker = FakeDocker::default();
        assert!(verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &[]).problem.unwrap().contains("predates overlay bundles"));

        // An earlier CLI left the overlay in the slice: it runs, with a note.
        std::fs::write(crate::addons::pins::legacy_overlay(&d, "trellion_intel"), OVERLAY).unwrap();
        let lines = launch_lines(&d, "v0.6.0", &names, &|_| Ok(anchor()));
        assert!(lines[0].starts_with("pin trellion_intel NOO_ADDON_IMAGE_TRELLION_INTEL "), "{lines:?}");
        let reference = v.lock.images["trellion-intel"].clone();
        let mut docker = FakeDocker { local: vec![reference.clone()], ids: vec![(reference, "sha256:x".into())], ..Default::default() };
        let verdict = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &[]);
        assert!(verdict.problem.is_none(), "{verdict:?}");
        assert!(verdict.notes.iter().any(|n| n.contains("deprecated docker-compose.trellion-intel.yml")), "{verdict:?}");
    }

    #[test]
    fn launch_pins_read_the_given_root_not_the_cwd() {
        let (d, reference) = pinned_root("launch-root");
        let cwd = std::env::current_dir().unwrap();
        assert_ne!(cwd, d, "the fake root must not be the cwd");
        let args: Vec<String> = ["--root", d.to_str().unwrap(), "v0.6.0", "trellion_intel"].map(String::from).into();
        let (root, rest) = launch_root_arg(&args).unwrap();
        assert_eq!(root.as_deref(), Some(d.as_path()));
        assert_eq!(rest, ["v0.6.0", "trellion_intel"]);
        let lines = launch_lines(root.as_deref().unwrap(), &rest[0], &rest[1..], &|_| Ok(anchor()));
        assert_eq!(lines[0], format!("pin trellion_intel NOO_ADDON_IMAGE_TRELLION_INTEL {reference}"));
        // The cwd has no pins: reading it (the old behaviour) finds nothing.
        let from_cwd = launch_lines(&cwd, "v0.6.0", &rest[1..], &|_| Ok(anchor()));
        assert!(from_cwd[0].starts_with("refuse"), "{from_cwd:?}");

        let eq: Vec<String> = ["--root=/x", "v0.6.0"].map(String::from).into();
        assert_eq!(launch_root_arg(&eq).unwrap().0.as_deref(), Some(std::path::Path::new("/x")));
        assert!(launch_root_arg(&["--root".to_string()]).is_err());
        assert!(launch_root_arg(&["v0.6.0".to_string()]).unwrap().0.is_none());
    }

    #[test]
    fn verify_reports_missing_images_and_drift_and_notes_not_running() {
        let (d, reference) = pinned_root("verify");
        let id = format!("sha256:{}", "a".repeat(64));
        let mut docker = FakeDocker { local: vec![reference.clone()], ids: vec![(reference.clone(), id.clone())], ..Default::default() };
        // What `docker inspect` reports for a container the launcher created
        // from the digest-only pin (`docker ps` would print just the repo).
        let running = |config_image: &str, image_id: &str| {
            vec![resolve::Container { name: "noo-trellion-intel".into(), config_image: config_image.into(), image_id: image_id.into() }]
        };
        let ok = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &running(&reference, &id));
        assert!(ok.problem.is_none() && ok.notes.is_empty(), "{ok:?}");

        let idle = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &[]);
        assert!(idle.problem.is_none(), "{idle:?}");
        assert_eq!(idle.notes, ["trellion-intel is not running"]);

        let drift = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &running(&format!("{ROOT}:v0.6.0"), &id));
        assert!(drift.problem.unwrap().contains("not the pinned image"));

        // The pinned reference, but a container recreated from other bytes.
        let other = format!("sha256:{}", "b".repeat(64));
        let retagged = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &running(&reference, &other));
        let why = retagged.problem.unwrap();
        assert!(why.contains("not the pinned image") && why.contains("runs image bbbbbbbbbbbb, not aaaaaaaaaaaa"), "{why}");

        let mut no_id = FakeDocker { local: vec![reference.clone()], ..Default::default() };
        let unread = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut no_id, &running(&reference, &id));
        assert!(unread.problem.unwrap().contains("not the pinned image"));

        let mut empty = FakeDocker::default();
        let gone = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut empty, &[]);
        assert!(gone.problem.unwrap().contains("not in the local image store"));

        let no_anchor = verify_one(&d, "trellion_intel", "v0.6.0", Err(resolve::Refusal::NoAnchor), &mut docker, &[]);
        assert!(no_anchor.problem.unwrap().contains("names no signing key"));
    }

    fn input<'a>(root: &'a std::path::Path, dist: bool, addons: &[&str]) -> PinEnvInput<'a> {
        let overlay = OVERLAY.to_string();
        PinEnvInput {
            root,
            dist,
            tag: "v0.6.0",
            image_prefix: "noomesh",
            compose_texts: vec![overlay],
            composed_addons: addons.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn wizard_env_pins_a_pinned_addon_and_refuses_an_unpinned_one() {
        let (d, reference) = pinned_root("wizard-env");
        let r2 = reference.clone();
        let env = addon_image_env(&input(&d, true, &["trellion", "trellion_intel"]), &|_| Ok(anchor()), &|r| r == r2).unwrap();
        assert_eq!(env, vec![("NOO_ADDON_IMAGE_TRELLION_INTEL".to_string(), reference.clone())]);

        // Pinned but not local: refused, naming the add-on and the remedy.
        let e = addon_image_env(&input(&d, true, &["trellion_intel"]), &|_| Ok(anchor()), &|_| false).unwrap_err();
        assert_eq!(e[0].0, "trellion_intel");
        assert!(e[0].1.contains("is not on this host"), "{e:?}");
        assert_eq!(e[0].2, "noo addons upgrade trellion_intel");

        // On but unpinned (a fresh root): refused the same way.
        let empty = scratch("wizard-env-unpinned");
        let e = addon_image_env(&input(&empty, true, &["trellion_intel"]), &|_| Ok(anchor()), &|_| true).unwrap_err();
        assert!(e[0].1.contains("no verified pin for v0.6.0") && e[0].1.contains("has no pin"), "{e:?}");
        assert_eq!(e[0].2, "noo addons upgrade trellion_intel");

        // The overlay reads a variable no pin supplies (the add-on is not in
        // the composed set): refused by variable.
        let e = addon_image_env(&input(&d, true, &["trellion"]), &|_| Ok(anchor()), &|_| true).unwrap_err();
        assert_eq!(e[0].0, "NOO_ADDON_IMAGE_TRELLION_INTEL");

        // A dev install runs the dev build's name and verifies nothing.
        let dev = addon_image_env(&input(&empty, false, &["trellion_intel"]), &|_| Err(resolve::Refusal::NoAnchor), &|_| false).unwrap();
        assert_eq!(dev, vec![("NOO_ADDON_IMAGE_TRELLION_INTEL".to_string(), "noomesh/trellion-intel:v0.6.0".to_string())]);

        // No add-on overlay composed: nothing to do.
        let none = PinEnvInput { compose_texts: vec!["services:\n  gateway:\n    image: x\n".into()], ..input(&empty, true, &[]) };
        assert!(addon_image_env(&none, &|_| Err(resolve::Refusal::NoAnchor), &|_| false).unwrap().is_empty());
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
