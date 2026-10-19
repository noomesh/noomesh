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
//!   `verified <addon> <version> <stack>` line then one
//!   `pin <addon> <VAR> <ref>` line per image, or one
//!   `refuse <addon> <why>` line, per add-on. The launcher hands the
//!   `verified` lines to the gateway's add-on registry
//!   (`NOO_ADDONS_VERIFIED`, gateway-rust/src/addon_registry.rs).
//!
//! Nothing here restarts anything: a new pin takes effect on the operator's
//! next `noo stack restart --force`.

use std::path::Path;

use serde_json::json;

use crate::addons::{self, pins, resolve};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

const UPGRADE_USAGE: &str = "usage: noo addons upgrade [<name>...] [--check] [--allow-downgrade] [--lock <path|https-url>]";
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
            // Not an add-on the CLI ships: acceptable when the operator trusts a
            // signing key for it (`noo addons trust-key`).
            None if matches!(addons::trust::trusted_anchor(n), Ok(Some(_))) => Box::leak(n.clone().into_boxed_str()) as &'static str,
            None => fail(g.json, ExitCode::Usage, "unknown_addon",
                &format!("unknown add-on `{n}`, and no signing key is trusted for it"),
                Some(&format!("noo addons trust-key {n} <pubkey> --registry <root>"))),
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
    let mut lock_ref: Option<String> = None;
    let mut args_it = args.iter();
    while let Some(a) = args_it.next() {
        match a.as_str() {
            "--check" => check = true,
            "--allow-downgrade" => allow_downgrade = true,
            "--lock" => match args_it.next() {
                Some(v) if !v.starts_with('-') => lock_ref = Some(v.clone()),
                _ => fail(g.json, ExitCode::Usage, "usage", "--lock needs a path or an https:// URL", Some(UPGRADE_USAGE)),
            },
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
    let client = match addons::installed_client() {
        Ok(c) => c,
        Err(e) => fail(g.json, ExitCode::Generic, "store_unreadable", &e, Some("noo security secrets audit")),
    };
    let current = match pins::read(&root) {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "pins_unreadable", &e, Some("noo addons verify")),
    };
    // A third-party add-on is fetched with NO credential: the vendor token is
    // never sent to a registry the operator named.
    let plain = addons::lock_fetch::Client::new(None);
    if lock_ref.is_some() && (named.len() != 1 || !resolve::third_party(&named[0])) {
        fail(g.json, ExitCode::Usage, "usage", "--lock names one third-party add-on's lock: give exactly that add-on", Some(UPGRADE_USAGE));
    }
    let mut rows = Vec::new();
    let mut failed = 0;
    for addon in list {
        let third_party = resolve::third_party(addon);
        let client = if third_party { &plain } else { &client };
        let ctx = addons::Ctx { root: &root, tag: &tag, stack_lock: stack_lock.as_deref(), allow_downgrade, client };
        let installed = current.get(addon).cloned();
        let supplied = match (third_party, lock_ref.as_deref()) {
            (true, Some(r)) => Some(addons::trust::fetch_supplied(r).map_err(resolve::Refusal::Supplied)),
            _ => None,
        };
        let outcome = if let Some(Err(e)) = &supplied {
            Err(e.clone())
        } else if check {
            let supplied = supplied.and_then(Result::ok);
            resolve::installed_anchor(addon)
                .and_then(|anchor| {
                    let want = resolve::Want {
                        addon,
                        stack_tag: &tag,
                        stack_lock: stack_lock.as_deref(),
                        pinned: installed.as_ref().map(|p| p.version.as_str()),
                        allow_downgrade,
                    };
                    let route = client.route(&anchor).map_err(resolve::Refusal::Route)?;
                    addons::resolve_lock(client, &anchor, &want, supplied)
                        .and_then(|(v, f)| resolve::require_bundle(&v, &tag).map(|()| (v, f)))
                        .map(|(v, f)| (pins::Pin::from_verified(&v, &tag, &f.lock, route.pulled_from()), 0usize, client.describe(&route)))
                })
        } else {
            let supplied = supplied.and_then(Result::ok);
            resolve::installed_anchor(addon)
                .and_then(|anchor| addons::prepare_from(&ctx, addon, &anchor, supplied, &mut resolve::LiveDocker::new(&root)))
                .and_then(|p| addons::commit(&root, &p, &tag).map(|pin| (pin, p.pulled, p.via.clone())))
        };
        match outcome {
            Ok((offered, pulled, via)) => {
                let changed = installed.as_ref() != Some(&offered);
                rows.push(json!({
                    "addon": addon, "installed": installed.as_ref().map(|p| &p.version),
                    "offered": offered.version, "stack": tag, "key_index": offered.key_index,
                    "changed": changed, "pulled": pulled, "pinned": !check, "via": via,
                    "pulled_from": offered.pulled_from,
                }));
                if !g.json {
                    let was = installed.as_ref().map(|p| format!("{} for {}", p.version, p.stack)).unwrap_or_else(|| "not pinned".into());
                    if check {
                        let state = if changed { ui::bad("update available") } else { ui::good("current") };
                        println!("  {addon}  installed {was}; offered {} (add-on key #{}; {via})  {state}", offered.version, offered.key_index);
                    } else if changed {
                        ui::done(&format!("{addon} {} pinned for stack {tag} (was {was}; add-on key #{}; {pulled} image(s) pulled {via})",
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
    // A new bundle may declare the add-on's own NATS principal (i70 residue):
    // render it now, so the restart below presents a user the server knows.
    // Best-effort — without it the add-on presents the worker for one release.
    if !check && rows.iter().any(|r| r["changed"] == true) {
        match crate::commands::nats_users::reconcile_addon_principals(g, &root) {
            Ok(Some(out)) => {
                let reloaded = crate::commands::nats_users::hup_nats();
                if !g.json {
                    ui::done(&format!("add-on NATS principals rendered ({} principals){}",
                        out.users, if reloaded { "; noo-nats reloaded" } else { "" }));
                }
            }
            Ok(None) => {}
            Err(e) => if !g.json {
                ui::warned(&format!("an add-on's NATS principal was not rendered ({e}); run: noo cluster nats-users render"));
            },
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
    let pin = match resolve::offline_check(root, addon, tag, &anchor) {
        Ok(p) => p,
        Err(e) => {
            v.problem = Some(e);
            return v;
        }
    };
    for (name, r) in &pin.local_images() {
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
                "pulled_from": v.pin.as_ref().and_then(|p| p.pulled_from.as_ref()),
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
        // A built-in add-on is covered when it is licensed; any other name is a
        // third-party add-on whose lock must verify against a trusted key (no
        // key, no verdict: it is refused here, by name).
        let addon: &str = match crate::commands::addons::row(n) {
            Some(r) if r.licensed.is_none() => continue,
            Some(r) => r.key,
            None if resolve::third_party(n) => n.as_str(),
            None => continue,
        };
        if !seen.insert(addon.to_string()) {
            continue;
        }
        let res = anchor(addon).map_err(|e| e.why(addon)).and_then(|a| resolve::offline_check(root, addon, tag, &a));
        match res {
            Ok(pin) => {
                // The verdict the gateway's add-on registry reads
                // (`NOO_ADDONS_VERIFIED`): this add-on's signed lock verified
                // offline AND lists `tag`. Emitted before its `pin` lines so a
                // launcher that stops at the first problem still saw it.
                out.push(format!("verified {addon} {} {}", pin.version, pin.stack));
                for (image, reference) in &pin.local_images() {
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
            // Not an image: the registry verdict (`launch_lines`). The wizard
            // composes the stack but starts no gateway of its own.
            "verified" => {}
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
        resolve::record(&d, "trellion_intel", &v, &f, "v0.6.0", None).unwrap();
        let r = v.lock.images["trellion-intel"].clone();
        (d, r)
    }

    #[test]
    fn launch_lines_pin_what_verifies_and_refuse_the_rest() {
        let (d, reference) = pinned_root("launch");
        let names = vec!["trellion-intel".to_string(), "evolve".to_string(), "voice".to_string(), "trellion_intel".to_string()];
        let lines = launch_lines(&d, "v0.6.0", &names, &|a| if a == "trellion_intel" { Ok(anchor()) } else { Err(resolve::Refusal::NoAnchor) });
        assert_eq!(lines[0], "verified trellion_intel 1.2.0 v0.6.0", "the registry verdict leads: {lines:?}");
        assert_eq!(lines[1], format!("pin trellion_intel NOO_ADDON_IMAGE_TRELLION_INTEL {reference}"));
        assert!(lines[2].starts_with("refuse evolve the installed entitlement names no signing key"), "{lines:?}");
        assert_eq!(lines.len(), 3, "voice is not licensed and a duplicate spelling is one add-on: {lines:?}");

        let other_tag = launch_lines(&d, "v0.6.1", &names[..1], &|_| Ok(anchor()));
        assert!(other_tag[0].starts_with("refuse trellion_intel trellion_intel is pinned for stack v0.6.0"), "{other_tag:?}");
        assert!(!other_tag.iter().any(|l| l.starts_with("verified")), "a refused add-on is never reported verified: {other_tag:?}");
    }

    /// Pulled through the proxy: compose runs, and verify compares with,
    /// the pulled ref (same digest, the proxy host), never the GHCR ref
    /// docker does not hold.
    #[test]
    fn a_proxy_pin_launches_and_verifies_the_pulled_ref() {
        let d = scratch("proxy-pin");
        let f = signed_bundle(&lock("1.2.0", &["v0.6.0"], None));
        let want = resolve::Want { addon: "trellion_intel", stack_tag: "v0.6.0", stack_lock: None, pinned: None, allow_downgrade: false };
        let v = resolve::check(&f, &anchor(), &want).unwrap();
        let pull = "addons.noomesh.ai/example/intel";
        resolve::record(&d, "trellion_intel", &v, &f, "v0.6.0", Some(pull.into())).unwrap();
        let a = crate::addon_lock::TrustAnchor { pull: Some(pull.into()), ..anchor() };
        let signed_ref = v.lock.images["trellion-intel"].clone();
        let local = signed_ref.replacen("ghcr.io", "addons.noomesh.ai", 1);
        let names = vec!["trellion_intel".to_string()];
        let lines = launch_lines(&d, "v0.6.0", &names, &|_| Ok(a.clone()));
        assert_eq!(lines, ["verified trellion_intel 1.2.0 v0.6.0".to_string(), format!("pin trellion_intel NOO_ADDON_IMAGE_TRELLION_INTEL {local}")]);
        let running = vec![resolve::Container { name: "noo-trellion-intel".into(), config_image: local.clone(), image_id: "sha256:x".into() }];
        let mut docker = FakeDocker { local: vec![local.clone()], ids: vec![(local.clone(), "sha256:x".into())], ..Default::default() };
        let verdict = verify_one(&d, "trellion_intel", "v0.6.0", Ok(a.clone()), &mut docker, &running);
        assert!(verdict.problem.is_none() && verdict.notes.is_empty(), "{verdict:?}");
        // Only the GHCR ref local: the pulled ref is missing, and that is what is said.
        let mut ghcr_only = FakeDocker { local: vec![signed_ref.clone()], ..Default::default() };
        let verdict = verify_one(&d, "trellion_intel", "v0.6.0", Ok(a), &mut ghcr_only, &[]);
        assert!(verdict.problem.as_deref().is_some_and(|p| p.contains(&local)), "{verdict:?}");
    }

    /// Every docker-facing use of a pin goes through `local_images` (i91
    /// §4.2): a direct walk over `pin.images` would hand compose a ref docker
    /// does not hold on the proxy path.
    #[test]
    fn docker_facing_pin_refs_go_through_local_images() {
        let src = include_str!("addon_pins.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(!prod.contains("in &pin.images"), "iterate pin.local_images(), not pin.images");
        assert!(prod.matches("pin.local_images()").count() >= 2, "verify and launch-pins both map refs");
    }

    #[test]
    fn a_lock_without_a_bundle_is_refused_by_launch_pins_and_verify() {
        let d = scratch("legacy");
        let f = signed(&lock("1.2.0", &["v0.6.0"], None));
        let want = resolve::Want { addon: "trellion_intel", stack_tag: "v0.6.0", stack_lock: None, pinned: None, allow_downgrade: false };
        let v = resolve::check(&f, &anchor(), &want).unwrap();
        resolve::record(&d, "trellion_intel", &v, &f, "v0.6.0", None).unwrap();
        // An overlay an earlier CLI left in the install root no longer rescues it.
        std::fs::write(d.join("docker-compose.trellion-intel.yml"), OVERLAY).unwrap();
        let names = vec!["trellion_intel".to_string()];
        let lines = launch_lines(&d, "v0.6.0", &names, &|_| Ok(anchor()));
        assert!(lines[0].starts_with("refuse trellion_intel ") && lines[0].contains("predates signed bundles"), "{lines:?}");
        assert!(lines[0].contains("noo addons upgrade trellion_intel --check"), "{lines:?}");
        assert!(!lines.iter().any(|l| l.starts_with("pin ")), "{lines:?}");
        let mut docker = FakeDocker::default();
        let verdict = verify_one(&d, "trellion_intel", "v0.6.0", Ok(anchor()), &mut docker, &[]);
        assert!(verdict.problem.unwrap().contains("predates signed bundles"));
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
