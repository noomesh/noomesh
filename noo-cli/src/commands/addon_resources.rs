// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons launch-resources` (hidden; the launcher's materialiser) and
//! `noo addons rotate-secret`: an add-on's declared runtime inputs
//! (`resources.json`, `crate::addons::resources`; noomesh-internal i239
//! section 10).
//!
//! `launch-resources --root <dir> --tag <tag> --project <p>
//! --network <cluster network> <name>[=<overlay>]...` is run by
//! `scripts/lib-dist.sh` `addon_resources_materialise`, right after
//! `require_addon_pins`, for every add-on that is on and not refused. Per
//! add-on it re-verifies the signed lock offline (a `<name>=<overlay>` form,
//! a development checkout, reads the files beside that overlay instead and
//! verifies nothing: the launcher passes it only when the verdict is `dev`),
//! then prints, one per line:
//!
//! | line | meaning |
//! |---|---|
//! | `hold <addon> <service> <why>` | a third-party add-on's service that asks for a GPU, the Docker socket or `privileged`: never started |
//! | `env <addon> <VAR> <value>` | export it (non-secret values only) |
//! | `mount <addon> <VAR> <path>` | export it: a mount directory's host path |
//! | `own <addon> <uid> <path>` | hand this directory, recursively, to `uid` (a fresh generation) |
//! | `gen <addon> <path>` | the fresh generation: mark it complete once handed over |
//! | `stale <addon> <path>` | an older generation: remove it |
//! | `notice <addon> <text>` | an OPTIONAL resource could not be produced and was skipped |
//! | `refuse <addon> <why>` | leave the add-on out of this start, naming the resource or the secret |
//!
//! Every add-on on is checked here (`addons::guards`), with or without a
//! `resources.json`: its overlay may source, reference or interpolate only
//! its own secrets, and a third-party add-on may not hold a core name. A
//! refusal is a `refuse` line, so the launcher leaves it out of the start.
//!
//! No line carries a secret: a secret part cannot be declared with an
//! environment delivery (`resources::parse`), and files are written here, on
//! tmpfs, 0400 under 0700 directories, never printed.

use std::path::{Path, PathBuf};

use serde_json::json;

use crate::addons::{decls, guards, pins, resolve, resources};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

const LAUNCH_USAGE: &str = "noo addons launch-resources --root <d> --tag <t> --project <p> --network <n> <name>...";

#[derive(Debug)]
struct LaunchArgs {
    root: PathBuf,
    tag: String,
    project: String,
    cluster_network: String,
    /// `(addon, development overlay)`.
    addons: Vec<(String, Option<PathBuf>)>,
}

fn parse_launch(args: &[String]) -> Result<LaunchArgs, String> {
    let (mut root, mut tag, mut project, mut net) = (None, None, None, None);
    let mut addons = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |what: &str| it.next().filter(|v| !v.is_empty()).cloned().ok_or_else(|| format!("{what} needs a value"));
        match a.as_str() {
            "--root" => root = Some(PathBuf::from(val("--root")?)),
            "--tag" => tag = Some(val("--tag")?),
            "--project" => project = Some(val("--project")?),
            "--network" => net = Some(val("--network")?),
            s if s.starts_with('-') => return Err(format!("unknown flag {s}")),
            s => {
                let (name, dev) = match s.split_once('=') {
                    Some((n, p)) => (n, Some(PathBuf::from(p))),
                    None => (s, None),
                };
                if !crate::addons::trust::name_ok(name) {
                    return Err(format!("`{name}` is not an add-on name"));
                }
                addons.push((name.to_string(), dev));
            }
        }
    }
    Ok(LaunchArgs {
        root: root.ok_or("--root is required")?,
        tag: tag.unwrap_or_default(),
        project: project.ok_or("--project is required")?,
        cluster_network: net.ok_or("--network is required")?,
        addons,
    })
}

/// The bundle files of one add-on: verified against its signed lock (dist),
/// or read beside a development overlay (dev).
fn bundle_files(a: &LaunchArgs, addon: &str, dev: Option<&Path>) -> Result<std::collections::BTreeMap<String, Vec<u8>>, String> {
    let names: Vec<String> = ["docker-compose.yml", decls::SYSTEM_FILE, resources::RESOURCES_FILE].iter().map(|s| s.to_string()).collect();
    if let Some(overlay) = dev {
        let mut out = std::collections::BTreeMap::new();
        out.insert("docker-compose.yml".to_string(), std::fs::read(overlay).map_err(|e| format!("{}: {e}", overlay.display()))?);
        let dir = overlay.parent().unwrap_or(Path::new("."));
        for n in &names[1..] {
            if let Ok(b) = std::fs::read(dir.join(n)) {
                out.insert(n.clone(), b);
            }
        }
        return Ok(out);
    }
    let anchor = resolve::installed_anchor(addon).map_err(|e| e.why(addon))?;
    let (_pin, listed) = resolve::offline_check_files(&a.root, addon, &a.tag, &anchor)?;
    let wanted: Vec<String> = names.into_iter().filter(|n| listed.contains(n)).collect();
    Ok(pins::materialised_files(&a.root, addon, wanted.iter()))
}

/// The texts of the install root's core compose files (`docker-compose*.yml`
/// at the root; add-on overlays live under `addons/`).
fn core_compose_texts(root: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(root) else { return Vec::new() };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with("docker-compose") && n.ends_with(".yml") {
            if let Ok(t) = std::fs::read_to_string(e.path()) {
                out.push(t);
            }
        }
    }
    out
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// The base rundir, created 0700, owned by this process, on tmpfs.
fn prepare_base() -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;
    let base = resources::rundir(std::env::var("NOO_ADDON_RUNDIR").ok().as_deref(), euid());
    crate::commands::addon_provision::private_dir(&base)?;
    let owner = std::fs::metadata(&base).map_err(|e| format!("{}: {e}", base.display()))?.uid();
    if owner != euid() {
        return Err(format!("{} is owned by uid {owner}, not by this user; remove it or set NOO_ADDON_RUNDIR", base.display()));
    }
    match crate::commands::addon_provision::ram_backed(&base) {
        Ok(true) => Ok(base),
        Ok(false) => Err(format!("{} is not on tmpfs; add-on inputs are written to RAM only (set NOO_ADDON_RUNDIR to a tmpfs directory)", base.display())),
        Err(e) => Err(e),
    }
}

/// `NOO_<KEY>` from this process's environment, else the install's `.env`.
fn env_or_dotenv(root: &Path, key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .or_else(|| Some(crate::onboard::env::read_env_key(&root.join(".env"), key)))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

/// The launcher's lines for one add-on (see the module docs).
fn launch_one(a: &LaunchArgs, addon: &str, dev: Option<&Path>, store: &mut Option<crate::commands::secrets::SecretStore>) -> Vec<String> {
    let mut out = Vec::new();
    let refuse = |why: String| format!("refuse {addon} {}", why.replace('\n', " "));
    let files = match bundle_files(a, addon, dev) {
        Ok(f) => f,
        Err(e) => return vec![refuse(e)],
    };
    // What its overlay takes from core (only its own secrets) and, for a
    // third-party add-on, its name: checked again here, on the files this
    // start composes, before any of its inputs is produced.
    if let Err(e) = guards::guard_install(&a.root, addon, &files) {
        return vec![refuse(e)];
    }
    if resolve::third_party(addon) {
        let overlay = files.get("docker-compose.yml").map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
        match resources::holds(&overlay) {
            Ok(h) => {
                for (svc, why) in h {
                    out.push(format!("hold {addon} {svc} {why}"));
                }
            }
            Err(e) => return vec![refuse(e)],
        }
    }
    let Some(bytes) = files.get(resources::RESOURCES_FILE) else { return out };
    let facts = resources::bundle_facts(addon, &files);
    let res = match resources::parse(addon, bytes, &facts) {
        Ok(r) => r,
        Err(e) => return vec![refuse(e)],
    };
    let core = resources::core_compose_vars(&core_compose_texts(&a.root));
    if let Some(v) = resources::declared_vars(&res).into_iter().find(|v| core.contains(v)) {
        return vec![refuse(format!("its resources.json sets {v}, which a core compose file reads; it would change core"))];
    }
    if store.is_none() {
        match crate::commands::secrets::SecretStore::load_sops(&crate::envfile::repo_root().join("secrets/env.sops")) {
            Ok(s) => *store = Some(s),
            Err(e) => return vec![refuse(format!("its resources could not be produced: the encrypted store could not be read ({e})"))],
        }
    }
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    let mut src = resources::LiveSources {
        ca: &ca,
        store: store.as_ref().expect("loaded above"),
        project: a.project.clone(),
        cluster_network: a.cluster_network.clone(),
        console_origin: env_or_dotenv(&a.root, "NOO_CONSOLE_ORIGIN"),
        gateway_port: env_or_dotenv(&a.root, "NOO_PORT_GATEWAY").filter(|p| p.bytes().all(|b| b.is_ascii_digit())).unwrap_or_else(|| "8080".into()),
    };
    let plan = match resources::plan(addon, &res, &facts, &mut src) {
        Ok(p) => p,
        Err(e) => return vec![refuse(e)],
    };
    let written = match prepare_base().and_then(|base| resources::write_generation(&base, addon, &res, &plan)) {
        Ok(w) => w,
        Err(e) => return vec![refuse(format!("its resources could not be written: {e}"))],
    };
    let receipt = resources::receipt(addon, &res, &written).to_string();
    if let Some(dir) = written.gen_dir.parent() {
        if let Err(e) = crate::commands::addon_provision::write_private(dir, resources::RECEIPT_FILE, receipt.as_bytes(), 0o600) {
            return vec![refuse(format!("its receipt could not be written: {e}"))];
        }
    }
    for n in &plan.notices {
        out.push(format!("notice {addon} {}", n.replace('\n', " ")));
    }
    for (var, value) in &plan.env {
        out.push(format!("env {addon} {var} {value}"));
    }
    for (var, path) in &written.mounts {
        out.push(format!("mount {addon} {var} {}", path.display()));
    }
    if written.fresh {
        for (_, path) in &written.mounts {
            out.push(format!("own {addon} {} {}", res.uid, path.display()));
        }
        out.push(format!("gen {addon} {}", written.gen_dir.display()));
    }
    for s in &written.stale {
        out.push(format!("stale {addon} {}", s.display()));
    }
    out
}

/// `noo addons launch-resources …` (hidden; the launcher's materialiser).
pub fn addons_launch_resources(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = match parse_launch(args) {
        Ok(a) => a,
        Err(e) => fail(g.json, ExitCode::Usage, "usage", &e, Some(LAUNCH_USAGE)),
    };
    let mut store = None;
    for (addon, dev) in &a.addons {
        for l in launch_one(&a, addon, dev.as_deref(), &mut store) {
            println!("{l}");
        }
    }
    Ok(0)
}

/// `noo addons rotate-secret <name> <resource>`: give one declared
/// `shared_secret` a new value in the encrypted store. The add-on's services
/// read it on their next start.
pub fn addons_rotate_secret(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [name, resource] = args else { return Err(Unhandled) };
    if name.starts_with('-') || resource.starts_with('-') {
        return Err(Unhandled);
    }
    let root = crate::envfile::repo_root();
    let declared = match decls::materialised(&root, name) {
        Ok(decls::Declared { resources: Some(r), .. }) => r,
        Ok(_) => fail(g.json, ExitCode::Usage, "no_resources", &format!("{name}'s signed bundle declares no resources"), Some("noo addons show <name>")),
        Err(e) => fail(g.json, ExitCode::Generic, "bundle", &e, Some("noo addons verify")),
    };
    let Some(r) = declared.resources.iter().find(|r| &r.name == resource) else {
        fail(g.json, ExitCode::Usage, "unknown_resource", &format!("{name} declares no resource `{resource}`"), Some("noo addons show <name>"));
    };
    if r.what != resources::What::SharedSecret {
        fail(
            g.json,
            ExitCode::Usage,
            "not_a_shared_secret",
            &format!("`{resource}` is a {} resource; only a shared_secret is rotated here", r.what.kind()),
            Some("noo addons show <name>"),
        );
    }
    let var = resources::shared_secret_var(name, resource);
    let sops = root.join("secrets/env.sops");
    if let Err(e) = crate::commands::secrets::mint_replace(&[var.as_str()], &sops) {
        fail(g.json, ExitCode::Generic, "store", &format!("could not rotate {var}: {e}"), Some("noo security secrets audit"));
    }
    if g.json {
        println!("{}", json!({"addon": name, "resource": resource, "rotated": var, "restart_needed": true}));
        return Ok(0);
    }
    ui::done(&format!("{name}: {resource} has a new value in the encrypted store ({var}; the value is not printed)"));
    ui::guide(&[("noo stack restart <name> --force", "starts the add-on's services with the new value")]);
    Ok(0)
}

/// `noo addons show`'s resources section: names, kinds and destinations,
/// and the generation the last launch wrote (paths only).
pub(crate) fn show_rows(addon: &str, res: &resources::Resources) -> (Vec<Vec<String>>, Option<String>) {
    let rows = res
        .resources
        .iter()
        .map(|r| {
            vec![
                r.name.clone(),
                match r.what.part() {
                    Some(p) => format!("{} {p}", r.what.kind()),
                    None => r.what.kind().to_string(),
                },
                r.deliver.iter().map(resources::Target::describe).collect::<Vec<_>>().join(", "),
            ]
        })
        .collect();
    let base = resources::rundir(std::env::var("NOO_ADDON_RUNDIR").ok().as_deref(), euid());
    let receipt = std::fs::read_to_string(base.join(addon).join(resources::RECEIPT_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v["generation"].as_str().map(str::to_string));
    (rows, receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The launch-time half of the secrets guard, on a development overlay
    /// (the `<name>=<overlay>` form reads the files beside it): an overlay
    /// that sources core's JWT secret is a `refuse` line naming the add-on
    /// and the variable, and nothing else is printed for it. Reverting the
    /// `guards::guard_install` call in `launch_one` prints no refusal.
    #[test]
    fn launch_refuses_an_overlay_that_sources_a_core_secret() {
        let d = std::env::temp_dir().join(format!("noo-launch-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("addons/rhaddon")).unwrap();
        std::fs::write(
            d.join("docker-compose.cluster.yml"),
            "services:\n  gateway:\n    image: g\nsecrets:\n  noo_jwt_secret:\n    file: ${NOO_SECRET_RUNDIR:-/x}/noo_jwt_secret\n    x-noo-source: NOO_JWT_SECRET\n",
        )
        .unwrap();
        let overlay = d.join("addons/rhaddon/docker-compose.yml");
        let a = LaunchArgs { root: d.clone(), tag: String::new(), project: "noomesh".into(), cluster_network: "noo-cluster".into(), addons: vec![] };
        std::fs::write(&overlay, "services:\n  noo-rhaddon:\n    image: x\n    environment:\n      K: ${NOO_JWT_SECRET}\n").unwrap();
        let lines = launch_one(&a, "rhaddon", Some(overlay.as_path()), &mut None);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("refuse rhaddon ") && lines[0].contains("NOO_JWT_SECRET"), "{lines:?}");
        // Its own: no refusal (no resources.json, so nothing else is printed).
        std::fs::write(&overlay, "services:\n  noo-rhaddon:\n    image: ${NOO_ADDON_IMAGE_RHADDON:-x}\n").unwrap();
        assert!(launch_one(&a, "rhaddon", Some(overlay.as_path()), &mut None).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn launch_args_parse_names_and_dev_overlays() {
        let a: Vec<String> = ["--root", "/r", "--tag", "v1", "--project", "noomesh", "--network", "noo-cluster", "rhaddon", "other=/x/docker-compose.other.yml"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let p = parse_launch(&a).unwrap();
        assert_eq!(p.addons, vec![("rhaddon".to_string(), None), ("other".to_string(), Some(PathBuf::from("/x/docker-compose.other.yml")))]);
        assert!(parse_launch(&a[2..]).unwrap_err().contains("--root"));
        let bad: Vec<String> = ["--root", "/r", "--project", "p", "--network", "n", "Bad"].iter().map(|s| s.to_string()).collect();
        assert!(parse_launch(&bad).unwrap_err().contains("not an add-on name"));
    }
}
