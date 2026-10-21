// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo systems` — turn a database-extending system on or off.
//!
//! The manifest in `noomesh.yaml` DECLARES which
//! systems exist; this decides which of them an install actually runs, and
//! mints their credentials in the same step.
//!
//! WHY ENABLING IS A COMMAND AND NOT A HAND-EDITED FLAG.
//!
//! Noomesh's broker provisions a system's role and schema when it sees intent
//! AND a credential. If those two can be set independently, they diverge: an
//! operator flips the flag, restarts, and the gateway refuses to provision a
//! system they believe they enabled. So one command does both, in an order
//! where each step's precondition is the previous step's output.
//!
//! THE CLI MINTS. THE BROKER NEVER DOES.
//!
//! The alternative — mesh noticing the flag and generating the password
//! itself — would put sops keys and write access to `secrets/env.sops` inside
//! the gateway container. That is a large privilege increase for the component
//! An earlier change exists to DE-privilege, and it moves store mutation somewhere
//! the re-encryption rules cannot be followed the way they are on the host.
//! The broker's privilege stays scoped to Postgres.
//!
//! MINT ONLY IF ABSENT. An upgrade path already has these passwords.
//! Regenerating would rewrite a role that the broker deliberately never
//! `ALTER`s — the rule two production outages bought. `enable` on an
//! already-enabled system is a no-op.
//!
//! DISABLE IS NOT A DATA OPERATION. It clears intent. It does not drop the
//! role, the schema, or the rows: a disable that destroyed data would make
//! "turn it off and see" unrecoverable. Reclaiming storage stays a separate,
//! loudly-named step that does not exist yet, on purpose.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::commands::secrets;
use crate::envfile;
use crate::{Globals, Unhandled};
use crate::ui::{self, Col, Glyph};

/// Result/data lines (stdout).
fn g_out(line: &str) {
    println!("{line}");
}

/// Refusals and failures (stderr, `✗`).
fn g_err(line: &str) {
    ui::failed(line, None);
}

/// One system as declared in `noomesh.yaml`.
///
/// Deliberately a separate parse from the gateway's `SystemConfig`: noo-cli
/// does not link the gateway crate. The FIELD NAMES are the contract, and
/// `the_documented_example_parses` keeps this honest against the committed
/// example rather than against a fixture that can drift from it.
///
/// Read out of a `serde_yaml::Value` by hand rather than with a derive —
/// `serde` is here without its `derive` feature, and turning that on to save
/// twenty lines would move the whole crate's dependency graph for one struct.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemEntry {
    pub role: String,
    pub ddl_role: String,
    pub schema: String,
    pub enabled_when: Option<String>,
    pub password_env: String,
    pub ddl_password_env: String,
}

fn required_str(m: &serde_yaml::Value, name: &str, sys: &str) -> Result<String, String> {
    m.get(name)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            format!("system {sys:?} is missing required field `{name}` in the systems manifest")
        })
}

pub(crate) fn parse_systems(text: &str) -> Result<BTreeMap<String, SystemEntry>, String> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| format!("could not parse config: {e}"))?;
    let Some(systems) = doc.get("systems").and_then(|v| v.as_mapping()) else {
        return Ok(BTreeMap::new());
    };
    let mut out = BTreeMap::new();
    for (k, v) in systems {
        let name = k.as_str().unwrap_or_default().to_string();
        out.insert(
            name.clone(),
            SystemEntry {
                role: required_str(v, "role", &name)?,
                ddl_role: required_str(v, "ddl_role", &name)?,
                schema: required_str(v, "schema", &name)?,
                enabled_when: v
                    .get("enabled_when")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                password_env: required_str(v, "password_env", &name)?,
                ddl_password_env: required_str(v, "ddl_password_env", &name)?,
            },
        );
    }
    Ok(out)
}

pub(crate) fn manifest_path() -> PathBuf {
    envfile::repo_root().join("noomesh.yaml")
}

pub fn load_manifest(path: &Path) -> Result<BTreeMap<String, SystemEntry>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "could not read {}: {e}. The `systems:` manifest lives there — see \
             noomesh.yaml.example",
            path.display()
        )
    })?;
    parse_systems(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Is this system on, and what decides it — for the status table.
///
/// A system whose name is an add-on follows the `addons:` map, the same
/// answer the gateway's `intent_declared` gives; it never has a flag of its
/// own (`enabled_when: NOO_PRO_ENABLED` was that flag, and the launcher
/// refuses to start on it). A system that is not an add-on may name a plain
/// env flag; none does today, and none at all means mandatory.
fn system_gate(name: &str, e: &SystemEntry) -> (bool, String) {
    let on = enabled_in(name, e, &crate::commands::addons::effective);
    if crate::commands::addons::row(name).is_some() {
        return (on, format!("addons.{name}"));
    }
    (on, e.enabled_when.as_deref().unwrap_or("always").to_string())
}

/// Is this system on, given what an `addons:` map declares (`declared`
/// answers `addons.<name>`, `None` when the map is silent)? The ONE answer:
/// `systems status`, the launcher's pre-`up` check and `cluster verify` all
/// ask it, so none of them can disagree with the gateway's `intent_declared`
/// in its own way.
pub(crate) fn enabled_in(name: &str, e: &SystemEntry, declared: &dyn Fn(&str) -> Option<bool>) -> bool {
    if let Some(row) = crate::commands::addons::row(name) {
        return declared(name).unwrap_or(row.default_on);
    }
    e.enabled_when.as_deref().map(flag_is_on).unwrap_or(true)
}

/// Shell truthiness, matching `lib-config.sh` and the gateway's reader. Three
/// implementations of this now exist and they must agree; a system that reads
/// "true" as off in one place and on in another is unprovisionable in a way
/// that looks like a broker bug.
fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn flag_is_on(flag: &str) -> bool {
    std::env::var(flag).map(|v| is_truthy(&v)).unwrap_or(false)
}

/// The credentials a system needs before the broker can provision it.
pub(crate) fn required_keys(e: &SystemEntry) -> [&str; 2] {
    [&e.password_env, &e.ddl_password_env]
}

/// THE credential step: mint whichever of the system's
/// credentials the store lacks, and nothing else. Every enable path runs this
/// one function — `systems enable`, `addons enable`, `entitlement install
/// --enable` — because three commands claimed to switch evolve on and only
/// one of them minted what the gateway then refused to start without.
///
/// Mint-if-absent, never rotate: an existing role is never rewritten (the
/// broker does not `ALTER`, see the module docs). Returns the key NAMES that
/// were minted and the backup the write left; no value ever leaves
/// `secrets::mint_missing`.
pub(crate) fn mint_credentials(e: &SystemEntry, sops_path: &Path) -> Result<(Vec<String>, Option<PathBuf>), String> {
    secrets::mint_missing(&required_keys(e), sops_path)
}

/// Every ENABLED system that lacks a credential it needs, with the keys it
/// lacks — `systems status`'s "enabled with no credential" state, as data.
/// `present` answers whether a key has a value in the store the caller can
/// see: the launcher's environment for the pre-`up` check, the sops store
/// for `cluster verify`.
pub(crate) fn missing_credentials(
    manifest: &BTreeMap<String, SystemEntry>,
    declared: &dyn Fn(&str) -> Option<bool>,
    present: &dyn Fn(&str) -> bool,
) -> Vec<(String, Vec<String>)> {
    manifest
        .iter()
        .filter(|(name, e)| enabled_in(name, e, declared))
        .filter_map(|(name, e)| {
            let lacking: Vec<String> =
                required_keys(e).iter().filter(|k| !present(k)).map(|k| (*k).to_string()).collect();
            (!lacking.is_empty()).then(|| (name.clone(), lacking))
        })
        .collect()
}

/// Exit code of `noo config launch-check system-credentials` when it
/// refuses — the same contract as `bind_sources::EXIT_REFUSED`, so
/// `lib-bind-sources.sh` tells "the check said no" (3) from "the check could
/// not run" (anything else) the same way for both.
pub const EXIT_REFUSED: i32 = crate::commands::bind_sources::EXIT_REFUSED;

/// The refusal text, pure so the words are pinned.
pub(crate) fn launch_refusal(missing: &[(String, Vec<String>)]) -> String {
    let mut s = String::new();
    for (name, keys) in missing {
        s.push_str(&format!(
            "REFUSED: system {name:?} is enabled but {} {} not in the secret store — the gateway \
             refuses to start without {} and would crash-loop.\n  fix: noo systems enable {name}   \
             (mints only what is absent; never rotates)\n",
            keys.join(", "),
            if keys.len() == 1 { "is" } else { "are" },
            if keys.len() == 1 { "it" } else { "them" },
        ));
    }
    s.push_str("Nothing was started or recreated; the running stack is untouched.\n");
    s
}

/// `noo config launch-check system-credentials [<noomesh.yaml>]` — the
/// launchers' pre-`up` refusal. Reads the `systems:`
/// manifest and the `addons:` map from the SAME file the gateway mounts, and
/// asks the launcher's own environment (where `load_secrets` exported the
/// store) — or, on the plaintext backend, the `.env` beside the file — for
/// each enabled system's credentials.
///
/// 0 = every enabled system has them (or there is no manifest);
/// [`EXIT_REFUSED`] = one line per system on stderr; 65 = the file does not
/// parse (the launcher warns and lets `up` speak).
pub fn launch_check(args: &[String]) -> i32 {
    let file = match args {
        [] => manifest_path(),
        [f] if !f.starts_with('-') => PathBuf::from(f),
        _ => {
            eprintln!("usage: noo config launch-check system-credentials [<noomesh.yaml>]");
            return 2;
        }
    };
    let Ok(text) = std::fs::read_to_string(&file) else {
        return 0; // no config, no manifest: nothing declares a system
    };
    let manifest = match parse_systems(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("noo config launch-check system-credentials: {}: {e}", file.display());
            return 65;
        }
    };
    let declared = crate::commands::addons::declared_in(&text);
    let dotenv = std::fs::read_to_string(file.with_file_name(".env")).unwrap_or_default();
    let present = |k: &str| {
        std::env::var(k).map(|v| !v.trim().is_empty()).unwrap_or(false) || dotenv_has_value(&dotenv, k)
    };
    let missing = missing_credentials(&manifest, &|n| declared.get(n).copied(), &present);
    if missing.is_empty() {
        return 0;
    }
    eprint!("{}", launch_refusal(&missing));
    EXIT_REFUSED
}

/// The same question from the operator's side, for `cluster verify`: every
/// enabled system whose credentials are in neither the sops store nor
/// `.env` under `repo_root()`. `Err` when the store exists and cannot be
/// read — "not read" is not "missing", and reporting it as missing would
/// send the operator minting duplicates.
pub(crate) fn store_missing_credentials() -> Result<Vec<(String, Vec<String>)>, String> {
    let path = manifest_path();
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(Vec::new()) };
    let manifest = parse_systems(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if manifest.is_empty() {
        return Ok(Vec::new());
    }
    let root = envfile::repo_root();
    let sops_path = root.join("secrets/env.sops");
    let store = if sops_path.exists() { Some(secrets::SecretStore::load_sops(&sops_path)?) } else { None };
    let dotenv = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
    let declared = crate::commands::addons::declared_in(&text);
    let present = |k: &str| store.as_ref().is_some_and(|s| s.contains(k)) || dotenv_has_value(&dotenv, k);
    Ok(missing_credentials(&manifest, &|n| declared.get(n).copied(), &present))
}

/// Why `noo upgrade --stack`'s credential stage stopped the roll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredRefusal {
    /// No `secrets/env.sops`, and an enabled system needs credentials minted:
    /// they are never written to plaintext `.env`. Carries what was missing.
    NoStore(Vec<(String, Vec<String>)>),
    /// The manifest or the store could not be read, or the write failed.
    Store(String),
}

/// The decision, with the store behind closures so it is testable without
/// sops: nothing missing → nothing touched (not even a store check); missing
/// and no store → refuse; otherwise mint each system through `mint`, which is
/// [`mint_credentials`] in production — mint-if-absent, never rotate.
pub(crate) fn credentials_stage(
    missing: Vec<(String, Vec<String>)>,
    store_exists: bool,
    mut mint: impl FnMut(&str) -> Result<Vec<String>, String>,
) -> Result<Vec<(String, Vec<String>)>, CredRefusal> {
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    if !store_exists {
        return Err(CredRefusal::NoStore(missing));
    }
    let mut minted = Vec::new();
    for (name, _) in &missing {
        let keys = mint(name).map_err(|e| CredRefusal::Store(format!("{name}: {e}")))?;
        minted.push((name.clone(), keys));
    }
    Ok(minted)
}

/// `noo upgrade --stack`'s stage:
/// mint the absent credentials of every ENABLED system under `root` before
/// anything in the roll moves, so the launcher's refusal never fires on a
/// supported upgrade. Returns what was minted, per system (empty = nothing
/// was missing, and nothing was written).
pub(crate) fn reconcile_credentials(root: &Path) -> Result<Vec<(String, Vec<String>)>, CredRefusal> {
    let path = root.join("noomesh.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(Vec::new()) };
    let manifest = parse_systems(&text).map_err(|e| CredRefusal::Store(format!("{}: {e}", path.display())))?;
    let sops = root.join("secrets/env.sops");
    let store = if sops.is_file() {
        Some(secrets::SecretStore::load_sops(&sops).map_err(CredRefusal::Store)?)
    } else {
        None
    };
    let dotenv = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
    let declared = crate::commands::addons::declared_in(&text);
    let present = |k: &str| store.as_ref().is_some_and(|s| s.contains(k)) || dotenv_has_value(&dotenv, k);
    let missing = missing_credentials(&manifest, &|n| declared.get(n).copied(), &present);
    credentials_stage(missing, store.is_some(), |name| {
        mint_credentials(&manifest[name], &sops).map(|(minted, _backup)| minted)
    })
}

/// Does `.env` text assign `key` a non-empty value? The plaintext backend's
/// half of "present": compose reads `.env` itself, so the launcher never
/// exports it.
fn dotenv_has_value(text: &str, key: &str) -> bool {
    text.lines().rev().find_map(|l| {
        let l = l.trim_start();
        let l = l.strip_prefix("export ").unwrap_or(l);
        l.strip_prefix(key)?.strip_prefix('=').map(|v| !v.trim().trim_matches(['"', '\'']).is_empty())
    }).unwrap_or(false)
}

pub fn systems_status(_g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    let manifest = match load_manifest(&manifest_path()) {
        Ok(m) => m,
        Err(e) => {
            g_err(&e);
            return Ok(1);
        }
    };
    if manifest.is_empty() {
        println!("{}", ui::muted("no `systems:` manifest — nothing extends this database yet"));
        println!("  {}", ui::muted("see the commented block in noomesh.yaml.example"));
        return Ok(0);
    }

    let sops_path = envfile::repo_root().join("secrets/env.sops");
    let sops = match secrets::SecretStore::load_sops(&sops_path) {
        Ok(s) => s,
        Err(e) => {
            // Not "no credentials": a failed decrypt returns zero keys, and
            // reporting that as MISSING for every system would send an
            // operator minting duplicates of secrets they already have.
            g_err(&format!("could not decrypt {}: {e}", sops_path.display()));
            return Ok(1);
        }
    };

    println!("{}", ui::header("systems", Some(&format!("{} declared", manifest.len()))));
    println!("{}", ui::section("systems"));
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut inconsistent: Vec<&String> = Vec::new();
    for (name, e) in &manifest {
        let (on, gate) = system_gate(name, e);
        let missing: Vec<&str> = required_keys(e)
            .into_iter()
            .filter(|k| !sops.contains(k))
            .collect();

        // The two facts an operator needs, and the inconsistent case called
        // out rather than left to be inferred from two adjacent columns.
        let (glyph, creds) = if missing.is_empty() {
            (if on { Glyph::Ok } else { Glyph::Bullet }, ui::state("verified"))
        } else {
            (if on { Glyph::Err } else { Glyph::Warn }, ui::err(&format!("missing {}", missing.join(", "))))
        };
        if on && !missing.is_empty() {
            inconsistent.push(name);
        }
        rows.push(vec![
            ui::glyph_cell(glyph),
            name.clone(),
            ui::state(if on { "running" } else { "stopped" }).replace("running", "enabled").replace("stopped", "disabled"),
            gate,
            creds,
        ]);
    }
    print!(
        "{}",
        ui::table(
            &[Col::left(""), Col::left("system"), Col::left("state"), Col::left("gate"), Col::left("credentials")],
            &rows
        )
    );
    for name in inconsistent {
        println!();
        println!(
            "{}",
            ui::status_line(Glyph::Err, &format!("{name} is enabled with no credential — the broker will refuse to provision it"))
        );
        println!("{}", ui::hint(&format!("noo systems enable {name}")));
    }
    Ok(0)
}

/// The entitlement feature a system needs to be enabled, if it is licensed.
/// Mirrors `gateway-rust/src/addons.rs::ADDONS[*].requires_feature`.
fn licensed_feature(system: &str) -> Option<&'static str> {
    match system {
        "evolve" => Some("evolve"),
        _ => None,
    }
}

pub fn systems_enable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    run_toggle(g, args, true)
}

pub fn systems_disable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    run_toggle(g, args, false)
}

fn run_toggle(_g: &Globals, args: &[String], enabling: bool) -> Result<i32, Unhandled> {
    let verb = if enabling { "enable" } else { "disable" };
    let mut name: Option<String> = None;
    let mut dry_run = false;
    for a in args {
        match a.as_str() {
            "--dry-run" | "-n" => dry_run = true,
            s if s.starts_with('-') => {
                g_err(&format!("unknown flag {s}"));
                return Ok(2);
            }
            s => name = Some(s.to_string()),
        }
    }
    let Some(name) = name else {
        g_err(&format!("usage: noo systems {verb} <name> [--dry-run]"));
        return Ok(2);
    };

    let manifest = match load_manifest(&manifest_path()) {
        Ok(m) => m,
        Err(e) => {
            g_err(&e);
            return Ok(1);
        }
    };
    let Some(entry) = manifest.get(&name) else {
        g_err(&format!(
            "{name:?} is not in the `systems:` manifest. Known: {}",
            manifest.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
        return Ok(1);
    };

    // A system with no `enabled_when` is mandatory — trellion, since the
    // container split. There is no flag to set, but it STILL NEEDS ITS
    // CREDENTIALS MINTED, and the first cut of this returned early here for
    // both verbs. That made trellion's DDL password unmintable by the only
    // command that mints, while the broker demands it unconditionally: the
    // manifest could be filled in and the gateway would then refuse to start,
    // with no supported way to fix it.
    // An add-on-named system has no flag of its own: `addons.<name>` is the
    // switch, and `noo addons enable` is what calls this verb to mint the
    // credentials. A flag written here would be the second home.
    let is_addon = crate::commands::addons::row(&name).is_some();
    let flag = if is_addon { None } else { entry.enabled_when.as_deref() };

    if !enabling {
        if is_addon {
            ui::done(&format!("no change: {name} is an add-on — its switch is `addons.{name}` in noomesh.yaml"));
            ui::guide(&[(&format!("noo addons disable {name}"), "declare it off; the containers stop on the next `noo stack start`")]);
            return Ok(0);
        }
        let Some(flag) = flag else {
            // Disable genuinely is a no-op here: the operator asked for a
            // state the system cannot be in.
            ui::done(&format!("no change: {name} has no `enabled_when` — it is mandatory and always on"));
            return Ok(0);
        };
        // Deliberately narrow. See the module docs: clearing intent is the
        // whole operation, and the data stays.
        if dry_run {
            g_out(&ui::status_line(Glyph::Bullet, &format!("would unset {flag} in .env (data untouched)")));
            return Ok(0);
        }
        // Single phase: disable is one env edit.
        ui::step(&format!("unsetting {flag} in .env"));
        if let Err(e) = envfile::set_env_flag(flag, false) {
            g_err(&e);
            return Ok(1);
        }
        ui::close_done(&format!("{name} disabled ({flag} unset)"));
        println!("{}", ui::note("its role, schema and rows are untouched — disable is not a data operation"));
        let consumers = entry_consumers(entry).join(", ");
        let why = format!("compose up recreates {consumers} so they drop the flag from their environment; a plain restart keeps the old env");
        ui::guide(&[
            ("noo stack start", why.as_str()),
            ("noo systems status", "confirms the system now shows Disabled"),
        ]);
        return Ok(0);
    }

    // ── enable ───────────────────────────────────────────────────────────
    // Licensed systems: enabling without an entitlement
    // that grants the feature only produces a gateway that refuses
    // "unlicensed" — say so here, before minting anything.
    if let Some(feature) = licensed_feature(&name) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        match crate::entitlement::installed_grants(feature, now) {
            Ok(ent) => ui::done(&format!("{name} is licensed to '{}' (feature `{feature}`)", ent.sub)),
            Err(why) => {
                ui::failed(
                    &format!("{name} is a licensed add-on and no installed entitlement grants `{feature}` ({why})"),
                    Some("noo security entitlement install <token>"),
                );
                if !dry_run {
                    return Ok(1);
                }
            }
        }
    }
    let sops_path = envfile::repo_root().join("secrets/env.sops");
    let keys = required_keys(entry);

    if dry_run {
        match flag {
            Some(f) => g_out(&ui::status_line(Glyph::Bullet, &format!("would set {f}=1 in .env"))),
            None if is_addon => g_out(&ui::status_line(Glyph::Bullet, &format!("{name} follows addons.{name} — no flag to set"))),
            None => g_out(&ui::status_line(Glyph::Bullet, &format!("{name} is mandatory — no flag to set"))),
        }
        g_out(&ui::status_line(Glyph::Bullet, &format!("would mint any of these that are absent: {}", keys.join(", "))));
        g_out(&ui::status_line(Glyph::Bullet, &format!("would recreate: {}", entry_consumers(entry).join(", "))));
        return Ok(0);
    }

    // Two phases (guide §5 Rhythm): Credentials → Environment.
    println!("{}", ui::phase("Credentials"));
    ui::step(&format!("minting any of {} that are absent", keys.join(", ")));
    // Minting lives inside the secrets module: SecretStore exposes no
    // accessor that returns a value, and that absence is a compile-time guard
    // worth more than the convenience of doing it here.
    match mint_credentials(entry, &sops_path) {
        Ok((minted, backup)) if minted.is_empty() => {
            ui::done("credentials already present — nothing minted (an existing role is never rewritten)");
            let _ = backup;
        }
        Ok((minted, backup)) => {
            ui::done(&format!("minted {} into {}", minted.join(", "), sops_path.display()));
            if let Some(b) = backup {
                println!("{}", ui::note(&format!("previous store backed up at {}", b.display())));
            }
        }
        Err(e) => {
            println!();
            g_err(&format!("could not mint credentials: {e}"));
            return Ok(1);
        }
    }

    println!("{}", ui::phase("Environment"));
    match flag {
        Some(f) => {
            ui::step(&format!("setting {f}=1 in .env"));
            if let Err(e) = envfile::set_env_flag(f, true) {
                println!();
                g_err(&e);
                return Ok(1);
            }
            ui::done(&format!("{f}=1"));
            ui::close_done(&format!("{name} enabled"));
        }
        None => {
            println!("{}", ui::note(&if is_addon {
                format!("{name} follows addons.{name} — no flag to set; credentials are what it needed")
            } else {
                format!("{name} is mandatory — no flag to set; credentials are what it needed")
            }));
            ui::close_done(&format!("{name} ready"));
        }
    }
    println!("{}", ui::note(&format!(
        "on the gateway's next boot the broker provisions role {:?} and schema {:?}",
        entry.role, entry.schema
    )));
    let consumers = entry_consumers(entry).join(", ");
    let why = format!("compose up recreates {consumers} with the new environment; a plain restart keeps the old env");
    ui::guide(&[
        ("noo stack start", why.as_str()),
        ("noo systems status", "confirms the system shows Enabled with its credential present"),
    ]);
    Ok(0)
}

/// Containers that must be recreated. Taken from the secrets REGISTRY, which
/// already records exactly this per credential, rather than a second list in
/// the manifest that could disagree with it.
///
/// The gateway is ALWAYS first: it hosts the broker, and it receives every
/// system's flag and passwords — by name for the systems compose names, in
/// the one `noo_systems_secrets` file for every other — only when it is
/// recreated. A system the registry has no rows for (one core does not name)
/// therefore still names it.
fn entry_consumers(e: &SystemEntry) -> Vec<String> {
    let mut out: Vec<String> = vec!["noo-gateway".to_string()];
    for key in required_keys(e) {
        if let Some(spec) = secrets::spec_for(key) {
            for c in spec.consumers {
                if !out.iter().any(|x| x == c) {
                    out.push((*c).to_string());
                }
            }
        }
    }
    // Display-only list — remap once so the "recreate these" message
    // names THIS instance's containers.
    out.into_iter().map(|c| crate::envfile::instanced(&c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The manifest shape, inline.
    ///
    /// It would be better to parse `noomesh.yaml.example` directly, and the
    /// first version did — but `scripts/cargo-docker.sh` mounts only the CRATE
    /// directory, so a repo-root file does not exist inside the test
    /// environment at all. Rather than pretend otherwise, the drift check
    /// against the committed example lives in
    /// `tests/test_systems_manifest_example.py`, which runs from the repo root
    /// and can see it. This side owns the parse; that side owns the agreement.
    fn example_manifest() -> &'static str {
        "systems:
  trellion:
    role: noo_trellion
    ddl_role: noo_trellion_ddl
    schema: trellion
    password_env: NOO_TRELLION_DB_PASSWORD
    ddl_password_env: NOO_TRELLION_DDL_PASSWORD
  evolve:
    role: noo_evolve
    ddl_role: noo_evolve_ddl
    schema: evolve
    password_env: NOO_EVOLVE_DB_PASSWORD
    ddl_password_env: NOO_EVOLVE_DDL_PASSWORD
"
    }

    #[test]
    fn enabling_a_system_core_does_not_name_recreates_the_gateway() {
        // No registry row knows these keys: the gateway (the broker's host,
        // and the only reader of the systems-secrets file) must still be named.
        let e = SystemEntry {
            role: "noo_example_addon".into(),
            ddl_role: "noo_example_addon_ddl".into(),
            schema: "example_addon".into(),
            enabled_when: Some("NOO_EXAMPLE_ADDON_ENABLED".into()),
            password_env: "NOO_EXAMPLE_ADDON_DB_PASSWORD".into(),
            ddl_password_env: "NOO_EXAMPLE_ADDON_DDL_PASSWORD".into(),
        };
        let got = entry_consumers(&e);
        assert_eq!(got.first(), Some(&crate::envfile::instanced("noo-gateway")), "{got:?}");
        assert_eq!(got.len(), 1, "{got:?}");
        // A system with registry rows keeps them, after the gateway, once each.
        let trellion = parse_systems(example_manifest()).unwrap().remove("trellion").unwrap();
        let got = entry_consumers(&trellion);
        assert_eq!(got.first(), Some(&crate::envfile::instanced("noo-gateway")), "{got:?}");
        let unique: std::collections::BTreeSet<&String> = got.iter().collect();
        assert_eq!(unique.len(), got.len(), "{got:?}");
    }

    #[test]
    fn the_manifest_shape_parses() {
        let systems = parse_systems(example_manifest()).expect("example systems block must parse");
        let trellion = systems.get("trellion").expect("trellion in the example");
        assert_eq!(trellion.role, "noo_trellion");
        assert_eq!(trellion.ddl_role, "noo_trellion_ddl");
        assert!(
            trellion.enabled_when.is_none(),
            "trellion is mandatory since the container split — it has no flag"
        );

        let evolve = systems.get("evolve").expect("evolve in the example");
        assert!(evolve.enabled_when.is_none(), "evolve is an add-on: addons.evolve is its switch, not a flag");
        assert_eq!(evolve.ddl_password_env, "NOO_EVOLVE_DDL_PASSWORD");
    }

    #[test]
    fn every_system_needs_two_credentials() {
        let systems = parse_systems(example_manifest()).unwrap();
        for (name, e) in &systems {
            let keys = required_keys(e);
            assert_ne!(keys[0], keys[1], "{name}: DDL and runtime must not share a credential");
        }
    }

    /// The bug this file shipped with, as a test.
    ///
    /// A system with no `enabled_when` is mandatory, and the first cut
    /// returned early for BOTH verbs — so trellion's DDL credential was
    /// unmintable by the only command that mints, while the broker demands it
    /// unconditionally. The manifest could be filled in and the gateway would
    /// then refuse to start, with no supported way out.
    ///
    /// Asserted on the parse rather than by running the command, which would
    /// need a repo, a sops key and a writable `.env`. What matters here is
    /// that a mandatory system still declares credentials that something has
    /// to mint.
    #[test]
    fn a_mandatory_system_still_declares_credentials_to_mint() {
        let systems = parse_systems(example_manifest()).unwrap();
        let trellion = &systems["trellion"];
        assert!(
            trellion.enabled_when.is_none(),
            "trellion is the mandatory case this test is about"
        );
        for key in required_keys(trellion) {
            assert!(
                !key.is_empty(),
                "a mandatory system still needs credentials — `enable` must not \
                 short-circuit before minting them"
            );
        }
    }

    #[test]
    fn truthiness_matches_the_shell_convention() {
        for on in ["1", "true", "TRUE", "yes", "on", " 1 "] {
            assert!(is_truthy(on), "{on:?}");
        }
        for off in ["0", "false", "no", "off", "", "maybe"] {
            assert!(!is_truthy(off), "{off:?}");
        }
    }

    #[test]
    fn a_missing_manifest_is_an_error_that_says_where_to_look() {
        let err = load_manifest(Path::new("/nonexistent/noomesh.yaml")).unwrap_err();
        assert!(err.contains("noomesh.yaml.example"), "got: {err}");
    }
}

#[cfg(test)]
mod launch_check_tests {
    use super::*;

    /// Unique env names, so no other test (or the operator's shell) can
    /// supply a value by accident: presence comes from the scratch `.env`.
    fn config(evolve_on: bool) -> String {
        format!(
            "addons:\n  evolve: {evolve_on}\nsystems:\n  evolve:\n    role: noo_evolve\n    ddl_role: noo_evolve_ddl\n    \
             schema: evolve\n    password_env: NOO_T1261_EVOLVE_DB\n    ddl_password_env: NOO_T1261_EVOLVE_DDL\n"
        )
    }

    fn scratch(tag: &str, yaml: &str, dotenv: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-launch-syscreds-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("noomesh.yaml"), yaml).unwrap();
        std::fs::write(d.join(".env"), dotenv).unwrap();
        d.join("noomesh.yaml")
    }

    fn run(p: &Path) -> i32 {
        launch_check(&[p.display().to_string()])
    }

    /// The rehearsal's state: evolve switched on, its DDL password never
    /// minted. The launcher must refuse instead of letting the gateway
    /// crash-loop.
    #[test]
    fn an_enabled_addon_without_its_ddl_password_is_refused() {
        let p = scratch("refuse", &config(true), "NOO_T1261_EVOLVE_DB=x\n");
        assert_eq!(run(&p), EXIT_REFUSED);
    }

    #[test]
    fn a_disabled_addon_or_complete_credentials_pass() {
        let p = scratch("off", &config(false), "");
        assert_eq!(run(&p), 0, "an add-on that is off needs nothing");
        let p = scratch("complete", &config(true), "NOO_T1261_EVOLVE_DB=x\nNOO_T1261_EVOLVE_DDL=\"y\"\n");
        assert_eq!(run(&p), 0);
    }

    #[test]
    fn an_empty_assignment_is_not_a_credential() {
        let p = scratch("empty", &config(true), "NOO_T1261_EVOLVE_DB=x\nNOO_T1261_EVOLVE_DDL=\"\"\n");
        assert_eq!(run(&p), EXIT_REFUSED);
    }

    #[test]
    fn no_config_passes_and_a_broken_one_cannot_run() {
        assert_eq!(launch_check(&["/nonexistent/noomesh.yaml".into()]), 0);
        let p = scratch("broken", "systems:\n  evolve:\n    role: r\n", "");
        assert_eq!(run(&p), 65, "a manifest missing required fields is 'could not run', not a refusal");
    }

    #[test]
    fn the_refusal_names_the_system_the_keys_and_the_fix() {
        let t = launch_refusal(&[("evolve".into(), vec!["NOO_EVOLVE_DDL_PASSWORD".into()])]);
        assert!(t.contains("\"evolve\" is enabled but NOO_EVOLVE_DDL_PASSWORD is not in the secret store"), "{t}");
        assert!(t.contains("fix: noo systems enable evolve"), "{t}");
        assert!(t.contains("untouched"), "{t}");
    }

    #[test]
    fn missing_credentials_follows_the_addons_map() {
        let m = parse_systems(&config(true)).unwrap();
        let none = |_: &str| false;
        let off = missing_credentials(&m, &|_| Some(false), &none);
        assert!(off.is_empty());
        let on = missing_credentials(&m, &|_| Some(true), &|k| k == "NOO_T1261_EVOLVE_DB");
        assert_eq!(on, vec![("evolve".to_string(), vec!["NOO_T1261_EVOLVE_DDL".to_string()])]);
        // Silent map: evolve's own polarity (off).
        assert!(missing_credentials(&m, &|_| None, &none).is_empty());
    }
}

#[cfg(test)]
mod upgrade_stage_tests {
    use super::*;

    #[test]
    fn nothing_missing_touches_nothing() {
        let out = credentials_stage(vec![], false, |_| panic!("minted with nothing missing"));
        assert_eq!(out, Ok(vec![]));
    }

    #[test]
    fn missing_without_a_store_refuses_and_mints_nothing() {
        let m = vec![("evolve".to_string(), vec!["NOO_EVOLVE_DDL_PASSWORD".to_string()])];
        let out = credentials_stage(m.clone(), false, |_| panic!("minted without a store"));
        assert_eq!(out, Err(CredRefusal::NoStore(m)));
    }

    #[test]
    fn missing_with_a_store_mints_each_system_and_a_failure_stops() {
        let m = vec![("evolve".to_string(), vec!["NOO_EVOLVE_DDL_PASSWORD".to_string()])];
        let mut calls = Vec::new();
        let out = credentials_stage(m.clone(), true, |n| { calls.push(n.to_string()); Ok(vec!["NOO_EVOLVE_DDL_PASSWORD".into()]) });
        assert_eq!(out, Ok(m.clone()));
        assert_eq!(calls, ["evolve"]);
        assert!(matches!(credentials_stage(m, true, |_| Err("EACCES".into())), Err(CredRefusal::Store(_))));
    }

    /// The rehearsal's shape on an install with no encrypted store: evolve on,
    /// no DDL password. Refused, and `.env` is left byte-for-byte alone.
    #[test]
    fn reconcile_without_a_store_refuses_and_writes_nothing() {
        let root = std::env::temp_dir().join(format!("noo-reconcile-creds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("noomesh.yaml"), "addons:\n  evolve: true\nsystems:\n  evolve:\n    role: r\n    \
            ddl_role: d\n    schema: s\n    password_env: NOO_T1261U_DB\n    ddl_password_env: NOO_T1261U_DDL\n").unwrap();
        let env_before = "NOO_SECRETS_BACKEND=env\nNOO_T1261U_DB=x\n";
        std::fs::write(root.join(".env"), env_before).unwrap();
        let out = reconcile_credentials(&root);
        let env_after = std::fs::read_to_string(root.join(".env")).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(out, Err(CredRefusal::NoStore(vec![("evolve".into(), vec!["NOO_T1261U_DDL".into()])])));
        assert_eq!(env_after, env_before);
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    fn entry(flag: Option<&str>) -> SystemEntry {
        SystemEntry {
            role: "r".into(),
            ddl_role: "d".into(),
            schema: "s".into(),
            enabled_when: flag.map(str::to_string),
            password_env: "P".into(),
            ddl_password_env: "D".into(),
        }
    }

    /// The trap this closes: a manifest entry for evolve carrying
    /// `enabled_when: NOO_PRO_ENABLED` made `systems status` read the
    /// retired flag (always off) and `systems disable` WRITE it into .env —
    /// which the launcher then refuses to start on.
    #[test]
    fn an_addon_named_system_is_gated_by_the_map_not_its_flag() {
        let (_, gate) = system_gate("evolve", &entry(Some("NOO_PRO_ENABLED")));
        assert_eq!(gate, "addons.evolve", "the flag on an add-on entry must be ignored");
        let (_, gate) = system_gate("trellion", &entry(None));
        assert_eq!(gate, "addons.trellion");
    }

    #[test]
    fn a_plain_system_still_reads_its_flag_or_is_mandatory() {
        std::env::remove_var("NOO_GATE_TEST_FLAG");
        let (on, gate) = system_gate("ledger", &entry(Some("NOO_GATE_TEST_FLAG")));
        assert!(!on);
        assert_eq!(gate, "NOO_GATE_TEST_FLAG");
        let (on, gate) = system_gate("ledger", &entry(None));
        assert!(on);
        assert_eq!(gate, "always");
    }
}
