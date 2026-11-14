// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo stack monitoring on|off|status`: whether this install runs Grafana,
//! Loki and Tempo (about 250 MiB idle). Prometheus, Alertmanager and
//! node-exporter always run and are not switched here.
//!
//! The ONE declaration is `cluster.monitoring: full | lean` in the install's
//! noomesh.yaml, beside `cluster.image_retention` and, like it, never an
//! environment variable. A MISSING value means FULL: the fleet controller is
//! itself a standalone-profile install, so nothing else can tell a
//! one-machine install from the fleet, and an install that never chose keeps
//! everything. Only the literal `lean` turns the three off. The launcher
//! (`scripts/lib-config.sh` `monitoring_level`, through `noo config
//! launch-render monitoring`), the gateway and `noo cluster verify` read the
//! same key with the same rule: [`declared_in`] + [`level_of`].
//!
//! Two things outrank the declaration, and both force the set ON:
//! `COMPOSE_PROFILES` listing `monitoring` (the launcher passes operator
//! profiles on), and the `controller` install profile, whose services include
//! the set. `status` names them; `off` refuses while either holds, because
//! writing `lean` would change nothing that runs.

use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use serde_json::json;
use std::path::Path;

/// The services this switch starts and removes, by compose service name.
pub(crate) const OPTIONAL: [&str; 3] = ["loki", "tempo", "grafana"];

/// Recreated after a switch: they read the Loki and Tempo addresses
/// (NOO_LOKI_URL, NOO_TEMPO_*) and noomesh.yaml at creation.
const RECREATE: [&str; 2] = ["gateway", "worker"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Level {
    Full,
    Lean,
}

impl Level {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Level::Full => "full",
            Level::Lean => "lean",
        }
    }
}

/// The raw `cluster.monitoring` of a noomesh.yaml text, trimmed. `None` when
/// the key is absent, not a string, or the text does not parse.
pub(crate) fn declared_in(yaml: &str) -> Option<String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    doc.get("cluster")?.get("monitoring")?.as_str().map(|s| s.trim().to_string())
}

/// Unset = full. Only the literal `lean` is lean; a typo keeps everything.
pub(crate) fn level_of(declared: Option<&str>) -> Level {
    match declared.map(str::trim) {
        Some("lean") => Level::Lean,
        _ => Level::Full,
    }
}

/// What can outrank the declaration (both force the set on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Shadow {
    /// `COMPOSE_PROFILES` lists `monitoring`; the string says where it is set.
    ComposeProfiles(String),
    /// The install runs the `controller` profile, which includes the set.
    ControllerProfile,
}

impl Shadow {
    fn describe(&self) -> String {
        match self {
            Shadow::ComposeProfiles(from) => format!("COMPOSE_PROFILES in {from} lists monitoring"),
            Shadow::ControllerProfile => "this install runs the controller profile, which always includes Grafana, Loki and Tempo".to_string(),
        }
    }

    fn remedy(&self) -> String {
        match self {
            Shadow::ComposeProfiles(from) => format!("remove `monitoring` from COMPOSE_PROFILES in {from}, then run this again"),
            Shadow::ControllerProfile => "a controller-profile install (a source checkout) keeps the set; nothing to switch".to_string(),
        }
    }
}

/// Everything the decision reads, gathered by [`facts_live`].
#[derive(Debug, Clone, Default)]
pub(crate) struct Facts {
    /// `cluster.monitoring` as written, if any.
    pub declared: Option<String>,
    /// The effective COMPOSE_PROFILES and where it comes from.
    pub compose_profiles: Option<(String, String)>,
    /// The install profile the launchers start (NOO_DEFAULT_PROFILE, else
    /// `.noo-standalone`, else controller).
    pub profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Status {
    /// What runs.
    pub effective: Level,
    /// What noomesh.yaml says (unset = full).
    pub declared_level: Level,
    pub declared: Option<String>,
    pub shadow: Option<Shadow>,
}

fn lists_monitoring(profiles: &str) -> bool {
    profiles
        .split(',')
        .map(|p| p.trim().trim_matches('"').trim_matches('\'').trim())
        .any(|p| p == "monitoring")
}

pub(crate) fn status_of(f: &Facts) -> Status {
    let declared_level = level_of(f.declared.as_deref());
    let shadow = match &f.compose_profiles {
        Some((v, from)) if lists_monitoring(v) => Some(Shadow::ComposeProfiles(from.clone())),
        _ if f.profile.trim() == "controller" => Some(Shadow::ControllerProfile),
        _ => None,
    };
    let effective = if shadow.is_some() { Level::Full } else { declared_level };
    Status { effective, declared_level, declared: f.declared.clone(), shadow }
}

/// Where the value came from, in words: the second half of `status`.
pub(crate) fn source_words(s: &Status) -> String {
    let declared = match s.declared.as_deref() {
        Some(v @ ("full" | "lean")) => format!("noomesh.yaml cluster.monitoring: {v}"),
        Some(v) => format!("noomesh.yaml cluster.monitoring: '{v}' is neither full nor lean, so full"),
        None => "cluster.monitoring is unset in noomesh.yaml; unset means full".to_string(),
    };
    match &s.shadow {
        Some(sh) => format!("shadowed: {}; {declared}", sh.describe()),
        None => declared,
    }
}

/// Which source a COMPOSE_PROFILES value the CLI sees came from. The CLI's
/// own environment already holds noomesh.yaml `compose_env` and `.env`
/// (envfile::ensure_repo_env fills unset keys from both), and the launcher
/// inherits exactly that environment, so `effective` is what the launcher
/// will read; the two files only say where it was written.
pub(crate) fn compose_profiles_source(effective: Option<&str>, yaml_compose_env: Option<&str>, dotenv: Option<&str>) -> Option<(String, String)> {
    let nonempty = |v: Option<&str>| v.map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
    let (eff, yaml, env) = (nonempty(effective), nonempty(yaml_compose_env), nonempty(dotenv));
    match eff {
        Some(v) if yaml.as_deref() == Some(v.as_str()) => Some((v, "noomesh.yaml compose_env".into())),
        Some(v) if env.as_deref() == Some(v.as_str()) => Some((v, ".env".into())),
        Some(v) => Some((v, "the environment (a shell export or a unit file)".into())),
        None => env.map(|v| (v, ".env".into())),
    }
}

/// The data directories of the three, under the state root: the bind
/// `device:` paths of the loki-data, tempo-data and grafana-data volumes in
/// docker-compose.cluster.yml. `off` keeps them; `on` finds them again.
pub(crate) fn data_dirs(state_root: &str) -> Vec<String> {
    let root = state_root.trim_end_matches('/');
    OPTIONAL.iter().map(|s| format!("{root}/{s}")).collect()
}

// ── writing the declaration ──────────────────────────────────────────────

/// `text` with `cluster.monitoring` set to `level`, everything else as it
/// was: an existing entry is rewritten in place (its trailing comment kept),
/// a missing one is inserted first under `cluster:`, a missing `cluster:`
/// block is appended. Only a key at the block's own indentation counts, so a
/// nested `monitoring:` deeper down is never touched.
pub(crate) fn set_in(text: &str, level: Level) -> String {
    let val = level.as_str();
    let lines: Vec<&str> = text.lines().collect();
    let head = lines.iter().position(|l| {
        let t = l.trim_end();
        !l.starts_with(char::is_whitespace)
            && (t == "cluster:" || (t.starts_with("cluster:") && t["cluster:".len()..].trim_start().starts_with('#')))
    });
    let Some(head) = head else {
        let mut out = text.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("\ncluster:\n  monitoring: {val}\n"));
        return out;
    };
    let mut end = head + 1;
    let mut indent: Option<String> = None;
    while end < lines.len() {
        let l = lines[end];
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            end += 1;
            continue;
        }
        if !l.starts_with(char::is_whitespace) {
            break;
        }
        if indent.is_none() {
            indent = Some(l[..l.len() - l.trim_start().len()].to_string());
        }
        end += 1;
    }
    let indent = indent.unwrap_or_else(|| "  ".to_string());
    let existing = (head + 1..end).find(|&i| {
        let l = lines[i];
        let ind = &l[..l.len() - l.trim_start().len()];
        let t = l.trim_start();
        ind == indent && t.starts_with("monitoring") && t["monitoring".len()..].trim_start().starts_with(':')
    });
    let mut out: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    match existing {
        Some(i) => {
            let l = lines[i];
            let comment = l.find(" #").map(|p| format!("  {}", l[p..].trim())).unwrap_or_default();
            out[i] = format!("{indent}monitoring: {val}{comment}");
        }
        None => out.insert(head + 1, format!("{indent}monitoring: {val}")),
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Write `level` into the noomesh.yaml at `path`. Refuses a file that does
/// not parse, and an edit that would not parse or not read back as `level`.
/// `std::fs::write` truncates and rewrites the SAME inode, so the gateway's
/// single-file bind mount of noomesh.yaml sees the change.
pub(crate) fn write_at(path: &Path, level: Level) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !text.trim().is_empty() && serde_yaml::from_str::<serde_yaml::Value>(&text).is_err() {
        return Err(format!("{} does not parse as YAML; refusing to edit it. Fix the file first", path.display()));
    }
    let updated = set_in(&text, level);
    if serde_yaml::from_str::<serde_yaml::Value>(&updated).is_err() || declared_in(&updated).as_deref() != Some(level.as_str()) {
        return Err(format!(
            "the edit would not leave cluster.monitoring: {} readable in {}; nothing was written. Set it by hand under `cluster:`",
            level.as_str(),
            path.display()
        ));
    }
    std::fs::write(path, updated).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

// ── on / off, behind a host so a test drives every effect ────────────────

pub(crate) trait MonHost {
    /// Write the declaration into noomesh.yaml.
    fn write(&mut self, level: Level) -> Result<(), String>;
    /// Stop and remove this service's container (never its data). Ok(false)
    /// when there was none.
    fn remove_container(&mut self, service: &str) -> Result<bool, String>;
    /// `noo stack restart --force <services>`: its exit code.
    fn restart(&mut self, services: &[&str]) -> i32;
    /// One line to the person.
    fn say(&mut self, line: &str);
}

/// The lines `off` prints about the data it kept: the paths, how to delete
/// them deliberately (printed, never run), and how to get them back.
pub(crate) fn kept_data_lines(dirs: &[String]) -> Vec<String> {
    let mut v = vec!["Their data is kept, nothing was deleted:".to_string()];
    v.extend(dirs.iter().map(|d| format!("  {d}")));
    v.push("To delete it deliberately (this cannot be undone):".to_string());
    v.push(format!("  sudo rm -rf {}", dirs.join(" ")));
    v.push("`noo stack monitoring on` starts them again on the same directories.".to_string());
    v
}

/// `off`: refuse while shadowed (Err, nothing changed); else write lean,
/// remove the three containers, recreate gateway and worker, say what was
/// kept.
pub(crate) fn off_on(h: &mut impl MonHost, st: &Status, dirs: &[String]) -> Result<i32, String> {
    if let Some(sh) = &st.shadow {
        return Err(format!("{}: writing lean would not turn anything off. Nothing was changed; {}", sh.describe(), sh.remedy()));
    }
    h.write(Level::Lean)?;
    h.say("monitoring: lean (cluster.monitoring in noomesh.yaml)");
    let mut failed: Vec<String> = Vec::new();
    for svc in OPTIONAL {
        match h.remove_container(svc) {
            Ok(true) => h.say(&format!("  {svc}: stopped and removed")),
            Ok(false) => {}
            Err(e) => {
                h.say(&format!("  {svc}: could not be removed ({e})"));
                failed.push(svc.to_string());
            }
        }
    }
    let rc = h.restart(&RECREATE);
    for l in kept_data_lines(dirs) {
        h.say(&l);
    }
    if rc != 0 {
        h.say("The gateway and worker were not recreated: run `noo stack restart --force gateway worker`.");
        return Ok(rc);
    }
    if !failed.is_empty() {
        h.say(&format!("Still there: {}. Remove by hand: docker rm -f <container>", failed.join(", ")));
        return Ok(1);
    }
    Ok(0)
}

/// `on`: write full, start the three (and recreate gateway and worker) under
/// the monitoring profile, say where the data is.
pub(crate) fn on_on(h: &mut impl MonHost, st: &Status, dirs: &[String]) -> Result<i32, String> {
    if st.declared.as_deref() != Some("full") {
        h.write(Level::Full)?;
        h.say("wrote cluster.monitoring: full to noomesh.yaml, so the declaration matches what runs");
    }
    if let Some(sh) = &st.shadow {
        h.say(&format!("note: {} (the set ran already)", sh.describe()));
    }
    h.say("monitoring: full (cluster.monitoring in noomesh.yaml)");
    let mut svcs: Vec<&str> = OPTIONAL.to_vec();
    svcs.extend(RECREATE);
    let rc = h.restart(&svcs);
    if rc != 0 {
        h.say("Grafana, Loki and Tempo did not all start: run `noo stack start` (the declaration is already full).");
        return Ok(rc);
    }
    h.say(&format!("Grafana, Loki and Tempo run on their earlier data, where it exists: {}", dirs.join(", ")));
    Ok(0)
}

// ── live ─────────────────────────────────────────────────────────────────

fn facts_live(root: &Path) -> Facts {
    crate::envfile::ensure_repo_env();
    let yaml = std::fs::read_to_string(root.join("noomesh.yaml")).unwrap_or_default();
    let yaml_ce = serde_yaml::from_str::<serde_yaml::Value>(&yaml).ok().and_then(|d| {
        d.get("compose_env")?.get("COMPOSE_PROFILES")?.as_str().map(str::to_string)
    });
    let dotenv = std::fs::read_to_string(root.join(".env")).ok().and_then(|t| crate::envfile::dotenv_last(&t, "COMPOSE_PROFILES"));
    let effective = std::env::var("COMPOSE_PROFILES").ok();
    let profile = std::env::var("NOO_DEFAULT_PROFILE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| if root.join(".noo-standalone").exists() { "standalone".into() } else { "controller".into() });
    Facts {
        declared: declared_in(&yaml),
        compose_profiles: compose_profiles_source(effective.as_deref(), yaml_ce.as_deref(), dotenv.as_deref()),
        profile,
    }
}

/// This install's EFFECTIVE level is lean (declared lean, nothing
/// outranking it): Grafana, Loki and Tempo do not run by choice. For the
/// paths that would otherwise act on them (a Grafana secret recreate, the
/// tailnet door for Grafana's port during an upgrade).
pub(crate) fn effective_lean_live(root: &Path) -> bool {
    status_of(&facts_live(root)).effective == Level::Lean
}

fn state_root_live() -> String {
    crate::commands::at_rest_volume::resolve_state_root(&|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
}

struct LiveHost<'a> {
    g: &'a Globals,
    root: std::path::PathBuf,
}

impl MonHost for LiveHost<'_> {
    fn write(&mut self, level: Level) -> Result<(), String> {
        write_at(&self.root.join("noomesh.yaml"), level)
    }

    fn remove_container(&mut self, service: &str) -> Result<bool, String> {
        let name = crate::envfile::container(service);
        let present = std::process::Command::new("docker")
            .args(["ps", "-aq", "--filter", &format!("name=^/{name}$")])
            .output()
            .map_err(|e| format!("docker: {e}"))?;
        if String::from_utf8_lossy(&present.stdout).trim().is_empty() {
            return Ok(false);
        }
        let _ = std::process::Command::new("docker").args(["stop", "-t", "30", &name]).output();
        let rm = std::process::Command::new("docker").args(["rm", &name]).output().map_err(|e| format!("docker: {e}"))?;
        if rm.status.success() {
            Ok(true)
        } else {
            Err(String::from_utf8_lossy(&rm.stderr).trim().to_string())
        }
    }

    fn restart(&mut self, services: &[&str]) -> i32 {
        let mut args: Vec<String> = vec!["--force".into()];
        args.extend(services.iter().map(|s| s.to_string()));
        super::mesh::restart_reporting(self.g, &args, false).unwrap_or(2)
    }

    fn say(&mut self, line: &str) {
        if !self.g.json {
            println!("{line}");
        }
    }
}

fn status_json(st: &Status, root: &Path, dirs: &[String]) -> serde_json::Value {
    json!({
        "monitoring": st.effective.as_str(),
        "declared": st.declared,
        "declared_level": st.declared_level.as_str(),
        "source": source_words(st),
        "shadowed": st.shadow.as_ref().map(|s| s.describe()),
        "config": root.join("noomesh.yaml").display().to_string(),
        "data": dirs,
    })
}

/// `noo stack monitoring status`
pub fn stack_monitoring_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let root = crate::envfile::repo_root();
    let st = status_of(&facts_live(&root));
    let dirs = data_dirs(&state_root_live());
    if g.json {
        println!("{}", status_json(&st, &root, &dirs));
        return Ok(0);
    }
    println!("monitoring: {}  ({})", st.effective.as_str(), source_words(&st));
    match st.effective {
        Level::Full => println!("  Grafana, Loki and Tempo are on. Turn them off (data kept): `noo stack monitoring off`"),
        Level::Lean => println!("  Grafana, Loki and Tempo are off; their data, if any, is kept in {}. Turn them on: `noo stack monitoring on`", dirs.join(", ")),
    }
    Ok(0)
}

/// `noo stack monitoring on`
pub fn stack_monitoring_on(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let root = crate::envfile::repo_root();
    let st = status_of(&facts_live(&root));
    let dirs = data_dirs(&state_root_live());
    let mut h = LiveHost { g, root: root.clone() };
    match on_on(&mut h, &st, &dirs) {
        Ok(rc) => {
            if g.json {
                println!("{}", status_json(&status_of(&facts_live(&root)), &root, &dirs));
            }
            Ok(rc)
        }
        Err(e) => fail(g.json, ExitCode::Generic, "monitoring", &e, None),
    }
}

/// `noo stack monitoring off`
pub fn stack_monitoring_off(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let root = crate::envfile::repo_root();
    let st = status_of(&facts_live(&root));
    let dirs = data_dirs(&state_root_live());
    let mut h = LiveHost { g, root: root.clone() };
    match off_on(&mut h, &st, &dirs) {
        Ok(rc) => {
            if g.json {
                println!("{}", status_json(&status_of(&facts_live(&root)), &root, &dirs));
            }
            Ok(rc)
        }
        Err(e) => fail(g.json, ExitCode::Generic, "monitoring", &e, Some("noo stack monitoring status")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(declared: Option<&str>) -> Facts {
        Facts { declared: declared.map(str::to_string), compose_profiles: None, profile: "standalone".into() }
    }

    #[test]
    fn unset_is_full_and_only_lean_is_lean() {
        assert_eq!(level_of(None), Level::Full, "a missing decision is FULL: the fleet controller is a standalone install");
        assert_eq!(level_of(Some("full")), Level::Full);
        assert_eq!(level_of(Some("lean")), Level::Lean);
        assert_eq!(level_of(Some(" lean ")), Level::Lean);
        assert_eq!(level_of(Some("off")), Level::Full, "a typo keeps everything");
        assert_eq!(level_of(Some("")), Level::Full);
    }

    #[test]
    fn the_setting_is_cluster_monitoring_in_noomesh_yaml() {
        assert_eq!(declared_in("cluster:\n  monitoring: lean\n").as_deref(), Some("lean"));
        assert_eq!(declared_in("cluster:\n  default_backend: vllm\n"), None);
        assert_eq!(declared_in("monitoring: lean\n"), None, "only under cluster:");
        assert_eq!(declared_in("cluster:\n  backends:\n    monitoring: lean\n"), None, "never a nested key");
        assert_eq!(declared_in(": not yaml ["), None);
        assert_eq!(declared_in(""), None);
    }

    #[test]
    fn status_names_where_the_value_came_from() {
        let s = status_of(&facts(None));
        assert_eq!(s.effective, Level::Full);
        assert_eq!(source_words(&s), "cluster.monitoring is unset in noomesh.yaml; unset means full");
        let s = status_of(&facts(Some("lean")));
        assert_eq!(s.effective, Level::Lean);
        assert_eq!(source_words(&s), "noomesh.yaml cluster.monitoring: lean");
        let s = status_of(&facts(Some("full")));
        assert_eq!(source_words(&s), "noomesh.yaml cluster.monitoring: full");
        let s = status_of(&facts(Some("of")));
        assert_eq!(s.effective, Level::Full);
        assert!(source_words(&s).contains("'of' is neither full nor lean, so full"), "{}", source_words(&s));
    }

    #[test]
    fn compose_profiles_listing_monitoring_shadows_lean() {
        let mut f = facts(Some("lean"));
        f.compose_profiles = Some(("embed-cpu, monitoring".into(), ".env".into()));
        let s = status_of(&f);
        assert_eq!(s.effective, Level::Full, "the shadow wins: the set runs");
        assert_eq!(s.declared_level, Level::Lean);
        assert_eq!(s.shadow, Some(Shadow::ComposeProfiles(".env".into())));
        assert_eq!(source_words(&s), "shadowed: COMPOSE_PROFILES in .env lists monitoring; noomesh.yaml cluster.monitoring: lean");
        f.compose_profiles = Some(("embed-cpu,monitoring-x".into(), ".env".into()));
        assert_eq!(status_of(&f).shadow, None, "a name that only starts with monitoring is not it");
    }

    #[test]
    fn the_controller_profile_shadows_lean() {
        let mut f = facts(Some("lean"));
        f.profile = "controller".into();
        let s = status_of(&f);
        assert_eq!(s.effective, Level::Full);
        assert_eq!(s.shadow, Some(Shadow::ControllerProfile));
    }

    #[test]
    fn compose_profiles_source_says_which_file() {
        assert_eq!(compose_profiles_source(None, None, None), None);
        assert_eq!(compose_profiles_source(Some("monitoring"), Some("monitoring"), None).unwrap().1, "noomesh.yaml compose_env");
        assert_eq!(compose_profiles_source(Some("monitoring"), None, Some("monitoring")).unwrap().1, ".env");
        assert_eq!(compose_profiles_source(Some("monitoring"), Some("embed-cpu"), Some("x")).unwrap().1, "the environment (a shell export or a unit file)");
        assert_eq!(compose_profiles_source(Some(" "), None, Some("monitoring")).unwrap(), ("monitoring".into(), ".env".into()));
    }

    #[test]
    fn set_in_rewrites_inserts_and_appends() {
        let t = "server:\n  port: 8080\ncluster:\n  default_backend: vllm\n  backends:\n    monitoring: keep\n";
        let out = set_in(t, Level::Lean);
        assert_eq!(declared_in(&out).as_deref(), Some("lean"));
        assert!(out.contains("    monitoring: keep"), "a nested key is never touched: {out}");
        assert!(out.starts_with("server:\n  port: 8080\ncluster:\n  monitoring: lean\n"), "{out}");
        let again = set_in(&out, Level::Full);
        assert_eq!(declared_in(&again).as_deref(), Some("full"));
        assert_eq!(again.matches("monitoring: full").count(), 1, "rewritten, not added twice: {again}");
        let commented = "cluster:\n  monitoring: lean  # chosen at onboard\n";
        assert_eq!(set_in(commented, Level::Full), "cluster:\n  monitoring: full  # chosen at onboard\n");
        let none = "server:\n  port: 8080\n";
        let out = set_in(none, Level::Lean);
        assert_eq!(declared_in(&out).as_deref(), Some("lean"));
        assert!(out.starts_with(none), "{out}");
    }

    #[test]
    fn write_at_refuses_an_unparseable_file_and_writes_a_good_one() {
        let dir = std::env::temp_dir().join(format!("noo-mon-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("noomesh.yaml");
        std::fs::write(&p, "cluster: [unclosed\n").unwrap();
        assert!(write_at(&p, Level::Lean).unwrap_err().contains("does not parse"));
        std::fs::write(&p, "cluster:\n  default_backend: vllm\n").unwrap();
        write_at(&p, Level::Lean).unwrap();
        assert_eq!(declared_in(&std::fs::read_to_string(&p).unwrap()).as_deref(), Some("lean"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_data_dirs_are_the_compose_bind_paths() {
        assert_eq!(data_dirs("/var/lib/noo/state/"), vec!["/var/lib/noo/state/loki", "/var/lib/noo/state/tempo", "/var/lib/noo/state/grafana"]);
        // The paths `on` finds again are the volumes' bind devices: if
        // compose moved them, off's "kept here" would point at nothing.
        let compose = std::fs::read_to_string(crate::test_support::repo_file("docker-compose.cluster.yml")).unwrap();
        for s in OPTIONAL {
            let vol = format!("\n  {s}-data:\n");
            let at = compose.find(&vol).unwrap_or_else(|| panic!("{s}-data volume moved"));
            let block = &compose[at..at + 400usize.min(compose.len() - at)];
            assert!(
                block.contains(&format!("device: ${{NOO_STATE_ROOT:-${{NOO_DATA_ROOT:?NOO_DATA_ROOT is not set - run noo onboard --only storage or set it in .env}}}}/{s}\n")),
                "{s}-data is no longer bound at <state root>/{s}: {block}"
            );
        }
    }

    #[derive(Default)]
    struct Fake {
        writes: Vec<Level>,
        removed: Vec<String>,
        restarts: Vec<Vec<String>>,
        said: Vec<String>,
        present: Vec<&'static str>,
        restart_rc: i32,
    }

    impl MonHost for Fake {
        fn write(&mut self, level: Level) -> Result<(), String> {
            self.writes.push(level);
            Ok(())
        }
        fn remove_container(&mut self, service: &str) -> Result<bool, String> {
            if self.present.contains(&service) {
                self.removed.push(service.to_string());
                Ok(true)
            } else {
                Ok(false)
            }
        }
        fn restart(&mut self, services: &[&str]) -> i32 {
            self.restarts.push(services.iter().map(|s| s.to_string()).collect());
            self.restart_rc
        }
        fn say(&mut self, line: &str) {
            self.said.push(line.to_string());
        }
    }

    fn dirs() -> Vec<String> {
        data_dirs("/srv/noo/state")
    }

    #[test]
    fn off_writes_lean_removes_containers_recreates_and_keeps_the_data() {
        let mut h = Fake { present: vec!["loki", "grafana"], ..Default::default() };
        let rc = off_on(&mut h, &status_of(&facts(None)), &dirs()).unwrap();
        assert_eq!(rc, 0);
        assert_eq!(h.writes, vec![Level::Lean]);
        assert_eq!(h.removed, vec!["loki", "grafana"]);
        assert_eq!(h.restarts, vec![vec!["gateway".to_string(), "worker".to_string()]]);
        let all = h.said.join("\n");
        assert!(all.contains("Their data is kept, nothing was deleted:"), "{all}");
        for d in dirs() {
            assert!(all.contains(&format!("  {d}\n")), "{d} not named: {all}");
        }
        assert!(all.contains("  sudo rm -rf /srv/noo/state/loki /srv/noo/state/tempo /srv/noo/state/grafana\n"), "{all}");
    }

    #[test]
    fn off_refuses_when_shadowed_and_changes_nothing() {
        let mut f = facts(Some("full"));
        f.compose_profiles = Some(("monitoring".into(), "noomesh.yaml compose_env".into()));
        let mut h = Fake { present: vec!["loki"], ..Default::default() };
        let e = off_on(&mut h, &status_of(&f), &dirs()).unwrap_err();
        assert!(e.contains("COMPOSE_PROFILES in noomesh.yaml compose_env lists monitoring"), "{e}");
        assert!(e.contains("Nothing was changed"), "{e}");
        assert!(h.writes.is_empty() && h.removed.is_empty() && h.restarts.is_empty());
        f.compose_profiles = None;
        f.profile = "controller".into();
        let mut h = Fake::default();
        assert!(off_on(&mut h, &status_of(&f), &dirs()).is_err());
        assert!(h.writes.is_empty());
    }

    /// general 2026-11-14: `on` while shadowed proceeds (the set runs
    /// already) AND writes full, saying so, so the declaration matches.
    #[test]
    fn on_while_shadowed_writes_full_and_says_so() {
        let mut f = facts(Some("lean"));
        f.compose_profiles = Some(("monitoring".into(), ".env".into()));
        let st = status_of(&f);
        assert!(st.shadow.is_some());
        let mut h = Fake::default();
        assert_eq!(on_on(&mut h, &st, &dirs()).unwrap(), 0);
        assert_eq!(h.writes, vec![Level::Full], "the declaration is written even when shadowed");
        assert!(h.said.iter().any(|l| l.contains("wrote cluster.monitoring: full to noomesh.yaml")), "{:?}", h.said);
        assert!(h.said.iter().any(|l| l.starts_with("note: ")), "{:?}", h.said);
    }

    #[test]
    fn on_writes_full_and_starts_the_three_with_gateway_and_worker() {
        let mut h = Fake::default();
        assert_eq!(on_on(&mut h, &status_of(&facts(Some("lean"))), &dirs()).unwrap(), 0);
        assert_eq!(h.writes, vec![Level::Full]);
        assert_eq!(h.restarts, vec![vec!["loki", "tempo", "grafana", "gateway", "worker"].into_iter().map(String::from).collect::<Vec<_>>()]);
        assert!(h.said.join("\n").contains("/srv/noo/state/loki"));
        // An unset value is written explicitly, so status names the file.
        let mut h = Fake::default();
        on_on(&mut h, &status_of(&facts(None)), &dirs()).unwrap();
        assert_eq!(h.writes, vec![Level::Full]);
        let mut h = Fake::default();
        on_on(&mut h, &status_of(&facts(Some("full"))), &dirs()).unwrap();
        assert!(h.writes.is_empty(), "already full: nothing to write");
    }

    #[test]
    fn a_failed_recreate_is_the_exit_code() {
        let mut h = Fake { restart_rc: 3, ..Default::default() };
        assert_eq!(off_on(&mut h, &status_of(&facts(None)), &dirs()).unwrap(), 3);
        assert!(h.said.join("\n").contains("Their data is kept"), "the data lines print even then");
    }

    /// `noo upgrade --stack` must not change an existing install: an
    /// install that never chose stays unset (= full), so the roll neither
    /// writes nor reads-and-rewrites the declaration. Only `noo stack
    /// monitoring` and the onboard question write it.
    #[test]
    fn upgrade_never_writes_the_declaration() {
        let upgrade = crate::test_src::own_code(include_str!("upgrade.rs"));
        assert!(!upgrade.contains("stack_monitoring"), "upgrade.rs reaches the monitoring declaration");
        assert!(!upgrade.contains("monitoring: lean") && !upgrade.contains("monitoring: full"));
        let steps = crate::test_src::own_code(include_str!("../onboard/steps.rs"));
        assert_eq!(steps.matches("write_at(&yaml, level)").count(), 1, "onboard writes it in one place");
    }

    /// `off` keeps the data: nothing in this module deletes a file or a
    /// directory, or runs a command that could; the deletion is a printed
    /// line the person runs themselves.
    #[test]
    fn off_never_deletes_data() {
        let own = crate::test_src::own_code(include_str!("stack_monitoring.rs"));
        for m in ["remove_dir_all(", "remove_dir(", "remove_file(", "Command::new(\"rm\")", "Command::new(\"sudo\")", "\"volume\"", "\"-v\""] {
            assert!(!own.contains(m), "{m} in stack_monitoring.rs: off must keep the data");
        }
        let body = crate::test_src::fn_body(&own, "fn remove_container(&mut self, service: &str) -> Result<bool, String> {\n        let name");
        assert!(body.contains(".args([\"rm\", &name])"), "containers are removed without -v: {body}");
    }

    #[test]
    fn the_switch_reads_no_environment_variable_of_its_own() {
        // The declaration is noomesh.yaml; the only environment this module
        // reads is what the launcher will read too (COMPOSE_PROFILES, the
        // install profile, the state root).
        let own = crate::test_src::own_code(include_str!("stack_monitoring.rs"));
        assert!(!own.contains("NOO_MONITORING"), "no environment switch for the declaration");
        for call in own.match_indices("std::env::var(\"").map(|(i, _)| &own[i + 15..(i + 40).min(own.len())]) {
            assert!(
                call.starts_with("COMPOSE_PROFILES\"") || call.starts_with("NOO_DEFAULT_PROFILE\""),
                "unexpected environment read: {call}"
            );
        }
    }
}
