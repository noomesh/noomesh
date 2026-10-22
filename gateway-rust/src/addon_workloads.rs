// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Add-on workloads: what an add-on's signed bundle says it runs on a node's
//! GPU, and the one seam the rest of the gateway reads them through
//! (noomesh-internal i163 part B; the reservation layer in
//! `routes/reservations.rs` consumes them).
//!
//! A workload is a container the add-on composes itself (`noo-pai-voice-worker`)
//! and labels `noo.addon=<addon>` and `noo.workload=<name>`. The declaration
//! carries what the mesh needs to place and run it: whether it takes the GPU
//! and how much (`need_mb`), and the add-on's own drain route (an `internal`
//! route of its manifest the gateway calls before stopping the workload).
//! Core never names a workload: everything here is read from the bundle.
//!
//! ## Where the declarations come from
//!
//! [`declared`] is the seam. It reads [`WORKLOADS_DIR`]`/<addon>/workloads.json`
//! for every REGISTERED add-on: the launcher materialises that file from the
//! add-on's SIGNED bundle (noomesh/noomesh#288, `addon_decls`), so the
//! signature covers it; the add-on's own image volume
//! (`addon_proxy::ROUTES_DIR`) is never read for this. [`validate`] is the
//! one gateway home of the spec rules (the CLI refuses the same at enable
//! time, so nothing valid is refused here). [`set_declared`] replaces the
//! read (tests, or a verdict that carries the declarations). The node agent
//! gets the same list in desired-config (`addon_workloads`) and acts on
//! nothing else.

use std::collections::HashMap;
use std::path::Path as FsPath;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Where the launcher materialises each add-on's declaration from its signed
/// bundle: `<WORKLOADS_DIR>/<addon>/workloads.json`. One home for the path:
/// `addon_decls` (noomesh/noomesh#288) owns it; this is the same constant.
pub use crate::addon_decls::WORKLOADS_DIR;
/// The declaration file's name.
pub const WORKLOADS_FILE: &str = "workloads.json";
/// At most this many workloads per add-on.
pub const MAX_WORKLOADS: usize = 16;
/// `need_mb` must be 1..=this (256 GiB).
pub const MAX_NEED_MB: u64 = 262_144;
/// A drain's `timeout_secs` must be 1..=this.
pub const MAX_DRAIN_SECS: u64 = 600;

/// A workload's drain: the manifest route (internal) the gateway calls
/// before stopping the workload, and how long it may take. Required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainSpec {
    pub route: String,
    pub timeout_secs: u64,
}

/// One declared workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadDecl {
    /// Filled from the file's directory, never trusted from the file.
    #[serde(default)]
    pub addon: String,
    pub name: String,
    /// `noo-<addon>-…`: the container the add-on's compose creates.
    pub container: String,
    /// Required: whether the workload takes the GPU.
    pub gpu: bool,
    /// Required, 1..=[`MAX_NEED_MB`]: GPU memory the workload needs.
    pub need_mb: u64,
    /// Required: the add-on's drain route and its bound.
    pub drain: DrainSpec,
}

impl WorkloadDecl {
    /// `<addon>/<name>`: the key a reservation names.
    pub fn key(&self) -> String {
        format!("{}/{}", self.addon, self.name)
    }

    /// What the node agent needs (desired-config `addon_workloads`).
    pub fn for_node(&self) -> Value {
        json!({"addon": self.addon, "name": self.name, "container": self.container, "gpu": self.gpu, "need_mb": self.need_mb})
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadsFile {
    workloads: Vec<WorkloadDecl>,
}

/// Is `s` a workload (or add-on) name by the spec: `^[a-z][a-z0-9-]{0,31}$`.
pub fn workload_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// The spec rules, in their one gateway home. Validate one declaration
/// against the add-on's manifest: names `^[a-z][a-z0-9-]{0,31}$`; the
/// container is `noo-<addon>-…` (letters, digits, `-`, `_`, `.`, at most
/// 128); `need_mb` 1..=[`MAX_NEED_MB`]; the drain route exists in the
/// manifest, is `internal`, and its `timeout_secs` is 1..=[`MAX_DRAIN_SECS`].
pub fn validate(d: &WorkloadDecl, manifest: Option<&crate::addon_proxy::AddonManifest>) -> Result<(), String> {
    if !workload_name_ok(&d.addon) || !workload_name_ok(&d.name) {
        return Err(format!("workload {:?}: add-on and workload names are a lowercase letter, then lowercase letters, digits and `-`, at most 32 characters", d.name));
    }
    let prefix = format!("noo-{}-", d.addon);
    if !d.container.starts_with(&prefix) || d.container.len() <= prefix.len() || d.container.len() > 128
        || !d.container.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
    {
        return Err(format!("workload {}: container must be `{prefix}…` (letters, digits, - _ ., at most 128)", d.key()));
    }
    if d.need_mb == 0 || d.need_mb > MAX_NEED_MB {
        return Err(format!("workload {}: need_mb must be 1..={MAX_NEED_MB}", d.key()));
    }
    if d.drain.timeout_secs == 0 || d.drain.timeout_secs > MAX_DRAIN_SECS {
        return Err(format!("workload {}: drain.timeout_secs must be 1..={MAX_DRAIN_SECS}", d.key()));
    }
    match manifest.and_then(|m| m.routes.iter().find(|r| r.name == d.drain.route)) {
        None => return Err(format!("workload {}: drain route {:?} is not a route of the add-on's manifest", d.key(), d.drain.route)),
        Some(r) if !r.internal => {
            return Err(format!("workload {}: drain route {:?} must be internal: the gateway calls it and decides when", d.key(), d.drain.route))
        }
        Some(_) => {}
    }
    Ok(())
}

/// Parse an add-on's `workloads.json` text. `addon` is the directory the
/// file came from and overrides anything the file says.
pub fn parse(addon: &str, text: &str, manifest: Option<&crate::addon_proxy::AddonManifest>) -> Result<Vec<WorkloadDecl>, String> {
    let file: WorkloadsFile = serde_json::from_str(text).map_err(|e| format!("{addon}/{WORKLOADS_FILE}: {e}"))?;
    if file.workloads.len() > MAX_WORKLOADS {
        return Err(format!("{addon}/{WORKLOADS_FILE}: at most {MAX_WORKLOADS} workloads, found {}", file.workloads.len()));
    }
    let mut out = Vec::with_capacity(file.workloads.len());
    for mut d in file.workloads {
        d.addon = addon.to_string();
        validate(&d, manifest)?;
        if out.iter().any(|o: &WorkloadDecl| o.name == d.name) {
            return Err(format!("{addon}/{WORKLOADS_FILE}: workload {:?} declared twice", d.name));
        }
        if out.iter().any(|o: &WorkloadDecl| o.container == d.container) {
            return Err(format!("{addon}/{WORKLOADS_FILE}: container {:?} declared twice", d.container));
        }
        out.push(d);
    }
    Ok(out)
}

/// Read `<dir>/<addon>/workloads.json` if present. `Ok(vec![])` when the
/// add-on declares no workload (no file).
pub fn read_dir(dir: &FsPath, addon: &str, manifest: Option<&crate::addon_proxy::AddonManifest>) -> Result<Vec<WorkloadDecl>, String> {
    if !crate::addon_registry::name_ok(addon) {
        return Err(format!("add-on name {addon:?} is not valid"));
    }
    let path = dir.join(addon).join(WORKLOADS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(addon, &text, manifest),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

static DECLARED: OnceLock<RwLock<Option<Vec<WorkloadDecl>>>> = OnceLock::new();

fn cell() -> &'static RwLock<Option<Vec<WorkloadDecl>>> {
    DECLARED.get_or_init(|| RwLock::new(None))
}

/// Install the declarations (the verified bundle's, once the launcher's
/// verdict carries them; tests). Replaces the file read entirely.
pub fn set_declared(d: Vec<WorkloadDecl>) {
    if let Ok(mut g) = cell().write() {
        *g = Some(d);
    }
}

/// Every declared workload of every registered add-on. Loaded once from
/// [`WORKLOADS_DIR`] on first use unless [`set_declared`] ran first; an
/// add-on whose file does not validate declares nothing and is logged.
pub fn declared() -> Vec<WorkloadDecl> {
    if let Ok(g) = cell().read() {
        if let Some(v) = g.as_ref() {
            return v.clone();
        }
    }
    let loaded = load_from_registry(FsPath::new(WORKLOADS_DIR));
    if let Ok(mut g) = cell().write() {
        if g.is_none() {
            *g = Some(loaded.clone());
        }
    }
    loaded
}

/// Read every registered add-on's file under `dir`.
pub fn load_from_registry(dir: &FsPath) -> Vec<WorkloadDecl> {
    let mut out = Vec::new();
    for entry in crate::addon_registry::all() {
        match read_dir(dir, entry.name(), Some(entry.manifest())) {
            Ok(v) => {
                if !v.is_empty() {
                    tracing::info!(addon = entry.name(), workloads = ?v.iter().map(|w| w.name.clone()).collect::<Vec<_>>(), "addon_workloads_declared");
                }
                out.extend(v);
            }
            Err(e) => tracing::warn!(addon = entry.name(), error = %e, "addon_workloads_refused"),
        }
    }
    out
}

/// The declaration for `<addon>/<name>`.
pub fn lookup(addon: &str, name: &str) -> Option<WorkloadDecl> {
    declared().into_iter().find(|d| d.addon == addon && d.name == name)
}

/// Split a reservation's `<addon>/<workload>`.
pub fn split_key(key: &str) -> Option<(String, String)> {
    let (a, w) = key.trim().split_once('/')?;
    if !workload_name_ok(a) || !workload_name_ok(w) {
        return None;
    }
    Some((a.to_string(), w.to_string()))
}

/// The declarations as the node agent needs them, keyed for a desired-config
/// answer (every node gets the whole list; the node acts only on a container
/// that exists there).
pub fn for_nodes() -> Vec<Value> {
    declared().iter().map(WorkloadDecl::for_node).collect()
}

/// The front door's rule for the workload proxy and status
/// (`/api/addon-workloads/{addon}/{workload}/proxy/...` and `.../status`): an
/// add-on's own token (`sub = addon:<addon>`) may reach the routes under ITS
/// OWN add-on name and no other. Everything else on the path stays with the
/// tier gate (an operator passes it anyway).
pub fn proxy_allows(sub: &str, path: &str) -> bool {
    let Some(addon) = sub.strip_prefix(crate::auth::ADDON_SUBJECT_PREFIX) else { return false };
    if addon.is_empty() || !crate::addon_registry::name_ok(addon) {
        return false;
    }
    let Some(rest) = path.strip_prefix("/api/addon-workloads/") else { return false };
    let Some((owner, tail)) = rest.split_once('/') else { return false };
    owner == addon && matches!(tail.split('/').nth(1), Some("proxy") | Some("status"))
}

/// Group declarations by add-on, for a report.
pub fn by_addon() -> HashMap<String, Vec<WorkloadDecl>> {
    let mut m: HashMap<String, Vec<WorkloadDecl>> = HashMap::new();
    for d in declared() {
        m.entry(d.addon.clone()).or_default().push(d);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(routes: &[(&str, bool)]) -> crate::addon_proxy::AddonManifest {
        let rs: Vec<Value> = routes
            .iter()
            .map(|(n, internal)| json!({"name": n, "method": "POST", "path": format!("/api/pai-voice/{n}"), "internal": internal}))
            .collect();
        serde_json::from_value(json!({
            "version": 1, "addon": "pai-voice", "base_url_env": "NOO_PAI_VOICE_URL",
            "base_url_default": "https://noo-pai-voice:9001", "routes": rs
        }))
        .expect("manifest")
    }

    const FILE: &str = r#"{"workloads": [{"name": "voice-worker", "container": "noo-pai-voice-worker", "gpu": true, "need_mb": 11264, "drain": {"route": "drain", "timeout_secs": 120}}]}"#;

    #[test]
    fn a_declaration_is_read_from_the_addons_directory_and_validated() {
        let m = manifest(&[("drain", true)]);
        let v = parse("pai-voice", FILE, Some(&m)).expect("parses");
        assert_eq!(v.len(), 1);
        let d = &v[0];
        assert_eq!((d.addon.as_str(), d.name.as_str(), d.container.as_str(), d.gpu, d.need_mb), ("pai-voice", "voice-worker", "noo-pai-voice-worker", true, 11264));
        assert_eq!(d.key(), "pai-voice/voice-worker");
        assert_eq!(d.drain.route, "drain");
        assert_eq!(d.for_node()["container"], "noo-pai-voice-worker");
        assert!(d.for_node().get("drain").is_none(), "the node does not get the drain route");

        // The file's own addon field never wins over the directory.
        let spoof = r#"{"workloads": [{"addon": "evolve", "name": "w", "container": "noo-pai-voice-w", "gpu": true, "need_mb": 1, "drain": {"route": "drain", "timeout_secs": 1}}]}"#;
        assert_eq!(parse("pai-voice", spoof, Some(&m)).unwrap()[0].addon, "pai-voice");
    }

    #[test]
    fn a_bad_declaration_is_refused_with_a_sentence() {
        let m = manifest(&[("drain", true), ("public_drain", false)]);
        let ok = |name: &str, container: &str, extra: &str| -> String {
            format!(r#"{{"name": "{name}", "container": "{container}", "gpu": true, "need_mb": 1024, "drain": {{"route": "drain", "timeout_secs": 120}}{extra}}}"#)
        };
        let sixteen_plus: String = (0..17).map(|i| ok(&format!("w{i}"), &format!("noo-pai-voice-w{i}"), "")).collect::<Vec<_>>().join(",");
        for (text, needle) in [
            (format!(r#"{{"workloads": [{}]}}"#, ok("Voice", "noo-pai-voice-x", "")), "names are"),
            (format!(r#"{{"workloads": [{}]}}"#, ok("voice_worker", "noo-pai-voice-x", "")), "names are"),
            (format!(r#"{{"workloads": [{}]}}"#, ok("w", "pai-voice-worker", "")), "noo-pai-voice-"),
            (format!(r#"{{"workloads": [{}]}}"#, ok("w", "noo-x", "")), "noo-pai-voice-"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "gpu": true, "need_mb": 0, "drain": {"route": "drain", "timeout_secs": 120}}]}"#.to_string(), "need_mb"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "gpu": true, "need_mb": 262145, "drain": {"route": "drain", "timeout_secs": 120}}]}"#.to_string(), "need_mb"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "gpu": true, "drain": {"route": "drain", "timeout_secs": 120}}]}"#.to_string(), "missing field"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "need_mb": 1, "drain": {"route": "drain", "timeout_secs": 120}}]}"#.to_string(), "missing field"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "gpu": true, "need_mb": 1}]}"#.to_string(), "missing field"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "gpu": true, "need_mb": 1, "drain": {"route": "nope", "timeout_secs": 1}}]}"#.to_string(), "not a route"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "gpu": true, "need_mb": 1, "drain": {"route": "public_drain", "timeout_secs": 1}}]}"#.to_string(), "must be internal"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "gpu": true, "need_mb": 1, "drain": {"route": "drain", "timeout_secs": 0}}]}"#.to_string(), "1..=600"),
            (r#"{"workloads": [{"name": "w", "container": "noo-pai-voice-x", "gpu": true, "need_mb": 1, "drain": {"route": "drain", "timeout_secs": 601}}]}"#.to_string(), "1..=600"),
            (format!(r#"{{"workloads": [{}, {}]}}"#, ok("w", "noo-pai-voice-x", ""), ok("w", "noo-pai-voice-y", "")), "declared twice"),
            (format!(r#"{{"workloads": [{}, {}]}}"#, ok("w", "noo-pai-voice-x", ""), ok("v", "noo-pai-voice-x", "")), "declared twice"),
            (format!(r#"{{"workloads": [{}]}}"#, ok("w", "noo-pai-voice-x", r#", "image": "evil""#)), "unknown field"),
            (format!(r#"{{"workloads": [{sixteen_plus}]}}"#), "at most 16"),
        ] {
            let text = text.as_str();
            let e = parse("pai-voice", text, Some(&m)).expect_err(text);
            assert!(e.contains(needle), "{text}: {e}");
        }
    }

    #[test]
    fn read_dir_is_empty_without_a_file_and_refuses_a_bad_name() {
        let dir = std::env::temp_dir().join(format!("noo-addon-workloads-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_dir(&dir, "pai-voice", None).unwrap(), vec![]);
        assert!(read_dir(&dir, "../x", None).is_err());
        std::fs::create_dir_all(dir.join("pai-voice")).unwrap();
        std::fs::write(dir.join("pai-voice").join(WORKLOADS_FILE), FILE).unwrap();
        let v = read_dir(&dir, "pai-voice", Some(&manifest(&[("drain", true)]))).unwrap();
        assert_eq!(v[0].name, "voice-worker");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_proxy_is_open_to_the_addons_own_token_for_its_own_workloads_only() {
        assert!(proxy_allows("addon:pai-voice", "/api/addon-workloads/pai-voice/voice-worker/proxy/v1/health"));
        assert!(!proxy_allows("addon:pai-voice", "/api/addon-workloads/evolve/worker/proxy/x"), "another add-on's workload");
        assert!(!proxy_allows("addon:pai-voice", "/api/addon-workloads/pai-voice/voice-worker/start"), "the actuator is not the proxy");
        assert!(proxy_allows("addon:pai-voice", "/api/addon-workloads/pai-voice/voice-worker/status"), "its own status");
        assert!(!proxy_allows("addon:pai-voice", "/api/addon-workloads/evolve/worker/status"));
        assert!(!proxy_allows("addon:pai-voice", "/api/cluster/reservations"), "not the reservation API");
        assert!(!proxy_allows("user:alice", "/api/addon-workloads/pai-voice/voice-worker/proxy/x"), "not an add-on token");
        assert!(!proxy_allows("addon:", "/api/addon-workloads//x/proxy/x"));
    }

    #[test]
    fn split_key_takes_addon_slash_workload() {
        assert_eq!(split_key("pai-voice/voice-worker"), Some(("pai-voice".into(), "voice-worker".into())));
        assert_eq!(split_key("pai-voice"), None);
        assert_eq!(split_key("Pai/Voice"), None);
        assert_eq!(split_key("pai-voice/voice_worker"), None, "the spec has no underscore");
        assert!(workload_name_ok("a") && workload_name_ok("voice-worker-2") && !workload_name_ok("1a") && !workload_name_ok(&"a".repeat(33)));
    }
}
