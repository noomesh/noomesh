// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! An add-on bundle's declarations beyond its overlay: `system.json` (its
//! database system) and `workloads.json` (its managed workloads), i163 E/B,
//! `routes.json` (its HTTP route manifest, handed to the gateway the same way
//! since 0.6.13) and `resources.json` (its runtime inputs, `super::resources`,
//! i239 s10).
//!
//! Both are ordinary bundle files: listed by name and sha256 in the signed
//! `noo-addon-lock/2` bundle, so the bundle signature covers them. This
//! module refuses a bundle whose declaration breaks a rule, BEFORE anything
//! is pinned (`resolve::check`), and reads the materialised ones for
//! `noo addons list|show` and for minting the system's passwords.
//!
//! The `system.json` rules are the gateway's (`gateway-rust/src/addon_decls.rs`),
//! which re-checks them on every start; noo-cli does not link the gateway
//! crate, so `tests/test_addon_decls_materialise.py` holds the constants equal.
//! The `workloads.json` rules here are the i163 spec and a strict SUBSET of
//! what the gateway's one workload parser (`addon_workloads`) accepts, so a
//! bundle this accepts is never refused there.
//!
//! - `system.json` = `{schema, role, ddl_role, extensions?}` with `<id>` =
//!   the add-on name, `-` as `_`: schema `<id>`, role `noo_<id>`, ddl_role
//!   `noo_<id>_ddl`; extensions from [`ALLOWED_EXTENSIONS`]. Passwords are
//!   derived, never declared: [`password_envs`].
//! - `workloads.json` = `{"workloads": [{name, container, gpu, need_mb,
//!   drain: {route, timeout_secs}}]}`; container `noo-<addon>-<suffix>`;
//!   need_mb 1..=262144; drain.route an `internal` route of `routes.json`
//!   (checked here when the bundle ships `routes.json`, always by the gateway).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::Value;

pub const SYSTEM_FILE: &str = "system.json";
pub const WORKLOADS_FILE: &str = "workloads.json";
/// A route manifest a bundle may carry beside them. When the signed lock
/// lists it, the launcher hands it to the gateway like the other two
/// (`<install root>/.noo-addon-routes/<addon>/routes.json`, which the gateway
/// reads before any copy an overlay delivers); the gateway validates it.
/// When the bundle has one, drain routes are checked against it here too.
pub const ROUTES_FILE: &str = "routes.json";
/// The declaration files the launcher copies for the gateway.
pub const DECL_FILES: &[&str] = &[SYSTEM_FILE, WORKLOADS_FILE, ROUTES_FILE];

pub const MAX_FILE_BYTES: usize = 64 * 1024;
pub const MAX_WORKLOADS: usize = 16;
pub const MAX_NEED_MB: u64 = 262_144;
pub const MAX_DRAIN_SECS: u64 = 600;
pub const ALLOWED_EXTENSIONS: &[&str] = &[
    "vector",
    "pg_trgm",
    "pgcrypto",
    "citext",
    "btree_gin",
    "btree_gist",
    "hstore",
    "unaccent",
    "fuzzystrmatch",
];
pub const RESERVED_IDS: &[&str] = &[
    "app", "worker", "gateway", "admin", "readonly", "replication", "backup", "monitor",
    "public", "mesh", "noo", "information_schema",
];

/// A validated `system.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    pub schema: String,
    pub role: String,
    pub ddl_role: String,
    pub extensions: Vec<String>,
}

/// A validated workload. Same fields as the gateway's `addon_decls::Workload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    pub name: String,
    pub container: String,
    pub gpu: bool,
    pub need_mb: u64,
    pub drain_route: String,
    pub drain_timeout_secs: u64,
}

/// The add-on's database id: its name with `-` as `_`.
pub fn system_id(addon: &str) -> String {
    addon.replace('-', "_")
}

/// `(NOO_<ID>_DB_PASSWORD, NOO_<ID>_DDL_PASSWORD)`.
pub fn password_envs(addon: &str) -> (String, String) {
    let up = system_id(addon).to_ascii_uppercase();
    (format!("NOO_{up}_DB_PASSWORD"), format!("NOO_{up}_DDL_PASSWORD"))
}

fn obj<'a>(v: &'a Value, what: &str, allowed: &[&str]) -> Result<&'a serde_json::Map<String, Value>, String> {
    let m = v.as_object().ok_or_else(|| format!("{what} is not a JSON object"))?;
    if let Some(k) = m.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("{what} has an unknown field `{k}` (allowed: {})", allowed.join(", ")));
    }
    Ok(m)
}

fn req_str(m: &serde_json::Map<String, Value>, k: &str, what: &str) -> Result<String, String> {
    m.get(k).and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("{what}: `{k}` is required and must be a string"))
}

fn req_u64(m: &serde_json::Map<String, Value>, k: &str, what: &str) -> Result<u64, String> {
    m.get(k).and_then(Value::as_u64).ok_or_else(|| format!("{what}: `{k}` is required and must be a non-negative integer"))
}

/// Parse and validate `system.json` for `addon`.
pub fn parse_system(addon: &str, bytes: &[u8]) -> Result<System, String> {
    let what = format!("{SYSTEM_FILE} of add-on {addon}");
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!("{what} is larger than {MAX_FILE_BYTES} bytes"));
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("{what} is not JSON: {e}"))?;
    let m = obj(&v, &what, &["schema", "role", "ddl_role", "extensions"])?;
    let id = system_id(addon);
    if RESERVED_IDS.contains(&id.as_str()) || id.starts_with("pg_") {
        return Err(format!("add-on {addon} may not declare a database: its schema and roles would be core's ({id})"));
    }
    let s = System {
        schema: req_str(m, "schema", &what)?,
        role: req_str(m, "role", &what)?,
        ddl_role: req_str(m, "ddl_role", &what)?,
        extensions: match m.get("extensions") {
            None => Vec::new(),
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| x.as_str().map(str::to_string).ok_or_else(|| format!("{what}: `extensions` must be strings")))
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(format!("{what}: `extensions` must be an array of strings")),
        },
    };
    for (field, got, want) in [
        ("schema", &s.schema, id.clone()),
        ("role", &s.role, format!("noo_{id}")),
        ("ddl_role", &s.ddl_role, format!("noo_{id}_ddl")),
    ] {
        if *got != want {
            return Err(format!(
                "{what}: `{field}` is {got:?}, and it must be {want:?} (schema `<id>`, role `noo_<id>`, \
                 ddl_role `noo_<id>_ddl`, with <id> = the add-on name, `-` as `_`)"
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for e in &s.extensions {
        if !ALLOWED_EXTENSIONS.contains(&e.as_str()) {
            return Err(format!("{what}: extension {e:?} is not one a bundle may ask for ({})", ALLOWED_EXTENSIONS.join(", ")));
        }
        if !seen.insert(e) {
            return Err(format!("{what}: extension {e:?} is listed twice"));
        }
    }
    Ok(s)
}

fn workload_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn container_ok(addon: &str, c: &str) -> bool {
    let Some(suffix) = c.strip_prefix(&format!("noo-{addon}-")) else { return false };
    !suffix.is_empty()
        && c.len() <= 63
        && suffix.starts_with(|ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && suffix.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// `name -> internal?` for each route of a `routes.json`, or `None` when it
/// is not a readable manifest (the gateway refuses it on its own).
fn route_kinds(routes_json: &[u8]) -> Option<BTreeMap<String, bool>> {
    let v: Value = serde_json::from_slice(routes_json).ok()?;
    Some(
        v.get("routes")?
            .as_array()?
            .iter()
            .filter_map(|r| Some((r.get("name")?.as_str()?.to_string(), r.get("internal").and_then(Value::as_bool).unwrap_or(false))))
            .collect(),
    )
}

/// Parse and validate `workloads.json` for `addon`. `routes_json` is the
/// bundle's `routes.json` when it ships one.
pub fn parse_workloads(addon: &str, bytes: &[u8], routes_json: Option<&[u8]>) -> Result<Vec<Workload>, String> {
    let what = format!("{WORKLOADS_FILE} of add-on {addon}");
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!("{what} is larger than {MAX_FILE_BYTES} bytes"));
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("{what} is not JSON: {e}"))?;
    let top = obj(&v, &what, &["workloads"])?;
    let list = top.get("workloads").and_then(Value::as_array).ok_or_else(|| format!("{what}: `workloads` must be an array"))?;
    if list.len() > MAX_WORKLOADS {
        return Err(format!("{what} declares {} workloads (at most {MAX_WORKLOADS})", list.len()));
    }
    let routes = routes_json.and_then(route_kinds);
    let (mut names, mut containers, mut out) = (BTreeSet::new(), BTreeSet::new(), Vec::new());
    for item in list {
        let m = obj(item, &format!("{what}: a workload"), &["name", "container", "gpu", "need_mb", "drain"])?;
        let name = req_str(m, "name", &what)?;
        let at = format!("{what}, workload {name:?}");
        if !workload_name_ok(&name) {
            return Err(format!("{what}: workload name {name:?} must be lowercase letters, digits and `-`, starting with a letter, at most 32"));
        }
        if !names.insert(name.clone()) {
            return Err(format!("{at}: the name is declared twice"));
        }
        let container = req_str(m, "container", &at)?;
        if !container_ok(addon, &container) {
            return Err(format!("{at}: container {container:?} must be `noo-{addon}-<suffix>` (lowercase letters, digits, `-`; at most 63 characters)"));
        }
        if !containers.insert(container.clone()) {
            return Err(format!("{at}: container {container:?} is used by another workload"));
        }
        let gpu = m.get("gpu").and_then(Value::as_bool).ok_or_else(|| format!("{at}: `gpu` is required and must be true or false"))?;
        let need_mb = req_u64(m, "need_mb", &at)?;
        if !(1..=MAX_NEED_MB).contains(&need_mb) {
            return Err(format!("{at}: need_mb {need_mb} is outside 1..={MAX_NEED_MB}"));
        }
        static NULL: Value = Value::Null;
        let drain = obj(m.get("drain").unwrap_or(&NULL), &format!("{at}: drain"), &["route", "timeout_secs"])?;
        let drain_route = req_str(drain, "route", &format!("{at}: drain"))?;
        let drain_timeout_secs = req_u64(drain, "timeout_secs", &format!("{at}: drain"))?;
        if !(1..=MAX_DRAIN_SECS).contains(&drain_timeout_secs) {
            return Err(format!("{at}: drain.timeout_secs {drain_timeout_secs} is outside 1..={MAX_DRAIN_SECS}"));
        }
        if drain_route.is_empty() {
            return Err(format!("{at}: drain.route is empty"));
        }
        if let Some(routes) = &routes {
            match routes.get(&drain_route) {
                Some(true) => {}
                Some(false) => return Err(format!("{at}: drain.route {drain_route:?} is a public route; it must be an `internal` route of routes.json")),
                None => return Err(format!("{at}: drain.route {drain_route:?} is not a route of the bundle's routes.json")),
            }
        }
        out.push(Workload { name, container, gpu, need_mb, drain_route, drain_timeout_secs });
    }
    Ok(out)
}

/// What one bundle declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Declared {
    pub system: Option<System>,
    pub workloads: Vec<Workload>,
    /// Its runtime inputs (`resources.json`, `super::resources`).
    pub resources: Option<super::resources::Resources>,
}

/// Validate the declarations among a bundle's verified files (name to
/// bytes). `Err` refuses the bundle.
pub fn check_bundle(addon: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<Declared, String> {
    let system = files.get(SYSTEM_FILE).map(|b| parse_system(addon, b)).transpose()?;
    let workloads = files
        .get(WORKLOADS_FILE)
        .map(|b| parse_workloads(addon, b, files.get(ROUTES_FILE).map(Vec::as_slice)))
        .transpose()?
        .unwrap_or_default();
    let facts = super::resources::bundle_facts(addon, files);
    let resources = files
        .get(super::resources::RESOURCES_FILE)
        .map(|b| super::resources::parse(addon, b, &facts))
        .transpose()?;
    Ok(Declared { system, workloads, resources })
}

/// The declarations materialised under `<root>/addons/<addon>/` (by
/// `noo addons enable|upgrade`, verified against the signed lock then).
/// Absent files declare nothing; an invalid one is an error.
pub fn materialised(root: &Path, addon: &str) -> Result<Declared, String> {
    let names: Vec<String> = [SYSTEM_FILE, WORKLOADS_FILE, ROUTES_FILE, super::resources::RESOURCES_FILE, "docker-compose.yml"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let files = super::pins::materialised_files(root, addon, names.iter());
    check_bundle(addon, &files)
}

/// The bundle-declared systems of the add-ons switched on under `root`, as
/// `systems:` entries keyed by system id: what `noo addons enable` and
/// `noo upgrade --stack` mint passwords for. `on` answers "is this add-on
/// switched on". An unreadable declaration is skipped here (the enable that
/// materialised it already validated it; `noo addons show` reports it).
pub fn bundle_systems(root: &Path, on: &dyn Fn(&str) -> bool) -> BTreeMap<String, crate::commands::systems::SystemEntry> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(root.join(super::pins::ADDONS_DIR)) else { return out };
    for e in rd.flatten() {
        let Some(addon) = e.file_name().to_str().map(str::to_string) else { continue };
        if !super::trust::name_ok(&addon) || !on(&addon) {
            continue;
        }
        if let Ok(Declared { system: Some(s), .. }) = materialised(root, &addon) {
            out.insert(system_id(&addon), system_entry(&addon, &s));
        }
    }
    out
}

/// A validated system as a `systems:` entry (no flag: the add-on switch and
/// the verified lock are the gate).
pub fn system_entry(addon: &str, s: &System) -> crate::commands::systems::SystemEntry {
    let (password_env, ddl_password_env) = password_envs(addon);
    crate::commands::systems::SystemEntry {
        role: s.role.clone(),
        ddl_role: s.ddl_role.clone(),
        schema: s.schema.clone(),
        enabled_when: None,
        password_env,
        ddl_password_env,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ADDON: &str = "example-addon";

    fn system() -> Value {
        json!({"schema": "example_addon", "role": "noo_example_addon", "ddl_role": "noo_example_addon_ddl", "extensions": ["vector"]})
    }

    fn workload() -> Value {
        json!({"name": "worker", "container": "noo-example-addon-worker", "gpu": true, "need_mb": 11264,
               "drain": {"route": "drain", "timeout_secs": 120}})
    }

    fn routes() -> Vec<u8> {
        json!({"version": 1, "addon": ADDON, "routes": [
            {"name": "drain", "method": "POST", "path": "/drain", "internal": true},
            {"name": "status", "method": "GET", "path": "/api/example-addon/status"}
        ]})
        .to_string()
        .into_bytes()
    }

    fn wl(ws: Vec<Value>) -> Vec<u8> {
        json!({"workloads": ws}).to_string().into_bytes()
    }

    #[test]
    fn the_documented_shapes_parse() {
        let s = parse_system(ADDON, system().to_string().as_bytes()).unwrap();
        assert_eq!(s.schema, "example_addon");
        assert_eq!(password_envs(ADDON), ("NOO_EXAMPLE_ADDON_DB_PASSWORD".into(), "NOO_EXAMPLE_ADDON_DDL_PASSWORD".into()));
        let w = parse_workloads(ADDON, &wl(vec![workload()]), Some(&routes())).unwrap();
        assert_eq!(w[0], Workload {
            name: "worker".into(), container: "noo-example-addon-worker".into(), gpu: true, need_mb: 11264,
            drain_route: "drain".into(), drain_timeout_secs: 120,
        });
    }

    #[test]
    fn a_system_with_any_other_name_is_refused() {
        for (field, bad) in [("schema", "public"), ("role", "noo_app"), ("ddl_role", "noo_example_addon"), ("schema", "example-addon")] {
            let mut v = system();
            v[field] = json!(bad);
            let e = parse_system(ADDON, v.to_string().as_bytes()).unwrap_err();
            assert!(e.contains(&format!("`{field}`")) && e.contains("must be"), "{e}");
        }
        let mut v = system();
        v["password_env"] = json!("X");
        assert!(parse_system(ADDON, v.to_string().as_bytes()).unwrap_err().contains("unknown field"));
        let mut v = system();
        v["extensions"] = json!(["plpython3u"]);
        assert!(parse_system(ADDON, v.to_string().as_bytes()).unwrap_err().contains("not one a bundle may ask for"));
        let v = json!({"schema": "app", "role": "noo_app", "ddl_role": "noo_app_ddl"});
        assert!(parse_system("app", v.to_string().as_bytes()).unwrap_err().contains("may not declare a database"));
    }

    #[test]
    fn workload_rules_refuse_with_their_reason() {
        type Mutate = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(Mutate, &str)> = vec![
            (Box::new(|w| w["container"] = json!("noo-other-worker")), "must be `noo-example-addon-<suffix>`"),
            (Box::new(|w| w["need_mb"] = json!(0)), "need_mb 0"),
            (Box::new(|w| w["need_mb"] = json!(262_145)), "need_mb 262145"),
            (Box::new(|w| w["drain"]["timeout_secs"] = json!(0)), "drain.timeout_secs"),
            (Box::new(|w| w["drain"]["route"] = json!("status")), "is a public route"),
            (Box::new(|w| w["drain"]["route"] = json!("nope")), "is not a route"),
            (Box::new(|w| w["image"] = json!("x")), "unknown field `image`"),
            (Box::new(|w| { w.as_object_mut().unwrap().remove("gpu"); }), "`gpu` is required"),
            (Box::new(|w| w["name"] = json!("Bad")), "workload name"),
        ];
        for (edit, needle) in cases {
            let mut w = workload();
            edit(&mut w);
            let e = parse_workloads(ADDON, &wl(vec![w]), Some(&routes())).unwrap_err();
            assert!(e.contains(needle), "{e:?} should mention {needle:?}");
        }
        let mut twin = workload();
        twin["container"] = json!("noo-example-addon-twin");
        assert!(parse_workloads(ADDON, &wl(vec![workload(), twin]), None).unwrap_err().contains("declared twice"));
    }

    #[test]
    fn without_routes_in_the_bundle_the_drain_route_is_left_to_the_gateway() {
        let mut w = workload();
        w["drain"]["route"] = json!("anything");
        assert!(parse_workloads(ADDON, &wl(vec![w]), None).is_ok());
    }

    #[test]
    fn check_bundle_reads_only_the_declaration_files() {
        let files = BTreeMap::from([
            ("docker-compose.yml".to_string(), b"services: {}\n".to_vec()),
            (SYSTEM_FILE.to_string(), system().to_string().into_bytes()),
            (WORKLOADS_FILE.to_string(), wl(vec![workload()])),
            (ROUTES_FILE.to_string(), routes()),
        ]);
        let d = check_bundle(ADDON, &files).unwrap();
        assert!(d.system.is_some());
        assert_eq!(d.workloads.len(), 1);
        let only_overlay = BTreeMap::from([("docker-compose.yml".to_string(), b"services: {}\n".to_vec())]);
        assert_eq!(check_bundle(ADDON, &only_overlay).unwrap(), Declared::default());
        let mut bad = files.clone();
        bad.insert(SYSTEM_FILE.into(), br#"{"schema":"x","role":"y","ddl_role":"z"}"#.to_vec());
        assert!(check_bundle(ADDON, &bad).is_err());
    }

    #[test]
    fn bundle_systems_lists_only_switched_on_addons_with_a_valid_system() {
        let root = std::env::temp_dir().join(format!("noo-decls-bundle-systems-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (addon, text) in [
            (ADDON, system().to_string()),
            ("other-addon", json!({"schema": "other_addon", "role": "noo_other_addon", "ddl_role": "noo_other_addon_ddl"}).to_string()),
            ("broken-addon", "{".to_string()),
        ] {
            let d = root.join("addons").join(addon);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(SYSTEM_FILE), text).unwrap();
        }
        let got = bundle_systems(&root, &|a| a != "other-addon");
        assert_eq!(got.keys().cloned().collect::<Vec<_>>(), vec!["example_addon".to_string()]);
        assert_eq!(got["example_addon"].password_env, "NOO_EXAMPLE_ADDON_DB_PASSWORD");
        assert_eq!(got["example_addon"].enabled_when, None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
