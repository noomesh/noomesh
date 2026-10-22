// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! What an add-on's signed bundle declares beyond its routes: its database
//! system (`system.json`). noomesh-internal i163 part E.
//!
//! ## Where the files come from
//!
//! Both are bundle files: listed by name and sha256 in the add-on's signed
//! `noo-addon-lock/2` bundle (`files`), so one signature covers them, exactly
//! like the compose overlay. `noo addons enable | upgrade` verifies them and
//! materialises them under `<install root>/addons/<name>/`; the launcher then
//! copies them, for add-ons that are switched on AND whose lock it verified
//! this start (`noo addons launch-pins` names each declaration file of a
//! verified lock), into two directories the gateway mounts read-only:
//!
//! | file | gateway path |
//! |---|---|
//! | `system.json` | [`SYSTEMS_DIR`]`/<addon>/system.json` |
//! | `workloads.json` | [`WORKLOADS_DIR`]`/<addon>/workloads.json` (read by `addon_workloads`) |
//!
//! The gateway still decides: [`crate::addon_registry`] reads `system.json`
//! only for an add-on it registers (enabled + verified + manifest valid),
//! validates it here with the same rules the CLI applied, and refuses the
//! WHOLE add-on when it is invalid (never a partial surface, the manifest
//! rule).
//!
//! ## `system.json`
//!
//! ```json
//! { "schema": "example_addon", "role": "noo_example_addon",
//!   "ddl_role": "noo_example_addon_ddl", "extensions": ["pg_trgm"] }
//! ```
//!
//! The names are not free: with `<id>` = the add-on name with `-` as `_`,
//! `schema` must be `<id>`, `role` `noo_<id>`, `ddl_role` `noo_<id>_ddl`.
//! Anything else refuses the fragment. A fixed derivation means a bundle can
//! never name a core schema or role (and [`RESERVED_IDS`] refuses the add-on
//! names whose derivation would), and the password variables need no
//! declaration either: `NOO_<ID>_DB_PASSWORD` and `NOO_<ID>_DDL_PASSWORD`
//! ([`password_envs`]), minted by `noo addons enable` into the store and
//! delivered through the ONE systems-secrets file
//! (`system_provision::SYSTEMS_SECRETS`). `extensions` are limited to
//! [`ALLOWED_EXTENSIONS`]: the broker installs them as superuser.
//!
//! ## `workloads.json` is not parsed here
//!
//! The launcher delivers an add-on's signed `workloads.json` the same way, to
//! [`WORKLOADS_DIR`]`/<addon>/workloads.json`, under the same rule (switched
//! on + lock verified + the file listed in the signed lock). The gateway's
//! ONE workload parser is `addon_workloads` (noomesh-internal i163 B, the
//! reservations change); it reads that directory. This module owns only the
//! database declaration.

use std::collections::BTreeSet;
use std::path::Path as FsPath;

use serde::{Deserialize, Serialize};

use crate::config::SystemConfig;

/// Where the launcher delivers `system.json`: `<SYSTEMS_DIR>/<addon>/system.json`.
pub const SYSTEMS_DIR: &str = "/opt/noo/addon-systems";
/// Where the launcher delivers the signed `workloads.json`:
/// `<WORKLOADS_DIR>/<addon>/workloads.json`. Parsed by `addon_workloads`
/// (i163 B), not here; that module points its read at this directory when
/// the two changes meet.
#[allow(dead_code)]
pub const WORKLOADS_DIR: &str = "/opt/noo/addon-workloads";
pub const SYSTEM_FILE: &str = "system.json";

/// Largest declaration file read (each).
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Extensions a bundle may ask the broker for. The broker installs them as
/// superuser (`CREATE EXTENSION`), so this is an allowlist of data-type and
/// index extensions, never a procedural language or a foreign-data wrapper.
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

/// Add-on ids (name with `-` as `_`) whose derived schema or roles would be
/// core's: `noo_app` is the gateway's runtime role, `public` and `mesh` are
/// core schemas, and so on. An add-on with one of these names may still
/// exist; it may not declare a database.
pub const RESERVED_IDS: &[&str] = &[
    "app", "worker", "gateway", "admin", "readonly", "replication", "backup", "monitor",
    "public", "mesh", "noo", "information_schema",
];

/// `system.json` as delivered.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddonSystem {
    pub schema: String,
    pub role: String,
    pub ddl_role: String,
    #[serde(default)]
    pub extensions: Vec<String>,
}

/// The add-on's database id: its name with `-` as `_` (`example-addon` →
/// `example_addon`).
pub fn system_id(addon: &str) -> String {
    addon.replace('-', "_")
}

/// The two role-password variables of an add-on's system, derived, never
/// declared: `(NOO_<ID>_DB_PASSWORD, NOO_<ID>_DDL_PASSWORD)`.
pub fn password_envs(addon: &str) -> (String, String) {
    let up = system_id(addon).to_ascii_uppercase();
    (format!("NOO_{up}_DB_PASSWORD"), format!("NOO_{up}_DDL_PASSWORD"))
}

fn sql_ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Validate a parsed `system.json` for `addon`. Pure.
pub fn validate_system(addon: &str, s: &AddonSystem) -> Result<(), String> {
    if !crate::addon_registry::name_ok(addon) {
        return Err(format!("{addon:?} is not a valid add-on name ({})", crate::addon_registry::NAME_RULE));
    }
    let id = system_id(addon);
    if RESERVED_IDS.contains(&id.as_str()) || id.starts_with("pg_") {
        return Err(format!(
            "add-on {addon:?} may not declare a database: its schema and roles would be core's ({id})"
        ));
    }
    let want = [("schema", &s.schema, id.clone()), ("role", &s.role, format!("noo_{id}")), ("ddl_role", &s.ddl_role, format!("noo_{id}_ddl"))];
    for (field, got, expected) in want {
        if *got != expected {
            return Err(format!(
                "{SYSTEM_FILE} of add-on {addon:?}: `{field}` is {got:?}, and it must be {expected:?} \
                 (schema `<id>`, role `noo_<id>`, ddl_role `noo_<id>_ddl`, with <id> = the add-on name, `-` as `_`)"
            ));
        }
        if !sql_ident_ok(got) {
            return Err(format!("{SYSTEM_FILE} of add-on {addon:?}: `{field}` {got:?} is not a bare lowercase SQL identifier"));
        }
    }
    let mut seen = BTreeSet::new();
    for ext in &s.extensions {
        if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
            return Err(format!(
                "{SYSTEM_FILE} of add-on {addon:?}: extension {ext:?} is not one a bundle may ask for ({})",
                ALLOWED_EXTENSIONS.join(", ")
            ));
        }
        if !seen.insert(ext) {
            return Err(format!("{SYSTEM_FILE} of add-on {addon:?}: extension {ext:?} is listed twice"));
        }
    }
    Ok(())
}

/// Parse and validate `system.json` text. Pure.
pub fn parse_system(addon: &str, text: &str) -> Result<AddonSystem, String> {
    let s: AddonSystem =
        serde_json::from_str(text).map_err(|e| format!("{SYSTEM_FILE} of add-on {addon:?} is not valid: {e}"))?;
    validate_system(addon, &s)?;
    Ok(s)
}

/// The broker's view of a validated add-on system: exactly a `systems:`
/// entry, with the derived password variables and no flag (the registry is
/// the gate: only a registered add-on contributes one).
pub fn to_system_config(addon: &str, s: &AddonSystem) -> SystemConfig {
    let (password_env, ddl_password_env) = password_envs(addon);
    SystemConfig {
        role: s.role.clone(),
        ddl_role: s.ddl_role.clone(),
        schema: s.schema.clone(),
        enabled_when: None,
        password_env,
        ddl_password_env,
        extensions: s.extensions.clone(),
    }
}

/// `<dir>/<addon>/<file>` as text: `Ok(None)` when absent, `Err` when
/// unreadable, too large or not a regular file. `addon` is a checked name.
fn read_decl(dir: &FsPath, addon: &str, file: &str) -> Result<Option<String>, String> {
    let path = dir.join(addon).join(file);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("add-on {addon:?}: cannot read {}: {e}", path.display())),
    };
    if !meta.file_type().is_file() {
        return Err(format!("add-on {addon:?}: {} is not a regular file", path.display()));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("add-on {addon:?}: {} is larger than {MAX_FILE_BYTES} bytes", path.display()));
    }
    std::fs::read_to_string(&path)
        .map(Some)
        .map_err(|e| format!("add-on {addon:?}: cannot read {}: {e}", path.display()))
}

/// Read and validate a registered add-on's `system.json` from
/// `<systems_dir>/<addon>/`. `Ok(None)` when it declares none; `Err` is the
/// operator's sentence, and refuses the add-on.
pub fn read_system(systems_dir: &FsPath, addon: &str) -> Result<Option<AddonSystem>, String> {
    if !crate::addon_registry::name_ok(addon) {
        return Err(format!("{addon:?} is not a valid add-on name ({})", crate::addon_registry::NAME_RULE));
    }
    read_decl(systems_dir, addon, SYSTEM_FILE)
        .and_then(|t| t.map(|t| parse_system(addon, &t)).transpose())
        .map_err(|why| format!("{why}. None of its routes are mounted; fix the add-on's signed bundle"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const ADDON: &str = "example-addon";

    fn system_json() -> Value {
        json!({"schema": "example_addon", "role": "noo_example_addon", "ddl_role": "noo_example_addon_ddl", "extensions": ["pg_trgm"]})
    }

    #[test]
    fn the_documented_system_parses_and_becomes_a_systems_entry() {
        let s = parse_system(ADDON, &system_json().to_string()).expect("valid");
        let c = to_system_config(ADDON, &s);
        assert_eq!(c.schema, "example_addon");
        assert_eq!(c.role, "noo_example_addon");
        assert_eq!(c.ddl_role, "noo_example_addon_ddl");
        assert_eq!(c.password_env, "NOO_EXAMPLE_ADDON_DB_PASSWORD");
        assert_eq!(c.ddl_password_env, "NOO_EXAMPLE_ADDON_DDL_PASSWORD");
        assert_eq!(c.enabled_when, None, "the registry is the gate, never a flag");
        assert_eq!(c.extensions, vec!["pg_trgm".to_string()]);
    }

    #[test]
    fn extensions_default_to_none() {
        let mut v = system_json();
        v.as_object_mut().unwrap().remove("extensions");
        assert_eq!(parse_system(ADDON, &v.to_string()).unwrap().extensions, Vec::<String>::new());
    }

    #[test]
    fn every_name_that_is_not_the_derived_one_is_refused() {
        for (field, bad) in [
            ("schema", "public"),
            ("schema", "example-addon"),
            ("schema", "other_addon"),
            ("role", "noo_app"),
            ("role", "example_addon"),
            ("ddl_role", "noo_example_addon"),
            ("ddl_role", "noo"),
        ] {
            let mut v = system_json();
            v[field] = json!(bad);
            let e = parse_system(ADDON, &v.to_string()).expect_err(&format!("{field}={bad} must be refused"));
            assert!(e.contains(&format!("`{field}`")), "{e}");
            assert!(e.contains("must be"), "the refusal names the expected value: {e}");
        }
    }

    #[test]
    fn a_reserved_addon_name_cannot_declare_a_database() {
        for addon in ["app", "public", "mesh", "pg_stat", "noo"] {
            let id = system_id(addon);
            let v = json!({"schema": id, "role": format!("noo_{id}"), "ddl_role": format!("noo_{id}_ddl")});
            let e = parse_system(addon, &v.to_string()).expect_err(addon);
            assert!(e.contains("may not declare a database"), "{e}");
        }
    }

    #[test]
    fn unknown_keys_and_unlisted_or_repeated_extensions_are_refused() {
        let mut v = system_json();
        v["password_env"] = json!("NOO_SOMETHING");
        assert!(parse_system(ADDON, &v.to_string()).is_err(), "no field may name a credential");
        for exts in [json!(["plpython3u"]), json!(["postgres_fdw"]), json!(["pg_trgm", "pg_trgm"]), json!(["PG_TRGM"])] {
            let mut v = system_json();
            v["extensions"] = exts.clone();
            assert!(parse_system(ADDON, &v.to_string()).is_err(), "{exts}");
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("noo-addon-decls-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn read_system_finds_the_file_or_nothing_and_refuses_a_bad_one() {
        let sys = scratch("read").join("systems");
        assert_eq!(read_system(&sys, ADDON).unwrap(), None, "absent is nothing declared");
        std::fs::create_dir_all(sys.join(ADDON)).unwrap();
        std::fs::write(sys.join(ADDON).join(SYSTEM_FILE), system_json().to_string()).unwrap();
        assert_eq!(read_system(&sys, ADDON).unwrap().map(|s| s.schema), Some("example_addon".to_string()));
        std::fs::write(sys.join(ADDON).join(SYSTEM_FILE), r#"{"schema":"public","role":"noo_app","ddl_role":"noo"}"#).unwrap();
        assert!(read_system(&sys, ADDON).unwrap_err().contains("None of its routes are mounted"));
        std::fs::write(sys.join(ADDON).join(SYSTEM_FILE), "x".repeat(MAX_FILE_BYTES as usize + 1)).unwrap();
        assert!(read_system(&sys, ADDON).unwrap_err().contains("larger than"));
    }
}
