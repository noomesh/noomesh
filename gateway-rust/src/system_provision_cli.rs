// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo-gateway provision-system`: the broker, run on demand for ONE system.
//!
//! `noo addons enable <name> --provision-only` has to create an add-on's
//! schema and roles without composing or starting any of its services, and
//! without a gateway restart. The broker ([`crate::system_provision`]) runs
//! at boot, inside the gateway container, on the privileged migration
//! connection; this is the same code ([`provision_system`]) run once more by
//! `docker exec -i noo-gateway noo-gateway provision-system`, for the single
//! system the request names. There is no hand-written SQL here and no second
//! implementation: a divergence between the boot path and this one would be a
//! schema that differs depending on how it was created.
//!
//! ## Why this is not the API the broker's design refused
//!
//! The broker's module doc rules out an authenticated `POST /api/db/provision`:
//! compromise the gateway process, mint any role. This is not that. There is
//! no listener and no route; the only way in is `docker exec` into the running
//! container, which already means the docker group (root-equivalent on the
//! host). The request is not trusted for what it names either: the system is
//! validated by the gateway's own `addon_decls::parse_system` (schema `<id>`,
//! role `noo_<id>`, ddl role `noo_<id>_ddl`, extensions on the allowlist, core
//! ids reserved), so a request can never name a core schema or role, and only
//! the two derived password variables are accepted.
//!
//! ## The request (stdin) and the report (stdout)
//!
//! ```json
//! { "addon": "pai-voice",
//!   "system": { "schema": "pai_voice", "role": "noo_pai_voice", "ddl_role": "noo_pai_voice_ddl" },
//!   "secrets": { "NOO_PAI_VOICE_DB_PASSWORD": "...", "NOO_PAI_VOICE_DDL_PASSWORD": "..." } }
//! ```
//!
//! The passwords travel on stdin (never argv, never env, never a file) and
//! are used only to `CREATE ROLE` a role that does not exist yet; an existing
//! role is left entirely alone, exactly as at boot. The report on stdout names
//! what was created and never carries a secret; logs go to stderr.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use serde::Deserialize;

use crate::config::SystemConfig;
use crate::system_provision::{provision_system, Outcome};

/// Largest request read from stdin.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// The wire request. Deliberately NOT `Debug`: it holds passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    addon: String,
    system: serde_json::Value,
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

/// A validated request: the system the broker will provision, and the
/// passwords it may use. Not `Debug`, for the same reason.
pub(crate) struct Prepared {
    pub addon: String,
    /// The system's name (the add-on name, `-` as `_`).
    pub name: String,
    pub spec: SystemConfig,
    pub delivered: BTreeMap<String, String>,
}

/// Parse and validate a request. Pure.
pub(crate) fn prepare(text: &str) -> Result<Prepared, String> {
    let req: Request = serde_json::from_str(text).map_err(|e| format!("the request is not valid: {e}"))?;
    let system = crate::addon_decls::parse_system(&req.addon, &req.system.to_string())?;
    let spec = crate::addon_decls::to_system_config(&req.addon, &system);
    for key in req.secrets.keys() {
        if *key != spec.password_env && *key != spec.ddl_password_env {
            return Err(format!(
                "the request carries a secret named {key:?}; only {} and {} belong to this system",
                spec.password_env, spec.ddl_password_env
            ));
        }
    }
    Ok(Prepared {
        name: crate::addon_decls::system_id(&req.addon),
        addon: req.addon,
        spec,
        delivered: req.secrets,
    })
}

/// The stdout report for an outcome. Names only; no value.
pub(crate) fn report(p: &Prepared, outcome: &Outcome) -> serde_json::Value {
    match outcome {
        Outcome::Provisioned(done) => serde_json::json!({
            "ok": true,
            "addon": p.addon,
            "system": p.name,
            "schema": p.spec.schema,
            "role": p.spec.role,
            "ddl_role": p.spec.ddl_role,
            "extensions": p.spec.extensions,
            "roles_created": done.roles_created,
            "schema_created": done.schema_created,
        }),
        Outcome::MissingCredential { var, message } => serde_json::json!({
            "ok": false,
            "addon": p.addon,
            "missing": var,
            "error": message,
        }),
    }
}

fn failure(error: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "ok": false, "error": error.into() })
}

/// Entry point for `noo-gateway provision-system`. Returns the exit code; the
/// JSON report is the only thing written to stdout.
pub async fn main() -> i32 {
    let (code, doc) = run().await;
    println!("{doc}");
    code
}

async fn run() -> (i32, serde_json::Value) {
    let mut text = String::new();
    if let Err(e) = std::io::stdin().take(MAX_REQUEST_BYTES).read_to_string(&mut text) {
        return (2, failure(format!("could not read the request from stdin: {e}")));
    }
    let prepared = match prepare(&text) {
        Ok(p) => p,
        Err(e) => return (2, failure(e)),
    };

    // The running gateway's PKI staging (`/tmp/pki`) is its own: staging again
    // would delete it under a live process. Stage a private copy, publish it
    // to THIS process's environment (the migration DSN reads NOO_TLS_*), and
    // remove it when done.
    let staged = std::path::PathBuf::from(format!("/tmp/noo-provision-pki-{}", std::process::id()));
    match crate::startup_tasks::stage_pki(Path::new("/app/pki"), &staged) {
        Ok(paths) => {
            for (var, path) in [("NOO_TLS_CERT", &paths.cert), ("NOO_TLS_KEY", &paths.key), ("NOO_TLS_CA", &paths.ca)] {
                if let Some(p) = path {
                    std::env::set_var(var, p);
                }
            }
        }
        Err(e) => return (1, failure(format!("could not stage the cluster PKI: {e}"))),
    }
    let out = provision(&prepared).await;
    let _ = std::fs::remove_dir_all(&staged);
    out
}

async fn provision(p: &Prepared) -> (i32, serde_json::Value) {
    let Some(dsn) = crate::mesh_migrate::migration_dsn() else {
        return (
            1,
            failure("no migration DSN (NOO_MIGRATIONS_DSN/PAGEINDEX_DSN/PGVECTOR_URL/DATABASE_URL): is this the gateway container?"),
        );
    };
    let db = match sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await {
        Ok(db) => db,
        Err(e) => return (1, failure(format!("migration connection failed: {e}"))),
    };
    let outcome = provision_system(&db, &p.name, &p.spec, &p.delivered).await;
    db.close().await;
    match outcome {
        Ok(o @ Outcome::Provisioned(_)) => (0, report(p, &o)),
        Ok(o) => (1, report(p, &o)),
        Err(e) => (1, failure(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_provision::Provisioned;

    const PW: &str = "THROWAWAY-pw-aaaa1111";
    const DDL: &str = "THROWAWAY-ddl-bbbb2222";

    fn request(extra_secret: Option<(&str, &str)>) -> String {
        let mut secrets = serde_json::json!({
            "NOO_PAI_VOICE_DB_PASSWORD": PW,
            "NOO_PAI_VOICE_DDL_PASSWORD": DDL,
        });
        if let Some((k, v)) = extra_secret {
            secrets[k] = serde_json::json!(v);
        }
        serde_json::json!({
            "addon": "pai-voice",
            "system": { "schema": "pai_voice", "role": "noo_pai_voice", "ddl_role": "noo_pai_voice_ddl" },
            "secrets": secrets,
        })
        .to_string()
    }

    #[test]
    fn a_valid_request_becomes_exactly_that_addons_system() {
        let Ok(p) = prepare(&request(None)) else { panic!("a valid request must prepare") };
        assert_eq!(p.name, "pai_voice");
        assert_eq!((p.spec.schema.as_str(), p.spec.role.as_str(), p.spec.ddl_role.as_str()), ("pai_voice", "noo_pai_voice", "noo_pai_voice_ddl"));
        assert_eq!(p.spec.password_env, "NOO_PAI_VOICE_DB_PASSWORD");
        assert_eq!(p.spec.ddl_password_env, "NOO_PAI_VOICE_DDL_PASSWORD");
        assert_eq!(p.delivered.get("NOO_PAI_VOICE_DB_PASSWORD").map(String::as_str), Some(PW));
        assert!(p.spec.enabled_when.is_none());
    }

    /// The gateway's own rules, not the caller's: a request cannot name a core
    /// schema or role, whatever the CLI sent.
    #[test]
    fn a_request_cannot_name_a_core_schema_or_role() {
        for (addon, schema, role, ddl) in [
            ("pai-voice", "mesh", "noo_pai_voice", "noo_pai_voice_ddl"),
            ("pai-voice", "pai_voice", "noo_app", "noo_pai_voice_ddl"),
            ("pai-voice", "pai_voice", "noo_pai_voice", "noo"),
            ("app", "app", "noo_app", "noo_app_ddl"),
            ("public", "public", "noo_public", "noo_public_ddl"),
        ] {
            let text = serde_json::json!({
                "addon": addon,
                "system": { "schema": schema, "role": role, "ddl_role": ddl },
                "secrets": {},
            })
            .to_string();
            assert!(prepare(&text).is_err(), "{addon}/{schema}/{role}/{ddl} must be refused");
        }
    }

    #[test]
    fn only_the_two_derived_password_variables_are_accepted() {
        match prepare(&request(Some(("POSTGRES_PASSWORD", "x")))) {
            Ok(_) => panic!("a foreign secret must be refused"),
            Err(e) => {
                assert!(e.contains("POSTGRES_PASSWORD"), "{e}");
                assert!(!e.contains(PW) && !e.contains(DDL), "an error must not carry a value: {e}");
            }
        }
    }

    #[test]
    fn unknown_fields_and_garbage_are_refused() {
        assert!(prepare("not json").is_err());
        assert!(prepare(r#"{"addon":"pai-voice","system":{},"secrets":{},"sql":"drop schema mesh"}"#).is_err());
        assert!(prepare(r#"{"addon":"pai-voice","system":{"schema":"pai_voice"},"secrets":{}}"#).is_err());
    }

    #[test]
    fn the_report_names_what_was_made_and_carries_no_value() {
        let Ok(p) = prepare(&request(None)) else { panic!("prepare") };
        let done = report(
            &p,
            &Outcome::Provisioned(Provisioned {
                roles_created: vec!["noo_pai_voice_ddl".into(), "noo_pai_voice".into()],
                schema_created: true,
            }),
        );
        let text = done.to_string();
        assert_eq!(done["ok"], true);
        assert_eq!(done["schema"], "pai_voice");
        assert_eq!(done["schema_created"], true);
        assert_eq!(done["roles_created"], serde_json::json!(["noo_pai_voice_ddl", "noo_pai_voice"]));
        assert!(!text.contains(PW) && !text.contains(DDL), "{text}");

        let missing = report(
            &p,
            &Outcome::MissingCredential { var: "NOO_PAI_VOICE_DB_PASSWORD".into(), message: "not set".into() },
        );
        assert_eq!(missing["ok"], false);
        assert_eq!(missing["missing"], "NOO_PAI_VOICE_DB_PASSWORD");
    }

    /// The boot path and this one must be the SAME function, or the schema
    /// depends on how it was made.
    #[test]
    fn the_boot_reconcile_and_this_path_share_one_implementation() {
        let broker = include_str!("system_provision.rs");
        let broker = &broker[..broker.find("#[cfg(test)]").expect("tests mod")];
        let reconcile = &broker[broker.find("pub async fn reconcile(").expect("reconcile")..];
        assert!(reconcile.contains("provision_system(db, name, spec, &delivered)"), "reconcile must call provision_system");
        assert!(
            !reconcile.contains("ensure_schema(") && !reconcile.contains("ensure_role("),
            "reconcile must not carry its own copy of the steps"
        );
        let this = include_str!("system_provision_cli.rs");
        let this = &this[..this.find("#[cfg(test)]").expect("tests mod")];
        assert!(this.contains("provision_system(&db, &p.name, &p.spec, &p.delivered)"));
        assert!(!this.contains("sqlx::query"), "this path carries no SQL of its own");
    }
}
