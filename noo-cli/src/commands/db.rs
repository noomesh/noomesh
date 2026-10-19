// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo db` — schema migration state and control, without Python.
//!
//! Ownership: the GATEWAY applies the mesh schema with its
//! native sqlx runner at boot (`gateway-rust/src/mesh_migrate.rs`, stamping
//! `alembic_version_mesh`); TRELLION applies the memory schema with alembic
//! at ITS container start; evolve (pro) likewise. `current`/`history` read
//! the gateway's `/api/db/migrations`; `upgrade` asks the gateway to run the
//! mesh runner now and re-runs trellion's entrypoint migration step for
//! memory. Until 0.3.34 these four docker-exec'd `python -m noomesh.cli db`
//! into the gateway container — which has carried no Python since the mesh
//! chain went native — so every one of them failed on every install.
use std::process::Command;

use crate::{Globals, Unhandled};
use crate::ui::{self, Col, Glyph};

fn migrations(g: &Globals) -> serde_json::Value {
    crate::http::get_json(g, "/api/db/migrations", true, 10)
}

/// One `system  stamp  owner` table row; a missing stamp is a WARN row.
fn stamp_row(name: &str, v: &serde_json::Value) -> Vec<String> {
    let (glyph, cur) = match v["current"].as_str().filter(|s| !s.is_empty()) {
        Some(c) => (Glyph::Ok, c.to_string()),
        None => (Glyph::Warn, "no stamp".to_string()),
    };
    vec![
        ui::glyph_cell(glyph),
        name.to_string(),
        cur,
        v["owner"].as_str().unwrap_or("").to_string(),
    ]
}

const STAMP_COLS: [Col; 4] = [Col::left(""), Col::left("system"), Col::left("stamp"), Col::left("owner")];

/// `noo db current` — the stamp each system's version table holds.
pub fn db_current(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let v = migrations(g);
    if g.json {
        println!("{v}");
        return Ok(0);
    }
    println!("{}", ui::header("migrations", None));
    println!("{}", ui::section("stamps"));
    let rows = vec![
        stamp_row("mesh", &v["mesh"]),
        stamp_row("memory", &v["memory"]),
        stamp_row("evolve", &v["evolve"]),
    ];
    print!("{}", ui::table(&STAMP_COLS, &rows));
    let pending = v["mesh"]["pending"].as_array().map(|a| a.len()).unwrap_or(0);
    if pending > 0 {
        println!();
        println!("{}", ui::status_line(Glyph::Warn, &format!("mesh: {pending} pending")));
        println!("{}", ui::hint("noo db upgrade"));
    }
    if let Some(e) = v["mesh"]["plan_error"].as_str() {
        println!("{}", ui::status_line(Glyph::Err, &format!("mesh plan error: {e}")));
    }
    Ok(0)
}

/// `noo db history` — the mesh runner's ported chain with applied/pending
/// markers, plus the other systems' stamps.
pub fn db_history(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let v = migrations(g);
    if g.json {
        println!("{v}");
        return Ok(0);
    }
    let cur = v["mesh"]["current"].as_str().unwrap_or("");
    println!(
        "{}",
        ui::header(
            "mesh migrations",
            Some(&format!(
                "native runner · engine {} · {} ported · current {}",
                v["mesh"]["engine"].as_str().unwrap_or("?"),
                v["mesh"]["ported"].as_u64().unwrap_or(0),
                if cur.is_empty() { ui::dash() } else { cur }
            )),
        )
    );
    println!("{}", ui::section("chain"));
    let rows: Vec<Vec<String>> = v["mesh"]["chain"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| {
            let rev = m["revision"].as_str().unwrap_or("?");
            let (glyph, mark) = if m["pending"].as_bool().unwrap_or(false) {
                (Glyph::Warn, "pending")
            } else if rev == cur {
                (Glyph::Ok, "current")
            } else {
                (Glyph::Ok, "applied")
            };
            vec![ui::glyph_cell(glyph), rev.to_string(), ui::state(mark)]
        })
        .collect();
    print!("{}", ui::table(&[Col::left(""), Col::left("revision"), Col::left("state")], &rows));
    println!("{}", ui::section("other systems"));
    let rows = vec![stamp_row("memory", &v["memory"]), stamp_row("evolve", &v["evolve"])];
    print!("{}", ui::table(&STAMP_COLS, &rows));
    println!(
        "  {}",
        ui::muted(&format!(
            "full alembic history: docker exec {} alembic history",
            crate::envfile::container("trellion")
        ))
    );
    Ok(0)
}

/// `noo db upgrade` — mesh via the gateway's runner (admin), memory via
/// trellion's own entrypoint migration step. No revision argument: the
/// runner applies the whole pending chain, the way it does at boot.
pub fn db_upgrade(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    match args {
        [] => {}
        [rev] if rev == "heads" || rev == "head" => {}
        [rev] => {
            ui::failed(
                &format!(
                    "partial upgrades (to `{rev}`) are not supported — the native runner \
                     applies the whole pending chain, exactly as the gateway does at boot"
                ),
                Some("noo db upgrade"),
            );
            return Ok(2);
        }
        _ => return Err(Unhandled),
    }
    // Two phases (guide §5 Rhythm): Mesh (gateway runner) → Memory
    // (trellion's entrypoint). Both report as a kv row so the two chains
    // read alike.
    if !g.json { println!("{}", ui::phase("Mesh")); ui::step("applying the pending mesh chain via the gateway runner"); }
    let v = crate::http::post_json(g, "/api/db/migrations/apply", &serde_json::json!({}), true, 300);
    if g.json {
        println!("{v}");
    } else {
        let before = v["mesh"]["before"].as_str().unwrap_or(ui::dash());
        let after = v["mesh"]["after"].as_str().unwrap_or(ui::dash());
        let applied = v["mesh"]["applied"].as_u64();
        let mut rows: Vec<(&str, String)> = vec![
            ("before", before.to_string()),
            ("after", after.to_string()),
        ];
        if let Some(n) = applied {
            rows.push(("applied", n.to_string()));
        }
        print!("{}", ui::kv(&rows));
        if before == after {
            ui::done(&format!("mesh up to date at {after}"));
        } else {
            ui::done(&format!("mesh migrated {before} → {after}"));
        }
    }
    // Memory: trellion's entrypoint runs the memory env when told so; `true`
    // as the exec target makes it exit cleanly after migrating.
    let trellion = crate::envfile::container("trellion");
    if !g.json { println!("{}", ui::phase("Memory")); ui::step(&format!("running the memory chain inside {trellion}")); }
    if g.verbose {
        eprintln!("docker exec -e NOO_MIGRATIONS_ENVS=memory {trellion} python /opt/entrypoint.py true");
    }
    // Capture, not inherit: the entrypoint's log lines are framed on
    // failure (or -v), never interleaved bare (guide §5).
    let out = Command::new("docker")
        .args(["exec", "-e", "NOO_MIGRATIONS_ENVS=memory", &trellion, "python", "/opt/entrypoint.py", "true"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            if !g.json {
                if g.verbose {
                    ui::capture("entrypoint output", &String::from_utf8_lossy(&o.stdout));
                    ui::capture("entrypoint stderr", &String::from_utf8_lossy(&o.stderr));
                }
                ui::done(&format!("memory migrated by {trellion}"));
                ui::close_done("both chains at head");
                ui::guide(&[
                    ("noo db current", "shows the revision each chain is stamped at"),
                    ("noo db status", "schema and plane checks"),
                ]);
            }
            Ok(0)
        }
        Ok(o) => {
            let code = o.status.code().unwrap_or(1);
            if !g.json {
                // Tail only: the last lines carry the error.
                let err = String::from_utf8_lossy(&o.stderr);
                let tail: Vec<&str> = err.lines().rev().take(12).collect::<Vec<_>>().into_iter().rev().collect();
                ui::capture("entrypoint stderr (tail)", &tail.join("\n"));
            }
            ui::close_failed(&format!("memory migration step in {trellion} exited {code}"), Some("noo stack logs trellion"));
            Ok(1)
        }
        Err(e) => {
            ui::close_warned(&format!("could not exec into {trellion} ({e}) — memory migrations apply when that container restarts"));
            ui::guide(&[
                ("noo stack restart trellion", "restarts the memory container; its entrypoint applies pending memory migrations"),
                ("noo db current", "afterwards: confirm the memory chain moved"),
            ]);
            Ok(0)
        }
    }
}

/// `noo db stamp` — refused: stamps belong to the runners.
pub fn db_stamp(_g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if args.len() > 1 {
        return Err(Unhandled);
    }
    ui::failed(
        "stamp refused — version stamps are owned by the runners (mesh: the gateway's native \
         runner writes alembic_version_mesh; memory: trellion's alembic); forcing one by hand \
         is the failure mode the native runner exists to prevent",
        None,
    );
    eprintln!("{}", ui::note("if you really need it, write the stamp by hand:"));
    eprintln!(
        "{}",
        ui::hint(&format!(
            "docker exec -i {} psql -U noo -d {} -c \"UPDATE mesh.alembic_version_mesh SET version_num = '<rev>'\"",
            crate::envfile::container("postgres"),
            resolve_db(&crate::envfile::container("postgres"))
        ))
    );
    Ok(2)
}

// ── noo db status ────────────────────────────────────────────────────────

/// First non-empty `POSTGRES_DB` in a `.env`-style text (last assignment wins).
fn dotenv_db(text: &str) -> Option<String> {
    text.lines().rev().find_map(|l| {
        let l = l.trim();
        let l = l.strip_prefix("export ").unwrap_or(l);
        let v = l.strip_prefix("POSTGRES_DB=")?.trim().trim_matches('"').trim_matches('\'');
        (!v.is_empty()).then(|| v.to_string())
    })
}

/// `POSTGRES_DB=<name>` out of `docker inspect --format '{{range .Config.Env}}…'` output.
fn inspect_db(env_lines: &str) -> Option<String> {
    env_lines.lines().find_map(|l| {
        let v = l.trim().strip_prefix("POSTGRES_DB=")?.trim();
        (!v.is_empty()).then(|| v.to_string())
    })
}

/// Pure resolution order: process env, `.env`, the container's env, `noo`
/// (the pre-0.6 database name). Fresh 0.6.x installs use `noomesh`.
fn pick_db(process: Option<String>, dotenv: Option<&str>, inspected: Option<String>) -> String {
    process
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| dotenv.and_then(dotenv_db))
        .or(inspected)
        .unwrap_or_else(|| "noo".to_string())
}

/// The database this install's postgres container serves, resolved once per command.
fn resolve_db(container: &str) -> String {
    let process = std::env::var("POSTGRES_DB").ok();
    let dotenv = std::fs::read_to_string(crate::envfile::repo_root().join(".env")).ok();
    let inspected = if process.as_deref().map(|v| !v.trim().is_empty()).unwrap_or(false)
        || dotenv.as_deref().and_then(dotenv_db).is_some()
    {
        None
    } else {
        Command::new("docker")
            .args(["inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| inspect_db(&String::from_utf8_lossy(&o.stdout)))
    };
    pick_db(process, dotenv.as_deref(), inspected)
}

fn psql(container: &str, db: &str, sql: &str) -> Option<String> {
    let out = std::process::Command::new("docker")
        .args(["exec", "-i", container, "psql", "-U", "noo", "-d", db, "-tAc", sql])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The mesh chain's stamp straight from Postgres (`docker exec … psql`), for
/// callers that must know it while the gateway may be down - the stack
/// rollback preflight. Per-system schema first, `public` second, like
/// `noo db status`. `None` = postgres could not be asked or holds no stamp.
pub(crate) fn mesh_stamp_from_postgres() -> Option<String> {
    let pg = std::env::var("PGCONTAINER").unwrap_or_else(|_| crate::envfile::container("postgres"));
    let db = resolve_db(&pg);
    ["mesh.alembic_version_mesh", "public.alembic_version_mesh"]
        .iter()
        .find_map(|t| psql(&pg, &db, &format!("SELECT version_num FROM {t}")).filter(|s| !s.is_empty()))
}

/// One migration chain's stamp, as read from Postgres.
struct ChainStamp {
    system: &'static str,
    /// "ok", "warn" or "err".
    state: &'static str,
    stamp: String,
    layout: String,
}

/// Resolve a chain's stamp: its per-system schema first (fresh installs),
/// `public` second (legacy). evolve is genuinely absent on OSS installs (a
/// warning); any other chain missing is an error.
fn chain_stamp(system: &'static str, fresh: Option<String>, legacy: Option<String>, schema: &str) -> ChainStamp {
    match (fresh, legacy) {
        (Some(v), _) if !v.is_empty() => ChainStamp { system, state: "ok", stamp: v, layout: format!("schema {schema}") },
        (_, Some(v)) if !v.is_empty() => ChainStamp { system, state: "ok", stamp: v, layout: "public (legacy layout)".into() },
        _ if system == "evolve" => ChainStamp {
            system,
            state: "warn",
            stamp: "absent".into(),
            layout: "pro not enabled or not yet migrated".into(),
        },
        _ => ChainStamp {
            system,
            state: "err",
            stamp: "no stamp found".into(),
            layout: "investigate before migrating anything".into(),
        },
    }
}

fn status_json(gateway: &str, gateway_bad: bool, stamps: &[ChainStamp]) -> serde_json::Value {
    serde_json::json!({
        "gateway": {"status": gateway, "ok": !gateway_bad},
        "stamps": stamps.iter().map(|r| serde_json::json!({
            "system": r.system, "state": r.state, "stamp": r.stamp, "layout": r.layout,
        })).collect::<Vec<_>>(),
    })
}

/// `noo db status` — every migration stamp, both layouts, plus the gateway's
/// state, in one command.
///
/// Exists because the cutover-readiness check was three raw docker/psql
/// incantations pasted from a runbook — the exact operational surface this
/// CLI is for. Layout-aware: each version table is looked for in its
/// per-system schema FIRST (fresh installs) and `public` second (legacy),
/// which is the same resolution order the runners themselves use.
pub fn db_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let pg = std::env::var("PGCONTAINER").unwrap_or_else(|_| crate::envfile::container("postgres"));

    let dbname = resolve_db(&pg);

    let gw = std::process::Command::new("docker")
        .args(["ps", "--filter", "name=noo-gateway", "--format", "{{.Status}}"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "NOT RUNNING".into());
    let gw_bad = !gw.contains("healthy") || gw.contains("Restarting");
    let chains = [
        ("mesh", "alembic_version_mesh", "mesh"),
        ("trellion", "alembic_version_memory", "trellion"),
        ("evolve", "alembic_version_evolve", "evolve"),
    ];
    let mut fail = gw_bad;
    let mut stamps: Vec<ChainStamp> = Vec::new();
    for (name, table, schema) in chains {
        let fresh = psql(&pg, &dbname, &format!("SELECT version_num FROM {schema}.{table}"));
        let legacy = psql(&pg, &dbname, &format!("SELECT version_num FROM public.{table}"));
        let row = chain_stamp(name, fresh, legacy, schema);
        if row.state == "err" {
            fail = true;
        }
        stamps.push(row);
    }
    if g.json {
        println!("{}", status_json(&gw, gw_bad, &stamps));
        return Ok(if fail { 1 } else { 0 });
    }
    println!("{}", ui::header("db status", None));
    println!(
        "{}",
        ui::status_line(
            if gw_bad { Glyph::Err } else { Glyph::Ok },
            &format!("gateway {}  {}", if gw_bad { ui::state("degraded") } else { ui::state("running") }, ui::muted(&gw))
        )
    );
    println!("{}", ui::section("stamps"));
    let rows: Vec<Vec<String>> = stamps
        .iter()
        .map(|r| {
            let glyph = match r.state {
                "ok" => Glyph::Ok,
                "warn" => Glyph::Warn,
                _ => Glyph::Err,
            };
            vec![ui::glyph_cell(glyph), r.system.to_string(), r.stamp.clone(), r.layout.clone()]
        })
        .collect();
    print!("{}", ui::table(&[Col::left(""), Col::left("system"), Col::left("stamp"), Col::left("layout")], &rows));
    Ok(if fail { 1 } else { 0 })
}

/// `noo db verify-plane [DB]` — the privilege-plane invariants, as a command.
///
/// Thin wrapper over `scripts/verify-privilege-plane.sh`, which is the single
/// home of the invariants (CI runs the same file — a Rust reimplementation
/// here would be a second copy that drifts). Requires a repo checkout, like
/// every other script-backed operation; the error says so instead of a bare
/// file-not-found.
pub fn db_verify_plane(_g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let db = match args {
        [] => resolve_db(&crate::envfile::container("postgres")),
        [d] if !d.starts_with('-') => d.clone(),
        _ => return Err(Unhandled),
    };
    let script = crate::envfile::repo_root().join("scripts/verify-privilege-plane.sh");
    if !script.exists() {
        ui::failed(
            &format!(
                "scripts/verify-privilege-plane.sh not found under {} — this command needs \
                 the repo checkout (the invariants live in one file so CI and this command \
                 cannot drift apart)",
                crate::envfile::repo_root().display()
            ),
            None,
        );
        return Ok(1);
    }
    let status = std::process::Command::new("bash")
        .arg(script)
        .arg(&db)
        .status()
        .map_err(|_| Unhandled)?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn db_name_resolves_env_then_dotenv_then_container_then_noo() {
        assert_eq!(pick_db(Some("noomesh".into()), Some("POSTGRES_DB=other\n"), Some("x".into())), "noomesh");
        assert_eq!(pick_db(None, Some("A=1\nexport POSTGRES_DB=\"noomesh\"\n"), Some("x".into())), "noomesh");
        assert_eq!(pick_db(Some("  ".into()), None, Some("noomesh".into())), "noomesh");
        assert_eq!(pick_db(None, Some("POSTGRES_DB=\n"), None), "noo");
        assert_eq!(pick_db(None, None, None), "noo");
        assert_eq!(inspect_db("PATH=/bin\nPOSTGRES_DB=noo\nPOSTGRES_USER=noo\n").as_deref(), Some("noo"));
        assert_eq!(inspect_db("PATH=/bin\n"), None);
    }

    #[test]
    fn stamp_rows_resolve_fresh_then_legacy_and_flag_missing() {
        let r = chain_stamp("mesh", Some("abc".into()), Some("old".into()), "mesh");
        assert_eq!((r.state, r.stamp.as_str(), r.layout.as_str()), ("ok", "abc", "schema mesh"));
        let r = chain_stamp("mesh", None, Some("old".into()), "mesh");
        assert_eq!(r.layout, "public (legacy layout)");
        assert_eq!(chain_stamp("trellion", None, None, "trellion").state, "err");
        assert_eq!(chain_stamp("evolve", None, Some(String::new()), "evolve").state, "warn");
    }

    #[test]
    fn status_json_carries_gateway_and_every_stamp() {
        let rows = vec![chain_stamp("mesh", Some("abc".into()), None, "mesh"), chain_stamp("evolve", None, None, "evolve")];
        let v = status_json("Up (healthy)", false, &rows);
        assert_eq!(v["gateway"]["ok"], true);
        assert_eq!(v["stamps"][0]["stamp"], "abc");
        assert_eq!(v["stamps"][1]["state"], "warn");
    }
}
