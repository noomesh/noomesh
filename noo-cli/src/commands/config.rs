// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo config …` — gateway runtime config + local YAML view.
//!
//! `get`/`set`/`export-effective` talk to the gateway; `show` is fully LOCAL
//! (reads noomesh.yaml — no gateway, no auth), mirroring the Python CLI's
//! `load_config()` search path.

use crate::http::{get_json, get_json_opt, put_json};
use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui;
use std::path::PathBuf;

/// `noo config launch-render SECTION` — hidden internal command, called
/// only by the launcher scripts (`scripts/lib-config.sh`,
/// `scripts/lib-addons.sh`, `scripts/noomesh-start.sh`). Prints the same
/// text their embedded `python3` + PyYAML blocks used to, from
/// `<repo_root>/noomesh.yaml`, so `noo` — already on every host that runs
/// these scripts — is the ONE parser instead of a second, host-Python one.
/// See `commands::launch_render` for the byte-compatible renderers and
/// `docs/reference/config.md` for why the launcher reads
/// `addons:`/`compose_env:` at all.
pub fn config_launch_render(_g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    // The launcher passes the file it would have read itself: the CLI's own
    // repo_root() resolves to the state home (~/.noo) on a box that has one,
    // so a script running inside a dev checkout on that box would otherwise
    // render the wrong install's config.
    let (section, file) = match args {
        [s] => (s, None),
        [s, f] => (s, Some(std::path::Path::new(f.as_str()))),
        _ => return Err(Unhandled),
    };
    match section.as_str() {
        "compose-env" | "addons" | "override" | "systems" => Ok(crate::commands::launch_render::run(section, file)),
        _ => Err(Unhandled),
    }
}

/// `noo config launch-check bind-sources …` — hidden internal command, called
/// by `scripts/lib-bind-sources.sh` before every launcher `compose up`, with
/// `docker compose … config --format json` on stdin. Exit 0 = every bind
/// source exists and is the right type; 3 = refused (one line per source on
/// stderr). See `commands::bind_sources`.
///
/// `noo config launch-check system-credentials [<noomesh.yaml>]` — the same
/// lib's other pre-start refusal: an enabled system (evolve, trellion)
/// without its credentials in the launcher's environment, which the gateway
/// would crash-loop on. See `systems::launch_check`.
/// `noo config launch-check secrets-at-rest [<install-root>]` — the
/// launchers' refusal of a plaintext-`.env` install. See
/// `plaintext_env::launch_check`.
/// `noo config launch-check state-root [<install-root>]` — the launchers'
/// (and hostd boot restore's) refusal to start onto a closed encrypted state
/// volume (i10a). See `at_rest_volume::launch_check`.
pub fn config_launch_check(_g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    match args.split_first() {
        Some((what, rest)) if what == "bind-sources" => {
            crate::commands::bind_sources::run(rest).map_err(|_| Unhandled)
        }
        Some((what, rest)) if what == "system-credentials" => Ok(crate::commands::systems::launch_check(rest)),
        Some((what, rest)) if what == "secrets-at-rest" => Ok(crate::commands::plaintext_env::launch_check(rest)),
        Some((what, rest)) if what == "state-root" => Ok(crate::commands::at_rest_volume::launch_check(rest)),
        _ => Err(Unhandled),
    }
}

/// `noo config get [SECTION]` — runtime config from the gateway.
/// GET /api/config or /api/config/{section} (Rust settings routes).
pub fn config_get(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if args.first().map(String::as_str) == Some("cli") {
        let prefs = ui::read_prefs();
        if g.json {
            println!("{}", if prefs.is_null() { serde_json::json!({}) } else { prefs });
            return Ok(0);
        }
        println!("{}", ui::header("CLI preferences", Some(&ui::prefs_path().display().to_string())));
        match prefs.as_object() {
            Some(o) if !o.is_empty() => {
                let rows: Vec<(&str, String)> = o.iter().map(|(k, v)| (k.as_str(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect();
                print!("{}", ui::kv(&rows));
            }
            _ => println!("{}", ui::muted("no preferences set")),
        }
        ui::guide(&[("noo config set cli '{\"color\":\"never\"}'", "auto | always | never — persisted colour mode, below NO_COLOR/--color in precedence")]);
        return Ok(0);
    }
    let section = match args {
        [] => None,
        [s] if !s.starts_with('-') => Some(s.clone()),
        _ => return Err(Unhandled),
    };
    let path = match &section {
        Some(s) => format!("/api/config/{s}"),
        None => "/api/config".to_string(),
    };
    let body = get_json(g, &path, true, 10);
    if g.json {
        println!("{body}");
    } else {
        // Parity with the Python CLI: human mode prints the config as
        // (pretty) JSON — config sections are arbitrary nested objects.
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()));
    }
    Ok(0)
}

/// `noo config set SECTION UPDATES_JSON` — update a runtime config section.
/// PUT /api/config/{section} with the parsed JSON updates as the body;
/// server-side validation failures surface through the normal error path
/// (non-2xx → exit 5).
pub fn config_set(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [section, updates] = args else { return Err(Unhandled) };
    if section.starts_with('-') || updates.starts_with('-') {
        return Err(Unhandled);
    }
    let parsed: serde_json::Value = match serde_json::from_str(updates) {
        Ok(v) => v,
        Err(_) => fail(
            g.json,
            ExitCode::Generic,
            "invalid_json",
            "invalid JSON in updates argument",
            Some("pass updates as a JSON object, e.g. '{\"key\": \"value\"}'"),
        ),
    };
    // `cli` is the per-user CLI preference file (~/.config/mesh/cli.json),
    // not a gateway section: `color` = auto|always|never (CLI_STYLE_GUIDE
    // §3). Local, no auth, applies to the next invocation.
    if section == "cli" {
        let Some(obj) = parsed.as_object() else {
            fail(g.json, ExitCode::Generic, "invalid_json", "cli preferences must be a JSON object", None)
        };
        if let Some(c) = obj.get("color") {
            if !c.as_str().and_then(ui::Mode::parse).is_some() {
                fail(g.json, ExitCode::Generic, "invalid_value", "color must be auto, always or never (cli.color)", None);
            }
        }
        let mut prefs = ui::read_prefs();
        if !prefs.is_object() {
            prefs = serde_json::json!({});
        }
        for (k, v) in obj {
            prefs[k] = v.clone();
        }
        let path = ui::prefs_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&prefs).unwrap_or_default()) {
            fail(g.json, ExitCode::Generic, "write_failed", &format!("could not write {}: {e}", path.display()), None);
        }
        if g.json {
            println!("{}", serde_json::json!({"section": "cli", "path": path.display().to_string(), "prefs": prefs}));
        } else {
            ui::done(&format!("CLI preferences updated ({})", path.display()));
        }
        return Ok(0);
    }
    let resp = put_json(g, &format!("/api/config/{section}"), &parsed, true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let msg = resp["message"].as_str().map(str::to_string);
    ui::done(&msg.unwrap_or_else(|| format!("updated {section}")));
    ui::guide(&[
        (&format!("noo config get {section}"), "the section as the gateway now holds it"),
        ("noo config export-effective", "the whole effective config, for the record"),
    ]);
    Ok(0)
}

/// The places `noo config show` looks, in order, when no path is given:
/// `./noomesh.yaml` → `<repo_root>/noomesh.yaml` → `~/.config/mesh/config.yaml`.
/// `repo_root()` is the INSTALL: a standalone state home (`~/.noo`) when
/// one exists, else the checkout. Until 2026-10-22 the install was not on
/// the list (only cwd and the legacy `~/.config/mesh` path were), so
/// `noo config show` run from the operator's home on a standalone
/// controller printed `config path —` and `{}` for a box that carried a
/// full noomesh.yaml. Pure so the ordering is testable.
fn config_search_candidates(cwd: Option<PathBuf>, root: PathBuf, home: Option<String>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    // pai-assistant.yaml retired 2026-08-02 — see config.py.
    if let Some(c) = cwd {
        push(c.join("noomesh.yaml"));
    }
    push(root.join("noomesh.yaml"));
    if let Some(h) = home {
        push(PathBuf::from(h).join(".config").join("mesh").join("config.yaml"));
    }
    out
}

fn config_search_path() -> Vec<PathBuf> {
    config_search_candidates(
        std::env::current_dir().ok(),
        crate::envfile::repo_root(),
        std::env::var("HOME").ok(),
    )
}

/// The first candidate that is a file, else None. (The explicit
/// `--config`/`$NOO_CONFIG` branch is handled by the caller, which — unlike
/// Python's silent empty-config fallback — reports a missing explicit file
/// as a clear local error.)
fn discover_config_path() -> Option<PathBuf> {
    config_search_path().into_iter().find(|p| p.is_file())
}

/// `noo config show [--config PATH]` — show the LOCAL configuration file.
///
/// Pure file read, no gateway: resolves the YAML exactly like Python's
/// `load_config()` (`--config` > `$NOO_CONFIG` > search path) and renders
/// `config_path` + the parsed content. Deliberate divergence from Python:
/// we display what the file actually declares rather than the full
/// pydantic `model_dump()` (which expands every builtin default) — the
/// merged defaults+overrides view is `config export-effective`.
pub fn config_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut cfg: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--config" => cfg = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }

    let explicit = cfg.or_else(|| std::env::var("NOO_CONFIG").ok().filter(|s| !s.is_empty()));
    let resolved: Option<PathBuf> = match explicit {
        Some(p) => {
            let pb = PathBuf::from(&p);
            if !pb.is_file() {
                // Local error, NOT gateway_unreachable — no gateway involved.
                fail(
                    g.json,
                    ExitCode::Generic,
                    "config_not_found",
                    &format!("config file not found: {p}"),
                    Some("pass --config with an existing YAML file, or unset NOO_CONFIG"),
                );
            }
            Some(pb)
        }
        None => discover_config_path(),
    };

    let data: serde_json::Value = match &resolved {
        Some(path) => {
            let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "config_unreadable",
                    &format!("cannot read {}: {e}", path.display()),
                    None,
                )
            });
            if text.trim().is_empty() {
                serde_json::json!({})
            } else {
                // Parse via serde_yaml straight into JSON (config files are
                // string-keyed mappings); parity with yaml.safe_load.
                serde_yaml::from_str(&text).unwrap_or_else(|e| {
                    fail(
                        g.json,
                        ExitCode::Generic,
                        "invalid_yaml",
                        &format!("invalid YAML in {}: {e}", path.display()),
                        None,
                    )
                })
            }
        }
        None => serde_json::json!({}),
    };

    if g.json {
        // Python envelope: {"config_path": …, **config}.
        let mut obj = serde_json::Map::new();
        obj.insert(
            "config_path".into(),
            resolved
                .as_ref()
                .map(|p| serde_json::Value::String(p.display().to_string()))
                .unwrap_or(serde_json::Value::Null),
        );
        if resolved.is_none() {
            // Say where we looked, so `{}` reads as "no file" and not as
            // "an empty config".
            obj.insert(
                "searched".into(),
                serde_json::Value::Array(
                    config_search_path().iter().map(|p| serde_json::Value::String(p.display().to_string())).collect(),
                ),
            );
        }
        if let Some(m) = data.as_object() {
            for (k, v) in m {
                obj.insert(k.clone(), v.clone());
            }
        }
        println!("{}", serde_json::Value::Object(obj));
        return Ok(0);
    }
    let Some(path) = resolved.as_ref() else {
        // No local file anywhere on the search path. The old output here was
        // `config path —` followed by `{}`, which read as an empty config.
        print!("{}", ui::kv(&[("config path", ui::warn("no noomesh.yaml found"))]));
        println!("  searched:");
        for p in config_search_path() {
            println!("    {}", ui::muted(&p.display().to_string()));
        }
        ui::guide(&[
            ("noo config export-effective", "the config the gateway is actually running (asks the gateway)"),
            ("noo config show --config <path>", "a file somewhere else"),
        ]);
        return Ok(0);
    };
    print!("{}", ui::kv(&[("config path", path.display().to_string())]));
    // Parity with the Python CLI: human mode prints the config as pretty JSON.
    println!("{}", serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string()));
    Ok(0)
}

/// UTC timestamp matching Python's `isoformat(timespec="seconds")`
/// (e.g. `2026-07-31T12:34:56+00:00`).
fn utc_now_iso_seconds() -> String {
    let fmt = time::format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]T[hour]:[minute]:[second]+00:00",
    )
    .expect("static format string");
    time::OffsetDateTime::now_utc().format(&fmt).unwrap_or_default()
}

/// `noo config export-effective [--output/-o FILE]` — export the EFFECTIVE
/// runtime configuration (builtins + YAML seed + DB overrides merged) as
/// YAML, for review/diffing. Best-effort composite like the Python CLI: each
/// of the three fetches tolerates failure and embeds `{"error": …}` instead
/// of aborting, so the command exits 0 even with the gateway down.
pub fn config_export_effective(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut output: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--output" | "-o" => output = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }

    let fetch = |path: &str| {
        get_json_opt(g, path, true, 15)
            .unwrap_or_else(|| serde_json::json!({"error": format!("GET {path} failed")}))
    };
    let autonomy = fetch("/api/autonomy/status");
    let kb_rules = fetch("/api/kb/rules");
    let kb_grants = fetch("/api/kb/grants");

    // Python's `d.get(key, d)`: unwrap the named field when present, else
    // embed the whole response (which may be the {"error": …} placeholder).
    let pick = |v: &serde_json::Value, key: &str| {
        if v.get(key).is_some() {
            v[key].clone()
        } else {
            v.clone()
        }
    };

    // Build the snapshot as serde_yaml Mappings (insertion-ordered) so the
    // YAML matches Python's `yaml.safe_dump(…, sort_keys=False)` key order;
    // serde_json maps would render alphabetically.
    let ykey = |s: &str| serde_yaml::Value::String(s.into());
    let yval = |v: &serde_json::Value| serde_yaml::to_value(v).unwrap_or(serde_yaml::Value::Null);

    let mut autonomy_m = serde_yaml::Mapping::new();
    autonomy_m.insert(ykey("enabled"), yval(&autonomy["running"]));
    autonomy_m.insert(ykey("locations_enabled"), yval(&autonomy["locations_enabled"]));
    autonomy_m.insert(ykey("locations"), yval(&pick(&autonomy, "locations")));

    let mut kb_m = serde_yaml::Mapping::new();
    kb_m.insert(ykey("source_rules_db"), yval(&pick(&kb_rules, "rules")));
    kb_m.insert(ykey("role_grants"), yval(&pick(&kb_grants, "grants")));

    let mut snapshot = serde_yaml::Mapping::new();
    snapshot.insert(ykey("generated_at"), ykey(&utc_now_iso_seconds()));
    snapshot.insert(
        ykey("note"),
        ykey(
            "Effective runtime config (builtins + YAML seed + DB overrides). \
             Export, not seed — promote into noomesh.yaml deliberately.",
        ),
    );
    snapshot.insert(ykey("autonomy"), serde_yaml::Value::Mapping(autonomy_m));
    snapshot.insert(ykey("kb"), serde_yaml::Value::Mapping(kb_m));
    let snapshot = serde_yaml::Value::Mapping(snapshot);

    if g.json && output.is_none() {
        let as_json = serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null);
        println!("{as_json}");
        return Ok(0);
    }

    let rendered = serde_yaml::to_string(&snapshot).unwrap_or_default();

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &rendered) {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "write_failed",
                    &format!("cannot write {path}: {e}"),
                    None,
                );
            }
            if g.json {
                println!("{}", serde_json::json!({"written": path}));
            } else {
                ui::done(&format!("effective config written to {path}"));
                ui::value(&path);
                ui::guide(&[
                    ("noo config show", "the layered sources this file was resolved from"),
                    ("noo cluster seed", "export, not seed — promote settings into noomesh.yaml deliberately"),
                ]);
            }
        }
        None => println!("{rendered}"),
    }
    Ok(0)
}

#[cfg(test)]
mod search_path_tests {
    use super::*;

    #[test]
    fn the_install_root_is_searched_between_cwd_and_the_legacy_path() {
        let got = config_search_candidates(
            Some(PathBuf::from("/home/op")),
            PathBuf::from("/home/op/.noo"),
            Some("/home/op".into()),
        );
        assert_eq!(
            got,
            vec![
                PathBuf::from("/home/op/noomesh.yaml"),
                PathBuf::from("/home/op/.noo/noomesh.yaml"),
                PathBuf::from("/home/op/.config/mesh/config.yaml"),
            ]
        );
    }

    #[test]
    fn a_cwd_that_is_the_install_is_listed_once() {
        let got = config_search_candidates(
            Some(PathBuf::from("/srv/mesh-install")),
            PathBuf::from("/srv/mesh-install"),
            None,
        );
        assert_eq!(got, vec![PathBuf::from("/srv/mesh-install/noomesh.yaml")]);
    }
}
