// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! CLI pieces: an add-on describes its own `noo` commands.
//!
//! The released `noo` is generic. An enabled add-on serves a piece that names
//! its command groups and commands; the CLI turns each command into a request
//! to the gateway's existing add-on proxy. `GET /api/addons/{addon_id}/cli-piece`
//! fetches the piece and hands the CLI a validated copy.
//!
//! The security property is in [`validate_piece`]: every command's method and
//! path must match a MOUNTED, non-internal route of THAT add-on's manifest
//! as loaded at startup ([`crate::addon_proxy::AddonManifest`]). An add-on can therefore
//! only make the CLI call routes the gateway already exposes for it. The check
//! reads the manifest; no route is named here.
//!
//! Transport: only HTTP add-ons have one. A manifest with an internal
//! `cli_piece` route is reached through [`crate::addon_proxy::call`]; an
//! add-on without that row (including the NATS-only `trellion_intel`) answers
//! 404 `{"error":"no_cli_piece"}`.
//!
//! Status codes: unknown id 404 `{"error":"unknown_addon"}`; no CLI piece 404
//! `{"error":"no_cli_piece"}`; add-on disabled or unlicensed 503 with
//! [`crate::addons::refusal_msg`]; enabled but its route manifest refused at
//! startup 503 with [`crate::addon_proxy::refusal`]; enabled but no answer, a timeout, a non-2xx
//! upstream or a piece that fails validation 502. Never 500.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{extract::Path, http::StatusCode, routing::get, Json, Router};
use serde_json::{json, Map, Value};

use crate::addon_proxy::{AddonManifest, RouteSpec};
use crate::state::AppState;

/// Name of the internal manifest route that serves the piece.
const PIECE_ROUTE: &str = "cli_piece";
/// A piece is a table of commands. Anything near this is a bug upstream.
const MAX_PIECE_BYTES: usize = 64 * 1024;
const KINDS: &[&str] = &["string", "int", "uuid", "bool"];

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/addons/{addon_id}/cli-piece", get(cli_piece))
}

/// GET /api/addons/{addon_id}/cli-piece — the add-on's `noo` commands.
/// 404 unknown add-on or none offered, 503 disabled or unlicensed, 502 when
/// the add-on does not answer with a valid piece.
async fn cli_piece(Path(addon_id): Path<String>) -> (StatusCode, Json<Value>) {
    let (status, body) = respond(&addon_id).await;
    (status, Json(body))
}

fn bad_gateway(addon: &str, why: impl std::fmt::Display) -> (StatusCode, Value) {
    tracing::warn!(addon, "cli piece unavailable: {why}");
    (
        StatusCode::BAD_GATEWAY,
        json!({ "error": "cli_piece_unavailable", "addon": addon, "detail": why.to_string() }),
    )
}

async fn respond(addon_id: &str) -> (StatusCode, Value) {
    let Some(addon) = crate::addons::ADDONS.iter().find(|a| a.name == addon_id) else {
        return (StatusCode::NOT_FOUND, json!({ "error": "unknown_addon" }));
    };
    // Only an HTTP add-on (one that ships a route manifest) can have a piece.
    if !addon.routes_manifest {
        return (StatusCode::NOT_FOUND, json!({ "error": "no_cli_piece" }));
    }
    if !crate::addons::enabled(addon.name) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": crate::addons::refusal_msg(addon.name),
                "addon": addon.name,
                "state": crate::addons::health_word(addon.name),
            }),
        );
    }
    // On, but its manifest was missing or refused at startup: say why.
    if let Some(why) = crate::addon_proxy::refusal(addon.name) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "error": why, "addon": addon.name, "state": "unhealthy" }),
        );
    }
    let manifest = crate::addon_proxy::manifests()
        .into_iter()
        .find(|m| m.addon == addon.name);
    // A manifest without the row: this add-on has no CLI piece.
    let Some(manifest) = manifest.filter(|m| m.routes.iter().any(|r| r.name == PIECE_ROUTE)) else {
        return (StatusCode::NOT_FOUND, json!({ "error": "no_cli_piece" }));
    };
    let raw = match crate::addon_proxy::call(addon.name, PIECE_ROUTE, None).await {
        crate::addon_proxy::CallOutcome::Ok(v) => v,
        crate::addon_proxy::CallOutcome::Unavailable(why) => return bad_gateway(addon.name, why),
    };
    match validate_piece(&manifest, &raw) {
        Ok(piece) => (StatusCode::OK, piece),
        Err(why) => bad_gateway(addon.name, format!("invalid piece: {why}")),
    }
}

fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 24
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A JSON pointer: empty (the whole value) or `/`-led.
fn pointer_ok(s: &str) -> bool {
    s.is_empty() || s.starts_with('/')
}

fn str_field<'a>(o: &'a Map<String, Value>, f: &str, ctx: &str) -> Result<&'a str, String> {
    o.get(f)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{ctx}: {f} must be a string"))
}

fn opt_str<'a>(o: &'a Map<String, Value>, f: &str, ctx: &str) -> Result<Option<&'a str>, String> {
    match o.get(f) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{ctx}: {f} must be a string")),
    }
}

/// `{param}` names in a path template, in order.
fn path_params(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = path;
    while let Some(i) = rest.find('{') {
        let Some(j) = rest[i..].find('}') else { break };
        out.push(&rest[i + 1..i + j]);
        rest = &rest[i + j + 1..];
    }
    out
}

/// The mounted, non-internal manifest route a command's method and path name.
fn mounted_route<'a>(m: &'a AddonManifest, method: &str, path: &str) -> Option<&'a RouteSpec> {
    m.routes.iter().find(|r| {
        !r.internal
            && r.method.eq_ignore_ascii_case(method)
            && (r.path == path || r.aliases.iter().any(|a| a == path))
    })
}

/// Check a piece against the contract and `manifest`, and return a normalized
/// copy (only the known fields survive). `Err` names the first violation.
pub(crate) fn validate_piece(manifest: &AddonManifest, raw: &Value) -> Result<Value, String> {
    let obj = raw.as_object().ok_or("not a JSON object")?;
    if obj.get("version") != Some(&json!(1)) {
        return Err("version must be 1".into());
    }
    match obj.get("addon").and_then(Value::as_str) {
        Some(a) if a == manifest.addon => {}
        other => return Err(format!("addon is {other:?}, expected {:?}", manifest.addon)),
    }

    let mut group_names: HashSet<&str> = HashSet::new();
    let mut groups_out = Vec::new();
    for g in obj.get("groups").and_then(Value::as_array).ok_or("groups must be an array")? {
        let g = g.as_object().ok_or("a group is not an object")?;
        let name = str_field(g, "name", "group")?;
        if !name_ok(name) {
            return Err(format!("group name {name:?} must match ^[a-z][a-z0-9-]{{0,23}}$"));
        }
        if !group_names.insert(name) {
            return Err(format!("group {name:?} is declared twice"));
        }
        let summary = str_field(g, "summary", &format!("group {name:?}"))?;
        groups_out.push(json!({ "name": name, "summary": summary }));
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut commands_out = Vec::new();
    for c in obj.get("commands").and_then(Value::as_array).ok_or("commands must be an array")? {
        let c = c.as_object().ok_or("a command is not an object")?;
        let group = str_field(c, "group", "command")?;
        let name = str_field(c, "name", "command")?;
        let ctx = format!("command {group} {name}");
        if !name_ok(name) {
            return Err(format!("{ctx}: name must match ^[a-z][a-z0-9-]{{0,23}}$"));
        }
        if !group_names.contains(group) {
            return Err(format!("{ctx}: group {group:?} is not declared in groups"));
        }
        if !seen.insert((group.to_string(), name.to_string())) {
            return Err(format!("{ctx} is declared twice"));
        }
        let summary = str_field(c, "summary", &ctx)?;
        let method = str_field(c, "method", &ctx)?;
        let path = str_field(c, "path", &ctx)?;
        let route = mounted_route(manifest, method, path).ok_or_else(|| {
            format!(
                "{ctx}: {method} {path} is not a mounted, non-internal route of the {} add-on",
                manifest.addon
            )
        })?;

        let mut args_out = Vec::new();
        let mut names: HashSet<&str> = HashSet::new();
        let mut flags: HashSet<&str> = HashSet::new();
        let mut path_args: Vec<&str> = Vec::new();
        for a in c.get("args").and_then(Value::as_array).ok_or_else(|| format!("{ctx}: args must be an array"))? {
            let a = a.as_object().ok_or_else(|| format!("{ctx}: an arg is not an object"))?;
            let aname = str_field(a, "name", &ctx)?;
            let actx = format!("{ctx} arg {aname:?}");
            if !names.insert(aname) {
                return Err(format!("{actx} is declared twice"));
            }
            let kind = str_field(a, "kind", &actx)?;
            if !KINDS.contains(&kind) {
                return Err(format!("{actx}: kind {kind:?} must be one of {KINDS:?}"));
            }
            let required = match a.get("required") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err(format!("{actx}: required must be a boolean")),
            };
            let into = str_field(a, "into", &actx)?;
            let (target, dest) = into
                .split_once(':')
                .filter(|(_, d)| !d.is_empty())
                .ok_or_else(|| format!("{actx}: into {into:?} must be path:<param>, query:<name> or body:<name>"))?;
            match target {
                "path" => {
                    if !path_params(path).contains(&dest) {
                        return Err(format!("{actx}: path:{dest} is not a {{param}} of {path}"));
                    }
                    if path_args.contains(&dest) {
                        return Err(format!("{actx}: path:{dest} is covered by two args"));
                    }
                    if !required {
                        return Err(format!("{actx}: a path arg must be required"));
                    }
                    path_args.push(dest);
                }
                "query" if !route.query => {
                    return Err(format!("{actx}: {path} takes no query string in the manifest"));
                }
                "query" => {}
                "body" if !method.eq_ignore_ascii_case("POST") => {
                    return Err(format!("{actx}: only a POST command takes a body arg"));
                }
                "body" => {}
                _ => return Err(format!("{actx}: into {into:?} must be path:<param>, query:<name> or body:<name>")),
            }
            let flag = opt_str(a, "flag", &actx)?;
            match flag {
                Some(f) if !f.starts_with("--") || f.len() < 3 => {
                    return Err(format!("{actx}: flag {f:?} must start with --"));
                }
                Some(f) if !flags.insert(f) => return Err(format!("{actx}: flag {f} is used twice")),
                None if kind == "bool" => return Err(format!("{actx}: a bool arg is a flag")),
                None if target != "path" && !required => {
                    return Err(format!("{actx}: an optional arg needs a flag"));
                }
                _ => {}
            }
            let mut entry = json!({ "name": aname, "kind": kind, "required": required, "into": into });
            if let Some(f) = flag {
                entry["flag"] = json!(f);
            }
            if let Some(h) = opt_str(a, "help", &actx)? {
                entry["help"] = json!(h);
            }
            args_out.push(entry);
        }
        // Every `{param}` of the path needs exactly one `path:` arg.
        for p in path_params(path) {
            if !path_args.contains(&p) {
                return Err(format!("{ctx}: path param {{{p}}} has no path:{p} arg"));
            }
        }

        let mut entry = json!({
            "group": group, "name": name, "summary": summary,
            "method": method.to_ascii_uppercase(), "path": path, "args": args_out,
        });
        if let Some(confirm) = opt_str(c, "confirm", &ctx)? {
            entry["confirm"] = json!(confirm);
        }
        if let Some(out) = c.get("output") {
            entry["output"] = validate_output(out, &ctx)?;
        }
        commands_out.push(entry);
    }

    let piece = json!({
        "version": 1, "addon": manifest.addon,
        "groups": groups_out, "commands": commands_out,
    });
    let size = serde_json::to_vec(&piece).map(|b| b.len()).unwrap_or(usize::MAX);
    if size >= MAX_PIECE_BYTES {
        return Err(format!("piece is {size} bytes; the limit is under {MAX_PIECE_BYTES}"));
    }
    Ok(piece)
}

fn key_labels(v: &Value, what: &str, ctx: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for f in v.as_array().ok_or_else(|| format!("{ctx}: output.{what} must be an array"))? {
        let f = f.as_object().ok_or_else(|| format!("{ctx}: an output.{what} entry is not an object"))?;
        let key = str_field(f, "key", ctx)?;
        if !pointer_ok(key) {
            return Err(format!("{ctx}: output.{what} key {key:?} is not a JSON pointer"));
        }
        out.push(json!({ "key": key, "label": str_field(f, "label", ctx)? }));
    }
    Ok(out)
}

fn validate_output(v: &Value, ctx: &str) -> Result<Value, String> {
    let o = v.as_object().ok_or_else(|| format!("{ctx}: output must be an object"))?;
    let mut out = Map::new();
    if let Some(t) = opt_str(o, "title", ctx)? {
        out.insert("title".into(), json!(t));
    }
    if let Some(f) = o.get("fields") {
        out.insert("fields".into(), json!(key_labels(f, "fields", ctx)?));
    }
    if let Some(l) = opt_str(o, "list", ctx)? {
        if !pointer_ok(l) {
            return Err(format!("{ctx}: output.list {l:?} is not a JSON pointer"));
        }
        out.insert("list".into(), json!(l));
        let cols = o.get("columns").ok_or_else(|| format!("{ctx}: output.list needs output.columns"))?;
        out.insert("columns".into(), json!(key_labels(cols, "columns", ctx)?));
    } else if o.contains_key("columns") {
        return Err(format!("{ctx}: output.columns needs output.list"));
    }
    if let Some(h) = opt_str(o, "hint", ctx)? {
        out.insert("hint".into(), json!(h));
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The neutral sample manifest (the core names no add-on's routes).
    fn evolve() -> AddonManifest {
        crate::addon_proxy::tests::sample()
    }

    fn good() -> Value {
        json!({
            "version": 1, "addon": "evolve",
            "groups": [{"name": "sample", "summary": "Sample"}, {"name": "items", "summary": "items"}],
            "commands": [
                {
                    "group": "sample", "name": "rollback", "summary": "Restore",
                    "method": "POST", "path": "/api/sample/rollback",
                    "args": [{"name": "to", "flag": "--to", "kind": "int", "required": false,
                              "into": "body:genome_id", "help": "genome id"}],
                    "confirm": "Restore?",
                    "output": {"title": "sample rollback",
                               "fields": [{"key": "/restored", "label": "restored"}],
                               "hint": "noo sample status"}
                },
                {
                    "group": "items", "name": "list", "summary": "List",
                    "method": "GET", "path": "/api/sample/items",
                    "args": [{"name": "limit", "flag": "--limit", "kind": "int", "required": false,
                              "into": "query:limit"}],
                    "output": {"list": "/items", "columns": [{"key": "/id", "label": "id"}]}
                },
                {
                    "group": "items", "name": "detail", "summary": "One",
                    "method": "GET", "path": "/api/sample/items/{item_id}",
                    "args": [{"name": "item-id", "kind": "uuid", "required": true, "into": "path:item_id"}]
                },
            ]
        })
    }

    fn with_cmd(f: impl FnOnce(&mut Value)) -> Value {
        let mut p = good();
        f(&mut p["commands"][0]);
        p
    }

    fn refused(p: &Value, needle: &str) {
        let e = validate_piece(&evolve(), p).expect_err("must be refused");
        assert!(e.contains(needle), "{e:?} should mention {needle:?}");
    }

    #[test]
    fn a_good_piece_passes_and_is_normalized() {
        let mut p = good();
        p["commands"][0]["extra"] = json!("dropped");
        p["commands"][0]["method"] = json!("post");
        let out = validate_piece(&evolve(), &p).expect("valid");
        assert!(out["commands"][0].get("extra").is_none());
        assert_eq!(out["commands"][0]["method"], json!("POST"));
        assert_eq!(out["commands"][0]["confirm"], json!("Restore?"));
        assert_eq!(out["commands"][1]["output"]["columns"][0]["label"], json!("id"));
    }

    #[test]
    fn a_path_not_in_the_manifest_is_refused() {
        refused(&with_cmd(|c| c["path"] = json!("/api/sample/nuke")), "not a mounted");
        // The method is part of the match: GET on a POST-only route.
        refused(&with_cmd(|c| c["method"] = json!("GET")), "not a mounted");
        // Another add-on's, or the gateway's own, surface is not reachable.
        refused(&with_cmd(|c| c["path"] = json!("/api/security/posture")), "not a mounted");
    }

    #[test]
    fn an_internal_route_is_refused() {
        // Both exist in the manifest and are internal: not mounted, so not callable.
        for (m, p) in [("GET", "/cli-piece"), ("GET", "/console-piece"), ("POST", "/api/sample/dispatch")] {
            let mut piece = with_cmd(|c| {
                c["method"] = json!(m);
                c["path"] = json!(p);
            });
            piece["commands"][0]["args"] = json!([]);
            refused(&piece, "not a mounted");
        }
    }

    #[test]
    fn the_surface_check_follows_the_manifest_not_a_list() {
        // A manifest with exactly one mounted route accepts that and nothing else.
        let mut m = evolve();
        m.routes.retain(|r| r.name == "sample_status");
        let p = json!({"version":1,"addon":"evolve","groups":[{"name":"sample","summary":"s"}],
            "commands":[{"group":"sample","name":"status","summary":"s","method":"GET","path":"/api/sample/status","args":[]}]});
        assert!(validate_piece(&m, &p).is_ok());
        assert!(validate_piece(&evolve(), &p).is_ok());
        m.routes[0].internal = true;
        assert!(validate_piece(&m, &p).is_err());
        m.routes[0].internal = false;
        m.routes[0].path = "/api/sample/other".into();
        assert!(validate_piece(&m, &p).is_err());
    }

    #[test]
    fn a_bad_arg_kind_is_refused() {
        for kind in ["float", "", "Int"] {
            refused(&with_cmd(|c| c["args"][0]["kind"] = json!(kind)), "kind");
        }
        refused(&with_cmd(|c| c["args"][0]["kind"] = json!(3)), "kind must be a string");
    }

    #[test]
    fn bad_into_and_flags_are_refused() {
        for into in ["body", "body:", "header:x", "path:nope", "query:"] {
            let e = validate_piece(&evolve(), &with_cmd(|c| c["args"][0]["into"] = json!(into)));
            assert!(e.is_err(), "{into}");
        }
        refused(&with_cmd(|c| c["args"][0]["flag"] = json!("to")), "--");
        refused(
            &with_cmd(|c| {
                c["args"][0].as_object_mut().unwrap().remove("flag");
            }),
            "needs a flag",
        );
        // A query arg on a route the manifest does not mark `query`.
        refused(&with_cmd(|c| c["args"][0]["into"] = json!("query:x")), "query");
        // A body arg on a GET.
        let mut p = good();
        p["commands"][1]["args"][0]["into"] = json!("body:limit");
        let e = validate_piece(&evolve(), &p).unwrap_err();
        assert!(e.contains("body"), "{e}");
    }

    #[test]
    fn an_uncovered_or_doubly_covered_path_param_is_refused() {
        let mut p = good();
        p["commands"][2]["args"] = json!([]);
        let e = validate_piece(&evolve(), &p).unwrap_err();
        assert!(e.contains("item_id"), "{e}");
        let mut p = good();
        let a = p["commands"][2]["args"][0].clone();
        let mut b = a.clone();
        b["name"] = json!("other");
        p["commands"][2]["args"] = json!([a, b]);
        assert!(validate_piece(&evolve(), &p).unwrap_err().contains("two args"));
        // An optional path arg cannot build the path.
        let mut p = good();
        p["commands"][2]["args"][0]["required"] = json!(false);
        assert!(validate_piece(&evolve(), &p).unwrap_err().contains("required"));
    }

    #[test]
    fn names_must_match_the_pattern() {
        for bad in ["Sample", "1s", "-s", "s_a", "", "a".repeat(25).as_str(), "sample rollback"] {
            let mut p = good();
            p["groups"][0]["name"] = json!(bad);
            assert!(validate_piece(&evolve(), &p).is_err(), "group {bad:?}");
            let mut p = good();
            p["commands"][0]["name"] = json!(bad);
            assert!(validate_piece(&evolve(), &p).is_err(), "command {bad:?}");
        }
        let mut p = good();
        p["groups"][0]["name"] = json!("a".repeat(24));
        p["commands"][0]["group"] = json!("a".repeat(24));
        assert!(validate_piece(&evolve(), &p).is_ok());
    }

    #[test]
    fn groups_and_commands_must_be_consistent() {
        let mut p = good();
        p["commands"][0]["group"] = json!("undeclared");
        assert!(validate_piece(&evolve(), &p).unwrap_err().contains("not declared"));
        let mut p = good();
        let dup = p["commands"][0].clone();
        p["commands"].as_array_mut().unwrap().push(dup);
        assert!(validate_piece(&evolve(), &p).unwrap_err().contains("twice"));
    }

    #[test]
    fn wrong_version_addon_or_shape_is_refused() {
        for v in [json!(2), json!("1"), json!(null)] {
            let mut p = good();
            p["version"] = v;
            refused(&p, "version");
        }
        let mut p = good();
        p["addon"] = json!("trellion_intel");
        refused(&p, "addon");
        refused(&json!([1]), "object");
        refused(&json!({"version": 1, "addon": "evolve"}), "groups");
        let mut p = good();
        p["commands"][0]["summary"] = json!(7);
        refused(&p, "summary");
        let mut p = good();
        p["commands"][0]["confirm"] = json!(true);
        refused(&p, "confirm");
        let mut p = good();
        p["commands"][0]["output"]["fields"][0]["key"] = json!("restored");
        refused(&p, "JSON pointer");
        let mut p = good();
        p["commands"][1]["output"].as_object_mut().unwrap().remove("columns");
        refused(&p, "columns");
    }

    #[test]
    fn an_oversize_piece_is_refused() {
        let mut p = good();
        p["commands"][0]["summary"] = json!("x".repeat(MAX_PIECE_BYTES));
        refused(&p, "bytes");
    }

    #[tokio::test]
    async fn an_unknown_addon_is_404() {
        let (status, body) = respond("nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, json!({ "error": "unknown_addon" }));
    }

    #[tokio::test]
    async fn an_addon_without_a_cli_piece_is_404_no_cli_piece() {
        // trellion_intel is NATS-only and has no manifest; trellion is open and has none either.
        for id in ["trellion_intel", "trellion"] {
            let (status, body) = respond(id).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{id}");
            assert_eq!(body, json!({ "error": "no_cli_piece" }), "{id}");
        }
    }

    #[tokio::test]
    async fn a_disabled_addon_is_503_with_the_refusal_text() {
        // evolve is opt-in and the test env does not turn it on.
        if crate::addons::enabled("evolve") {
            return;
        }
        let (status, body) = respond("evolve").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], json!(crate::addons::refusal_msg("evolve")));
    }
}
